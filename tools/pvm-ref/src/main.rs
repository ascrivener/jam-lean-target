//! Reference side of the PVM differential harness.
//!
//! Runs testcases in the koute/jamtestvectors `pvm/programs` format on PolkaVM's interpreter,
//! configured exactly as PolkaVM's `spectool` (the generator of those vectors) configures it:
//! interpreter backend, dynamic paging, strict module, synchronous (per-block) gas metering, step
//! tracing and the full cost model with an L2-hit cache model. The `program` field is the raw JAM
//! program blob (GP deblob format), handed to PolkaVM as the `code_and_jump_table` of a `JamV1`
//! program.
//!
//! Usage:
//!   pvm-ref run FILE|DIR...    print each testcase as JSON (one per line), with every `assert`
//!                              step replaced by the state actually observed (an `assert` is
//!                              inserted after a `run` that has none)
//!   pvm-ref check FILE|DIR...  compare against the asserts in the files (fields present only)
//!
//! A blob that PolkaVM refuses to load is reported as status `load-error` (with `error`).

use polkavm::{CacheModel, CostModelKind, Engine, InterruptKind, MemoryProtection, Module, ModuleConfig, ProgramBlob, Reg};
use polkavm_common::program::{InstructionSetKind, ProgramParts};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

fn collect(paths: &[String]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for p in paths {
        let p = Path::new(p);
        if p.is_dir() {
            let mut v: Vec<PathBuf> = std::fs::read_dir(p)
                .unwrap()
                .map(|e| e.unwrap().path())
                .filter(|q| q.extension().is_some_and(|e| e == "json" || e == "jsonl"))
                .collect();
            v.sort();
            out.extend(v);
        } else {
            out.push(p.to_path_buf());
        }
    }
    out
}

fn u64_of(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| panic!("not a u64: {v}"))
}

fn bytes_of(v: &Value) -> Vec<u8> {
    v.as_array().unwrap().iter().map(|b| u8::try_from(u64_of(b)).unwrap()).collect()
}

/// Runs of non-zero octets over all mapped regions, merged across adjacent regions.
fn memory_chunks(instance: &mut polkavm::RawInstance, pages: &[(u32, u32)]) -> Value {
    let mut nonzero: BTreeMap<u64, u8> = BTreeMap::new();
    for &(address, length) in pages {
        let contents = instance.read_memory(address, length).unwrap();
        for (k, &b) in contents.iter().enumerate() {
            if b != 0 {
                nonzero.insert(u64::from(address) + k as u64, b);
            }
        }
    }
    let mut chunks: Vec<Value> = Vec::new();
    let mut cur: Option<(u64, Vec<u8>)> = None;
    for (a, b) in nonzero {
        match &mut cur {
            Some((start, bs)) if *start + bs.len() as u64 == a => bs.push(b),
            _ => {
                if let Some((start, bs)) = cur.take() {
                    chunks.push(json!({"address": start, "contents": bs}));
                }
                cur = Some((a, vec![b]));
            }
        }
    }
    if let Some((start, bs)) = cur {
        chunks.push(json!({"address": start, "contents": bs}));
    }
    Value::Array(chunks)
}

/// Execute one testcase; returns the steps with every assert filled from the observed state.
fn execute(engine: &Engine, tc: &Value, strict: bool) -> (Vec<Value>, Option<Value>) {
    let program = bytes_of(&tc["program"]);
    let initial_pc = u64_of(&tc["initial-pc"]) as u32;
    let initial_gas = tc["initial-gas"].as_i64().unwrap();
    let steps = tc["steps"].as_array().unwrap();

    let mut parts = ProgramParts::empty(InstructionSetKind::JamV1);
    parts.code_and_jump_table = program.into();

    let mut module_config = ModuleConfig::default();
    module_config.set_strict(strict);
    module_config.set_gas_metering(Some(polkavm::GasMeteringKind::Sync));
    module_config.set_step_tracing(true);
    module_config.set_dynamic_paging(true);
    module_config.set_cost_model(Some(CostModelKind::Full(CacheModel::L2Hit)));

    let load_error = |e: String| -> (Vec<Value>, Option<Value>) {
        let mut out = Vec::new();
        let mut seen_run = false;
        for s in steps {
            if s.get("assert").is_some() {
                continue;
            }
            out.push(s.clone());
            if s.get("run").is_some() && !seen_run {
                seen_run = true;
                out.push(json!({"assert": {"status": "load-error", "error": e}}));
            }
        }
        (out, None)
    };
    let blob = match ProgramBlob::from_parts(parts) {
        Ok(b) => b,
        Err(e) => return load_error(format!("parse: {e}")),
    };
    let module = match Module::from_blob(engine, &module_config, blob.clone()) {
        Ok(m) => m,
        Err(e) => return load_error(format!("module: {e}")),
    };
    // ϱ^Δ at every basic-block start, as PolkaVM computes it.
    let mut costs = Vec::new();
    for inst in blob.instructions() {
        if let Some(c) = module.calculate_gas_cost_for(inst.offset) {
            costs.push(json!({"pc": inst.offset.0, "cost": c}));
        }
    }
    let mut instance = module.instantiate().unwrap();
    instance.set_gas(initial_gas);
    instance.set_next_program_counter(polkavm::ProgramCounter(initial_pc));

    let mut pages: Vec<(u32, u32)> = Vec::new();
    let mut last_pc = initial_pc;
    let mut out: Vec<Value> = Vec::new();
    let mut last_assert: Option<Value> = None;

    let mut done = false;
    let mut i = 0;
    while i < steps.len() {
        let step = &steps[i];
        i += 1;
        let (kind, body) = step.as_object().unwrap().iter().next().unwrap();
        match kind.as_str() {
            "map" => {
                let address = u64_of(&body["address"]) as u32;
                let length = u64_of(&body["length"]) as u32;
                let w = body["is-writable"].as_bool().unwrap();
                instance
                    .zero_memory_with_memory_protection(
                        address,
                        length,
                        if w { MemoryProtection::ReadWrite } else { MemoryProtection::Read },
                    )
                    .unwrap();
                pages.push((address, length));
                out.push(step.clone());
            }
            "write" => {
                let address = u64_of(&body["address"]) as u32;
                let contents = bytes_of(&body["contents"]);
                let mut reprotect = Vec::new();
                let end = (address as u64 + contents.len() as u64).next_multiple_of(4096);
                let mut a = address as u64 / 4096 * 4096;
                while a < end {
                    let a32 = a as u32;
                    assert!(instance.is_memory_accessible(a32, 4096, MemoryProtection::Read), "write to unmapped page");
                    if !instance.is_memory_accessible(a32, 4096, MemoryProtection::ReadWrite) {
                        reprotect.push(a32);
                        instance.unprotect_memory(a32, 4096).unwrap();
                    }
                    a += 4096;
                }
                instance.write_memory(address, &contents).unwrap();
                for a in reprotect {
                    instance.protect_memory(a, 4096).unwrap();
                }
                out.push(step.clone());
            }
            "set-reg" => {
                let r = u64_of(&body["reg"]) as usize;
                instance.set_reg(Reg::ALL[r], u64_of(&body["value"]));
                out.push(step.clone());
            }
            "assert" => {
                // Replaced by the observed state (emitted after the run).
                if let Some(a) = last_assert.take() {
                    out.push(a);
                }
            }
            "run" => {
                // After halt or panic there is nothing to resume: later runs are dropped.
                if done {
                    continue;
                }
                out.push(step.clone());
                let (status, fault, host) = loop {
                    match instance.run().unwrap() {
                        InterruptKind::Finished => break ("halt", None, None),
                        InterruptKind::Trap => break ("panic", None, None),
                        InterruptKind::Ecalli(h) => break ("ecalli", None, Some(h)),
                        InterruptKind::NotEnoughGas => break ("out-of-gas", None, None),
                        InterruptKind::Segfault(s) => break ("page-fault", Some(s.page_address), None),
                        InterruptKind::Step => {
                            last_pc = instance.program_counter().unwrap().0;
                            continue;
                        }
                    }
                };
                done = status == "halt" || status == "panic";
                if status != "halt" {
                    last_pc = instance.program_counter().unwrap().0;
                }
                let regs: Vec<u64> = Reg::ALL.iter().map(|&r| instance.reg(r)).collect();
                let mut a = Map::new();
                a.insert("status".into(), json!(status));
                a.insert("regs".into(), json!(regs));
                a.insert("pc".into(), json!(last_pc));
                a.insert("memory".into(), memory_chunks(&mut instance, &pages));
                a.insert("gas".into(), json!(instance.gas()));
                if let Some(f) = fault {
                    a.insert("page-fault-address".into(), json!(f));
                }
                if let Some(h) = host {
                    a.insert("hostcall".into(), json!(h));
                }
                let a = json!({"assert": Value::Object(a)});
                if steps.get(i).is_some_and(|s| s.get("assert").is_some()) {
                    last_assert = Some(a);
                } else {
                    out.push(a);
                }
            }
            other => panic!("unknown step {other}"),
        }
    }
    (out, Some(Value::Array(costs)))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 || (args[1] != "run" && args[1] != "check") {
        eprintln!("usage: pvm-ref run|check FILE|DIR...");
        std::process::exit(2);
    }
    let mut config = polkavm::Config::new();
    config.set_backend(Some(polkavm::BackendKind::Interpreter));
    config.set_allow_dynamic_paging(true);
    let engine = Engine::new(&config).unwrap();

    let files = collect(&args[2..]);
    let mut failed = 0;
    let mut cases: Vec<(String, Value)> = Vec::new();
    for f in &files {
        let text = std::fs::read_to_string(f).unwrap();
        if f.extension().is_some_and(|e| e == "jsonl") {
            for (n, line) in text.lines().enumerate().filter(|(_, l)| !l.trim().is_empty()) {
                cases.push((format!("{}:{}", f.display(), n + 1), serde_json::from_str(line).unwrap()));
            }
        } else {
            cases.push((f.display().to_string(), serde_json::from_str(&text).unwrap()));
        }
    }
    let total = cases.len();
    for (f, tc) in &cases {
        let (got, costs) = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| execute(&engine, tc, true))) {
            // Strict mode (as spectool) refuses out-of-range jump-table entries, which GP v0.8.0
            // allows (they only matter when used): run those non-strict and say so.
            Ok((g, _)) if g.iter().any(|s| s["assert"]["error"] == json!("module: out of range jump table entry found")) => {
                let (mut g2, c2) = execute(&engine, tc, false);
                for s in g2.iter_mut() {
                    if let Some(a) = s.get_mut("assert").and_then(|a| a.as_object_mut()) {
                        a.insert("strict-error".into(), json!("out of range jump table entry found"));
                    }
                }
                (g2, c2)
            }
            Ok(g) => g,
            Err(e) => {
                let msg = e.downcast_ref::<String>().cloned().or(e.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
                (vec![json!({"run": {}}), json!({"assert": {"status": "ref-crash", "error": msg}})], None)
            }
        };
        if args[1] == "run" {
            let mut t = tc.as_object().unwrap().clone();
            t.insert("steps".into(), Value::Array(got));
            if let Some(c) = costs {
                t.insert("block-gas-costs".into(), c);
            }
            println!("{}", serde_json::to_string(&Value::Object(t)).unwrap());
        } else {
            let exp: Vec<&Value> = tc["steps"].as_array().unwrap().iter().filter_map(|s| s.get("assert")).collect();
            let act: Vec<&Value> = got.iter().filter_map(|s| s.get("assert")).collect();
            let mut err = None;
            if exp.len() != act.len() {
                err = Some(format!("{} asserts, expected {}", act.len(), exp.len()));
            } else {
                'o: for (e, a) in exp.iter().zip(act.iter()) {
                    for (k, v) in e.as_object().unwrap() {
                        if a.get(k) != Some(v) {
                            err = Some(format!("{k}: got {:?}, expected {v}", a.get(k)));
                            break 'o;
                        }
                    }
                    for k in ["page-fault-address", "hostcall"] {
                        if a.get(k).is_some() && e.get(k).is_none() {
                            err = Some(format!("unexpected {k}"));
                            break 'o;
                        }
                    }
                }
            }
            if let Some(e) = err {
                failed += 1;
                eprintln!("FAIL {f}: {e}");
            }
        }
    }
    if args[1] == "check" {
        println!("pvm-ref: {} of {} vectors pass", total - failed, total);
        if failed > 0 {
            std::process::exit(1);
        }
    }
}
