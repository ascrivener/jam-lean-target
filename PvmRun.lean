import Lean.Data.Json
import PVM.Invocation

/-! # PVM runner (`lake exe pvmrun run|check FILE|DIR…`)

The Lean side of the PVM differential harness. It runs testcases in the koute/jamtestvectors
`pvm/programs` format (schema `pvm/schema.asn`) on jam-lean's Ψ (`PVM.psi`, which compiled code
runs as the proved-equal `PVM.psiFast`).

* `run`   prints each testcase as one JSON line, with every `assert` step replaced by the state Ψ
          actually produced (an `assert` is inserted after a `run` that has none).
* `check` compares against the files' `assert` steps (the fields they give); exits 1 on any
          mismatch.

Conventions (as in the vectors and jam-lean's own runner `Tests/PvmTest`, which we may not import):

* `map` sets page access (all octets of the mapped pages stay as they are; the vectors only map
  fresh pages), `write` writes octets regardless of access, `set-reg` sets a register.
* `run` calls Ψ(p, ı, ϱ, ϱ̃, ω, μ). Ψ returns ı = 0 on ∎ and ☇; the vectors report as `pc` the
  instruction whose step ended the run, which we recompute (`exitIndex`). After h̵ the next run
  starts at ı + 1 + skip(ı) (as Ψ_H does, GP v0.8.0 §A.6); after F or ∞ at ı. ϱ̃ is carried over.
* After ∎ or ☇ later `run` steps are dropped (as PolkaVM cannot resume either).
* `memory` lists the maximal runs of non-zero octets, in address order.
-/

namespace PvmRun

open Lean (Json)
open PVM

abbrev M := Except String

def field (j : Json) (k : String) : M Json := j.getObjVal? k
def natField (j : Json) (k : String) : M Nat := do (← field j k).getNat?
def bytesOf (j : Json) : M ByteArray := do
  let ns ← (← j.getArr?).mapM (·.getNat?)
  if ns.any (· ≥ 256) then throw "octet out of range"
  return ⟨ns.map UInt8.ofNat⟩

/-- The instruction whose step ended a run of Ψ: the same steps as `Prepared.run` (and hence as
    `PVM.runFuel`, by `PVM.run_prepare`), returning the last ı. -/
def exitIdx (Q : Prepared) : Nat → Nat → UInt64 → Bool → Regs → Memory → Nat
  | 0, i, _, _, _, _ => i
  | fuel + 1, i, gas, ch, ω, μ =>
    if !(Q.valid && Q.prog.vInst i) then i
    else
      let r := Q.step i gas ch ω μ
      if r.status = .cont then exitIdx Q fuel r.pc r.gas r.charged r.regs r.mem else i

def exitIndex (p : ByteArray) (i : Nat) (gas : UInt64) (ch : Bool) (ω : Regs) (μ : Memory) : Nat :=
  match Blob.parse? p with
  | none => i
  | some P => exitIdx P.prepare (stepBound p i gas ch) i gas ch ω μ

def statusName : Status → String
  | .cont => "continue"
  | .halt => "halt"
  | .panic => "panic"
  | .oog => "out-of-gas"
  | .fault _ => "page-fault"
  | .host _ => "ecalli"

/-- Maximal runs of non-zero octets. -/
def memoryJson (μ : Memory) : Json := Id.run do
  let mut chunks : Array Json := #[]
  let mut cur : Option (Nat × Array Nat) := none
  for (a, v) in μ.bytes.toList do
    if v == 0 then continue
    match cur with
    | some (s, bs) =>
      if s + bs.size == a then cur := some (s, bs.push v.toNat)
      else
        chunks := chunks.push (Json.mkObj [("address", s), ("contents", Lean.toJson bs)])
        cur := some (a, #[v.toNat])
    | none => cur := some (a, #[v.toNat])
  if let some (s, bs) := cur then
    chunks := chunks.push (Json.mkObj [("address", s), ("contents", Lean.toJson bs)])
  return Json.arr chunks

def assertJson (r : Result) (pc : Nat) : Json :=
  let base : List (String × Json) :=
    [("status", Json.str (statusName r.status)),
     ("regs", Json.arr (r.regs.toArray.map fun x => (x.toNat : Json))),
     ("pc", (pc : Json)), ("memory", memoryJson r.mem), ("gas", (r.gas.toNat : Json))]
  let extra : List (String × Json) := match r.status with
    | .fault a => [("page-fault-address", (a.toNat : Json))]
    | .host h => [("hostcall", (h.toNat : Json))]
    | _ => []
  Json.mkObj [("assert", Json.mkObj (base ++ extra))]

structure VmState where
  pc : Nat
  gas : UInt64
  charged : Bool := false
  regs : Regs := Vector.replicate 13 0
  mem : Memory := .empty

def isAssertAt (steps : Array Json) (k : Nat) : Bool :=
  match steps[k]? with
  | some s => (s.getObjVal? "assert").isOk
  | none => false

/-- Run a testcase; the steps with every `assert` replaced by the observed state. -/
def execute (j : Json) : M (Array Json) := do
  let p ← bytesOf (← field j "program")
  let mut s : VmState := { pc := ← natField j "initial-pc", gas := UInt64.ofInt (← (← field j "initial-gas").getInt?) }
  let steps ← (← field j "steps").getArr?
  let mut out : Array Json := #[]
  let mut pending : Option Json := none
  let mut done := false
  for k in [0:steps.size] do
    let stepJ := steps[k]!
    let .obj kvs := stepJ | throw "bad step"
    let some (kind, body) := kvs.toArray[0]? | throw "empty step"
    match kind with
    | "run" =>
      -- After ∎ or ☇ there is nothing to resume: later runs are dropped.
      if done then continue
      out := out.push stepJ
      let r := psi p s.pc s.gas s.charged s.regs s.mem
      let e := exitIndex p s.pc s.gas s.charged s.regs s.mem
      let pc := match r.status with
        | .host _ => blobNext p e
        | _ => e
      s := { s with pc, gas := r.gas, charged := r.charged, regs := r.regs, mem := r.mem }
      done := r.status == .halt || r.status == .panic
      let a := assertJson r e
      if isAssertAt steps (k + 1) then pending := some a
      else out := out.push a
    | "assert" =>
      if let some a := pending then out := out.push a
      pending := none
    | "map" =>
      out := out.push stepJ
      let a ← natField body "address"
      let len ← natField body "length"
      let w ← (← field body "is-writable").getBool?
      if a % pageSize != 0 || len % pageSize != 0 then throw "unaligned map"
      s := { s with mem := s.mem.setPages (a / pageSize) (len / pageSize) (some (if w then .write else .read)) }
    | "write" =>
      out := out.push stepJ
      let a ← natField body "address"
      let bs ← bytesOf (← field body "contents")
      s := { s with mem := s.mem.writeN a bs.toList }
    | "set-reg" =>
      out := out.push stepJ
      let r ← natField body "reg"
      let v ← natField body "value"
      if h : r < 13 then s := { s with regs := s.regs.set r (UInt64.ofNat v) } else throw "bad register"
    | other => throw s!"unknown step {other}"
  return out

def asserts (steps : Array Json) : Array Json :=
  steps.filterMap fun s => (s.getObjVal? "assert").toOption

/-- Compare the observed asserts against the expected ones (only the fields these give). -/
def compare (exp act : Array Json) : Option String := Id.run do
  if exp.size != act.size then return some s!"{act.size} asserts, expected {exp.size}"
  for (e, a) in exp.zip act do
    let .obj kvs := e | return some "bad assert"
    for ⟨k, v⟩ in kvs.toArray do
      match a.getObjVal? k with
      | .ok w => if w != v then return some s!"{k}: got {w.compress}, expected {v.compress}"
      | .error _ => return some s!"{k}: missing, expected {v.compress}"
    for k in ["page-fault-address", "hostcall"] do
      if (a.getObjVal? k).isOk && !(e.getObjVal? k).isOk then return some s!"unexpected {k}"
  return none

def jsonFiles (paths : List String) : IO (Array System.FilePath) := do
  let mut out := #[]
  for p in paths do
    let fp : System.FilePath := p
    if ← fp.isDir then
      let es ← fp.readDir
      let fs := es.filter (fun e => e.fileName.endsWith ".json" || e.fileName.endsWith ".jsonl") |>.map (·.path)
      out := out ++ fs.qsort (·.toString < ·.toString)
    else out := out.push fp
  return out

end PvmRun

open PvmRun Lean in
def main (args : List String) : IO UInt32 := do
  let usage : IO UInt32 := do IO.eprintln "usage: pvmrun run|check FILE|DIR…"; return 2
  match args with
  | mode :: paths@(_ :: _) =>
    unless mode == "run" || mode == "check" do return ← usage
    let files ← jsonFiles paths
    let mut cases : Array (String × Json) := #[]
    for f in files do
      let text ← IO.FS.readFile f
      let pieces := if f.toString.endsWith ".jsonl" then
          (text.splitOn "\n").toArray.zipIdx.filter (fun (l, _) => l.any (fun c => !c.isWhitespace)) |>.map fun (l, n) => (s!"{f}:{n + 1}", l)
        else #[(f.toString, text)]
      for (name, t) in pieces do
        match Json.parse t with
        | .ok j => cases := cases.push (name, j)
        | .error e => throw <| IO.userError s!"{name}: {e}"
    let mut failed := 0
    let stdout ← IO.getStdout
    for (f, j) in cases do
      match execute j with
      | .error e =>
        failed := failed + 1
        IO.eprintln s!"ERROR {f}: {e}"
      | .ok steps =>
        if mode == "run" then
          stdout.putStrLn (j.setObjVal! "steps" (Json.arr steps)).compress
          stdout.flush
        else
          let exp := asserts ((j.getObjValD "steps").getArr?.toOption.getD #[])
          if let some e := compare exp (asserts steps) then
            failed := failed + 1
            IO.eprintln s!"FAIL {f}: {e}"
    if mode == "check" then
      IO.println s!"pvmrun: {cases.size - failed} of {cases.size} vectors pass"
    return if failed == 0 && cases.size > 0 then 0 else 1
  | _ => usage
