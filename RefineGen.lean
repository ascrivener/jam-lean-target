import JamTarget.Session

/-!
# `refinegen`: refine vectors (fuzzer sessions with `RefineBundle`)

`lake exe refinegen BASE OUT` reads `BASE`, a fuzzer `Initialize` message (the 0.8.0 example
sessions' `00000001_fuzzer_initialize.bin`), adds a service that holds a few tiny PVM programs as
preimages, and writes one minifuzz session per case under `OUT/<case>/`:

    00000000_fuzzer_peer_info.bin   00000000_target_peer_info.bin
    00000001_fuzzer_initialize.bin  00000001_target_state_root.bin
    00000002_fuzzer_refine_bundle.bin  00000002_target_work_report.bin (or _error.bin)

The responses are the model's (GP v0.8.0). `jam-lean-target session OUT/<case>` replays a case.
-/

open JAM JamTarget

namespace RefineGen

def blake := Refine.blake

/-! ## Programs -/

/-- p = ℰ(|j|) ⌢ ℰ_1(z) ⌢ ℰ(|c|) ⌢ j ⌢ c ⌢ k with no jump table, `code` and its bitmask `k`. -/
def pvmBlob (code : List UInt8) (starts : List Nat) : List UInt8 :=
  let k := (List.range ((code.length + 7) / 8)).map fun byte =>
    UInt8.ofNat ((List.range 8).foldl (fun acc b =>
      if starts.contains (8 * byte + b) then acc ||| (1 <<< b) else acc) 0)
  Codec.nat 0 ++ [0] ++ Codec.nat code.length ++ code ++ k

/-- The preimage of a service program: ↕**m** (empty metadata) ⌢ ℰ_3(|o|) ⌢ ℰ_3(|w|) ⌢ ℰ_2(z) ⌢
    ℰ_3(s) ⌢ o ⌢ w ⌢ ℰ_4(|p|) ⌢ p, with no data, no heap pages, a 4096-octet stack. -/
def program (code : List UInt8) (starts : List Nat) : List UInt8 :=
  let p := pvmBlob code starts
  Codec.nat 0 ++ Codec.fixed 3 0 ++ Codec.fixed 3 0 ++ Codec.fixed 2 0 ++ Codec.fixed 3 4096 ++
    Codec.fixed 4 p.length ++ p

/-- `jump_ind ω₀ 0`: halt at once (ω₀ = 2^32 − 2^16). The output is ω₇, ω₈ = the arguments. -/
def progHalt := program [50, 0] [0]
/-- `trap`: panic. -/
def progTrap := program [0] [0]
/-- `jump 0`: loop until out of gas. -/
def progLoop := program [40] [0]
/-- `ecalli 8` (export the arguments, zero-padded to a segment), then halt. The output is then
    ω₇ = 0 (the segment index), ω₈ = |a|: not readable, so empty. -/
def progExport := program [10, 8, 50, 0] [0, 2]
/-- `ecalli 8` twice: the second reads from ω₇ = the first segment's index, which is not readable,
    so it panics. -/
def progExport2 := program [10, 8, 10, 8, 50, 0] [0, 2, 4]

def h (b : List UInt8) : ByteArray := ⟨(blake b).toArray⟩

/-- The service holding the programs. -/
def sid : Nat := 1000

def programs : List (List UInt8) := [progHalt, progTrap, progLoop, progExport, progExport2]

def account : ServiceAccount :=
  { preimages := Std.ExtTreeMap.ofList (programs.map fun p => (blake p, p))
    requests := Std.ExtTreeMap.ofList (programs.map fun p => ((blake p, p.length), [0]))
    codeHash := blake progHalt, balance := 10 ^ 12, minAccGas := 0, minMemoGas := 0 }

/-! ## Packages -/

def context (slot : Nat) : RefineContext :=
  { anchorHash := ⟨(List.replicate 32 1).toArray⟩, anchorSlot := slot,
    anchorStateRoot := ⟨(List.replicate 32 2).toArray⟩,
    anchorAccOutLog := ⟨(List.replicate 32 3).toArray⟩,
    lookupAnchorHash := ⟨(List.replicate 32 4).toArray⟩, lookupAnchorSlot := slot,
    lookupAnchorStateRoot := ⟨(List.replicate 32 5).toArray⟩ }

def item (code : List UInt8) (payload : List UInt8) (gas : Nat := 100000) (exports : Nat := 0)
    (imports : List (SegmentRoot × Nat) := []) (xts : List (List UInt8) := []) : WorkItem :=
  { service := sid, codeHash := h code, payload := ⟨payload.toArray⟩, refineGasLimit := gas,
    accumulateGasLimit := 5000, exportCount := exports, importSegments := imports,
    extrinsics := xts.map fun x => (h x, x.length) }

def package (slot : Nat) (items : List WorkItem) (auth : List UInt8 := progHalt) : WorkPackage :=
  { authToken := ⟨"token".toUTF8.toList.toArray⟩, authCodeHost := sid, authCodeHash := h auth,
    authConfig := ⟨"config".toUTF8.toList.toArray⟩, context := context slot, items }

/-- A segment of 𝖶_G octets filled with `b`. -/
def seg (b : Nat) : List UInt8 := List.replicate Constants.Csegmentsize (UInt8.ofNat b)

/-- Three segments some earlier package exported: their root and J_0 paths. -/
def exported : List (List UInt8) := [seg 7, seg 8, seg 9]
def exportedRoot : ByteArray := ⟨(Refine.constRoot exported).toArray⟩
def exportedPkg : ByteArray := h "an earlier package".toUTF8.toList

structure Case where
  name : String
  core : Nat := 0
  lookup : OctetDict := ∅
  shards : Nat := 6
  bundle : Refine.Bundle

def cases (slot : Nat) : List Case :=
  let pk := package slot
  let b (items : List WorkItem) (auth := progHalt) : Refine.Bundle :=
    { package := package slot items auth, extrinsics := [], imports := [], justifications := [] }
  let pl := "payload".toUTF8.toList
  let xt := "extrinsic data".toUTF8.toList
  let imp (k : Nat) := (exported[k]!, Refine.justPath 0 exported k)
  -- GP v0.8.0 has no erasure root when nothing is exported, so most cases end with an item that
  -- exports one segment
  let ex := item progExport "exporter".toUTF8.toList (exports := 1)
  [ { name := "halt", bundle := b [item progHalt pl, ex] },
    { name := "halt_core1", core := 1, bundle := b [item progHalt pl, ex] },
    { name := "panic", bundle := b [item progTrap pl, ex] },
    { name := "out_of_gas", bundle := b [item progLoop pl (gas := 1000), ex] },
    { name := "two_items", bundle := b [item progHalt pl, item progTrap pl, ex] },
    { name := "export", bundle := b [item progExport pl (exports := 1)] },
    { name := "export_two_items",
      bundle := b [item progExport pl (exports := 1), item progExport (pl ++ pl) (exports := 1)] },
    -- one export, then a panic: v0.8.0 ⊚ (no exports on ☇), GP #568 ☇
    { name := "export_then_panic", bundle := b [item progExport2 pl (exports := 2)] },
    -- ⊚: the item exports nothing but declares one
    { name := "bad_exports", bundle := b [item progHalt pl (exports := 1)] },
    -- v0.8.0: ⊚ (|e| ≠ w_e is checked before r ∉ 𝔹); GP #568: ☇
    { name := "panic_with_exports", bundle := b [item progTrap pl (exports := 1)] },
    -- BAD: no preimage for the code hash
    { name := "no_code", bundle := b [{ item progHalt pl with codeHash := h [1, 2, 3] }, ex] },
    -- ⊖: the output (the arguments, which hold the payload) does not fit 𝖶_R
    { name := "oversize", bundle := b [item progHalt (List.replicate Constants.Cmaxreportvarsize 0x55), ex] },
    { name := "oversize_second_item",
      bundle := b [item progHalt (List.replicate 30000 1), item progHalt (List.replicate 20000 2), ex] },
    { name := "extrinsic",
      bundle := { b [item progHalt pl (xts := [xt, []]), ex] with extrinsics := [xt, []] } },
    { name := "import_by_root",
      bundle := { b [item progHalt pl (imports := [(.root exportedRoot, 1)]), ex] with
                  imports := [(imp 1).1], justifications := [(imp 1).2] } },
    { name := "import_by_package",
      lookup := Std.ExtTreeMap.ofList [(exportedPkg.toList, exportedRoot.toList)],
      bundle := { b [item progHalt pl (imports := [(.package exportedPkg, 2), (.root exportedRoot, 0)]), ex] with
                  imports := [(imp 2).1, (imp 0).1], justifications := [(imp 2).2, (imp 0).2] } },
    -- nothing exported: no erasure root in GP v0.8.0 (GP #583 later defined one)
    { name := "err_nothing_exported", bundle := b [item progHalt pl] },
    { name := "err_nothing_exported_two_items", bundle := b [item progHalt pl, item progTrap pl] },
    -- errors
    { name := "err_auth_panics", bundle := b [item progHalt pl] progTrap },
    { name := "err_extrinsic_mismatch",
      bundle := { b [item progHalt pl (xts := [xt])] with extrinsics := ["extrinsic DATA".toUTF8.toList] } },
    { name := "err_bad_justification",
      bundle := { b [item progHalt pl (imports := [(.root exportedRoot, 1)])] with
                  imports := [(imp 1).1], justifications := [(imp 0).2] } },
    { name := "err_lookup_keys",
      lookup := Std.ExtTreeMap.ofList [(exportedPkg.toList, exportedRoot.toList)],
      bundle := b [item progHalt pl] } ]
  |>.map fun c => let _ := pk; c

/-- The erasure-code weights of GP #580 (after v0.8.0; the official erasure vectors' convention),
    for cross-checks only: p of degree < d' = 2^⌈log₂ d⌉ through the d message words and zeros at
    d̃ … (d'−1)~; validator i ≥ d gets p((i + d' − d)~). The zero points contribute nothing, so
    each parity row keeps its first d weights. -/
def weights580 (v : Nat) : Array (Array Nat) :=
  let d := Erasure.originalShards v
  let d' := 2 ^ Refine.ceilLog2 d
  let parity := Erasure.lagrange (List.range d') ((List.range (v - d)).map (· + d'))
  ((List.range d).map fun i => (Array.range d).map fun j => if i = j then 1 else 0).toArray ++
    parity.map (·.extract 0 d)

/-- The other reading of PR #214's wire format: the three sequences and each extrinsic
    with the codec's length prefixes, as the ASN `SEQUENCE OF` / `ByteSequence` would give. For
    cross-checks only (`refinegen BASE OUT --prefixed`); the target reads the GP bundle encoding. -/
def encodePrefixed (q : Refine.Request) : List UInt8 :=
  Codec.fixed 2 q.core ++ Codec.varHashDict q.lookup ++ Codec.fixed 2 q.shards ++
    q.bundle.package.encode ++ Codec.varSeq (fun x => Codec.nat x.length ++ x) q.bundle.extrinsics ++
    Codec.varSeq id q.bundle.imports ++ Codec.varSeq (Codec.varSeq id) q.bundle.justifications

/-- A with the erasure code of GP #580 and, when nothing is exported, GP #583's **s**♣ (v zero
    hashes): the report after those later GP changes, for comparison tooling only. -/
def specPost080 (v : Nat) (h b : List UInt8) (s : List (List UInt8)) :
    Except Refine.Failure AvailabilitySpec :=
  match Refine.availabilityWith (weights580 v) h b s v with
  | some a => pure a
  | none => throw (.bundle "erasure coding failed")

end RefineGen

open RefineGen

def writeBin (p : System.FilePath) (b : List UInt8) : IO Unit := IO.FS.writeBinFile p ⟨b.toArray⟩

def pad8 (n : Nat) : String := let t := toString n; String.ofList (List.replicate (8 - t.length) '0') ++ t

def main (args : List String) : IO UInt32 := do
  let (base, out, prefixed) ← match args with
    | [b, o] => pure (b, o, false)
    | [b, o, "--prefixed"] => pure (b, o, true)
    | _ => IO.eprintln "usage: refinegen BASE-INITIALIZE.bin OUT-DIR [--prefixed]"; return 2
  let some params := paramsOf "tiny" | return 1
  let msg ← IO.FS.readBinFile base
  let .ok (.initialize hdr raw _) := Decoder.run (Request.decode params) msg
    | IO.eprintln "BASE is not an Initialize message"; return 1
  let .ok d := StateDecode.decode params raw | IO.eprintln "state does not decode"; return 1
  let σ := { d.state with accounts := d.state.accounts.insert sid account }
  let initMsg := 1 :: hdr.encode ++ encodeRawState σ.serializeList ++ Codec.nat 0
  let peer : PeerInfo := { fuzzVersion := 1, features := 7, jamVersion := ⟨0, 8, 0⟩,
                           appVersion := ⟨0, 1, 0⟩, appName := "refinegen" }
  let dir := System.FilePath.mk out
  IO.FS.createDirAll dir
  let s0 : Session := { params }
  let (s1, r0, _) := s0.handle (.peerInfo peer)
  let .ok req1 := Decoder.run (Request.decode params) ⟨initMsg.toArray⟩ | return 1
  let (s, r1, _) := s1.handle req1
  writeBin (dir / "00000000_fuzzer_peer_info.bin") (0 :: peer.encode)
  writeBin (dir / "00000000_target_peer_info.bin") ((r0.map Response.encode).getD [])
  writeBin (dir / "00000001_fuzzer_initialize.bin") initMsg
  writeBin (dir / "00000001_target_state_root.bin") ((r1.map Response.encode).getD [])
  let mut index : List String :=
    ["Responses are GP v0.8.0's. `NNNNNNNN_post080_work_report.bin` (not a response) is the report",
     "after GP #580 (erasure code) and GP #583 (erasure root when nothing is exported), for",
     "comparison tooling only.", "",
     "| # | case | response | summary |",
     "|---|------|----------|---------|"]
  let mut n := 2
  for c in cases hdr.slot do
    let q : Refine.Request := { core := c.core, lookup := c.lookup, shards := c.shards, bundle := c.bundle }
    let qMsg := 6 :: q.encode
    -- through the decoder, as the target sees it
    let .ok req := Decoder.run (Request.decode params) ⟨qMsg.toArray⟩
      | IO.eprintln s!"{c.name}: the request does not decode"; return 1
    let t0 ← IO.monoMsNow
    let (_, r, log) := s.handle req
    let rb := (r.map Response.encode).getD []
    let t1 ← IO.monoMsNow
    let kind := if rb.headD 0 == 7 then "work_report" else "error"
    writeBin (dir / s!"{pad8 n}_fuzzer_refine_bundle.bin") (if prefixed then 6 :: encodePrefixed q else qMsg)
    writeBin (dir / s!"{pad8 n}_target_{kind}.bin") rb
    IO.println s!"{pad8 n} {c.name}: {kind} ({t1 - t0} ms) {String.intercalate "; " log}"
    let summary := match r with
      | some (.workReport w) =>
        let items := w.digests.map fun (dg : WorkDigest) => match dg.result with
          | .ok o => s!"ok ({o.size} octets, gas {dg.gasUsed})"
          | .err e => s!"{(reprStr e).replace "JAM.WorkError." ""} (gas {dg.gasUsed})"
        s!"items: {String.intercalate ", " items}; bundle {w.spec.bundleLength} octets, {w.spec.segmentCount} exports"
      | some (.error m) => m
      | _ => ""
    -- the report after GP #580 / #583, for comparison tooling (not a response)
    let post := Refine.xiWith (specPost080 c.shards) params σ.accounts c.core c.lookup c.shards c.bundle
    if let .ok w := post then
      if (some (Response.workReport w)).map Response.encode != r.map Response.encode then
        writeBin (dir / s!"{pad8 n}_post080_work_report.bin") (7 :: w.encode)
    index := index ++ [s!"| {pad8 n} | {c.name} | {kind} | {summary} |"]
    n := n + 1
  IO.FS.writeFile (dir / "CASES.md") (String.intercalate "\n" index ++ "\n")
  return 0
