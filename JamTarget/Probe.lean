import JamTarget.CraftCli

/-!
# Block-level probes of findings F4 and F6 (docs/findings.md)

A probe is the fuzzer's genesis state with two additions, then one crafted block:

* a service `probeService` whose code is ℰ(↕[]) ⌢ a standard program (GP §A.7: no RO/RW data,
  no heap pages, a 4096-octet stack) around the probe's PVM blob;
* a work report for it pending on core 0 (ρ[0], reported at slot 0, guaranteed by validators 0, 1
  and 2 of κ with valid signatures), whose one digest has result ok([]) and gas limit `probeGas`.

The block (slot 1) carries assurances by validators 0–4 for core 0: 5 > ⅔·6, so the report is
available, has no prerequisites, and accumulates at once: Ψ_A runs the probe's code from
instruction 5 with `probeGas`. The accumulation statistics π_S[s] then record the gas used,
which enters the state root.

| kind | code (from instruction 5) | GP v0.8.1 (as v0.8.0) |
| --- | --- | --- |
| `control` | `jump_ind ω0` (ω0 = 2³² − 2¹⁶) | halt |
| `panic` | `trap` | charge the block, ☇ |
| `oog` | `jump` to itself | ∞; ϱ' = the gas left when a block's cost exceeds it (§A.4), u = g − ϱ' |
| `f4` | `fallthrough` as the last instruction | charge the block, ☇ (blob valid) |
| `f6` | `load_imm ω1, 2; jump_ind ω1` with \|j\| = 1, z = 0 | j₀ = 0: jump to 0, which loops: ∞ as `oog` |
-/

namespace JamTarget.Probe

open JAM JamTarget JamTarget.Craft

def ba (l : List UInt8) : ByteArray := ⟨l.toArray⟩

/-- The service id of the probe service. -/
def probeService : Nat := 0x0b0b0b0b

/-- The digest's accumulate gas limit g. -/
def probeGas : Nat := 100000

/-- deblob's encoding: ℰ(|j|) ⌢ ℰ_1(z) ⌢ ℰ(|c|) ⌢ ℰ_z(j) ⌢ c ⌢ k (GP §A.2), for one-octet lengths. -/
def pvmBlob (jLen z : Nat) (code : List UInt8) (starts : List Nat) : List UInt8 :=
  let k := (List.range ((code.length + 7) / 8)).map fun i =>
    UInt8.ofNat ((List.range 8).foldl (fun a b => a + if starts.contains (8 * i + b) then 2 ^ b else 0) 0)
  [UInt8.ofNat jLen, UInt8.ofNat z, UInt8.ofNat code.length] ++ List.replicate (jLen * z) 0 ++ code ++ k

/-- The PVM blob of each probe. -/
def blobOf : String → Option (List UInt8)
  -- 0–4: fallthrough; 5: jump_ind ω0, 0
  | "control" => some (pvmBlob 0 0 [1, 1, 1, 1, 1, 50, 0] [0, 1, 2, 3, 4, 5])
  -- 0–5: fallthrough; the last instruction falls off the end (F4)
  -- 0–4: fallthrough; 5: trap (☇ after charging the block; the control of F4)
  | "panic" => some (pvmBlob 0 0 [1, 1, 1, 1, 1, 0] [0, 1, 2, 3, 4, 5])
  -- 0–4: fallthrough; 5: jump 5 (a loop: ∞; the control of F6)
  | "oog" => some (pvmBlob 0 0 [1, 1, 1, 1, 1, 40] [0, 1, 2, 3, 4, 5])
  | "f4" => some (pvmBlob 0 0 [1, 1, 1, 1, 1, 1] [0, 1, 2, 3, 4, 5])
  -- 0: jump 0 (a loop); 1–4: fallthrough; 5: load_imm ω1, 2; 8: jump_ind ω1, 0; |j| = 1, z = 0 (F6)
  | "f6" => some (pvmBlob 1 0 [40, 1, 1, 1, 1, 51, 1, 2, 50, 1] [0, 1, 2, 3, 4, 5, 8])
  | _ => none

open Codec in
/-- The service code blob: ℰ(↕m) with m = [], then the standard program
    ℰ_3(|o|) ⌢ ℰ_3(|w|) ⌢ ℰ_2(z) ⌢ ℰ_3(s) ⌢ o ⌢ w ⌢ ℰ_4(|p|) ⌢ p (GP §A.7, §9). -/
def codeBlob (pvm : List UInt8) : List UInt8 :=
  nat 0 ++ fixed 3 0 ++ fixed 3 0 ++ fixed 2 0 ++ fixed 3 4096 ++ fixed 4 pvm.length ++ pvm

/-- The pending report on core 0. -/
def probeReport (σ : State) (genesisHash : List UInt8) (codeHash : List UInt8) : WorkReport :=
  let ctx : RefineContext :=
    { anchorHash := ba genesisHash, anchorSlot := 0, anchorStateRoot := ba σ.root,
      anchorAccOutLog := ba (List.replicate 32 0), lookupAnchorHash := ba genesisHash,
      lookupAnchorSlot := 0, lookupAnchorStateRoot := ba σ.root }
  { spec := { packageHash := ba (hashL "jam-lean-target probe package".toUTF8.toList),
              bundleLength := 0, erasureRoot := ba (List.replicate 32 0), erasureShards := 0,
              segmentRoot := ba (List.replicate 32 0), segmentCount := 0 },
    context := ctx, core := 0,
    authorizerHash := ba ((σ.authPools.headD []).headD (List.replicate 32 0)),
    authTrace := ByteArray.empty,
    digests := [{ service := probeService, codeHash := ba codeHash, payloadHash := ba (hashL []),
                  gasLimit := probeGas, result := .ok ByteArray.empty, gasUsed := 0,
                  importCount := 0, extrinsicCount := 0, extrinsicSize := 0, exportCount := 0 }],
    authGasUsed := 0 }

/-- The probe's initial state and its block. -/
def build (p : Params) (σ : State) (genesis : Header) (kind : String) :
    Except String (State × List BlockSpec) := do
  let some pvm := blobOf kind | throw s!"unknown probe {kind} (control, panic, oog, f4, f6)"
  let code := codeBlob pvm
  let h := hashL code
  let acct : ServiceAccount :=
    ({ codeHash := h, balance := 10 ^ 12, minAccGas := 0, minMemoGas := 0,
       preimages := (∅ : Std.ExtTreeMap (List UInt8) (List UInt8)).insert h code } : ServiceAccount
    ).requestSet h code.length [0]
  let r := probeReport σ genesis.hash h
  let g ← signGuarantee (devKeys σ.active.length) σ.active r 0 [0, 1, 2]
  let avail := (List.range p.coreCount).map fun c =>
    if c == 0 then some ({ guarantee := g, time := 0 } : AvailAssignment) else none
  let σ' := { σ with accounts := σ.accounts.insert probeService acct, avail }
  let bits := (List.range p.coreCount).map (· == 0)
  return (σ', [{ slot := some (σ.tau + 1), assurances := (List.range 5).map (·, bits) }])

end JamTarget.Probe
