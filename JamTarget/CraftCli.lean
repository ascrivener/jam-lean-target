import JamTarget.Craft

/-!
# The crafter's front end: fuzzer-protocol sessions from a description

`craftSession` starts from an `Initialize` (genesis header and state), optionally edits σ, then
crafts one block per `BlockSpec` on top of the previous one and imports each through the target's
own session handler (jam-lean's Υ). It writes the session in the minifuzz format of jam-fuzzing
`fuzz-proto/examples` (raw, unframed messages):

* `00000000_fuzzer_peer_info.bin` (and the model's `00000000_target_peer_info.bin`), `00000001_fuzzer_initialize.bin`,
  `0000000N_fuzzer_import_block.bin`;
* the model's answers `0000000N_target_state_root.bin` / `_target_error.bin` (GP v0.8.0's), so
  `jam-lean-target session DIR` and `scripts/drive.py DIR` compare any target against the model;
* `signatures.txt`: every signature of every block (`ed KEY MSG SIG` / `bs KEY CTX MSG SIG`), for
  `JamCryptoTest/generator verify` (ed25519-dalek and ark-vrf);
* `trace/genesis.bin` = ℰ(genesis header, initial state) and `trace/NNNNNNNN.bin`: each imported block as a fuzz-reports trace step
  ℰ(pre-state, block, post-state), each state ℰ(root, ↕[(key, ↕value)]), for
  `jam-lean-target trace DIR`;
* `expected_state.bin`: the model's answer to GetState for the last block (a State message), and
  `last_header_hash.txt` that block's header hash (hex).

The text description (`craft SPEC OUTDIR`), one directive per line, `#` comments:

```
init PATH            Initialize message (.bin, tag 1): genesis header and state
block                start a block (on top of the previous one)
slot N               H_T (default τ + 1)
assure V BITS        an assurance by validator V, BITS one 0/1 per core (e.g. 10)
guarantee PATH T V…  a guarantee of the report ℰ(r) in PATH (binary), slot T, by validators V…
preimage S PATH      a preimage for service S
```
-/

namespace JamTarget.CraftCli

open JAM JamTarget JamTarget.Craft

open Codec in
/-- ℰ of a request (without its length prefix). -/
def encodeInitialize (h : Header) (kvs : RawState) : List UInt8 :=
  1 :: (h.encode ++ encodeRawState kvs ++ nat 0)

def encodeImport (b : Block) : List UInt8 := 3 :: b.encode

/-- The fuzzer's PeerInfo: fuzz v1, features ancestry and fork, JAM 0.8.0. -/
def fuzzerPeerInfo : List UInt8 :=
  0 :: ({ fuzzVersion := 1, features := featureAncestry ||| featureFork,
          jamVersion := { major := 0, minor := 8, patch := 0 },
          appVersion := { major := 0, minor := 1, patch := 0 }, appName := "jam-lean-craft" } : PeerInfo).encode

def pad8 (n : Nat) : String := let s := toString n; String.ofList (List.replicate (8 - s.length) '0') ++ s

def writeBin (path : System.FilePath) (b : List UInt8) : IO Unit := IO.FS.writeBinFile path ⟨b.toArray⟩

open Codec in
def encodeStateR (σ : State) : List UInt8 := σ.root ++ encodeRawState σ.serializeList

/-- The result of a crafted session. -/
structure Crafted where
  /-- (header hash, model response) per block. -/
  steps : List (List UInt8 × Response)
  /-- All signatures valid under the `JamCrypto` verifiers. -/
  sigsOk : Bool
  /-- The last posterior state. -/
  post : State
  /-- The initial state (after edits). -/
  pre : State
  blocks : List Block
  log : List String

/-- Craft and import the blocks; write the session to `out`. -/
def craftSession (s0 : Session) (genesis : Header) (σ0 : State) (specs : List BlockSpec)
    (out : System.FilePath) : IO Crafted := do
  let p := s0.params
  let keys := devKeys σ0.active.length
  IO.FS.createDirAll out
  writeBin (out / "00000000_fuzzer_peer_info.bin") fuzzerPeerInfo
  writeBin (out / "00000000_target_peer_info.bin") (Response.peerInfo (ourInfo supportedFeatures)).encode
  let kvs := σ0.serializeList
  writeBin (out / "00000001_fuzzer_initialize.bin") (encodeInitialize genesis kvs)
  let (s1, r1, log1) := s0.handle (.initialize genesis kvs [])
  let some r1 := r1 | throw (IO.userError s!"Initialize refused: {log1}")
  writeBin (out / "00000001_target_state_root.bin") r1.encode
  let mut s := s1
  let mut parent := genesis
  let mut σ := (s1.entries.head?.map (·.state)).getD σ0
  let mut steps := []
  let mut sigLines : List String := []
  let mut sigsOk := true
  let mut log := log1
  let mut blocks := []
  let mut n := 2
  IO.FS.createDirAll (out / "trace")
  writeBin (out / "trace" / "genesis.bin") (genesis.encode ++ encodeStateR σ)
  for spec in specs do
    let b ← match craftBlock p s.crypto keys parent σ spec with
      | .ok b => pure b
      | .error e => throw (IO.userError s!"block {n - 1}: {e}")
    match signatures p s.crypto σ b with
    | .ok (ls, ok) => sigLines := sigLines ++ ls; sigsOk := sigsOk && ok
    | .error e => throw (IO.userError s!"block {n - 1}: {e}")
    writeBin (out / s!"{pad8 n}_fuzzer_import_block.bin") (encodeImport b)
    let (s', r, l) := s.handle (.importBlock b)
    log := log ++ l
    let some r := r | throw (IO.userError s!"block {n - 1}: no response")
    let kind := match r with | .error _ => "error" | _ => "state_root"
    writeBin (out / s!"{pad8 n}_target_{kind}.bin") r.encode
    steps := steps ++ [(b.header.hash, r)]
    blocks := blocks ++ [b]
    match r with
    | .stateRoot _ =>
      s := s'
      parent := b.header
      let σ' := ((s'.entries.find? (·.hash == b.header.hash)).map (·.state)).getD σ
      writeBin (out / "trace" / s!"{pad8 (n - 1)}.bin") (encodeStateR σ ++ b.encode ++ encodeStateR σ')
      σ := σ'

    | _ => pure ()
    n := n + 1
  IO.FS.writeFile (out / "signatures.txt") (String.intercalate "\n" sigLines ++ "\n")
  writeBin (out / "expected_state.bin") (Response.state σ.serializeList).encode
  IO.FS.writeFile (out / "last_header_hash.txt") (((hex parent.hash).drop 2).toString ++ "\n")
  return { steps, sigsOk, post := σ, pre := σ0, blocks, log }

def hexDigit (c : Char) : Nat :=
  if c.isDigit then c.toNat - '0'.toNat else c.toLower.toNat - 'a'.toNat + 10

/-- The genesis header and state of an `Initialize` message. -/
def readInitialize (p : Params) (path : System.FilePath) : IO (Header × RawState) := do
  match Decoder.run (Request.decode p) (← IO.FS.readBinFile path) with
  | .ok (.initialize h kvs _) => return (h, kvs)
  | .ok _ => throw (IO.userError s!"{path}: not an Initialize message")
  | .error e => throw (IO.userError s!"{path}: {e}")

def decodeState (p : Params) (kvs : RawState) : IO State := do
  match JAM.StateDecode.decodeState p kvs with
  | .ok σ => return σ
  | .error e => throw (IO.userError e)

/-- Parse the text description. Returns the Initialize path and the block specs. -/
def parseSpec (p : Params) (text : String) : IO (Option String × List BlockSpec) := do
  let mut init := none
  let mut specs : List BlockSpec := []
  for raw in text.splitOn "\n" do
    let line := ((raw.splitOn "#").headD "").trimAscii.toString
    if line.isEmpty then continue
    let ws := (line.splitOn " ").filter (· ≠ "")
    let upd (f : BlockSpec → IO BlockSpec) : IO (List BlockSpec) := do
      match specs.getLast? with
      | none => throw (IO.userError s!"'{line}' before any 'block'")
      | some b => return specs.dropLast ++ [← f b]
    match ws with
    | ["init", path] => init := some path
    | ["block"] => specs := specs ++ [({} : BlockSpec)]
    | ["slot", n] => specs ← upd fun b => pure { b with slot := n.toNat? }
    | ["assure", v, bits] =>
      specs ← upd fun b => pure { b with assurances := b.assurances ++ [(v.toNat!, bits.toList.map (· == '1'))] }
    | "guarantee" :: path :: t :: vs =>
      let bytes ← IO.FS.readBinFile path
      let r ← match Decoder.run WorkReport.decode bytes with
        | .ok r => pure r
        | .error e => throw (IO.userError s!"{path}: {e}")
      specs ← upd fun b => pure { b with guarantees := b.guarantees ++ [(r, t.toNat!, vs.map String.toNat!)] }
    | ["preimage", sv, path] =>
      let d ← IO.FS.readBinFile path
      specs ← upd fun b => pure { b with preimages := b.preimages ++ [(sv.toNat!, d.toList)] }
    | _ => throw (IO.userError s!"cannot parse '{line}'")
  let _ := p
  return (init, specs)

end JamTarget.CraftCli
