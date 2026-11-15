import JAM.BlockImport
import JAM.Sha512
import JamTarget.Wire
import JamTarget.StateDecode
import JamCrypto.Ring
import JamCrypto.Crypto

/-!
# One fuzzer session

The target's state for one connection: the states it holds by header hash (forks of depth 1 make
the parent of a block not always the last block imported), the headers each state's chain retains
(the ancestor set 𝒜 of GP §11.4.1), and the ring roots it knows.

Block import is jam-lean's Υ (`JAM.importBlock`, GP §4–§5), unchanged.

## Cryptography

`JAM.Crypto` is a parameter of Υ. The session's `crypto` (`sessionCrypto`) is all in plain Lean
(`JamCrypto`): Ed25519 under ZIP-215 rules (Adam's decision 2026-11-15), the Bandersnatch IETF VRF,
the ring root O(**k**) for the chain's V validators, and Ring VRF proofs (GP §3.8, Appendix G).
-/

namespace JamTarget

open JAM

/-- The crypto stand-ins for what is not yet implemented (see the module note). -/
def oracleCrypto : Crypto :=
  { edVerify := fun _ _ _ => true
    bsVerify := fun _ _ _ _ => true
    bsOut := Sha512.vrfOutput
    bsRingRoot := fun _ => []
    bsRingVerify := fun _ _ _ _ => true
    bsRingOut := Sha512.vrfOutput }

/-- V, the number of validators: 6 for the tiny chain (the vectors' convention), 1023 for the full
    chain (GP `Cvalcount`). The ring domain is sized by V (see docs/crypto-notes.md). -/
def validatorsOf (p : Params) : Nat := if p.coreCount == 2 then 6 else 1023

/-- The session's crypto: everything in plain Lean. -/
def sessionCrypto (srs : JamCrypto.Ring.Srs) (p : Params) : Crypto :=
  JamCrypto.withSignatures (JamCrypto.Ring.crypto srs (validatorsOf p) oracleCrypto)

/-- A state the target holds: σ after the block with this header, and the headers 𝒜 its chain
    retains (oldest first, ending with this block's header). -/
structure Entry where
  hash : List UInt8
  header : Header
  state : State
  ancestors : List Header

/-- The session. -/
structure Session where
  params : Params
  /-- The cryptographic primitives (`sessionCrypto`). -/
  crypto : Crypto := oracleCrypto
  /-- The features both peers support. -/
  features : Nat := 0
  initialized : Bool := false
  /-- The states held, most recent first. -/
  entries : List Entry := []
  /-- Ring roots: (Bandersnatch keys of γ_P, γ_Z) of every state seen. -/
  roots : List (List (List UInt8) × List UInt8) := []
  /-- Ancestry items of `Initialize` (slot, hash): not headers, so the GP's condition on 𝒜 cannot
      be checked against them (see `docs/gaps.md`). -/
  ancestry : List AncestryItem := []

/-- At most this many states are kept. The fuzzer extends the chain only from original blocks and
    forks have depth 1, so a handful suffices. -/
def maxEntries : Nat := 16

/-- The parameters for `JAM_FUZZ_SPEC`. For `tiny`, 𝖫 = 24 as the fuzzer protocol specifies
    (fuzz-proto README, "Ancestry"); the GP defines only the full chain. -/
def paramsOf (spec : String) : Option Params :=
  match spec with
  | "tiny" => some { Params.tiny with maxLookupAnchorAge := 24 }
  | "full" => some Params.full
  | _ => none

def ourInfo (features : Nat) : PeerInfo :=
  { fuzzVersion := 1, features, jamVersion := { major := 0, minor := 8, patch := 0 },
    appVersion := { major := 0, minor := 1, patch := 0 }, appName := "jam-lean" }

/-- The features the target supports. Ancestry is advertised: headers imported in the session
    are retained as 𝒜; `Initialize` ancestry items are kept but carry no header. -/
def supportedFeatures : Nat := featureAncestry ||| featureFork

def Session.noteRoots (s : Session) (σ : State) : Session :=
  let key := σ.pending.map ValidatorKey.bs
  if s.roots.any (·.1 == key) || σ.ringRoot.isEmpty then s
  else { s with roots := (key, σ.ringRoot) :: s.roots }

def hex (l : List UInt8) : String :=
  "0x" ++ String.join (l.map fun b =>
    (if b < 16 then "0" else "") ++ String.ofList (Nat.toDigits 16 b.toNat))

/-- What the session logs (to stderr). -/
abbrev Log := List String

/-- Handle one request. `none` means the session must end (closing the connection). -/
def Session.handle (s : Session) (r : Request) : Session × Option Response × Log :=
  match r with
  | .peerInfo p =>
    let f := p.features &&& supportedFeatures
    ({ s with features := f }, some (.peerInfo (ourInfo supportedFeatures)),
      [s!"peer {p.appName} fuzz v{p.fuzzVersion} features {p.features} jam {p.jamVersion.major}.{p.jamVersion.minor}.{p.jamVersion.patch}"])
  | .initialize h raw anc =>
    if s.initialized then (s, none, ["second Initialize in a session: closing"]) else
    match StateDecode.decode s.params raw with
    | .error e => (s, none, [s!"Initialize: state cannot be decoded: {e}"])
    | .ok d =>
      let σ := d.state
      let rawRoot := StateDecode.rawRoot raw
      let log := (if d.unplaced.isEmpty then [] else
          [s!"Initialize: {d.unplaced.length} entries cannot be placed in σ (storage keys are hashed in T); the model's state is incomplete"]) ++
        (if σ.root == rawRoot then [] else [s!"Initialize: M_σ(σ) = {hex σ.root} ≠ M(raw) = {hex rawRoot}"])
      let e : Entry := { hash := h.hash, header := h, state := σ, ancestors := [h] }
      let s' := { s with initialized := true, entries := [e], ancestry := anc }.noteRoots σ
      -- M_σ(σ) of the model's σ: if the model lost entries it differs from M(raw), and the
      -- fuzzer sees the difference at once.
      (s', some (.stateRoot σ.root), log)
  | .importBlock b =>
    let H := b.header
    match s.entries.find? (·.hash == H.parent.toList) with
    | none => (s, some (.error s!"unknown parent {hex H.parent.toList}"), [s!"import slot {H.slot}: unknown parent"])
    | some par =>
      let L := s.params.maxLookupAnchorAge
      let chain : Chain := { ancestors := par.ancestors }
      match importBlock s.params s.crypto chain par.state b with
      | .error err =>
        (s, some (.error (reprStr err)), [s!"import slot {H.slot}: rejected: {reprStr err}"])
      | .ok (σ', _) =>
        let hh := H.hash
        if s.entries.any (·.hash == hh) then
          (s, some (.stateRoot σ'.root), [s!"import slot {H.slot}: already imported"])
        else
        let anc := (par.ancestors ++ [H]).reverse.take L |>.reverse
        let e : Entry := { hash := hh, header := H, state := σ', ancestors := anc }
        let s' := { s with entries := (e :: s.entries).take maxEntries }.noteRoots σ'
        (s', some (.stateRoot σ'.root), [s!"import slot {H.slot}: ok {hex σ'.root}"])
  | .getState hh =>
    match s.entries.find? (·.hash == hh) with
    | some e => (s, some (.state e.state.serializeList), [s!"GetState {hex hh}"])
    | none => (s, none, [s!"GetState for an unknown header {hex hh}: closing"])

end JamTarget
