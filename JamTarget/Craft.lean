import JAM.BlockImport
import JamCrypto.DevKeys
import JamTarget.Session

/-!
# Crafting valid blocks (GP v0.8.1)

Given a state σ, the parent header and a description of the extrinsic, `craftBlock` builds a block
that GP v0.8.1 accepts, signed with the JIP-5 development keys (`JamCrypto.DevKeys`):

* H_P = ℋ(parent), H_R = M_σ(σ), H_X = the extrinsic hash (GP eq. `extrinsichash`);
* H_E and H_W as Safrole gives them for the slot, H_O = [] (no disputes);
* the author: in fallback mode the slot's key γ_S'[H_T mod 𝖤]; in ticket mode the validator whose
  VRF output for the slot's ticket context equals the ticket's identifier; H_I its index in κ';
* H_V ∈ 𝔹̄_{H_A}⟨X_E ⌢ Y(H_S)⟩⟨[]⟩, then H_S ∈ 𝔹̄_{H_A}⟨X_F ⌢ η'_3⟩⟨ℰ_U(H)⟩ (or the ticket
  context) — Y(H_S) depends only on the key and the context, so H_V is signed first. The
  signatures are the Thin VRF of GP v0.8.1 (VRF spec Draft 35, its vectors' reading `rd`, the one
  the target uses; 96 octets O ⌢ R ⌢ s, graypaper#593);
* assurances (no anchor, GP #562): a_s over X_A ⌢ ℋ(ℰ(H_P, a_f)) by κ[a_v]'s Ed25519 key;
* guarantees: each credential over X_G ⌢ ℋ(ℰ(r)) by κ'[v] (or λ', as the caller chooses the
  indices; the crafter only signs).

Every key must be one of the development keys; other validators cannot sign. `checkBlock` runs
jam-lean's Υ on the result and re-verifies every signature with the `JamCrypto` verifiers.
-/

namespace JamTarget.Craft

open JAM JamCrypto

/-- The reading of the VRF spec's Draft 35 the crafter signs and checks with (the target's, see
    `sessionCrypto`). -/
def rd : Reading := .vectors

/-- What the caller chooses for one block. -/
structure BlockSpec where
  /-- H_T; default τ + 1. -/
  slot : Option Nat := none
  /-- (a_v, a_f) per assurance, in ascending a_v. -/
  assurances : List (Nat × List Bool) := []
  /-- (report, t, validator indices) per guarantee. -/
  guarantees : List (WorkReport × Nat × List Nat) := []
  /-- (s, p) per preimage. -/
  preimages : List (Nat × List UInt8) := []

/-- The development keys of the first `n` validators (n ≤ 1023), computed lazily by key lookup. -/
def devKeys (n : Nat) : List DevKeys.DevKey := (List.range n).map DevKeys.dev

/-- The dev key whose Ed25519 key is `ed`. -/
def byEd (keys : List DevKeys.DevKey) (ed : List UInt8) : Except String DevKeys.DevKey :=
  match keys.find? (·.ed == ed) with
  | some k => .ok k
  | none => .error s!"no development key for Ed25519 key {hex ed}"

/-- The dev key whose Bandersnatch key is `bs`. -/
def byBs (keys : List DevKeys.DevKey) (bs : List UInt8) : Except String DevKeys.DevKey :=
  match keys.find? (·.bs == bs) with
  | some k => .ok k
  | none => .error s!"no development key for Bandersnatch key {hex bs}"

def ba (l : List UInt8) : ByteArray := ⟨l.toArray⟩

/-- The signature of an Ed25519 credential on a report: X_G ⌢ ℋ(ℰ(r)). -/
def guaranteeMessage (r : WorkReport) : List UInt8 := Xguarantee ++ hashL r.encode

/-- A guarantee of `r` at slot `t`, signed by the given validators of `vals` (κ' or λ'). -/
def signGuarantee (keys : List DevKeys.DevKey) (vals : List ValidatorKey) (r : WorkReport) (t : Nat)
    (who : List Nat) : Except String Guarantee := do
  let cred ← who.mapM fun v => do
    let k ← byEd keys (vals.getD v ValidatorKey.null).ed
    return (v, ba (Ed25519.sign k.edSeed (guaranteeMessage r)))
  return { report := r, slot := t, credential := cred }

/-- Build a block on `parent` (whose posterior state is σ). -/
def craftBlock (p : Params) (c : Crypto) (keys : List DevKeys.DevKey) (parent : Header) (σ : State)
    (spec : BlockSpec) : Except String Block := do
  let slot := spec.slot.getD (σ.tau + 1)
  let parentHash := parent.hash
  -- Safrole for the slot. Its γ_S', κ', η'_3 and markers do not depend on the block's entropy
  -- contribution, so a placeholder is used here; Υ recomputes them with the real one.
  let sIn : SafroleInput :=
    { slot, entropy := List.replicate 32 0, tickets := [], offenders := σ.disputes.offenders.toList }
  let (saf', sOut) ← match safrole p c σ.safrole sIn with
    | .ok x => pure x
    | .error e => throw s!"safrole: {reprStr e}"
  let eta3 := saf'.eta.getD 3 []
  -- The author and its seal context.
  let (author, sealCtx) ← match saf'.sealKeys with
    | .keys ks =>
      let bs := ks.getD (slot % p.epochLen) []
      pure (← byBs keys bs, Xfallback ++ eta3)
    | .tickets ts =>
      let some tk := ts[slot % p.epochLen]? | throw "no ticket for the slot"
      let ctx := ticketContext eta3 tk.attempt
      match keys.find? (fun k => Bandersnatch.Thin.signOutput k.bsSecret ctx rd == some tk.id.toList) with
      | some k => pure (k, ctx)
      | none => throw "the slot's ticket belongs to no development key"
  let some authorIndex := saf'.active.findIdx? (·.bs == author.bs)
    | throw "the author is not in κ'"
  let some yS := Bandersnatch.Thin.signOutput author.bsSecret sealCtx rd | throw "hash-to-curve failed"
  let some vrfSig := Bandersnatch.Thin.sign author.bsSecret (Xentropy ++ yS) [] rd | throw "hash-to-curve failed"
  -- The extrinsic.
  let assurances ← spec.assurances.mapM fun (v, bits) => do
    let k ← byEd keys (σ.active.getD v ValidatorKey.null).ed
    return ({ bitfield := bits, assurer := v,
              signature := ba (Ed25519.sign k.edSeed (assuranceMessage (ba parentHash) bits)) } : Assurance)
  let guarantees ← spec.guarantees.mapM fun (r, t, who) =>
    -- κ' for guarantees of the current rotation, λ'... the caller picks indices of κ'.
    signGuarantee keys saf'.active r t who
  let X : Extrinsic :=
    { tickets := [], disputes := { verdicts := [], culprits := [], faults := [] },
      preimages := spec.preimages.map fun (s, d) => { requester := s, blob := ba d },
      assurances, guarantees }
  let H0 : Header :=
    { parent := ba parentHash, priorStateRoot := ba σ.root, extrinsicHash := ba X.hash, slot,
      epochMark := sOut.epochMark, winnersMark := sOut.ticketsMark, offendersMark := [],
      authorIndex, vrfSig := ba vrfSig, sealSig := ByteArray.empty }
  let some sealSig := Bandersnatch.Thin.sign author.bsSecret sealCtx H0.encodeUnsigned rd
    | throw "hash-to-curve failed"
  return { header := { H0 with sealSig := ba sealSig }, extrinsic := X }

/-- Every signature of a crafted block, as `ed KEY MSG SIG` / `bs KEY CTX MSG SIG` lines (hex, `-`
    for empty), for an outside check (`JamCryptoTest/generator` `verify`), and whether the
    `JamCrypto` verifiers accept them all. -/
def signatures (p : Params) (c : Crypto) (σ : State) (b : Block) : Except String (List String × Bool) := do
  let H := b.header
  let sIn : SafroleInput :=
    { slot := H.slot, entropy := c.bsOut H.vrfSig.toList, tickets := [],
      offenders := σ.disputes.offenders.toList }
  let (saf', _) ← match safrole p c σ.safrole sIn with
    | .ok x => pure x
    | .error e => throw s!"safrole: {reprStr e}"
  let h (l : List UInt8) := if l.isEmpty then "-" else ((hex l).drop 2).toString
  let eta3 := saf'.eta.getD 3 []
  let author := (saf'.active.getD H.authorIndex ValidatorKey.null).bs
  let sealCtx := match saf'.sealKeys with
    | .keys _ => Xfallback ++ eta3
    | .tickets ts => ticketContext eta3 ((ts[H.slot % p.epochLen]?.map (·.attempt)).getD 0)
  let yS := Bandersnatch.Thin.vrfOutput H.sealSig.toList
  let mut lines := [
    (s!"bs {h author} {h sealCtx} {h H.encodeUnsigned} {h H.sealSig.toList}",
      Bandersnatch.Thin.verify author sealCtx H.encodeUnsigned H.sealSig.toList rd),
    (s!"bs {h author} {h (Xentropy ++ yS)} - {h H.vrfSig.toList}",
      Bandersnatch.Thin.verify author (Xentropy ++ yS) [] H.vrfSig.toList rd)]
  for a in b.extrinsic.assurances do
    let k := (σ.active.getD a.assurer ValidatorKey.null).ed
    let m := assuranceMessage H.parent a.bitfield
    lines := lines ++ [(s!"ed {h k} {h m} {h a.signature.toList}", Ed25519.verify k m a.signature.toList)]
  for g in b.extrinsic.guarantees do
    for (v, s) in g.credential do
      let k := (saf'.active.getD v ValidatorKey.null).ed
      let m := guaranteeMessage g.report
      lines := lines ++ [(s!"ed {h k} {h m} {h s.toList}", Ed25519.verify k m s.toList)]
  return (lines.map (·.1), lines.all (·.2))

end JamTarget.Craft
