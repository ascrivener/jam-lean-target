import JAM.StateDecode
import JAM.Trie

/-!
# A GP v0.8.0 state's key-values in v0.8.1 form (for the generators only)

The block crafter, the probes and `refinegen` start from the fuzzer's published 0.8.0 genesis (the
only published genesis so far). GP v0.8.1 changed the encoding of two state rows, so that genesis
does not decode under the v0.8.1 model. `upgradeKvs` rewrites those two rows and nothing else; it
is the same conversion as jam-lean's test-only `Tests.TraceState.upgradeRaw`:

* C(13): the validator statistics π_V and π_L become variable-length naturals (GP #564,
  eq. `serialization`); π_C and π_S are unchanged.
* C(255, s): ℰ_4(a_u, a_u') is inserted after a_c and ℰ_8(a_b') after a_b (GP #539, junior
  services, eq. `serialization`). A v0.8.0 account has no supervisor, so it gets the values under
  which GP v0.8.1 behaves as v0.8.0 did: a_u = s with a_u' = a_r (the effective supervisor
  E(**d**, s) = s, eq. `effectivesupervisor`) and a_b' = 0 (a_b + a_b' = a_b in every threshold
  test).

`serve` and `session` never convert: the fuzzer sends v0.8.1 states.
-/

namespace JamTarget.Upgrade

open JAM JAM.Decoder

/-- One v0.8.0 C(13) value in the v0.8.1 encoding (GP #564). -/
def upgradeStats (v : List UInt8) : Except String (List UInt8) := do
  let old : Decoder (List (List Nat)) := varSeq (seqN 6 (fixed 4))
  let dec : Decoder (List (List Nat) × List (List Nat) × Nat) := do
    let a ← old; let b ← old; let pos ← get; let _ ← bytes (← remaining); return (a, b, pos)
  let (a, b, pos) ← match Decoder.run dec ⟨v.toArray⟩ with
    | .ok r => pure r
    | .error e => throw s!"C(13): {e}"
  let enc (xs : List (List Nat)) := Codec.varSeq (fun r => r.flatMap Codec.nat) xs
  return enc a ++ enc b ++ v.drop pos

/-- One v0.8.0 C(255, s) value in the v0.8.1 layout (GP #539). -/
def upgradeInfo (s : Nat) (v : List UInt8) : Except String (List UInt8) := do
  if v.length != 1 + 32 + 40 + 16 then throw s!"C(255, {s}): {v.length} octets, not a v0.8.0 account"
  let created := v.drop (1 + 32 + 40 + 4) |>.take 4
  return v.take 33 ++ Codec.fixed 4 s ++ created ++ (v.drop 33).take 8 ++ Codec.fixed 8 0 ++ v.drop 41

/-- The key-values of a v0.8.0 state in v0.8.1 form. -/
def upgradeKvs (kvs : List (List UInt8 × List UInt8)) : Except String (List (List UInt8 × List UInt8)) :=
  kvs.mapM fun (k, v) => do
    if k == Trie.keyOfIndex 13 then return (k, ← upgradeStats v)
    else if JAM.StateDecode.isInfoKey k then
      return (k, ← upgradeInfo (PVM.Num.decodeLE [k.getD 1 0, k.getD 3 0, k.getD 5 0, k.getD 7 0]) v)
    else return (k, v)

end JamTarget.Upgrade
