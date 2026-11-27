import JAM.Guarantee

/-!
# The `RefineBundle` request and Ξ's answer (GP v0.8.1 §14.4)

The work-report function Ξ (eq. `computereport`), the bundle encoding B (eq. `makebundle`) and its
decoding, the availability specifier A (§14.4.1), I, C, p_a, the bundle checks of §17.1 and the
constant-depth Merkle functions are jam-lean's (`JAM.Guarantee`, `JAM.Segments`). This module adds
only what the fuzzer protocol needs around them:

* the `RefineBundle` request (jam-fuzzing PR #214): c, l, v and the bundle, read as B;
* the target-only bound v ≤ 1023 (with R(v) > 0);
* the text of the `Error` answer: jam-lean's checks give the verdict, `rejection` and `noReport`
  name the first failing check in the words the target has always used.

## What GP v0.8.1 changed here (see docs/refine.md)

* **No exports (GP #583).** **s**♣ uses the sized transpose ᵀ_v, so with **s** = [] each of its
  v items is ℳ_B([]) = H_0 ("if no segments are exported, each item of **s**♣ is the zero hash").
  v0.8.0 left this case undefined and the target answered `Error`.
* **Errors before oversize and bad exports (GP #568).** I(p, j) first keeps an error r ∉ 𝔹, then
  checks |r| + z > 𝖶_R, then |**e**| ≠ w_e (eq. `computereport`). v0.8.0 checked bad exports
  first, so a panicking item with w_e > 0 gave ⊚.
* **Erasure code (GP #580).** jam-lean's ℰ_C is v0.8.1's padded systematic code (`JAM.Erasure`):
  every parity shard, and so the erasure root, differs from v0.8.0's.
-/

namespace JamTarget.Refine

open JAM

/-- H, Blake2b-256 on octet lists. -/
def blake (b : List UInt8) : List UInt8 := (Blake2b.hash256 ⟨b.toArray⟩).toList

def blakeBA (b : ByteArray) : ByteArray := Blake2b.hash256 b

/-- Why Ξ gives no report, or why the bundle does not verify. -/
inductive Failure where
  | bundle (why : String)
  | noReport (why : String)

def Failure.message : Failure → String
  | .bundle w => s!"bundle does not verify: {w}"
  | .noReport w => s!"no work-report: {w}"

/-- The first of §17.1's checks that bundle b fails against l (jam-lean `Guarantee.checkBundle`
    gives the verdict), in the order and words of the target's answers: the extrinsics (all
    items, in order), the counts, K(l), then each import segment. -/
def rejection (l : OctetDict) (b : Guarantee.Bundle) : Failure := Id.run do
  let items := b.package.items
  let refs := items.flatMap (·.extrinsics)
  let xs := b.items.flatMap (·.extrinsics)
  if refs.length ≠ xs.length then
    return .bundle s!"{xs.length} extrinsics, the items declare {refs.length}"
  for ((h, n), x) in refs.zip xs do
    unless x.length = n ∧ blake x = h.toList do
      return .bundle s!"an extrinsic of length {x.length} does not match its (hash, {n})"
  let is := items.flatMap (·.importSegments)
  let ss := b.items.flatMap (·.imports)
  let js := b.items.flatMap (·.justifications)
  unless is.length = ss.length ∧ is.length = js.length do
    return .bundle s!"{ss.length} import segments and {js.length} justifications, the items declare {is.length}"
  unless Guarantee.lookupMatches b.package l do
    return .noReport "keys of the segment-root lookup are not the imported package hashes"
  for (((r, n), seg), j) in (is.zip ss).zip js do
    unless seg.length = Constants.Csegmentsize do return .bundle "import segment of wrong size"
    unless Segments.verifySegment blakeBA ((Guarantee.lookupRoot l r).getD []) n seg j do
      return .bundle s!"import segment {n} does not verify against its justification"
  return .bundle "the bundle's data does not match its work-items"

/-- Why Ξ gives ∇ for a bundle that passes the checks (jam-lean `Guarantee.computeReport` gives
    the verdict): Is-Authorized fails, or its trace exceeds 𝖶_R. -/
def noReport (params : Params) (d : Accounts) (p : WorkPackage) (c : Nat) : Failure :=
  match (psiI params d p c).1 with
  | .err e => .noReport s!"Is-Authorized: {reprStr e}"
  | .ok r => .noReport s!"authorizer trace of {r.size} octets"

/-- The answer to `RefineBundle`: Ξ(p, c, l, v) of GP v0.8.1 (eq. `computereport`, jam-lean
    `Guarantee.computeReport`) over the accounts **d**, after §17.1's checks on the bundle
    (`Guarantee.checkBundle`) and the target's bound on v. -/
def xi (params : Params) (d : Accounts) (c : Nat) (l : OctetDict) (v : Nat) (b : Guarantee.Bundle) :
    Except Failure WorkReport := do
  if Erasure.originalShards v = 0 ∨ v > 1023 then throw (.bundle s!"erasure-shards {v} out of range")
  unless Guarantee.checkBundle blakeBA l b do throw (rejection l b)
  match Guarantee.computeReport params d b.package c l v b.items with
  | some r => pure r
  | none => throw (noReport params d b.package c)

/-! ## The request -/

/-- `RefineBundle`: the arguments c, l, v of Ξ and the bundle (jam-fuzzing PR #214). The bundle is
    the GP bundle encoding B (eq. `makebundle`, jam-lean `Guarantee.Bundle.decode`): ℰ(p), then the
    extrinsic data, the import segments and the ↕ justifications, with no other length prefixes;
    the lengths come from the work-items. -/
structure Request where
  core : Nat
  lookup : OctetDict
  shards : Nat
  bundle : Guarantee.Bundle

open Decoder in
def Request.decode : Decoder Request := do
  let core ← fixed 2
  let lookup ← varHashDict
  let shards ← fixed 2
  let bundle ← Guarantee.Bundle.decode
  return { core, lookup, shards, bundle }

open Codec in
def Request.encode (q : Request) : List UInt8 :=
  fixed 2 q.core ++ varHashDict q.lookup ++ fixed 2 q.shards ++
    Guarantee.bundle q.bundle.package q.bundle.items

end JamTarget.Refine
