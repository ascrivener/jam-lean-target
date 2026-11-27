import JAM.Refine
import JAM.Erasure
import JAM.Merkle
import JAM.Decode
import JAM.Segments

/-!
# The work-report function Ξ (GP v0.8.1 §14.4) and the `RefineBundle` request

jam-lean gives the invocations Ψ_I and Ψ_R (`JAM.psiI`, `JAM.psiR`), the report types and their
encodings, the erasure code ℰ_C (`JAM.Erasure.encode`), the well-balanced Merkle root ℳ_B
(`JAM.Merkle.root`), and the constant-depth Merkle root ℳ, the justification paths J_x, the leaf
pages L_x, the paged proofs P, the zero-padding 𝒫 and the segment check against a justification
(`JAM.Segments`: `cdRoot`, `justify`, `page`, `pagedProofs`, `zeroPad`, `verifySegment`). This module
adds what Ξ needs beyond them, from GP v0.8.1:

* the bundle encoding B (eq. `makebundle`) and the availability specifier A (§14.4.1);
* Ξ itself (eq. `computereport`) with the count-up I, the digest function C (§14.3) and the
  authorizer p_a.

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

/-! ## Bundle, availability specifier (GP §14.4) -/

/-- 𝖶_G zero octets. -/
def zeroSegment : List UInt8 := List.replicate Constants.Csegmentsize 0

/-- The parts of a work-package bundle. -/
structure Bundle where
  package : WorkPackage
  /-- the extrinsic data of all items, in item order -/
  extrinsics : List (List UInt8)
  /-- the import segments of all items, in item order -/
  imports : List (List UInt8)
  /-- the justification path of each import segment -/
  justifications : List (List (List UInt8))

/-- B(p, l) = ℰ(p, X^#(p_w), I^#(p_w), J^#(p_w)) (eq. `makebundle`): no length prefixes except
    each justification's. -/
def Bundle.encode (b : Bundle) : List UInt8 :=
  b.package.encode ++ b.extrinsics.flatten ++ b.imports.flatten ++
    (b.justifications.map (Codec.varSeq id)).flatten

/-- ᵀ_v of the rows (each a list of chunks, one per validator) given as columns: chunk i of every
    row, for every i < v. With no rows each of the v items is [] (the sized transpose of GP v0.8.1,
    GP #583). -/
def columns (v : Nat) (rows : List (List ByteArray)) : List (List (List UInt8)) :=
  (List.range v).map fun i => rows.map fun r => (r.getD i ByteArray.empty).toList

/-- A(h, **b**, **s**, v) (§14.4.1, the availability specifier) with the erasure-code weights `w`
    from the d message words to the v code words. `none` if R(v) = 0. -/
def availabilityWith (w : Array (Array Nat)) (h : List UInt8) (b : List UInt8)
    (s : List (List UInt8)) (v : Nat) : Option AvailabilitySpec := do
  let d := Erasure.originalShards v
  if d = 0 then none
  let z := 2 * d
  let bChunks ← Erasure.encodeWith d w ⟨(Segments.zeroPad z b).toArray⟩
  let bClub := bChunks.map fun c => (blakeBA c).toList
  let segRows ← (s ++ Segments.pagedProofs blakeBA s).mapM fun x => Erasure.encodeWith d w ⟨x.toArray⟩
  let sClub := (columns v segRows).map (Merkle.root blakeBA)
  let er := Merkle.root blakeBA ((bClub.zip sClub).map fun (x, y) => x ++ y)
  return { packageHash := ⟨h.toArray⟩, bundleLength := b.length, erasureRoot := ⟨er.toArray⟩,
           erasureShards := v, segmentRoot := ⟨(Segments.cdRoot blakeBA s).toArray⟩, segmentCount := s.length }

/-- A(h, **b**, **s**, v) with GP v0.8.1's erasure code ℰ_C (jam-lean `Erasure.encodeWeights`). -/
def availability (h : List UInt8) (b : List UInt8) (s : List (List UInt8)) (v : Nat) :
    Option AvailabilitySpec :=
  availabilityWith (Erasure.encodeWeights v) h b s v

/-! ## Ξ (eq. `computereport`) -/

/-- p_a = H(p_u ⌢ p_f) (§14.3). -/
def packageAuthorizer (p : WorkPackage) : Hash :=
  blakeBA (p.authCodeHash ++ p.authConfig)

/-- C(w, r, u) (§14.3, the item-to-digest function). -/
def digest (w : WorkItem) (r : WorkResult) (u : Nat) : WorkDigest :=
  { service := w.service, codeHash := w.codeHash, payloadHash := blakeBA w.payload,
    gasLimit := w.accumulateGasLimit, result := r, gasUsed := u,
    importCount := w.importSegments.length, extrinsicCount := w.extrinsics.length,
    extrinsicSize := (w.extrinsics.map (·.2)).sum, exportCount := w.exportCount }

/-- Split a flat list by the given lengths. -/
def splitBy {α : Type} : List Nat → List α → List (List α)
  | [], _ => []
  | n :: ns, xs => xs.take n :: splitBy ns (xs.drop n)

/-- I(p, j) for all j, in order (eq. `computereport`): each item's digest and exports. `z` is the
    trace length plus the output lengths so far, ℓ the exports so far. -/
def countUp (params : Params) (d : Accounts) (c : Nat) (p : WorkPackage) (r : List UInt8)
    (ibar xbar : List (List (List UInt8))) : List (WorkDigest × List (List UInt8)) :=
  let step := fun (acc : List (WorkDigest × List (List UInt8)) × Nat × Nat) (jw : WorkItem × Nat) =>
    let (out, z, ℓ) := acc
    let (w, j) := jw
    let o := psiR params d c j p r ibar xbar ℓ
    let zeros := List.replicate w.exportCount zeroSegment
    let (res, e) : WorkResult × List (List UInt8) :=
      -- GP v0.8.1 order (#568): r ∉ 𝔹, then |r| + z > 𝖶_R, then |e| ≠ w_e
      match o.result with
      | .err er => (.err er, zeros)
      | .ok b =>
        if b.size + z > Constants.Cmaxreportvarsize then (.err .oversize, zeros)
        else if o.exports.length ≠ w.exportCount then (.err .badExports, zeros)
        else (o.result, o.exports)
    let z' := match res with | .ok b => z + b.size | .err _ => z
    (out ++ [(digest w res o.gasUsed, e)], z', ℓ + w.exportCount)
  ((p.items.zip (List.range p.items.length)).foldl step ([], r.length, 0)).1

/-- Why Ξ gives no report, or why the bundle does not verify. -/
inductive Failure where
  | bundle (why : String)
  | noReport (why : String)

def Failure.message : Failure → String
  | .bundle w => s!"bundle does not verify: {w}"
  | .noReport w => s!"no work-report: {w}"

/-- Check the bundle parts against the package (§14.4: X(w) and I_l(w), J_l(w)) and split them
    per item: (x̄, ī). -/
def verify (b : Bundle) (l : OctetDict) :
    Except Failure (List (List (List UInt8)) × List (List (List UInt8))) := do
  let items := b.package.items
  let xs := items.flatMap (·.extrinsics)
  unless xs.length = b.extrinsics.length do
    throw (.bundle s!"{b.extrinsics.length} extrinsics, the items declare {xs.length}")
  for ((h, n), x) in xs.zip b.extrinsics do
    unless x.length = n ∧ blake x = h.toList do
      throw (.bundle s!"an extrinsic of length {x.length} does not match its (hash, {n})")
  let is := items.flatMap (·.importSegments)
  unless is.length = b.imports.length ∧ is.length = b.justifications.length do
    throw (.bundle s!"{b.imports.length} import segments and {b.justifications.length} justifications, the items declare {is.length}")
  -- keys(l) = the package hashes imported from (part of E; checked first so that L(r) is defined)
  let pkgs : OctetSet := Std.ExtTreeSet.ofList (is.filterMap fun
    | (.package h, _) => some h.toList | _ => none)
  unless l.keys = pkgs.toList do
    throw (.noReport "keys of the segment-root lookup are not the imported package hashes")
  for (((r, n), seg), j) in (is.zip b.imports).zip b.justifications do
    unless seg.length = Constants.Csegmentsize do throw (.bundle "import segment of wrong size")
    let root := match r with | .root h => h.toList | .package h => (l.get? h.toList).getD []
    unless Segments.verifySegment blakeBA root n seg j do
      throw (.bundle s!"import segment {n} does not verify against its justification")
  let lens := items.map (·.extrinsics.length)
  return (splitBy lens b.extrinsics, splitBy (items.map (·.importSegments.length)) b.imports)

/-- Ξ(p, c, l, v) (eq. `computereport`) over the accounts **d**, after checking the bundle, with
    the availability specifier `spec` (given h, **b**, **s**). -/
def xiWith (spec : List UInt8 → List UInt8 → List (List UInt8) → Except Failure AvailabilitySpec)
    (params : Params) (d : Accounts) (c : Nat) (l : OctetDict) (v : Nat) (b : Bundle) :
    Except Failure WorkReport := do
  let p := b.package
  if Erasure.originalShards v = 0 ∨ v > 1023 then throw (.bundle s!"erasure-shards {v} out of range")
  let (xbar, ibar) ← verify b l
  let (o, gI) := psiI params d p c
  let r : ByteArray ← match o with
    | .ok r =>
      if r.size ≤ Constants.Cmaxreportvarsize then pure r
      else throw (Failure.noReport s!"authorizer trace of {r.size} octets")
    | .err e => throw (Failure.noReport s!"Is-Authorized: {reprStr e}")
  let ds := countUp params d c p r.toList ibar xbar
  let s := (ds.map (·.2)).flatten
  let a ← spec (blake p.encode) (Bundle.encode b) s
  return { spec := a, context := p.context, core := c, authorizerHash := packageAuthorizer p,
           authTrace := r, segmentRootLookup := l, digests := ds.map (·.1), authGasUsed := gI }

/-- A of GP v0.8.1 (§14.4.1), defined also when nothing is exported (GP #583). -/
def spec081 (v : Nat) (h b : List UInt8) (s : List (List UInt8)) : Except Failure AvailabilitySpec :=
  match availability h b s v with
  | some a => pure a
  | none => throw (.bundle "erasure coding failed")

/-- Ξ(p, c, l, v) of GP v0.8.1 (eq. `computereport`) over the accounts **d**. -/
def xi (params : Params) (d : Accounts) (c : Nat) (l : OctetDict) (v : Nat) (b : Bundle) :
    Except Failure WorkReport :=
  xiWith (spec081 v) params d c l v b

/-! ## The request -/

/-- `RefineBundle`: the arguments c, l, v of Ξ and the bundle (jam-fuzzing PR #214). The bundle is
    the GP bundle encoding B (eq. `makebundle`): ℰ(p), then the extrinsic data, the import
    segments and the ↕ justifications, with no other length prefixes; the lengths come from the
    work-items. -/
structure Request where
  core : Nat
  lookup : OctetDict
  shards : Nat
  bundle : Bundle

open Decoder in
def Request.decode : Decoder Request := do
  let core ← fixed 2
  let lookup ← varHashDict
  let shards ← fixed 2
  let package ← WorkPackage.decode
  let xs := package.items.flatMap (·.extrinsics)
  let is := package.items.flatMap (·.importSegments)
  let extrinsics ← xs.mapM fun (_, n) => do return (← bytes n).toList
  let imports ← is.mapM fun _ => do return (← bytes Constants.Csegmentsize).toList
  let justifications ← is.mapM fun _ => varSeq (do return (← bytes 32).toList)
  return { core, lookup, shards, bundle := { package, extrinsics, imports, justifications } }

open Codec in
def Request.encode (q : Request) : List UInt8 :=
  fixed 2 q.core ++ varHashDict q.lookup ++ fixed 2 q.shards ++ q.bundle.encode

end JamTarget.Refine
