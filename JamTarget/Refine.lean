import JAM.Refine
import JAM.Erasure
import JAM.Merkle
import JAM.Decode

/-!
# The work-report function Ξ (GP v0.8.0 §14.4) and the `RefineBundle` request

jam-lean gives the invocations Ψ_I and Ψ_R (`JAM.psiI`, `JAM.psiR`), the report types and their
encodings, the erasure code ℰ_C (`JAM.Erasure.encode`) and the well-balanced Merkle root ℳ_B
(`JAM.Merkle.root`). This module adds what Ξ needs beyond them, from GP v0.8.0:

* the constant-depth Merkle root ℳ, its preprocessor C, the trace T, the justification paths J_x
  and the leaf pages L_x (Appendix E, eqs. `constantdepthmerkleroot`,
  `constantdepthsubtreemerklejust`, `constantdepthsubtreemerkleleafpage`);
* the paged proofs P (eq. `pagedproofs`);
* the bundle encoding B (eq. `makebundle`) and the availability specifier A (§14.4.1);
* Ξ itself (eq. `computereport`) with the count-up I, the digest function C (§14.3) and the
  authorizer p_a.

## Readings of v0.8.0 (see docs/refine.md)

* **No exports.** With **s** = [] the paper's ᵀ[] has no size, so ᵀ[**b**♣, **s**♣] is ragged. We
  take **s**♣ to be v items ℳ_B([]) = H_0, the completion GP #583 later wrote down.
* **Bad exports before errors.** v0.8.0 checks |**e**| ≠ w_e before r ∉ 𝔹, and Ψ_R returns no
  exports for ☇ and ∞, so an item with w_e > 0 that panics gives ⊚. GP #568 later swapped the
  order; we keep v0.8.0's.
* **Erasure code.** jam-lean's ℰ_C is §H.3 of v0.8.0 (degree < d); GP #580 later changed the
  generator polynomial, which changes every parity shard and so the erasure root.
-/

namespace JamTarget.Refine

open JAM

/-- H, Blake2b-256 on octet lists. -/
def blake (b : List UInt8) : List UInt8 := (Blake2b.hash256 ⟨b.toArray⟩).toList

def blakeBA (b : ByteArray) : ByteArray := Blake2b.hash256 b

def zeroHash : List UInt8 := List.replicate 32 0

/-! ## Constant-depth Merkle trees (GP Appendix E) -/

def leafPrefix : List UInt8 := "leaf".toUTF8.toList

/-- ⌈log₂(max(1, n))⌉. -/
def ceilLog2 (n : Nat) : Nat :=
  ((List.range 65).find? fun k => n ≤ 2 ^ k).getD 64

/-- C(**v**, H): the items hashed with the prefix $leaf, padded with H_0 to a power of two. -/
def constancy (v : List (List UInt8)) : List (List UInt8) :=
  let n := 2 ^ ceilLog2 v.length
  v.map (fun x => blake (leafPrefix ++ x)) ++ List.replicate (n - v.length) zeroHash

/-- N(**v**, Blake2b). -/
def node (v : List (List UInt8)) : List UInt8 := Merkle.node blakeBA v.length v

/-- ℳ(**v**) = N(C(**v**)) (eq. `constantdepthmerkleroot`). -/
def constRoot (v : List (List UInt8)) : List UInt8 := node (constancy v)

/-- T(**v**, i, H) (Appendix E, the trace): the opposite nodes from the top down to item i. `fuel`
    bounds the depth; |**v**| suffices. -/
def trace : Nat → List (List UInt8) → Nat → List (List UInt8)
  | 0, _, _ => []
  | fuel + 1, v, i =>
    if v.length ≤ 1 then [] else
    let h := (v.length + 1) / 2
    if i < h then node (v.drop h) :: trace fuel (v.take h) i
    else node (v.take h) :: trace fuel (v.drop h) (i - h)

/-- J_x(**v**, i) = T(C(**v**), 2^x·i)_{…max(0, ⌈log₂(max(1,|**v**|))⌉ − x)}
    (eq. `constantdepthsubtreemerklejust`). -/
def justPath (x : Nat) (v : List (List UInt8)) (i : Nat) : List (List UInt8) :=
  let c := constancy v
  (trace c.length c (2 ^ x * i)).take (ceilLog2 v.length - x)

/-- L_x(**v**, i): the hashed leaves of page i (eq. `constantdepthsubtreemerkleleafpage`). -/
def leafPage (x : Nat) (v : List (List UInt8)) (i : Nat) : List (List UInt8) :=
  ((v.drop (2 ^ x * i)).take (2 ^ x)).map fun l => blake (leafPrefix ++ l)

/-- The root that a path **j** (top first, as T gives it) from item n with value `seg` implies,
    for a tree of depth |**j**|. `none` if n is not below 2^|**j**|. -/
def rootOfPath (seg : List UInt8) (n : Nat) (j : List (List UInt8)) : Option (List UInt8) :=
  let d := j.length
  if n ≥ 2 ^ d then none else
  some <| (j.zipIdx.reverse).foldl (init := blake (leafPrefix ++ seg)) fun h (sib, k) =>
    -- level k from the top: bit d−1−k of n says whether the item is in the right half
    if (n >>> (d - 1 - k)) % 2 = 0 then blake (Merkle.nodePrefix ++ h ++ sib)
    else blake (Merkle.nodePrefix ++ sib ++ h)

/-! ## Paged proofs, bundle, availability specifier (GP §14.4) -/

/-- 𝖶_G zero octets. -/
def zeroSegment : List UInt8 := List.replicate Constants.Csegmentsize 0

/-- P_n(**x**): **x** zero-padded to a multiple of n (n > 0). -/
def zeroPad (n : Nat) (x : List UInt8) : List UInt8 :=
  x ++ List.replicate ((n - x.length % n) % n) 0

/-- ↕ of a sequence of hashes. -/
def varHashes (hs : List (List UInt8)) : List UInt8 := Codec.nat hs.length ++ hs.flatten

/-- P(**s**) (eq. `pagedproofs`). -/
def pagedProofs (s : List (List UInt8)) : List (List UInt8) :=
  (List.range ((s.length + 63) / 64)).map fun i =>
    zeroPad Constants.Csegmentsize (varHashes (justPath 6 s i) ++ varHashes (leafPage 6 s i))

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
    (b.justifications.map varHashes).flatten

/-- ᵀ of v rows (each a list of chunks, one per validator) given as columns: chunk i of every row,
    for every i < v. With no rows each of the v items is []. -/
def columns (v : Nat) (rows : List (List ByteArray)) : List (List (List UInt8)) :=
  (List.range v).map fun i => rows.map fun r => (r.getD i ByteArray.empty).toList

/-- A(h, **b**, **s**, v) (§14.4.1, the availability specifier). `none` if R(v) = 0. -/
def availability (h : List UInt8) (b : List UInt8) (s : List (List UInt8)) (v : Nat) :
    Option AvailabilitySpec := do
  let d := Erasure.originalShards v
  if d = 0 then none
  let z := 2 * d
  let w := Erasure.encodeWeights v
  let bChunks ← Erasure.encodeWith d w ⟨(zeroPad z b).toArray⟩
  let bClub := bChunks.map fun c => (blakeBA c).toList
  let segRows ← (s ++ pagedProofs s).mapM fun x => Erasure.encodeWith d w ⟨x.toArray⟩
  let sClub := (columns v segRows).map (Merkle.root blakeBA)
  let er := Merkle.root blakeBA ((bClub.zip sClub).map fun (x, y) => x ++ y)
  return { packageHash := ⟨h.toArray⟩, bundleLength := b.length, erasureRoot := ⟨er.toArray⟩,
           erasureShards := v, segmentRoot := ⟨(constRoot s).toArray⟩, segmentCount := s.length }

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
      match o.result with
      | .ok b =>
        if b.size + z > Constants.Cmaxreportvarsize then (.err .oversize, zeros)
        else if o.exports.length ≠ w.exportCount then (.err .badExports, zeros)
        else (o.result, o.exports)
      | .err er =>
        -- v0.8.0 order: |r| + z > 𝖶_R cannot hold for an error (z ≤ 𝖶_R), then bad exports
        if o.exports.length ≠ w.exportCount then (.err .badExports, zeros) else (.err er, zeros)
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
    unless rootOfPath seg n j = some root do
      throw (.bundle s!"import segment {n} does not verify against its justification")
  let lens := items.map (·.extrinsics.length)
  return (splitBy lens b.extrinsics, splitBy (items.map (·.importSegments.length)) b.imports)

/-- Ξ(p, c, l, v) (eq. `computereport`) over the accounts **d**, after checking the bundle. -/
def xi (params : Params) (d : Accounts) (c : Nat) (l : OctetDict) (v : Nat) (b : Bundle) :
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
  let h := blake p.encode
  let spec ← match availability h (Bundle.encode b) s v with
    | some a => pure a
    | none => throw (.bundle "erasure coding failed")
  return { spec, context := p.context, core := c, authorizerHash := packageAuthorizer p, authTrace := r,
           segmentRootLookup := l, digests := ds.map (·.1), authGasUsed := gI }

/-! ## The request -/

/-- `RefineBundle`: the arguments c, l, v of Ξ and the bundle parts (jam-fuzzing PR #214). The
    three sequences and each extrinsic carry the codec's length prefixes on the wire. -/
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
  let extrinsics ← varSeq (do return (← var).toList)
  let imports ← varSeq (do return (← bytes Constants.Csegmentsize).toList)
  let justifications ← varSeq (varSeq (do return (← bytes 32).toList))
  return { core, lookup, shards, bundle := { package, extrinsics, imports, justifications } }

open Codec in
def Request.encode (q : Request) : List UInt8 :=
  fixed 2 q.core ++ varHashDict q.lookup ++ fixed 2 q.shards ++ q.bundle.package.encode ++
    varSeq (fun x => nat x.length ++ x) q.bundle.extrinsics ++ varSeq id q.bundle.imports ++
    varSeq (varSeq id) q.bundle.justifications

end JamTarget.Refine
