import JAM.State
import JAM.Block

/-!
# From a raw state to σ: the inverse of T (GP v0.8.0 §D.1) as far as it exists

The fuzzer's `Initialize` carries the state as the key-value pairs T(σ). jam-lean's σ keeps
storage under the unhashed key, while T keeps only C(s, ℰ_4(2³²−1) ⌢ k), whose last 27 octets are
a prefix of ℋ(ℰ_4(2³²−1) ⌢ k): a storage entry's key cannot be recovered from T. The same holds for
a request entry C(s, ℰ_4(l) ⌢ h) whose preimage is not in the state.

`decode` therefore inverts T for C(1) … C(16) and for each C(255, s); it recognises a preimage
entry by hashing its value, and a request entry when the preimage of its hash is present. Any other
entry is returned in `unplaced`: the caller must not proceed with a σ that lost entries. The check
`root σ = M(raw)` makes any loss visible.

Each decoder below inverts the model's encoder of the same name in `JAM.Serialize`.
-/

namespace JamTarget.StateDecode

open JAM JAM.Decoder

def hash32 : Decoder (List UInt8) := do return (← bytes 32).toList

/-- One validator key (336 octets). -/
def vkey : Decoder ValidatorKey := do return (← bytes 336).toList

def valRecord : Decoder ValidatorRecord := do
  return { blocks := ← fixed 4, tickets := ← fixed 4, preimages := ← fixed 4,
           preimagesSize := ← fixed 4, guarantees := ← fixed 4, assurances := ← fixed 4 }

def coreRecord : Decoder CoreRecord := do
  return { daLoad := ← nat, popularity := ← nat, imports := ← nat, xtCount := ← nat,
           xtSize := ← nat, exports := ← nat, bundleLen := ← nat, gasUsed := ← nat }

def serviceRecord : Decoder ServiceRecord := do
  let p1 ← nat; let p2 ← nat; let r1 ← nat; let r2 ← nat
  let i ← nat; let x ← nat; let z ← nat; let e ← nat
  let a1 ← nat; let a2 ← nat; let a3 ← nat
  return { provided := (p1, p2), refinement := (r1, r2), imports := i, xtCount := x,
           xtSize := z, exports := e, accumulation := (a1, a2, a3) }

/-- C(3). -/
def recent : Decoder Recent := do
  let history ← varSeq do
    let h ← hash32; let b ← hash32; let s ← hash32; let t ← fixed 4; let p ← varHashDict
    return ({ headerHash := h, accRoot := b, stateRoot := s, slot := t, reported := p } : RecentBlock)
  let belt ← varSeq (opt hash32)
  return { history, belt }

/-- γ_S. -/
def sealKeys (E : Nat) : Decoder SealKeys := do
  match ← nat with
  | 0 => return .tickets (← seqN E Ticket.decode)
  | 1 => return .keys (← seqN E hash32)
  | k => fail s!"γ_S discriminator {k}"

/-- C(4). -/
def gamma (E : Nat) : Decoder (List ValidatorKey × List UInt8 × SealKeys × List Ticket) := do
  let pk ← varSeq vkey
  let z ← bytes 144
  let sk ← sealKeys E
  let acc ← varSeq Ticket.decode
  return (pk, z.toList, sk, acc)

/-- C(255, s) without its dictionaries. a_o and a_i are not stored in `ServiceAccount`: the model
    derives them from **s** and **l** (GP eq. `deposits`); they are returned for the check that
    the decoded dictionaries reproduce them. -/
def accountInfo : Decoder (ServiceAccount × Nat × Nat) := do
  let v ← nat
  if v ≠ 0 then fail s!"account version {v}"
  let c ← hash32
  let b ← fixed 8; let g ← fixed 8; let m ← fixed 8; let o ← fixed 8; let f ← fixed 8
  let i ← fixed 4; let r ← fixed 4; let a ← fixed 4; let p ← fixed 4
  return ({ codeHash := c, balance := b, minAccGas := g, minMemoGas := m, gratis := f,
            created := r, lastAcc := a, parent := p }, o, i)

/-- The result of `decode`. -/
structure Decoded where
  state : State
  /-- Entries that cannot be placed in σ (storage, or requests without their preimage). -/
  unplaced : List (List UInt8 × List UInt8)

def get (kvs : List (List UInt8 × List UInt8)) (i : Nat) : Except String ByteArray :=
  match kvs.lookup (Trie.keyOfIndex i) with
  | some v => .ok ⟨v.toArray⟩
  | none => .error s!"no C({i})"

def dec {α : Type} (kvs : List (List UInt8 × List UInt8)) (i : Nat) (d : Decoder α) :
    Except String α := do
  match Decoder.run d (← get kvs i) with
  | .ok x => .ok x
  | .error e => .error s!"C({i}): {e}"

/-- Is k a key C(255, s) (GP §D.1: [255, n₀, 0, n₁, 0, n₂, 0, n₃, 0, 0, …])? -/
def isInfoKey (k : List UInt8) : Bool :=
  k.length == 31 && k.headD 0 == 255 &&
    (List.range 31).all fun j => j ∈ [0, 1, 3, 5, 7] || k.getD j 0 == 0

/-- Decode a raw state (see the module note). -/
def decode (p : Params) (kvs : List (List UInt8 × List UInt8)) : Except String Decoded := do
  let C := p.coreCount
  let E := p.epochLen
  let authPools ← dec kvs 1 (seqN C (varSeq hash32))
  let authQueue ← dec kvs 2 (seqN C (seqN p.authQueueSize hash32))
  let rec_ ← dec kvs 3 recent
  let (pending, ringRoot, sealKeys, accumulator) ← dec kvs 4 (gamma E)
  let disputes ← dec kvs 5 do
    return ({ good := ← varHashSet, bad := ← varHashSet, wonky := ← varHashSet,
              offenders := ← varHashSet } : DisputesState)
  let eta ← dec kvs 6 (seqN 4 hash32)
  let staging ← dec kvs 7 (varSeq vkey)
  let active ← dec kvs 8 (varSeq vkey)
  let prev ← dec kvs 9 (varSeq vkey)
  let avail ← dec kvs 10 (seqN C (opt do
    return ({ guarantee := ← Guarantee.decode, time := ← fixed 4 } : AvailAssignment)))
  let tau ← dec kvs 11 (fixed 4)
  let (manager, assigners, delegator, registrar, alwaysAcc) ← dec kvs 12 do
    let m ← fixed 4; let a ← seqN C (fixed 4); let v ← fixed 4; let r ← fixed 4
    let z ← varSeq (do return (← fixed 4, ← fixed 8))
    return (m, a, v, r, Std.ExtTreeMap.ofList z)
  let (valStats, valStatsLast, coreStats, serviceStats) ← dec kvs 13 do
    let v ← varSeq valRecord; let l ← varSeq valRecord; let c ← seqN C coreRecord
    let s ← varSeq (do return (← fixed 4, ← serviceRecord))
    return (v, l, c, Std.ExtTreeMap.ofList s)
  let ready ← dec kvs 14 (seqN E (varSeq (do return (← WorkReport.decode, ← varHashSet))))
  let accumulated ← dec kvs 15 (seqN E varHashSet)
  let lastAccOut ← dec kvs 16 (varSeq (do return (← fixed 4, ← hash32)))
  -- C(255, s).
  let infos := kvs.filter fun (k, _) => isInfoKey k
  let mut accounts : Accounts := ∅
  for (k, v) in infos do
    let s := PVM.Num.decodeLE [k.getD 1 0, k.getD 3 0, k.getD 5 0, k.getD 7 0]
    match Decoder.run accountInfo ⟨v.toArray⟩ with
    | .ok (a, _, _) => accounts := accounts.insert s a
    | .error e => throw s!"C(255, {s}): {e}"
  let small := (List.range 17).map Trie.keyOfIndex
  let rest := kvs.filter fun (k, _) => !(isInfoKey k || small.contains k)
  -- Preimage entries: C(s, ℰ_4(2³²−2) ⌢ ℋ(p)) ↦ p.
  let mut left : List (List UInt8 × List UInt8) := []
  for (k, v) in rest do
    let h := (Blake2b.hash256 ⟨v.toArray⟩).toList
    match accounts.keys.find? fun s =>
        Trie.keyOfServiceData s (Codec.fixed 4 (2 ^ 32 - 2) ++ h) == k with
    | some s =>
      let a := accounts.getD s default
      accounts := accounts.insert s { a with preimages := a.preimages.insert h v }
    | none => left := left ++ [(k, v)]
  -- Request entries of present preimages: C(s, ℰ_4(|p|) ⌢ ℋ(p)) ↦ ↕[ℰ_4(t)].
  let mut unplaced : List (List UInt8 × List UInt8) := []
  for (k, v) in left do
    let found := accounts.toList.findSome? fun (s, a) =>
      a.preimages.toList.findSome? fun (h, pv) =>
        if Trie.keyOfServiceData s (Codec.fixed 4 pv.length ++ h) == k then some (s, h, pv.length)
        else none
    match found with
    | some (s, h, l) =>
      match Decoder.run (varSeq (fixed 4)) ⟨v.toArray⟩ with
      | .ok t =>
        let a := accounts.getD s default
        accounts := accounts.insert s { a with requests := a.requests.insert (h, l) t }
      | .error _ => unplaced := unplaced ++ [(k, v)]
    | none => unplaced := unplaced ++ [(k, v)]
  let state : State :=
    { authPools, authQueue, recent := rec_, lastAccOut, pending, ringRoot, sealKeys,
      accumulator, accounts, eta, staging, active, prev, avail, tau, manager, assigners,
      delegator, registrar, alwaysAcc, disputes, valStats, valStatsLast, coreStats,
      serviceStats, ready, accumulated }
  return { state, unplaced }

/-- M of a raw state (GP §D.2), for comparison with M_σ of a decoded σ. -/
def rawRoot (kvs : List (List UInt8 × List UInt8)) : List UInt8 :=
  Trie.root (Std.ExtTreeMap.ofList kvs)

end JamTarget.StateDecode
