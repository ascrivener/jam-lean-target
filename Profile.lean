import JamTarget.Session
import JamCrypto.DevKeys
import JamCrypto.Ed25519Sign
import JamCrypto.ThinVrf

/-!
# `profile`: where the target spends time

`lake exe profile [-n REPS] DIR…` replays recorded fuzzer sessions (minifuzz format, as
`jam-lean-target session`) and, for every request, times the session handler with the target's
crypto and with parts of it replaced by an accept-all stand-in, so that the differences give the
cost of each primitive:

* `full`   — the target's crypto (`sessionCrypto`), as `serve` runs it;
* `-ring`  — ring root O(k) and ring VRF verification accept-all / empty;
* `-bs`    — also the Bandersnatch Thin VRF verification accept-all (Y(s) still computed);
* `-ed`    — also Ed25519 accept-all (the target's `oracleCrypto` plus the real Y(s)).

It also times the parts of an import that do not depend on crypto: decoding the message, M_σ of the
pre- and post-state (serialization T(σ) and the trie), and encoding the response. Startup (Lean
module initialisation, before `main`) and SRS loading are reported separately. Each request is
timed REPS times (default 3) from the same session state; the minimum is reported. The session then
advances with the `full` result. Timings are wall clock (`IO.monoNanosNow`). Nothing here changes
the target: it only calls `Session.handle` with different `Crypto` values.

`lake exe profile --prims` times single crypto primitives on jam-lean's vectors (run from the
repository root, which holds `.lake/packages/jam-lean`).
-/

open JAM JamTarget

def msOf (a b : Nat) : Float := (b - a).toFloat / 1.0e6

def fmt (x : Float) : String :=
  let r := (x * 10.0).round / 10.0
  let s := toString r
  match s.splitOn "." with
  | [i, f] => i ++ "." ++ (f.take 1)
  | _ => s

def srsPath : IO String := do
  return (← IO.getEnv "JAM_LEAN_SRS").getD
    ".lake/packages/jam-lean/JamCryptoTest/data/bls12-381-srs-2-11-uncompressed-zcash.bin"

def getParams : IO Params := do
  let spec := (← IO.getEnv "JAM_FUZZ_SPEC").getD "tiny"
  match paramsOf spec with
  | some p => return p
  | none => throw (IO.userError s!"JAM_FUZZ_SPEC must be tiny or full, not {spec}")

/-- Time `f ()` `n` times (the input read from a ref each time, so nothing is hoisted); the
    minimum in ms and the last result. -/
def timeMin {α β : Type} (n : Nat) (ref : IO.Ref α) (f : α → β) (force : β → Nat) :
    IO (Float × β) := do
  let x0 ← ref.get
  let t0 ← IO.monoNanosNow
  let y0 := f x0
  let k0 := force y0
  let t1 ← IO.monoNanosNow
  if k0 == 12345678901 then IO.println "."
  let mut best : Float := msOf t0 t1
  let mut out : β := y0
  for _ in [1:n] do
    let x ← ref.get
    let t0 ← IO.monoNanosNow
    let y := f x
    let k := force y
    let t1 ← IO.monoNanosNow
    if k == 12345678901 then IO.println "."
    best := min best (msOf t0 t1)
    out := y
  return (best, out)

def kindOf : Request → String
  | .peerInfo _ => "PeerInfo"
  | .initialize .. => "Initialize"
  | .importBlock b => s!"ImportBlock slot {b.header.slot} (E_T {b.extrinsic.tickets.length}, E_G {b.extrinsic.guarantees.length}, E_A {b.extrinsic.assurances.length}, E_P {b.extrinsic.preimages.length})"
  | .getState _ => "GetState"
  | .refineBundle q => s!"RefineBundle core {q.core}"

def respSize : Option Response → Nat
  | some r => r.encode.length
  | none => 0

def handleOut (x : Session × Option Response × Log) : Nat := respSize x.2.1

def profileDir (p : Params) (full : Crypto) (n : Nat) (dir : System.FilePath) : IO Unit := do
  let noRing : Crypto := { full with
    bsRingRoot := oracleCrypto.bsRingRoot, bsRingVerify := oracleCrypto.bsRingVerify }
  let noBs : Crypto := { noRing with bsVerify := oracleCrypto.bsVerify }
  let noEd : Crypto := { noBs with edVerify := oracleCrypto.edVerify }
  let files := ((← dir.readDir).map (·.fileName)).filter (·.endsWith ".bin") |>.qsort (· < ·)
  let reqs := files.filter (fun f => (f.splitOn "_fuzzer_").length == 2)
  let mut s : Session := { params := p, crypto := full }
  IO.println s!"## {dir}"
  IO.println "| msg | kind | decode | full | -ring | -bs | -ed | M(pre) | M(post) | encode |"
  IO.println "|---|---|---|---|---|---|---|---|---|---|"
  for f in reqs do
    let msg ← IO.FS.readBinFile (dir / f)
    let mref ← IO.mkRef msg
    let (tDec, dr) ← timeMin n mref (fun m => Decoder.run (Request.decode p) m)
      (fun r => match r with | .ok _ => 1 | .error _ => 0)
    let .ok r := dr | IO.println s!"{f}: cannot decode"; return
    let isHeavy := match r with | .importBlock _ | .refineBundle _ | .initialize .. => true | _ => false
    let sref ← IO.mkRef s
    let (tFull, out) ← timeMin n sref (fun s => s.handle r) handleOut
    let cols ← if isHeavy && (match r with | .importBlock _ => true | _ => false) then do
        let (a, _) ← timeMin n sref (fun s => ({ s with crypto := noRing } : Session).handle r) handleOut
        let (b, _) ← timeMin n sref (fun s => ({ s with crypto := noBs } : Session).handle r) handleOut
        let (c, _) ← timeMin n sref (fun s => ({ s with crypto := noEd } : Session).handle r) handleOut
        pure [fmt a, fmt b, fmt c]
      else pure ["", "", ""]
    let (s', resp, _) := out
    -- M_σ of the pre-state (parent) and post-state
    let (tPre, tPost) ← match r with
      | .importBlock b => do
        let pre := (s.entries.find? (·.hash == b.header.parent.toList)).map (·.state)
        let post := s'.entries.head?.map (·.state)
        let pr ← IO.mkRef pre
        let po ← IO.mkRef post
        let (a, _) ← timeMin n pr (fun x => x.map State.root) (fun x => (x.getD []).length)
        let (c, _) ← timeMin n po (fun x => x.map State.root) (fun x => (x.getD []).length)
        pure (fmt a, fmt c)
      | _ => pure ("", "")
    let rref ← IO.mkRef resp
    let (tEnc, _) ← timeMin n rref (fun r => (r.map Response.encode).getD []) List.length
    IO.println s!"| {f.take 8} | {kindOf r} | {fmt tDec} | {fmt tFull} | {cols[0]!} | {cols[1]!} | {cols[2]!} | {tPre} | {tPost} | {fmt tEnc} |"
    (← IO.getStdout).flush
    s := s'

def unhex (s : String) : List UInt8 :=
  let d (c : Char) : Nat := if c.isDigit then c.toNat - 48 else c.toLower.toNat - 87
  let cs := s.toList
  (List.range (cs.length / 2)).map fun i => UInt8.ofNat (d cs[2*i]! * 16 + d cs[2*i+1]!)

/-- Single primitives on jam-lean's vectors. -/
def prims (p : Params) (srs : JamCrypto.Ring.Srs) (n : Nat) : IO Unit := do
  let base := ".lake/packages/jam-lean/JamCryptoTest/"
  let full := sessionCrypto srs p
  IO.println "| primitive | ms (min of reps) | result |"
  IO.println "|---|---|---|"
  -- Ed25519: first vector line "key msg sig ..." (see vectors/README.md)
  let row (name : String) (t : Float) (ok : Bool) := IO.println s!"| {name} | {fmt t} | {ok} |"
  -- ring root, the GP v0.8.1 way (domain 2048), tiny V = 6 keys of the ticket vector file
  let keys : List (List UInt8) := (List.range (validatorsOf p)).map fun i =>
    (JamCrypto.DevKeys.dev i).bs
  let kref ← IO.mkRef keys
  let (tRoot, root) ← timeMin n kref (fun k => full.bsRingRoot k) List.length
  row s!"ring root O(k), {keys.length} keys, domain 2048" tRoot (root.length == 144)
  -- ring VRF: Draft 35 vector (domain 512, ring size 255), valid
  for line in (← IO.FS.lines (base ++ "ring/ring-d35.txt")) do
    match (line.splitOn " ").filter (· ≠ "") with
    | ["proof081", size, root, ctx, msg, sig, "1", _] =>
      let ctx := if ctx == "-" then [] else unhex ctx
      let msg := if msg == "-" then [] else unhex msg
      let r ← IO.mkRef (unhex sig)
      let (t, ok) ← timeMin n r (fun sg => JamCrypto.Ring.verify081 srs size.toNat! (unhex root) ctx msg sg .vectors) (fun b => if b then 1 else 0)
      row s!"ring VRF verify (Draft 35 vector, ring size {size})" t ok
      let (t2, ok2) ← timeMin n r (fun sg => full.bsRingVerify (unhex root) ctx msg sg) (fun b => if b then 1 else 0)
      row s!"ring VRF verify, same proof at the target's keyset size (domain 2048; rejects)" t2 ok2
      break
    | _ => pure ()
  -- Ed25519 and Thin VRF: sign with a dev key, then verify
  let k := JamCrypto.DevKeys.dev 0
  let m := (List.range 200).map UInt8.ofNat
  let esig := JamCrypto.Ed25519.sign k.edSeed m
  let er ← IO.mkRef esig
  let (tEd, okEd) ← timeMin n er (fun sg => full.edVerify k.ed m sg) (fun b => if b then 1 else 0)
  row "Ed25519 verify (ZIP-215), 200-octet message" tEd okEd
  let ctx := "jam_fallback_seal".toUTF8.toList
  let tsig := (JamCrypto.Bandersnatch.Thin.sign k.bsSecret ctx m .vectors).getD []
  let tr ← IO.mkRef tsig
  let (tThin, okThin) ← timeMin n tr (fun sg => full.bsVerify k.bs ctx m sg) (fun b => if b then 1 else 0)
  row "Bandersnatch Thin VRF verify" tThin okThin
  let (tOut, _) ← timeMin n tr (fun sg => full.bsOut sg) List.length
  row "Bandersnatch Y(s) (VRF output)" tOut true
  let bl ← IO.mkRef ((List.range 4104).map UInt8.ofNat)
  let (tB, _) ← timeMin n bl (fun x => (JAM.Blake2b.hash256 ⟨x.toArray⟩).size) id
  row "Blake2b-256 of 4104 octets" tB true

def main (args : List String) : IO UInt32 := do
  let t0 ← IO.monoNanosNow
  let p ← getParams
  let (n, rest) := match args with
    | "-n" :: k :: r => (k.toNat!, r)
    | r => (3, r)
  let srs := JamCrypto.Ring.withSelectors (← JamCrypto.Ring.Srs.load (← srsPath))
  let t1 ← IO.monoNanosNow
  IO.println s!"SRS load + selector commitments: {fmt (msOf t0 t1)} ms ({srs.selectors.length} selectors)"
  if rest == ["--prims"] then prims p srs n; return 0
  let full := sessionCrypto srs p
  for d in rest do profileDir p full n d
  return 0
