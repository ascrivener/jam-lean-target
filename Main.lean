import JamTarget.Session
import JamTarget.Probe

/-!
# `jam-lean-target`

* `jam-lean-target serve` — the fuzzer protocol on stdin/stdout, one session per process. Each
  message is framed by its length as a 32-bit little-endian integer. A Unix-socket listener (e.g.
  `socat UNIX-LISTEN:$JAM_FUZZ_SOCK_PATH,fork EXEC:'jam-lean-target serve'`) gives each fuzzer
  connection a fresh process, which is the protocol's session lifetime. Lean's core and Std have
  no Unix-domain sockets.
* `jam-lean-target session DIR` — replay a recorded session (jam-fuzzing `fuzz-proto/examples`,
  the minifuzz format: `NNNNNNNN_fuzzer_*.bin` requests and `NNNNNNNN_target_*.bin` responses,
  unframed) and compare each response as minifuzz does.
* `jam-lean-target trace DIR …` — import block-import traces (`genesis.bin` optional, then
  `NNNNNNNN.bin` = ℰ(pre-state, block, post-state)) through the same session handler and compare
  every post-state root.
* `jam-lean-target craft SPEC OUTDIR` — craft valid blocks signed with the JIP-5 development keys
  from a text description and write them as a recorded session with the model's answers
  (`JamTarget.CraftCli`).
* `jam-lean-target probe KIND INIT OUTDIR` — the block-level probe KIND (`control`, `f4`, `f6`,
  see `JamTarget.Probe`) on the genesis of the `Initialize` message INIT, written as by `craft`.

`JAM_FUZZ_SPEC` (`tiny` or `full`, default `tiny`) selects the parameters.
-/

open JAM JamTarget

def readExact (h : IO.FS.Stream) (n : Nat) : IO (Option ByteArray) := do
  let mut acc := ByteArray.empty
  while acc.size < n do
    let chunk ← h.read (n - acc.size).toUSize
    if chunk.isEmpty then return none
    acc := acc ++ chunk
  return some acc

def le32 (n : Nat) : ByteArray := ⟨(PVM.Num.encodeLE 4 n).toArray⟩

def logErr (lines : List String) : IO Unit := do
  let e ← IO.getStderr
  for l in lines do e.putStrLn s!"[jam-lean] {l}"
  e.flush

/-- The SRS for the ring root: `JAM_LEAN_SRS`, default `data/bls12-381-srs-2-11-uncompressed-zcash.bin`. -/
def loadSrs : IO JamCrypto.Ring.Srs := do
  let path := (← IO.getEnv "JAM_LEAN_SRS").getD "data/bls12-381-srs-2-11-uncompressed-zcash.bin"
  return JamCrypto.Ring.withSelectors (← JamCrypto.Ring.Srs.load path)

/-- The `--gp VERSION` option, if given (it takes precedence over `JAM_GP`). -/
initialize gpOption : IO.Ref (Option String) ← IO.mkRef none

/-- The Gray Paper version of the crypto: `--gp`, else `JAM_GP`, else 0.8.0. 0.8.1 switches only
    the Bandersnatch VRFs (GP #550); the state transition stays the pinned jam-lean model's. -/
def getGp : IO JamCrypto.GpVersion := do
  let v ← match ← gpOption.get with
    | some v => pure v
    | none => pure ((← IO.getEnv "JAM_GP").getD "0.8.0")
  match v with
  | "0.8.0" => return .v080
  | "0.8.1" => return .v081
  | _ => throw (IO.userError s!"the GP version (--gp / JAM_GP) must be 0.8.0 or 0.8.1, not {v}")

/-- A fresh session with the full crypto. -/
def newSession (p : Params) : IO Session := do
  return { params := p, crypto := sessionCrypto (← loadSrs) p (← getGp) }

def getParams : IO Params := do
  let spec := (← IO.getEnv "JAM_FUZZ_SPEC").getD "tiny"
  match paramsOf spec with
  | some p => return p
  | none => throw (IO.userError s!"JAM_FUZZ_SPEC must be tiny or full, not {spec}")

def serve : IO UInt32 := do
  let p ← getParams
  let i ← IO.getStdin
  let o ← IO.getStdout
  let mut s ← newSession p
  repeat
    let some len ← readExact i 4 | break
    let n := PVM.Num.decodeLE len.toList
    let some msg ← readExact i n | logErr ["truncated message"]; break
    match Decoder.run (Request.decode p) msg with
    | .error e => logErr [s!"malformed message: {e}"]; break
    | .ok r =>
      let (s', resp, log) := s.handle r
      logErr log
      s := s'
      match resp with
      | none => break
      | some r =>
        let bytes : ByteArray := ⟨r.encode.toArray⟩
        o.write (le32 bytes.size ++ bytes)
        o.flush
  return 0

/-- The tag of a response, for comparison with a recorded one. -/
def tagOf (b : List UInt8) : Nat := (b.headD 0).toNat

def replaySession (dir : System.FilePath) : IO Bool := do
  let p ← getParams
  let files := ((← dir.readDir).map (·.fileName)).filter (·.endsWith ".bin") |>.qsort (· < ·)
  let reqs := files.filter (fun f => (f.splitOn "_fuzzer_").length == 2)
  let mut s ← newSession p
  let mut ok := 0
  let mut bad := 0
  for f in reqs do
    let idx := (f.splitOn "_").headD ""
    let some exp := files.find? (fun g => g.startsWith (idx ++ "_target_"))
      | IO.println s!"{f}: no recorded response"; bad := bad + 1
    let msg ← IO.FS.readBinFile (dir / f)
    let want := (← IO.FS.readBinFile (dir / exp)).toList
    match Decoder.run (Request.decode p) msg with
    | .error e => IO.println s!"{f}: cannot decode: {e}"; bad := bad + 1; break
    | .ok r =>
      let (s', resp, log) := s.handle r
      s := s'
      let got := (resp.map Response.encode).getD []
      -- As minifuzz: the message kind must match; errors match by kind only; peer info by
      -- protocol version; everything else exactly.
      let same := tagOf got == tagOf want &&
        (tagOf want == 255 || tagOf want == 0 || got == want)
      if same then ok := ok + 1
      else
        bad := bad + 1
        IO.println s!"{f}: expected {exp} ({hex (want.take 33)}), got {hex (got.take 33)}"
        for l in log do IO.println s!"  {l}"
  IO.println s!"{dir}: {ok}/{ok + bad} responses as recorded"
  return bad == 0

/-- A raw state with its root: ℰ(root, ↕[(key, ↕value)]). -/
def rawStateR : Decoder (List UInt8 × RawState) := do
  return ((← Decoder.bytes 32).toList, ← rawState)

structure Step where
  pre : List UInt8 × RawState
  block : Block
  post : List UInt8 × RawState

def readStep (p : Params) (path : System.FilePath) : IO Step := do
  let d : Decoder Step := do
    return { pre := ← rawStateR, block := ← Block.decode p, post := ← rawStateR }
  match Decoder.run d (← IO.FS.readBinFile path) with
  | .ok s => return s
  | .error e => throw (IO.userError s!"{path}: {e}")

/-- Replay one trace directory. Returns (steps, matching, notes). -/
def replayTrace (dir : System.FilePath) : IO (Nat × Nat × List String) := do
  let p ← getParams
  let files := ((← dir.readDir).map (·.fileName)).filter
    (fun f => f.endsWith ".bin" && f != "genesis.bin" && f != "report.bin") |>.qsort (· < ·) |>.toList
  let some first := files.head? | return (0, 0, ["no steps"])
  let st1 ← readStep p (dir / first)
  -- Initialize from genesis.bin when present, else from the first step's pre-state (whose header
  -- the trace does not hold: the entry is keyed by the first block's parent hash).
  let s00 ← newSession p
  let mut s := s00
  let mut notes : List String := []
  let hasGen ← (dir / "genesis.bin").pathExists
  let (initHeader, initKvs) ← if hasGen then do
      let d : Decoder (Header × List UInt8 × RawState) := do
        let h ← Header.decode p; let (r, k) ← rawStateR; return (h, r, k)
      match Decoder.run d (← IO.FS.readBinFile (dir / "genesis.bin")) with
      | .ok (h, _, k) => pure (h, k)
      | .error e => throw (IO.userError s!"{dir}/genesis.bin: {e}")
    else pure (st1.block.header, st1.pre.2)
  let (s1, resp, log) := s.handle (.initialize initHeader initKvs [])
  s := s1
  notes := notes ++ log
  match resp with
  | some (.stateRoot r) =>
    let want := if hasGen then rawStateRoot initKvs else st1.pre.1
    if r != want then notes := notes ++ [s!"Initialize: root {hex r}, expected {hex want}"]
  | _ => return (files.length, 0, notes ++ ["Initialize failed"])
  unless hasGen do
    s := { s with entries := s.entries.map fun e => { e with hash := st1.block.header.parent.toList, ancestors := [] } }
    notes := notes ++ ["no genesis.bin: started from the first step's pre-state; 𝒜 holds no earlier header"]
  let mut good := 0
  for f in files do
    let st ← readStep p (dir / f)
    -- Each step on its own: σ from the step's pre-state, keyed by the block's parent. The session
    -- of the first step keeps 𝒜 from genesis when there is one.
    let held := s.entries.any fun e =>
      e.hash == st.block.header.parent.toList && e.state.root == st.pre.1
    let s0 : Session ← if f == first || held then pure s else do
      let (sx, rx, lx) := s00.handle (.initialize st.block.header st.pre.2 [])
      match rx with
      | some (.stateRoot r) =>
        if r != st.pre.1 then notes := notes ++ [s!"{f}: pre-state not reproduced ({lx.length} notes): {String.intercalate "; " lx}"]
      | _ => notes := notes ++ [s!"{f}: pre-state cannot be decoded: {String.intercalate "; " lx}"]
      pure { sx with entries := sx.entries.map fun e =>
        { e with hash := st.block.header.parent.toList, ancestors := [] } }
    let expectReject := st.pre.1 == st.post.1
    let (s', resp, log) := s0.handle (.importBlock st.block)
    s := s'
    match resp, expectReject with
    | some (.error e), true => good := good + 1; notes := notes ++ [s!"{f}: rejected as the trace: {e}"]
    | some (.stateRoot r), false =>
      if r == st.post.1 then good := good + 1
      else
        notes := notes ++ [s!"{f}: post-state root {hex r}, expected {hex st.post.1}"] ++ log
        match s'.entries.head? with
        | some e =>
          let got := e.state.serializeList
          let exp := st.post.2
          let diff := exp.filterMap (fun (k, v) => match got.lookup k with
              | none => some s!"  missing {hex k}"
              | some v' => if v == v' then none else some s!"  differs {hex k}")
            ++ got.filterMap (fun (k, _) => if (exp.lookup k).isNone then some s!"  extra {hex k}" else none)
          notes := notes ++ diff.take 20
        | none => pure ()
    | some (.stateRoot _), true => notes := notes ++ [s!"{f}: imported a block the trace rejects"] ++ log
    | some (.error e), false => notes := notes ++ [s!"{f}: rejected a block the trace imports: {e}"]
    | _, _ => notes := notes ++ [s!"{f}: no response"] ++ log
  return (files.length, good, notes)

def main (args : List String) : IO UInt32 := do
  let args ← match args with
    | "--gp" :: v :: rest => gpOption.set (some v); pure rest
    | _ => pure args
  discard getGp
  match args with
  | ["serve"] | [] => serve
  | "session" :: dirs =>
    let mut allOk := true
    for d in dirs do
      if !(← replaySession d) then allOk := false
    return if allOk then 0 else 1
  | "trace" :: dirs =>
    let mut allOk := true
    for d in dirs do
      let (n, g, notes) ← replayTrace d
      IO.println s!"{d}: {g}/{n} steps as the trace"
      for l in notes do IO.println s!"  {l}"
      if g != n then allOk := false
    return if allOk then 0 else 1
  | ["craft", spec, out] =>
    let p ← getParams
    let (init, specs) ← CraftCli.parseSpec p (← IO.FS.readFile spec)
    let some init := init | IO.eprintln "craft: no 'init'"; return 2
    let (h, kvs) ← CraftCli.readInitialize p init
    let σ ← CraftCli.decodeState p kvs
    let c ← CraftCli.craftSession (← newSession p) h σ specs out
    for (hh, r) in c.steps do
      IO.println s!"block {hex hh}: {match r with | .stateRoot x => s!"root {hex x}" | .error e => s!"ERROR {e}" | _ => "?"}"
    IO.println s!"signatures valid (JamCrypto): {c.sigsOk}"
    return if c.sigsOk && c.steps.all (fun (_, r) => match r with | .stateRoot _ => true | _ => false) then 0 else 1
  | ["probe", kind, init, out] =>
    let p ← getParams
    let (h, kvs) ← CraftCli.readInitialize p init
    let σ ← CraftCli.decodeState p kvs
    let (σ', specs) ← match Probe.build p σ h kind with
      | .ok x => pure x
      | .error e => IO.eprintln e; return 2
    let c ← CraftCli.craftSession (← newSession p) h σ' specs out
    for (hh, r) in c.steps do
      IO.println s!"block {hex hh}: {match r with | .stateRoot x => s!"root {hex x}" | .error e => s!"ERROR {e}" | _ => "?"}"
    IO.println s!"signatures valid (JamCrypto): {c.sigsOk}"
    match c.post.serviceStats.get? Probe.probeService with
    | some st => IO.println s!"π_S[{Probe.probeService}].accumulation (count, transfers, gas) = {st.accumulation}"
    | none => IO.println s!"π_S[{Probe.probeService}]: none"
    IO.println s!"service {Probe.probeService} last accumulation slot: {(c.post.accounts.get? Probe.probeService).map (·.lastAcc)}"
    return 0
  | _ =>
    IO.eprintln "usage: jam-lean-target [--gp 0.8.0|0.8.1] [serve | session DIR … | trace DIR … | craft SPEC OUTDIR | probe KIND INIT OUTDIR]"
    return 2
