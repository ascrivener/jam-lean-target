import JamCrypto

/-!
# `lake exe cryptotest [DIR]`: the JamCrypto test vectors

Runs every vector of `DIR/ed25519.txt` and `DIR/bandersnatch_ietf.txt` (default
`JamCryptoTest/vectors`, see its README) and exits non-zero on a mismatch. Prints the time per
verification.
-/

open JamCrypto JamCrypto.Modular

def hexDigit (c : Char) : Nat :=
  if c.isDigit then c.toNat - '0'.toNat else c.toLower.toNat - 'a'.toNat + 10

def unhex (s : String) : List UInt8 :=
  if s == "-" then [] else
  let cs := s.toList
  (List.range (cs.length / 2)).map fun i =>
    UInt8.ofNat (16 * hexDigit cs[2 * i]! + hexDigit cs[2 * i + 1]!)

def toHex (bs : List UInt8) : String :=
  String.join (bs.map fun b =>
    let h := Nat.toDigits 16 b.toNat
    String.ofList (if h.length == 1 then '0' :: h else h))

def check (name : String) (ok : Bool) (failures : IO.Ref Nat) : IO Unit := do
  unless ok do
    IO.eprintln s!"MISMATCH {name}"
    failures.modify (· + 1)

def timed {α : Type} (f : Unit → α) : IO (α × Nat) := do
  let t0 ← IO.monoNanosNow
  let a ← IO.lazyPure f
  let t1 ← IO.monoNanosNow
  return (a, t1 - t0)

def main (args : List String) : IO UInt32 := do
  let dir := args.headD "JamCryptoTest/vectors"
  let failures ← IO.mkRef 0
  -- fixed points of the suites
  check "bandersnatch generator encoding"
    (toHex (Bandersnatch.encode Bandersnatch.G)
      == "664197ccb667315e6064e4ee81ad8c3586d5dcba508b7d150f3e12da9e666c2a") failures
  check "bandersnatch hash-to-curve of the empty input (ark-vrf vector 1, h)"
    ((Bandersnatch.hashToCurve []).map Bandersnatch.encode
      == some (unhex "c5eaf38334836d4b10e05d2c1021959a917e08eaf4eb46a8c4c8d1bec04e2c00")) failures
  check "bandersnatch hash-to-curve of 0a (ark-vrf vector 2, h)"
    ((Bandersnatch.hashToCurve [0x0a]).map Bandersnatch.encode
      == some (unhex "8c1d1425374f01d86b23bfeab770c60b58d2eeb9afc5900c8b8a918d09a6086b")) failures
  -- Ed25519: tag zip215 rfc8032Strict rfc8032Cofactorless key msg sig
  let mut edN := 0
  let mut edT := 0
  for line in (← IO.FS.lines s!"{dir}/ed25519.txt") do
    match line.splitOn " " with
    | [tag, z, s, c, key, msg, sig] =>
      let (key, msg, sig) := (unhex key, unhex msg, unhex sig)
      let (rz, t) ← timed fun _ => Ed25519.verify key msg sig
      if z == "1" then
        edN := edN + 1
        edT := edT + t
      check s!"ed25519 {tag} zip215" (rz == (z == "1")) failures
      check s!"ed25519 {tag} rfc8032Strict"
        (Ed25519.verifyWith Ed25519.rfc8032Strict key msg sig == (s == "1")) failures
      check s!"ed25519 {tag} rfc8032Cofactorless"
        (Ed25519.verifyWith Ed25519.rfc8032Cofactorless key msg sig == (c == "1")) failures
    | _ => if line != "" then check s!"ed25519 malformed line: {line}" false failures
  -- Bandersnatch IETF VRF: tag valid key ctx msg sig Y
  let mut bsN := 0
  let mut bsT := 0
  for line in (← IO.FS.lines s!"{dir}/bandersnatch_ietf.txt") do
    match line.splitOn " " with
    | [tag, v, key, ctx, msg, sig, y] =>
      let (key, ctx, msg, sig) := (unhex key, unhex ctx, unhex msg, unhex sig)
      let (ok, t) ← timed fun _ => Bandersnatch.ietfVerify key ctx msg sig
      if v == "1" then
        bsN := bsN + 1
        bsT := bsT + t
      check s!"bandersnatch {tag} verify" (ok == (v == "1")) failures
      if ok then
        check s!"bandersnatch {tag} Y" (Bandersnatch.vrfOutput sig == unhex y) failures
        check s!"bandersnatch {tag} Y = JAM.Sha512.vrfOutput"
          (Bandersnatch.vrfOutput sig == JAM.Sha512.vrfOutput sig) failures
    | _ => if line != "" then check s!"bandersnatch malformed line: {line}" false failures
  IO.println s!"ed25519: {edT / 1000 / max edN 1} µs per valid signature (ZIP 215)"
  IO.println s!"bandersnatch ietf: {bsT / 1000 / max bsN 1} µs per valid signature"
  let f ← failures.get
  if f == 0 then
    IO.println "all vectors pass"
    return 0
  else
    IO.eprintln s!"{f} mismatches"
    return 1
