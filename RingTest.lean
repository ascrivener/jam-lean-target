import JamCrypto.Ring

/-! Ring vectors (`lake exe ringtest [FILE…]`, run from the repository root). Each line of a vector
    file is `root RINGSIZE ROOT KEY…` (hex; a key may be any octet string),
    `proof RINGSIZE ROOT CTX MSG SIG VALID OUT` (MSG `-` for empty; VALID 1 or 0; OUT the expected
    Y for valid ones) or a `#` comment. Exits 1 on any
    mismatch. Vector sources: `tests/gen/` (jam-test-vectors and jam-fuzzing states; ark-vrf 0.1.0). -/

open JamCrypto

def unhex (s : String) : List UInt8 :=
  let s := if s.startsWith "0x" then (s.drop 2).toString else s
  let d (c : Char) : Nat :=
    if c.isDigit then c.toNat - '0'.toNat else if 'a' ≤ c && c ≤ 'f' then c.toNat - 'a'.toNat + 10
    else c.toNat - 'A'.toNat + 10
  let cs := s.toList
  (List.range (cs.length / 2)).map fun i => UInt8.ofNat (d cs[2*i]! * 16 + d cs[2*i+1]!)

def hex (l : List UInt8) : String :=
  String.join (l.map fun b => (if b < 16 then "0" else "") ++ String.ofList (Nat.toDigits 16 b.toNat))

def main (args : List String) : IO UInt32 := do
  let t0 ← IO.monoMsNow
  let srs := Ring.withSelectors (← Ring.Srs.load "data/bls12-381-srs-2-11-uncompressed-zcash.bin")
  IO.println s!"{srs.selectors.length} selectors"
  let t1 ← IO.monoMsNow
  IO.println s!"SRS loaded: {srs.g1.size} G1, {srs.g2Raw.size} G2 ({t1 - t0} ms)"
  -- self-checks: SHAKE128 (FIPS 202 vector), the Frobenius, bilinearity e(τ·G1, G2) = e(G1, τ·G2)
  let shakeOk := hex (Ring.shake128 [] 32) ==
    "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"
  let g2 := (Pairing.G2.decode srs.g2Raw[0]!).get!
  let tg2 := (Pairing.G2.decode srs.g2Raw[1]!).get!
  let m := Pairing.miller srs.g1[1]! g2
  let frobOk := Pairing.frob m == m.pow Fq.P
  let pairOk := Pairing.pairing srs.g1[1]! g2 == Pairing.pairing srs.g1[0]! tg2 &&
    Pairing.pairing srs.g1[0]! g2 != Pairing.Fq12.one
  IO.println s!"self-checks: shake128 {shakeOk}, frobenius {frobOk}, bilinearity {pairOk}"
  let mut bad := if shakeOk && frobOk && pairOk then 0 else 1
  let files := if args.isEmpty then ["tests/vectors/ring-root-jam.txt", "tests/vectors/ring-root-ark.txt", "tests/vectors/ring-proof-ark.txt",
    "tests/vectors/ring-proof-jam.txt"] else args
  let mut n := 0
  for f in files do
    for line in (← IO.FS.lines f) do
      match (line.splitOn " ").filter (· ≠ "") with
      | "root" :: size :: want :: keys =>
        let s ← IO.monoMsNow
        let got := Ring.root srs size.toNat! (keys.map unhex)
        let e ← IO.monoMsNow
        n := n + 1
        if got != unhex want then
          bad := bad + 1
          IO.println s!"FAIL root (ring size {size}, {keys.length} keys): got {hex got} want {want}"
        else IO.println s!"ok root (ring size {size}, {keys.length} keys, {e - s} ms)"
      | "proof" :: size :: root :: ctx :: msg :: sig :: valid :: out :: _ =>
        let s ← IO.monoMsNow
        let ok := Ring.verify srs size.toNat! (unhex root) (unhex ctx) (if msg == "-" then [] else unhex msg) (unhex sig)
        let e ← IO.monoMsNow
        n := n + 1
        let want := valid == "1"
        let outOk := !want || hex (Ring.output (unhex sig)) == out
        if ok != want || !outOk then
          bad := bad + 1
          IO.println s!"FAIL proof (ring size {size}): verify {ok} want {want}, output ok {outOk}"
        else IO.println s!"ok proof (ring size {size}, valid {want}, {e - s} ms)"
      | _ => pure ()
  IO.println s!"{n - bad}/{n} passed"
  return if bad == 0 then 0 else 1
