import JamCrypto.Ring

/-! Ring vectors (`lake exe ringtest [FILE…]`, run from the repository root). Each line of a vector
    file is `root RINGSIZE ROOT KEY…` (hex; a key may be any octet string) or a `#` comment. Exits 1 on any
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
  let files := if args.isEmpty then ["tests/vectors/ring-root-jam.txt", "tests/vectors/ring-root-ark.txt"] else args
  let mut bad := 0
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
      | _ => pure ()
  IO.println s!"{n - bad}/{n} passed"
  return if bad == 0 then 0 else 1
