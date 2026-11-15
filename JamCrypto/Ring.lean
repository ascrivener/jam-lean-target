import JAM.Crypto
import JamCrypto.RingRoot

/-!
# Bandersnatch ring VRF primitives for `JAM.Crypto`

`JamCrypto.Ring.crypto srs c` is `c` with the ring root O (GP Appendix G) computed in Lean. Load
the SRS once at startup:

```
let srs := JamCrypto.Ring.withSelectors (← JamCrypto.Ring.Srs.load "data/bls12-381-srs-2-11-uncompressed-zcash.bin")
```
-/

namespace JamCrypto.Ring

/-- `c` with `bsRingRoot` := O (`Ring.root`) for a chain of `validators` = V validators. -/
def crypto (srs : Srs) (validators : Nat) (c : JAM.Crypto) : JAM.Crypto :=
  { c with bsRingRoot := root srs validators }

end JamCrypto.Ring
