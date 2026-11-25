import JAM.Crypto
import JamCrypto.RingRoot
import JamCrypto.RingVerify
import JamCrypto.RingVerify081
import JamCrypto.Crypto

/-!
# Bandersnatch ring VRF primitives for `JAM.Crypto`

`JamCrypto.Ring.crypto srs V c` is `c` with the ring root O, ring VRF verification and output Y
(GP Appendix G) computed in Lean, for a chain of V validators. `gp` selects the Gray Paper
version (default v0.8.0; v0.8.1 uses the VRF spec's Draft 35, see `RingVerify081`). Load
the SRS once at startup:

```
let srs := JamCrypto.Ring.withSelectors (← JamCrypto.Ring.Srs.load "data/bls12-381-srs-2-11-uncompressed-zcash.bin")
```
-/

namespace JamCrypto.Ring

/-- `c` with the ring VRF primitives for a chain of `validators` = V validators: `bsRingRoot` := O
    (`Ring.root`), `bsRingVerify` := 𝔹̄° (`Ring.verify`), `bsRingOut` := Y (`Ring.output`). -/
def crypto (srs : Srs) (validators : Nat) (c : JAM.Crypto) (gp : GpVersion := .v080) : JAM.Crypto :=
  match gp with
  | .v080 =>
    { c with
      bsRingRoot := root srs validators
      bsRingVerify := verify srs validators
      bsRingOut := output }
  | .v081 =>
    { c with
      bsRingRoot := fun keys => root srs validators keys .v081
      bsRingVerify := verify081 srs validators
      bsRingOut := output081 }

end JamCrypto.Ring
