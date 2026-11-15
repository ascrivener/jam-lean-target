import JamCrypto.Ed25519
import JamCrypto.Bandersnatch
import JAM.Crypto

/-!
# The `JAM.Crypto` fields this library implements

`withSignatures base` is `base` with Ed25519 verification (ZIP 215 rules, see `Ed25519.Rules`), the
Bandersnatch IETF VRF verification and its output Y; the ring fields (`bsRingRoot`, `bsRingVerify`,
`bsRingOut`) stay those of `base`.
-/

namespace JamCrypto

/-- `base` with `edVerify`, `bsVerify` and `bsOut` implemented. -/
def withSignatures (base : JAM.Crypto) (rules : Ed25519.Rules := Ed25519.zip215) : JAM.Crypto :=
  { base with
    edVerify := Ed25519.verifyWith rules
    bsVerify := Bandersnatch.ietfVerify
    bsOut := Bandersnatch.vrfOutput }

end JamCrypto
