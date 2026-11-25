# Cryptography notes

Points where the GP v0.8.0 leaves the cryptography to its references, and where the model and the
references disagree. One section per point.

## Ring root: the ring size is the validator count V, not |k| (GP ambiguity)

GP Appendix G defines O(**k**) = commit(**k**) and defers commit to the Bandersnatch ring VRF.
The ring proof's polynomial domain depends on a *ring size*, which the GP does not fix: ark-vrf
sizes the domain as the least power of two ≥ ring size + 257 (512 for 6, 2048 for 1023).

The 0.8.0 vectors fix it at the chain's V, whatever |γ_P'| is: in jam-test-vectors 0.8.0
`stf/safrole/full/enact-epoch-change-with-set-resize-1.json`, γ_P' holds 6 keys and its γ_Z' is the
commitment over the domain of 2048 (ring size 1023), not 512. `JamCrypto.Ring.root srs V keys`
takes V explicitly; `tests/vectors/ring-root-jam.txt` includes that case.

## Context strings: `$jam_…` is notation, not octets (model issue in jam-lean)

The GP writes contexts as `$jam_ticket_seal`, `$jam_valid`, …; the `$` marks a string token and is
not part of the octets. Ring VRF tickets in jam-test-vectors 0.8.0 (`stf/safrole`) verify with the
context "jam_ticket_seal" ⌢ η'_2 ⌢ attempt, and fail with a leading `$`
(`tests/vectors/ring-ticket-jam.txt`, checked by `ringtest`).

jam-lean's `JAM.contextString "$jam_ticket_seal"` (Safrole.lean) keeps the `$`, as do `Xvalid`,
`Xinvalid`, `Xguarantee` (Disputes.lean) and `Xavailable` (Assurances.lean). Reported to the
jam-lean session; `JamCrypto.Ring.verify` takes the context as given.

The same holds for the Bandersnatch IETF VRF and Ed25519 contexts: in the 0.8.0 `no_forks` session
and the 0.8.0 fuzz-report traces, every seal (`jam_fallback_seal` ⌢ η'_3), entropy source
(`jam_entropy` ⌢ Y(H_S)) and Ed25519 assurance, guarantee and judgment signature verifies with the
context octets without `$` (`JamCrypto.Bandersnatch.ietfVerify`, `JamCrypto.Ed25519.verify`, and
ark-vrf 0.1.0 / ed25519-dalek), and none with it; the one IETF signature that fails is in a trace
step polkajam also rejects.

## Ed25519 acceptance rules: ZIP 215 (GP leaves it open; Adam's decision 2026-11-15)

GP v0.8.0 (notation.tex) defines 𝕍̄_k⟨m⟩ as "the set of valid Ed25519 signatures, defined by
[RFC 8032]". RFC 8032 §5.1.7 allows the cofactored check [8][S]B = [8]R + [8][k]A or the
cofactorless [S]B = R + [k]A, and its §5.1.3 decoding rejects non-canonical encodings, which
widely used implementations accept. The jam-fuzzing consensus vectors (commit 5bbd4266,
`crypto/ed25519`, removed by #219) target ZIP 215: small-order and non-canonically encoded A and R
with s = 0, all valid. `JamCrypto.Ed25519.verify` follows ZIP 215; the RFC 8032 strict variants
are parameters (`Ed25519.Rules`), and `JamCryptoTest/vectors/ed25519.txt` gives each vector's
verdict under all three.

## Bandersnatch IETF VRF: the cited spec draft's prose disagrees with its vectors

GP v0.8.0 Appendix G cites the Bandersnatch VRF-AD specification, "Draft 29" (biblio.bib,
`hosseini2024bandersnatch`). Draft 29 (davxy/bandersnatch-vrf-spec, commit 01b0eb0, §2.1) says
`cLen` = 16 and that `string_to_int` reads little-endian. A 16-octet challenge would make the
signature 32 + 16 + 32 = 80 octets, but GP (bandersnatch.tex) has 𝔹̄_k⟨c⟩⟨m⟩ ⊂ 𝕐_96. Draft 29's
own IETF test vectors are those of ark-vrf 0.1.0: a 32-octet c, derived as the first 32 octets of
the SHA-512 challenge hash read big-endian, reduced mod r, stored little-endian (ark-vrf 0.1.0
`utils::challenge_rfc_9381`). Draft 28 (commit 38cf32d) still says `cLen` = 32. `JamCrypto.Bandersnatch`
follows the vectors and GP's 96 octets. Two further details come from arkworks 0.5 rather than from
RFC 9380, which the spec cites: `expand_message_xmd` pads with 48 zero octets instead of SHA-512's
block size of 128, and the Elligator 2 sign rule makes y odd for the first candidate x and even for
the second (instead of matching the sign of u). The fuzzer's blocks verify with both.

## GP v0.8.1 (GP #550): Thin VRF and the VRF spec's Draft 35

GP v0.8.1 switches 𝔹̄ to the **Thin VRF** and cites the Bandersnatch VRF-AD specification
**Draft 35** (davxy/bandersnatch-vrf-spec commit 181aba2) for all of Appendix G, so the ring VRF
changes too. The v0.8.1 path is chosen by `JamCrypto.GpVersion.v081`. The target selects it with
`--gp 0.8.1` or `JAM_GP=0.8.1`; the default stays 0.8.0 until the jam-lean pin moves to its
gp-v0.8.1 branch. Only the crypto changes; the state transition is still the pinned model's.

* `JamCrypto/ThinVrf.lean`: suite `Bandersnatch-SHA512-ELL2-v1`, SHA-512 counter-mode transcript,
  hash to curve (DST suite_id ⌢ 0x60), output hash, Thin VRF prove and verify. Tests: the spec's 7
  thin vectors (`JamCryptoTest/vectors/bandersnatch_thin.txt`).
* `JamCrypto/PedersenVrf.lean`: the Draft 35 Pedersen VRF. Tests: the spec's 7 pedersen vectors.
* `JamCrypto/RingVerify081.lean`, and `Ring.Consts.v081` for the ring root: compared with v0.8.0,
  the ring proof (SNARK) and the ring layout are unchanged. The constants (blinding base,
  padding point, accumulator seed; each is hash_to_curve of its name, which cryptotest checks)
  and the ring transcript's label (the new suite id) are new, and so are the Pedersen proof and
  the output hash. Tests: the spec's 7 ring vectors, roots and proofs (`tests/vectors/ring-d35.txt`).

Choices the paper and the draft leave open:

* **96-octet signature layout.** GP gives 𝔹̄ as 96-octet strings and reads Y from the signature,
  but the draft encodes only the proof (R, s). We read it as O ⌢ R ⌢ s, the output point first as
  in the v0.8.0 IETF signature and the ring proof (`Thin.thinEncode`/`thinDecode`); Adam,
  2026-11-25. The planned check: once fuzzer blocks for 0.8.1 exist, only one layout will verify.
* **Z_pad**: hash to curve uses a zero prefix of 48 octets, not RFC 9380's 128. Draft 35's own
  vectors require this, and Draft 36 states it explicitly.
* **Ring transcript label**: §5 of the draft says the ring proof transcript starts with a
  "ring-proof" label. Its ring vectors verify only with the suite id `Bandersnatch-SHA512-ELL2-v1`
  as the label, so we follow the vectors.
* **Ring domain**: §5 of Draft 35 fixes the domain at 2048. The 181aba2 ring vectors themselves
  use domain 512; the spec's later commit 0b7422f regenerates them at 2048, and our root matches
  that regeneration too. Adam, 2026-11-25: the v0.8.1 path uses the fixed domain 2048 of the cited
  §5 for every chain, tiny included (`Ring.domain081`, a parameter of `Ring.crypto`), as the
  reading of the cited spec, to be confirmed by 0.8.1 vectors or fuzzer blocks. The v0.8.0 path
  stays sized by V.
