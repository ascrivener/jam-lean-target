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
