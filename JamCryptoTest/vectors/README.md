# JamCrypto test vectors

Read by `lake exe cryptotest` (`JamCryptoTest.lean`). One case per line, fields separated by one
space, octet strings in hex, `-` for the empty string.

## `ed25519.txt`

`tag zip215 rfc8032Strict rfc8032Cofactorless key msg sig`, where the three flags (1 = valid) are
the expected verdicts under the three `JamCrypto.Ed25519.Rules`.

* `rfc8032-*`: the five Ed25519 test vectors of RFC 8032 §7.1.
* `jam-zip215-*`: the 196 consensus-critical vectors of jam-conformance/jam-fuzzing (commit
  5bbd4266, `crypto/ed25519/vectors.json`, removed by #219): small-order A and R, s = 0, canonical
  and non-canonical encodings; ZIP 215 accepts all of them.
* `gen-*`: signatures from ed25519-dalek with deterministic random keys and messages, and their
  mutations: bit flips in R, S, key and message, S + L, torsion added to R, a 63-octet signature,
  and signatures whose R and/or A carry a torsion component but are otherwise consistent (valid
  under the cofactored equation only).

Expected verdicts: ZIP 215 from ed25519-zebra 4 (checked against a curve25519-dalek reference),
the strict variants from that reference (canonical encoding = re-encoding is identical).

## `bandersnatch_ietf.txt`

`tag valid key ctx msg sig Y`: `valid` is the verdict of x ∈ 𝔹̄_key⟨ctx⟩⟨msg⟩ and `Y` the VRF
output of a valid signature (`-` otherwise).

* `ark-vrf-*`: the 7 vectors of ark-vrf 0.1.0 (`data/vectors/bandersnatch_sha-512_ell2_ietf.json`,
  identical to those of the spec's Draft 29), with ctx = alpha, msg = ad, sig = gamma ⌢ c ⌢ s.
* `gen-*`: proofs from ark-vrf 0.1.0 with deterministic random keys, inputs and additional data,
  and mutations: bit flips in the output, c, s and key, another ctx or msg, c + r (accepted: c is
  reduced mod r), s + r (rejected), key or output plus the 2-torsion point (0, −1) (rejected), key
  with y + q (rejected), a 95-octet signature.

Expected verdicts: ark-vrf 0.1.0 verification after checked (`deserialize_compressed`) decoding of
the key, the output point and the proof.

## Regenerating

```
git -C jam-fuzzing show c3c6fb23^:crypto/ed25519/vectors.json > jam_ed25519.json
cd JamCryptoTest/generator
cargo run --release -- rfc8032_ed25519.txt ../../jam_ed25519.json \
  ARK_VRF_0.1.0/data/vectors/bandersnatch_sha-512_ell2_ietf.json ../vectors
```

`rfc8032_ed25519.txt` holds the RFC 8032 §7.1 vectors (`name key msg sig`). The generator is not
part of the Lean build and CI does not run it.
