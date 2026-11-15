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
