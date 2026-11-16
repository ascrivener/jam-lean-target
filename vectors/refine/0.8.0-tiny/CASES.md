Responses are GP v0.8.0's. `NNNNNNNN_post080_work_report.bin` (not a response) is the report
after GP #580 (erasure code) and GP #583 (erasure root when nothing is exported), for
comparison tooling only.

| # | case | response | summary |
|---|------|----------|---------|
| 00000002 | halt | work_report | items: ok (44 octets, gas 22), ok (0 octets, gas 3621); bundle 348 octets, 1 exports |
| 00000003 | halt_core1 | work_report | items: ok (44 octets, gas 22), ok (0 octets, gas 3621); bundle 348 octets, 1 exports |
| 00000004 | panic | work_report | items: panic (gas 2), ok (0 octets, gas 3621); bundle 348 octets, 1 exports |
| 00000005 | out_of_gas | work_report | items: outOfGas (gas 990), ok (0 octets, gas 3621); bundle 348 octets, 1 exports |
| 00000006 | two_items | work_report | items: ok (44 octets, gas 22), panic (gas 2), ok (0 octets, gas 3621); bundle 412 octets, 1 exports |
| 00000007 | export | work_report | items: ok (0 octets, gas 3621); bundle 283 octets, 1 exports |
| 00000008 | export_two_items | work_report | items: ok (0 octets, gas 3621), ok (0 octets, gas 3621); bundle 354 octets, 2 exports |
| 00000009 | export_then_panic | work_report | items: badExports (gas 7143); bundle 283 octets, 2 exports |
| 00000010 | bad_exports | work_report | items: badExports (gas 22); bundle 283 octets, 1 exports |
| 00000011 | panic_with_exports | work_report | items: badExports (gas 2); bundle 283 octets, 1 exports |
| 00000012 | no_code | work_report | items: bad (gas 0), ok (0 octets, gas 3621); bundle 348 octets, 1 exports |
| 00000013 | oversize | work_report | items: oversize (gas 22), ok (0 octets, gas 3621); bundle 49495 octets, 1 exports |
| 00000014 | oversize_second_item | work_report | items: ok (30039 octets, gas 22), oversize (gas 22), ok (0 octets, gas 3621); bundle 50402 octets, 1 exports |
| 00000015 | extrinsic | work_report | items: ok (44 octets, gas 22), ok (0 octets, gas 3621); bundle 434 octets, 1 exports |
| 00000016 | import_by_root | work_report | items: ok (44 octets, gas 22), ok (0 octets, gas 3621); bundle 4551 octets, 1 exports |
| 00000017 | import_by_package | work_report | items: ok (44 octets, gas 22), ok (0 octets, gas 3621); bundle 8754 octets, 1 exports |
| 00000018 | err_nothing_exported | error | no work-report: nothing exported: undefined in GP v0.8.0 (see GP #583) |
| 00000019 | err_nothing_exported_two_items | error | no work-report: nothing exported: undefined in GP v0.8.0 (see GP #583) |
| 00000020 | err_auth_panics | error | no work-report: Is-Authorized: JAM.WorkError.panic |
| 00000021 | err_extrinsic_mismatch | error | bundle does not verify: an extrinsic of length 14 does not match its (hash, 14) |
| 00000022 | err_bad_justification | error | bundle does not verify: import segment 1 does not verify against its justification |
| 00000023 | err_lookup_keys | error | no work-report: keys of the segment-root lookup are not the imported package hashes |
