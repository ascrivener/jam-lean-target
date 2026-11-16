Responses are GP v0.8.0's. The last column is the erasure root under GP #580's erasure code (not
v0.8.0's), for cross-checks only.

| # | case | response | summary | erasure root, GP #580 code |
|---|------|----------|---------|----|
| 00000002 | halt | work_report | items: ok (44 octets, gas 22); bundle 283 octets, 0 exports | 0xb1d1a2ed4a40a3a55813d7e22429cea11f0b8963776db51b99a0b07ead3fe17d |
| 00000003 | halt_core1 | work_report | items: ok (44 octets, gas 22); bundle 283 octets, 0 exports | 0xb1d1a2ed4a40a3a55813d7e22429cea11f0b8963776db51b99a0b07ead3fe17d |
| 00000004 | panic | work_report | items: panic (gas 2); bundle 283 octets, 0 exports | 0x7053e610a417f20e14af95fec7f8deacebb7e9e2d941d6f839d4d505221ddac4 |
| 00000005 | out_of_gas | work_report | items: outOfGas (gas 990); bundle 283 octets, 0 exports | 0x75affd2d623006e070373218c8cbdebee884883bf18b3105529824990fb88a51 |
| 00000006 | two_items | work_report | items: ok (44 octets, gas 22), panic (gas 2); bundle 347 octets, 0 exports | 0x441331141277fbf802541f9a2a8529219cb43f6d1b8af5647d8f08e032254671 |
| 00000007 | export | work_report | items: ok (0 octets, gas 3621); bundle 283 octets, 1 exports | 0x574ce58a28debefa1c2f8fd674b9ba61e5849f70108a2b407bd2f458d021d7b0 |
| 00000008 | export_two_items | work_report | items: ok (0 octets, gas 3621), ok (0 octets, gas 3621); bundle 354 octets, 2 exports | 0xb8608757bfda10cc924c7db4392918b9b997794cf1867afc159047886400b52e |
| 00000009 | export_then_panic | work_report | items: badExports (gas 7143); bundle 283 octets, 2 exports | 0x92b6022d9eea1e756b4504e3789866827c8d5e3034f8cef1abb55e5cb6cb5327 |
| 00000010 | bad_exports | work_report | items: badExports (gas 22); bundle 283 octets, 1 exports | 0xb659692081702f721091e9ec279634dd321252ee77e58a395f7b3b3ea976e96e |
| 00000011 | panic_with_exports | work_report | items: badExports (gas 2); bundle 283 octets, 1 exports | 0xc336c3ac5a97e4da84f82c05d937d54e9b3624768ad970e04cd6bb9e7f190406 |
| 00000012 | no_code | work_report | items: bad (gas 0); bundle 283 octets, 0 exports | 0xc0cab58298de487b2ce869d0a1306f5342fefc8b996fef46e1768c1a47c42836 |
| 00000013 | oversize | work_report | items: oversize (gas 22); bundle 49430 octets, 0 exports | 0x08c090d45588e07162ab251f6a25978a015fa76f6cd04ad020754b02d94d05f6 |
| 00000014 | oversize_second_item | work_report | items: ok (30039 octets, gas 22), oversize (gas 22); bundle 50337 octets, 0 exports | 0xb55943457ed3661224a8ad13aca954daf201946baf75f76c0834b97f3aab9aa3 |
| 00000015 | extrinsic | work_report | items: ok (44 octets, gas 22); bundle 369 octets, 0 exports | 0xc62ea631a29e759d97af4e6470c2be3bdee8c874f622174527777be1ac68dd15 |
| 00000016 | import_by_root | work_report | items: ok (44 octets, gas 22); bundle 4486 octets, 0 exports | 0x5c0d76318b4badc0b9bec66f60a6007b987f42c674de7093f0599da3bd2881d0 |
| 00000017 | import_by_package | work_report | items: ok (44 octets, gas 22); bundle 8689 octets, 0 exports | 0x625e6f16f60b0b0407660ee73c0963a86afca3d5ee7f5ce26e18c45b8e6cb51b |
| 00000018 | err_auth_panics | error | no work-report: Is-Authorized: JAM.WorkError.panic |  |
| 00000019 | err_extrinsic_mismatch | error | bundle does not verify: an extrinsic of length 14 does not match its (hash, 14) |  |
| 00000020 | err_bad_justification | error | bundle does not verify: import segment 1 does not verify against its justification |  |
| 00000021 | err_lookup_keys | error | no work-report: keys of the segment-root lookup are not the imported package hashes |  |
