//! Ring vector generator (ark-vrf 0.1.0, features ring + bandersnatch, as JAM uses it).
//! usage: SRS=path/to/bls12-381-srs-2-11-uncompressed-zcash.bin gen roots > ring-root-ark.txt
use ark_vrf::suites::bandersnatch::*;
use ark_vrf::reexports::ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::env;

fn srs() -> PcsParams {
    let path = env::var("SRS").unwrap();
    let raw = std::fs::read(path).unwrap();
    PcsParams::deserialize_uncompressed_unchecked(&mut &raw[..]).unwrap()
}

fn points(keys: &[Vec<u8>]) -> Vec<AffinePoint> {
    keys.iter().map(|k| Public::deserialize_compressed(&k[..]).map(|p| p.0)
        .unwrap_or(RingProofParams::padding_point())).collect()
}

fn commit(params: &RingProofParams, keys: &[Vec<u8>]) -> Vec<u8> {
    let vk = params.verifier_key(&points(keys));
    let mut out = vec![];
    vk.commitment().serialize_compressed(&mut out).unwrap();
    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let pcs = srs();
    match args[1].as_str() {
        // commit RINGSIZE hexkey...
        "commit" => {
            let rs: usize = args[2].parse().unwrap();
            let params = RingProofParams::from_pcs_params(rs, pcs).unwrap();
            let keys: Vec<Vec<u8>> = args[3..].iter().map(|h| hex::decode(h.trim_start_matches("0x")).unwrap()).collect();
            println!("{}", hex::encode(commit(&params, &keys)));
        }
        // roots: ark-vrf-generated ring roots, one `root ROOT KEY...` line each
        "roots" => roots(pcs),
        _ => panic!(),
    }
}

use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

fn enc(p: &AffinePoint) -> Vec<u8> {
    let mut v = vec![];
    p.serialize_compressed(&mut v).unwrap();
    v
}

fn line(size: usize, params: &RingProofParams, keys: &[Vec<u8>]) {
    let ks: Vec<String> = keys.iter().map(|k| hex::encode(k)).collect();
    println!("root {} {} {}", size, hex::encode(commit(params, keys)), ks.join(" "));
}

fn roots(pcs: PcsParams) {
    let mut rng = ChaCha20Rng::from_seed([7u8; 32]);
    let key = |rng: &mut ChaCha20Rng| -> Vec<u8> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        enc(&Secret::from_seed(&seed).public().0)
    };
    for &(size, n) in &[(6usize, 6usize), (6, 3), (1023, 1023), (1023, 6), (300, 200)] {
        let params = RingProofParams::from_pcs_params(size, pcs.clone()).unwrap();
        let mut keys: Vec<Vec<u8>> = (0..n).map(|_| key(&mut rng)).collect();
        line(size, &params, &keys);
        // padding: bad encodings, off-curve, non-subgroup (x, -y), y >= r, explicit padding point
        let p0 = Public::deserialize_compressed(&keys[0][..]).unwrap().0;
        let mut nonsub = p0; nonsub.y = -nonsub.y;
        let mut yhigh = vec![0xffu8; 32]; yhigh[31] = 0x7f;
        let mut flagged = keys[1].clone(); flagged[31] ^= 0x80; // the other x: -P, still valid
        let specials: Vec<Vec<u8>> = vec![
            vec![0u8; 32], vec![0xffu8; 32], yhigh, enc(&nonsub), vec![1, 2, 3],
            enc(&RingProofParams::padding_point()), flagged,
            { let mut v = vec![0u8; 32]; v[0] = 2; v },
        ];
        for (i, s) in specials.iter().enumerate() {
            let at = (i * 7 + 1) % n;
            keys[at] = s.clone();
        }
        line(size, &params, &keys);
        if n == 1023 { continue; } // keep the committed vectors small
        // a permutation
        let mut perm = keys.clone();
        perm.reverse();
        perm.swap(0, n / 2);
        line(size, &params, &perm);
    }
}
