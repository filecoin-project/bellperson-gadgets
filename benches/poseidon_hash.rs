#![feature(test)]

extern crate test;

use bellperson_gadgets::group_hash::BlakeHasher;
use bellperson_gadgets::poseidon::bn256::Bn256PoseidonParams;
use bellperson_gadgets::poseidon::{poseidon_hash, PoseidonHashParams};
use pairing::bn256::{Bn256, Fr};
use rand::{Rng, SeedableRng, XorShiftRng};

#[bench]
fn bench_poseidon_hash(b: &mut test::Bencher) {
    let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
    let params = Bn256PoseidonParams::new::<BlakeHasher>();
    let input: Vec<Fr> = (0..(params.t() - 1) * 2).map(|_| rng.gen()).collect();

    b.iter(|| {
        poseidon_hash::<Bn256>(&params, &input[..]);
    });
}
