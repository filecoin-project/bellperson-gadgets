#![feature(test)]

extern crate test;

use bellperson_gadgets::alt_babyjubjub::AltJubjubBn256;
use bellperson_gadgets::pedersen_hash::{pedersen_hash, Personalization};
use pairing::bn256::Bn256;
use rand::{thread_rng, Rand};

#[bench]
fn bench_baby_pedersen_hash(b: &mut test::Bencher) {
    let params = AltJubjubBn256::new();
    let rng = &mut thread_rng();
    let bits = (0..510).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    let personalization = Personalization::MerkleTree(31);

    b.iter(|| pedersen_hash::<Bn256, _>(personalization, bits.clone(), &params));
}
