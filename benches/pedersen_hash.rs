#![feature(test)]
extern crate test;

use bellperson_gadgets::jubjub::JubjubBls12;
use bellperson_gadgets::pedersen_hash::{pedersen_hash, Personalization};
use pairing::bls12_381::Bls12;
use rand::{thread_rng, Rand};

#[bench]
fn bench_pedersen_hash(b: &mut test::Bencher) {
    let params = JubjubBls12::new();
    let rng = &mut thread_rng();
    let bits = (0..510).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    let personalization = Personalization::MerkleTree(31);

    b.iter(|| pedersen_hash::<Bls12, _>(personalization, bits.clone(), &params));
}
