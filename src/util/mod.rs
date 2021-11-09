pub mod bench;
pub mod bit;
pub mod convert;
pub mod gadget;
pub mod lazy;
pub mod num;
pub mod verbose;

#[cfg(test)]
#[macro_use]
pub mod test_helpers;

use crate::jubjub::{JubjubEngine, ToUniform};
use blake2_rfc_bellman_edition::blake2b::Blake2b;
use blake2_rfc_bellman_edition::blake2s::Blake2s;
use sha2::{Digest, Sha256};

pub fn hash_to_scalar<E: JubjubEngine>(persona: &[u8], a: &[u8], b: &[u8]) -> E::Fs {
    let mut hasher = Blake2b::with_params(64, &[], &[], persona);
    hasher.update(a);
    hasher.update(b);
    let ret = hasher.finalize();
    E::Fs::to_uniform(ret.as_ref())
}

pub fn hash_to_scalar_s<E: JubjubEngine>(persona: &[u8], a: &[u8], b: &[u8]) -> E::Fs {
    let mut hasher = Blake2s::with_params(32, &[], &[], persona);
    hasher.update(a);
    hasher.update(b);
    let ret = hasher.finalize();
    E::Fs::to_uniform_32(ret.as_ref())
}

pub fn sha256_hash_to_scalar<E: JubjubEngine>(persona: &[u8], a: &[u8], b: &[u8]) -> E::Fs {
    let mut hasher = Sha256::new();
    hasher.input(persona);
    hasher.input(a);
    hasher.input(b);
    let result = hasher.result();
    E::Fs::to_uniform_32(result.as_slice())
}
