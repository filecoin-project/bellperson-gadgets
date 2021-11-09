// #[cfg(test)]
pub mod test;

pub mod as_waksman;
pub mod baby_ecc;
pub mod baby_eddsa;
pub mod baby_pedersen_hash;
pub mod blake2s;
pub mod boolean;
pub mod ecc;
pub mod float_point;
pub mod lookup;
pub mod merkle;
pub mod multieq;
pub mod multipack;
pub mod num;
pub mod pedersen_hash;
pub mod polynomial_lookup;
pub mod poseidon_hash;
pub mod sha256;
pub mod uint32;

pub mod sapling;
pub mod sprout;

use bellman::SynthesisError;

pub trait Assignment<T> {
    fn get(&self) -> Result<&T, SynthesisError>;
}

impl<T> Assignment<T> for Option<T> {
    fn get(&self) -> Result<&T, SynthesisError> {
        match *self {
            Some(ref v) => Ok(v),
            None => Err(SynthesisError::AssignmentMissing),
        }
    }
}
