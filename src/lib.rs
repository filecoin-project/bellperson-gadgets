#![allow(unused_imports)]
#![allow(dead_code)]
#![allow(unused_variables)]

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate derivative;

#[cfg(test)]
extern crate quickcheck;
#[cfg(test)]
#[macro_use(quickcheck)]
extern crate quickcheck_macros;

#[cfg(test)]
#[macro_use]
extern crate hex_literal;

pub mod alt_babyjubjub;
pub mod as_waksman;
pub mod baby_group_hash;
pub mod baby_pedersen_hash;
pub mod baby_util;
pub mod babyjubjub;
pub mod circuit;
pub mod constants;
pub mod eddsa;
pub mod group_hash;
pub mod interpolation;
pub mod jubjub;
pub mod pedersen_hash;
pub mod poseidon;
pub mod primitives;
pub mod redbabyjubjub;
pub mod redjubjub;
#[macro_use]
pub mod util;
pub mod group;
pub mod hash;
pub mod mp;
pub mod rollup;
pub mod set;
pub mod wesolowski;

use bellman::SynthesisError;

type CResult<T> = Result<T, SynthesisError>;

trait OptionExt<T> {
    fn grab(&self) -> Result<&T, SynthesisError>;
    fn grab_mut(&mut self) -> Result<&mut T, SynthesisError>;
}

impl<T> OptionExt<T> for Option<T> {
    fn grab(&self) -> Result<&T, SynthesisError> {
        self.as_ref().ok_or(SynthesisError::AssignmentMissing)
    }
    fn grab_mut(&mut self) -> Result<&mut T, SynthesisError> {
        self.as_mut().ok_or(SynthesisError::AssignmentMissing)
    }
}
