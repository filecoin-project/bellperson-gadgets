use crate::circuit::boolean::Boolean;
use crate::circuit::num::AllocatedNum;
use bellman::{ConstraintSystem, SynthesisError};
use ff::Field;
use ff::PrimeField;
use pairing::Engine;

use super::circuit::CircuitHasher;
use super::HashDomain;
use crate::mp::bignat::BigNat;
use crate::util::num::Num;
use crate::OptionExt;

pub mod helper {
    use ff::Field;
    use ff::PrimeField;
    use rug::Integer;

    use super::super::low_k_bits;
    use super::super::HashDomain;
    use super::super::Hasher;
    use crate::util::convert::f_to_nat;

    pub fn hash_to_integer<H: Hasher>(inputs: &[H::F], domain: &HashDomain, hasher: &H) -> Integer {
        let bits_per_hash = <H::F as PrimeField>::CAPACITY as usize;

        let bits_from_hash = domain.n_bits - 1 - domain.n_trailing_ones;
        let n_hashes = (bits_from_hash - 1) / bits_per_hash + 1;

        // First we hash the inputs
        let hash = hasher.hash(inputs);

        // Then, to get more bits, we extend additively
        let mut sum_of_hashes = low_k_bits(&f_to_nat(&hash), bits_per_hash);
        let mut perm = hash;
        for i in 1..n_hashes {
            perm.add_assign(&H::F::one());
            let low_bits = low_k_bits(&f_to_nat(&perm), bits_per_hash);
            sum_of_hashes += low_bits << (bits_per_hash * i) as u32;
        }

        // Now we assemble the 1024b number. Notice the ORs are all disjoint.
        let mut acc = (Integer::from(1) << domain.n_trailing_ones as u32) - Integer::from(1usize);
        acc |= low_k_bits(&sum_of_hashes, bits_from_hash) << domain.n_trailing_ones as u32;
        acc |= Integer::from(1) << (domain.n_bits - 1) as u32;
        acc
    }
}

pub fn hash_to_integer<E, H, CS>(
    mut cs: CS,
    input: &[AllocatedNum<E>],
    limb_width: usize,
    domain: &HashDomain,
    hasher: &H,
) -> Result<BigNat<E>, SynthesisError>
where
    E: Engine,
    H: CircuitHasher<E = E>,
    CS: ConstraintSystem<E>,
{
    let bits_per_hash = E::Fr::CAPACITY as usize;
    let bits_from_hash = domain.n_bits - 1 - domain.n_trailing_ones;
    let n_hashes = (bits_from_hash - 1) / bits_per_hash + 1;

    // First we hash the inputs, with poseidon
    let hash = hasher.allocate_hash(cs.namespace(|| "inputs"), &input)?;

    let mut hash_bits = hash.into_bits_le_strict(cs.namespace(|| "bitify"))?;
    hash_bits.truncate(bits_per_hash);

    // Then we extend with MiMC
    let mut perm = hash.clone();
    for i in 0..(n_hashes - 1) {
        let new = AllocatedNum::alloc(cs.namespace(|| format!("perm {}", i)), || {
            Ok({
                let mut t = perm.get_value().grab()?.clone();
                t.add_assign(&E::Fr::one());
                t
            })
        })?;
        cs.enforce(
            || format!("correct perm {}", i),
            |lc| lc,
            |lc| lc,
            |lc| lc + new.get_variable() - perm.get_variable() - CS::one(),
        );
        perm = new;
        let low_bits: Vec<Boolean> = {
            let mut b = perm.into_bits_le_strict(cs.namespace(|| format!("bitify {}", i)))?;
            b.truncate(bits_per_hash);
            b
        };
        hash_bits.extend(low_bits);
    }

    let mut all_bits = Vec::new();
    all_bits.extend(std::iter::repeat(Boolean::Constant(true)).take(domain.n_trailing_ones));
    all_bits.extend(hash_bits.into_iter().take(bits_from_hash));
    all_bits.push(Boolean::Constant(true));
    let nat = BigNat::from_limbs(
        all_bits
            .into_iter()
            .map(|bit| {
                let lc = bit.lc(CS::one(), E::Fr::one());
                let val = bit
                    .get_value()
                    .map(|v| if v { E::Fr::one() } else { E::Fr::zero() });
                Num::new(val, lc)
            })
            .collect(),
        1,
    );
    Ok(nat.group_limbs(limb_width))
}
