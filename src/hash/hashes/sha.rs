use crate::circuit::num::AllocatedNum;
use bellman::ConstraintSystem;
use pairing::Engine;

use crate::util::bench::WitnessTimer;

/// Use the sha256 hash algorithm to digest these items
pub fn sha256<E: Engine>(inputs: &[E::Fr]) -> E::Fr {
    let mut cs = WitnessTimer::new();
    let nums: Vec<AllocatedNum<E>> = inputs
        .into_iter()
        .enumerate()
        .map(|(i, input)| {
            AllocatedNum::alloc(cs.namespace(|| format!("input {}", i)), || Ok(*input)).unwrap()
        })
        .collect();
    let output = circuit::sha256(cs.namespace(|| "sha"), &nums).unwrap();
    output.get_value().unwrap()
}

pub mod circuit {
    use crate::circuit::boolean::Boolean;
    use crate::circuit::num::AllocatedNum;
    use crate::circuit::sha256::sha256 as sapling_sha256;
    use bellman::ConstraintSystem;
    use ff::{Field, PrimeField};
    use pairing::Engine;
    use rug::Integer;

    use crate::util::convert::nat_to_f;
    use crate::util::convert::usize_to_f;
    use crate::CResult;
    use crate::OptionExt;

    use std::cmp::min;
    use std::iter::repeat;

    pub fn bools_to_num<E: Engine, CS: ConstraintSystem<E>>(
        mut cs: CS,
        input: &[Boolean],
    ) -> CResult<AllocatedNum<E>> {
        let bits = &input[..min(input.len(), <E::Fr as PrimeField>::CAPACITY as usize)];
        let num = AllocatedNum::alloc(cs.namespace(|| "num"), || {
            bits.iter()
                .enumerate()
                .try_fold(E::Fr::zero(), |mut acc, (i, b)| {
                    let mut bit = usize_to_f::<E::Fr>(*b.get_value().grab()? as usize);
                    bit.mul_assign(
                        &nat_to_f(&(Integer::from(1) << i as u32)).expect("out-of-bounds scalar"),
                    );
                    acc.add_assign(&bit);
                    Ok(acc)
                })
        })?;
        cs.enforce(
            || "sum",
            |lc| lc,
            |lc| lc,
            |lc| {
                bits.iter()
                    .enumerate()
                    .fold(lc - num.get_variable(), |acc, (i, b)| {
                        acc + &b.lc(
                            CS::one(),
                            nat_to_f(&(Integer::from(1) << i as u32))
                                .expect("out-of-bounds scalar"),
                        )
                    })
            },
        );
        Ok(num)
    }

    pub fn sha256<E: Engine, CS: ConstraintSystem<E>>(
        mut cs: CS,
        inputs: &[AllocatedNum<E>],
    ) -> CResult<AllocatedNum<E>> {
        let mut bits = inputs.into_iter().enumerate().try_fold(
            Vec::new(),
            |mut v, (i, n)| -> CResult<Vec<Boolean>> {
                v.extend(n.into_bits_le_strict(cs.namespace(|| format!("bits {}", i)))?);
                Ok(v)
            },
        )?;
        bits.extend(
            repeat(Boolean::constant(false)).take(((bits.len() - 1) / 8 + 1) * 8 - bits.len()),
        );
        assert_eq!(bits.len() % 8, 0);
        let digest = sapling_sha256(cs.namespace(|| "sapling sha"), &bits)?;
        bools_to_num(cs.namespace(|| "to num"), &digest)
    }
}
