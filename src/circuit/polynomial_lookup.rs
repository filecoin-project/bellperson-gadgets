use super::*;
use bellman::{ConstraintSystem, SynthesisError};
use ff::{BitIterator, Field, PrimeField, PrimeFieldRepr};
use pairing::Engine;

pub fn generate_powers<E: Engine, CS>(
    mut cs: CS,
    base: &num::AllocatedNum<E>,
    num_powers: usize,
) -> Result<Vec<num::AllocatedNum<E>>, SynthesisError>
where
    CS: ConstraintSystem<E>,
{
    let mut result = vec![];

    let mut power = num::AllocatedNum::alloc(cs.namespace(|| format!("0-th power")), || {
        return Ok(E::Fr::one());
    })?;

    cs.enforce(
        || "enforce 0-th power",
        |lc| lc + power.get_variable(),
        |lc| lc + CS::one(),
        |lc| lc + CS::one(),
    );

    result.push(power.clone());

    for i in 1..num_powers {
        power = power.mul(cs.namespace(|| format!("{}-th power", i)), &base)?;

        result.push(power.clone());
    }

    Ok(result)
}

pub fn do_the_lookup<E: Engine, CS>(
    mut cs: CS,
    coeffs: &[E::Fr],
    bases: &[num::AllocatedNum<E>],
) -> Result<num::AllocatedNum<E>, SynthesisError>
where
    CS: ConstraintSystem<E>,
{
    assert_eq!(coeffs.len(), bases.len());

    let mut num = num::Num::<E>::zero();
    for (c, b) in coeffs.iter().zip(bases.iter()) {
        num = num.add_number_with_coeff(b, c.clone());
    }

    let result = num::AllocatedNum::alloc(cs.namespace(|| "do the lookup"), || {
        Ok(*num.get_value().get()?)
    })?;

    cs.enforce(
        || "enforce a lookup",
        |lc| lc + result.get_variable(),
        |lc| lc + CS::one(),
        |_| num.lc(E::Fr::one()),
    );

    Ok(result)
}
