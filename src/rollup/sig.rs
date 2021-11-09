use crate::circuit::baby_eddsa::EddsaSignature;
use crate::circuit::ecc::EdwardsPoint;
use crate::circuit::num::AllocatedNum;
use crate::eddsa::{PublicKey, Signature};
use crate::jubjub::edwards::Point;
use crate::jubjub::JubjubEngine;
use bellman::ConstraintSystem;

use crate::util::convert::{f_to_nat, nat_to_f};
use crate::CResult;
use crate::OptionExt;

pub fn allocate_point<E: JubjubEngine, Subgroup, CS: ConstraintSystem<E>>(
    mut cs: CS,
    value: Option<&Point<E, Subgroup>>,
    param: &E::Params,
) -> CResult<EdwardsPoint<E>> {
    let x = AllocatedNum::alloc(cs.namespace(|| "x"), || Ok(value.grab()?.into_xy().0))?;
    let y = AllocatedNum::alloc(cs.namespace(|| "y"), || Ok(value.grab()?.into_xy().1))?;
    EdwardsPoint::interpret(cs.namespace(|| "src"), &x, &y, param)
}

pub fn allocate_sig<E: JubjubEngine, CS: ConstraintSystem<E>>(
    mut cs: CS,
    value: Option<(Signature<E>, PublicKey<E>)>,
    param: &E::Params,
) -> CResult<EddsaSignature<E>> {
    let pk = allocate_point(
        cs.namespace(|| "pk"),
        value.as_ref().map(|&(_, ref pk)| &pk.0),
        param,
    )?;
    let r = allocate_point(
        cs.namespace(|| "r"),
        value.as_ref().map(|&(ref sig, _)| &sig.r),
        param,
    )?;
    let s = AllocatedNum::alloc(cs.namespace(|| "s"), || {
        Ok(nat_to_f(&f_to_nat(&value.grab()?.0.s)).unwrap())
    })?;
    Ok(EddsaSignature { pk, r, s })
}
