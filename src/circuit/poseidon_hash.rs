use super::boolean::Boolean;
use super::num::{AllocatedNum, Num};
use super::Assignment;
use crate::poseidon::{PoseidonEngine, PoseidonHashParams, QuinticSBox, SBox};
use bellman::{ConstraintSystem, SynthesisError};
use ff::{Field, PrimeField};
use pairing::Engine;

impl<E: PoseidonEngine> QuinticSBox<E> {
    fn apply_constraints<CS: ConstraintSystem<E>>(
        mut cs: CS,
        state: &[AllocatedNum<E>],
    ) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
        let mut squares = vec![];
        for (i, el) in state.iter().enumerate() {
            let sq = el.square(cs.namespace(|| format!("make 2nd power term for word {}", i)))?;
            squares.push(sq);
        }

        let mut quads = vec![];
        for (i, el) in squares.iter().enumerate() {
            let qd = el.square(cs.namespace(|| format!("make 4th power term for word {}", i)))?;
            quads.push(qd);
        }

        let mut result = vec![];
        for (i, (el, st)) in quads.iter().zip(state.iter()).enumerate() {
            let res = el.mul(
                cs.namespace(|| format!("make 5th power term for word {}", i)),
                &st,
            )?;
            result.push(res);
        }

        Ok(result)
    }

    fn apply_sbox<CS: ConstraintSystem<E>>(
        mut cs: CS,
        state: &[Num<E>],
    ) -> Result<Vec<AllocatedNum<E>>, SynthesisError> {
        let mut squares = vec![];
        for (i, el) in state.iter().enumerate() {
            let sq = AllocatedNum::alloc(
                cs.namespace(|| format!("make 2nd power term for word {}", i)),
                || {
                    let mut val = *el.get_value().get()?;
                    val.square();

                    Ok(val)
                },
            )?;

            cs.enforce(
                || format!("enforce 2nd power term for word {}", i),
                |_| el.lc(E::Fr::one()),
                |_| el.lc(E::Fr::one()),
                |lc| lc + sq.get_variable(),
            );
            squares.push(sq);
        }

        let mut quads = vec![];
        for (i, el) in squares.iter().enumerate() {
            let qd = el.square(cs.namespace(|| format!("make 4th power term for word {}", i)))?;
            quads.push(qd);
        }

        let mut result = vec![];
        for (i, (el, st)) in quads.iter().zip(state.iter()).enumerate() {
            let res = AllocatedNum::alloc(
                cs.namespace(|| format!("make 5th power term for word {}", i)),
                || {
                    let mut val = *st.get_value().get()?;
                    let other = *el.get_value().get()?;
                    val.mul_assign(&other);

                    Ok(val)
                },
            )?;

            cs.enforce(
                || format!("enforce 5th power term for word {}", i),
                |_| st.lc(E::Fr::one()),
                |lc| lc + el.get_variable(),
                |lc| lc + res.get_variable(),
            );

            result.push(res);
        }

        Ok(result)
    }
}

pub fn poseidon_hash<E: PoseidonEngine<SBox = QuinticSBox<E>>, CS>(
    mut cs: CS,
    input: &[AllocatedNum<E>],
    params: &E::Params,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError>
where
    CS: ConstraintSystem<E>,
{
    let output_len = params.output_len() as usize;
    let absorbtion_len = params.absorbtion_cycle_len() as usize;
    let t = params.t();

    let mut absorbtion_cycles = input.len() / absorbtion_len;
    if input.len() % absorbtion_len != 0 {
        absorbtion_cycles += 1;
    }

    // convert input into Nums
    let mut input: Vec<Num<E>> = input.iter().map(|el| Num::from(el.clone())).collect();
    input.resize(absorbtion_cycles * absorbtion_len, Num::zero());

    // make initial state: perform mimc round on an empty vector
    // TODO: make static precomputation
    let initial_state: Vec<E::Fr> =
        crate::poseidon::poseidon_mimc::<E>(params, &vec![E::Fr::zero(); t as usize]);
    let mut state: Vec<Num<E>> = initial_state
        .into_iter()
        .map(|el| {
            let mut lc = Num::zero();
            lc = lc.add_bool_with_coeff(CS::one(), &Boolean::constant(true), el);

            lc
        })
        .collect();

    for i in 0..absorbtion_cycles {
        // Don't touch top words of the state, only the bottom ones
        let absorbtion_slice = &input[(i * absorbtion_len)..((i + 1) * absorbtion_len)];
        for (w, abs) in state.iter_mut().zip(absorbtion_slice.iter()) {
            w.add_assign(abs);
        }
        state = poseidon_mimc_round(
            cs.namespace(|| format!("Poseidon mimc round {}", i)),
            &state,
            params,
        )?;
    }

    let mut result = vec![];

    for (i, num) in state[..output_len].iter().enumerate() {
        let allocated: AllocatedNum<E> = AllocatedNum::alloc(
            cs.namespace(|| format!("allocate output word {}", i)),
            || {
                let val = *num.get_value().get()?;

                Ok(val)
            },
        )?;

        cs.enforce(
            || format!("enforce allocaiton for word {}", i),
            |_| num.lc(E::Fr::one()),
            |lc| lc + CS::one(),
            |lc| lc + allocated.get_variable(),
        );

        result.push(allocated);
    }

    Ok(result)
}

pub fn poseidon_mimc<E: PoseidonEngine<SBox = QuinticSBox<E>>, CS>(
    mut cs: CS,
    input: &[AllocatedNum<E>],
    params: &E::Params,
) -> Result<Vec<AllocatedNum<E>>, SynthesisError>
where
    CS: ConstraintSystem<E>,
{
    let expected_input_len = params.t() as usize;
    assert!(input.len() == expected_input_len);

    let state_len = params.t();
    // we have to perform R_f -> R_p -> R_f

    // no optimization will be done in the first version in terms of reordering of
    // linear transformations, round constants additions and S-Boxes

    // let mut round = 0;

    // let r_f = params.r_f();
    // let r_p = params.r_p();
    // let t = params.t();

    // fn form_round_constants_linear_combinations<E: PoseidonEngine, CS>(
    //     params: &E::Params,
    //     words: &[AllocatedNum<E>],
    //     round: u32,
    //     full_round: bool) -> Vec<Num<E>>
    // where CS: ConstraintSystem<E> {
    //     let round_constants = if full_round {
    //         params.full_round_key(round)
    //     } else {
    //         params.partial_round_key(round)
    //     };
    //     let mut linear_combinations = vec![];
    //     for (el, c) in words.iter().zip(round_constants.iter()) {
    //         let mut lc = Num::from(el.clone());
    //         lc = lc.add_bool_with_coeff(CS::one(), &Boolean::constant(true), *c);
    //         linear_combinations.push(lc);
    //     }

    //     linear_combinations
    // }

    let state: Vec<Num<E>> = input.iter().map(|el| Num::from(el.clone())).collect();

    let round_result = poseidon_mimc_round(cs.namespace(|| "mimc round"), &state, params)?;

    let mut result = vec![];

    for (i, num) in round_result.iter().enumerate() {
        let allocated: AllocatedNum<E> = AllocatedNum::alloc(
            cs.namespace(|| format!("allocate output word {}", i)),
            || {
                let val = *num.get_value().get()?;

                Ok(val)
            },
        )?;

        cs.enforce(
            || format!("enforce allocaiton for word {}", i),
            |_| num.lc(E::Fr::one()),
            |lc| lc + CS::one(),
            |lc| lc + allocated.get_variable(),
        );

        result.push(allocated);
    }

    Ok(result)
}

fn poseidon_mimc_round<E: PoseidonEngine<SBox = QuinticSBox<E>>, CS>(
    mut cs: CS,
    input: &[Num<E>],
    params: &E::Params,
) -> Result<Vec<Num<E>>, SynthesisError>
where
    CS: ConstraintSystem<E>,
{
    let expected_input_len = params.t() as usize;
    assert!(input.len() == expected_input_len);

    let state_len = params.t();
    // we have to perform R_f -> R_p -> R_f

    // no optimization will be done in the first version in terms of reordering of
    // linear transformations, round constants additions and S-Boxes

    let mut round = 0;

    let r_f = params.r_f();
    let r_p = params.r_p();
    let t = params.t();
    let pre_full_rounds = r_f - r_f / 2;

    fn add_round_constants<E: PoseidonEngine, CS>(
        params: &E::Params,
        words: &mut [Num<E>],
        round: u32,
        full_round: bool,
    ) where
        CS: ConstraintSystem<E>,
    {
        let round_constants = if full_round {
            params.full_round_key(round)
        } else {
            params.partial_round_key(round)
        };
        for (el, c) in words.iter_mut().zip(round_constants.iter()) {
            el.mut_add_bool_with_coeff(CS::one(), &Boolean::constant(true), *c);
        }
    }

    // before the first round form linear combinations manually

    let mut state = input.to_vec();
    add_round_constants::<E, CS>(params, &mut state[..], 0, true);

    // do releated applications of MDS and then round constants and s-boxes

    for full_round in 0..(pre_full_rounds - 1) {
        let s_box_applied = E::SBox::apply_sbox(
            cs.namespace(|| format!("apply s-box for full round {}", full_round)),
            &state[..],
        )?;

        let mut linear_transformation_results = vec![];
        for row in 0..t {
            let row = params.mds_matrix_row(row);
            let linear_applied = scalar_product(&s_box_applied[..], row);
            linear_transformation_results.push(linear_applied);
        }

        add_round_constants::<E, CS>(
            params,
            &mut linear_transformation_results[..],
            full_round + 1,
            true,
        );

        state = linear_transformation_results;

        round += 1;
    }

    // up to this point we always made a well-formed LC that later was collapsed into
    // a signel variable after non-linearity application
    // now we need to make linear combinations of linear combinations, so basically make
    // filtering and joining. It's actually possible to just separate MSD matrix into
    // three in later optimizations

    // now we need to apply full SBox of the last full round, then do linear
    // transformation and add first round constants before going through partial rounds
    {
        let s_box_applied = E::SBox::apply_sbox(
            cs.namespace(|| format!("apply s-box for full round {}", pre_full_rounds - 1)),
            &state[..],
        )?;

        let mut linear_transformation_results = vec![];
        for row in 0..t {
            let row = params.mds_matrix_row(row);
            let linear_applied = scalar_product(&s_box_applied[..], row);
            linear_transformation_results.push(linear_applied);
        }

        add_round_constants::<E, CS>(params, &mut linear_transformation_results[..], 0, false);
        state = linear_transformation_results;

        // up to this point linear combinations are well-formed and have number
        // of terms equal to the number of variables in the state

        round += 1;
    }

    for partial_round in 0..(r_p - 1) {
        let s_box_applied = E::SBox::apply_sbox(
            cs.namespace(|| format!("apply s-box for partial round {}", partial_round)),
            &state[0..1],
        )?;

        // at this point state is a vector of linear combinations except of the first one that has to be replaced

        state[0] = Num::from(s_box_applied[0].clone());

        let mut linear_transformation_results = vec![];
        for row in 0..t {
            let row = params.mds_matrix_row(row);
            let linear_applied = scalar_product_over_lc(&state[..], row);
            linear_transformation_results.push(linear_applied);
        }

        add_round_constants::<E, CS>(
            params,
            &mut linear_transformation_results[..],
            partial_round + 1,
            false,
        );

        state = linear_transformation_results;

        round += 1;
    }

    // do the same after partial round: s-box, linear and add round constants
    {
        let s_box_applied = E::SBox::apply_sbox(
            cs.namespace(|| format!("apply s-box for partial round {}", r_p - 1)),
            &state[0..1],
        )?;

        state[0] = Num::from(s_box_applied[0].clone());

        let mut linear_transformation_results = vec![];
        for row in 0..t {
            let row = params.mds_matrix_row(row);
            let linear_applied = scalar_product_over_lc(&state[..], row);
            linear_transformation_results.push(linear_applied);
        }

        add_round_constants::<E, CS>(
            params,
            &mut linear_transformation_results[..],
            pre_full_rounds,
            true,
        );
        state = linear_transformation_results;

        round += 1;
    }

    for full_round in pre_full_rounds..(r_f - 1) {
        let s_box_applied = E::SBox::apply_sbox(
            cs.namespace(|| format!("apply s-box for full round {}", full_round)),
            &state[..],
        )?;

        let mut linear_transformation_results = vec![];
        for row in 0..t {
            let row = params.mds_matrix_row(row);
            let linear_applied = scalar_product(&s_box_applied[..], row);
            linear_transformation_results.push(linear_applied);
        }

        add_round_constants::<E, CS>(
            params,
            &mut linear_transformation_results[..],
            full_round + 1,
            true,
        );

        state = linear_transformation_results;

        round += 1;
    }

    // for a final round we only apply s-box
    let full_round = r_f - 1;

    let state = E::SBox::apply_sbox(
        cs.namespace(|| format!("apply s-box for full round {}", full_round)),
        &state[..],
    )?;

    Ok(state.into_iter().map(|el| Num::from(el)).collect())
}

fn scalar_product<E: Engine>(input: &[AllocatedNum<E>], by: &[E::Fr]) -> Num<E> {
    assert!(input.len() == by.len());
    let mut result = Num::zero();
    for (a, b) in input.iter().zip(by.iter()) {
        result = result.add_number_with_coeff(a, *b);
    }

    result
}

fn scalar_product_over_lc<E: Engine>(input: &[Num<E>], by: &[E::Fr]) -> Num<E> {
    // inputs are already linear combinations, so we have to first multiply each of those by
    // scalar and then add them up
    // THIS IS UNSAFE and can only be used here cause we know that each LC is unique in terms of contained variables
    assert!(input.len() == by.len());
    let mut result = Num::zero();
    for (a, b) in input.iter().zip(by.iter()) {
        // this is input LC multiplied by scalar
        let mut this_lc = a.clone();
        this_lc.scale(*b);
        result.add_assign(&this_lc);
    }

    result
}

fn print_lc<E: Engine>(input: &[Num<E>]) {
    for el in input.iter() {
        println!("{}", el.get_value().unwrap());
    }
}

fn print_nums<E: Engine>(input: &[AllocatedNum<E>]) {
    for el in input.iter() {
        println!("{}", el.get_value().unwrap());
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::circuit::test::*;
    use crate::group_hash::BlakeHasher;
    use crate::poseidon;
    use crate::poseidon::bn256::*;
    use ff::PrimeField;
    use pairing::bn256::{Bn256, Fr};
    use rand::{Rng, SeedableRng, XorShiftRng};

    #[test]
    fn test_poseidon_mimc_gadget() {
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = Bn256PoseidonParams::new::<BlakeHasher>();
        let input: Vec<Fr> = (0..params.t()).map(|_| rng.gen()).collect();
        let expected = poseidon::poseidon_mimc::<Bn256>(&params, &input[..]);

        {
            let mut cs = TestConstraintSystem::<Bn256>::new();

            let input_words: Vec<AllocatedNum<Bn256>> = input
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("input {}", i)), || Ok(*b)).unwrap()
                })
                .collect();

            let res =
                poseidon_mimc(cs.namespace(|| "poseidon mimc"), &input_words, &params).unwrap();

            assert!(cs.is_satisfied());
            assert!(res.len() == (params.t() as usize));

            assert_eq!(res[0].get_value().unwrap(), expected[0]);
        }
    }

    #[test]
    fn test_poseidon_hash_gadget() {
        let mut rng = XorShiftRng::from_seed([0x3dbe6259, 0x8d313d76, 0x3237db17, 0xe5bc0654]);
        let params = Bn256PoseidonParams::new::<BlakeHasher>();
        let input: Vec<Fr> = (0..(params.t() - 1) * 2).map(|_| rng.gen()).collect();
        let expected = poseidon::poseidon_hash::<Bn256>(&params, &input[..]);

        {
            let mut cs = TestConstraintSystem::<Bn256>::new();

            let input_words: Vec<AllocatedNum<Bn256>> = input
                .iter()
                .enumerate()
                .map(|(i, b)| {
                    AllocatedNum::alloc(cs.namespace(|| format!("input {}", i)), || Ok(*b)).unwrap()
                })
                .collect();

            let res =
                poseidon_hash(cs.namespace(|| "poseidon hash"), &input_words, &params).unwrap();

            assert!(cs.is_satisfied());
            assert!(res.len() == 1);
            println!(
                "Poseidon hash {} to {} taken {} constraints",
                input.len(),
                res.len(),
                cs.num_constraints()
            );

            assert_eq!(res[0].get_value().unwrap(), expected[0]);
        }
    }
}
