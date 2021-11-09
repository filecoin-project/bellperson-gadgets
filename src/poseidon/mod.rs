use super::group_hash::GroupHasher;
/// Initial implementation of https://eprint.iacr.org/2019/458.pdf
use ff::{Field, PrimeField, PrimeFieldRepr};
use pairing::Engine;
use std::marker::PhantomData;

use rand::{Rand, Rng};

pub mod bls12;
pub mod bn256;

pub trait SBox<E: Engine>: Sized {
    fn apply(elements: &mut [E::Fr]);
}

pub struct CubicSBox<E: Engine> {
    _marker: PhantomData<E>,
}

impl<E: Engine> SBox<E> for CubicSBox<E> {
    fn apply(elements: &mut [E::Fr]) {
        for element in elements.iter_mut() {
            let mut squared = *element;
            squared.square();
            element.mul_assign(&squared);
        }
    }
}

pub struct QuinticSBox<E: Engine> {
    _marker: PhantomData<E>,
}

impl<E: Engine> SBox<E> for QuinticSBox<E> {
    fn apply(elements: &mut [E::Fr]) {
        for element in elements.iter_mut() {
            let mut quad = *element;
            quad.square();
            quad.square();
            element.mul_assign(&quad);
        }
    }
}

pub struct InversionSBox<E: Engine> {
    _marker: PhantomData<E>,
}

fn batch_inversion<E: Engine>(v: &mut [E::Fr]) {
    // Montgomery’s Trick and Fast Implementation of Masked AES
    // Genelle, Prouff and Quisquater
    // Section 3.2

    // First pass: compute [a, ab, abc, ...]
    let mut prod = Vec::with_capacity(v.len());
    let mut tmp = E::Fr::one();
    for g in v
        .iter()
        // Ignore zero elements
        .filter(|g| !g.is_zero())
    {
        tmp.mul_assign(&g);
        prod.push(tmp);
    }

    // Invert `tmp`.
    tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

    // Second pass: iterate backwards to compute inverses
    for (g, s) in v
        .iter_mut()
        // Backwards
        .rev()
        // Ignore normalized elements
        .filter(|g| !g.is_zero())
        // Backwards, skip last element, fill in one for last term.
        .zip(prod.into_iter().rev().skip(1).chain(Some(E::Fr::one())))
    {
        // tmp := tmp * g.z; g.z := tmp * s = 1/z
        let mut newtmp = tmp;
        newtmp.mul_assign(&g);
        *g = tmp;
        g.mul_assign(&s);
        tmp = newtmp;
    }
}

impl<E: Engine> SBox<E> for InversionSBox<E> {
    fn apply(elements: &mut [E::Fr]) {
        batch_inversion::<E>(elements);
    }
}

// TODO: Later use const functions
pub trait PoseidonHashParams<E: Engine>: Sized + Send + Sync {
    fn t(&self) -> u32;
    fn r_f(&self) -> u32;
    fn r_p(&self) -> u32;
    fn full_round_key(&self, round: u32) -> &[E::Fr];
    fn partial_round_key(&self, round: u32) -> &[E::Fr];
    fn mds_matrix_row(&self, row: u32) -> &[E::Fr];
    fn security_level(&self) -> u32;
    fn output_len(&self) -> u32 {
        let output_bits = 2 * self.security_level();
        let mut output_len = E::Fr::CAPACITY / output_bits;
        if E::Fr::CAPACITY % output_bits != 0 && E::Fr::CAPACITY < output_bits {
            output_len += 1;
        }

        output_len
    }
    fn absorbtion_cycle_len(&self) -> u32 {
        self.t() - self.output_len()
    }
    fn compression_rate(&self) -> u32 {
        self.absorbtion_cycle_len() / self.output_len()
    }
}

pub trait PoseidonEngine: Engine {
    type Params: PoseidonHashParams<Self>;
    type SBox: SBox<Self>;
}

pub fn poseidon_hash<E: PoseidonEngine>(params: &E::Params, input: &[E::Fr]) -> Vec<E::Fr> {
    let output_len = params.output_len() as usize;
    let absorbtion_len = params.absorbtion_cycle_len() as usize;
    let t = params.t();

    let mut input = input.to_vec();

    let mut absorbtion_cycles = input.len() / absorbtion_len;
    if input.len() % absorbtion_len != 0 {
        absorbtion_cycles += 1;
    }
    input.resize(absorbtion_cycles * absorbtion_len, E::Fr::zero());

    // follow the original implementation and form an initial permutation by permutting over full zeroes
    // TODO: make static precompute if there is a good way to make it
    let mut state: Vec<E::Fr> = poseidon_mimc::<E>(params, &vec![E::Fr::zero(); t as usize]);
    for i in 0..absorbtion_cycles {
        // Don't touch top words of the state, only the bottom ones
        let absorbtion_slice = &input[(i * absorbtion_len)..((i + 1) * absorbtion_len)];
        for (w, abs) in state.iter_mut().zip(absorbtion_slice.iter()) {
            w.add_assign(abs);
        }
        state = poseidon_mimc::<E>(params, &state);
    }

    state[..output_len].to_vec()
}

pub fn poseidon_mimc<E: PoseidonEngine>(params: &E::Params, input: &[E::Fr]) -> Vec<E::Fr> {
    assert_eq!(input.len(), params.t() as usize);
    let mut state = input.to_vec();
    let state_len = params.t() as usize;

    // we have to perform R_f -> R_p -> R_f

    // no optimization will be done in the first version in terms of reordering of
    // linear transformations, round constants additions and S-Boxes

    let mut round = 0;

    let r_f = params.r_f();
    let r_p = params.r_p();
    let pre_full_rounds = r_f - r_f / 2;

    for full_round in 0..pre_full_rounds {
        let round_constants = params.full_round_key(full_round);
        for (el, c) in state.iter_mut().zip(round_constants.iter()) {
            el.add_assign(c);
        }

        E::SBox::apply(&mut state[..]);

        let mut new_state = vec![E::Fr::zero(); state_len];

        for (row, el) in new_state.iter_mut().enumerate() {
            *el = scalar_product::<E>(&state[..], params.mds_matrix_row(row as u32));
        }

        state = new_state;

        round += 1;
    }

    for partial_round in 0..r_p {
        let round_constants = params.partial_round_key(partial_round);
        for (el, c) in state.iter_mut().zip(round_constants.iter()) {
            el.add_assign(c);
        }

        E::SBox::apply(&mut state[0..1]);

        let mut new_state = vec![E::Fr::zero(); state_len];

        for (row, el) in new_state.iter_mut().enumerate() {
            *el = scalar_product::<E>(&state[..], params.mds_matrix_row(row as u32));
        }
        state = new_state;

        round += 1;
    }

    // reference implementation says that last round does not have matrix muptiplication step,
    // that is true due to ease of inversion
    for full_round in pre_full_rounds..(r_f - 1) {
        let round_constants = params.full_round_key(full_round);
        for (el, c) in state.iter_mut().zip(round_constants.iter()) {
            el.add_assign(c);
        }

        E::SBox::apply(&mut state[..]);

        let mut new_state = vec![E::Fr::zero(); state_len];

        for (row, el) in new_state.iter_mut().enumerate() {
            *el = scalar_product::<E>(&state[..], params.mds_matrix_row(row as u32));
        }
        state = new_state;

        round += 1;
    }

    {
        let full_round = r_f - 1;
        let round_constants = params.full_round_key(full_round);
        for (el, c) in state.iter_mut().zip(round_constants.iter()) {
            el.add_assign(c);
        }

        E::SBox::apply(&mut state[..]);
    }

    state
}

fn scalar_product<E: Engine>(input: &[E::Fr], by: &[E::Fr]) -> E::Fr {
    assert!(input.len() == by.len());
    let mut result = E::Fr::zero();
    for (a, b) in input.iter().zip(by.iter()) {
        let mut tmp = *a;
        tmp.mul_assign(b);
        result.add_assign(&tmp);
    }

    result
}

// For simplicity we'll not generate a matrix using a way from the paper and sampling
// an element with some zero MSBs and instead just sample and retry
fn generate_mds_matrix<E: PoseidonEngine, R: Rng>(t: u32, rng: &mut R) -> Vec<E::Fr> {
    loop {
        let x: Vec<E::Fr> = (0..t).map(|_| rng.gen()).collect();
        let y: Vec<E::Fr> = (0..t).map(|_| rng.gen()).collect();

        let mut invalid = false;

        // quick and dirty check for uniqueness of x
        for i in 0..(t as usize) {
            if invalid {
                continue;
            }
            let el = x[i];
            for other in x[(i + 1)..].iter() {
                if el == *other {
                    invalid = true;
                    break;
                }
            }
        }

        if invalid {
            continue;
        }

        // quick and dirty check for uniqueness of y
        for i in 0..(t as usize) {
            if invalid {
                continue;
            }
            let el = y[i];
            for other in y[(i + 1)..].iter() {
                if el == *other {
                    invalid = true;
                    break;
                }
            }
        }

        if invalid {
            continue;
        }

        // quick and dirty check for uniqueness of x vs y
        for i in 0..(t as usize) {
            if invalid {
                continue;
            }
            let el = x[i];
            for other in y.iter() {
                if el == *other {
                    invalid = true;
                    break;
                }
            }
        }

        if invalid {
            continue;
        }

        // by previous checks we can be sure in uniqueness and perform subtractions easily
        let mut mds_matrix = vec![E::Fr::zero(); (t * t) as usize];
        for (i, x) in x.into_iter().enumerate() {
            for (j, y) in y.iter().enumerate() {
                let place_into = i * (t as usize) + j;
                let mut element = x;
                element.sub_assign(y);
                mds_matrix[place_into] = element;
            }
        }

        // now we need to do the inverse
        batch_inversion::<E>(&mut mds_matrix[..]);

        return mds_matrix;
    }
}
