use bellman::{ConstraintSystem, SynthesisError};
use ff::Field;
use ff::PrimeField;
use pairing::Engine;

use crate::circuit::boolean::Boolean;
use crate::circuit::multipack;
use crate::circuit::num::{AllocatedNum, Num};
use crate::circuit::pedersen_hash;
use crate::circuit::poseidon_hash;
use crate::circuit::Assignment;
use crate::jubjub::{JubjubEngine, JubjubParams};
use crate::poseidon::QuinticSBox;
use crate::poseidon::{PoseidonEngine, PoseidonHashParams};

pub trait MerkleTree<E: Engine> {
    type Hash;

    fn path_bits_per_level(&self) -> usize;
    fn branching_factor(&self) -> usize;

    // hashes a bit representation of the leaf
    fn hash_leaf<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        leaf: &[Boolean],
    ) -> Result<Self::Hash, SynthesisError>;

    // hashes a node with
    fn hash_node<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        children: &[Self::Hash],
        level: usize,
    ) -> Result<Self::Hash, SynthesisError>;

    // checks inclusion of the leaf into the root
    fn check_inclusion<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        leaf: &[Boolean],
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError>;

    // checks inclusion of the leaf into the root
    fn check_inclusion_for_root<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        root: &Self::Hash,
        leaf: &[Boolean],
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError>;

    // checks inclusion of the leaf hash into the root
    fn check_hash_inclusion<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        hash: &Self::Hash,
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError>;

    // checks inclusion of the leaf hash into the root
    fn check_hash_inclusion_for_root<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        root: &Self::Hash,
        hash: &Self::Hash,
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError>;

    fn update<CS: ConstraintSystem<E>>(
        &mut self,
        cs: CS,
        leaf: &[Boolean],
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Self::Hash, SynthesisError>;
    fn update_from_hash<CS: ConstraintSystem<E>>(
        &mut self,
        cs: CS,
        hash: &Self::Hash,
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Self::Hash, SynthesisError>;

    fn update_intersect<CS: ConstraintSystem<E>>(
        &mut self,
        cs: CS,
        leafs: (&[Boolean], &[Boolean]),
        paths: (&[Boolean], &[Boolean]),
        witnesses: (&[Self::Hash], &[Self::Hash]),
    ) -> Result<Self::Hash, SynthesisError>;
    fn update_from_hash_intersect<CS: ConstraintSystem<E>>(
        &mut self,
        cs: CS,
        leafs: (&Self::Hash, &Self::Hash),
        paths: (&[Boolean], &[Boolean]),
        witnesses: (&[Self::Hash], &[Self::Hash]),
    ) -> Result<Self::Hash, SynthesisError>;
}

pub struct PedersenHashTree<'a, E: JubjubEngine> {
    root: AllocatedNum<E>,
    height: usize,
    params: &'a E::Params,
}

impl<'a, E: JubjubEngine> PedersenHashTree<'a, E> {
    fn new(root: AllocatedNum<E>, height: usize, params: &'a E::Params) -> Self {
        Self {
            root: root.clone(),
            height,
            params,
        }
    }
}

impl<'a, E: JubjubEngine> MerkleTree<E> for PedersenHashTree<'a, E> {
    type Hash = AllocatedNum<E>;

    fn path_bits_per_level(&self) -> usize {
        1
    }
    fn branching_factor(&self) -> usize {
        2
    }

    fn hash_leaf<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        leaf: &[Boolean],
    ) -> Result<Self::Hash, SynthesisError> {
        let leaf_hash = pedersen_hash::pedersen_hash(
            cs.namespace(|| "hash leaf content"),
            pedersen_hash::Personalization::NoteCommitment,
            &leaf,
            self.params,
        )?
        .get_x()
        .clone();

        Ok(leaf_hash)
    }

    fn hash_node<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        children: &[Self::Hash],
        level: usize,
    ) -> Result<Self::Hash, SynthesisError> {
        if children.len() != self.branching_factor() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let cs = &mut cs.namespace(|| format!("merkle tree hash {}", level));

        let mut preimage = vec![];
        preimage.extend(children[0].into_bits_le(cs.namespace(|| "left childred into bits"))?);
        preimage.extend(children[1].into_bits_le(cs.namespace(|| "right chinlder into bits"))?);

        let node_hash = pedersen_hash::pedersen_hash(
            cs.namespace(|| "computation of pedersen hash"),
            pedersen_hash::Personalization::MerkleTree(level),
            &preimage,
            self.params,
        )?
        .get_x()
        .clone();

        Ok(node_hash)
    }

    // checks inclusion of the leaf into the root
    fn check_inclusion<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        leaf: &[Boolean],
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError> {
        let leaf_hash = self.hash_leaf(cs.namespace(|| "leaf hash calculation"), leaf)?;

        self.check_hash_inclusion(cs, &leaf_hash, path, witness)
    }

    // checks inclusion of the leaf into the root
    fn check_inclusion_for_root<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        root: &Self::Hash,
        leaf: &[Boolean],
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError> {
        let leaf_hash = self.hash_leaf(cs.namespace(|| "leaf hash calculation"), leaf)?;

        self.check_hash_inclusion_for_root(cs, root, &leaf_hash, path, witness)
    }

    // checks inclusion of the leaf hash into the root
    fn check_hash_inclusion<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        hash: &Self::Hash,
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError> {
        self.check_hash_inclusion_for_root(cs, &self.root, hash, path, witness)
    }

    // checks inclusion of the leaf hash into the root
    fn check_hash_inclusion_for_root<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        root: &Self::Hash,
        hash: &Self::Hash,
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError> {
        if self.height != witness.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = hash.clone();

        // Ascend the merkle tree authentication path
        for (i, direction_bit) in path.clone().into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            // "direction_bit" determines if the current subtree
            // is the "right" leaf at this depth of the tree.

            // Witness the authentication path element adjacent
            // at this depth.
            let path_element = &witness[i];

            // Swap the two if the current subtree is on the right
            let (xl, xr) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                path_element,
                &direction_bit,
            )?;

            cur = self.hash_node(cs.namespace(|| "node hash computation"), &[xl, xr], i)?;
        }

        let included = AllocatedNum::equals(cs.namespace(|| "compare roots"), &cur, &root)?;

        Ok(included)
    }

    fn update<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        leaf: &[Boolean],
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Self::Hash, SynthesisError> {
        let leaf_hash = self.hash_leaf(cs.namespace(|| "leaf hash calculation"), leaf)?;

        self.update_from_hash(cs, &leaf_hash, path, witness)
    }

    fn update_from_hash<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        hash: &Self::Hash,
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Self::Hash, SynthesisError> {
        if self.height != witness.len() {
            return Err(SynthesisError::Unsatisfiable);
        }

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = hash.clone();

        // Ascend the merkle tree authentication path
        for (i, direction_bit) in path.clone().into_iter().enumerate() {
            let cs = &mut cs.namespace(|| format!("merkle tree hash {}", i));

            // "direction_bit" determines if the current subtree
            // is the "right" leaf at this depth of the tree.

            // Witness the authentication path element adjacent
            // at this depth.
            let path_element = &witness[i];

            // Swap the two if the current subtree is on the right
            let (xl, xr) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of preimage"),
                &cur,
                path_element,
                &direction_bit,
            )?;

            cur = self.hash_node(
                cs.namespace(|| format!("node hash computation level {}", i)),
                &[xl, xr],
                i,
            )?;
        }

        self.root = cur.clone();

        Ok(cur)
    }

    fn update_intersect<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        leafs: (&[Boolean], &[Boolean]),
        paths: (&[Boolean], &[Boolean]),
        witnesses: (&[Self::Hash], &[Self::Hash]),
    ) -> Result<Self::Hash, SynthesisError> {
        let (leaf_0, leaf_1) = leafs;

        let leaf_hash_0 = self.hash_leaf(cs.namespace(|| "leaf 0 hash calculation"), leaf_0)?;

        let leaf_hash_1 = self.hash_leaf(cs.namespace(|| "leaf 1 hash calculation"), leaf_1)?;

        self.update_from_hash_intersect(cs, (&leaf_hash_0, &leaf_hash_1), paths, witnesses)
    }

    fn update_from_hash_intersect<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        leafs: (&Self::Hash, &Self::Hash),
        paths: (&[Boolean], &[Boolean]),
        witnesses: (&[Self::Hash], &[Self::Hash]),
    ) -> Result<Self::Hash, SynthesisError> {
        // First assemble new leafs

        let (leaf_hash_0, leaf_hash_1) = leafs;
        let mut cur_0 = leaf_hash_0.clone();
        let mut cur_1 = leaf_hash_1.clone();

        let (path_bits_0, path_bits_1) = paths;

        let (audit_path_0, audit_path_1) = witnesses;

        let intersection_point_bits = find_intersection_point(
            cs.namespace(|| "find intersection point for merkle paths"),
            path_bits_0,
            path_bits_1,
            &audit_path_0,
            &audit_path_1,
        )?;

        {
            // Ascend the merkle tree authentication path
            for (i, ((direction_bit_0, direction_bit_1), intersection_bit)) in path_bits_0
                .clone()
                .into_iter()
                .zip(path_bits_1.clone().into_iter())
                .zip(intersection_point_bits.into_iter())
                .enumerate()
            {
                let cs = &mut cs.namespace(|| format!("assemble new root level {}", i));

                let original_path_element_0 = &audit_path_0[i];
                let original_path_element_1 = &audit_path_1[i];

                // Now the most fancy part is to determine when to use path element form witness,
                // or recalculated element from another subtree

                // If we are on intersection place take a current hash from another branch instead of path element
                let path_element_0 = AllocatedNum::conditionally_select(
                    cs.namespace(|| "conditional select of preimage from"),
                    &cur_1,
                    original_path_element_0,
                    &intersection_bit,
                )?;

                // Swap the two if the current subtree is on the right
                let (xl_0, xr_0) = AllocatedNum::conditionally_reverse(
                    cs.namespace(|| "conditional reversal of preimage from"),
                    &cur_0,
                    &path_element_0,
                    &direction_bit_0,
                )?;

                // If we are on intersection place take a current hash from another branch instead of path element
                let path_element_1 = AllocatedNum::conditionally_select(
                    cs.namespace(|| "conditional select of preimage to"),
                    &cur_0,
                    original_path_element_1,
                    &intersection_bit,
                )?;

                // Swap the two if the current subtree is on the right
                let (xl_1, xr_1) = AllocatedNum::conditionally_reverse(
                    cs.namespace(|| "conditional reversal of preimage to"),
                    &cur_1,
                    &path_element_1,
                    &direction_bit_1,
                )?;

                // Compute the new subtree value
                cur_0 = self.hash_node(
                    cs.namespace(|| format!("node 0 hash computation level {}", i)),
                    &[xl_0, xr_0],
                    i,
                )?;

                // Compute the new subtree value
                cur_1 = self.hash_node(
                    cs.namespace(|| format!("node 1 hash computation level {}", i)),
                    &[xl_1, xr_1],
                    i,
                )?;
            }

            // enforce roots are the same
            cs.enforce(
                || "enforce correct new root recalculation",
                |lc| lc + cur_1.get_variable(),
                |lc| lc + CS::one(),
                |lc| lc + cur_0.get_variable(),
            );
        }

        self.root = cur_1;

        Ok(cur_0)
    }
}

// returns a bit vector with ones up to the first point of divergence
fn find_common_prefix<E, CS>(
    mut cs: CS,
    a: &[Boolean],
    b: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    assert_eq!(a.len(), b.len());

    // initiall divergence did NOT happen yet

    let mut no_divergence_bool = Boolean::Constant(true);

    let mut mask_bools = vec![];

    for (i, (a_bit, b_bit)) in a.iter().zip(b.iter()).enumerate() {
        // on common prefix mean a == b AND divergence_bit

        // a == b -> NOT (a XOR b)

        let a_xor_b = Boolean::xor(
            cs.namespace(|| format!("Common prefix a XOR b {}", i)),
            &a_bit,
            &b_bit,
        )?;

        let mask_bool = Boolean::and(
            cs.namespace(|| format!("Common prefix mask bit {}", i)),
            &a_xor_b.not(),
            &no_divergence_bool,
        )?;

        // is no_divergence_bool == true: mask_bool = a == b
        // else: mask_bool == false
        // -->
        // if mask_bool == false: divergence = divergence AND mask_bool

        no_divergence_bool = Boolean::and(
            cs.namespace(|| format!("recalculate divergence bit {}", i)),
            &no_divergence_bool,
            &mask_bool,
        )?;

        mask_bools.push(no_divergence_bool.clone());
    }

    Ok(mask_bools)
}

fn find_intersection_point<E, CS>(
    mut cs: CS,
    from_path_bits: &[Boolean],
    to_path_bits: &[Boolean],
    audit_path_from: &[AllocatedNum<E>],
    audit_path_to: &[AllocatedNum<E>],
) -> Result<Vec<Boolean>, SynthesisError>
where
    E: JubjubEngine,
    CS: ConstraintSystem<E>,
{
    if from_path_bits.len() != to_path_bits.len() {
        return Err(SynthesisError::Unsatisfiable);
    }
    // Intersection point is the only element required in outside scope
    let mut intersection_point_lc = Num::<E>::zero();

    let mut bitmap_path_from: Vec<Boolean> = from_path_bits.to_vec();
    bitmap_path_from.reverse();

    let mut bitmap_path_to: Vec<Boolean> = to_path_bits.to_vec();
    bitmap_path_to.reverse();

    let common_prefix = find_common_prefix(
        cs.namespace(|| "common prefix search"),
        &bitmap_path_from,
        &bitmap_path_to,
    )?;

    // common prefix is reversed because it's enumerated from the root, while
    // audit path is from the leafs

    let mut common_prefix_reversed = common_prefix.clone();
    common_prefix_reversed.reverse();

    // Common prefix is found, not we enforce equality of
    // audit path elements on a common prefix

    for (i, bitmask_bit) in common_prefix_reversed.into_iter().enumerate() {
        let path_element_from = &audit_path_from[i];
        let path_element_to = &audit_path_to[i];

        cs.enforce(
            || format!("enforce audit path equality for {}", i),
            |lc| lc + path_element_from.get_variable() - path_element_to.get_variable(),
            |_| bitmask_bit.lc(CS::one(), E::Fr::one()),
            |lc| lc,
        );
    }

    // Now we have to find a "point of intersection"
    // Good for us it's just common prefix interpreted as binary number + 1
    // and bit decomposed

    let mut coeff = E::Fr::one();
    for bit in common_prefix.into_iter() {
        intersection_point_lc = intersection_point_lc.add_bool_with_coeff(CS::one(), &bit, coeff);
        coeff.double();
    }

    // and add one
    intersection_point_lc = intersection_point_lc.add_bool_with_coeff(
        CS::one(),
        &Boolean::Constant(true),
        E::Fr::one(),
    );

    // Intersection point is a number with a single bit that indicates how far
    // from the root intersection is

    let intersection_point =
        AllocatedNum::alloc(cs.namespace(|| "intersection as number"), || {
            Ok(*intersection_point_lc.get_value().get()?)
        })?;

    cs.enforce(
        || "pack intersection",
        |lc| lc + intersection_point.get_variable(),
        |lc| lc + CS::one(),
        |_| intersection_point_lc.lc(E::Fr::one()),
    );

    // Intersection point into bits to use for root recalculation
    let mut intersection_point_bits =
        intersection_point.into_bits_le(cs.namespace(|| "unpack intersection"))?;

    // truncating guarantees that even if the common prefix coincides everywhere
    // up to the last bit, it can still be properly used in next actions
    intersection_point_bits.truncate(from_path_bits.len());
    // reverse cause bits here are counted from root, and later we need from the leaf
    intersection_point_bits.reverse();

    Ok(intersection_point_bits)
}

fn pack_binary_decomposition<E, CS>(
    mut cs: CS,
    bits: &[Boolean],
) -> Result<AllocatedNum<E>, SynthesisError>
where
    E: Engine,
    CS: ConstraintSystem<E>,
{
    assert!(bits.len() <= E::Fr::CAPACITY as usize);
    let mut num = Num::<E>::zero();
    let mut coeff = E::Fr::one();
    for bit in bits {
        num = num.add_bool_with_coeff(CS::one(), &bit, coeff);
        coeff.double();
    }

    let allocated = AllocatedNum::alloc(cs.namespace(|| "allocate packed value"), || {
        Ok(*num.get_value().get()?)
    })?;

    cs.enforce(
        || "pack binary decomposition",
        |lc| lc + allocated.get_variable(),
        |lc| lc + CS::one(),
        |_| num.lc(E::Fr::one()),
    );

    Ok(allocated)
}

pub struct PoseidonHashTree<'a, E: PoseidonEngine<SBox = QuinticSBox<E>>> {
    root: AllocatedNum<E>,
    height: usize,
    params: &'a E::Params,
    zero: AllocatedNum<E>,
    bits_per_level: usize,
    branching_factor: usize,
}

impl<'a, E: PoseidonEngine<SBox = QuinticSBox<E>>> PoseidonHashTree<'a, E> {
    pub fn new(
        root: AllocatedNum<E>,
        height: usize,
        bits_per_level: usize,
        params: &'a E::Params,
        zero: AllocatedNum<E>,
    ) -> Self {
        assert!(height % bits_per_level == 0);
        assert_eq!(bits_per_level, 2); // for now
        let branching = 1 << bits_per_level;
        assert_eq!(params.absorbtion_cycle_len(), branching as u32);
        assert_eq!(params.output_len(), 1);
        // we expect to have input array as [previous_level_hash, N*witness],
        // and shuffle it like:
        // - path == 0: [previous_level_hash, witness_0, witness_1, witness_2]
        // - path == 1: [witness_0, previous_level_hash, witness_1, witness_2]
        // - path == 2: [witness_0, witness_1, previous_level_hash, witness_2]
        // - path == 3: [witness_0, witness_1, witness_2, previous_level_hash]
        // by kind-of transposing we should have 4 bitmask:
        // if path == b00 we should generate sequences like [1, 0, 0, 0], [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1],
        // where each sequence masks corresponding path element, and final elements are assembled using addition
        // if path == b01 -> [0, 1, 0, 0], [1, 0, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1]
        // if path == b10 -> [0, 1, 0, 0], [0, 0, 1, 0], [1, 0, 0, 0], [0, 0, 0, 1]
        // if path == b11 -> [0, 1, 0, 0], [0, 0, 1, 0], [0, 0, 0, 1], [1, 0, 0, 0]
        // this can be done by 3 "swaps":
        // swap previous and 0 if either LSB == 1 or MSB == 1
        // swap resulting "1" and "2" if MSB == 1 AND first swap happened
        // swap resulting "2" and "3" if LSB == 1 and MSB == 1 AND first swap happened

        Self {
            root: root.clone(),
            height,
            params,
            zero,
            bits_per_level: bits_per_level,
            branching_factor: branching,
        }
    }

    pub fn calculate_swaps<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        path_bits_slice: &[Boolean],
    ) -> Result<Vec<Boolean>, SynthesisError> {
        assert_eq!(path_bits_slice.len(), self.path_bits_per_level());
        // TODO:
        assert_eq!(path_bits_slice.len(), 2);
        let lsb = &path_bits_slice[0];
        let msb = &path_bits_slice[1];

        // first swap is lsb or msb
        let first_swap = Boolean::and(cs.namespace(|| "frist swap"), &lsb.not(), &msb.not())?.not();

        // second swap is MSB AND 1st swap
        let second_swap = Boolean::and(cs.namespace(|| "second swap"), &first_swap, &msb)?;

        let msb_and_lsb = Boolean::and(cs.namespace(|| "MSB and LSB"), &lsb, &msb)?;

        let third_swap = Boolean::and(cs.namespace(|| "third swap"), &msb_and_lsb, &second_swap)?;

        Ok(vec![first_swap, second_swap, third_swap])
    }
}

impl<'a, E: PoseidonEngine<SBox = QuinticSBox<E>>> MerkleTree<E> for PoseidonHashTree<'a, E> {
    type Hash = AllocatedNum<E>;

    fn path_bits_per_level(&self) -> usize {
        self.bits_per_level
    }
    fn branching_factor(&self) -> usize {
        self.branching_factor
    }

    fn hash_leaf<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        leaf: &[Boolean],
    ) -> Result<Self::Hash, SynthesisError> {
        let leaf_elements = multipack::pack_into_variables(
            cs.namespace(|| "pack leaf bits into variables"),
            &leaf,
        )?;

        let leaf_hash = poseidon_hash::poseidon_hash(
            cs.namespace(|| "hash leaf content"),
            &leaf_elements[..],
            self.params,
        )?;

        let leaf_hash = leaf_hash[0].clone();

        Ok(leaf_hash)
    }

    fn hash_node<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        children: &[Self::Hash],
        level: usize,
    ) -> Result<Self::Hash, SynthesisError> {
        if children.len() != self.branching_factor() {
            return Err(SynthesisError::Unsatisfiable);
        }

        let cs = &mut cs.namespace(|| format!("merkle tree hash {}", level));

        let node_hash = poseidon_hash::poseidon_hash(
            cs.namespace(|| "computation of pedersen hash"),
            &children,
            self.params,
        )?;

        let node_hash = node_hash[0].clone();

        Ok(node_hash)
    }

    // checks inclusion of the leaf into the root
    fn check_inclusion<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        leaf: &[Boolean],
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError> {
        let leaf_hash = self.hash_leaf(cs.namespace(|| "leaf hash calculation"), leaf)?;

        self.check_hash_inclusion(cs, &leaf_hash, path, witness)
    }

    // checks inclusion of the leaf into the root
    fn check_inclusion_for_root<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        root: &Self::Hash,
        leaf: &[Boolean],
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError> {
        let leaf_hash = self.hash_leaf(cs.namespace(|| "leaf hash calculation"), leaf)?;

        self.check_hash_inclusion_for_root(cs, root, &leaf_hash, path, witness)
    }

    // checks inclusion of the leaf hash into the root
    fn check_hash_inclusion<CS: ConstraintSystem<E>>(
        &self,
        cs: CS,
        hash: &Self::Hash,
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError> {
        self.check_hash_inclusion_for_root(cs, &self.root, hash, path, witness)
    }

    // checks inclusion of the leaf hash into the root
    fn check_hash_inclusion_for_root<CS: ConstraintSystem<E>>(
        &self,
        mut cs: CS,
        root: &Self::Hash,
        hash: &Self::Hash,
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Boolean, SynthesisError> {
        // this tree is not-binary, so lookup procedure is more compicated
        let path_elements_chunks = self.branching_factor() - 1;
        // TODO: make generic later
        assert_eq!(path_elements_chunks, 3); // take by 3 elements from the witness
        assert!(witness.len() % path_elements_chunks == 0);
        assert!(witness.len() / path_elements_chunks == path.len() / self.path_bits_per_level());
        assert!(path.len() % self.path_bits_per_level() == 0);

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = hash.clone();

        for (chunk_number, (bits, path_elements)) in path
            .chunks_exact(self.path_bits_per_level())
            .zip(witness.chunks_exact(path_elements_chunks))
            .enumerate()
        {
            let cs = &mut cs.namespace(|| format!("merkle tree chunk {}", chunk_number));

            let mut path_to_shuffle = vec![cur];
            path_to_shuffle.extend_from_slice(&path_elements);

            assert_eq!(path_to_shuffle.len(), self.branching_factor());

            let swaps = self.calculate_swaps(cs.namespace(|| "calculate swaps"), bits)?;

            let (new_0, new_1) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of 0 and 1"),
                &path_to_shuffle[0],
                &path_to_shuffle[1],
                &swaps[0],
            )?;

            path_to_shuffle[0] = new_0;
            path_to_shuffle[1] = new_1;

            let (new_1, new_2) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of 1 and 2"),
                &path_to_shuffle[1],
                &path_to_shuffle[2],
                &swaps[1],
            )?;

            path_to_shuffle[1] = new_1;
            path_to_shuffle[2] = new_2;

            let (new_2, new_3) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of 2 and 3"),
                &path_to_shuffle[2],
                &path_to_shuffle[3],
                &swaps[2],
            )?;

            path_to_shuffle[2] = new_2;
            path_to_shuffle[3] = new_3;

            cur = self.hash_node(
                cs.namespace(|| "hash round"),
                &path_to_shuffle,
                chunk_number,
            )?;
        }

        let included = AllocatedNum::equals(cs.namespace(|| "compare roots"), &cur, &root)?;

        Ok(included)
    }

    fn update<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        leaf: &[Boolean],
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Self::Hash, SynthesisError> {
        let leaf_hash = self.hash_leaf(cs.namespace(|| "leaf hash calculation"), leaf)?;

        self.update_from_hash(cs, &leaf_hash, path, witness)
    }

    fn update_from_hash<CS: ConstraintSystem<E>>(
        &mut self,
        mut cs: CS,
        hash: &Self::Hash,
        path: &[Boolean],
        witness: &[Self::Hash],
    ) -> Result<Self::Hash, SynthesisError> {
        // this tree is not-binary, so lookup procedure is more compicated
        let path_elements_chunks = self.branching_factor() - 1;
        // TODO: make generic later
        assert_eq!(path_elements_chunks, 3);
        assert!(witness.len() % path_elements_chunks == 0);
        assert!(witness.len() / path_elements_chunks == path.len() / self.path_bits_per_level());
        assert!(path.len() % self.path_bits_per_level() == 0);

        // This is an injective encoding, as cur is a
        // point in the prime order subgroup.
        let mut cur = hash.clone();

        for (chunk_number, (bits, path_elements)) in path
            .chunks_exact(self.path_bits_per_level())
            .zip(witness.chunks_exact(path_elements_chunks))
            .enumerate()
        {
            let cs = &mut cs.namespace(|| format!("merkle tree chunk {}", chunk_number));

            let mut path_to_shuffle = vec![cur];
            path_to_shuffle.extend_from_slice(&path_elements);

            assert_eq!(path_to_shuffle.len(), self.branching_factor());

            let swaps = self.calculate_swaps(cs.namespace(|| "calculate swaps"), bits)?;

            let (new_0, new_1) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of 0 and 1"),
                &path_to_shuffle[0],
                &path_to_shuffle[1],
                &swaps[0],
            )?;

            path_to_shuffle[0] = new_0;
            path_to_shuffle[1] = new_1;

            let (new_1, new_2) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of 1 and 2"),
                &path_to_shuffle[1],
                &path_to_shuffle[2],
                &swaps[1],
            )?;

            path_to_shuffle[1] = new_1;
            path_to_shuffle[2] = new_2;

            let (new_2, new_3) = AllocatedNum::conditionally_reverse(
                cs.namespace(|| "conditional reversal of 2 and 3"),
                &path_to_shuffle[2],
                &path_to_shuffle[3],
                &swaps[2],
            )?;

            path_to_shuffle[2] = new_2;
            path_to_shuffle[3] = new_3;

            cur = self.hash_node(
                cs.namespace(|| "hash round"),
                &path_to_shuffle,
                chunk_number,
            )?;
        }

        self.root = cur.clone();

        Ok(cur)
    }

    fn update_intersect<CS: ConstraintSystem<E>>(
        &mut self,
        cs: CS,
        leafs: (&[Boolean], &[Boolean]),
        paths: (&[Boolean], &[Boolean]),
        witnesses: (&[Self::Hash], &[Self::Hash]),
    ) -> Result<Self::Hash, SynthesisError> {
        unimplemented!();
    }

    fn update_from_hash_intersect<CS: ConstraintSystem<E>>(
        &mut self,
        cs: CS,
        leafs: (&Self::Hash, &Self::Hash),
        paths: (&[Boolean], &[Boolean]),
        witnesses: (&[Self::Hash], &[Self::Hash]),
    ) -> Result<Self::Hash, SynthesisError> {
        unimplemented!();
    }
}

#[test]
fn test_poseidon_quartic_tree() {
    use crate::circuit::merkle::{MerkleTree, PoseidonHashTree};
    use crate::circuit::num::AllocatedNum;
    use crate::circuit::poseidon_hash;
    use crate::circuit::test::*;
    use crate::group_hash::BlakeHasher;
    use crate::poseidon::bn256::Bn256PoseidonParams;
    use crate::poseidon::{self, PoseidonEngine, PoseidonHashParams};
    use ff::PrimeField;
    use pairing::bn256::{Bn256, Fr};

    let leaf_hashes = (0..16)
        .map(|el| Fr::from_str(&el.to_string()).unwrap())
        .collect::<Vec<_>>();
    let params = Bn256PoseidonParams::new_for_quartic_tree::<BlakeHasher>();

    let mut node_hashes_1: Vec<Fr> = vec![];
    for chunk in leaf_hashes.chunks(4) {
        let hash = poseidon::poseidon_hash::<Bn256>(&params, &chunk[..]);
        node_hashes_1.push(hash[0]);
    }

    // println!("Node hashes = {:?}", node_hashes_1);

    let root_hash = poseidon::poseidon_hash::<Bn256>(&params, &node_hashes_1[..])[0];

    let element_to_proof = 15;
    let mut cs = TestConstraintSystem::<Bn256>::new();

    let input = AllocatedNum::alloc(
        cs.namespace(|| format!("input {}", element_to_proof)),
        || Ok(leaf_hashes[element_to_proof]),
    )
    .unwrap();

    let root = AllocatedNum::alloc(cs.namespace(|| "expected root"), || Ok(root_hash)).unwrap();

    let path_as_fr = AllocatedNum::alloc(cs.namespace(|| "path"), || {
        Ok(Fr::from_str(&element_to_proof.to_string()).unwrap())
    })
    .unwrap();

    let mut path_bits = path_as_fr
        .into_bits_le(cs.namespace(|| "decompose path"))
        .unwrap();
    path_bits.truncate(4);

    let witness: Vec<AllocatedNum<Bn256>> = vec![
        leaf_hashes[12].clone(),
        leaf_hashes[13].clone(),
        leaf_hashes[14].clone(),
        node_hashes_1[0].clone(),
        node_hashes_1[1].clone(),
        node_hashes_1[2].clone(),
    ]
    .into_iter()
    .enumerate()
    .map(|(i, el)| {
        AllocatedNum::alloc(cs.namespace(|| format!("witness {}", i)), || Ok(el)).unwrap()
    })
    .collect();

    let zero = AllocatedNum::alloc(cs.namespace(|| "root"), || Ok(Fr::zero())).unwrap();

    let tree = PoseidonHashTree::new(root.clone(), 2, 2, &params, zero);

    let is_included = tree
        .check_hash_inclusion(
            cs.namespace(|| "check inclusion"),
            &input,
            &path_bits[..],
            &witness[..],
        )
        .unwrap();

    assert!(is_included.get_value().unwrap());

    println!(
        "Tree for 16 elements and 2 levels requires {} constraints",
        cs.num_constraints()
    );

    // let inputs: Vec<AllocatedNum<Bn256>> = leaf_hashes.iter().enumerate().map(|(i, b)| {
    //         AllocatedNum::alloc(cs.namespace(|| format!("input {}", i)), Some(*b)).unwrap()
    // }).collect();
}
