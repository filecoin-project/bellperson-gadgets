use super::*;
use pairing::bn256;

impl PoseidonEngine for bn256::Bn256 {
    type Params = Bn256PoseidonParams;
    type SBox = QuinticSBox<bn256::Bn256>;
}

pub struct Bn256PoseidonParams {
    t: u32,
    r_f: u32,
    r_p: u32,
    full_round_keys: Vec<bn256::Fr>,
    partial_round_keys: Vec<bn256::Fr>,
    mds_matrix: Vec<bn256::Fr>,
    security_level: u32,
}

impl Bn256PoseidonParams {
    pub fn new<H: GroupHasher>() -> Self {
        let t = 6u32;
        let r_f = 8u32;
        let r_p = 57u32;
        let security_level = 126u32;

        Self::new_for_params::<H>(t, r_f, r_p, security_level)
    }

    pub fn new_for_quartic_tree<H: GroupHasher>() -> Self {
        // TODO: Number of round can be reduced
        let t = 5u32;
        let r_f = 8u32;
        let r_p = 84u32;
        let security_level = 126u32;

        Self::new_for_params::<H>(t, r_f, r_p, security_level)
    }

    pub fn new_for_params<H: GroupHasher>(t: u32, r_f: u32, r_p: u32, security_level: u32) -> Self {
        use crate::constants;
        use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

        // generate round constants based on some seed and hashing
        let full_round_constants = {
            let tag = b"Hadesr_f";
            let mut round_constants = vec![];
            let mut nonce = 0u32;
            let mut nonce_bytes = [0u8; 4];

            loop {
                (&mut nonce_bytes[0..4])
                    .write_u32::<BigEndian>(nonce)
                    .unwrap();
                let mut h = H::new(&tag[..]);
                h.update(constants::GH_FIRST_BLOCK);
                h.update(&nonce_bytes[..]);
                let h = h.finalize();
                assert!(h.len() == 32);

                let mut constant_repr = <bn256::Fr as PrimeField>::Repr::default();
                constant_repr.read_le(&h[..]).unwrap();

                if let Ok(constant) = bn256::Fr::from_repr(constant_repr) {
                    if !constant.is_zero() {
                        round_constants.push(constant);
                    }
                }

                if round_constants.len() == ((r_f * 2 * t) as usize) {
                    break;
                }

                nonce += 1;
            }

            round_constants
        };

        // generate round constants based on some seed and hashing
        let partial_round_constants = {
            let tag = b"Hadesr_p";
            let mut round_constants = vec![];
            let mut nonce = 0u32;
            let mut nonce_bytes = [0u8; 4];

            loop {
                (&mut nonce_bytes[0..4])
                    .write_u32::<BigEndian>(nonce)
                    .unwrap();
                let mut h = H::new(&tag[..]);
                h.update(constants::GH_FIRST_BLOCK);
                h.update(&nonce_bytes[..]);
                let h = h.finalize();
                assert!(h.len() == 32);

                let mut constant_repr = <bn256::Fr as PrimeField>::Repr::default();
                constant_repr.read_le(&h[..]).unwrap();

                if let Ok(constant) = bn256::Fr::from_repr(constant_repr) {
                    if !constant.is_zero() {
                        round_constants.push(constant);
                    }
                }

                if round_constants.len() == ((r_p * t) as usize) {
                    break;
                }

                nonce += 1;
            }

            round_constants
        };

        let mds_matrix = {
            use rand::chacha::ChaChaRng;
            use rand::SeedableRng;
            // Create an RNG based on the outcome of the random beacon
            let mut rng = {
                let tag = b"Hadesmds";
                let mut h = H::new(&tag[..]);
                h.update(constants::GH_FIRST_BLOCK);
                let h = h.finalize();
                assert!(h.len() == 32);
                let mut seed = [0u32; 8];
                for i in 0..8 {
                    seed[i] = (&h[..])
                        .read_u32::<BigEndian>()
                        .expect("digest is large enough for this to work");
                }

                ChaChaRng::from_seed(&seed)
            };

            generate_mds_matrix::<bn256::Bn256, _>(t, &mut rng)
        };

        Self {
            t: t,
            r_f: r_f,
            r_p: r_p,
            full_round_keys: full_round_constants,
            partial_round_keys: partial_round_constants,
            mds_matrix: mds_matrix,
            security_level: 126,
        }
    }
}

impl PoseidonHashParams<bn256::Bn256> for Bn256PoseidonParams {
    fn t(&self) -> u32 {
        self.t
    }
    fn r_f(&self) -> u32 {
        self.r_f
    }
    fn r_p(&self) -> u32 {
        self.r_p
    }
    fn full_round_key(&self, round: u32) -> &[bn256::Fr] {
        let t = self.t;
        let start = (t * round) as usize;
        let end = (t * (round + 1)) as usize;

        &self.full_round_keys[start..end]
    }
    fn partial_round_key(&self, round: u32) -> &[bn256::Fr] {
        let t = self.t;
        let start = (t * round) as usize;
        let end = (t * (round + 1)) as usize;

        &self.partial_round_keys[start..end]
    }
    fn mds_matrix_row(&self, row: u32) -> &[bn256::Fr] {
        let t = self.t;
        let start = (t * row) as usize;
        let end = (t * (row + 1)) as usize;

        &self.mds_matrix[start..end]
    }
    fn security_level(&self) -> u32 {
        self.security_level
    }
}

#[cfg(test)]
mod test {
    use super::Bn256PoseidonParams;
    use crate::group_hash::BlakeHasher;
    use crate::poseidon::{poseidon_hash, PoseidonEngine, PoseidonHashParams};
    use ff::Field;
    use ff::PrimeField;
    use pairing::bn256::{Bn256, Fr};
    use rand::{thread_rng, Rand, Rng};

    #[test]
    fn test_generate_bn256_poseidon_params() {
        let params = Bn256PoseidonParams::new::<BlakeHasher>();
    }

    #[test]
    fn test_bn256_poseidon_hash() {
        let rng = &mut thread_rng();
        let params = Bn256PoseidonParams::new::<BlakeHasher>();
        let input: Vec<Fr> = (0..params.t()).map(|_| rng.gen()).collect();
        let output = poseidon_hash::<Bn256>(&params, &input[..]);
        assert!(output.len() == 1);
    }

    #[test]
    fn test_print_bn256_poseidon_params_for_quartic_tree() {
        let params = Bn256PoseidonParams::new_for_quartic_tree::<BlakeHasher>();
        println!("MSD");
        for el in params.mds_matrix.iter() {
            println!("{}", el);
        }
        println!("Partial rounds constants");
        for el in params.partial_round_keys.iter() {
            println!("{}", el);
        }
        println!("Full rounds constants");
        for el in params.full_round_keys.iter() {
            println!("{}", el);
        }
    }

    #[test]
    fn test_print_bn256_poseidon_params_for_quartic_tree_hash_empty_input() {
        let params = Bn256PoseidonParams::new_for_quartic_tree::<BlakeHasher>();
        let input = vec![Fr::zero(); 4];
        let output = poseidon_hash::<Bn256>(&params, &input);
        println!("{}", output[0]);
    }
}
