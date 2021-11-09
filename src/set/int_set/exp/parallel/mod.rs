use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use rug::{Assign, Integer};
use serde::{Deserialize, Serialize};

use std::cmp::min;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::ops::{Index, MulAssign, RemAssign};
use std::path::PathBuf;

use super::Exponentiator;
use crate::group::RsaQuotientGroup;

pub mod parallel_product;

const RSA_2048: &str = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
/// A comb of precomputed powers of a base, plus optional precomputed tables of combinations
pub struct ParExpComb {
    bs: Vec<Integer>,
    m: Integer,
    lgsp: usize,
    ts: Vec<Vec<Integer>>,
    npt: usize,
}

/// pcb[idx] is the idx'th precomputed table
impl Index<usize> for ParExpComb {
    type Output = Vec<Integer>;

    fn index(&self, idx: usize) -> &Self::Output {
        &self.ts[idx]
    }
}

impl Exponentiator<RsaQuotientGroup> for ParExpComb {
    /// get default precomps
    fn from_group(g: RsaQuotientGroup) -> Self {
        // XXX(HACK): Assert that the group matched our precomputation.
        assert!(g.m == Integer::from_str_radix(RSA_2048, 10).unwrap());
        assert!(g.g == Integer::from(2));
        // XXX(HACK): we read from $CARGO_MANIFEST_DIR/lib/pcb_dflt
        let dir = std::env::var("CARGO_MANIFEST_DIR")
            .expect("Missing CARGO_MANIFEST_DIR env variable (needed for ParExpComb)\nPlease run using cargo.");
        let mut pbuf = PathBuf::from(dir);
        pbuf.push("lib");
        pbuf.push("pcb_dflt");
        let mut this = Self::deserialize(pbuf.to_str().unwrap());
        this.make_tables(Self::N_PER_TABLE);
        this
    }

    fn exponentiate(&mut self, mut powers: Vec<Integer>) -> Integer {
        parallel_product::parallel_product(&mut powers);
        let exponent = powers.pop().unwrap();
        let x = self.exp(&exponent);
        let y = Integer::from(&self.m - &x);
        min(x, y)
    }
}

#[allow(clippy::len_without_is_empty)]
impl ParExpComb {
    const N_PER_TABLE: usize = 8;

    // ** initialization and precomputation ** //
    /// read in a file with bases
    pub fn from_file(filename: &str, log_spacing: usize) -> Self {
        let mut ifile = BufReader::new(File::open(filename).unwrap());
        let modulus = {
            let mut mbuf = String::new();
            ifile.read_line(&mut mbuf).unwrap();
            Integer::from_str_radix(&mbuf, 16).unwrap()
        };
        let ret = Self {
            bs: ifile
                .lines()
                .map(|x| Integer::from_str_radix(x.unwrap().as_ref(), 16).unwrap())
                .collect(),
            m: modulus,
            lgsp: log_spacing,
            ts: Vec::new(),
            npt: 0,
        };
        ret._check();
        ret
    }

    /// build tables from bases
    pub fn make_tables(&mut self, n_per_table: usize) {
        // parallel table building with Rayon
        use rayon::prelude::*;

        // n_per_table must be a power of 2 or things get messy
        assert!(n_per_table.is_power_of_two());

        // reset tables and n_per_table
        self.ts.clear();
        self.npt = n_per_table;
        if n_per_table == 0 {
            return;
        }

        // for each n bases, compute powerset of values
        self.ts.reserve(self.bs.len() / n_per_table + 1);
        self.ts.par_extend(self.bs.par_chunks(n_per_table).map({
            // closure would capture borrow of self, which breaks because self is borrowed already.
            // instead, borrow the piece of self we need outside, then move the borrow inside
            // http://smallcultfollowing.com/babysteps/blog/2018/04/24/rust-pattern-precise-closure-capture-clauses/
            let modulus = &self.m;
            move |x| _make_table(x, modulus)
        }));
    }

    // ** exponentiation ** //
    /// Parallel exponentiation using windows and combs
    pub fn exp(&self, expt: &Integer) -> Integer {
        use rayon::prelude::*;

        // expt must be positive
        let expt_sign = expt.cmp0();
        assert_ne!(expt_sign, std::cmp::Ordering::Less);
        if expt_sign == std::cmp::Ordering::Equal {
            return Integer::from(1);
        }

        // figure out how many of the tables we'll need to use
        let bits_per_expt = 1 << self.log_spacing();
        let expts_per_table = self.n_per_table();
        let bits_per_table = bits_per_expt * expts_per_table;
        let n_sig_bits = expt.significant_bits() as usize;
        let n_tables = (n_sig_bits + bits_per_table - 1) / bits_per_table;

        // make sure this precomp is big enough!
        assert!(n_sig_bits < (1 << (self.log_spacing() + self.log_num_bases())));
        assert!(n_tables <= self.len());

        // figure out chunk size
        let n_threads = rayon::current_num_threads();
        let tables_per_chunk = (n_tables + n_threads - 1) / n_threads;

        // parallel multiexponentiation
        let modulus = &self.m;
        self.ts[0..n_tables]
            .par_chunks(tables_per_chunk)
            .enumerate()
            .map(|(chunk_idx, ts)| {
                let mut acc = Integer::from(1);
                let chunk_offset = chunk_idx * tables_per_chunk * bits_per_table;
                for bdx in (0..bits_per_expt).rev() {
                    for (tdx, tsent) in ts.iter().enumerate() {
                        let mut val = 0u32;
                        for edx in 0..expts_per_table {
                            let bitnum =
                                chunk_offset + tdx * bits_per_table + edx * bits_per_expt + bdx;
                            let bit = expt.get_bit(bitnum as u32) as u32;
                            val |= bit << edx;
                        }
                        acc.mul_assign(&tsent[val as usize]);
                        acc.rem_assign(modulus);
                    }
                    if bdx != 0 {
                        acc.square_mut();
                        acc.rem_assign(modulus);
                    }
                }
                acc
            })
            .reduce(
                || Integer::from(1),
                |mut acc, next| {
                    acc.mul_assign(&next);
                    acc.rem_assign(modulus);
                    acc
                },
            )
    }

    // ** serialization ** //
    /// write struct to a file
    pub fn serialize(&self, filename: &str) {
        let output = GzEncoder::new(File::create(filename).unwrap(), Compression::default());
        bincode::serialize_into(output, self).unwrap();
    }

    /// read struct from file
    pub fn deserialize(filename: &str) -> Self {
        let input = GzDecoder::new(File::open(filename).unwrap());
        let ret: Self = bincode::deserialize_from(input).unwrap();
        ret._check();
        ret
    }

    // ** accessors and misc ** //
    /// return number of tables
    pub fn len(&self) -> usize {
        self.ts.len()
    }

    /// return number of bases per precomputed table (i.e., log2(table.len()))
    pub fn n_per_table(&self) -> usize {
        self.npt
    }

    /// log of the number of bases in this struct
    pub fn log_num_bases(&self) -> usize {
        // this works because we enforce self.bs.len() is power of two
        self.bs.len().trailing_zeros() as usize
    }

    /// spacing between successive exponents
    pub fn log_spacing(&self) -> usize {
        self.lgsp
    }

    /// return iterator over tables
    pub fn iter(&self) -> std::slice::Iter<Vec<Integer>> {
        self.ts.iter()
    }

    /// ref to bases
    pub fn bases(&self) -> &[Integer] {
        &self.bs[..]
    }

    /// ref to modulus
    pub fn modulus(&self) -> &Integer {
        &self.m
    }

    // ** internal ** //
    // internal consistency checks --- fn should be called on any newly created object
    fn _check(&self) {
        assert!(self.bs.len().is_power_of_two());
    }
}

// make a table from a set of bases
fn _make_table(bases: &[Integer], modulus: &Integer) -> Vec<Integer> {
    let mut ret = vec![Integer::new(); 1 << bases.len()];
    // base case: 0 and 1
    ret[0].assign(1);
    ret[1].assign(&bases[0]);

    // compute powerset of bases
    // for each element in bases
    for (bnum, base) in bases.iter().enumerate().skip(1) {
        let base_idx = 1 << bnum;
        // multiply bases[bnum] by the first base_idx elms of ret
        let (src, dst) = ret.split_at_mut(base_idx);
        for idx in 0..base_idx {
            dst[idx].assign(&src[idx] * base);
            dst[idx].rem_assign(modulus);
        }
    }

    ret
}

mod tests {
    use super::*;
    use rug::rand::RandState;

    #[test]
    fn precomp_table() {
        const NELMS: usize = 8;
        let group = RsaQuotientGroup::from_strs("2", RSA_2048);

        let mut pc = ParExpComb::from_group(group);
        pc.make_tables(NELMS);
        assert!(pc.len() > 0);

        let num_tables = (pc.bases().len() + NELMS - 1) / NELMS;
        assert!(pc.len() == num_tables);
        assert!(pc[0].len() == (1 << NELMS));

        // check the first precomputed table for correctness
        let bases = pc.bases();
        let modulus = pc.modulus();
        for idx in 0..(1 << NELMS) {
            let mut accum = Integer::from(1);
            for jdx in 0..NELMS {
                if idx & (1 << jdx) != 0 {
                    accum.mul_assign(&bases[jdx]);
                    accum.rem_assign(modulus);
                }
            }
            assert_eq!(&accum, &pc[0][idx]);
        }
    }

    #[test]
    fn precomp_serdes() {
        let pc = {
            let group = RsaQuotientGroup::from_strs("2", RSA_2048);

            let mut tmp = ParExpComb::from_group(group);
            tmp.make_tables(4);
            tmp
        };
        pc.serialize("/tmp/serialized.gz");
        let pc2 = ParExpComb::deserialize("/tmp/serialized.gz");
        assert_eq!(pc, pc2);
    }

    #[test]
    fn precomp_exp_test() {
        const LOG_EXPSIZE: usize = 22;

        let pc = {
            let group = RsaQuotientGroup::from_strs("2", RSA_2048);

            let mut tmp = ParExpComb::from_group(group);
            tmp.make_tables(2);
            tmp
        };

        let mut rnd = RandState::new();
        _seed_rng(&mut rnd);

        let expt = Integer::from(Integer::random_bits(1 << LOG_EXPSIZE, &mut rnd));
        let expect = Integer::from(pc.bases()[0].pow_mod_ref(&expt, pc.modulus()).unwrap());
        let result = pc.exp(&expt);

        assert_eq!(expect, result);
    }

    fn _seed_rng(rnd: &mut RandState) {
        use rug::integer::Order;
        rnd.seed(&Integer::from_digits(
            &rand::random::<[u64; 4]>()[..],
            Order::Lsf,
        ));
    }
}
