use rug::Integer;
use sapling_crypto::bellman::pairing::Engine;
use sapling_crypto::bellman::{ConstraintSystem, SynthesisError};

use std::fmt::Debug;

use crate::group::{CircuitSemiGroup, SemiGroup};
use crate::mp::bignat::BigNat;
use crate::util::gadget::Gadget;

/// A structure for a natural number which may have already been reduced modulo a challenge. Useful
/// for lazy reduction.
#[derive(Clone, Debug)]
pub struct Reduced<E: Engine> {
    pub raw: BigNat<E>,
    pub reduced: BigNat<E>,
}

impl<E: Engine> Reduced<E> {
    pub fn new(raw: BigNat<E>, reduced: BigNat<E>) -> Self {
        Self { raw, reduced }
    }

    pub fn from_raw(raw: BigNat<E>) -> Self {
        Self {
            reduced: raw.clone(),
            raw,
        }
    }
}

/// Computes `b ^ (prod(xs) / l) % m`, using gmp.
pub fn base_to_product<'a, G: SemiGroup, I: Iterator<Item = &'a Integer>>(
    g: &G,
    b: &G::Elem,
    l: &Integer,
    xs: I,
) -> G::Elem {
    let mut acc = Integer::from(1);
    for x in xs {
        acc *= x;
    }
    acc /= l;
    g.power(b, &acc)
}

/// \exists q s.t. q^l \times base^r = result
pub fn proof_of_exp<'a, E: Engine, G: CircuitSemiGroup<E = E>, CS: ConstraintSystem<E>>(
    mut cs: CS,
    group: &G,
    base: &G::Elem,
    power_factors: impl IntoIterator<Item = &'a Reduced<E>> + Clone,
    challenge: &BigNat<E>,
    result: &G::Elem,
) -> Result<(), SynthesisError>
where
    G::Elem: Gadget<Value = <G::Group as SemiGroup>::Elem> + Debug,
{
    let pf: Vec<&'a Reduced<E>> = power_factors.into_iter().collect();
    let q_value: Option<<G::Group as SemiGroup>::Elem> = {
        group.group().and_then(|g| {
            base.value().and_then(|b| {
                challenge.value().and_then(|c| {
                    pf.iter()
                        .map(|pow| pow.raw.value())
                        .collect::<Option<Vec<&Integer>>>()
                        .map(|facs| base_to_product(g, b, c, facs.into_iter()))
                })
            })
        })
    };
    let r = {
        let mut acc = BigNat::one::<CS>(challenge.params.limb_width);
        for (i, f) in pf.into_iter().enumerate() {
            acc = acc
                .mult_mod(
                    cs.namespace(|| format!("fold {}", i)),
                    &f.reduced,
                    challenge,
                )?
                .1;
        }
        acc
    };
    let q = <G::Elem as Gadget>::alloc(
        cs.namespace(|| "Q"),
        q_value.as_ref(),
        base.access().clone(),
        <G::Elem as Gadget>::params(base),
    )?;
    let ql = group.power(cs.namespace(|| "Q^l"), &q, &challenge)?;
    let br = group.power(cs.namespace(|| "b^r"), &base, &r)?;
    let left = group.op(cs.namespace(|| "Q^l b^r"), &ql, &br)?;
    <G::Elem as Gadget>::assert_equal(cs.namespace(|| "Q^l b^r == res"), &left, &result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::OptionExt;

    use quickcheck::TestResult;
    // use test::*;
    use crate::util::test_helpers::*;

    use crate::group::{CircuitRsaGroup, CircuitRsaGroupParams, RsaGroup};

    use std::str::FromStr;

    const RSA_2048: &str = "25195908475657893494027183240048398571429282126204032027777137836043662020707595556264018525880784406918290641249515082189298559149176184502808489120072844992687392807287776735971418347270261896375014971824691165077613379859095700097330459748808428401797429100642458691817195118746121515172654632282216869987549182422433637259085141865462043576798423387184774447920739934236584823824281198163815010674810451660377306056201619676256133844143603833904414952634432190114657544454178424020924616515723350778707749817125772467962926386356373289912154831438167899885040445364023527381951378636564391212010397122822120720357";

    pub struct PoEInputs<'a> {
        pub b: &'a str,
        pub exps: &'a [&'a str],
        pub l: &'a str,
        pub m: &'a str,
        pub res: Option<&'a str>, // If missing, it will be computed
    }

    pub struct PoEParams {
        pub limb_width: usize,
        pub n_limbs_b: usize,
        pub n_limbs_e: usize,
    }

    pub struct PoE<'a> {
        inputs: Option<PoEInputs<'a>>,
        params: PoEParams,
    }

    circuit_tests! {
        proof_1_to_1: (
                          PoE {
                              params: PoEParams {
                                  limb_width: 4,
                                  n_limbs_b: 2,
                                  n_limbs_e: 1,
                              },
                              inputs: Some(PoEInputs {
                                  b: "1",
                                  m: "255",
                                  exps: &["1"],
                                  l: "15",
                                  res: Some("1"),
                              }),
                          },
                          true
                      ),
                      proof_1_to_1_2_3_4_15: (
                          PoE {
                              params: PoEParams {
                                  limb_width: 4,
                                  n_limbs_b: 2,
                                  n_limbs_e: 1,
                              },
                              inputs: Some(PoEInputs {
                                  b: "1",
                                  m: "255",
                                  exps: &[
                                      "1",
                                      "2",
                                      "3",
                                      "4",
                                      "15",
                                  ],
                                  l: "15",
                                  res: Some("1"),
                              }),
                          },
                          true
                              ),
                              proof_2_to_1_2_3_4_15_wrong: (
                                  PoE {
                                      params: PoEParams {
                                          limb_width: 4,
                                          n_limbs_b: 2,
                                          n_limbs_e: 1,
                                      },
                                      inputs: Some(PoEInputs {
                                          b: "2",
                                          m: "255",
                                          exps: &[
                                              "1",
                                              "2",
                                              "3",
                                              "4",
                                              "15",
                                          ],
                                          l: "15",
                                          res: Some("16"),
                                      }),
                                  },
                                  false
                                      ),
                                      proof_2_to_1_2_3_4_15: (
                                          PoE {
                                              params: PoEParams {
                                                  limb_width: 4,
                                                  n_limbs_b: 2,
                                                  n_limbs_e: 1,
                                              },
                                              inputs: Some(PoEInputs {
                                                  b: "2",
                                                  m: "255",
                                                  exps: &[
                                                      "1",
                                                      "2",
                                                      "3",
                                                      "4",
                                                      "15",
                                                  ],
                                                  l: "15",
                                                  res: None,
                                              }),
                                          },
                                          true
                                              ),
                                              proof_7_to_many_powers: (
                                                  PoE {
                                                      params: PoEParams {
                                                          limb_width: 4,
                                                          n_limbs_b: 2,
                                                          n_limbs_e: 1,
                                                      },
                                                      inputs: Some(PoEInputs {
                                                          b: "7",
                                                          m: "255",
                                                          exps: &[
                                                              "1",
                                                              "2",
                                                              "3",
                                                              "4",
                                                              "9",
                                                              "4",
                                                              "11",
                                                              "15",
                                                              "4",
                                                              "15",
                                                          ],
                                                          l: "13",
                                                          res: None,
                                                      }),
                                                  },
                                                  true
                                                      ),
    }

    impl<'a, E: Engine> Circuit<E> for PoE<'a> {
        fn synthesize<CS: ConstraintSystem<E>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
            let b = BigNat::alloc_from_nat(
                cs.namespace(|| "b"),
                || Ok(Integer::from_str(self.inputs.grab()?.b).unwrap()),
                self.params.limb_width,
                self.params.n_limbs_b,
            )?;
            let exps = self
                .inputs
                .grab()?
                .exps
                .iter()
                .enumerate()
                .map(|(i, e)| {
                    Ok(Reduced::from_raw(BigNat::alloc_from_nat(
                        cs.namespace(|| format!("e {}", i)),
                        || Ok(Integer::from_str(e).unwrap()),
                        self.params.limb_width,
                        self.params.n_limbs_e,
                    )?))
                })
                .collect::<Result<Vec<Reduced<E>>, SynthesisError>>()?;
            let res_computation = || -> Result<Integer, SynthesisError> {
                let ref inputs = self.inputs.grab()?;
                inputs
                    .res
                    .map(|r| Ok(Integer::from_str(r).unwrap()))
                    .unwrap_or_else(|| {
                        let mut acc = Integer::from_str(inputs.b).unwrap();
                        let m = Integer::from_str(inputs.m).unwrap();
                        for p in inputs.exps {
                            acc.pow_mod_mut(&Integer::from_str(p).unwrap(), &m).unwrap();
                        }
                        Ok(acc)
                    })
            };
            let res = BigNat::alloc_from_nat(
                cs.namespace(|| "res"),
                res_computation,
                self.params.limb_width,
                self.params.n_limbs_b,
            )?;
            let group = self
                .inputs
                .as_ref()
                .map(|is| RsaGroup::from_strs("2", is.m));
            let g = <CircuitRsaGroup<E> as Gadget>::alloc(
                cs.namespace(|| "g"),
                group.as_ref(),
                (),
                &CircuitRsaGroupParams {
                    n_limbs: self.params.n_limbs_b,
                    limb_width: self.params.limb_width,
                },
            )?;
            let l = BigNat::alloc_from_nat(
                cs.namespace(|| "l"),
                || Ok(Integer::from_str(self.inputs.grab()?.l).unwrap()),
                self.params.limb_width,
                self.params.n_limbs_b,
            )?;
            proof_of_exp(cs.namespace(|| "proof of exp"), &g, &b, &exps, &l, &res)
        }
    }

    #[test]
    fn base_to_product_0() {
        let b = Integer::from(2usize);
        let l = Integer::from(2usize);
        let xs = [
            Integer::from(1usize),
            Integer::from(1usize),
            Integer::from(1usize),
        ];
        let g = RsaGroup::from_strs("2", "7");
        let clever = base_to_product(&g, &b, &l, xs.iter());
        assert_eq!(clever, Integer::from(1usize));
    }

    #[test]
    fn base_to_product_1() {
        let b = Integer::from(2usize);
        let xs = [
            Integer::from(4usize),
            Integer::from(3usize),
            Integer::from(1usize),
        ];
        let l = Integer::from(3usize);
        let g = RsaGroup::from_strs("2", "3");
        let clever = base_to_product(&g, &b, &l, xs.iter());
        assert_eq!(clever, Integer::from(1usize));
    }

    #[test]
    fn base_to_product_2() {
        let b = Integer::from(2usize);
        let l = Integer::from(2usize);
        let xs = [
            Integer::from(1usize),
            Integer::from(1usize),
            Integer::from(1usize),
        ];
        let g = RsaGroup::from_strs("2", "17");
        let clever = base_to_product(&g, &b, &l, xs.iter());
        assert_eq!(clever, Integer::from(1usize));
    }

    // #[bench]
    // fn bench_base_to_product(ben: &mut Bencher) {
    //     let b = Integer::from(2usize);
    //     let l = Integer::from_str("4378779693322314851078464711427904016245509035623856790738093868399234071816590832271409512479149219732517").unwrap();
    //     let xs = vec![
    //         Integer::from_str("31937553987974094718323624043504205546834586774376973142156746177420677478688763299109194760111447891192360362820159149396249147942612451155969619775305163496407638473777556838684741069061351141275104169798848446335239243312484965159829326775977793454245590125242263267420883094097592918381012308862157981711929572365175824672174089740874967056535954189180093379786870545069569186432812295310881940305587888652601685710785451536880821959636231557861961996647312938583891145806865161362164404798306963474067144506909829836959487322752735917184127271661403524679313392947295519723541385106382901941073514681220701690463").unwrap(); 2
    //     ];
    //     let g = RsaGroup::from_strs("2", RSA_2048);
    //     ben.iter(|| base_to_product(&g, &b, &l, xs.iter()))
    // }

    #[quickcheck]
    fn qc_proof_of_exp(b: u8, x0: u8, x1: u8, x2: u8, l: u8) -> TestResult {
        if b < 1 {
            return TestResult::discard();
        }
        if l < 2 {
            return TestResult::discard();
        }
        let b = format!("{}", b);
        let x0 = format!("{}", x0);
        let x1 = format!("{}", x1);
        let x2 = format!("{}", x2);
        let l = format!("{}", l);
        let m = "255";
        let xs: &[&str] = &[&x0, &x1, &x2];
        let circuit = PoE {
            inputs: Some(PoEInputs {
                b: &b,
                m: &m,
                l: &l,
                exps: xs,
                res: None,
            }),
            params: PoEParams {
                limb_width: 4,
                n_limbs_b: 2,
                n_limbs_e: 2,
            },
        };
        let mut cs = TestConstraintSystem::<Bn256>::new();

        circuit.synthesize(&mut cs).expect("synthesis failed");
        if !cs.is_satisfied() {
            println!("UNSAT: {:#?}", cs.which_is_unsatisfied())
        }

        TestResult::from_bool(cs.is_satisfied())
    }
}
