use rand::Rng;

use crate::eddsa::{PrivateKey, PublicKey, Signature};
use crate::jubjub::{FixedGenerators, JubjubEngine};
use ff::{PrimeField, PrimeFieldRepr};

use crate::hash::Hasher;

use crate::util::convert::usize_to_f;

use std::fmt::{Debug, Error, Formatter};

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Action<E: JubjubEngine> {
    pub dst: PublicKey<E>,
    pub amt: u64,
    pub tx_no: u64,
}

impl<E> Debug for Action<E>
where
    E: JubjubEngine,
{
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        f.debug_struct("Action")
            .field(
                "dst",
                &format_args!("({}, {})", self.dst.0.into_xy().0, self.dst.0.into_xy().1,),
            )
            .field("amt", &format_args!("{}", self.amt))
            .field("tx_no", &format_args!("{}", self.tx_no))
            .finish()
    }
}

impl<E: JubjubEngine> Action<E> {
    pub fn as_elems(&self) -> Vec<E::Fr> {
        vec![
            self.dst.0.into_xy().0.clone(),
            self.dst.0.into_xy().1.clone(),
            usize_to_f(self.amt as usize),
            usize_to_f(self.tx_no as usize),
        ]
    }
    pub fn sign<R: Rng, H: Hasher<F = E::Fr>>(
        &self,
        rng: &mut R,
        p_g: FixedGenerators,
        params: &E::Params,
        hasher: &H,
        sk: &PrivateKey<E>,
    ) -> SignedTx<E> {
        let hash = hasher.hash(&self.as_elems());
        let mut bytes = Vec::new();
        hash.into_repr().write_le(&mut bytes).unwrap();
        bytes.truncate((E::Fr::CAPACITY / 8) as usize);
        SignedTx {
            tx: Tx {
                src: PublicKey::from_private(sk, p_g, params),
                action: self.clone(),
            },
            sig: sk.sign_raw_message(&bytes, rng, p_g, params, (E::Fr::CAPACITY / 8) as usize),
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Tx<E: JubjubEngine> {
    pub src: PublicKey<E>,
    pub action: Action<E>,
}

impl<E> Debug for Tx<E>
where
    E: JubjubEngine,
{
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        f.debug_struct("Tx")
            .field(
                "src",
                &format_args!("({}, {})", self.src.0.into_xy().0, self.src.0.into_xy().1,),
            )
            .field("action", &self.action)
            .finish()
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct SignedTx<E: JubjubEngine> {
    pub tx: Tx<E>,
    pub sig: Signature<E>,
}

pub mod circuit {
    use crate::circuit::baby_eddsa::EddsaSignature;
    use crate::circuit::ecc::EdwardsPoint;
    use crate::circuit::num::AllocatedNum;
    use crate::jubjub::JubjubEngine;
    use bellman::{ConstraintSystem, LinearCombination, SynthesisError};
    use ff::ScalarEngine;
    use ff::{Field, PrimeField};
    use std::clone::Clone;
    use std::sync::Arc;

    use super::{Action, SignedTx};
    use crate::hash::circuit::CircuitHasher;
    use crate::rollup::sig::allocate_sig;
    use crate::util::convert::usize_to_f;
    use crate::util::gadget::Gadget;
    use crate::util::num::Num;
    use crate::CResult;
    use crate::OptionExt;

    #[derive(Derivative)]
    #[derivative(Clone(bound = ""))]
    pub struct CircuitAction<E: JubjubEngine> {
        pub dst: EdwardsPoint<E>,
        pub amt: AllocatedNum<E>,
        pub tx_no: AllocatedNum<E>,
        pub params: Arc<E::Params>,
        pub value: Option<Action<E>>,
    }

    impl<E: JubjubEngine> Gadget for CircuitAction<E> {
        type E = E;
        type Value = Action<E>;
        type Access = ();
        type Params = Arc<E::Params>;
        fn alloc<CS: ConstraintSystem<Self::E>>(
            mut cs: CS,
            value: Option<&Self::Value>,
            _access: Self::Access,
            params: &Self::Params,
        ) -> Result<Self, SynthesisError> {
            let dst_x = AllocatedNum::alloc(cs.namespace(|| "dst_x"), || {
                Ok(value.grab()?.dst.0.into_xy().0)
            })?;
            let dst_y = AllocatedNum::alloc(cs.namespace(|| "dst_y"), || {
                Ok(value.grab()?.dst.0.into_xy().1)
            })?;
            let amt = AllocatedNum::alloc(cs.namespace(|| "amt"), || {
                Ok(usize_to_f(value.grab()?.amt as usize))
            })?;
            let tx_no = AllocatedNum::alloc(cs.namespace(|| "tx_no"), || {
                Ok(usize_to_f(value.grab()?.tx_no as usize))
            })?;
            Ok(Self {
                dst: EdwardsPoint::interpret(cs.namespace(|| "dst"), &dst_x, &dst_y, &params)?,
                amt,
                tx_no,
                params: params.clone(),
                value: value.cloned(),
            })
        }
        fn wires(&self) -> Vec<LinearCombination<Self::E>> {
            vec![
                LinearCombination::zero() + self.dst.get_x().get_variable(),
                LinearCombination::zero() + self.dst.get_y().get_variable(),
                LinearCombination::zero() + self.amt.get_variable(),
                LinearCombination::zero() + self.tx_no.get_variable(),
            ]
        }
        fn wire_values(&self) -> Option<Vec<<Self::E as ScalarEngine>::Fr>> {
            vec![
                self.dst.get_x().get_value(),
                self.dst.get_y().get_value(),
                self.amt.get_value(),
                self.tx_no.get_value(),
            ]
            .into_iter()
            .collect::<Option<Vec<_>>>()
        }
        fn value(&self) -> Option<&Self::Value> {
            self.value.as_ref()
        }
        fn access(&self) -> &Self::Access {
            &()
        }
        fn params(&self) -> &Self::Params {
            &self.params
        }
    }

    impl<E: JubjubEngine> CircuitAction<E> {
        pub fn as_elems(&self) -> Vec<AllocatedNum<E>> {
            vec![
                self.dst.get_x().clone(),
                self.dst.get_y().clone(),
                self.amt.clone(),
                self.tx_no.clone(),
            ]
        }
        pub fn check_signature<CS: ConstraintSystem<E>, H: CircuitHasher<E = E>>(
            &self,
            mut cs: CS,
            generator: EdwardsPoint<E>,
            hasher: &H,
            signature: EddsaSignature<E>,
        ) -> CResult<()> {
            let elems = self.as_elems();
            let hash = hasher.allocate_hash(cs.namespace(|| "hash"), &elems)?;
            let mut bits = hash.into_bits_le_strict(cs.namespace(|| "bits"))?;
            bits.truncate((E::Fr::CAPACITY / 8 * 8) as usize);
            signature.verify_raw_message_signature(
                cs.namespace(|| "check sig"),
                &self.params,
                &bits,
                generator,
                (E::Fr::CAPACITY / 8) as usize,
            )
        }
    }

    #[derive(Derivative)]
    #[derivative(Clone(bound = ""))]
    pub struct CircuitSignedTx<E: JubjubEngine> {
        pub action: CircuitAction<E>,
        pub src: EdwardsPoint<E>,
        pub sig: EddsaSignature<E>,
        pub value: Option<SignedTx<E>>,
        pub params: Arc<E::Params>,
    }

    impl<E: JubjubEngine> Gadget for CircuitSignedTx<E> {
        type E = E;
        type Value = SignedTx<E>;
        type Access = ();
        type Params = Arc<E::Params>;
        fn alloc<CS: ConstraintSystem<Self::E>>(
            mut cs: CS,
            value: Option<&Self::Value>,
            _access: Self::Access,
            params: &Self::Params,
        ) -> Result<Self, SynthesisError> {
            let action = CircuitAction::alloc(
                cs.namespace(|| "action"),
                value.as_ref().map(|v| &v.tx.action),
                (),
                params,
            )?;
            let sig = allocate_sig(
                cs.namespace(|| "src"),
                value.as_ref().map(|v| (v.sig.clone(), v.tx.src.clone())),
                params.as_ref(),
            )?;
            Ok(Self {
                src: sig.pk.clone(),
                action,
                sig,
                value: value.cloned(),
                params: params.clone(),
            })
        }
        fn wires(&self) -> Vec<LinearCombination<Self::E>> {
            let mut v = self.action.wires();
            v.push(LinearCombination::zero() + self.sig.pk.get_x().get_variable());
            v.push(LinearCombination::zero() + self.sig.pk.get_y().get_variable());
            v.push(LinearCombination::zero() + self.sig.r.get_x().get_variable());
            v.push(LinearCombination::zero() + self.sig.r.get_y().get_variable());
            v.push(LinearCombination::zero() + self.sig.s.get_variable());
            v
        }
        fn wire_values(&self) -> Option<Vec<<Self::E as ScalarEngine>::Fr>> {
            if let Some(mut v) = self.action.wire_values() {
                v.push(self.sig.pk.get_x().get_value()?);
                v.push(self.sig.pk.get_y().get_value()?);
                v.push(self.sig.r.get_x().get_value()?);
                v.push(self.sig.r.get_y().get_value()?);
                v.push(self.sig.s.get_value()?);
                Some(v)
            } else {
                None
            }
        }
        fn value(&self) -> Option<&Self::Value> {
            self.value.as_ref()
        }
        fn access(&self) -> &Self::Access {
            &()
        }
        fn params(&self) -> &Self::Params {
            &self.params
        }
    }

    impl<E: JubjubEngine> CircuitSignedTx<E> {
        pub fn check_signature<CS: ConstraintSystem<E>, H: CircuitHasher<E = E>>(
            &self,
            cs: CS,
            hasher: &H,
            gen: EdwardsPoint<E>,
        ) -> CResult<()> {
            self.action
                .check_signature(cs, gen, hasher, self.sig.clone())
        }
    }

    #[derive(Derivative)]
    #[derivative(Clone(bound = ""))]
    pub struct CircuitAccount<E>
    where
        E: JubjubEngine,
    {
        pub id: EdwardsPoint<E>,
        pub amt: AllocatedNum<E>,
        pub next_tx_no: AllocatedNum<E>,
    }

    impl<E> CircuitAccount<E>
    where
        E: JubjubEngine,
    {
        pub fn as_elems(&self) -> Vec<AllocatedNum<E>> {
            vec![
                self.id.get_x().clone(),
                self.id.get_y().clone(),
                self.amt.clone(),
                self.next_tx_no.clone(),
            ]
        }

        pub fn with_less<CS: ConstraintSystem<E>>(
            &self,
            mut cs: CS,
            diff: &AllocatedNum<E>,
        ) -> CResult<Self> {
            Num::from(diff.clone()).fits_in_bits(cs.namespace(|| "rangecheck diff"), 64)?;
            let new_amt = AllocatedNum::alloc(cs.namespace(|| "new amt"), || {
                let mut f = self.amt.get_value().grab()?.clone();
                f.sub_assign(diff.get_value().grab()?);
                Ok(f)
            })?;
            Num::from(new_amt.clone()).fits_in_bits(cs.namespace(|| "rangecheck new amt"), 64)?;
            let new_next_tx_no = AllocatedNum::alloc(cs.namespace(|| "new next_tx_no"), || {
                let mut f = self.next_tx_no.get_value().grab()?.clone();
                f.add_assign(&E::Fr::one());
                Ok(f)
            })?;
            Num::from(new_next_tx_no.clone())
                .fits_in_bits(cs.namespace(|| "rangecheck new next_tx_no"), 64)?;
            Ok(Self {
                id: self.id.clone(),
                amt: new_amt,
                next_tx_no: new_next_tx_no,
            })
        }

        pub fn with_more<CS: ConstraintSystem<E>>(
            &self,
            mut cs: CS,
            diff: &AllocatedNum<E>,
        ) -> CResult<Self> {
            let new_amt = AllocatedNum::alloc(cs.namespace(|| "new amt"), || {
                let mut f = self.amt.get_value().grab()?.clone();
                f.add_assign(diff.get_value().grab()?);
                Ok(f)
            })?;
            Num::from(new_amt.clone()).fits_in_bits(cs.namespace(|| "rangecheck new amt"), 64)?;
            Ok(Self {
                id: self.id.clone(),
                amt: new_amt,
                next_tx_no: self.next_tx_no.clone(),
            })
        }
    }
}

#[derive(Derivative)]
#[derivative(Clone(bound = ""))]
pub struct Account<E>
where
    E: JubjubEngine,
{
    pub id: PublicKey<E>,
    pub amt: u64,
    pub next_tx_no: u64,
}

impl<E> Debug for Account<E>
where
    E: JubjubEngine,
{
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        f.debug_struct("Account")
            .field(
                "id",
                &format_args!("({}, {})", self.id.0.into_xy().0, self.id.0.into_xy().1,),
            )
            .field("amt", &format_args!("{}", self.amt))
            .field("next_tx_no", &format_args!("{}", self.next_tx_no))
            .finish()
    }
}

impl<E> Account<E>
where
    E: JubjubEngine,
{
    pub fn as_elems(&self) -> Vec<E::Fr> {
        vec![
            self.id.0.into_xy().0.clone(),
            self.id.0.into_xy().1.clone(),
            usize_to_f(self.amt as usize),
            usize_to_f(self.next_tx_no as usize),
        ]
    }
}

pub struct TxAccountChanges<E>
where
    E: JubjubEngine,
{
    pub src_init: Account<E>,
    pub src_final: Account<E>,
    pub dst_init: Account<E>,
    pub dst_final: Account<E>,
}
