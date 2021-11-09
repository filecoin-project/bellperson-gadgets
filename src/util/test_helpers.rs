pub use crate::circuit::test::TestConstraintSystem;
pub use bellman::Circuit;
pub use ff::PrimeField;
pub use pairing::bls12_381::Bls12;
pub use pairing::bn256::Bn256;

macro_rules! circuit_tests {
    ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (circuit, is_sat) = $value;
                let mut cs = TestConstraintSystem::<Bn256>::new();

                circuit.synthesize(&mut cs).expect("synthesis failed");
                println!(concat!("Constraints in {}: {}"), stringify!($name), cs.num_constraints());
                if is_sat && !cs.is_satisfied() {
                    println!("UNSAT: {:#?}", cs.which_is_unsatisfied())
                }
                let unconstrained = cs.find_unconstrained();
                if unconstrained.len() > 0 {
                    println!(concat!("Unconstrained in {}: {}"), stringify!($name), cs.find_unconstrained());
                }

                assert_eq!(cs.is_satisfied(), is_sat);
            }
        )*
    }
}

macro_rules! circuit_benches {
    ($($name:ident: $value:expr,)*) => {
        $(
            // #[bench]
            // fn $name(b: &mut test::Bencher) {
            //     let (circuit, is_sat) = $value;

            //     b.iter(|| {
            //         let circuit = circuit.clone();
            //         let mut cs = TestConstraintSystem::<Bls12>::new();
            //         circuit.synthesize(&mut cs).expect("synthesis failed");
            //         assert_eq!(cs.is_satisfied(), is_sat);
            //     })
            // }
        )*
    }
}
