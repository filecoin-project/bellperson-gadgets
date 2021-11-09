# Gadgets for `bellperson`

> The code is based on [alex-ozdemir/bellman-bignat](https://github.com/alex-ozdemir/bellman-bignat) and has been updated to work with bellperson and newer Rust.

This is a library providing different gadgets for use with `bellperson`, including multiprecision arithmetic and RSA accumulators.



## Contents

   * An implementation of multiprecision natural arithmetic based on the
      techniques of xJsnark, with additional features and optimizations.
   * A unified interface for a variety of hash functions.
      * Poseidon (from `sapling_crypto-ce`)
      * Pedersen (from `sapling_crypto-ce`)
      * Sha256 (from `sapling_crypto-ce`)
      * MiMC
   * A hash to provable primes, and associated checking machinery.
   * A division-intractable hash.
   * A hash-generic implementation of Merkle trees.
   * A hash-generic implementation of an RSA accumulator.

## Development

Test can be run using `cargo`.

## Examples

   * `set_proof N_SWAPS` does setup for, writes a proof of, and then checks the
      proof of `n` swaps in an RSA accumulator.
   * `set_bench` is used for measuring the constraint costs of RSA and Merkle
      accumulators when performing swaps in a set. It does not actually
      synthesize any proofs.
   * `rollup_bench` is for measuring the constraint costs of a payment system
      backed by RSA and Merkle accumulators.


## License

Licensed under either of

- Apache License, Version 2.0, |[LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.
