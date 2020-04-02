# bls12_381_ietf

`bls12_381_ietf` is a crate lib that implements the [IETF BLS draft standard v0](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-00) with [hash-to-curve v5](https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05) as per the inter-blockchain standardization agreement. The BLS standards specify [different ciphersuites](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-00#section-4.2) which each have different functionality to accommodate various use cases. The following ciphersuites are availible from this library:

- `G2Basic` also known as `BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_NUL_`
- `G2MessageAugmentation` also known as `BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_AUG_`
- (Pending) `G2ProofOfPossession` also known as `BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_POP_`

**WARNING**: This is a proof-of-concept prototype, and in particular has not been reviewed or audited. Use at your own risk.

## Security Warnings

This library does not make any guarantees about constant-time operations, memory access patterns, or resistance to side-channel attacks.

## Pending tasks

- [x] Implement KeyGen standard
- [ ] Implement `G2ProofOfPossession`
- [x] Implement signature verification
- [ ] Implement signature aggregation
- [ ] Add github actions to test PR and commits
- [ ] Add test vectors from other implementations
- [ ] Update BLS from IETF v1 -> v2
- [ ] Switches hash-to-field to new v06 hash system

## Commands

### Examples
```
$ cargo run --example g2basic
   Compiling bls12_381_ietf v0.1.0 (/Users/edu/bls/bls12_381_ietf)
    Finished dev [unoptimized + debuginfo] target(s) in 1.46s
     Running `target/debug/examples/g2basic`
Public Key:     81d84ab98c774e9f4f18f17d968dbb0ada8fbb6210ac48e372813ac5f7b67f188ddf11dcd71644c7226cab56869ba6a4
Message:        edu@dappnode.io
Signature:      b3731f23c92afafc4d511

$ cargo run --example g2messageaugmentation
   Compiling bls12_381_ietf v0.1.0 (/Users/edu/bls/bls12_381_ietf)
    Finished dev [unoptimized + debuginfo] target(s) in 0.62s
     Running `target/debug/examples/g2messageaugmentation`
Public Key:     8bb1ad17ca77078a500ef0780c3c3a5f0dc26290b0bfb21d2c76f1a827bed8764d7f32332dc2db3084b1faea29134ea7
Message:        edu@dappnode.io!!!
Signature:      b4352d55bf8e40afb0dbad2bb904dd080b74e3840850bb799a77d8c54100b652105d66a0756cb56fd4ceadc4f84863d00a6b5a839f6a275d45f569f5bc7a796089daf565229359cd676381a0926a6369ed19ce3887191c0809c1368abd68162d
Signature verified correctly!
```

### Tests
```
$ cargo test
   Compiling bls12_381_ietf v0.1.0 (/Users/edu/bls/bls12_381_ietf)
    Finished test [unoptimized + debuginfo] target(s) in 1.63s
     Running target/debug/deps/bls12_381_ietf-92da16f66df5b352

running 23 tests
test optimized_swu::tests::test_sgn0_be ... ok
test optimized_swu::tests::bench_iso_map_g2 ... ok
test optimized_swu::tests::test_iso_map_g2 ... ok
test optimized_swu::tests::bench_sqrt_division_fq2 ... ok
test optimized_swu::tests::test_sqrt_division_fq2 ... ok
test tests::bench_test_priv_to_pub ... ok
test optimized_swu::tests::bench_optimized_swu_g2 ... ok
test optimized_swu::tests::test_optimized_swu_g2 ... ok
test tests::bench_keygen ... ok
test tests::test_priv_to_pub ... ok
test tests::test_keygen ... ok
test tests::bench_hash_to_g2 ... ok
test tests::test_sign_g2basic ... ok
test tests::test_verify_g2_message_augmentation_panic ... ok
test tests::bench_sign_g2basic ... ok
test tests::test_verify_g2basic_panic ... ok
test tests::bench_sign_g2_message_augmentation ... ok
test tests::test_sign_g2_message_augmentation ... ok
test tests::test_hash_to_g2 ... ok
test tests::bench_verify_g2basic ... ok
test tests::bench_verify_g2_message_augmentation ... ok
test tests::test_verify_g2_message_augmentation ... ok
test tests::test_verify_g2basic ... ok

test result: ok. 23 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

   Doc-tests bls12_381_ietf

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Benches
```
$ cargo bench
   Compiling bls12_381_ietf v0.1.0 (/Users/edu/bls/bls12_381_ietf)
    Finished bench [optimized] target(s) in 2.56s
     Running target/release/deps/bls12_381_ietf-29a9ffc0e2b8dcd3

running 23 tests
test optimized_swu::tests::test_iso_map_g2 ... ignored
test optimized_swu::tests::test_optimized_swu_g2 ... ignored
test optimized_swu::tests::test_sgn0_be ... ignored
test optimized_swu::tests::test_sqrt_division_fq2 ... ignored
test tests::test_hash_to_g2 ... ignored
test tests::test_keygen ... ignored
test tests::test_priv_to_pub ... ignored
test tests::test_sign_g2_message_augmentation ... ignored
test tests::test_sign_g2basic ... ignored
test tests::test_verify_g2_message_augmentation ... ignored
test tests::test_verify_g2_message_augmentation_panic ... ignored
test tests::test_verify_g2basic ... ignored
test tests::test_verify_g2basic_panic ... ignored
test optimized_swu::tests::bench_iso_map_g2        ... bench:       7,789 ns/iter (+/- 1,293)
test optimized_swu::tests::bench_optimized_swu_g2  ... bench:     233,062 ns/iter (+/- 22,060)
test optimized_swu::tests::bench_sqrt_division_fq2 ... bench:     222,143 ns/iter (+/- 19,289)
test tests::bench_hash_to_g2                       ... bench:   3,571,612 ns/iter (+/- 332,016)
test tests::bench_keygen                           ... bench:     258,906 ns/iter (+/- 18,152)
test tests::bench_sign_g2_message_augmentation     ... bench:   3,637,884 ns/iter (+/- 393,305)
test tests::bench_sign_g2basic                     ... bench:   3,557,166 ns/iter (+/- 193,992)
test tests::bench_test_priv_to_pub                 ... bench:      17,496 ns/iter (+/- 1,461)
test tests::bench_verify_g2_message_augmentation   ... bench:   9,779,860 ns/iter (+/- 2,000,297)
test tests::bench_verify_g2basic                   ... bench:  10,094,099 ns/iter (+/- 2,964,663)

test result: ok. 0 passed; 0 failed; 13 ignored; 10 measured; 0 filtered out
```
## Reference implementations

* https://github.com/ethereum/py_ecc

* https://github.com/algorand/bls_sigs_ref

## Bibliography

* [IETF BLS draft standard v0](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-00)

* BCIMRT10: Brier, Coron, Icart, Madore, Randriam, Tibouchi.
["Efficient Indifferentiable Hashing into Ordinary Elliptic Curves."](https://eprint.iacr.org/2009/340)
Proc. CRYPTO, 2010.

* BLS01: Boneh, Lynn, and Shacham.
["Short signatures from the Weil pairing."](https://hovav.net/ucsd/dist/sigs.pdf)
Proc. ASIACRYPT, 2001.

* FT12: Fouque and Tibouchi,
["Indifferentiable hashing to Barreto-Naehrig curves."](https://link.springer.com/chapter/10.1007/978-3-642-33481-8_1)
Proc.  LATINCRYPT, 2012.

* SvdW06: Shallue and van de Woestijne,
["Construction of rational points on elliptic curves over finite fields."](https://works.bepress.com/andrew_shallue/1/download/)
Proc. ANTS 2006.