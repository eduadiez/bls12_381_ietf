# bls12_381_ietf

`bls12_381_ietf` is a crate lib that implements the [IETF BLS draft standard v0](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-00) with [hash-to-curve v5](https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05) as per the inter-blockchain standardization agreement. The BLS standards specify [different ciphersuites](https://tools.ietf.org/html/draft-irtf-cfrg-bls-signature-00#section-4.2) which each have different functionality to accommodate various use cases. The following ciphersuites are availible from this library:

- `G2Basic` also known as `BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_NUL_`
- `G2MessageAugmentation` also known as `BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_AUG_`
- (Pending) `G2ProofOfPossession` also known as `BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_POP_`

**WARNING**: This is a proof-of-concept prototype, and in particular has not been reviewed or audited. Use at your own risk.

## Security Warnings

This library does not make any guarantees about constant-time operations, memory access patterns, or resistance to side-channel attacks.

## Pending tasks

- [ ] Implement `G2ProofOfPossession`
- [ ] Implement signature verification
- [ ] Implement signature aggregation
- [ ] Add github actions to test PR and commits
- [ ] Add test vectors from other implementations
- [ ] Update BLS from IETF v1 -> v2
- [ ] Switches hash-to-field to new v06 hash system

## Commands

### Examples
```
$ cargo run --example main
    Finished dev [unoptimized + debuginfo] target(s) in 0.03s
     Running `target/debug/examples/main`
sign: [152, 112, 73, 150, 76, 45, 12, 146, 180, 42, 173, 215, 209, 124, 171, 95, 249, 133, 149, 54, 210, 139, 225, 49, 18, 9, 25, 108, 181, 63, 246, 41, 224, 95, 17, 199, 107, 84, 153, 41, 50, 190, 196, 243, 74, 48, 65, 204, 25, 143, 45, 80, 103, 103, 168, 242, 143, 77, 191, 109, 70, 140, 152, 195, 134, 187, 100, 247, 203, 162, 79, 252, 153, 138, 110, 128, 6, 128, 60, 193, 233, 221, 170, 195, 165, 152, 61, 8, 22, 222, 208, 67, 24, 8, 195, 117]
```

### Tests
```
$ cargo test
    Finished test [unoptimized + debuginfo] target(s) in 0.03s
     Running target/debug/deps/bls12_381_ietf-a0f9c147364f4d8f

running 15 tests
test optimized_swu::tests::test_sgn0_be ... ok
test optimized_swu::tests::bench_sqrt_division_fq2 ... ok
test optimized_swu::tests::test_iso_map_g2 ... ok
test optimized_swu::tests::bench_iso_map_g2 ... ok
test optimized_swu::tests::test_sqrt_division_fq2 ... ok
test tests::bench_test_priv_to_pub ... ok
test tests::test_priv_to_pub ... ok
test optimized_swu::tests::bench_optimized_swu_g2 ... ok
test optimized_swu::tests::test_optimized_swu_g2 ... ok
test tests::bench_hash_to_g2 ... ok
test tests::bench_sign_g2_message_augmentation ... ok
test tests::bench_sign_g2basic ... ok
test tests::test_sign_g2_message_augmentation ... ok
test tests::test_sign_g2basic ... ok
test tests::test_hash_to_g2 ... ok

test result: ok. 15 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

   Doc-tests bls12_381_ietf

running 0 tests

```

### Benches
```
$ cargo bench
   Compiling bls12_381_ietf v0.1.0 (/Users/edu/test/pairing_bench)
    Finished bench [optimized] target(s) in 2.03s
     Running target/release/deps/bls12_381_ietf-b40b8bd2734cabbc

running 15 tests
test optimized_swu::tests::test_iso_map_g2 ... ignored
test optimized_swu::tests::test_optimized_swu_g2 ... ignored
test optimized_swu::tests::test_sgn0_be ... ignored
test optimized_swu::tests::test_sqrt_division_fq2 ... ignored
test tests::test_hash_to_g2 ... ignored
test tests::test_priv_to_pub ... ignored
test tests::test_sign_g2_message_augmentation ... ignored
test tests::test_sign_g2basic ... ignored
test optimized_swu::tests::bench_iso_map_g2        ... bench:       8,155 ns/iter (+/- 951)
test optimized_swu::tests::bench_optimized_swu_g2  ... bench:     235,073 ns/iter (+/- 58,003)
test optimized_swu::tests::bench_sqrt_division_fq2 ... bench:     230,608 ns/iter (+/- 25,894)
test tests::bench_hash_to_g2                       ... bench:   3,515,192 ns/iter (+/- 318,478)
test tests::bench_sign_g2_message_augmentation     ... bench:   3,598,870 ns/iter (+/- 355,405)
test tests::bench_sign_g2basic                     ... bench:   3,579,574 ns/iter (+/- 936,845)
test tests::bench_test_priv_to_pub                 ... bench:      17,567 ns/iter (+/- 3,842)

test result: ok. 0 passed; 0 failed; 8 ignored; 7 measured; 0 filtered out
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