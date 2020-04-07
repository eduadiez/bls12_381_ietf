use crate::constants::H_EFF;
use crate::optimized_swu::{iso_map_g2, optimized_swu_g2};
use crate::pairing::CurveAffine;
use hkdf::Hkdf;
use num_bigint::BigUint;
use pairing::bls12_381::{Fq, Fq2, G2Affine, G2};
use pairing::ff::{Field, PrimeField};
use pairing::CurveProjective;
use sha2::Sha256;
/*
    Convert a message to a point on G2 as defined here:
    https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-6.6.3

    The idea is to first hash into FQ2 and then use SSWU to map the result into G2.

    Contants and inputs follow the ciphersuite ``BLS12381G2_XMD:SHA-256_SSWU_RO_`` defined here:
    https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-06#section-8.7.2
*/
pub fn hash_to_g2(message: &[u8], dst: &[u8]) -> G2 {
    let u0 = hash_to_base_fq2(message, 0, dst);
    let u1 = hash_to_base_fq2(message, 1, dst);
    let q0 = map_to_curve_g2(u0);
    let q1 = map_to_curve_g2(u1);
    let mut r = G2::from(q0);
    let r_2 = G2::from(q1);
    r.add_assign(&r_2);
    clear_cofactor_g2(r)
}

/*
    Hash To Base for FQ2

    Convert a message to a point in the finite field as defined here:
    https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-5
*/
pub fn hash_to_base_fq2(message: &[u8], ctr: u8, dst: &[u8]) -> Fq2 {
    // Copy of `message` with appended zero byte
    let msg = [&message[..], &[0x0]].concat();
    let hk = Hkdf::<Sha256>::new(Some(dst), &msg[..]);

    let mut info_pfx = String::from("H2C").into_bytes();
    info_pfx.push(ctr);

    let mut e = vec![];
    //for i in (1, ..., m), where m is the extension degree of FQ2
    for i in 1..3 {
        let mut info = info_pfx.clone();
        info.push(i);
        let mut okm = [0u8; 64];
        hk.expand(&info, &mut okm)
            .expect("64 is a valid length for Sha256 to output");
        let a = BigUint::from_bytes_be(&okm);
        let x = Fq::from_str(&a.to_str_radix(10))
            .expect("Error getting Fq from str when trying to hash_to_base_fq2");
        e.push(x);
    }
    Fq2 { c0: e[0], c1: e[1] }
}

/*
Map To Curve for G2

First, convert FQ2 point to a point on the 3-Isogeny curve.
SWU Map: https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-6.6.2

Second, map 3-Isogeny curve to BLS12-381-G2 curve.
3-Isogeny Map: https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#appendix-C.3
*/
pub fn map_to_curve_g2(u: Fq2) -> G2Affine {
    let (optimized_swu_x, optimized_swu_y, optimized_swu_z) = optimized_swu_g2(u);
    let (iso_map_u, iso_map_v, iso_map_t) =
        iso_map_g2(optimized_swu_x, optimized_swu_y, optimized_swu_z);
    let iso_map_t_inv = iso_map_t.inverse().expect("t should have an inverse");

    let mut iso_map_u_norm = iso_map_u;
    iso_map_u_norm.mul_assign(&iso_map_t_inv);

    let mut iso_map_v_norm = iso_map_v;
    iso_map_v_norm.mul_assign(&iso_map_t_inv);

    G2Affine::from_xy_unchecked(iso_map_u_norm, iso_map_v_norm)
}

/*
Clear Cofactor via Multiplication

Ensure a point falls in the correct sub group of the curve.

Cofactor Clearing Method by Multiplication
There is an optimization based on this Section 4.1 of https://eprint.iacr.org/2017/419
However there is a patent `US patent 7110538` so I'm not sure if it can be used.
*/
pub fn clear_cofactor_g2(f_g2: G2) -> G2 {
    multiply(&f_g2, &(*H_EFF).clone())
    /* Alternative implementation

    // h_eff from https://tools.ietf.org/html/draft-irtf-cfrg-hash-to-curve-05#section-8.9.2
    // "209869847837335686905080341498658477663839067235703451875306851526599783796572738804459333109033834234622528588876978987822447936461846631641690358257586228683615991308971558879306463436166481";
    // h_eff = (p-1) * (p-1) * a + (p-1) * b + c = (p-1) * [ (p-1) * a + b ] + c

    let p_minus_1 = Fr::from_str("52435875175126190479447740508185965837690552500527637822603658699938581184512").expect("Error getting Fq from str");
    let a = Fr::from_str("76329603384216526041794360617386901506").expect("Error getting Fq from str");
    let b = Fr::from_str("4620193101431536425187685247685423423039974257214862087508").expect("Error getting Fq from str");
    let c = Fr::from_str("4620193101431536426027310884911805209287858956884935005521").expect("Error getting Fq from str");
    let f_g2_affine = G2Affine::from(f_g2);
    let f_g2_affine_p_minus_1: G2Affine = G2Affine::from(f_g2_affine.mul(p_minus_1));

    let d = G2Affine::from(f_g2_affine_p_minus_1.mul(p_minus_1)).mul(a);
    let e = f_g2_affine_p_minus_1.mul(b);

    let mut h_eff_multi = f_g2_affine.mul(c);
    h_eff_multi.add_assign(&e);
    h_eff_multi.add_assign(&d);
    h_eff_multi
    */
}

// Review this
pub fn multiply(pt: &G2, n: &BigUint) -> G2 {
    let zero = &BigUint::from(0x0u8);
    let one = &BigUint::from(0x1u8);
    let two = &BigUint::from(0x2u8);
    let pt_g2 = pt;
    let mut dbl = *pt;
    dbl.double();
    if *n == *one {
        *pt
    } else if n % two == *zero {
        multiply(&dbl, &(n / two))
    } else {
        let mut tmp: G2 = multiply(&dbl, &(n / two));
        tmp.add_assign(&pt_g2);
        tmp
    }
}
