use crate::constants::ISO_3_A;
use crate::constants::ISO_3_B;
use crate::constants::{
    ETAS, ISO_3_MAP_COEFFICIENTS, ISO_3_Z, POSITIVE_EIGTH_ROOTS_OF_UNITY, P_MINUS_9_DIV_16,
};
use pairing::bls12_381::Fq2;
use pairing::ff::Field;
use std::cmp::Ordering;


//use optimized_field_elements::sgn0_be;

// Optimized SWU Map - FQ2 to G2': y^2 = x^3 + 240i * x + 1012 + 1012i
// Found in Section 4 of https://eprint.iacr.org/2019/403
pub fn optimized_swu_g2(t: Fq2) -> (Fq2, Fq2, Fq2) {
    let mut t2: Fq2 = t; // t^2
    t2.square();

    let mut iso_3_z_t2 = *ISO_3_Z; // Z * t^2
    iso_3_z_t2.mul_assign(&t2);

    let mut temp = iso_3_z_t2;
    temp.square(); // Z^2 * t^4
    temp.add_assign(&iso_3_z_t2); // Z * t^2 + Z^2 * t^4

    let mut denominator = *ISO_3_A; // -a(Z * t^2 + Z^2 * t^4)
    denominator.mul_assign(&temp);
    denominator.negate();

    temp.add_assign(&Fq2::one());
    let mut numerator = *ISO_3_B;
    numerator.mul_assign(&temp); // b(Z * t^2 + Z^2 * t^4 + 1)
                                 // Exceptional case
    if denominator == Fq2::zero() {
        denominator = *ISO_3_Z;
        denominator.mul_assign(&ISO_3_A);
    }

    let v = denominator.pow([0x3]); // v = D^3
    let mut a_n_d2 = *ISO_3_A;
    a_n_d2.mul_assign(&numerator);
    a_n_d2.mul_assign(&denominator.pow([0x2]));
    let mut b_d3 = *ISO_3_B;
    b_d3.mul_assign(&v);
    // u = N^3 + a * N * D^2 + b* D^3
    let mut u = numerator.pow([0x3]);
    u.add_assign(&a_n_d2);
    u.add_assign(&b_d3);

    let (success, mut sqrt_candidate) = sqrt_division_fq2(u, v);

    let t_pow_3 = t.pow([0x3]);
    let mut y = sqrt_candidate;

    // Handle case where (u / v) is not square
    // sqrt_candidate(x1) = sqrt_candidate(x0) * t^3

    sqrt_candidate.mul_assign(&t_pow_3);
    // u(x1) = Z^3 * t^6 * u(x0)
    let iso_3_z_t2_pow_3 = iso_3_z_t2.pow([0x3]);
    u.mul_assign(&iso_3_z_t2_pow_3);

    let mut success_2 = false;
    for eta in 0..ETAS.len() {
        // Valid solution if (eta * sqrt_candidate(x1)) ** 2 * v - u == 0
        let mut eta_sqrt_candidate = ETAS[eta];
        eta_sqrt_candidate.mul_assign(&sqrt_candidate);
        // temp1 = eta_sqrt_candidate ** 2 * v - u
        let mut temp1 = eta_sqrt_candidate.pow([0x2]);
        temp1.mul_assign(&v);
        temp1.sub_assign(&u);

        if temp1 == Fq2::zero() && !success && !success_2 {
            y = eta_sqrt_candidate;
            success_2 = true;
        }
    }
    if !success && !success_2 {
        panic!("Hash to Curve - Optimized SWU failure");
    }

    if !success {
        numerator.mul_assign(&iso_3_z_t2);
    }

    if sgn0_be(t) != sgn0_be(y) {
        y.negate();
    }

    y.mul_assign(&denominator);

    (numerator, y, denominator)
}

// Return: uv^7 * (uv^15)^((p^2 - 9) / 16) * root of unity
// If valid square root is found return true, else false
pub fn sqrt_division_fq2(u: Fq2, v: Fq2) -> (bool, Fq2) {
    let v_7 = v.pow([0x7]);
    let v_8 = v.pow([0x8]);

    let mut temp1 = u;
    temp1.mul_assign(&v_7);
    let mut temp2 = temp1;
    temp2.mul_assign(&v_8);

    // gamma =  uv^7 * (uv^15)^((p^2 - 9) / 16)
    let mut gamma = temp2.pow(*P_MINUS_9_DIV_16);
    gamma.mul_assign(&temp1);

    let mut result = gamma;
    let mut is_valid_root = false;
    for root in &*POSITIVE_EIGTH_ROOTS_OF_UNITY {
        // Valid if (root * gamma)^2 * v - u == 0
        let mut sqrt_candidate = *root;
        sqrt_candidate.mul_assign(&gamma);
        let mut temp2 = sqrt_candidate;
        temp2.square();
        temp2.mul_assign(&v);
        temp2.sub_assign(&u);
        if temp2 == Fq2::zero() && !is_valid_root {
            is_valid_root = true;
            result = sqrt_candidate;
        }
    }
    (is_valid_root, result)
}

// Optimal Map from 3-Isogenous Curve to G2
pub fn iso_map_g2(x: Fq2, y: Fq2, z: Fq2) -> (Fq2, Fq2, Fq2) {
    // x-numerator, x-denominator, y-numerator, y-denominator
    let z_powers = [z, z.pow([0x2]), z.pow([0x3])];
    let mut mapped_values = [Fq2::zero(), Fq2::zero(), Fq2::zero(), Fq2::zero()];

    for i in 0..ISO_3_MAP_COEFFICIENTS.len() {
        let last = ISO_3_MAP_COEFFICIENTS[i].len() - 1;
        mapped_values[i] = ISO_3_MAP_COEFFICIENTS[i][last];
        #[allow(clippy::needless_range_loop)]
        for j in 0..last {
            //mapped_values[i] = mapped_values[i] * x + z_powers[j] * k_i_j
            mapped_values[i].mul_assign(&x);
            let mut k_i_j = ISO_3_MAP_COEFFICIENTS[i][last - j - 1];
            k_i_j.mul_assign(&z_powers[j]);
            mapped_values[i].add_assign(&k_i_j);
        }
    }

    mapped_values[2].mul_assign(&y); // y-numerator * y
    mapped_values[3].mul_assign(&z); // y-denominator * z

    let mut z_g2 = mapped_values[1];
    z_g2.mul_assign(&mapped_values[3]); // x-denominator * y-denominator
    let mut x_g2 = mapped_values[0];
    x_g2.mul_assign(&mapped_values[3]); // x-numerator * y-denominator
    let mut y_g2 = mapped_values[1];
    y_g2.mul_assign(&mapped_values[2]);

    (x_g2, y_g2, z_g2)
}

fn sgn0_be(fq2: Fq2) -> i8 {
    let f = if fq2.c1.is_zero() { fq2.c0 } else { fq2.c1 };

    let mut f_neg = f;
    f_neg.negate();

    match f_neg.cmp(&f) {
        Ordering::Less => -1,
        Ordering::Greater => 1,
        Ordering::Equal => 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use pairing::bls12_381::Fq;
    use pairing::bls12_381::Fq2;
    use pairing::bls12_381::FqRepr;
    use pairing::ff::PrimeField;
    use test::Bencher;

    #[test]
    fn test_sqrt_division_fq2() {
        let u = Fq2 {
            c0: Fq::from_repr(FqRepr([
                17503171570832252551,
                5141792699049720375,
                504549480580830861,
                13922132864668023789,
                61413056583159152,
                1422855035367833114,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                17798635633672165556,
                6959728244147421064,
                2753201448541769001,
                6545000479225066630,
                6300494637941824560,
                950684344396705085,
            ]))
            .unwrap(),
        };
        let v = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xef93d0200ec70a51,
                0x526ad2b9762546de,
                0xe32e3163c05d9b1b,
                0x2320a58c8f1aa1c6,
                0xefb14ef18ae483ce,
                0x17ec3fd5cf2991b1,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0xc3d75995e1e5a83d,
                0x493f5fa59fcf01d7,
                0xcdd6a92ef475e2eb,
                0x97df321c872dfefa,
                0xdacb1234a7c564f5,
                0x1378b15581208f6a,
            ]))
            .unwrap(),
        };
        let result = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x9f4c6c3bd7bb303b,
                0x4989e742f2818891,
                0xdbc4cb4e2f61c9fa,
                0x2ba212b50f1a5856,
                0x5a7c04f13483fde7,
                0x5b12c48e9ba9d2,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x17f74a6dc8dbe272,
                0xccdd167abbb28e02,
                0x3670cc22474a68dd,
                0x220fb312c6045957,
                0x79a03fba0f5f94b5,
                0xd2244ec42889faf,
            ]))
            .unwrap(),
        };
        assert_eq!(sqrt_division_fq2(u, v), (false, result));
    }

    #[bench]
    fn bench_sqrt_division_fq2(b: &mut Bencher) {
        let u = Fq2 {
            c0: Fq::from_repr(FqRepr([
                17503171570832252551,
                5141792699049720375,
                504549480580830861,
                13922132864668023789,
                61413056583159152,
                1422855035367833114,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                17798635633672165556,
                6959728244147421064,
                2753201448541769001,
                6545000479225066630,
                6300494637941824560,
                950684344396705085,
            ]))
            .unwrap(),
        };
        let v = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xef93d0200ec70a51,
                0x526ad2b9762546de,
                0xe32e3163c05d9b1b,
                0x2320a58c8f1aa1c6,
                0xefb14ef18ae483ce,
                0x17ec3fd5cf2991b1,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0xc3d75995e1e5a83d,
                0x493f5fa59fcf01d7,
                0xcdd6a92ef475e2eb,
                0x97df321c872dfefa,
                0xdacb1234a7c564f5,
                0x1378b15581208f6a,
            ]))
            .unwrap(),
        };
        b.iter(|| sqrt_division_fq2(u, v));
    }

    #[test]
    fn test_sgn0_be() {
        let a = Fq2 {
            c0: Fq::from_str("3400995197588649499514718931891019932020219913477300396945897079704359373123890193425021466541888401327510842382024").unwrap(),
            c1: Fq::from_str("2640660398189119931591286239136316775787391856283464416572613747696938207373985210025315643824728614835369849666497").unwrap(),
        };
        assert_eq!(sgn0_be(a), -1);
        let b = Fq2 {
            c0: Fq::from_str("897598677619248849670597273674499428653764852482722129173435280391013681971809585028517534315749704239618277926608").unwrap(),
            c1: Fq::from_str("602216641362179541003284817953289937917685536763265888208200275981291187009542459614580769820381122449718257466637").unwrap(),
        };
        assert_eq!(sgn0_be(b), 1);
    }

    #[test]
    fn test_optimized_swu_g2() {
        let x = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x55a091c116cfafec,
                0x1a8d084061f04b99,
                0x8ff19ef620afd26f,
                0xba1252b819253f92,
                0x7f8ea67f60712cc3,
                0x1e9a3131bb55f13,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x639ba6be5220b0cb,
                0x69dbae9f8a68e7c5,
                0x38e14220784c21e4,
                0x781d902f1772e0f0,
                0xfac94978cd96dfcd,
                0x10c92d781a75e23b,
            ]))
            .unwrap(),
        };
        let y = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x370b04ae17a905d9,
                0x4b5f39b364f368fa,
                0xa7dc43948e2346c6,
                0xd764f3f805e0d730,
                0x46e2cdb8572e1347,
                0x177d09ec6a5b8773,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x627b0c2a4a691f55,
                0x3694594abb285e97,
                0xeb96a2f04895a020,
                0xeadf79169bd7450b,
                0xc264902e69a7a3bd,
                0xea59f3076192825,
            ]))
            .unwrap(),
        };
        let z = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xf289cff1b322ac8e,
                0xe2a1cfba96cc7a52,
                0x7b11839416e051e,
                0xcacfd747207dda6b,
                0xb90b3c901f15a7e6,
                0x14c269a66651834e,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x87865c9aee66d3b3,
                0xebfa3d1313c9d13c,
                0x60f61b13897b5cdf,
                0xc2ec19c20589147,
                0xd4e9711aaf11e52a,
                0x150deee2cd71e942,
            ]))
            .unwrap(),
        };
        let u = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x34f735b9d2948bf3,
                0x7391c552ba49ed73,
                0xec3f95d1b272d11a,
                0xcd96e9284f0e776f,
                0xf7de6dd6e9a5b614,
                0x723f5fdf9b2592a,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0xb5a8ae9f22ee854d,
                0x4119212677c792b6,
                0x91dd5b7a2125a54,
                0x8402050bfd11d0e0,
                0x8d799b93be1516d6,
                0x1465009cf28b0046,
            ]))
            .unwrap(),
        };
        assert_eq!(optimized_swu_g2(u), (x, y, z));
    }

    #[bench]
    fn bench_optimized_swu_g2(b: &mut Bencher) {
        let u = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x34f735b9d2948bf3,
                0x7391c552ba49ed73,
                0xec3f95d1b272d11a,
                0xcd96e9284f0e776f,
                0xf7de6dd6e9a5b614,
                0x723f5fdf9b2592a,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0xb5a8ae9f22ee854d,
                0x4119212677c792b6,
                0x91dd5b7a2125a54,
                0x8402050bfd11d0e0,
                0x8d799b93be1516d6,
                0x1465009cf28b0046,
            ]))
            .unwrap(),
        };
        b.iter(|| optimized_swu_g2(u));
    }

    #[test]
    fn test_iso_map_g2() {
        let x = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x55a091c116cfafec,
                0x1a8d084061f04b99,
                0x8ff19ef620afd26f,
                0xba1252b819253f92,
                0x7f8ea67f60712cc3,
                0x1e9a3131bb55f13,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x639ba6be5220b0cb,
                0x69dbae9f8a68e7c5,
                0x38e14220784c21e4,
                0x781d902f1772e0f0,
                0xfac94978cd96dfcd,
                0x10c92d781a75e23b,
            ]))
            .unwrap(),
        };
        let y = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x370b04ae17a905d9,
                0x4b5f39b364f368fa,
                0xa7dc43948e2346c6,
                0xd764f3f805e0d730,
                0x46e2cdb8572e1347,
                0x177d09ec6a5b8773,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x627b0c2a4a691f55,
                0x3694594abb285e97,
                0xeb96a2f04895a020,
                0xeadf79169bd7450b,
                0xc264902e69a7a3bd,
                0xea59f3076192825,
            ]))
            .unwrap(),
        };
        let z = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xf289cff1b322ac8e,
                0xe2a1cfba96cc7a52,
                0x7b11839416e051e,
                0xcacfd747207dda6b,
                0xb90b3c901f15a7e6,
                0x14c269a66651834e,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x87865c9aee66d3b3,
                0xebfa3d1313c9d13c,
                0x60f61b13897b5cdf,
                0xc2ec19c20589147,
                0xd4e9711aaf11e52a,
                0x150deee2cd71e942,
            ]))
            .unwrap(),
        };
        let u = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xf5413df674299fc7,
                0xdd31d5a1d08cf298,
                0xcb41d58ed6e5ee6f,
                0xf93209271030e32,
                0x1ffd3a98faba01be,
                0x160fe4b75c06daf3,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0xbd71dd9d2ca2cde4,
                0xef35c222b0ad2e1,
                0x1d5c02840d41a91a,
                0x405488dbd978e4e1,
                0x973f9bcbc1188e2d,
                0x17748ab0c8f709d7,
            ]))
            .unwrap(),
        };
        let v = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x86ffe4908b7bb04f,
                0x9a252adfd2e233f8,
                0xdb597dc6177708f,
                0x4c41a99d73c66e10,
                0x9a7de725883ee745,
                0x1170afd6d79f3f6c,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x7cea423ebaab3f75,
                0x6895c91b6904a0b9,
                0xf71a2d2f8540d37,
                0x5d31d43751362955,
                0x5cb6cc5356a28321,
                0xec7c797620760bc,
            ]))
            .unwrap(),
        };
        let t = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xc47eff163740492e,
                0x2522abf70b7f729,
                0x55d9af6104e70a53,
                0x8fb1dfc0298e88fb,
                0x8138ecaf073524d9,
                0x14f6b3bca27212ba,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0xd9724aa60d690d0a,
                0x429169ff2abc6354,
                0x81cd47b3f4b5ea6f,
                0x8c3fc71cc6af614b,
                0x984cb7319b57a8cc,
                0x12e39dc6f1ca3087,
            ]))
            .unwrap(),
        };
        assert_eq!(iso_map_g2(x, y, z), (u, v, t));
    }

    #[bench]
    fn bench_iso_map_g2(b: &mut Bencher) {
        let x = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x55a091c116cfafec,
                0x1a8d084061f04b99,
                0x8ff19ef620afd26f,
                0xba1252b819253f92,
                0x7f8ea67f60712cc3,
                0x1e9a3131bb55f13,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x639ba6be5220b0cb,
                0x69dbae9f8a68e7c5,
                0x38e14220784c21e4,
                0x781d902f1772e0f0,
                0xfac94978cd96dfcd,
                0x10c92d781a75e23b,
            ]))
            .unwrap(),
        };
        let y = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0x370b04ae17a905d9,
                0x4b5f39b364f368fa,
                0xa7dc43948e2346c6,
                0xd764f3f805e0d730,
                0x46e2cdb8572e1347,
                0x177d09ec6a5b8773,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x627b0c2a4a691f55,
                0x3694594abb285e97,
                0xeb96a2f04895a020,
                0xeadf79169bd7450b,
                0xc264902e69a7a3bd,
                0xea59f3076192825,
            ]))
            .unwrap(),
        };
        let z = Fq2 {
            c0: Fq::from_repr(FqRepr([
                0xf289cff1b322ac8e,
                0xe2a1cfba96cc7a52,
                0x7b11839416e051e,
                0xcacfd747207dda6b,
                0xb90b3c901f15a7e6,
                0x14c269a66651834e,
            ]))
            .unwrap(),
            c1: Fq::from_repr(FqRepr([
                0x87865c9aee66d3b3,
                0xebfa3d1313c9d13c,
                0x60f61b13897b5cdf,
                0xc2ec19c20589147,
                0xd4e9711aaf11e52a,
                0x150deee2cd71e942,
            ]))
            .unwrap(),
        };
        b.iter(|| iso_map_g2(x, y, z));
    }
}
