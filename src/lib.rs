#![feature(test)]
extern crate test;

extern crate hex;
extern crate pairing;

mod constants;
mod hash_to_curve;
mod optimized_swu;

use crate::constants::{L, SALT};
use crate::pairing::ff::PrimeField;
use hash_to_curve::hash_to_g2;
use hkdf::Hkdf;
use num_bigint::BigUint;
use pairing::bls12_381::{Bls12, Fq12, Fr, G1Affine, G1Compressed, G2Compressed};
use pairing::ff::Field;
use pairing::{CurveAffine, CurveProjective, EncodedPoint, Engine, GroupDecodingError};
use sha2::Sha256;

pub trait BaseG2Ciphersuite: Engine {
    const DST: &'static str;

    type BLSPublicKey;
    type BLSSecretKey;
    type BLSSignature;
    type Fq2;

    fn sk_to_pk(secret_key: Self::BLSSecretKey) -> Self::BLSPublicKey;
    fn keygen<T: AsRef<[u8]>>(ikm: T) -> (Self::BLSPublicKey, Self::BLSSecretKey);
    fn key_validate(
        secret_key: Self::BLSPublicKey,
    ) -> Result<<Self as pairing::Engine>::G1Affine, pairing::GroupDecodingError>;
    fn core_sign<T: AsRef<[u8]>>(
        secret_key: Self::BLSSecretKey,
        message: T,
        dst: &'static str,
    ) -> Self::BLSSignature;
    fn core_verify<T: AsRef<[u8]>>(
        public_key: &Self::BLSPublicKey,
        message: T,
        signature: &Self::BLSSignature,
        dst: &'static str,
    ) -> Result<bool, GroupDecodingError>;
}

impl BaseG2Ciphersuite for Bls12 {
    const DST: &'static str = "";
    type BLSSecretKey = Self::Fr;
    type BLSPublicKey = G1Compressed;
    type BLSSignature = G2Compressed;
    type Fq2 = Self::Fqe;

    fn sk_to_pk(secret_key: Self::BLSSecretKey) -> Self::BLSPublicKey {
        G1Compressed::from_affine(G1Affine::one().mul(secret_key).into_affine())
    }

    fn keygen<T: AsRef<[u8]>>(ikm: T) -> (Self::BLSPublicKey, Self::BLSSecretKey) {
        let (_, hk) = Hkdf::<Sha256>::extract(Some(SALT.as_bytes()), ikm.as_ref());
        let mut okm = [0u8; L];
        hk.expand(&[], &mut okm)
            .expect("L is a valid length for Sha256 to output");
        let b = BigUint::from_bytes_be(&okm[..]);
        let sk = Fr::from_str(&b.to_str_radix(10)).unwrap();
        (Self::sk_to_pk(sk), sk)
    }

    fn key_validate(public_key: Self::BLSPublicKey) -> Result<Self::G1Affine, GroupDecodingError> {
        public_key.into_affine()
    }

    fn core_sign<T: AsRef<[u8]>>(
        secret_key: Self::BLSSecretKey,
        message: T,
        dst: &'static str,
    ) -> Self::BLSSignature {
        let message_point = hash_to_g2(message.as_ref(), dst.as_bytes()).into_affine();
        let sig = message_point.mul(secret_key).into_affine();
        sig.into_compressed()
    }

    fn core_verify<T: AsRef<[u8]>>(
        public_key: &Self::BLSPublicKey,
        message: T,
        signature: &Self::BLSSignature,
        dst: &'static str,
    ) -> Result<bool, GroupDecodingError> {
        let message_point = hash_to_g2(message.as_ref(), dst.as_bytes()).into_affine();
        let mut pk_neg = public_key.into_affine()?;
        pk_neg.negate();
        let pairing_1 = Bls12::pairing(pk_neg, message_point);

        let signature_affine = signature.into_affine()?;
        let pairing_2 = Bls12::pairing(G1Affine::one(), signature_affine);

        let mut result = pairing_1;
        result.mul_assign(&pairing_2);

        if result == Fq12::one() {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

pub trait G2Basic: BaseG2Ciphersuite {
    const DST: &'static str;
    fn sign(secret_key: Self::BLSSecretKey, message: &[u8]) -> Self::BLSSignature;
    fn verify(
        public_key: &Self::BLSPublicKey,
        message: &[u8],
        signature: &Self::BLSSignature,
    ) -> Result<bool, GroupDecodingError>;
}

impl G2Basic for Bls12 {
    const DST: &'static str = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_NUL_";
    fn sign(secret_key: Self::BLSSecretKey, message: &[u8]) -> Self::BLSSignature {
        Self::core_sign(secret_key, message, <Self as G2Basic>::DST)
    }
    fn verify(
        public_key: &Self::BLSPublicKey,
        message: &[u8],
        signature: &Self::BLSSignature,
    ) -> Result<bool, GroupDecodingError> {
        Self::core_verify(public_key, message, signature, <Self as G2Basic>::DST)
    }
}

pub trait G2MessageAugmentation: BaseG2Ciphersuite {
    const DST: &'static str;
    fn sign(secret_key: Self::BLSSecretKey, message: &[u8]) -> Self::BLSSignature;
    fn verify(
        public_key: &Self::BLSPublicKey,
        message: &[u8],
        signature: &Self::BLSSignature,
    ) -> Result<bool, GroupDecodingError>;
}

impl G2MessageAugmentation for Bls12 {
    const DST: &'static str = "BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_AUG_";
    fn sign(secret_key: Self::BLSSecretKey, message: &[u8]) -> Self::BLSSignature {
        let pk = Self::sk_to_pk(secret_key);
        let augmented_message = [pk.as_ref(), message].concat();
        Self::core_sign(
            secret_key,
            &augmented_message[..],
            <Self as G2MessageAugmentation>::DST,
        )
    }
    fn verify(
        public_key: &Self::BLSPublicKey,
        message: &[u8],
        signature: &Self::BLSSignature,
    ) -> Result<bool, GroupDecodingError> {
        let augmented_message = [public_key.as_ref(), message].concat();
        Self::core_verify(
            public_key,
            &augmented_message,
            signature,
            <Self as G2MessageAugmentation>::DST,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pairing::bls12_381::Bls12;
    use pairing::bls12_381::Fq2;
    use pairing::bls12_381::Fq;
    use pairing::bls12_381::FqRepr;
    use pairing::bls12_381::Fr;
    use pairing::bls12_381::G2Affine;
    use pairing::ff::PrimeField;
    use test::Bencher;

    #[test]
    fn test_keygen() {
        let (pk, sk) = Bls12::keygen(b"edu");
        let res_pk = [
            138, 58, 168, 150, 94, 218, 53, 78, 97, 36, 99, 248, 47, 204, 52, 231, 51, 134, 143,
            162, 76, 76, 81, 121, 192, 32, 125, 53, 115, 34, 198, 103, 197, 155, 141, 121, 160, 99,
            200, 222, 213, 1, 150, 80, 152, 29, 195, 29,
        ];
        let res_sk = [
            0x704540e43a495e37,
            0xedd0ee81a783e073,
            0x918acabb2d1c50e7,
            0x46229f89c6de24b9,
        ];
        assert_eq!(pk.as_ref(), &res_pk[..]);
        assert_eq!(sk.into_repr().as_ref(), res_sk);
    }

    #[bench]
    fn bench_keygen(b: &mut Bencher) {
        b.iter(|| Bls12::keygen(b"edu"));
    }

    #[test]
    fn test_priv_to_pub() {
        let a = Bls12::sk_to_pk(Fr::from_str("3333").unwrap());
        let b = [
            139, 177, 173, 23, 202, 119, 7, 138, 80, 14, 240, 120, 12, 60, 58, 95, 13, 194, 98,
            144, 176, 191, 178, 29, 44, 118, 241, 168, 39, 190, 216, 118, 77, 127, 50, 51, 45, 194,
            219, 48, 132, 177, 250, 234, 41, 19, 78, 167,
        ];
        assert_eq!(a.as_ref(), &b[..]);
    }

    #[bench]
    fn bench_test_priv_to_pub(b: &mut Bencher) {
        let pk = Fr::from_str("3333").unwrap();
        b.iter(|| Bls12::sk_to_pk(pk));
    }

    #[test]
    fn test_hash_to_g2() {
        // Hello!
        let message = [72, 101, 108, 108, 111, 33];
        // BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_NUL_
        let dst = [
            66, 76, 83, 95, 83, 73, 71, 95, 66, 76, 83, 49, 50, 51, 56, 49, 71, 50, 45, 83, 72, 65,
            50, 53, 54, 45, 83, 83, 87, 85, 45, 82, 79, 45, 95, 78, 85, 76, 95,
        ];

        let result = G2Affine::from_xy_unchecked(
            Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0xf0827e0ff0ea4e5a,
                    0xf67403477c64ca54,
                    0x60105fa92270f03e,
                    0x8179958d9ffbbe0f,
                    0x51f68ccecfdfc76f,
                    0x160a52dda57a6489,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x48c5ac798e356233,
                    0xa071167ae6b912b8,
                    0x6a08e106be121b56,
                    0xea9d2081cd7255a6,
                    0xbfb67f385b878dfa,
                    0x760b83bfc9b79d9,
                ]))
                .unwrap(),
            },
            Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x3d9f81c519fc11b9,
                    0xe7c922037530014e,
                    0xf772e99043078d53,
                    0x1deebe94e9dac409,
                    0xc36b0d9b73456be8,
                    0x13faaea8309e22b4,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0xb6929583cd3550f4,
                    0x560edf8e11692c36,
                    0xd27eea22e71a6e98,
                    0xc7bdee8f51df6fd5,
                    0xb100ef57a9208cf3,
                    0x2aa3e3219450a96,
                ]))
                .unwrap(),
            },
        );
        assert_eq!(hash_to_g2(&message[..], &dst).into_affine(), result);
        // edu@dappnode.io
        let message = [
            101, 100, 117, 64, 100, 97, 112, 112, 110, 111, 100, 101, 46, 105, 111,
        ];
        let result = G2Affine::from_xy_unchecked(
            Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0x85565d90ac4b44bb,
                    0xd2a434ca17bb4b98,
                    0x22355c585b43e12d,
                    0x4e9a37112267527d,
                    0xe15ad75d93139482,
                    0x784940eae6f11f9,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0xc42aba5793264316,
                    0xd809a0d362302f9a,
                    0xd7ba024f48577473,
                    0x5b03edf3357d765e,
                    0x2d8aade70cd4e17,
                    0x8edc88475af0832,
                ]))
                .unwrap(),
            },
            Fq2 {
                c0: Fq::from_repr(FqRepr([
                    0xe1e12ec63ce51005,
                    0x46de6681c2a53d31,
                    0x6e0ae3e8f8090aee,
                    0xd141442cb38deaa3,
                    0xc35c90eb79ec0fad,
                    0x19c96737dcfb4cf,
                ]))
                .unwrap(),
                c1: Fq::from_repr(FqRepr([
                    0x35a0905c959af032,
                    0x6461705ced47fa2d,
                    0xb9c32d29c4fde6b2,
                    0x4869dbfad2dbbd75,
                    0xa3a780ca1076911f,
                    0x1871351e7d6b1270,
                ]))
                .unwrap(),
            },
        );
        assert_eq!(hash_to_g2(&message[..], &dst).into_affine(), result);
    }

    #[bench]
    fn bench_hash_to_g2(b: &mut Bencher) {
        // BLS_SIG_BLS12381G2-SHA256-SSWU-RO-_NUL_
        let dst = [
            66, 76, 83, 95, 83, 73, 71, 95, 66, 76, 83, 49, 50, 51, 56, 49, 71, 50, 45, 83, 72, 65,
            50, 53, 54, 45, 83, 83, 87, 85, 45, 82, 79, 45, 95, 78, 85, 76, 95,
        ];
        // edu@dappnode.io
        let message = [
            101, 100, 117, 64, 100, 97, 112, 112, 110, 111, 100, 101, 46, 105, 111,
        ];
        b.iter(|| hash_to_g2(&message[..], &dst));
    }

    #[test]
    fn test_sign_g2basic() {
        let result = [
            129, 227, 155, 111, 126, 207, 212, 203, 144, 185, 29, 177, 233, 195, 100, 19, 169, 2,
            255, 253, 35, 240, 213, 62, 74, 68, 143, 149, 28, 203, 73, 80, 82, 75, 88, 241, 210,
            58, 30, 172, 17, 62, 17, 121, 10, 192, 5, 235, 13, 136, 242, 156, 250, 176, 159, 122,
            133, 89, 36, 105, 87, 109, 98, 87, 36, 212, 227, 208, 97, 241, 244, 69, 37, 93, 123,
            141, 173, 5, 163, 124, 223, 96, 56, 86, 223, 142, 83, 25, 40, 205, 141, 171, 53, 97,
            244, 149,
        ];
        let sk = Fr::from_str("3333").unwrap();
        assert_eq!(
            <Bls12 as G2Basic>::sign(sk, b"edu@dappnode.io").as_ref(),
            &result[..]
        );
    }

    #[bench]
    fn bench_sign_g2basic(b: &mut Bencher) {
        let sk = Fr::from_str("3333").unwrap();
        b.iter(|| <Bls12 as G2Basic>::sign(sk, b"edu@dappnode.io"));
    }

    #[test]
    fn test_sign_g2_message_augmentation() {
        let result = [
            152, 112, 73, 150, 76, 45, 12, 146, 180, 42, 173, 215, 209, 124, 171, 95, 249, 133,
            149, 54, 210, 139, 225, 49, 18, 9, 25, 108, 181, 63, 246, 41, 224, 95, 17, 199, 107,
            84, 153, 41, 50, 190, 196, 243, 74, 48, 65, 204, 25, 143, 45, 80, 103, 103, 168, 242,
            143, 77, 191, 109, 70, 140, 152, 195, 134, 187, 100, 247, 203, 162, 79, 252, 153, 138,
            110, 128, 6, 128, 60, 193, 233, 221, 170, 195, 165, 152, 61, 8, 22, 222, 208, 67, 24,
            8, 195, 117,
        ];
        let sk = Fr::from_str("3333").unwrap();
        assert_eq!(
            <Bls12 as G2MessageAugmentation>::sign(sk, b"edu@dappnode.io").as_ref(),
            &result[..]
        );
    }

    #[bench]
    fn bench_sign_g2_message_augmentation(b: &mut Bencher) {
        let sk = Fr::from_str("3333").unwrap();
        b.iter(|| <Bls12 as G2MessageAugmentation>::sign(sk, b"edu@dappnode.io"));
    }

    #[test]
    fn test_verify_g2basic() {
        const SK: &'static str = "3333";
        const MESSAGE: &'static str = "edu@dappnode.io!!!";
        let pk = Bls12::sk_to_pk(Fr::from_str(SK).unwrap());
        let signature = <Bls12 as G2Basic>::sign(Fr::from_str(SK).unwrap(), MESSAGE.as_bytes());

        assert!((<Bls12 as G2Basic>::verify(&pk, MESSAGE.as_bytes(), &signature)).unwrap());
    }
    #[test]
    #[should_panic]
    fn test_verify_g2basic_panic() {
        const SK: &'static str = "3333";
        const MESSAGE: &'static str = "edu@dappnode.io!!!";
        let pk = Bls12::sk_to_pk(Fr::from_str(SK).unwrap());
        let signature = hex::decode("7d1ecc51bdbf1f7b6e714c8b2195e6ef039f651186d9fe22930791444be6dccef26fe90df82bd0feb9cddabf7ff5d550ed2ba9c8fd1399b3b3248288b2d011e5d5aa94d98fb543324a92a9d49c172cfaea5611a2deb923653643b7603d006c8").unwrap();
        let mut sign = G2Compressed::empty();
        let sign_mut = sign.as_mut();
        sign_mut.clone_from_slice(&signature[..]);
        <Bls12 as G2Basic>::verify(&pk, MESSAGE.as_bytes(), &sign).unwrap();
    }

    #[bench]
    fn bench_verify_g2basic(b: &mut Bencher) {
        const SK: &'static str = "3333";
        const MESSAGE: &'static str = "edu@dappnode.io!!!";
        let pk = Bls12::sk_to_pk(Fr::from_str(SK).unwrap());
        let signature = <Bls12 as G2Basic>::sign(Fr::from_str(SK).unwrap(), MESSAGE.as_bytes());
        b.iter(|| <Bls12 as G2Basic>::verify(&pk, MESSAGE.as_bytes(), &signature));
    }
    #[test]
    fn test_verify_g2_message_augmentation() {
        const SK: &'static str = "3333";
        const MESSAGE: &'static str = "edu@dappnode.io!!!";
        let pk = Bls12::sk_to_pk(Fr::from_str(SK).unwrap());
        let signature =
            <Bls12 as G2MessageAugmentation>::sign(Fr::from_str(SK).unwrap(), MESSAGE.as_bytes());
        assert!(
            (<Bls12 as G2MessageAugmentation>::verify(&pk, MESSAGE.as_bytes(), &signature))
                .unwrap()
        );
    }
    #[test]
    #[should_panic]
    fn test_verify_g2_message_augmentation_panic() {
        const SK: &'static str = "3333";
        const MESSAGE: &'static str = "edu@dappnode.io!!!";
        let pk = Bls12::sk_to_pk(Fr::from_str(SK).unwrap());
        let signature = hex::decode("7d1ecc51bdbf1f7b6e714c8b2195e6ef039f651186d9fe22930791444be6dccef26fe90df82bd0feb9cddabf7ff5d550ed2ba9c8fd1399b3b3248288b2d011e5d5aa94d98fb543324a92a9d49c172cfaea5611a2deb923653643b7603d006c8").unwrap();
        let mut sign = G2Compressed::empty();
        let sign_mut = sign.as_mut();
        sign_mut.clone_from_slice(&signature[..]);
        <Bls12 as G2MessageAugmentation>::verify(&pk, MESSAGE.as_bytes(), &sign).unwrap();
    }

    #[bench]
    fn bench_verify_g2_message_augmentation(b: &mut Bencher) {
        const SK: &'static str = "3333";
        const MESSAGE: &'static str = "edu@dappnode.io!!!";
        let pk = Bls12::sk_to_pk(Fr::from_str(SK).unwrap());
        let signature =
            <Bls12 as G2MessageAugmentation>::sign(Fr::from_str(SK).unwrap(), MESSAGE.as_bytes());
        b.iter(|| <Bls12 as G2MessageAugmentation>::verify(&pk, MESSAGE.as_bytes(), &signature));
    }
}
