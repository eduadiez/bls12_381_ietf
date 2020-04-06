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
    fn keygen(ikm: &[u8]) -> (Self::BLSPublicKey, Self::BLSSecretKey);
    fn key_validate(
        secret_key: Self::BLSPublicKey,
    ) -> Result<<Self as pairing::Engine>::G1Affine, pairing::GroupDecodingError>;
    fn core_sign(
        secret_key: Self::BLSSecretKey,
        message: &[u8],
        dst: &'static str,
    ) -> Self::BLSSignature;
    fn core_verify(
        public_key: &Self::BLSPublicKey,
        message: &[u8],
        signature: &Self::BLSSignature,
        dst: &'static str,
    ) -> Result<bool, ()>;
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

    fn keygen(ikm: &[u8]) -> (Self::BLSPublicKey, Self::BLSSecretKey) {
        let (_, hk) = Hkdf::<Sha256>::extract(Some(SALT.as_bytes()), &ikm);
        let mut okm = [0u8; L];
        hk.expand(&[], &mut okm)
            .expect("L is a valid length for Sha256 to output");
        let b = BigUint::from_bytes_be(&okm[..]);
        let sk = Fr::from_str(&b.to_str_radix(10)).expect("A Fr valid point");
        (Self::sk_to_pk(sk), sk)
    }

    fn key_validate(public_key: Self::BLSPublicKey) -> Result<Self::G1Affine, GroupDecodingError> {
        public_key.into_affine()
    }

    fn core_sign(
        secret_key: Self::BLSSecretKey,
        message: &[u8],
        dst: &'static str,
    ) -> Self::BLSSignature {
        let message_point = hash_to_g2(message, dst.as_bytes()).into_affine();
        let sig = message_point.mul(secret_key).into_affine();
        sig.into_compressed()
    }

    fn core_verify(
        public_key: &Self::BLSPublicKey,
        message: &[u8],
        signature: &Self::BLSSignature,
        dst: &'static str,
    ) -> Result<bool, ()> {
        let message_point = hash_to_g2(message, dst.as_bytes()).into_affine();
        let mut pk_neg = public_key
            .into_affine()
            .expect("Convert the public key into its affine");
        pk_neg.negate();
        let pairing_1 = Bls12::pairing(pk_neg, message_point);

        let signature_affine = signature
            .into_affine()
            .expect("Convert the signature into its affine");
        let pairing_2 = Bls12::pairing(G1Affine::one(), signature_affine);

        let mut result = pairing_1;
        result.mul_assign(&pairing_2);

        if result == Fq12::one() {
            Ok(true)
        } else {
            Err(())
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
    ) -> Result<bool, ()>;
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
    ) -> Result<bool, ()> {
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
    ) -> Result<bool, ()>;
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
    ) -> Result<bool, ()> {
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
    use pairing::bls12_381::Fr;
    use pairing::bls12_381::G2Uncompressed;
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

        let mut result: G2Uncompressed = G2Uncompressed::empty();

        result.as_mut().copy_from_slice(&[
            7, 96, 184, 59, 252, 155, 121, 217, 191, 182, 127, 56, 91, 135, 141, 250, 234, 157, 32,
            129, 205, 114, 85, 166, 106, 8, 225, 6, 190, 18, 27, 86, 160, 113, 22, 122, 230, 185,
            18, 184, 72, 197, 172, 121, 142, 53, 98, 51, 22, 10, 82, 221, 165, 122, 100, 137, 81,
            246, 140, 206, 207, 223, 199, 111, 129, 121, 149, 141, 159, 251, 190, 15, 96, 16, 95,
            169, 34, 112, 240, 62, 246, 116, 3, 71, 124, 100, 202, 84, 240, 130, 126, 15, 240, 234,
            78, 90, 2, 170, 62, 50, 25, 69, 10, 150, 177, 0, 239, 87, 169, 32, 140, 243, 199, 189,
            238, 143, 81, 223, 111, 213, 210, 126, 234, 34, 231, 26, 110, 152, 86, 14, 223, 142,
            17, 105, 44, 54, 182, 146, 149, 131, 205, 53, 80, 244, 19, 250, 174, 168, 48, 158, 34,
            180, 195, 107, 13, 155, 115, 69, 107, 232, 29, 238, 190, 148, 233, 218, 196, 9, 247,
            114, 233, 144, 67, 7, 141, 83, 231, 201, 34, 3, 117, 48, 1, 78, 61, 159, 129, 197, 25,
            252, 17, 185,
        ]);
        //result:

        assert_eq!(
            hash_to_g2(&message[..], &dst).into_affine(),
            result.into_affine().unwrap()
        );
        // edu@dappnode.io
        let message = [
            101, 100, 117, 64, 100, 97, 112, 112, 110, 111, 100, 101, 46, 105, 111,
        ];
        let mut result: G2Uncompressed = G2Uncompressed::empty();

        result.as_mut().copy_from_slice(&[
            8, 237, 200, 132, 117, 175, 8, 50, 2, 216, 170, 222, 112, 205, 78, 23, 91, 3, 237, 243,
            53, 125, 118, 94, 215, 186, 2, 79, 72, 87, 116, 115, 216, 9, 160, 211, 98, 48, 47, 154,
            196, 42, 186, 87, 147, 38, 67, 22, 7, 132, 148, 14, 174, 111, 17, 249, 225, 90, 215,
            93, 147, 19, 148, 130, 78, 154, 55, 17, 34, 103, 82, 125, 34, 53, 92, 88, 91, 67, 225,
            45, 210, 164, 52, 202, 23, 187, 75, 152, 133, 86, 93, 144, 172, 75, 68, 187, 24, 113,
            53, 30, 125, 107, 18, 112, 163, 167, 128, 202, 16, 118, 145, 31, 72, 105, 219, 250,
            210, 219, 189, 117, 185, 195, 45, 41, 196, 253, 230, 178, 100, 97, 112, 92, 237, 71,
            250, 45, 53, 160, 144, 92, 149, 154, 240, 50, 1, 156, 150, 115, 125, 207, 180, 207,
            195, 92, 144, 235, 121, 236, 15, 173, 209, 65, 68, 44, 179, 141, 234, 163, 110, 10,
            227, 232, 248, 9, 10, 238, 70, 222, 102, 129, 194, 165, 61, 49, 225, 225, 46, 198, 60,
            229, 16, 5,
        ]);

        assert_eq!(
            hash_to_g2(&message[..], &dst).into_affine(),
            result.into_affine().unwrap()
        );
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
