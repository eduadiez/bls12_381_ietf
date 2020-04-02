use bls12_381_ietf::{BaseG2Ciphersuite, G2Basic};
use pairing::bls12_381::Bls12;
use pairing::CurveAffine;

const IKM: &'static str = "3333";
const MESSAGE: &'static str = "edu@dappnode.io";

pub fn main() {
    let (pk, sk) = Bls12::keygen(IKM.as_bytes());
    match Bls12::key_validate(pk) {
        Ok(pk) => println!("Public Key:\t{}", hex::encode(pk.into_compressed())),
        Err(e) => panic!(e),
    }

    println!("Message:\t{}", MESSAGE);
    let signature = Bls12::sign(sk, MESSAGE.as_bytes());
    println!("Signature:\t{}", hex::encode(signature));

    match Bls12::verify(&pk, MESSAGE.as_bytes(), &signature) {
        Ok(_) => println!("Signature verified correctly!"),
        Err(_) => println!("Signature NOT valid!"),
    }
}
