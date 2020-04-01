use bls12_381_ietf::{BaseG2Ciphersuite, G2MessageAugmentation};
use pairing::bls12_381::{Bls12, Fr};
use pairing::ff::PrimeField;
use pairing::CurveAffine;

const SK: &'static str = "3333";
const MESSAGE: &'static str = "edu@dappnode.io!!!";


pub fn main() {
    let pk = Bls12::sk_to_pk(Fr::from_str(SK).unwrap());
    match Bls12::key_validate(pk) {
        Ok(pk) => println!("Public Key:\t{}", hex::encode(pk.into_compressed())),
        Err(e) => panic!(e),
    }

    println!("Message:\t{}", MESSAGE);
    let signature = Bls12::sign(Fr::from_str(SK).unwrap(), MESSAGE.as_bytes());
    println!("Signature:\t{}", hex::encode(signature));    


    match Bls12::verify(&pk, MESSAGE.as_bytes(),&signature) {
        Ok(_) => println!("Signature verified correctly!"),
        Err(_) => println!("Signature NOT valid!"),
    }

}
