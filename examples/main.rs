use bls12_381_ietf::{BaseG2Ciphersuite, G2MessageAugmentation};
use pairing::bls12_381::{Bls12, Fr};
use pairing::ff::PrimeField;

pub fn main() {
    let a = Bls12::sk_to_pk(Fr::from_str("3333").unwrap());
    Bls12::key_validate(a).unwrap();
    let signature = Bls12::sign(Fr::from_str("3333").unwrap(), b"edu@dappnode.io");
    println!("sign: {:?}", signature);
}
