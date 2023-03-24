use bellman::{
    groth16, Circuit, ConstraintSystem, SynthesisError,
};
use bls12_381::Bls12;
use ff::{Field, PrimeField};
use pairing::Engine;
use rand::rngs::OsRng;
use bls12_381::Scalar;
use bls12_381::G1Affine;
use pairing::group::Curve;

pub struct SecretKey{
    pub sk: Scalar
}

pub struct PublicKey{
    pub pk: G1Affine
}

impl SecretKey {
    pub fn generate_sk() -> Self{
        Self{
            sk: Scalar::random(&mut OsRng)
        }
    }
}

impl PublicKey {
    pub fn from_sk(sk:SecretKey) -> Self{
        Self{
            pk: (G1Affine::generator() * sk.sk).to_affine()
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
pub struct Ownership<'a, S: PrimeField> {
    pub sk: Option<S>,
    pub pk: Option<PublicKey>,
}

#[test]
pub fn test(){

}