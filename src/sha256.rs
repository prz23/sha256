use bellman::{
    gadgets::{
        boolean::{AllocatedBit, Boolean},
        multipack,
        sha256::sha256,
    },
    groth16, Circuit, ConstraintSystem, SynthesisError,
};
use bls12_381::Bls12;
use ff::PrimeField;
use pairing::Engine;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

fn sha256_only<Scalar: PrimeField, CS: ConstraintSystem<Scalar>>(
    mut cs: CS,
    data: &[Boolean],
) -> Result<Vec<Boolean>, SynthesisError> {
    // Flip endianness of each input byte
    let input: Vec<_> = data
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect();

    let res = sha256(cs.namespace(|| "SHA-256(input)"), &input)?;

    // Flip endianness of each output byte
    Ok(res
        .chunks(8)
        .map(|c| c.iter().rev())
        .flatten()
        .cloned()
        .collect())
}

struct Sha256Circuit {
    preimage: Option<[u8; 160]>,
}

impl<Scalar: PrimeField> Circuit<Scalar> for Sha256Circuit {
    fn synthesize<CS: ConstraintSystem<Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let bit_values = if let Some(preimage) = self.preimage {
            preimage
                .into_iter()
                .map(|byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8))
                .flatten()
                .map(|b| Some(b))
                .collect()
        } else {
            vec![None; 160 * 8]
        };
        assert_eq!(bit_values.len(), 160 * 8);

        let preimage_bits = bit_values
            .into_iter()
            .enumerate()
            // Allocate each bit.
            .map(|(i, b)| {
                AllocatedBit::alloc(cs.namespace(|| format!("preimage bit {}", i)), b)
            })
            .map(|b| b.map(Boolean::from))
            .collect::<Result<Vec<_>, _>>()?;

        let hash = sha256_only(cs.namespace(|| "SHA-256(preimage)"), &preimage_bits)?;

        multipack::pack_into_inputs(cs.namespace(|| "pack hash"), &hash)
    }
}

#[test]
pub fn test(){
    let params = {
        let c = Sha256Circuit { preimage: None };
        groth16::generate_random_parameters::<Bls12, _, _>(c, &mut OsRng).unwrap()
    };

    let pvk = groth16::prepare_verifying_key(&params.vk);

    let preimage = [52; 160];
    let hash = Sha256::digest(&preimage);

    let c = Sha256Circuit {
        preimage: Some(preimage),
    };

    let proof = groth16::create_random_proof(c, &params, &mut OsRng).unwrap();

    let hash_bits = multipack::bytes_to_bits_le(&hash);
    let inputs = multipack::compute_multipacking(&hash_bits);

    assert!(groth16::verify_proof(&pvk, &proof, &inputs).is_ok());
}