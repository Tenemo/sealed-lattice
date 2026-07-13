use super::*;
use crate::bgv::parameters::PLAINTEXT_MODULUS;

pub(crate) fn decryption_accumulator_to_coefficients(
    ciphertext: &Ciphertext,
    accumulator: &[Vec<u64>],
) -> CanonicalResult<Vec<u64>> {
    let primes = ciphertext.primes();
    if accumulator.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "BGV decryption accumulator must have one limb per active data prime",
        ));
    }
    for (limb_index, (limb, modulus)) in accumulator.iter().zip(primes.iter()).enumerate() {
        if limb.len() != POLYNOMIAL_DEGREE {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                format!(
                    "BGV decryption accumulator limb {limb_index} has the wrong coefficient count"
                ),
            ));
        }
        if limb.iter().any(|coefficient| *coefficient >= *modulus) {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!("BGV decryption accumulator limb {limb_index} has non-canonical residues"),
            ));
        }
    }

    let crt = CrtContext::new(primes);
    let scaling = ciphertext.decrypt_scaling;
    let mut message_coefficients = Vec::with_capacity(POLYNOMIAL_DEGREE);
    for coefficient_index in 0..POLYNOMIAL_DEGREE {
        let residues = accumulator
            .iter()
            .map(|limb| limb[coefficient_index])
            .collect::<Vec<_>>();
        let centered_mod_plaintext = crt.center_then_reduce_mod_plaintext(&residues);
        message_coefficients.push(mul_mod(centered_mod_plaintext, scaling, PLAINTEXT_MODULUS)?);
    }

    Ok(message_coefficients)
}

struct CrtContext {
    modulus: BigInt,
    half_modulus: BigInt,
    factors: Vec<BigInt>,
    plaintext_modulus: BigInt,
}

impl CrtContext {
    fn new(primes: &[u64]) -> Self {
        let modulus: BigInt = primes.iter().map(|prime| BigInt::from(*prime)).product();
        let factors = primes
            .iter()
            .map(|prime| {
                let prime_big = BigInt::from(*prime);
                let cofactor = &modulus / &prime_big;
                let cofactor_mod = (&cofactor % &prime_big)
                    .to_u64()
                    .expect("cofactor residue below the prime fits u64");
                let inverse =
                    inverse_mod(cofactor_mod, *prime).expect("cofactor is coprime to its prime");
                (&cofactor * BigInt::from(inverse)) % &modulus
            })
            .collect::<Vec<_>>();
        let half_modulus = &modulus / 2;

        Self {
            modulus,
            half_modulus,
            factors,
            plaintext_modulus: BigInt::from(PLAINTEXT_MODULUS),
        }
    }

    fn center_then_reduce_mod_plaintext(&self, residues: &[u64]) -> u64 {
        let mut accumulator = BigInt::zero();
        for (residue, factor) in residues.iter().zip(self.factors.iter()) {
            accumulator += BigInt::from(*residue) * factor;
        }
        accumulator %= &self.modulus;
        if accumulator > self.half_modulus {
            accumulator -= &self.modulus;
        }
        let reduced = ((accumulator % &self.plaintext_modulus) + &self.plaintext_modulus)
            % &self.plaintext_modulus;

        reduced.to_u64().expect("plaintext residue fits u64")
    }
}
