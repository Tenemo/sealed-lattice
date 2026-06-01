use crate::{
    bgv::{
        evaluator::{
            engine::{Ciphertext, DevelopmentBgvKey, negacyclic_mul, signed_residue},
            prg::DeterministicSampler,
        },
        modular_arithmetic::{add_mod, add_mod_fast, mul_mod_fast, sub_mod},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
        profile::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;

const PLAINTEXT_MODULUS_I64: i64 = 65_537;
pub(crate) const KEY_SWITCH_ERROR_DOMAIN: &str = "sealed-lattice-bgv-evaluator/key-switch-error-v1";
pub(crate) const KEY_SWITCH_SAMPLE_DOMAIN: &str =
    "sealed-lattice-bgv-evaluator/key-switch-sample-v1";

// A polynomial component held as residue vectors, one per active prime.
type LimbMatrix = Vec<Vec<u64>>;

// A leveled RNS key-switching key: for each digit `j` in the active prime set it
// holds an RLWE encryption (under the secret) of `src * gadget_j`, where the
// gadget is the CRT idempotent (one modulo prime j, zero elsewhere). Switching a
// ciphertext term that multiplies `src` re-expresses it as a term that
// multiplies the secret instead, the core of relinearization and rotation.
#[derive(Clone)]
pub(crate) struct KeySwitchKey {
    pub(crate) level: usize,
    pub(crate) components: Vec<KeySwitchComponent>,
}

#[derive(Clone)]
pub(crate) struct KeySwitchComponent {
    pub(crate) component_b: Vec<Vec<u64>>,
    component_b_ntt: Vec<Vec<u64>>,
    component_a_ntt: Vec<Vec<u64>>,
}

impl KeySwitchComponent {
    fn from_coefficients(
        component_b: Vec<Vec<u64>>,
        component_a: Vec<Vec<u64>>,
        primes: &[u64],
    ) -> CanonicalResult<Self> {
        let component_b_ntt = ntt_limbs(&component_b, primes)?;
        let component_a_ntt = ntt_limbs(&component_a, primes)?;

        Ok(Self {
            component_b,
            component_b_ntt,
            component_a_ntt,
        })
    }
}

fn ntt_limbs(limbs: &[Vec<u64>], primes: &[u64]) -> CanonicalResult<Vec<Vec<u64>>> {
    if limbs.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component limb count does not match its modulus level",
        ));
    }

    limbs
        .iter()
        .zip(primes.iter())
        .map(|(limb, modulus)| forward_negacyclic_ntt(limb, *modulus))
        .collect()
}

fn secret_residues_for_level(secret: &[i64], level: usize) -> Vec<Vec<u64>> {
    DATA_PRIMES[..=level]
        .iter()
        .map(|modulus| {
            secret
                .iter()
                .map(|coefficient| signed_residue(*coefficient, *modulus))
                .collect::<Vec<_>>()
        })
        .collect()
}

// Generate a key-switching key for a source polynomial whose RNS limbs are
// `source_limbs` (one residue vector per active prime), under the development
// secret, at the given modulus level.
fn generate_key_switch_key(
    key: &DevelopmentBgvKey,
    source_limbs: &[Vec<u64>],
    level: usize,
    domain: &str,
    seed_hex: &str,
) -> CanonicalResult<KeySwitchKey> {
    let primes = &DATA_PRIMES[..=level];
    let secret_residues = secret_residues_for_level(key.secret(), level);
    let mut components = Vec::with_capacity(primes.len());
    for (digit_index, source_limb) in source_limbs.iter().enumerate() {
        let digit_bytes = (digit_index as u64).to_le_bytes();
        // One small error polynomial per digit, shared across limbs.
        let error = DeterministicSampler::new(
            KEY_SWITCH_ERROR_DOMAIN,
            &[domain.as_bytes(), seed_hex.as_bytes(), &digit_bytes],
        )
        .centered_binomial_eta2(POLYNOMIAL_DEGREE);
        let mut component_b = Vec::with_capacity(primes.len());
        let mut component_a = Vec::with_capacity(primes.len());
        for (limb_index, modulus) in primes.iter().enumerate() {
            let modulus_bytes = modulus.to_le_bytes();
            let public_sample = DeterministicSampler::new(
                KEY_SWITCH_SAMPLE_DOMAIN,
                &[
                    domain.as_bytes(),
                    seed_hex.as_bytes(),
                    &digit_bytes,
                    &modulus_bytes,
                ],
            )
            .uniform_residues(*modulus, POLYNOMIAL_DEGREE);
            let public_sample_secret_product =
                negacyclic_mul(&public_sample, &secret_residues[limb_index], *modulus)?;
            let limb = (0..POLYNOMIAL_DEGREE)
                .map(|coefficient_index| {
                    let scaled_error =
                        signed_residue(error[coefficient_index] * PLAINTEXT_MODULUS_I64, *modulus);
                    let mut value = sub_mod(
                        scaled_error,
                        public_sample_secret_product[coefficient_index],
                        *modulus,
                    )?;
                    // src * gadget_j contributes src's limb j into component j only.
                    if limb_index == digit_index {
                        value = add_mod(value, source_limb[coefficient_index], *modulus)?;
                    }
                    Ok(value)
                })
                .collect::<CanonicalResult<Vec<_>>>()?;
            component_b.push(limb);
            component_a.push(public_sample);
        }
        components.push(KeySwitchComponent::from_coefficients(
            component_b,
            component_a,
            primes,
        )?);
    }

    Ok(KeySwitchKey { level, components })
}

pub(crate) fn key_switch_key_from_public_component_b(
    level: usize,
    domain: &str,
    seed_hex: &str,
    component_b_by_digit: Vec<Vec<Vec<u64>>>,
) -> CanonicalResult<KeySwitchKey> {
    let primes = DATA_PRIMES.get(..=level).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public key-switch material level is outside the selected data basis",
        )
    })?;
    if component_b_by_digit.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public key-switch material digit count does not match its level",
        ));
    }
    let mut components = Vec::with_capacity(primes.len());
    for (digit_index, component_b) in component_b_by_digit.into_iter().enumerate() {
        if component_b.len() != primes.len()
            || component_b
                .iter()
                .any(|limb| limb.len() != POLYNOMIAL_DEGREE)
        {
            return Err(CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "public key-switch material component shape does not match its level",
            ));
        }
        let digit_bytes = (digit_index as u64).to_le_bytes();
        let mut component_a = Vec::with_capacity(primes.len());
        for modulus in primes {
            let modulus_bytes = modulus.to_le_bytes();
            component_a.push(
                DeterministicSampler::new(
                    KEY_SWITCH_SAMPLE_DOMAIN,
                    &[
                        domain.as_bytes(),
                        seed_hex.as_bytes(),
                        &digit_bytes,
                        &modulus_bytes,
                    ],
                )
                .uniform_residues(*modulus, POLYNOMIAL_DEGREE),
            );
        }
        components.push(KeySwitchComponent::from_coefficients(
            component_b,
            component_a,
            primes,
        )?);
    }

    Ok(KeySwitchKey { level, components })
}

// Apply a key-switching key to a single ciphertext component (the term that
// multiplies the source key), producing the two-component RLWE encryption of
// source * term under the secret.
fn key_switch_component(
    term: &[Vec<u64>],
    key_switch_key: &KeySwitchKey,
) -> CanonicalResult<(LimbMatrix, LimbMatrix)> {
    let primes = &DATA_PRIMES[..=key_switch_key.level];
    if term.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "key-switch term level does not match the key-switching key level",
        ));
    }
    let mut switched_zero = vec![vec![0_u64; POLYNOMIAL_DEGREE]; primes.len()];
    let mut switched_one = vec![vec![0_u64; POLYNOMIAL_DEGREE]; primes.len()];
    #[cfg(not(target_arch = "wasm32"))]
    let partials = key_switch_key
        .components
        .par_iter()
        .enumerate()
        .map(|(digit_index, component)| {
            key_switch_component_digit(term, primes, digit_index, component)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let partials = key_switch_key
        .components
        .iter()
        .enumerate()
        .map(|(digit_index, component)| {
            key_switch_component_digit(term, primes, digit_index, component)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    for (partial_zero, partial_one) in partials {
        add_component_in_place(&mut switched_zero, &partial_zero, key_switch_key.level)?;
        add_component_in_place(&mut switched_one, &partial_one, key_switch_key.level)?;
    }

    Ok((switched_zero, switched_one))
}

fn key_switch_component_digit(
    term: &[Vec<u64>],
    primes: &[u64],
    digit_index: usize,
    component: &KeySwitchComponent,
) -> CanonicalResult<(LimbMatrix, LimbMatrix)> {
    let digit = &term[digit_index];
    let mut switched_zero = vec![vec![0_u64; POLYNOMIAL_DEGREE]; primes.len()];
    let mut switched_one = vec![vec![0_u64; POLYNOMIAL_DEGREE]; primes.len()];
    for (limb_index, modulus) in primes.iter().enumerate() {
        let digit_in_limb = digit
            .iter()
            .map(|value| value % modulus)
            .collect::<Vec<_>>();
        let digit_ntt = forward_negacyclic_ntt(&digit_in_limb, *modulus)?;
        let product_b =
            multiply_ntt_by_ntt(&digit_ntt, &component.component_b_ntt[limb_index], *modulus)?;
        let product_a =
            multiply_ntt_by_ntt(&digit_ntt, &component.component_a_ntt[limb_index], *modulus)?;
        switched_zero[limb_index] = product_b;
        switched_one[limb_index] = product_a;
    }

    Ok((switched_zero, switched_one))
}

fn multiply_ntt_by_ntt(
    left_ntt: &[u64],
    right_ntt: &[u64],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let product_ntt = left_ntt
        .iter()
        .zip(right_ntt.iter())
        .map(|(left_value, right_value)| mul_mod_fast(*left_value, *right_value, modulus))
        .collect::<Vec<_>>();

    inverse_negacyclic_ntt(&product_ntt, modulus)
}

fn add_component_in_place(
    target: &mut [Vec<u64>],
    addend: &[Vec<u64>],
    level: usize,
) -> CanonicalResult<()> {
    for (limb_index, modulus) in DATA_PRIMES[..=level].iter().enumerate() {
        for coefficient_index in 0..POLYNOMIAL_DEGREE {
            target[limb_index][coefficient_index] = add_mod_fast(
                target[limb_index][coefficient_index],
                addend[limb_index][coefficient_index],
                *modulus,
            );
        }
    }

    Ok(())
}

pub(crate) fn generate_relinearization_key(
    key: &DevelopmentBgvKey,
    level: usize,
    seed_hex: &str,
) -> CanonicalResult<KeySwitchKey> {
    // The relinearization source is the squared secret.
    let secret_residues = secret_residues_for_level(key.secret(), level);
    let squared = secret_residues
        .iter()
        .enumerate()
        .map(|(limb_index, limb)| negacyclic_mul(limb, limb, DATA_PRIMES[limb_index]))
        .collect::<CanonicalResult<Vec<_>>>()?;

    generate_key_switch_key(key, &squared, level, "relinearization", seed_hex)
}

pub(crate) fn relinearize(
    ciphertext: &Ciphertext,
    relinearization_key: &KeySwitchKey,
) -> CanonicalResult<Ciphertext> {
    if ciphertext.component_count() != 3 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization requires a three-component ciphertext",
        ));
    }
    if relinearization_key.level != ciphertext.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization key level does not match the ciphertext level",
        ));
    }
    let (switched_zero, switched_one) =
        key_switch_component(&ciphertext.components[2], relinearization_key)?;
    let mut component_zero = ciphertext.components[0].clone();
    let mut component_one = ciphertext.components[1].clone();
    add_component_in_place(&mut component_zero, &switched_zero, ciphertext.level)?;
    add_component_in_place(&mut component_one, &switched_one, ciphertext.level)?;

    Ok(Ciphertext {
        components: vec![component_zero, component_one],
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

// Apply the Galois automorphism X -> X^galois_element to a residue vector. The
// exponent reduces modulo 2N; the upper half wraps with a sign flip because
// X^N = -1 in the ring.
fn automorphism_residues(
    input: &[u64],
    galois_element: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let two_n = 2 * POLYNOMIAL_DEGREE;
    let mut output = vec![0_u64; POLYNOMIAL_DEGREE];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = (coefficient_index * galois_element) % two_n;
        if exponent < POLYNOMIAL_DEGREE {
            output[exponent] = add_mod(output[exponent], *value, modulus)?;
        } else {
            output[exponent - POLYNOMIAL_DEGREE] =
                sub_mod(output[exponent - POLYNOMIAL_DEGREE], *value, modulus)?;
        }
    }

    Ok(output)
}

fn automorphism_signed(input: &[i64], galois_element: usize) -> Vec<i64> {
    let two_n = 2 * POLYNOMIAL_DEGREE;
    let mut output = vec![0_i64; POLYNOMIAL_DEGREE];
    for (coefficient_index, value) in input.iter().enumerate() {
        let exponent = (coefficient_index * galois_element) % two_n;
        if exponent < POLYNOMIAL_DEGREE {
            output[exponent] += value;
        } else {
            output[exponent - POLYNOMIAL_DEGREE] -= value;
        }
    }

    output
}

fn apply_automorphism(
    ciphertext: &Ciphertext,
    galois_element: usize,
) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            component
                .iter()
                .enumerate()
                .map(|(limb_index, limb)| {
                    automorphism_residues(limb, galois_element, primes[limb_index])
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(Ciphertext {
        components,
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

pub(crate) fn generate_galois_key(
    key: &DevelopmentBgvKey,
    galois_element: usize,
    level: usize,
    seed_hex: &str,
) -> CanonicalResult<KeySwitchKey> {
    // The rotation source is the automorphism applied to the secret.
    let rotated_secret = automorphism_signed(key.secret(), galois_element);
    let rotated_secret_limbs = DATA_PRIMES[..=level]
        .iter()
        .map(|modulus| {
            rotated_secret
                .iter()
                .map(|coefficient| signed_residue(*coefficient, *modulus))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let domain = format!("galois-{galois_element}");

    generate_key_switch_key(key, &rotated_secret_limbs, level, &domain, seed_hex)
}

pub(crate) fn rotate(
    ciphertext: &Ciphertext,
    galois_element: usize,
    galois_key: &KeySwitchKey,
) -> CanonicalResult<Ciphertext> {
    if ciphertext.component_count() != 2 {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rotation requires a two-component ciphertext",
        ));
    }
    if galois_key.level != ciphertext.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "rotation key level does not match the ciphertext level",
        ));
    }
    let rotated = apply_automorphism(ciphertext, galois_element)?;
    let (switched_zero, switched_one) = key_switch_component(&rotated.components[1], galois_key)?;
    let mut component_zero = rotated.components[0].clone();
    add_component_in_place(&mut component_zero, &switched_zero, ciphertext.level)?;

    Ok(Ciphertext {
        components: vec![component_zero, switched_one],
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use super::{
        automorphism_residues, generate_galois_key, generate_relinearization_key, relinearize,
        rotate,
    };
    use crate::bgv::{
        evaluator::engine::{
            Ciphertext, DevelopmentBgvKey, ciphertext_tensor, encode_slots_to_coefficients,
            modulus_switch,
        },
        ntt::forward_negacyclic_ntt,
        profile::PLAINTEXT_MODULUS,
    };

    const DEVELOPMENT_SEED: &str = "0011223344556677";
    const TEST_LEVEL: usize = 3;

    fn shared_key() -> &'static DevelopmentBgvKey {
        static KEY: OnceLock<DevelopmentBgvKey> = OnceLock::new();
        KEY.get_or_init(|| {
            DevelopmentBgvKey::generate(DEVELOPMENT_SEED).expect("development key generates")
        })
    }

    fn at_test_level(ciphertext: &Ciphertext) -> Ciphertext {
        let mut current = ciphertext.clone();
        while current.level > TEST_LEVEL {
            current = modulus_switch(&current).expect("modulus switch");
        }
        current
    }

    #[test]
    fn relinearization_recovers_two_component_product() {
        let key = shared_key();
        let left = at_test_level(&key.encrypt_slots(&[2, 3, 4], "ksk01").expect("left"));
        let right = at_test_level(&key.encrypt_slots(&[5, 6, 7], "ksk02").expect("right"));
        let product = ciphertext_tensor(&left, &right).expect("tensor");
        let relinearization_key =
            generate_relinearization_key(key, TEST_LEVEL, "relin-seed").expect("relin key");
        let relinearized = relinearize(&product, &relinearization_key).expect("relinearize");
        assert_eq!(relinearized.component_count(), 2);
        assert_eq!(
            key.decrypt_to_slots(&relinearized).expect("decrypt")[..3].to_vec(),
            vec![10, 18, 28]
        );
    }

    #[test]
    fn relinearized_product_supports_a_second_multiplication() {
        let key = shared_key();
        let a = at_test_level(&key.encrypt_slots(&[2, 3, 4], "ksk03").expect("a"));
        let b = at_test_level(&key.encrypt_slots(&[1, 5, 2], "ksk04").expect("b"));
        let relinearization_key =
            generate_relinearization_key(key, TEST_LEVEL, "relin-seed").expect("relin key");
        let first = relinearize(
            &ciphertext_tensor(&a, &b).expect("ab"),
            &relinearization_key,
        )
        .expect("relinearize ab");
        let c = at_test_level(&key.encrypt_slots(&[3, 2, 4], "ksk05").expect("c"));
        let second = relinearize(
            &ciphertext_tensor(&first, &c).expect("abc"),
            &relinearization_key,
        )
        .expect("relinearize abc");
        assert_eq!(
            key.decrypt_to_slots(&second).expect("decrypt")[..3].to_vec(),
            vec![6, 30, 32]
        );
    }

    #[test]
    fn rotation_matches_the_plaintext_automorphism() {
        let key = shared_key();
        let galois_element = 3_usize;
        let slots = [11_u64, 22, 33, 44, 55, 66, 77, 88];
        let ciphertext = at_test_level(&key.encrypt_slots(&slots, "ksk06").expect("encrypt"));
        let galois_key = generate_galois_key(key, galois_element, TEST_LEVEL, "galois-seed")
            .expect("galois key");
        let rotated = rotate(&ciphertext, galois_element, &galois_key).expect("rotate");

        let plaintext_coefficients = encode_slots_to_coefficients(&slots).expect("encode");
        let rotated_coefficients =
            automorphism_residues(&plaintext_coefficients, galois_element, PLAINTEXT_MODULUS)
                .expect("plaintext automorphism");
        let expected_slots =
            forward_negacyclic_ntt(&rotated_coefficients, PLAINTEXT_MODULUS).expect("decode");

        assert_eq!(
            key.decrypt_to_slots(&rotated).expect("decrypt"),
            expected_slots
        );
    }

    #[test]
    fn inverse_rotation_matches_the_plaintext_automorphism() {
        let key = shared_key();
        let galois_element = 43_691_usize;
        let slots = [11_u64, 22, 33, 44, 55, 66, 77, 88];
        let ciphertext = at_test_level(&key.encrypt_slots(&slots, "ksk07").expect("encrypt"));
        let galois_key =
            generate_galois_key(key, galois_element, TEST_LEVEL, "inverse-galois-seed")
                .expect("galois key");
        let rotated = rotate(&ciphertext, galois_element, &galois_key).expect("rotate");

        let plaintext_coefficients = encode_slots_to_coefficients(&slots).expect("encode");
        let rotated_coefficients =
            automorphism_residues(&plaintext_coefficients, galois_element, PLAINTEXT_MODULUS)
                .expect("plaintext automorphism");
        let expected_slots =
            forward_negacyclic_ntt(&rotated_coefficients, PLAINTEXT_MODULUS).expect("decode");

        assert_eq!(
            key.decrypt_to_slots(&rotated).expect("decrypt"),
            expected_slots
        );
    }
}
