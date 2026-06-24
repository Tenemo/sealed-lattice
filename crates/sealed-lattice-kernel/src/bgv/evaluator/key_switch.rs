use crate::{
    bgv::{
        evaluator::{
            engine::{Ciphertext, DevelopmentBgvKey, negacyclic_mul, signed_residue},
            prg::DeterministicSampler,
        },
        modular_arithmetic::{add_mod, add_mod_fast, mul_mod_fast, sub_mod},
        ntt::{forward_negacyclic_ntt, inverse_negacyclic_ntt},
        parameters::{DATA_PRIMES, POLYNOMIAL_DEGREE},
    },
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
};

mod rotation;

#[cfg(not(target_arch = "wasm32"))]
use rayon::prelude::*;
#[cfg(test)]
use rotation::automorphism_residues;
pub(crate) use rotation::{generate_galois_key, rotate};

pub(crate) const PLAINTEXT_MODULUS_I64: i64 = 65_537;
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
    pub(crate) component_b: Option<Vec<Vec<u64>>>,
    component_b_ntt: Vec<Vec<u64>>,
    component_a_ntt: Option<Vec<Vec<u64>>>,
    component_a_source: KeySwitchComponentASource,
    digit_index: usize,
}

#[derive(Clone)]
enum KeySwitchComponentASource {
    DeterministicStream { domain: String, seed_hex: String },
    RetainedPublicSample,
}

impl KeySwitchKey {
    pub(crate) fn drop_component_a_ntt(&mut self) {
        for component in &mut self.components {
            if matches!(
                component.component_a_source,
                KeySwitchComponentASource::DeterministicStream { .. }
            ) {
                component.component_a_ntt = None;
            }
        }
    }
}

impl KeySwitchComponent {
    fn from_coefficients(
        component_b: Vec<Vec<u64>>,
        component_a: Vec<Vec<u64>>,
        primes: &[u64],
        domain: &str,
        seed_hex: &str,
        digit_index: usize,
    ) -> CanonicalResult<Self> {
        Self::from_coefficients_with_source(
            component_b,
            component_a,
            primes,
            KeySwitchComponentASource::DeterministicStream {
                domain: domain.to_string(),
                seed_hex: seed_hex.to_string(),
            },
            digit_index,
        )
    }

    fn from_retained_public_sample(
        component_b: Vec<Vec<u64>>,
        component_a: Vec<Vec<u64>>,
        primes: &[u64],
        digit_index: usize,
    ) -> CanonicalResult<Self> {
        Self::from_coefficients_with_source(
            component_b,
            component_a,
            primes,
            KeySwitchComponentASource::RetainedPublicSample,
            digit_index,
        )
    }

    fn from_coefficients_with_source(
        component_b: Vec<Vec<u64>>,
        component_a: Vec<Vec<u64>>,
        primes: &[u64],
        component_a_source: KeySwitchComponentASource,
        digit_index: usize,
    ) -> CanonicalResult<Self> {
        let component_b_ntt = ntt_limbs(&component_b, primes)?;
        let component_a_ntt = ntt_limbs(&component_a, primes)?;
        drop(component_a);

        Ok(Self {
            component_b: Some(component_b),
            component_b_ntt,
            component_a_ntt: Some(component_a_ntt),
            component_a_source,
            digit_index,
        })
    }

    fn component_a_ntt_for_limb(
        &self,
        limb_index: usize,
        modulus: u64,
    ) -> CanonicalResult<Vec<u64>> {
        if let Some(component_a_ntt) = &self.component_a_ntt {
            return Ok(component_a_ntt[limb_index].clone());
        }
        let KeySwitchComponentASource::DeterministicStream { domain, seed_hex } =
            &self.component_a_source
        else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "retained public key-switch component-a material is unavailable",
            ));
        };
        let public_sample = public_component_a_limb(domain, seed_hex, self.digit_index, modulus);

        forward_negacyclic_ntt(&public_sample, modulus)
    }
}

fn ntt_limbs(limbs: &[Vec<u64>], primes: &[u64]) -> CanonicalResult<Vec<Vec<u64>>> {
    if limbs.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "key-switch component limb count does not match its modulus level",
        ));
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        limbs
            .par_iter()
            .zip(primes.par_iter())
            .map(|(limb, modulus)| forward_negacyclic_ntt(limb, *modulus))
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        limbs
            .iter()
            .zip(primes.iter())
            .map(|(limb, modulus)| forward_negacyclic_ntt(limb, *modulus))
            .collect()
    }
}

fn secret_residues_for_level(secret: &[i64], level: usize) -> Vec<Vec<u64>> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        DATA_PRIMES[..=level]
            .par_iter()
            .map(|modulus| {
                secret
                    .iter()
                    .map(|coefficient| signed_residue(*coefficient, *modulus))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
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
    #[cfg(not(target_arch = "wasm32"))]
    let components = source_limbs
        .par_iter()
        .enumerate()
        .map(|(digit_index, source_limb)| {
            generate_key_switch_component_for_digit(
                primes,
                &secret_residues,
                digit_index,
                source_limb,
                domain,
                seed_hex,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let components = source_limbs
        .iter()
        .enumerate()
        .map(|(digit_index, source_limb)| {
            generate_key_switch_component_for_digit(
                primes,
                &secret_residues,
                digit_index,
                source_limb,
                domain,
                seed_hex,
            )
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(KeySwitchKey { level, components })
}

fn generate_key_switch_component_for_digit(
    primes: &[u64],
    secret_residues: &[Vec<u64>],
    digit_index: usize,
    source_limb: &[u64],
    domain: &str,
    seed_hex: &str,
) -> CanonicalResult<KeySwitchComponent> {
    let digit_bytes = (digit_index as u64).to_le_bytes();
    // One small error polynomial per digit, shared across limbs.
    let error = DeterministicSampler::new(
        KEY_SWITCH_ERROR_DOMAIN,
        &[domain.as_bytes(), seed_hex.as_bytes(), &digit_bytes],
    )
    .centered_binomial_eta2(POLYNOMIAL_DEGREE);
    #[cfg(not(target_arch = "wasm32"))]
    let limbs = primes
        .par_iter()
        .enumerate()
        .map(|(limb_index, modulus)| {
            generate_key_switch_component_limb_for_digit(KeySwitchComponentLimbInput {
                secret_residue_limb: &secret_residues[limb_index],
                source_limb,
                error: &error,
                limb_index,
                modulus: *modulus,
                digit_index,
                domain,
                seed_hex,
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let limbs = primes
        .iter()
        .enumerate()
        .map(|(limb_index, modulus)| {
            generate_key_switch_component_limb_for_digit(KeySwitchComponentLimbInput {
                secret_residue_limb: &secret_residues[limb_index],
                source_limb,
                error: &error,
                limb_index,
                modulus: *modulus,
                digit_index,
                domain,
                seed_hex,
            })
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    let (component_b, component_a) = limbs.into_iter().unzip();

    KeySwitchComponent::from_coefficients(
        component_b,
        component_a,
        primes,
        domain,
        seed_hex,
        digit_index,
    )
}

struct KeySwitchComponentLimbInput<'a> {
    secret_residue_limb: &'a [u64],
    source_limb: &'a [u64],
    error: &'a [i64],
    limb_index: usize,
    modulus: u64,
    digit_index: usize,
    domain: &'a str,
    seed_hex: &'a str,
}

fn generate_key_switch_component_limb_for_digit(
    input: KeySwitchComponentLimbInput<'_>,
) -> CanonicalResult<(Vec<u64>, Vec<u64>)> {
    let public_sample = public_component_a_limb(
        input.domain,
        input.seed_hex,
        input.digit_index,
        input.modulus,
    );
    let public_sample_secret_product =
        negacyclic_mul(&public_sample, input.secret_residue_limb, input.modulus)?;
    let component_b_limb = (0..POLYNOMIAL_DEGREE)
        .map(|coefficient_index| {
            // Noise is scaled by the plaintext modulus t so it lies in t*Z and
            // vanishes under the final mod-t reduction.
            let scaled_error = signed_residue(
                input.error[coefficient_index] * PLAINTEXT_MODULUS_I64,
                input.modulus,
            );
            let mut value = sub_mod(
                scaled_error,
                public_sample_secret_product[coefficient_index],
                input.modulus,
            )?;
            if input.limb_index == input.digit_index {
                value = add_mod(value, input.source_limb[coefficient_index], input.modulus)?;
            }
            Ok(value)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok((component_b_limb, public_sample))
}

pub(crate) fn key_switch_key_from_public_component_b(
    level: usize,
    domain: &str,
    seed_hex: &str,
    component_b_by_digit: Vec<Vec<Vec<u64>>>,
) -> CanonicalResult<KeySwitchKey> {
    let component_a_by_digit = public_component_a_by_digit(level, domain, seed_hex)?;

    key_switch_key_from_public_components(level, component_b_by_digit, component_a_by_digit)
}

pub(crate) fn key_switch_key_from_public_components(
    level: usize,
    component_b_by_digit: Vec<Vec<Vec<u64>>>,
    component_a_by_digit: Vec<Vec<Vec<u64>>>,
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
    if component_a_by_digit.len() != primes.len() {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public key-switch component-a digit count does not match its level",
        ));
    }
    #[cfg(not(target_arch = "wasm32"))]
    let components = component_b_by_digit
        .into_par_iter()
        .zip(component_a_by_digit.into_par_iter())
        .enumerate()
        .map(|(digit_index, (component_b, component_a))| {
            public_key_switch_component_for_digit(primes, digit_index, component_b, component_a)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let components = component_b_by_digit
        .into_iter()
        .zip(component_a_by_digit.into_iter())
        .enumerate()
        .map(|(digit_index, (component_b, component_a))| {
            public_key_switch_component_for_digit(primes, digit_index, component_b, component_a)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(KeySwitchKey { level, components })
}

fn public_key_switch_component_for_digit(
    primes: &[u64],
    digit_index: usize,
    component_b: Vec<Vec<u64>>,
    component_a: Vec<Vec<u64>>,
) -> CanonicalResult<KeySwitchComponent> {
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
    if component_a.len() != primes.len()
        || component_a
            .iter()
            .any(|limb| limb.len() != POLYNOMIAL_DEGREE)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public key-switch component-a shape does not match its level",
        ));
    }

    KeySwitchComponent::from_retained_public_sample(component_b, component_a, primes, digit_index)
}

fn public_component_a_by_digit(
    level: usize,
    domain: &str,
    seed_hex: &str,
) -> CanonicalResult<Vec<Vec<Vec<u64>>>> {
    let primes = DATA_PRIMES.get(..=level).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "public key-switch material level is outside the selected data basis",
        )
    })?;
    #[cfg(not(target_arch = "wasm32"))]
    {
        (0..=level)
            .into_par_iter()
            .map(|digit_index| public_component_a_for_digit(primes, domain, seed_hex, digit_index))
            .collect()
    }
    #[cfg(target_arch = "wasm32")]
    {
        (0..=level)
            .map(|digit_index| public_component_a_for_digit(primes, domain, seed_hex, digit_index))
            .collect()
    }
}

fn public_component_a_for_digit(
    primes: &[u64],
    domain: &str,
    seed_hex: &str,
    digit_index: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    #[cfg(not(target_arch = "wasm32"))]
    {
        Ok(primes
            .par_iter()
            .map(|modulus| public_component_a_limb(domain, seed_hex, digit_index, *modulus))
            .collect::<Vec<_>>())
    }
    #[cfg(target_arch = "wasm32")]
    {
        Ok(primes
            .iter()
            .map(|modulus| public_component_a_limb(domain, seed_hex, digit_index, *modulus))
            .collect::<Vec<_>>())
    }
}

fn public_component_a_limb(
    domain: &str,
    seed_hex: &str,
    digit_index: usize,
    modulus: u64,
) -> Vec<u64> {
    let digit_bytes = (digit_index as u64).to_le_bytes();
    let modulus_bytes = modulus.to_le_bytes();
    DeterministicSampler::new(
        KEY_SWITCH_SAMPLE_DOMAIN,
        &[
            domain.as_bytes(),
            seed_hex.as_bytes(),
            &digit_bytes,
            &modulus_bytes,
        ],
    )
    .uniform_residues(modulus, POLYNOMIAL_DEGREE)
}

// Apply a key-switching key to a single ciphertext component (the term that
// multiplies the source key), producing the two-component RLWE encryption of
// source * term under the secret. The key may be generated at a higher level
// than the term: the CRT-idempotent gadget keys public samples by digit and
// modulus only, so the digits and limbs 0..=term_level of a higher-level key
// are exactly the lower-level key, and the active window is sliced here.
fn key_switch_component(
    term: &[Vec<u64>],
    key_switch_key: &KeySwitchKey,
) -> CanonicalResult<(LimbMatrix, LimbMatrix)> {
    let term_level = term.len().checked_sub(1).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "key-switch term must carry at least one limb",
        )
    })?;
    if key_switch_key.level < term_level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "key-switching key level is below the term level",
        ));
    }
    let primes = &DATA_PRIMES[..=term_level];
    let mut switched_zero = vec![vec![0_u64; POLYNOMIAL_DEGREE]; primes.len()];
    let mut switched_one = vec![vec![0_u64; POLYNOMIAL_DEGREE]; primes.len()];
    let active_components = &key_switch_key.components[..=term_level];
    #[cfg(not(target_arch = "wasm32"))]
    let partials = active_components
        .par_iter()
        .enumerate()
        .map(|(digit_index, component)| {
            key_switch_component_digit(term, primes, digit_index, component)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
    let partials = active_components
        .iter()
        .enumerate()
        .map(|(digit_index, component)| {
            key_switch_component_digit(term, primes, digit_index, component)
        })
        .collect::<CanonicalResult<Vec<_>>>()?;
    for (partial_zero, partial_one) in partials {
        add_component_in_place(&mut switched_zero, &partial_zero, term_level)?;
        add_component_in_place(&mut switched_one, &partial_one, term_level)?;
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
        let component_a_ntt = component.component_a_ntt_for_limb(limb_index, *modulus)?;
        let product_a = multiply_ntt_by_ntt(&digit_ntt, &component_a_ntt, *modulus)?;
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
    #[cfg(not(target_arch = "wasm32"))]
    let squared = secret_residues
        .par_iter()
        .enumerate()
        .map(|(limb_index, limb)| negacyclic_mul(limb, limb, DATA_PRIMES[limb_index]))
        .collect::<CanonicalResult<Vec<_>>>()?;
    #[cfg(target_arch = "wasm32")]
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
    if relinearization_key.level < ciphertext.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "relinearization key level is below the ciphertext level",
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
        parameters::PLAINTEXT_MODULUS,
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
    fn higher_level_key_truncates_to_the_lower_level_key() {
        // The CRT-idempotent gadget keys public samples by digit and modulus
        // only, so the digits and limbs 0..=l of a level-L key generated from
        // one seed must equal the level-l key generated from the same seed.
        let key = shared_key();
        let higher = generate_relinearization_key(key, 5, "truncation-seed").expect("level 5");
        let lower = generate_relinearization_key(key, 2, "truncation-seed").expect("level 2");
        assert_eq!(lower.components.len(), 3);
        for (digit_index, lower_component) in lower.components.iter().enumerate() {
            let higher_component = &higher.components[digit_index];
            let higher_b = higher_component
                .component_b
                .as_ref()
                .expect("component b retained");
            let lower_b = lower_component
                .component_b
                .as_ref()
                .expect("component b retained");
            assert_eq!(
                &higher_b[..lower_b.len()],
                &lower_b[..],
                "digit {digit_index} component b must restrict to the lower level"
            );
        }
    }

    #[test]
    fn higher_level_relinearization_key_relinearizes_lower_level_ciphertexts() {
        let key = shared_key();
        let left = at_test_level(&key.encrypt_slots(&[4, 5, 6], "ksk-trunc-a").expect("left"));
        let right = at_test_level(&key.encrypt_slots(&[7, 8, 9], "ksk-trunc-b").expect("right"));
        let product = ciphertext_tensor(&left, &right).expect("tensor");
        // Key generated two levels above the ciphertext level.
        let relinearization_key =
            generate_relinearization_key(key, TEST_LEVEL + 2, "trunc-relin-seed")
                .expect("relin key");
        let relinearized = relinearize(&product, &relinearization_key).expect("relinearize");
        assert_eq!(
            key.decrypt_to_slots(&relinearized).expect("decrypt")[..3].to_vec(),
            vec![28, 40, 54]
        );
    }

    #[test]
    fn higher_level_galois_key_rotates_lower_level_ciphertexts() {
        let key = shared_key();
        let galois_element = 3_usize;
        let slots = [9_u64, 8, 7, 6, 5, 4, 3, 2];
        let ciphertext =
            at_test_level(&key.encrypt_slots(&slots, "ksk-trunc-rot").expect("encrypt"));
        let galois_key =
            generate_galois_key(key, galois_element, TEST_LEVEL + 2, "trunc-galois-seed")
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
        let first_factor = at_test_level(
            &key.encrypt_slots(&[2, 3, 4], "ksk03")
                .expect("first factor"),
        );
        let second_factor = at_test_level(
            &key.encrypt_slots(&[1, 5, 2], "ksk04")
                .expect("second factor"),
        );
        let relinearization_key =
            generate_relinearization_key(key, TEST_LEVEL, "relin-seed").expect("relin key");
        let first = relinearize(
            &ciphertext_tensor(&first_factor, &second_factor).expect("first times second"),
            &relinearization_key,
        )
        .expect("relinearize first times second");
        let third_factor = at_test_level(
            &key.encrypt_slots(&[3, 2, 4], "ksk05")
                .expect("third factor"),
        );
        let second = relinearize(
            &ciphertext_tensor(&first, &third_factor).expect("product with third factor"),
            &relinearization_key,
        )
        .expect("relinearize product with third factor");
        assert_eq!(
            key.decrypt_to_slots(&second).expect("decrypt")[..3].to_vec(),
            vec![6, 30, 32]
        );
    }

    fn assert_rotation_matches_plaintext_automorphism(
        galois_element: usize,
        encryption_seed: &str,
        galois_key_seed: &str,
    ) {
        let key = shared_key();
        let slots = [11_u64, 22, 33, 44, 55, 66, 77, 88];
        let ciphertext =
            at_test_level(&key.encrypt_slots(&slots, encryption_seed).expect("encrypt"));
        let galois_key = generate_galois_key(key, galois_element, TEST_LEVEL, galois_key_seed)
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
    fn rotation_matches_the_plaintext_automorphism() {
        assert_rotation_matches_plaintext_automorphism(3, "ksk06", "galois-seed");
    }

    #[test]
    fn inverse_rotation_matches_the_plaintext_automorphism() {
        assert_rotation_matches_plaintext_automorphism(43_691, "ksk07", "inverse-galois-seed");
    }
}
