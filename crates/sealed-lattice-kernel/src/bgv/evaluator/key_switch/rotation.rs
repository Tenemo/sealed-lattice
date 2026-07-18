use super::*;

#[derive(Clone, Copy)]
struct AutomorphismDestination {
    coefficient_index: usize,
    negate: bool,
}

fn automorphism_permutation(
    galois_element: usize,
) -> CanonicalResult<Vec<AutomorphismDestination>> {
    let automorphism_modulus = POLYNOMIAL_DEGREE.checked_mul(2).ok_or_else(|| {
        CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "selected-ring automorphism modulus overflowed",
        )
    })?;
    if galois_element <= 1
        || galois_element >= automorphism_modulus
        || galois_element.is_multiple_of(2)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "Galois element is not an odd selected-ring automorphism",
        ));
    }
    (0..POLYNOMIAL_DEGREE)
        .map(|source_coefficient_index| {
            let mapped_exponent = source_coefficient_index
                .checked_mul(galois_element)
                .ok_or_else(|| {
                    CanonicalError::new(
                        CanonicalErrorCode::InvalidProtocolObject,
                        "selected-ring automorphism index overflowed",
                    )
                })?
                % automorphism_modulus;
            Ok(AutomorphismDestination {
                coefficient_index: mapped_exponent % POLYNOMIAL_DEGREE,
                negate: mapped_exponent >= POLYNOMIAL_DEGREE,
            })
        })
        .collect()
}

// Apply the Galois automorphism X -> X^galois_element to a residue vector. The
// exponent reduces modulo 2N; the upper half wraps with a sign flip because
// X^N = -1 in the ring.
pub(super) fn automorphism_residues(
    input: &[u64],
    galois_element: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let permutation = automorphism_permutation(galois_element)?;
    automorphism_residues_with_permutation(input, &permutation, modulus)
}

fn automorphism_residues_with_permutation(
    input: &[u64],
    permutation: &[AutomorphismDestination],
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if input.len() != POLYNOMIAL_DEGREE
        || permutation.len() != POLYNOMIAL_DEGREE
        || input.iter().any(|value| *value >= modulus)
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "automorphism input is not a canonical selected-ring residue vector",
        ));
    }
    let mut output = vec![0_u64; POLYNOMIAL_DEGREE];
    for (value, destination) in input.iter().copied().zip(permutation.iter().copied()) {
        output[destination.coefficient_index] = if destination.negate && value != 0 {
            modulus - value
        } else {
            value
        };
    }

    Ok(output)
}

#[cfg(test)]
fn automorphism_signed(input: &[i64], galois_element: usize) -> CanonicalResult<Vec<i64>> {
    let permutation = automorphism_permutation(galois_element)?;
    if input.len() != POLYNOMIAL_DEGREE {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "automorphism input has the wrong selected-ring degree",
        ));
    }
    let mut output = vec![0_i64; POLYNOMIAL_DEGREE];
    for (value, destination) in input.iter().copied().zip(permutation) {
        output[destination.coefficient_index] = if destination.negate {
            value.checked_neg().ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidProtocolObject,
                    "automorphism coefficient negation overflowed",
                )
            })?
        } else {
            value
        };
    }

    Ok(output)
}

fn apply_automorphism(
    ciphertext: &Ciphertext,
    galois_element: usize,
) -> CanonicalResult<Ciphertext> {
    let primes = ciphertext.primes();
    let permutation = automorphism_permutation(galois_element)?;
    let components = ciphertext
        .components
        .iter()
        .map(|component| {
            component
                .iter()
                .enumerate()
                .map(|(limb_index, limb)| {
                    automorphism_residues_with_permutation(limb, &permutation, primes[limb_index])
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

#[cfg(test)]
pub(crate) fn generate_galois_key(
    key: &DevelopmentBgvKey,
    galois_element: usize,
    level: usize,
    seed_hex: &str,
) -> CanonicalResult<KeySwitchKey> {
    // The rotation source is the automorphism applied to the secret.
    let rotated_secret = automorphism_signed(key.secret(), galois_element)?;
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
            CanonicalErrorCode::InvalidProtocolObject,
            "rotation requires a two-component ciphertext",
        ));
    }
    if galois_key.level() < ciphertext.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "rotation key level is below the ciphertext level",
        ));
    }
    let rotated = apply_automorphism(ciphertext, galois_element)?;
    let (switched_zero, switched_one) = key_switch_component(&rotated.components[1], galois_key)?;
    let mut component_zero = rotated.components[0].clone();
    add_component_in_place(&mut component_zero, &switched_zero, ciphertext.level);

    Ok(Ciphertext {
        components: vec![component_zero, switched_one],
        level: ciphertext.level,
        decrypt_scaling: ciphertext.decrypt_scaling,
    })
}
