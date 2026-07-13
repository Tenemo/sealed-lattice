use super::*;

// Apply the Galois automorphism X -> X^galois_element to a residue vector. The
// exponent reduces modulo 2N; the upper half wraps with a sign flip because
// X^N = -1 in the ring.
pub(super) fn automorphism_residues(
    input: &[u64],
    galois_element: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    let two_n = 2 * POLYNOMIAL_DEGREE;
    let mut output = vec![0_u64; POLYNOMIAL_DEGREE];
    for (coefficient_index, value) in input.iter().enumerate() {
        // X -> X^k sends coefficient i to i*k mod 2N; the subtraction on the
        // upper half is the negacyclic X^N = -1 sign fold.
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
    if galois_key.level < ciphertext.level {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
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
