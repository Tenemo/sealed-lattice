//! Committed-material VSS commitment records.
//!
//! The public commitment for a VSS message (a Shamir coefficient, a recipient
//! share, an aggregate threshold share, or a target-decryption smudging
//! coefficient) is one common-proof-field root over the message's canonical
//! four-column layout. Every consuming proof opens that byte-identical tree on
//! the profile-bound Goldilocks evaluation domain.

use super::*;

const VSS_COMMITTED_MATERIAL_OPENING_PAYLOAD_HASH_DOMAIN: &str =
    "sealed-lattice-vss-committed-material/opening-payload";

pub(crate) struct VssCommittedMaterialCommitmentInput<'a> {
    pub(crate) commitment_role: &'a str,
    pub(crate) commitment_context: &'a Value,
    pub(crate) rns_limb_index: usize,
    pub(crate) rns_prime: u64,
    pub(crate) ring_degree: usize,
    pub(crate) message_coefficients: &'a [u64],
    pub(crate) message_coefficient_bound: u64,
    // The holder's private deterministic seed for the mask and salt streams; a
    // 128-character lowercase hexadecimal protocol-hash-shaped secret. The
    // same seed regenerates byte-identical trees in later ceremony phases.
    pub(crate) material_seed_hex: &'a str,
}

pub(crate) struct VssCommittedMaterialCommitmentComputation {
    pub(crate) commitment: Value,
    #[cfg(test)]
    pub(crate) commitment_root: String,
    pub(crate) opening_root: String,
}

pub(crate) fn compute_vss_committed_material_commitment(
    input: VssCommittedMaterialCommitmentInput<'_>,
) -> CanonicalResult<VssCommittedMaterialCommitmentComputation> {
    validate_vss_public_commitment_role(input.commitment_role)?;
    validate_hash_string(input.material_seed_hex, "materialSeedHex")?;
    if input.rns_prime == 0 {
        return Err(invalid_vss_public_input("rnsPrime must be positive"));
    }
    if input.ring_degree == 0 {
        return Err(invalid_vss_public_input("ringDegree must be positive"));
    }
    if input.message_coefficient_bound == 0 {
        return Err(invalid_vss_public_input(
            "messageCoefficientBound must be positive",
        ));
    }
    if input.message_coefficients.len() != input.ring_degree {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "VSS message coefficient count must match ringDegree",
        ));
    }
    for (coefficient_index, coefficient) in input.message_coefficients.iter().enumerate() {
        if *coefficient >= input.message_coefficient_bound {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                format!(
                    "VSS message coefficient {coefficient_index} must be below messageCoefficientBound"
                ),
            ));
        }
    }
    let message_digit_columns =
        vss_public_canonical_message_digit_columns(input.message_coefficients, input.ring_degree)?;

    let commitment_context_hash = derive_canonical_object_hash(&json!({
        "objectType": "VssCommittedMaterialCommitmentContext",
        "commitmentRole": input.commitment_role,
        "commitmentContext": input.commitment_context,
    }))?;

    let material_context_hash =
        decode_protocol_hash(&commitment_context_hash, "commitmentContextHash")?;
    let material_seed = decode_protocol_hash(input.material_seed_hex, "materialSeedHex")?;
    let material_profile =
        crate::bgv::proof_suite::CommittedMaterialProfile::selected(input.ring_degree)
            .map_err(committed_material_error)?;
    let material_tree = crate::bgv::proof_suite::CommittedMaterialTree::construct(
        crate::bgv::proof_suite::CommittedMaterialTreeInput {
            profile: material_profile,
            material_context_hash,
            material_seed,
            message_digit_columns: &message_digit_columns,
        },
    )
    .map_err(committed_material_error)?;
    let material_root_hex = crate::transcript_core::encode_hex(&material_tree.root());

    let commitment = json!({
        "objectType": "VssCommittedMaterialCommitment",
        "commitmentRole": input.commitment_role,
        "commitmentContextHash": crate::transcript_core::encode_hex(&material_context_hash),
        "rnsLimbIndex": input.rns_limb_index,
        "rnsPrime": input.rns_prime,
        "ringDegree": input.ring_degree,
        "materialRootHex": material_root_hex,
    });
    #[cfg(test)]
    let commitment_root = derive_canonical_object_hash(&commitment)?;
    let opening_root = derive_canonical_object_hash(&json!({
        "objectType": "VssCommittedMaterialCommitmentOpening",
        "commitmentRole": input.commitment_role,
        "commitmentContext": input.commitment_context,
        "rnsLimbIndex": input.rns_limb_index,
        "rnsPrime": input.rns_prime,
        "ringDegree": input.ring_degree,
        "openingPayloadHash512": vss_committed_material_opening_payload_hash(
            input.message_coefficients,
            &message_digit_columns,
            input.material_seed_hex,
        )?,
    }))?;

    Ok(VssCommittedMaterialCommitmentComputation {
        commitment,
        #[cfg(test)]
        commitment_root,
        opening_root,
    })
}

fn decode_protocol_hash(value: &str, field_name: &str) -> CanonicalResult<[u8; 64]> {
    let bytes = crate::transcript_core::decode_hex(value)?;
    bytes.try_into().map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            format!("{field_name} must be a 64-byte lowercase hex digest"),
        )
    })
}

fn committed_material_error(
    error: crate::bgv::proof_suite::CommittedMaterialError,
) -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("committed-material tree construction failed: {error:?}"),
    )
}

// The private opening reference: a length-framed hash of the message, its
// canonical digit columns, and the holder's material seed. The seed term makes
// the published reference hiding; the framing makes it injective over the
// payload shape.
fn vss_committed_material_opening_payload_hash(
    message_coefficients: &[u64],
    message_digit_columns: &[Vec<u64>],
    material_seed_hex: &str,
) -> CanonicalResult<String> {
    let word_count = 3_usize
        .checked_add(message_coefficients.len())
        .and_then(|count| {
            message_digit_columns
                .iter()
                .try_fold(count, |total, column| {
                    total.checked_add(1)?.checked_add(column.len())
                })
        })
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "VSS committed-material opening payload length overflowed",
            )
        })?;
    let mut bytes = Vec::with_capacity(word_count * 8 + material_seed_hex.len());
    bytes.extend((message_coefficients.len() as u64).to_le_bytes());
    for coefficient in message_coefficients {
        bytes.extend(coefficient.to_le_bytes());
    }
    bytes.extend((message_digit_columns.len() as u64).to_le_bytes());
    for column in message_digit_columns {
        bytes.extend((column.len() as u64).to_le_bytes());
        for digit in column {
            bytes.extend(digit.to_le_bytes());
        }
    }
    bytes.extend((material_seed_hex.len() as u64).to_le_bytes());
    bytes.extend(material_seed_hex.as_bytes());

    Ok(hash512_hex(
        VSS_COMMITTED_MATERIAL_OPENING_PAYLOAD_HASH_DOMAIN,
        &[&bytes],
    ))
}

pub(crate) fn compute_vss_committed_material_commitment_request(
    request: &Value,
) -> CanonicalResult<Value> {
    let commitment_role = string_at_path(request, &["commitmentRole"])?;
    let commitment_context = value_at_path(request, &["commitmentContext"])?;
    let rns_limb_index = usize_at_path(request, &["rnsLimbIndex"])?;
    let rns_prime = *DATA_PRIMES
        .get(rns_limb_index)
        .ok_or_else(|| invalid_vss_public_input("rnsLimbIndex is outside the Q_share basis"))?;
    let ring_degree = usize_at_path(request, &["ringDegree"])?;
    let message_coefficient_bound = if commitment_role == "target-decryption-flooding-noise" {
        u64::try_from(
            super::super::trustee_evaluation_key_proof::TARGET_DECRYPTION_FLOODING_NOISE_COEFFICIENT_BOUND
                * 2
                + 1,
        )
        .map_err(|_| invalid_vss_public_input("flooding-noise coefficient bound is invalid"))?
    } else {
        rns_prime
    };
    let message_coefficients = read_vss_public_message_coefficients(
        request,
        "messageCoefficients",
        ring_degree,
        message_coefficient_bound,
    )?;
    let material_seed_hex = string_at_path(request, &["materialSeedHex"])?;

    let computation =
        compute_vss_committed_material_commitment(VssCommittedMaterialCommitmentInput {
            commitment_role,
            commitment_context,
            rns_limb_index,
            rns_prime,
            ring_degree,
            message_coefficients: &message_coefficients,
            message_coefficient_bound,
            material_seed_hex,
        })?;

    Ok(json!({
        "commitment": computation.commitment,
        "openingRoot": computation.opening_root,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_RING_DEGREE: usize = 128;

    fn test_material_seed_hex(fill_byte: u8) -> String {
        let nibble = |value: u8| -> char {
            char::from_digit(u32::from(value & 0x0f), 16).expect("hex nibble")
        };
        (0..128)
            .map(|index| {
                if index % 2 == 0 {
                    nibble(fill_byte >> 4)
                } else {
                    nibble(fill_byte)
                }
            })
            .collect()
    }

    fn test_message(rns_prime: u64) -> Vec<u64> {
        (0..TEST_RING_DEGREE)
            .map(|coefficient_index| {
                let mixed = (coefficient_index as u128 + 3)
                    * (coefficient_index as u128 + 41)
                    * 2_654_435_761_u128;
                (mixed % u128::from(rns_prime)) as u64
            })
            .collect()
    }

    fn commitment_request(message_coefficients: &[u64], material_seed_hex: &str) -> Value {
        json!({
            "commitmentRole": "coefficient",
            "commitmentContext": {
                "ceremonyId": "test-ceremony",
                "sourceTrusteeRosterPosition": 2,
                "shamirCoefficientIndex": 1,
            },
            "rnsLimbIndex": 0,
            "ringDegree": TEST_RING_DEGREE,
            "messageCoefficients": message_coefficients,
            "materialSeedHex": material_seed_hex,
        })
    }

    fn material_root_hexes(response: &Value) -> Vec<String> {
        response["commitment"]["commitmentFields"]
            .as_array()
            .expect("commitment fields")
            .iter()
            .map(|field| {
                field["materialRootHex"]
                    .as_str()
                    .expect("material root hex")
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn committed_material_commitment_is_deterministic_and_seed_and_context_bound()
    -> CanonicalResult<()> {
        let message = test_message(DATA_PRIMES[0]);
        let seed = test_material_seed_hex(0x5a);
        let request = commitment_request(&message, &seed);

        let first = compute_vss_committed_material_commitment_request(&request)?;
        let second = compute_vss_committed_material_commitment_request(&request)?;
        assert_eq!(
            first, second,
            "the committed-material commitment must regenerate byte-identically from the same message and seed"
        );
        let roots = material_root_hexes(&first);
        assert_eq!(
            roots.len(),
            VSS_PUBLIC_COMMITMENT_MODULUS_LIMB_INDICES.len(),
            "one material root per commitment field"
        );
        assert!(
            roots.iter().all(|root| root.len() == 128),
            "material roots are 64-byte H_512 digests in hex"
        );
        assert!(first.get("commitmentRoot").is_none());

        // A different private seed hides differently: same context hash, all
        // roots change, and the opening reference changes.
        let other_seed_response = compute_vss_committed_material_commitment_request(
            &commitment_request(&message, &test_material_seed_hex(0xa5)),
        )?;
        assert_eq!(
            first["commitment"]["commitmentContextHash"],
            other_seed_response["commitment"]["commitmentContextHash"]
        );
        let other_seed_roots = material_root_hexes(&other_seed_response);
        for (root, other_root) in roots.iter().zip(other_seed_roots.iter()) {
            assert_ne!(
                root, other_root,
                "a different material seed must change every field root"
            );
        }
        assert_ne!(first["openingRoot"], other_seed_response["openingRoot"]);

        // A different role re-derives the context hash and therefore the mask
        // and salt streams: every root changes even for the same message and
        // seed, so trees are never shared across roles.
        let mut role_request = commitment_request(&message, &seed);
        role_request["commitmentRole"] = json!("recipient-share");
        let role_response = compute_vss_committed_material_commitment_request(&role_request)?;
        assert_ne!(
            first["commitment"]["commitmentContextHash"],
            role_response["commitment"]["commitmentContextHash"]
        );
        for (root, role_root) in roots.iter().zip(material_root_hexes(&role_response).iter()) {
            assert_ne!(
                root, role_root,
                "a different commitment role must change every field root"
            );
        }

        Ok(())
    }

    // Committed-material roots must separate every
    // distinct canonical message, including single-position and
    // high-digit-only differences, under one fixed seed and context.
    #[test]
    fn committed_material_commitment_separates_distinct_messages() -> CanonicalResult<()> {
        let seed = test_material_seed_hex(0x33);
        let base_message = test_message(DATA_PRIMES[0]);
        let base_response = compute_vss_committed_material_commitment_request(
            &commitment_request(&base_message, &seed),
        )?;
        let base_roots = material_root_hexes(&base_response);

        let mut variants: Vec<(String, Vec<u64>)> = Vec::new();
        for tamper_position in [0_usize, 1, TEST_RING_DEGREE / 2, TEST_RING_DEGREE - 1] {
            let mut tampered = base_message.clone();
            tampered[tamper_position] = (tampered[tamper_position] + 1) % DATA_PRIMES[0];
            variants.push((format!("low-digit tamper at {tamper_position}"), tampered));
        }
        // A high-digit-only difference: adding the digit base leaves the low
        // digit unchanged and moves only the second digit column.
        let mut high_digit_tampered = base_message.clone();
        high_digit_tampered[7] =
            (high_digit_tampered[7] + VSS_PUBLIC_MESSAGE_DIGIT_BASE) % DATA_PRIMES[0];
        variants.push(("high-digit tamper at 7".to_string(), high_digit_tampered));
        // A many-position difference.
        let mut widely_tampered = base_message.clone();
        for value in widely_tampered.iter_mut() {
            *value = (*value + 12_345) % DATA_PRIMES[0];
        }
        variants.push(("every-position tamper".to_string(), widely_tampered));

        let mut all_root_sets = vec![base_roots];
        for (variant_label, variant_message) in &variants {
            let response = compute_vss_committed_material_commitment_request(&commitment_request(
                variant_message,
                &seed,
            ))?;
            let variant_roots = material_root_hexes(&response);
            for existing_roots in &all_root_sets {
                for (existing_root, variant_root) in existing_roots.iter().zip(variant_roots.iter())
                {
                    assert_ne!(
                        existing_root, variant_root,
                        "distinct canonical messages must have distinct material roots ({variant_label})"
                    );
                }
            }
            all_root_sets.push(variant_roots);
        }

        Ok(())
    }

    #[test]
    fn committed_material_commitment_rejects_malformed_input() {
        let seed = test_material_seed_hex(0x11);
        let message = test_message(DATA_PRIMES[0]);

        // Wrong message length.
        let mut short_message_request = commitment_request(&message, &seed);
        short_message_request["messageCoefficients"] = json!(message[..TEST_RING_DEGREE - 1]);
        assert!(
            compute_vss_committed_material_commitment_request(&short_message_request).is_err(),
            "a short message vector must be rejected"
        );

        // A coefficient at the bound.
        let mut out_of_bound_request = commitment_request(&message, &seed);
        out_of_bound_request["messageCoefficients"][3] = json!(DATA_PRIMES[0]);
        assert!(
            compute_vss_committed_material_commitment_request(&out_of_bound_request).is_err(),
            "a message coefficient at the bound must be rejected"
        );

        // An unsupported role.
        let mut unsupported_role_request = commitment_request(&message, &seed);
        unsupported_role_request["commitmentRole"] = json!("unsupported-role");
        assert!(
            compute_vss_committed_material_commitment_request(&unsupported_role_request).is_err(),
            "an unsupported commitment role must be rejected"
        );

        // A malformed seed (wrong length / alphabet).
        let mut short_seed_request = commitment_request(&message, &seed);
        short_seed_request["materialSeedHex"] = json!("abc123");
        assert!(
            compute_vss_committed_material_commitment_request(&short_seed_request).is_err(),
            "a malformed material seed must be rejected"
        );

        // A non-power-of-two ring degree cannot host the trace split.
        let mut odd_degree_request = commitment_request(&message, &seed);
        odd_degree_request["ringDegree"] = json!(TEST_RING_DEGREE - 1);
        odd_degree_request["messageCoefficients"] = json!(message[..TEST_RING_DEGREE - 1]);
        assert!(
            compute_vss_committed_material_commitment_request(&odd_degree_request).is_err(),
            "a non-power-of-two ring degree must be rejected"
        );

        // A trace below the minimum supported size is refused by the domain
        // plan, not silently committed.
        let tiny_message = &message[..64];
        let mut tiny_degree_request = commitment_request(tiny_message, &seed);
        tiny_degree_request["ringDegree"] = json!(64);
        assert!(
            compute_vss_committed_material_commitment_request(&tiny_degree_request).is_err(),
            "a ring degree below the minimum trace size must be rejected"
        );

        let flooding_noise_message = vec![32; TEST_RING_DEGREE];
        let mut flooding_noise_request = commitment_request(&flooding_noise_message, &seed);
        flooding_noise_request["commitmentRole"] = json!("target-decryption-flooding-noise");
        assert!(
            compute_vss_committed_material_commitment_request(&flooding_noise_request).is_ok(),
            "the largest canonical encoded flooding-noise coefficient must be accepted"
        );
        flooding_noise_request["messageCoefficients"][0] = json!(33);
        assert!(
            compute_vss_committed_material_commitment_request(&flooding_noise_request).is_err(),
            "the fixed flooding-noise range must be enforced by the kernel"
        );
    }
}
