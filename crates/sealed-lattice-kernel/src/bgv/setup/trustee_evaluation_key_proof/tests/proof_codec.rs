use super::*;
use crate::bgv::setup::trustee_evaluation_key_proof::merkle_commitment::MERKLE_DIGEST_BYTES;

const COMMITTED_LOW_DEGREE_LAYER_RING_DEGREE: usize = SMALL_RING_DEGREE * 64;
const COMMITTED_RESIDUAL_LOW_DEGREE_LAYER_RING_DEGREE: usize = SMALL_RING_DEGREE * 128;

#[test]
fn proof_codec_round_trips_and_rejects_malformed_bytes() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "c0dec0de",
        &[round_one(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let bytes = encode_trustee_evaluation_key_proof(&proof);
    let decoded = decode_trustee_evaluation_key_proof(&statement, &bytes)
        .expect("decode canonical proof bytes");
    verify_evaluation_key_share(&statement, &decoded).expect("verify decoded proof");

    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(
        decode_trustee_evaluation_key_proof(&statement, &trailing).is_err(),
        "trailing bytes must reject"
    );
    let truncated = &bytes[..bytes.len() - 1];
    assert!(
        decode_trustee_evaluation_key_proof(&statement, truncated).is_err(),
        "truncated bytes must reject"
    );
    let mut flipped = bytes.clone();
    let flip_position = bytes.len() / 2;
    flipped[flip_position] ^= 1;
    let tampered = decode_trustee_evaluation_key_proof(&statement, &flipped);
    if let Ok(tampered_proof) = tampered {
        assert!(
            verify_evaluation_key_share(&statement, &tampered_proof).is_err(),
            "a decoded bit-flipped proof must fail verification"
        );
    }
}

#[test]
fn proof_codec_rejects_nonzero_field_residue_padding() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "facecafe",
        &[round_one(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let mut bytes = encode_trustee_evaluation_key_proof(&proof);
    let (padding_byte, first_padding_bit) = first_field_residue_padding_bit(&statement, &proof)
        .expect("test proof must contain at least one padded field-residue slice");
    bytes[padding_byte] |= 1_u8 << first_padding_bit;

    let error = match decode_trustee_evaluation_key_proof(&statement, &bytes) {
        Ok(_) => panic!("nonzero field-residue padding must reject"),
        Err(error) => error,
    };
    assert!(
        error.message.contains("noncanonical field-residue padding"),
        "unexpected padding error: {}",
        error.message
    );
}

fn first_field_residue_padding_bit(
    statement: &TrusteeEvaluationKeyStatement,
    proof: &super::prover::SuccinctEvaluationKeyProof,
) -> Option<(usize, usize)> {
    let mut cursor = 8 + 8;
    for (limb_index, limb_proof) in statement
        .proof_limb_indices()
        .into_iter()
        .zip(&proof.limb_proofs)
    {
        let layout = LimbColumnLayout::new(statement, limb_index).expect("limb layout");
        let total_columns = layout.phase_one_physical_count() + PHASE_TWO_COLUMN_COUNT;
        cursor += 2 * MERKLE_DIGEST_BYTES;
        if let Some(padding) = field_residue_padding_bit(cursor, layout.claim_count()) {
            return Some(padding);
        }
        cursor += field_residue_slice_byte_count(layout.claim_count());
        for _ in &limb_proof.deep_evaluations {
            if let Some(padding) =
                field_residue_padding_bit(cursor, total_columns * CHALLENGE_EXTENSION_DEGREE)
            {
                return Some(padding);
            }
            cursor += extension_slice_byte_count(total_columns);
        }
        cursor += low_degree_proof_byte_count(&limb_proof.low_degree);
        cursor += low_degree_proof_byte_count(&limb_proof.sumcheck_residual_low_degree);
        for opening in &limb_proof.query_openings {
            for slot in 0..2 {
                if let Some(padding) =
                    field_residue_padding_bit(cursor, opening.phase_one_rows[slot].len())
                {
                    return Some(padding);
                }
                cursor += field_residue_slice_byte_count(opening.phase_one_rows[slot].len());
            }
            cursor += LEAF_SALT_BYTES;
            for slot in 0..2 {
                if let Some(padding) =
                    field_residue_padding_bit(cursor, opening.phase_two_rows[slot].len())
                {
                    return Some(padding);
                }
                cursor += field_residue_slice_byte_count(opening.phase_two_rows[slot].len());
            }
            cursor += LEAF_SALT_BYTES;
        }
        cursor += batched_opening_byte_count(&limb_proof.witness_batch_opening);
        cursor += batched_opening_byte_count(&limb_proof.quotient_batch_opening);
    }

    None
}

fn field_residue_padding_bit(start: usize, residue_count: usize) -> Option<(usize, usize)> {
    let bit_count = residue_count * FIELD_RESIDUE_BIT_WIDTH;
    let used_bits_in_final_byte = bit_count % 8;
    (used_bits_in_final_byte != 0).then(|| {
        (
            start + field_residue_slice_byte_count(residue_count) - 1,
            used_bits_in_final_byte,
        )
    })
}

fn field_residue_slice_byte_count(residue_count: usize) -> usize {
    (residue_count * FIELD_RESIDUE_BIT_WIDTH).div_ceil(8)
}

fn extension_slice_byte_count(element_count: usize) -> usize {
    field_residue_slice_byte_count(element_count * CHALLENGE_EXTENSION_DEGREE)
}

fn low_degree_proof_byte_count(proof: &super::super::low_degree_proof::LowDegreeProof) -> usize {
    let mut byte_count = 8;
    byte_count += proof.folded_layer_roots.len() * MERKLE_DIGEST_BYTES;
    byte_count += extension_slice_byte_count(proof.final_coefficients.len());
    for fold_index in 0..proof.folded_layer_roots.len() {
        byte_count += low_degree_sibling_table_byte_count(proof, fold_index);
    }
    for layer_opening in &proof.layer_batch_openings {
        byte_count += batched_opening_byte_count(layer_opening);
    }

    byte_count
}

fn low_degree_sibling_table_byte_count(
    proof: &super::super::low_degree_proof::LowDegreeProof,
    fold_index: usize,
) -> usize {
    let mut table = Vec::new();
    for query_opening in &proof.query_openings {
        let sibling = query_opening.folded_layer_siblings[fold_index].sibling;
        if !table.contains(&sibling) {
            table.push(sibling);
        }
    }
    let compressed_sibling_bytes = extension_slice_byte_count(table.len())
        + low_degree_sibling_reference_byte_count(table.len());
    let raw_sibling_bytes = extension_slice_byte_count(LOW_DEGREE_QUERY_COUNT);
    let sibling_payload_bytes =
        if table.len() < LOW_DEGREE_QUERY_COUNT && compressed_sibling_bytes < raw_sibling_bytes {
            compressed_sibling_bytes
        } else {
            raw_sibling_bytes
        };

    8 + sibling_payload_bytes
}

fn low_degree_sibling_reference_byte_count(table_count: usize) -> usize {
    LOW_DEGREE_QUERY_COUNT
        .checked_mul(low_degree_sibling_reference_bit_width(table_count))
        .expect("low-degree sibling reference bit count must fit usize")
        .div_ceil(8)
}

fn low_degree_sibling_reference_bit_width(table_count: usize) -> usize {
    if table_count <= 1 {
        0
    } else {
        usize::BITS as usize - (table_count - 1).leading_zeros() as usize
    }
}

fn batched_opening_byte_count(
    opening: &super::super::merkle_commitment::BatchedMerkleOpening,
) -> usize {
    8 + opening.authentication_nodes.len() * MERKLE_DIGEST_BYTES
}

#[test]
fn proof_codec_rejects_low_degree_shape_mismatches_before_verification() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "c0dec0de",
        &[round_one(2), rotation(3, 1)],
        COMMITTED_LOW_DEGREE_LAYER_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    proof.limb_proofs[0]
        .low_degree
        .folded_layer_roots
        .pop()
        .expect("at least one committed folded layer");
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let error = match decode_trustee_evaluation_key_proof(&statement, &encoded) {
        Ok(_) => panic!("wrong low-degree fold count must reject at decode"),
        Err(error) => error,
    };
    assert!(
        error
            .message
            .contains("low-degree committed fold count does not match the statement"),
        "unexpected low-degree fold-count error: {}",
        error.message
    );

    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "cafe0dd0",
        &[round_one(2), rotation(3, 1)],
        COMMITTED_RESIDUAL_LOW_DEGREE_LAYER_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    proof.limb_proofs[0]
        .sumcheck_residual_low_degree
        .folded_layer_roots
        .pop()
        .expect("at least one committed folded layer");
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let error = match decode_trustee_evaluation_key_proof(&statement, &encoded) {
        Ok(_) => panic!("wrong residual low-degree fold count must reject at decode"),
        Err(error) => error,
    };
    assert!(
        error
            .message
            .contains("low-degree committed fold count does not match the statement"),
        "unexpected residual low-degree fold-count error: {}",
        error.message
    );

    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "dec0ded0",
        &[round_one(2), rotation(3, 1)],
        COMMITTED_LOW_DEGREE_LAYER_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    // A batched folded-layer opening whose node count exceeds its per-layer
    // bound by one is rejected at decode, before any oversized allocation. The
    // bound mirrors the decoder: LOW_DEGREE_QUERY_COUNT openings over a layer of
    // the given depth.
    let layout = LimbColumnLayout::new(&statement, 0).expect("limb layout");
    let extension_size = layout.trace_size * DOMAIN_BLOWUP;
    let maximum_layer_zero_nodes =
        LOW_DEGREE_QUERY_COUNT * folded_layer_path_length(extension_size, 0);
    proof.limb_proofs[0].low_degree.layer_batch_openings[0]
        .authentication_nodes
        .resize(maximum_layer_zero_nodes + 1, [0_u8; MERKLE_DIGEST_BYTES]);
    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let error = match decode_trustee_evaluation_key_proof(&statement, &encoded) {
        Ok(_) => panic!("an oversized batched opening must reject at decode"),
        Err(error) => error,
    };
    assert!(
        error
            .message
            .contains("batched opening node count exceeds the statement bound"),
        "unexpected batched-opening error: {}",
        error.message
    );
}

fn assert_noncanonical_encoded_proof_rejects(
    label: &str,
    mutate_proof: impl FnOnce(&mut super::prover::SuccinctEvaluationKeyProof, u64),
) {
    assert_noncanonical_encoded_proof_rejects_for_ring(label, SMALL_RING_DEGREE, mutate_proof);
}

fn assert_noncanonical_encoded_proof_rejects_for_ring(
    label: &str,
    ring_degree: usize,
    mutate_proof: impl FnOnce(&mut super::prover::SuccinctEvaluationKeyProof, u64),
) {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "c0decafe",
        &[round_one(2), rotation(3, 1)],
        ring_degree,
        Some(3),
    )
    .expect("development instance");
    let mut proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let modulus = DATA_PRIMES[0];
    mutate_proof(&mut proof, modulus);
    let encoded = encode_trustee_evaluation_key_proof(&proof);

    assert!(
        decode_trustee_evaluation_key_proof(&statement, &encoded).is_err(),
        "{label} with a noncanonical residue must be rejected by the decoder"
    );
}

#[test]
fn proof_codec_rejects_noncanonical_values_in_every_encoded_area() {
    assert_noncanonical_encoded_proof_rejects("masked consistency claim", |proof, modulus| {
        proof.limb_proofs[0].masked_consistency_claims[0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects("deep evaluation coordinate", |proof, modulus| {
        proof.limb_proofs[0].deep_evaluations[0][0][0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects("phase-one query row", |proof, modulus| {
        proof.limb_proofs[0].query_openings[0].phase_one_rows[0][0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects("phase-two coordinate row", |proof, modulus| {
        proof.limb_proofs[0].query_openings[0].phase_two_rows[0][0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects("low-degree final coefficient", |proof, modulus| {
        proof.limb_proofs[0].low_degree.final_coefficients[0][0] = modulus;
    });
    assert_noncanonical_encoded_proof_rejects_for_ring(
        "low-degree folded opening",
        COMMITTED_LOW_DEGREE_LAYER_RING_DEGREE,
        |proof, modulus| {
            proof.limb_proofs[0].low_degree.query_openings[0].folded_layer_siblings[0].sibling[0] =
                modulus;
        },
    );
    assert_noncanonical_encoded_proof_rejects(
        "residual low-degree final coefficient",
        |proof, modulus| {
            proof.limb_proofs[0]
                .sumcheck_residual_low_degree
                .final_coefficients[0][0] = modulus;
        },
    );
}

#[test]
fn proof_codec_rejects_noncanonical_values_for_each_succinct_family_shape() {
    let family_cases = [
        generate_development_trustee_instance_with_linkage(
            "1111aaaa",
            &[],
            SMALL_RING_DEGREE,
            Some(DATA_PRIMES.len()),
        )
        .expect("same-secret anchor instance"),
        generate_development_public_key_share_instance("2222bbbb", SMALL_RING_DEGREE)
            .expect("public-key share instance"),
        generate_development_trustee_instance_with_linkage(
            "3333cccc",
            &[round_one(2), round_two(2), rotation(3, 1)],
            SMALL_RING_DEGREE,
            Some(3),
        )
        .expect("trustee evaluation-key instance"),
    ];

    for (statement, witness) in family_cases {
        let mut proof =
            prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
        proof.limb_proofs[0].masked_consistency_claims[0] = DATA_PRIMES[0];
        let encoded = encode_trustee_evaluation_key_proof(&proof);
        assert!(
            decode_trustee_evaluation_key_proof(&statement, &encoded).is_err(),
            "noncanonical proof bytes must reject for {}",
            statement.context.proof_family
        );
    }
}
