use crate::{
    foundation::Hash512,
    tally_circuit::{CompiledTallyCircuit, TallyCircuitProfile},
};

use super::{
    BinaryFieldElement256, TallyPreparationContext, TallyPreparationError,
    authenticated_key_share_vector::{
        AuthenticatedKeyShareVectorDescriptor, AuthenticatedKeyShareVectorDescriptorBuilder,
    },
    authenticated_key_share_vector_codeword_check::AuthenticatedKeyShareVectorCodewordCheck,
    authenticated_key_share_vector_codeword_manifest::AuthenticatedKeyShareVectorCodewordManifest,
    output_sharing::canonical_evaluation_point,
};

const INCONSISTENT_FIELD_MARKER: u16 = 0xa55a;

#[test]
fn streamed_codeword_check_requires_every_roster_point_and_reconstructs_every_chunk() {
    let circuit = circuit(9, 2, 1);
    let context = preparation_context(0x21, &circuit);
    let holder_commitment_root = hash(0x32);
    let fixture = codeword_fixture(context, &circuit, holder_commitment_root, None);
    let manifest = AuthenticatedKeyShareVectorCodewordManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &fixture.descriptors,
    )
    .unwrap();

    let incomplete_check = AuthenticatedKeyShareVectorCodewordCheck::begin(
        context,
        &circuit,
        holder_commitment_root,
        &manifest,
        &fixture.descriptors,
    )
    .unwrap();
    assert!(matches!(
        incomplete_check.finish(),
        Err(
            TallyPreparationError::AuthenticatedKeyShareVectorCodewordCheckIncomplete {
                checked_chunk_count: 0,
                checked_field_count: 0,
                absorbed_sender_count: 0,
                ..
            }
        )
    ));

    let mut check = AuthenticatedKeyShareVectorCodewordCheck::begin(
        context,
        &circuit,
        holder_commitment_root,
        &manifest,
        &fixture.descriptors,
    )
    .unwrap();
    let mut expected_first_field_index = 0_u64;
    for chunk_index in 0..fixture.chunk_count() {
        check
            .absorb_next_payload_chunk(&fixture.payloads[0][chunk_index])
            .unwrap();
        assert!(matches!(
            check.finalize_current_chunk(),
            Err(
                TallyPreparationError::AuthenticatedKeyShareVectorCodewordChunkIncomplete {
                    expected_sender_count: 9,
                    absorbed_sender_count: 1,
                }
            )
        ));
        for sender_position in 1..fixture.payloads.len() {
            check
                .absorb_next_payload_chunk(&fixture.payloads[sender_position][chunk_index])
                .unwrap();
        }
        assert!(matches!(
            check.absorb_next_payload_chunk(&fixture.payloads[0][chunk_index]),
            Err(
                TallyPreparationError::AuthenticatedKeyShareVectorCodewordChunkAwaitingFinalization
            )
        ));
        let checked_chunk = check.finalize_current_chunk().unwrap();
        assert_eq!(
            checked_chunk.first_field_index(),
            expected_first_field_index
        );
        let reconstructed_fields = checked_chunk.reconstructed_fields();
        assert!(!reconstructed_fields.is_empty());
        assert_eq!(
            reconstructed_fields[0],
            fixture.expected_first_constants[chunk_index]
        );
        if reconstructed_fields.len() > 2 {
            assert_eq!(
                reconstructed_fields[reconstructed_fields.len() / 2],
                fixture.expected_middle_constant
            );
        }
        assert_eq!(
            reconstructed_fields[reconstructed_fields.len() - 1],
            fixture.expected_last_constants[chunk_index]
        );
        expected_first_field_index += reconstructed_fields.len() as u64;
    }
    assert_eq!(expected_first_field_index, manifest.total_field_count());
    assert!(matches!(
        check.absorb_next_payload_chunk(&fixture.payloads[0][fixture.chunk_count() - 1]),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorCodewordCheckAlreadyComplete)
    ));
    check.finish().unwrap();
}

#[test]
fn codeword_check_rejects_bound_nonbasis_and_basis_inconsistency() {
    let circuit = circuit(9, 2, 1);
    let context = preparation_context(0x22, &circuit);
    let holder_commitment_root = hash(0x33);

    let inconsistent_nonbasis_fixture =
        codeword_fixture(context, &circuit, holder_commitment_root, Some(8));
    let manifest = AuthenticatedKeyShareVectorCodewordManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &inconsistent_nonbasis_fixture.descriptors,
    )
    .unwrap();
    let mut check = AuthenticatedKeyShareVectorCodewordCheck::begin(
        context,
        &circuit,
        holder_commitment_root,
        &manifest,
        &inconsistent_nonbasis_fixture.descriptors,
    )
    .unwrap();
    for sender_position in 0..8 {
        check
            .absorb_next_payload_chunk(&inconsistent_nonbasis_fixture.payloads[sender_position][0])
            .unwrap();
    }
    assert_eq!(
        check.absorb_next_payload_chunk(&inconsistent_nonbasis_fixture.payloads[8][0]),
        Err(TallyPreparationError::InconsistentShare { roster_position: 8 })
    );
    assert_eq!(
        check.absorb_next_payload_chunk(&inconsistent_nonbasis_fixture.payloads[8][0]),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorCodewordCheckFailed)
    );

    let inconsistent_basis_fixture =
        codeword_fixture(context, &circuit, holder_commitment_root, Some(2));
    let manifest = AuthenticatedKeyShareVectorCodewordManifest::derive(
        context,
        &circuit,
        holder_commitment_root,
        &inconsistent_basis_fixture.descriptors,
    )
    .unwrap();
    let mut check = AuthenticatedKeyShareVectorCodewordCheck::begin(
        context,
        &circuit,
        holder_commitment_root,
        &manifest,
        &inconsistent_basis_fixture.descriptors,
    )
    .unwrap();
    for sender_position in 0..4 {
        check
            .absorb_next_payload_chunk(&inconsistent_basis_fixture.payloads[sender_position][0])
            .unwrap();
    }
    assert_eq!(
        check.absorb_next_payload_chunk(&inconsistent_basis_fixture.payloads[4][0]),
        Err(TallyPreparationError::InconsistentShare { roster_position: 4 })
    );
}

#[test]
fn codeword_check_rejects_payload_mutation_wrong_source_and_non_degree_three_profile() {
    let compiled_circuit = circuit(9, 2, 1);
    let context = preparation_context(0x23, &compiled_circuit);
    let holder_commitment_root = hash(0x34);
    let fixture = codeword_fixture(context, &compiled_circuit, holder_commitment_root, None);
    let manifest = AuthenticatedKeyShareVectorCodewordManifest::derive(
        context,
        &compiled_circuit,
        holder_commitment_root,
        &fixture.descriptors,
    )
    .unwrap();
    let mut check = AuthenticatedKeyShareVectorCodewordCheck::begin(
        context,
        &compiled_circuit,
        holder_commitment_root,
        &manifest,
        &fixture.descriptors,
    )
    .unwrap();
    let mut mutated_payload = fixture.payloads[0][0].clone();
    let mutated_payload_position = mutated_payload.len() / 2;
    mutated_payload[mutated_payload_position] ^= 1;
    assert_eq!(
        check.absorb_next_payload_chunk(&mutated_payload),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorPayloadDigestMismatch)
    );
    assert!(matches!(
        AuthenticatedKeyShareVectorCodewordCheck::begin(
            context,
            &compiled_circuit,
            hash(0x35),
            &manifest,
            &fixture.descriptors,
        ),
        Err(TallyPreparationError::AuthenticatedKeyShareVectorSourceMismatch)
    ));

    let non_degree_three_circuit = circuit(8, 2, 1);
    let non_degree_three_context = preparation_context(0x24, &non_degree_three_circuit);
    let non_degree_three_fixture = codeword_fixture(
        non_degree_three_context,
        &non_degree_three_circuit,
        holder_commitment_root,
        None,
    );
    let non_degree_three_manifest = AuthenticatedKeyShareVectorCodewordManifest::derive(
        non_degree_three_context,
        &non_degree_three_circuit,
        holder_commitment_root,
        &non_degree_three_fixture.descriptors,
    )
    .unwrap();
    assert!(matches!(
        AuthenticatedKeyShareVectorCodewordCheck::begin(
            non_degree_three_context,
            &non_degree_three_circuit,
            holder_commitment_root,
            &non_degree_three_manifest,
            &non_degree_three_fixture.descriptors,
        ),
        Err(
            TallyPreparationError::AuthenticatedKeyReleaseProfileMismatch {
                participant_count: 8,
                derived_reconstruction_threshold: 3,
                supported_reconstruction_threshold: 4,
            }
        )
    ));
}

struct CodewordFixture {
    descriptors: Vec<AuthenticatedKeyShareVectorDescriptor>,
    payloads: Vec<Vec<Vec<u8>>>,
    expected_middle_constant: BinaryFieldElement256,
    expected_first_constants: Vec<BinaryFieldElement256>,
    expected_last_constants: Vec<BinaryFieldElement256>,
}

impl CodewordFixture {
    fn chunk_count(&self) -> usize {
        self.payloads[0].len()
    }
}

fn codeword_fixture(
    context: TallyPreparationContext,
    circuit: &CompiledTallyCircuit,
    holder_commitment_root: Hash512,
    inconsistent_sender_position: Option<u16>,
) -> CodewordFixture {
    let participant_count = circuit.profile().participant_count();
    let middle_coefficients = polynomial_coefficients(0x0135);
    let expected_middle_constant = middle_coefficients[0];
    let mut descriptors = Vec::with_capacity(usize::from(participant_count));
    let mut payloads = Vec::with_capacity(usize::from(participant_count));
    let mut expected_first_constants = Vec::new();
    let mut expected_last_constants = Vec::new();

    for sender_position in 0..participant_count {
        let evaluation_point =
            canonical_evaluation_point(participant_count, sender_position).unwrap();
        let middle_value = evaluate_polynomial(middle_coefficients, evaluation_point);
        let mut builder = AuthenticatedKeyShareVectorDescriptorBuilder::new(
            context,
            circuit,
            holder_commitment_root,
            sender_position,
        )
        .unwrap();
        let mut sender_payloads =
            Vec::with_capacity(usize::try_from(builder.chunk_count()).unwrap());
        for chunk_index in 0..builder.chunk_count() {
            let first_coefficients = polynomial_coefficients(
                0x0200_u16
                    .checked_add(u16::try_from(chunk_index).unwrap())
                    .unwrap(),
            );
            let last_coefficients = polynomial_coefficients(
                0x0300_u16
                    .checked_add(u16::try_from(chunk_index).unwrap())
                    .unwrap(),
            );
            if sender_position == 0 {
                expected_first_constants.push(first_coefficients[0]);
                expected_last_constants.push(last_coefficients[0]);
            }
            let payload_byte_length =
                usize::try_from(builder.expected_next_payload_byte_length().unwrap()).unwrap();
            let mut payload = middle_value
                .canonical_bytes()
                .repeat(payload_byte_length / BinaryFieldElement256::CANONICAL_BYTE_LENGTH);
            let first_value =
                if inconsistent_sender_position == Some(sender_position) && chunk_index == 0 {
                    BinaryFieldElement256::from_low_polynomial_u16(INCONSISTENT_FIELD_MARKER)
                } else {
                    evaluate_polynomial(first_coefficients, evaluation_point)
                };
            payload[..BinaryFieldElement256::CANONICAL_BYTE_LENGTH]
                .copy_from_slice(&first_value.canonical_bytes());
            let last_value = evaluate_polynomial(last_coefficients, evaluation_point);
            let last_field_start = payload.len() - BinaryFieldElement256::CANONICAL_BYTE_LENGTH;
            payload[last_field_start..].copy_from_slice(&last_value.canonical_bytes());
            builder.absorb_next_payload_chunk(&payload).unwrap();
            sender_payloads.push(payload);
        }
        descriptors.push(builder.finish().unwrap());
        payloads.push(sender_payloads);
    }

    CodewordFixture {
        descriptors,
        payloads,
        expected_middle_constant,
        expected_first_constants,
        expected_last_constants,
    }
}

fn polynomial_coefficients(marker: u16) -> [BinaryFieldElement256; 4] {
    core::array::from_fn(|coefficient_position| {
        BinaryFieldElement256::from_low_polynomial_u16(
            marker
                .checked_add(u16::try_from(coefficient_position).unwrap())
                .unwrap(),
        )
    })
}

fn evaluate_polynomial(
    coefficients: [BinaryFieldElement256; 4],
    evaluation_point: BinaryFieldElement256,
) -> BinaryFieldElement256 {
    coefficients
        .into_iter()
        .rev()
        .fold(BinaryFieldElement256::ZERO, |value, coefficient| {
            value.multiply(evaluation_point).add(coefficient)
        })
}

fn preparation_context(marker: u8, circuit: &CompiledTallyCircuit) -> TallyPreparationContext {
    TallyPreparationContext::new(
        hash(marker),
        hash(marker.wrapping_add(1)),
        [marker.wrapping_add(2); 32],
        circuit,
    )
    .unwrap()
}

fn hash(marker: u8) -> Hash512 {
    Hash512::from_bytes([marker; Hash512::BYTE_LENGTH])
}

fn circuit(participant_count: u16, option_count: u16, top_count: u16) -> CompiledTallyCircuit {
    CompiledTallyCircuit::compile(
        TallyCircuitProfile::new(participant_count, option_count, top_count).unwrap(),
    )
    .unwrap()
}
