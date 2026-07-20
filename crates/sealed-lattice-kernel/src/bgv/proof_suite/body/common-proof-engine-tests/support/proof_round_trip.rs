use super::*;
use crate::foundation::ParticipantIdentity;

#[test]
fn complete_common_proof_engine_round_trip_binds_proof_statement_and_verified_source_root() {
    let mut fixture = common_proof_engine_fixture();
    let verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        None,
        fixture.schedule_position,
        fixture.top_count,
    );
    let proof_bytes = generate_fixture_proof(&mut fixture);

    let verified_proof = verify_fixture_proof_capability(
        &fixture,
        &proof_bytes,
        &fixture.canonical_application_statement_bytes,
        &verified_trees,
    )
    .expect("the complete generated proof verifies");
    assert_eq!(
        verified_proof.application_statement_schema_identifier(),
        APPLICATION_STATEMENT_SCHEMA_IDENTIFIER
    );
    assert_eq!(verified_proof.schedule_position(), None);
    assert_eq!(verified_proof.top_count(), None);
    assert_ne!(verified_proof.application_statement_hash(), [0_u8; 64]);
    assert_ne!(verified_proof.relation_plan_variant_hash(), [0_u8; 64]);

    let incrementally_verified_proof =
        verify_fixture_proof_incrementally(&fixture, &proof_bytes, &verified_trees)
            .expect("the same proof verifies across changing two-chunk resident windows");
    assert_eq!(
        incrementally_verified_proof.application_statement_hash(),
        verified_proof.application_statement_hash(),
    );
    assert_eq!(
        incrementally_verified_proof.relation_plan_variant_hash(),
        verified_proof.relation_plan_variant_hash(),
    );

    let header_byte_length =
        canonical_proof_object_header_bytes(&fixture.canonical_application_statement_bytes)
            .expect("the canonical proof header encodes")
            .len();
    let mut changed_proof_bytes = proof_bytes.clone();
    changed_proof_bytes[header_byte_length] ^= 1;
    assert!(
        verify_fixture_proof(
            &fixture,
            &changed_proof_bytes,
            &fixture.canonical_application_statement_bytes,
            &verified_trees,
        )
        .is_err(),
        "a changed proof-body root must fail closed",
    );

    let mut changed_statement_roots = fixture
        .setup_polynomial_trees
        .iter()
        .map(SetupPublicPolynomialTree::root)
        .collect::<Vec<_>>();
    changed_statement_roots[0][0] ^= 1;
    let changed_statement = canonical_collective_public_key_statement(&changed_statement_roots);
    assert_eq!(
        verify_fixture_proof(&fixture, &proof_bytes, &changed_statement, &verified_trees,),
        Err(CommonProofVerifierError::InvalidProofHeader),
    );

    let changed_source_tree = test_setup_polynomial_tree(0, 8);
    assert_ne!(
        changed_source_tree.root(),
        fixture.setup_polynomial_trees[0].root(),
        "a changed public-polynomial body must recompute a different LDE root",
    );
    let changed_verified_trees = verified_statement_trees(
        &fixture.relation_plan,
        &fixture.setup_polynomial_trees,
        Some(&changed_source_tree),
        fixture.schedule_position,
        fixture.top_count,
    );
    assert!(
        verify_fixture_proof(
            &fixture,
            &proof_bytes,
            &fixture.canonical_application_statement_bytes,
            &changed_verified_trees,
        )
        .is_err(),
        "a public-polynomial body/root mismatch must fail the statement binding",
    );
}

pub(super) fn verified_fixture_proof_stream(proof_bytes: &[u8]) -> VerifiedCanonicalStreamSummary {
    let stream_domain = CanonicalStreamDomain::CollectivePublicKeyAggregateProof;
    let descriptor = derive_canonical_stream_descriptor(stream_domain, proof_bytes)
        .expect("the complete fixture proof derives a canonical descriptor");
    let mut verifier = CanonicalStreamVerifier::new(stream_domain, descriptor)
        .expect("the fixture descriptor starts a stream verifier");
    for (chunk_index, chunk) in proof_bytes
        .chunks(FOUNDATION_PROFILE.stream_chunk_byte_length)
        .enumerate()
    {
        assert!(
            verifier.absorb_chunk(chunk_index, chunk).is_valid(),
            "every fixture chunk must match the derived descriptor",
        );
    }
    verifier
        .finish_with_summary()
        .into_result()
        .expect("the complete fixture stream mints its terminal summary")
}

pub(super) fn authenticated_storage_head_source(
    namespace_sequence: u64,
    authenticated_head_digest: [u8; 64],
    storage_instance_identity: [u8; 64],
) -> BrowserWorkerAuthenticatedStorageHeadSource {
    authenticated_storage_head_source_with_binding(
        LocalStorageBinding::new(
            Hash512::from_bytes([0x11; 64]),
            Hash512::from_bytes([0x32; 64]),
            Hash512::from_bytes([0x31; 64]),
            ParticipantIdentity::from_bytes([0x91; 64]),
        ),
        [0x92; 64],
        namespace_sequence,
        authenticated_head_digest,
        storage_instance_identity,
    )
}

pub(super) fn authenticated_storage_head_source_with_binding(
    local_storage_binding: LocalStorageBinding,
    storage_root_commitment: [u8; 64],
    namespace_sequence: u64,
    authenticated_head_digest: [u8; 64],
    storage_instance_identity: [u8; 64],
) -> BrowserWorkerAuthenticatedStorageHeadSource {
    BrowserWorkerAuthenticatedStorageHeadSource::from_test_fixture(
        local_storage_binding,
        Hash512::from_bytes(storage_root_commitment),
        namespace_sequence,
        Hash512::from_bytes(authenticated_head_digest),
        Hash512::from_bytes(storage_instance_identity),
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authenticated_storage_transition_source(
    local_storage_binding: LocalStorageBinding,
    storage_root_commitment: [u8; 64],
    predecessor_namespace_sequence: u64,
    predecessor_authenticated_head_digest: [u8; 64],
    successor_namespace_sequence: u64,
    successor_authenticated_head_digest: [u8; 64],
    storage_instance_identity: [u8; 64],
    authenticated_record_digest: [u8; 64],
) -> BrowserWorkerAuthenticatedStorageTransitionSource {
    BrowserWorkerAuthenticatedStorageTransitionSource::from_test_fixture(
        local_storage_binding,
        Hash512::from_bytes(storage_root_commitment),
        predecessor_namespace_sequence,
        Hash512::from_bytes(predecessor_authenticated_head_digest),
        successor_namespace_sequence,
        Hash512::from_bytes(successor_authenticated_head_digest),
        Hash512::from_bytes(storage_instance_identity),
        Hash512::from_bytes(authenticated_record_digest),
    )
}
