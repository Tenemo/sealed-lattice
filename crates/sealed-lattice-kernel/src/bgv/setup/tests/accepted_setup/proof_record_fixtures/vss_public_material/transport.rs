use super::*;

#[test]
fn structural_vss_bindings_do_not_bypass_the_common_proof_gate() {
    let finalized_fixture = structural_vss_public_material_fixture();
    let package = finalized_fixture;
    let participant_count = usize::try_from(participant_count_from_package(&package))
        .expect("participant count fits usize");
    let trustee_identities = (0..participant_count)
        .map(|roster_position| format!("trustee-{roster_position}"))
        .collect::<Vec<_>>();
    let request = serde_json::json!({
        "statement": package["vssShareLinkageStatement"],
        "coefficientCommitmentSet": package["vssPublicCoefficientCommitmentSet"],
        "recipientShareCommitmentSet": package["vssPublicRecipientShareCommitmentSet"],
        "aggregateThresholdCommitmentSet": package["vssPublicAggregateThresholdCommitmentSet"],
        "proofMaterialSet": package["vssShareLinkageProofMaterialSet"],
    });
    crate::bgv::setup::vss_commitment::verify_vss_share_linkage_bindings_request(
        &request,
        &trustee_identities,
    )
    .expect("VSS structural bindings verify before the proof gate");

    let setup_context_hash =
        crate::bgv::setup::accepted_setup::setup_context_hash(&package["setupContext"])
            .expect("setup context hash");
    let public_matrix_seed_hash = package["commonRandomness"]["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let common_proof_gate_error =
        crate::bgv::setup::vss_commitment::verify_vss_public_aggregate_threshold_proofs(
            None,
            &package["vssPublicCoefficientCommitmentSet"],
            &package["vssPublicRecipientShareCommitmentSet"],
            &package["vssPublicAggregateThresholdCommitmentSet"],
            &crate::bgv::setup::vss_commitment::VssAggregateThresholdProofContext {
                setup_context_hash,
                public_matrix_seed_hash,
                ring_degree: vss_commitment_ring_degree_from_fixture_package(&package),
                participant_count,
                rns_limb_count: DATA_PRIMES.len(),
                trustee_identities: &trustee_identities,
            },
        )
        .expect_err("structural aggregate bindings must not satisfy proof acceptance");
    assert_eq!(
        common_proof_gate_error.code,
        crate::encoding::CanonicalErrorCode::InvalidProtocolObject,
    );
    assert_eq!(
        common_proof_gate_error.message,
        "aggregate threshold-share acceptance requires verification by the common proof suite",
    );

    assert_tampered_canonical_stream_chunk_is_refused(
        crate::foundation::CanonicalStreamDomain::DealerVssShareLinkageProof,
        &vec![0x5a; crate::foundation::FOUNDATION_PROFILE.stream_chunk_byte_length + 1],
    );
}

#[test]
fn same_secret_proof_stream_rejects_a_tampered_chunk() {
    assert_tampered_canonical_stream_chunk_is_refused(
        crate::foundation::CanonicalStreamDomain::SameSecretProof,
        &vec![0xa5; crate::foundation::FOUNDATION_PROFILE.stream_chunk_byte_length + 1],
    );
}

fn assert_tampered_canonical_stream_chunk_is_refused(
    stream_domain: crate::foundation::CanonicalStreamDomain,
    proof_bytes: &[u8],
) {
    use crate::foundation::{
        CanonicalStreamVerifier, FOUNDATION_PROFILE, RefusalReason, VerificationResult,
        derive_canonical_stream_descriptor,
    };

    let descriptor = derive_canonical_stream_descriptor(stream_domain, proof_bytes)
        .expect("canonical proof stream descriptor");
    let mut verifier =
        CanonicalStreamVerifier::new(stream_domain, descriptor).expect("canonical stream verifier");
    let first_chunk_length = proof_bytes
        .len()
        .min(FOUNDATION_PROFILE.stream_chunk_byte_length);
    let mut tampered_chunk = proof_bytes[..first_chunk_length].to_vec();
    tampered_chunk[0] ^= 1;
    assert_eq!(
        verifier.absorb_chunk(0, &tampered_chunk),
        VerificationResult::refused(RefusalReason::WrongHashOrRoot),
        "canonical stream authentication must reject tampered proof bytes",
    );
}
