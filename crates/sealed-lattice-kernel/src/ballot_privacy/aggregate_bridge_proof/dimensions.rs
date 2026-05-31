use super::validation::{read_u64_object_field, read_usize_object_field};
use super::*;

#[derive(Debug)]
pub(super) struct BridgeVariantDimensions {
    pub(super) participant_count: u64,
    pub(super) option_count: u64,
    pub(super) share_vector_width: usize,
    pub(super) claim_tier: &'static str,
    pub(super) evidence_tier: &'static str,
}

// The only (participantCount, optionCount) shapes with checked-in row evidence; any other
// shape is flagged full-matrix-row-evidence-missing below (downgraded, not rejected).
const REPRESENTATIVE_EVIDENCE_VARIANTS: &[(u64, u64)] = &[
    (3, 2),
    (3, 20),
    (4, 2),
    (9, 20),
    (10, 2),
    (10, 20),
    (16, 2),
    (16, 20),
    (20, 2),
    (20, 20),
];

pub(super) fn bridge_variant_dimensions(
    statement: &Value,
) -> CanonicalResult<BridgeVariantDimensions> {
    let participant_count = read_u64_object_field(
        statement,
        "participantCount",
        "aggregateDerivationStatement",
    )?;
    let option_count =
        read_u64_object_field(statement, "optionCount", "aggregateDerivationStatement")?;
    let share_vector_width = read_usize_object_field(
        statement,
        "shareVectorWidth",
        "aggregateDerivationStatement",
    )?;
    // IMPORTANT: the bridge caps participants at 20 (MANDATORY_RECEIVER_COUNT) while the
    // aggregate-derivation statement allows up to MAXIMUM_PARTICIPANT_COUNT (50). This narrower
    // bound is intentional for the encrypted aggregate bridge profile, not a bug.
    let maximum_bridge_participant_count = u64::try_from(BALLOT_PRIVACY_MANDATORY_RECEIVER_COUNT)
        .map_err(|_| {
        CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "Encrypted aggregate bridge maximum participant count does not fit u64",
        )
    })?;
    if participant_count < BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT as u64
        || participant_count > maximum_bridge_participant_count
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge participantCount must be within the n=3..20 variant matrix",
        ));
    }
    if option_count < BALLOT_PRIVACY_MINIMUM_OPTION_COUNT as u64
        || option_count > BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT as u64
    {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge optionCount must be within the m=2..20 variant matrix",
        ));
    }
    let expected_share_vector_width = option_count
        .checked_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::MalformedLength,
                "encrypted aggregate bridge shareVectorWidth calculation overflowed",
            )
        })?;
    if u64::try_from(share_vector_width).ok() != Some(expected_share_vector_width) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::ProfileComponentMismatch,
            "encrypted aggregate bridge shareVectorWidth must equal 11 * optionCount",
        ));
    }
    // 3..9 participants are accepted structurally but fall outside the privacy claim (anonymity
    // set too small); this tier ties to the casualMicroRosterAcknowledged acknowledgement.
    let claim_tier = if participant_count < BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT as u64 {
        "micro-roster-outside-claim"
    } else {
        "claim-candidate"
    };
    let evidence_tier =
        if REPRESENTATIVE_EVIDENCE_VARIANTS.contains(&(participant_count, option_count)) {
            "representative-row-evidence"
        } else {
            "full-matrix-row-evidence-missing"
        };

    Ok(BridgeVariantDimensions {
        participant_count,
        option_count,
        share_vector_width,
        claim_tier,
        evidence_tier,
    })
}
