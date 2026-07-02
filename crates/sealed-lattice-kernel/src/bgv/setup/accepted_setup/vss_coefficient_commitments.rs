use super::*;

// The roster of expected trustees (roster position to trustee identity) read
// from the setup phase transcript. Setup phases that verify per-trustee records
// bind against this roster.
pub(super) fn expected_trustees_from_phase_transcript(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, String>> {
    let phase_transcript = setup_package
        .get("phaseTranscript")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phaseTranscript was required before setup phase verification",
            )
        })?;
    let Some(first_phase) = phase_transcript.first() else {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "phaseTranscript was required before setup phase verification",
        ));
    };
    let participants = first_phase
        .get("participantPhaseObjects")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phase participant objects were required before setup phase verification",
            )
        })?;
    let mut trustees = BTreeMap::new();
    for participant in participants {
        let Some(roster_position) = participant.get("rosterPosition").and_then(Value::as_u64)
        else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phase participant object must bind rosterPosition",
            ));
        };
        let Some(trustee_identity) = participant.get("trusteeIdentity").and_then(Value::as_str)
        else {
            return Err(CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "phase participant object must bind trusteeIdentity",
            ));
        };
        trustees.insert(roster_position, trustee_identity.to_string());
    }

    Ok(trustees)
}
