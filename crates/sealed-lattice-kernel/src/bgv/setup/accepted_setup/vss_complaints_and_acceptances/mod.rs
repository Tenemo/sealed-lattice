use super::*;

use crate::hashing::derive_canonical_object_hash;

pub(super) struct VssRecordVerificationContext<'a> {
    pub(super) setup_context: &'a Value,
    pub(super) expected_trustees: &'a BTreeMap<u64, String>,
    pub(super) trustee_registrations: &'a setup_intent::SetupIntentTrusteeRegistrationMap,
    pub(super) source_trustee_commitment_roots: &'a BTreeMap<u64, String>,
    pub(super) private_vss_envelope_commitment_root: &'a str,
    pub(super) private_vss_envelope_bindings: &'a PrivateVssEnvelopeBindingMap,
}

pub(super) fn source_trustee_commitment_roots_from_vss_commitments(
    setup_package: &Value,
) -> CanonicalResult<BTreeMap<u64, String>> {
    // Each source trustee is identified by its coefficient commitment set root:
    // the per-source-trustee root over that trustee's coefficient commitments,
    // which the private envelopes and share acceptances bind against.
    let (commitment_set_field, source_root_field) = (
        "vssPublicCoefficientCommitmentSet",
        "sourceCoefficientCommitmentRoot",
    );
    let source_trustee_records = setup_package
        .get(commitment_set_field)
        .and_then(|commitment_set| commitment_set.get("sourceTrusteeRecords"))
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CanonicalError::new(
                CanonicalErrorCode::InvalidFixture,
                "VSS source trustee commitments were required before VSS share acceptance verification",
            )
        })?;
    let mut source_trustee_roots = BTreeMap::new();
    for source_trustee_record in source_trustee_records {
        let source_trustee_roster_position = source_trustee_record
            .get("sourceTrusteeRosterPosition")
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "source trustee VSS commitment record must bind sourceTrusteeRosterPosition",
                )
            })?;
        let source_trustee_commitment_root = source_trustee_record
            .get(source_root_field)
            .and_then(Value::as_str)
            .ok_or_else(|| {
                CanonicalError::new(
                    CanonicalErrorCode::InvalidFixture,
                    "source trustee VSS commitment record must bind its per-trustee coefficient commitment root",
                )
            })?;
        source_trustee_roots.insert(
            source_trustee_roster_position,
            source_trustee_commitment_root.to_string(),
        );
    }

    Ok(source_trustee_roots)
}

mod acceptances;
mod complaints;

pub(super) use acceptances::verify_vss_share_acceptances;
pub(super) use complaints::verify_vss_complaints;
