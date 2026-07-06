//! Direct encrypted ballot accepted-setup handoff consumer.
//!
//! SL3 Phase A: the accepted ballot path consumes only the verifier-produced
//! `CollectiveBgvAcceptedSetupHandoff`, never the passive development package or
//! a private setup seed. This module recomputes the handoff root over the
//! received object and compares it to the bound root (so a tampered handoff is
//! refused), then extracts the fields the ballot statement binds: the five-field
//! setup context, the setup package hash, and the collective public-key root.
//! Refusals are typed; there are no forbidden-field scanners, because acceptance
//! is by positive recomputation and the extracted fields are exactly what the
//! statement binds.

use serde_json::Value;

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};
use crate::hashing::derive_canonical_object_hash;

const ACCEPTED_SETUP_HANDOFF_OBJECT_TYPE: &str = "CollectiveBgvAcceptedSetupHandoff";
const ACCEPTED_SETUP_HANDOFF_OBJECT_VERSION: u64 = 1;
const ACCEPTED_SETUP_HANDOFF_ROOT_FIELD: &str = "acceptedSetupHandoffRoot";

fn invalid_handoff(message: &str) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

fn required_string(value: &Value, field_name: &str) -> CanonicalResult<String> {
    value
        .get(field_name)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            invalid_handoff(&format!(
                "accepted setup handoff is missing the string field {field_name}"
            ))
        })
}

// The ballot-relevant bindings extracted from a verified accepted-setup
// handoff. The ballot statement binds the setup package hash and the collective
// public-key root; the five-field context ties the handoff to the ceremony.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) struct AcceptedSetupHandoffBinding {
    pub(super) ceremony_id: String,
    pub(super) manifest_hash: String,
    pub(super) roster_hash: String,
    pub(super) setup_parameters_hash: String,
    pub(super) setup_epoch: String,
    pub(super) setup_package_hash: String,
    pub(super) collective_public_key_root: String,
}

// Consume a `CollectiveBgvAcceptedSetupHandoff`: check the object type and
// version, recompute the handoff root over every other field and compare it to
// the bound root (so a handoff whose any field was altered after the accepted
// verifier produced it is refused), then extract the ballot bindings. The
// passive development package and private setup seed are not inputs; a caller
// that supplies one of those objects instead of a handoff fails the object-type
// check.
#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn consume_accepted_setup_handoff(
    handoff: &Value,
) -> CanonicalResult<AcceptedSetupHandoffBinding> {
    let object = handoff
        .as_object()
        .ok_or_else(|| invalid_handoff("accepted setup handoff must be a JSON object"))?;
    if handoff.get("objectType").and_then(Value::as_str)
        != Some(ACCEPTED_SETUP_HANDOFF_OBJECT_TYPE)
    {
        return Err(invalid_handoff(
            "accepted setup handoff objectType must be CollectiveBgvAcceptedSetupHandoff",
        ));
    }
    if handoff.get("objectVersion").and_then(Value::as_u64)
        != Some(ACCEPTED_SETUP_HANDOFF_OBJECT_VERSION)
    {
        return Err(invalid_handoff(
            "accepted setup handoff objectVersion is not the supported version",
        ));
    }

    let bound_root = required_string(handoff, ACCEPTED_SETUP_HANDOFF_ROOT_FIELD)?;
    let mut root_input = object.clone();
    root_input.remove(ACCEPTED_SETUP_HANDOFF_ROOT_FIELD);
    let recomputed_root = derive_canonical_object_hash(&Value::Object(root_input))?;
    if recomputed_root != bound_root {
        return Err(invalid_handoff(
            "accepted setup handoff root does not match the recomputed handoff object",
        ));
    }

    let direct_ballot_handoff = handoff.get("directBallotEncryptionHandoff").ok_or_else(|| {
        invalid_handoff("accepted setup handoff is missing directBallotEncryptionHandoff")
    })?;

    Ok(AcceptedSetupHandoffBinding {
        ceremony_id: required_string(handoff, "ceremonyId")?,
        manifest_hash: required_string(handoff, "manifestHash")?,
        roster_hash: required_string(handoff, "rosterHash")?,
        setup_parameters_hash: required_string(handoff, "setupParametersHash")?,
        setup_epoch: required_string(handoff, "setupEpoch")?,
        setup_package_hash: required_string(handoff, "setupPackageHash")?,
        collective_public_key_root: required_string(
            direct_ballot_handoff,
            "collectivePublicKeyRoot",
        )?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::hash512_hex;
    use serde_json::json;

    fn hash(seed: &str) -> String {
        hash512_hex("accepted-setup-handoff-test", &[seed.as_bytes()])
    }

    // Build a handoff object shaped like the accepted-setup verifier's output,
    // with the root derived exactly as the producer derives it (over every field
    // except the root itself).
    fn sample_handoff() -> Value {
        let mut handoff = json!({
            "objectType": ACCEPTED_SETUP_HANDOFF_OBJECT_TYPE,
            "objectVersion": ACCEPTED_SETUP_HANDOFF_OBJECT_VERSION,
            "ceremonyId": "ceremony-0",
            "manifestHash": hash("manifest"),
            "rosterHash": hash("roster"),
            "setupParametersHash": hash("setup-parameters"),
            "setupEpoch": "setup-epoch-1",
            "setupPackageHash": hash("setup-package"),
            "directBallotEncryptionHandoff": {
                "collectivePublicKeyRoot": hash("collective-public-key"),
                "publicKeyShareMaterialSetRoot": hash("public-key-share-material"),
                "publicKeyShareSuccinctProofSetRoot": hash("public-key-share-proofs"),
            },
        });
        let root = derive_canonical_object_hash(&handoff).expect("handoff root");
        handoff
            .as_object_mut()
            .expect("handoff object")
            .insert(ACCEPTED_SETUP_HANDOFF_ROOT_FIELD.to_string(), json!(root));
        handoff
    }

    #[test]
    fn consumes_a_valid_handoff_and_extracts_the_ballot_bindings() {
        let handoff = sample_handoff();
        let binding = consume_accepted_setup_handoff(&handoff).expect("valid handoff");
        assert_eq!(binding.ceremony_id, "ceremony-0");
        assert_eq!(binding.manifest_hash, hash("manifest"));
        assert_eq!(binding.roster_hash, hash("roster"));
        assert_eq!(binding.setup_parameters_hash, hash("setup-parameters"));
        assert_eq!(binding.setup_epoch, "setup-epoch-1");
        assert_eq!(binding.setup_package_hash, hash("setup-package"));
        assert_eq!(
            binding.collective_public_key_root,
            hash("collective-public-key")
        );
    }

    #[test]
    fn refuses_a_tampered_handoff_root() {
        // Altering any bound field without re-deriving the root must be refused:
        // change the collective public-key root but keep the old handoff root.
        let mut handoff = sample_handoff();
        handoff["directBallotEncryptionHandoff"]["collectivePublicKeyRoot"] =
            json!(hash("substituted-public-key"));
        assert!(
            consume_accepted_setup_handoff(&handoff).is_err(),
            "a handoff whose field changed after root derivation must be refused"
        );

        // A directly overwritten root must also be refused.
        let mut forged_root = sample_handoff();
        forged_root[ACCEPTED_SETUP_HANDOFF_ROOT_FIELD] = json!(hash("forged-root"));
        assert!(
            consume_accepted_setup_handoff(&forged_root).is_err(),
            "a forged handoff root must be refused"
        );
    }

    #[test]
    fn refuses_a_passive_package_or_wrong_object_in_place_of_the_handoff() {
        // The passive development package and a private seed are not inputs; a
        // caller that supplies one instead of the handoff fails the object-type
        // check rather than being silently accepted.
        let passive_package = json!({
            "objectType": "CollectiveBgvPassiveSetupPackage",
            "objectVersion": 1,
            "ceremonyId": "ceremony-0",
        });
        assert!(
            consume_accepted_setup_handoff(&passive_package).is_err(),
            "the passive setup package must not be accepted as a handoff"
        );

        let seed = json!({ "privateSetupSeedHex": hash("seed") });
        assert!(
            consume_accepted_setup_handoff(&seed).is_err(),
            "a private setup seed must not be accepted as a handoff"
        );
    }

    #[test]
    fn refuses_a_handoff_missing_a_required_field() {
        let mut handoff = sample_handoff();
        handoff
            .as_object_mut()
            .expect("handoff object")
            .remove("setupPackageHash");
        // Removing a field changes the object, so the root check fails first;
        // either way the handoff is refused.
        assert!(
            consume_accepted_setup_handoff(&handoff).is_err(),
            "a handoff missing the setup package hash must be refused"
        );
    }
}
