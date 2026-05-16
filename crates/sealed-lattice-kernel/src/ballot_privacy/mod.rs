use serde_json::{Value, json};

pub const MODULE_MARKER: &str = "ballot-privacy";
pub const BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE: bool = false;

const UNAVAILABLE_BACKEND_MESSAGE: &str = "Ballot privacy proof verification requires the frozen LaZer-style lattice proof backend, which is not implemented in this build.";

fn fail_closed(operation: &str) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "operation": operation,
        "statusLabels": [],
        "acceptedDigests": [],
        "refusedObjects": [
            {
                "code": "OperationUnavailable",
                "message": format!("{operation}: {UNAVAILABLE_BACKEND_MESSAGE}")
            }
        ],
        "unresolvedReason": "OperationUnavailable"
    })
}

pub fn verify_receiver_key_proof() -> Value {
    fail_closed("verifyReceiverKeyProof")
}

pub fn verify_ballot_proof() -> Value {
    fail_closed("verifyBallotProof")
}

pub fn verify_claim_bearing_ballot_package() -> Value {
    fail_closed("verifyClaimBearingBallotPackage")
}

#[cfg(test)]
mod tests {
    #[test]
    fn ballot_privacy_backend_is_explicitly_unavailable_until_integrated() {
        let verification = super::verify_ballot_proof();

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["unresolvedReason"], "OperationUnavailable");
        assert_eq!(
            verification["refusedObjects"][0]["message"],
            "verifyBallotProof: Ballot privacy proof verification requires the frozen LaZer-style lattice proof backend, which is not implemented in this build."
        );
    }
}
