use serde_json::{Value, json};

pub const MODULE_MARKER: &str = "ballot-privacy";
pub const BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE: bool = false;

const UNAVAILABLE_BACKEND_MESSAGE: &str = "Ballot privacy proof verification requires the frozen LaZer-style lattice proof backend, which is not implemented in this build.";
const BACKEND_NAME: &str = "LaZer-style linear lattice proof backend";
const UPSTREAM_LAZER_REFERENCE: &str = "lazer-crypto/lazer";

pub const REQUIRED_LAZER_PORT_COMPONENTS: &[&str] = &[
    "generated linear proof parameters from lin-codegen.sage",
    "portable polynomial ring arithmetic for Z_q[X]/(X^d + 1)",
    "portable polynomial vector and matrix arithmetic",
    "sparse polynomial vector and matrix arithmetic",
    "ABDLop commitment key generation, commitment, and commitment hashing",
    "linear relation statement mapping for A*w + t = 0",
    "linear witness decomposition into short and message coordinates",
    "tbox proof generation and verification",
    "quadratic-to-linear helper relations used by the tbox backend",
    "proof byte coder and decoder",
    "SHAKE128 transcript and expansion path",
    "rejection sampling and bounded short-vector checks",
    "browser-safe prover randomness source",
];

pub const UPSTREAM_LAZER_REFERENCE_FILES: &[&str] = &[
    "src/lin-proofs.c",
    "src/lnp.c",
    "src/lnp-tbox.c",
    "src/lnp-quad.c",
    "src/lnp-quad-many.c",
    "src/lnp-quad-eval.c",
    "src/abdlop.c",
    "src/poly.c",
    "src/polyvec.c",
    "src/polymat.c",
    "src/spolyvec.c",
    "src/spolymat.c",
    "src/coder.c",
    "src/rejection.c",
    "src/rng.c",
    "src/shake128.c",
    "scripts/lin-codegen.sage",
];

pub fn describe_proof_backend() -> Value {
    json!({
        "backendName": BACKEND_NAME,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "upstreamReference": UPSTREAM_LAZER_REFERENCE,
        "upstreamDirectDependencyUsableInBrowser": false,
        "portableRustWasmPortRequired": true,
        "requiredComponents": REQUIRED_LAZER_PORT_COMPONENTS,
        "upstreamReferenceFiles": UPSTREAM_LAZER_REFERENCE_FILES,
        "blockedReason": UNAVAILABLE_BACKEND_MESSAGE
    })
}

fn fail_closed(operation: &str) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
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
    use serde_json::json;

    #[test]
    fn ballot_privacy_backend_is_explicitly_unavailable_until_integrated() {
        let verification = super::verify_ballot_proof();

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(
            verification["backendStatus"]["portableRustWasmPortRequired"],
            true
        );
        assert!(
            verification["backendStatus"]["requiredComponents"]
                .as_array()
                .expect("backend component list should be an array")
                .contains(&json!(
                    "ABDLop commitment key generation, commitment, and commitment hashing"
                ))
        );
        assert_eq!(verification["unresolvedReason"], "OperationUnavailable");
        assert_eq!(
            verification["refusedObjects"][0]["message"],
            "verifyBallotProof: Ballot privacy proof verification requires the frozen LaZer-style lattice proof backend, which is not implemented in this build."
        );
    }
}
