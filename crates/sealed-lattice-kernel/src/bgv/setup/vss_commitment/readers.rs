use super::*;

pub(super) fn validate_vss_public_commitment_role(commitment_role: &str) -> CanonicalResult<()> {
    match commitment_role {
        "coefficient"
        | "recipient-share"
        | "aggregate-threshold-share"
        | "target-decryption-flooding-noise" => Ok(()),
        _ => Err(invalid_vss_public_input(
            "VSS commitment role is not supported",
        )),
    }
}
