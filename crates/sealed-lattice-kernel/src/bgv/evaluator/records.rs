use serde_json::json;

use crate::{
    bgv::parameters::POLYNOMIAL_DEGREE,
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::derive_canonical_object_hash,
};

pub(crate) const MAXIMUM_OPTION_COUNT: usize = 20;
pub(crate) const DIRECT_TARGET_PROJECTION_ID: &str = "direct-encrypted-target-projection";

pub(crate) fn target_layout_hash(option_count: usize) -> CanonicalResult<String> {
    if option_count == 0 || option_count > MAXIMUM_OPTION_COUNT {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidFixture,
            "target layout option count must be between 1 and the supported maximum",
        ));
    }

    derive_canonical_object_hash(&json!({
        "objectType": "DirectEncryptedBallotTargetLayout",
        "layoutId": DIRECT_TARGET_PROJECTION_ID,
        "optionCount": option_count,
        "slotCount": POLYNOMIAL_DEGREE,
    }))
}
