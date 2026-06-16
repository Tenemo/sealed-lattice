use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PrivateVssRefusal {
    reason_code: &'static str,
    message: String,
    object_path: String,
}

impl PrivateVssRefusal {
    pub(super) fn new(
        reason_code: &'static str,
        message: impl Into<String>,
        object_path: impl Into<String>,
    ) -> Self {
        Self {
            reason_code,
            message: message.into(),
            object_path: object_path.into(),
        }
    }

    pub(super) fn to_value(&self) -> Value {
        json!({
            "reasonCode": self.reason_code,
            "message": self.message,
            "objectPath": self.object_path,
        })
    }
}

pub(super) fn private_vss_refusal_to_error(refusal: PrivateVssRefusal) -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{}: {}", refusal.reason_code, refusal.message),
    )
}

pub(super) fn refusal_to_error(refusal: PrivateVssRefusal) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, refusal.message)
}
