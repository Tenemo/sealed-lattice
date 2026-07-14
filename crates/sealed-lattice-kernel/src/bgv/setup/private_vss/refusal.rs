#[cfg(test)]
use crate::encoding::{CanonicalError, CanonicalErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PrivateVssRefusal {
    reason_code: &'static str,
    message: String,
}

impl PrivateVssRefusal {
    pub(super) fn new(
        reason_code: &'static str,
        message: impl Into<String>,
        _object_path: impl Into<String>,
    ) -> Self {
        Self {
            reason_code,
            message: message.into(),
        }
    }

    pub(super) fn refusal_reason(&self) -> crate::foundation::RefusalReason {
        crate::bgv::setup::setup_refusal_reason(self.reason_code)
    }
}

#[cfg(test)]
pub(super) fn private_vss_refusal_to_error(refusal: PrivateVssRefusal) -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{}: {}", refusal.reason_code, refusal.message),
    )
}
