#[cfg(test)]
use crate::encoding::{CanonicalError, CanonicalErrorCode};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PrivateVssRefusal {
    refusal_reason: crate::foundation::RefusalReason,
    reason_code: &'static str,
    message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct PrivateVssRefusalCode {
    reason_code: &'static str,
    refusal_reason: crate::foundation::RefusalReason,
}

impl PrivateVssRefusalCode {
    const fn new(
        reason_code: &'static str,
        refusal_reason: crate::foundation::RefusalReason,
    ) -> Self {
        Self {
            reason_code,
            refusal_reason,
        }
    }

    pub(super) const fn malformed(reason_code: &'static str) -> Self {
        Self::new(
            reason_code,
            crate::foundation::RefusalReason::MalformedEncoding,
        )
    }

    pub(super) const fn wrong_type(reason_code: &'static str) -> Self {
        Self::new(
            reason_code,
            crate::foundation::RefusalReason::WrongTypeOrLength,
        )
    }

    pub(super) const fn wrong_hash(reason_code: &'static str) -> Self {
        Self::new(
            reason_code,
            crate::foundation::RefusalReason::WrongHashOrRoot,
        )
    }

    pub(super) const fn wrong_context(reason_code: &'static str) -> Self {
        Self::new(reason_code, crate::foundation::RefusalReason::WrongContext)
    }

    pub(super) const fn missing(reason_code: &'static str) -> Self {
        Self::new(
            reason_code,
            crate::foundation::RefusalReason::MissingPrerequisite,
        )
    }

    pub(super) const fn equivocation(reason_code: &'static str) -> Self {
        Self::new(reason_code, crate::foundation::RefusalReason::Equivocation)
    }

    pub(super) const fn invalid_proof(reason_code: &'static str) -> Self {
        Self::new(reason_code, crate::foundation::RefusalReason::InvalidProof)
    }
}

impl PrivateVssRefusal {
    pub(super) fn new(
        code: PrivateVssRefusalCode,
        message: impl Into<String>,
        _object_path: impl Into<String>,
    ) -> Self {
        Self {
            refusal_reason: code.refusal_reason,
            reason_code: code.reason_code,
            message: message.into(),
        }
    }

    pub(super) fn refusal_reason(&self) -> crate::foundation::RefusalReason {
        self.refusal_reason
    }
}

#[cfg(test)]
pub(super) fn private_vss_refusal_to_error(refusal: PrivateVssRefusal) -> CanonicalError {
    CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        format!("{}: {}", refusal.reason_code, refusal.message),
    )
}
