mod activation;
mod canonical;
mod challenge;
mod direct_check;
mod field;
mod finality;
mod flow_context;
mod garbling;
mod inventory;
mod mailbox;
mod preparation;
mod private_payload;
mod protocol_oracle;
mod random_tape;
mod roster_signature;
mod sharing;
mod signed_message;
mod source;
mod state;
mod token;

use crate::foundation::RefusalReason;

pub(crate) type ProtocolResult<Value> = Result<Value, ProtocolRefusal>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProtocolRefusal {
    pub(crate) reason: RefusalReason,
    pub(crate) message: &'static str,
}

impl ProtocolRefusal {
    pub(crate) const fn new(reason: RefusalReason, message: &'static str) -> Self {
        Self { reason, message }
    }
}

impl From<crate::foundation::CanonicalCodecError> for ProtocolRefusal {
    fn from(error: crate::foundation::CanonicalCodecError) -> Self {
        let reason = if error.kind == crate::foundation::CanonicalCodecErrorKind::LimitExceeded {
            RefusalReason::OutsideSupportedProfile
        } else {
            RefusalReason::MalformedEncoding
        };
        Self::new(reason, "protocol value is not canonical")
    }
}
