use crate::foundation::{CanonicalItem, Hash512, RefusalReason};

use super::{
    ProtocolRefusal, ProtocolResult,
    canonical::{read_hash, read_u64},
};

pub(crate) const FLOW_CONTEXT_ITEM_COUNT: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReferenceFlowContext {
    pub(crate) suite_identity: Hash512,
    pub(crate) build_identity: Hash512,
    pub(crate) action_identity: Hash512,
    pub(crate) roster_identity: Hash512,
    pub(crate) circuit_identity: Hash512,
    pub(crate) action_predecessor_identity: Hash512,
    pub(crate) attempt_ordinal: u64,
    pub(crate) output_ordinal: u64,
}

impl ReferenceFlowContext {
    pub(crate) fn canonical_items(self) -> [CanonicalItem; FLOW_CONTEXT_ITEM_COUNT] {
        [
            hash_item(self.suite_identity),
            hash_item(self.build_identity),
            hash_item(self.action_identity),
            hash_item(self.roster_identity),
            hash_item(self.circuit_identity),
            hash_item(self.action_predecessor_identity),
            CanonicalItem::unsigned64(self.attempt_ordinal),
            CanonicalItem::unsigned64(self.output_ordinal),
        ]
    }

    pub(crate) fn read_from_items(items: &[CanonicalItem]) -> ProtocolResult<Self> {
        if items.len() < FLOW_CONTEXT_ITEM_COUNT {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongTypeOrLength,
                "reference-flow message context is truncated",
            ));
        }
        Ok(Self {
            suite_identity: read_hash(&items[0])?,
            build_identity: read_hash(&items[1])?,
            action_identity: read_hash(&items[2])?,
            roster_identity: read_hash(&items[3])?,
            circuit_identity: read_hash(&items[4])?,
            action_predecessor_identity: read_hash(&items[5])?,
            attempt_ordinal: read_u64(&items[6])?,
            output_ordinal: read_u64(&items[7])?,
        })
    }

    pub(crate) fn require(self, expected: Self) -> ProtocolResult<()> {
        if self != expected {
            return Err(ProtocolRefusal::new(
                RefusalReason::WrongContext,
                "reference-flow message does not match the expected action context",
            ));
        }
        Ok(())
    }
}

pub(crate) fn require_participant_position(position: u16) -> ProtocolResult<usize> {
    let position = usize::from(position);
    if position >= super::field::PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "reference-flow participant position is outside the roster",
        ));
    }
    Ok(position)
}

pub(crate) fn hash_item(identity: Hash512) -> CanonicalItem {
    CanonicalItem::hash512(identity.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ReferenceFlowContext {
        ReferenceFlowContext {
            suite_identity: Hash512::from_bytes([1; 64]),
            build_identity: Hash512::from_bytes([2; 64]),
            action_identity: Hash512::from_bytes([3; 64]),
            roster_identity: Hash512::from_bytes([4; 64]),
            circuit_identity: Hash512::from_bytes([5; 64]),
            action_predecessor_identity: Hash512::from_bytes([6; 64]),
            attempt_ordinal: 7,
            output_ordinal: 0,
        }
    }

    #[test]
    fn context_items_round_trip_and_wrong_context_refuses() {
        let items = context().canonical_items();
        let decoded = ReferenceFlowContext::read_from_items(&items).unwrap();
        decoded.require(context()).unwrap();
        assert!(
            decoded
                .require(ReferenceFlowContext {
                    attempt_ordinal: 8,
                    ..context()
                })
                .is_err()
        );
        assert!(ReferenceFlowContext::read_from_items(&items[..7]).is_err());
        assert!(require_participant_position(10).is_err());
    }
}
