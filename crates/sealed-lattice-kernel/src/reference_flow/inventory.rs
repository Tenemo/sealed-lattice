use crate::foundation::{CanonicalItem, Hash512, RefusalReason};

use super::{
    ProtocolRefusal, ProtocolResult, field::PARTICIPANT_COUNT, flow_context::ReferenceFlowContext,
    protocol_oracle::protocol_oracle_512,
};

pub(crate) const PROTECTED_SOURCE_POSITION: usize = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InventoryKind {
    PreparationContribution,
    PreparationChallengeOpening,
    PreparationResponse,
    SourceContribution,
    SourceChallengeOpening,
    SourceResponse,
    Activation,
}

impl InventoryKind {
    const fn domain(self) -> &'static str {
        match self {
            Self::PreparationContribution => {
                "sealed-lattice/protocol/preparation-contribution-inventory/v1"
            }
            Self::PreparationChallengeOpening => {
                "sealed-lattice/protocol/preparation-opening-inventory/v1"
            }
            Self::PreparationResponse => {
                "sealed-lattice/protocol/preparation-response-inventory/v1"
            }
            Self::SourceContribution => "sealed-lattice/protocol/source-contribution-inventory/v1",
            Self::SourceChallengeOpening => "sealed-lattice/protocol/source-opening-inventory/v1",
            Self::SourceResponse => "sealed-lattice/protocol/source-response-inventory/v1",
            Self::Activation => "sealed-lattice/protocol/activation-inventory/v1",
        }
    }
}

pub(crate) fn complete_inventory_identity(
    kind: InventoryKind,
    ordered_body_identities: &[Hash512],
) -> ProtocolResult<Hash512> {
    if ordered_body_identities.len() != PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "protocol inventory is missing a roster position",
        ));
    }
    let mut items = Vec::with_capacity(PARTICIPANT_COUNT + 1);
    items.push(CanonicalItem::unsigned16(PARTICIPANT_COUNT as u16));
    items.extend(
        ordered_body_identities
            .iter()
            .map(|identity| CanonicalItem::hash512(identity.into_bytes())),
    );
    protocol_oracle_512(kind.domain(), &items)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceDeclaration {
    Submit,
    Abstain,
    NoSource,
}

impl SourceDeclaration {
    pub(crate) const fn canonical_code(self) -> u16 {
        match self {
            Self::Submit => 1,
            Self::Abstain => 2,
            Self::NoSource => 3,
        }
    }
}

pub(crate) fn verify_vertical_source_declarations(
    declarations: &[SourceDeclaration],
) -> ProtocolResult<bool> {
    if declarations.len() != PARTICIPANT_COUNT {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongTypeOrLength,
            "source declaration inventory is missing a roster position",
        ));
    }
    if !matches!(
        declarations[PROTECTED_SOURCE_POSITION],
        SourceDeclaration::Submit | SourceDeclaration::Abstain
    ) || declarations
        .iter()
        .enumerate()
        .any(|(position, declaration)| {
            position != PROTECTED_SOURCE_POSITION && *declaration != SourceDeclaration::NoSource
        })
    {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "source declarations do not match the one-protected-input vertical",
        ));
    }
    Ok(declarations[PROTECTED_SOURCE_POSITION] == SourceDeclaration::Submit)
}

pub(crate) fn declaration_inventory_identity(
    context: ReferenceFlowContext,
    declarations: &[SourceDeclaration],
) -> ProtocolResult<Hash512> {
    verify_vertical_source_declarations(declarations)?;
    let mut items =
        Vec::with_capacity(super::flow_context::FLOW_CONTEXT_ITEM_COUNT + PARTICIPANT_COUNT + 1);
    items.extend(context.canonical_items());
    items.push(CanonicalItem::unsigned16(PARTICIPANT_COUNT as u16));
    items.extend(
        declarations
            .iter()
            .map(|declaration| CanonicalItem::unsigned16(declaration.canonical_code())),
    );
    protocol_oracle_512(
        "sealed-lattice/protocol/source-declaration-inventory/v1",
        &items,
    )
}

pub(crate) fn selected_source_identity(
    context: ReferenceFlowContext,
    protected_source_contribution_identity: Hash512,
    declaration: SourceDeclaration,
) -> ProtocolResult<Hash512> {
    if !matches!(
        declaration,
        SourceDeclaration::Submit | SourceDeclaration::Abstain
    ) {
        return Err(ProtocolRefusal::new(
            RefusalReason::WrongContext,
            "protected source declaration is neither submit nor abstain",
        ));
    }
    let mut items = Vec::with_capacity(super::flow_context::FLOW_CONTEXT_ITEM_COUNT + 3);
    items.extend(context.canonical_items());
    items.extend([
        CanonicalItem::unsigned16(PROTECTED_SOURCE_POSITION as u16),
        CanonicalItem::unsigned16(declaration.canonical_code()),
        CanonicalItem::hash512(protected_source_contribution_identity.into_bytes()),
    ]);
    protocol_oracle_512("sealed-lattice/protocol/selected-source/v1", &items)
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
            attempt_ordinal: 1,
            output_ordinal: 0,
        }
    }

    #[test]
    fn inventories_are_ordered_complete_and_domain_separated() {
        let identities = (0_u8..PARTICIPANT_COUNT as u8)
            .map(|position| Hash512::from_bytes([position; 64]))
            .collect::<Vec<_>>();
        let preparation =
            complete_inventory_identity(InventoryKind::PreparationContribution, &identities)
                .unwrap();
        let source =
            complete_inventory_identity(InventoryKind::SourceContribution, &identities).unwrap();
        assert_ne!(preparation, source);
        let mut reordered = identities.clone();
        reordered.swap(0, 1);
        assert_ne!(
            preparation,
            complete_inventory_identity(InventoryKind::PreparationContribution, &reordered)
                .unwrap()
        );
        assert!(
            complete_inventory_identity(InventoryKind::PreparationContribution, &identities[..9])
                .is_err()
        );
    }

    #[test]
    fn vertical_declarations_have_one_exact_protected_source_role() {
        let mut declarations = [SourceDeclaration::NoSource; PARTICIPANT_COUNT];
        declarations[PROTECTED_SOURCE_POSITION] = SourceDeclaration::Submit;
        assert!(verify_vertical_source_declarations(&declarations).unwrap());
        let submit_identity = declaration_inventory_identity(context(), &declarations).unwrap();
        declarations[PROTECTED_SOURCE_POSITION] = SourceDeclaration::Abstain;
        assert!(!verify_vertical_source_declarations(&declarations).unwrap());
        assert_ne!(
            submit_identity,
            declaration_inventory_identity(context(), &declarations).unwrap()
        );
        declarations[4] = SourceDeclaration::Submit;
        assert!(verify_vertical_source_declarations(&declarations).is_err());
    }
}
