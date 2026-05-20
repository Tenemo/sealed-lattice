import type {
    BallotPrivacyBackendProofComponentId,
    BallotPrivacyBackendStatementRowBatch,
} from './backend-contracts.js';

const componentIdForBatch = (
    batch: BallotPrivacyBackendStatementRowBatch,
): BallotPrivacyBackendProofComponentId => {
    if (batch.rowKind === 'EncodedScoreFieldRows') {
        return 'score-and-shamir-field-component';
    }
    if (
        batch.rowKind === 'ReceiverPayloadPlaintextBindingRows' ||
        batch.rowKind === 'ReceiverPayloadPlaintextBitDecompositionRows'
    ) {
        return 'payload-plaintext-field-component';
    }
    if (
        batch.rowKind === 'ShareCommitmentEquation' ||
        batch.rowKind === 'ShareCommitmentEquationRows'
    ) {
        return 'share-commitment-component';
    }
    if (
        batch.rowKind === 'ReceiverPayloadEncryptionEquation' ||
        batch.rowKind === 'ReceiverPayloadEncryptionEquationRows'
    ) {
        return 'receiver-encryption-component';
    }

    return 'receiver-key-binding-component';
};

const ballotPrivacyBackendProofComponentOrder: readonly BallotPrivacyBackendProofComponentId[] =
    [
        'score-and-shamir-field-component',
        'payload-plaintext-field-component',
        'share-commitment-component',
        'receiver-encryption-component',
        'receiver-key-binding-component',
    ];

export { componentIdForBatch, ballotPrivacyBackendProofComponentOrder };
