import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type { ProtocolDigest } from '@sealed-lattice/types';

import type { BallotPrivacyBackendProofComponentId } from '../relation-backend-lowering.js';

import type {
    BallotProofComponentBundleStatement,
    BallotProofComponentProofBundlePayload,
    BallotProofComponentProofRecordPayload,
    BallotProofComponentProofStatementPlan,
    BallotProofComponentStatement,
    BallotProofLinearProofStatement,
    BallotProofSparseComponentLinearProofStatement,
    BallotProofStructuredReceiverEncryptionProofStatement,
    BallotProofStructuredShareCommitmentProofStatement,
    DensePolynomialMatrix,
    DensePolynomialVector,
    SparseMatrixEntry,
    SparseTargetVectorEntry,
} from './statement-contracts.js';

const deriveLinearStatementDigest = (
    statementPayload: Omit<BallotProofLinearProofStatement, 'statementDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-linear-proof-statement-v1',
    });

const deriveSparseLinearStatementDigest = (
    statementPayload: Omit<
        BallotProofSparseComponentLinearProofStatement,
        'statementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-sparse-linear-proof-statement-v1',
    });

const deriveStructuredReceiverEncryptionStatementDigest = (
    statementPayload: Omit<
        BallotProofStructuredReceiverEncryptionProofStatement,
        'statementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose:
            'ballot-proof-structured-receiver-encryption-proof-statement-v1',
    });

const deriveStructuredShareCommitmentStatementDigest = (
    statementPayload: Omit<
        BallotProofStructuredShareCommitmentProofStatement,
        'statementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-structured-share-commitment-proof-statement-v1',
    });

const deriveComponentStatementDigest = (
    statementPayload: Omit<
        BallotProofComponentStatement,
        'componentStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-statement-v1',
    });

const deriveComponentBundleStatementDigest = (
    statementPayload: Omit<
        BallotProofComponentBundleStatement,
        'componentBundleStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-bundle-statement-v1',
    });

const deriveComponentProofRecordDigest = (
    proofRecordPayload: BallotProofComponentProofRecordPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: proofRecordPayload,
        purpose: 'ballot-proof-component-proof-record-v1',
    });

const deriveComponentProofBundleDigest = (
    proofBundlePayload: BallotProofComponentProofBundlePayload,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: proofBundlePayload,
        purpose: 'ballot-proof-component-proof-bundle-v1',
    });

const deriveStatementMatrixDigest = (
    statementMatrixCoefficients: DensePolynomialMatrix,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-linear-statement-matrix-v1',
        statementMatrixCoefficients,
    });

const deriveSparseStatementMatrixDigest = (
    sparseStatementMatrixEntries: readonly SparseMatrixEntry[],
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-sparse-linear-statement-matrix-v1',
        sparseStatementMatrixEntries,
    });

const deriveTargetVectorDigest = (
    targetVectorCoefficients: DensePolynomialVector,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-linear-target-vector-v1',
        targetVectorCoefficients,
    });

const deriveSparseTargetVectorDigest = (
    targetVectorEntries: readonly SparseTargetVectorEntry[],
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-sparse-linear-target-vector-v1',
        targetVectorEntries,
    });

const deriveComponentMatrixDigest = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly rowBatchMatrixDigests: readonly ProtocolDigest[];
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        componentId: input.componentId,
        purpose: 'ballot-proof-component-matrix-v1',
        rowBatchMatrixDigests: input.rowBatchMatrixDigests,
    });

const deriveComponentTargetVectorDigest = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly rowBatchTargetVectorDigests: readonly ProtocolDigest[];
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        componentId: input.componentId,
        purpose: 'ballot-proof-component-target-vector-v1',
        rowBatchTargetVectorDigests: input.rowBatchTargetVectorDigests,
    });

const deriveComponentProofStatementDigest = (
    statementPayload: Omit<
        BallotProofComponentProofStatementPlan,
        'componentProofStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-proof-statement-plan-v1',
    });

export {
    deriveLinearStatementDigest,
    deriveSparseLinearStatementDigest,
    deriveStructuredReceiverEncryptionStatementDigest,
    deriveStructuredShareCommitmentStatementDigest,
    deriveComponentStatementDigest,
    deriveComponentBundleStatementDigest,
    deriveComponentProofRecordDigest,
    deriveComponentProofBundleDigest,
    deriveStatementMatrixDigest,
    deriveSparseStatementMatrixDigest,
    deriveTargetVectorDigest,
    deriveSparseTargetVectorDigest,
    deriveComponentMatrixDigest,
    deriveComponentTargetVectorDigest,
    deriveComponentProofStatementDigest,
};
