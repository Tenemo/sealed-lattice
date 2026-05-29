import { deriveProtocolHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import type { BallotPrivacyBackendProofComponentId } from '../relation-backend-lowering.js';

import type {
    BallotProofComponentBundleStatement,
    BallotProofComponentProofBundlePayload,
    BallotProofComponentProofRecordPayload,
    BallotProofComponentProofStatementDescriptor,
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

const deriveLinearStatementHash = (
    statementPayload: Omit<BallotProofLinearProofStatement, 'statementHash'>,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: statementPayload,
        purpose: 'ballot-proof-linear-proof-statement-v1',
    });

const deriveSparseLinearStatementHash = (
    statementPayload: Omit<
        BallotProofSparseComponentLinearProofStatement,
        'statementHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: statementPayload,
        purpose: 'ballot-proof-sparse-linear-proof-statement-v1',
    });

const deriveStructuredReceiverEncryptionStatementHash = (
    statementPayload: Omit<
        BallotProofStructuredReceiverEncryptionProofStatement,
        'statementHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: statementPayload,
        purpose:
            'ballot-proof-structured-receiver-encryption-proof-statement-v1',
    });

const deriveStructuredShareCommitmentStatementHash = (
    statementPayload: Omit<
        BallotProofStructuredShareCommitmentProofStatement,
        'statementHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: statementPayload,
        purpose: 'ballot-proof-structured-share-commitment-proof-statement-v1',
    });

const deriveComponentStatementHash = (
    statementPayload: Omit<
        BallotProofComponentStatement,
        'componentStatementHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-statement-v1',
    });

const deriveComponentBundleStatementHash = (
    statementPayload: Omit<
        BallotProofComponentBundleStatement,
        'componentBundleStatementHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-bundle-statement-v1',
    });

const deriveComponentProofRecordHash = (
    proofRecordPayload: BallotProofComponentProofRecordPayload,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: proofRecordPayload,
        purpose: 'ballot-proof-component-proof-record-v1',
    });

const deriveComponentProofBundleHash = (
    proofBundlePayload: BallotProofComponentProofBundlePayload,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: proofBundlePayload,
        purpose: 'ballot-proof-component-proof-bundle-v1',
    });

const deriveStatementMatrixHash = (
    statementMatrixCoefficients: DensePolynomialMatrix,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        purpose: 'ballot-proof-linear-statement-matrix-v1',
        statementMatrixCoefficients,
    });

const deriveSparseStatementMatrixHash = (
    sparseStatementMatrixEntries: readonly SparseMatrixEntry[],
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        purpose: 'ballot-proof-sparse-linear-statement-matrix-v1',
        sparseStatementMatrixEntries,
    });

const deriveTargetVectorHash = (
    targetVectorCoefficients: DensePolynomialVector,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        purpose: 'ballot-proof-linear-target-vector-v1',
        targetVectorCoefficients,
    });

const deriveSparseTargetVectorHash = (
    targetVectorEntries: readonly SparseTargetVectorEntry[],
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        purpose: 'ballot-proof-sparse-linear-target-vector-v1',
        targetVectorEntries,
    });

const deriveComponentMatrixHash = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly rowBatchMatrixHashes: readonly ProtocolHash[];
}): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        componentId: input.componentId,
        purpose: 'ballot-proof-component-matrix-v1',
        rowBatchMatrixHashes: input.rowBatchMatrixHashes,
    });

const deriveComponentTargetVectorHash = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly rowBatchTargetVectorHashes: readonly ProtocolHash[];
}): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        componentId: input.componentId,
        purpose: 'ballot-proof-component-target-vector-v1',
        rowBatchTargetVectorHashes: input.rowBatchTargetVectorHashes,
    });

const deriveComponentProofStatementHash = (
    statementPayload: Omit<
        BallotProofComponentProofStatementDescriptor,
        'componentProofStatementHash'
    >,
): ProtocolHash =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-proof-statement-descriptor-v1',
    });

export {
    deriveLinearStatementHash,
    deriveSparseLinearStatementHash,
    deriveStructuredReceiverEncryptionStatementHash,
    deriveStructuredShareCommitmentStatementHash,
    deriveComponentStatementHash,
    deriveComponentBundleStatementHash,
    deriveComponentProofRecordHash,
    deriveComponentProofBundleHash,
    deriveStatementMatrixHash,
    deriveSparseStatementMatrixHash,
    deriveTargetVectorHash,
    deriveSparseTargetVectorHash,
    deriveComponentMatrixHash,
    deriveComponentTargetVectorHash,
    deriveComponentProofStatementHash,
};
