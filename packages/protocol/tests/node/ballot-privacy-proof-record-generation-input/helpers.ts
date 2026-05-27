import { deriveProtocolDigest } from '@sealed-lattice/crypto';

import type { BallotProofRecordGenerationFixture } from '../ballot-privacy-proof-record-generation-fixtures';
export const digest = (label: string): string =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        label,
        purpose: 'ballot-proof-record-generation-input-test',
    });
export const mandatoryProfileFixtureTimeoutMs = 900_000;
export const casualMicroRosterSizes = [3, 4, 5, 6, 7, 8, 9] as const;

export const requireRecord = (
    value: unknown,
    label: string,
): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${label} should be an object.`);
    }

    return value as Record<string, unknown>;
};

export const receiverEncryptionProofStatement = (
    fixture: BallotProofRecordGenerationFixture,
): {
    readonly receiverRows: readonly {
        readonly ciphertextChunkCount: number;
        readonly plaintextBitLength: number;
        readonly rowCount: number;
    }[];
    readonly sourceBackendColumnIndices: readonly number[];
    readonly statementColumns: number;
    readonly statementRows: number;
} => {
    const receiverEncryptionInput = fixture.request.componentProofInputs.find(
        (proofInput) =>
            proofInput.componentId === 'receiver-encryption-component',
    );
    if (receiverEncryptionInput === undefined) {
        throw new Error('Receiver-encryption input should be present.');
    }

    return receiverEncryptionInput.proofStatement as {
        readonly receiverRows: readonly {
            readonly ciphertextChunkCount: number;
            readonly plaintextBitLength: number;
            readonly rowCount: number;
        }[];
        readonly sourceBackendColumnIndices: readonly number[];
        readonly statementColumns: number;
        readonly statementRows: number;
    };
};

export const shareCommitmentProofStatement = (
    fixture: BallotProofRecordGenerationFixture,
): {
    readonly proofStatementFormat: string;
    readonly receiverRows?: readonly {
        readonly commitmentPolynomialVector: readonly (readonly string[])[];
        readonly rowCount: number;
        readonly rowOffsetWithinStatement: number;
    }[];
    readonly shareVectorWidth: number;
    readonly sourceBackendColumnIndices: readonly number[];
    readonly statementColumns: number;
    readonly statementRows: number;
} => {
    const shareCommitmentInput = fixture.request.componentProofInputs.find(
        (proofInput) => proofInput.componentId === 'share-commitment-component',
    );
    if (shareCommitmentInput === undefined) {
        throw new Error('Share-commitment input should be present.');
    }

    return shareCommitmentInput.proofStatement as {
        readonly proofStatementFormat: string;
        readonly receiverRows?: readonly {
            readonly commitmentPolynomialVector: readonly (readonly string[])[];
            readonly rowCount: number;
            readonly rowOffsetWithinStatement: number;
        }[];
        readonly shareVectorWidth: number;
        readonly sourceBackendColumnIndices: readonly number[];
        readonly statementColumns: number;
        readonly statementRows: number;
    };
};

export const fieldProofStatement = (
    fixture: BallotProofRecordGenerationFixture,
    componentId:
        | 'score-and-shamir-field-component'
        | 'payload-plaintext-field-component',
): {
    readonly sourceBackendColumnIndices: readonly number[];
    readonly sourceColumnPackings?: readonly unknown[];
    readonly statementColumns: number;
    readonly statementRows: number;
} => {
    const proofInput = fixture.request.componentProofInputs.find(
        (candidate) => candidate.componentId === componentId,
    );
    if (proofInput === undefined) {
        throw new Error(`${componentId} input should be present.`);
    }

    return proofInput.proofStatement as {
        readonly sourceBackendColumnIndices: readonly number[];
        readonly sourceColumnPackings?: readonly unknown[];
        readonly statementColumns: number;
        readonly statementRows: number;
    };
};
