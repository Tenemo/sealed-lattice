import type {
    BallotPrivacyBackendProofComponent,
    BallotPrivacyBackendProofComponentId,
} from '../relation-backend-lowering.js';

import type {
    BackendRowBatchForComponentStatement,
    BallotProofComponentProofBackendRequirement,
    BallotProofComponentProofStatementFormat,
    StructuredShareCommitmentRowBatch,
} from './statement-contracts.js';
import {
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
} from './statement-contracts.js';

const sourceRingDegreeForComponentProofStatement = (
    componentId: BallotPrivacyBackendProofComponentId,
): number | null => {
    switch (componentId) {
        case 'score-and-shamir-field-component':
        case 'payload-plaintext-field-component':
            return 64;
        case 'share-commitment-component':
        case 'receiver-encryption-component':
            return 256;
        case 'receiver-key-binding-component':
            return null;
    }
};

const proofSystemRingDegreeForComponentProofStatement = (
    componentId: BallotPrivacyBackendProofComponentId,
): number | null =>
    componentId === 'receiver-key-binding-component' ? null : 64;

const proofStatementFormatForComponent = (input: {
    readonly component: BallotPrivacyBackendProofComponent;
    readonly rowBatches: readonly BackendRowBatchForComponentStatement[];
}): BallotProofComponentProofStatementFormat => {
    if (
        input.component.componentId === 'receiver-key-binding-component' &&
        input.component.variableColumnCount === 0
    ) {
        return 'public-binding-check-only-v1';
    }
    if (
        input.rowBatches.some(
            (rowBatch) =>
                rowBatch.batchKind ===
                'StructuredModuleLweReceiverEncryptionRows',
        )
    ) {
        return 'structured-module-lwe-linear-proof-v1';
    }
    if (
        input.rowBatches.some(
            (rowBatch) =>
                rowBatch.batchKind === 'StructuredModuleSisShareCommitmentRows',
        )
    ) {
        return 'structured-module-sis-share-commitment-v1';
    }
    if (
        input.component.rowBatchNames.length === 1 &&
        input.component.rowBatchNames[0] === 'encoded_score_field_rows' &&
        input.component.rowCount <= 100
    ) {
        return 'dense-polynomial-matrix-linear-proof-v1';
    }

    return 'sparse-polynomial-matrix-linear-proof-v1';
};

const proofBackendRequirementForStatementFormat = (
    proofStatementFormat: BallotProofComponentProofStatementFormat,
): BallotProofComponentProofBackendRequirement => {
    switch (proofStatementFormat) {
        case 'dense-polynomial-matrix-linear-proof-v1':
            return 'dense-proof-bytes-available-lab-only';
        case 'sparse-polynomial-matrix-linear-proof-v1':
        case 'structured-module-sis-share-commitment-v1':
            return 'sparse-proof-statement-required';
        case 'structured-module-lwe-linear-proof-v1':
            return 'structured-proof-statement-required';
        case 'public-binding-check-only-v1':
            return 'public-binding-check-only';
    }
};

const explicitRowBatchTermCount = (
    rowBatch: Extract<
        BackendRowBatchForComponentStatement,
        { readonly batchKind: 'ExplicitSparseRows' }
    >,
): bigint =>
    rowBatch.rows.reduce(
        (termCount, row) => termCount + BigInt(row.terms.length),
        0n,
    );

const structuredReceiverEncryptionWitnessTermCounts = (
    rowBatch: Extract<
        BackendRowBatchForComponentStatement,
        { readonly batchKind: 'StructuredModuleLweReceiverEncryptionRows' }
    >,
): {
    readonly ciphertextChunkCount: number;
    readonly receiverCount: number;
    readonly witnessTermCount: bigint;
} => {
    let ciphertextChunkCount = 0;
    let witnessTermCount = 0n;
    for (const receiverRows of rowBatch.receiverRows) {
        ciphertextChunkCount += receiverRows.ciphertextChunkCount;
        const randomnessTermsPerPolynomialRow =
            receiverEncryptionModuleRank * receiverEncryptionModuleDegree;
        const firstCiphertextRowsPerChunk =
            receiverEncryptionModuleRank * receiverEncryptionModuleDegree;
        const firstCiphertextTermsPerChunk =
            firstCiphertextRowsPerChunk * (randomnessTermsPerPolynomialRow + 1);
        let secondCiphertextTermsForReceiver = 0;
        for (
            let chunkIndex = 0;
            chunkIndex < receiverRows.ciphertextChunkCount;
            chunkIndex += 1
        ) {
            const plaintextTermsForChunk = Math.min(
                receiverEncryptionModuleDegree,
                Math.max(
                    receiverRows.plaintextBitLength -
                        chunkIndex * receiverEncryptionModuleDegree,
                    0,
                ),
            );
            secondCiphertextTermsForReceiver +=
                receiverEncryptionModuleDegree *
                    (randomnessTermsPerPolynomialRow + 1) +
                plaintextTermsForChunk;
        }
        witnessTermCount +=
            BigInt(receiverRows.ciphertextChunkCount) *
                BigInt(firstCiphertextTermsPerChunk) +
            BigInt(secondCiphertextTermsForReceiver);
    }

    return {
        ciphertextChunkCount,
        receiverCount: rowBatch.receiverRows.length,
        witnessTermCount,
    };
};

const structuredShareCommitmentSparseTermCount = (
    rowBatch: StructuredShareCommitmentRowBatch,
): bigint => {
    if (rowBatch.shareCommitmentRows.length === 0) {
        return 0n;
    }
    if (
        rowBatch.variableColumnIndices.length %
            rowBatch.shareCommitmentRows.length !==
        0
    ) {
        throw new Error(
            'Structured share-commitment row batch variables are not balanced by receiver.',
        );
    }
    const variableCountPerReceiver =
        rowBatch.variableColumnIndices.length /
        rowBatch.shareCommitmentRows.length;

    return rowBatch.shareCommitmentRows.reduce(
        (termCount, shareCommitmentRow) =>
            termCount +
            BigInt(shareCommitmentRow.rowCount) *
                BigInt(variableCountPerReceiver),
        0n,
    );
};

const rowBatchTermCount = (
    rowBatch: BackendRowBatchForComponentStatement,
): bigint => {
    if (rowBatch.batchKind === 'ExplicitSparseRows') {
        return explicitRowBatchTermCount(rowBatch);
    }
    if (rowBatch.batchKind === 'StructuredModuleSisShareCommitmentRows') {
        return structuredShareCommitmentSparseTermCount(rowBatch);
    }
    if (rowBatch.batchKind === 'StructuredModuleLweReceiverEncryptionRows') {
        return structuredReceiverEncryptionWitnessTermCounts(rowBatch)
            .witnessTermCount;
    }

    return 0n;
};

const denseCoefficientCountForComponentProofStatement = (input: {
    readonly rowCount: number;
    readonly sourceRingDegree: number | null;
    readonly variableColumnCount: number;
}): string | null => {
    if (input.sourceRingDegree === null || input.variableColumnCount === 0) {
        return null;
    }

    return (
        BigInt(input.rowCount) *
        BigInt(input.variableColumnCount) *
        BigInt(input.sourceRingDegree)
    ).toString();
};

export {
    sourceRingDegreeForComponentProofStatement,
    proofSystemRingDegreeForComponentProofStatement,
    proofStatementFormatForComponent,
    proofBackendRequirementForStatementFormat,
    structuredReceiverEncryptionWitnessTermCounts,
    rowBatchTermCount,
    denseCoefficientCountForComponentProofStatement,
};
