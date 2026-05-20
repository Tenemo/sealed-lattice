import type {
    BallotPrivacyBackendProofComponent,
    BallotPrivacyBackendProofComponentId,
} from '../relation-backend-lowering.js';

import type {
    BackendRowBatchForComponentStatement,
    BallotProofComponentProofBytesAvailability,
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
        return 'public-zero-witness-binding-check-v1';
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

const proofBytesAvailabilityForStatementFormat = (
    proofStatementFormat: BallotProofComponentProofStatementFormat,
): BallotProofComponentProofBytesAvailability => {
    switch (proofStatementFormat) {
        case 'dense-polynomial-matrix-linear-proof-v1':
            return 'available-for-small-dense-oracle';
        case 'sparse-polynomial-matrix-linear-proof-v1':
        case 'structured-module-sis-share-commitment-v1':
            return 'requires-sparse-proof-statement';
        case 'structured-module-lwe-linear-proof-v1':
            return 'requires-structured-proof-statement';
        case 'public-zero-witness-binding-check-v1':
            return 'public-zero-witness-binding-check';
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
        return structuredShareCommitmentSparseTermCount(
            rowBatch as StructuredShareCommitmentRowBatch,
        );
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
    proofBytesAvailabilityForStatementFormat,
    structuredReceiverEncryptionWitnessTermCounts,
    rowBatchTermCount,
    denseCoefficientCountForComponentProofStatement,
};
