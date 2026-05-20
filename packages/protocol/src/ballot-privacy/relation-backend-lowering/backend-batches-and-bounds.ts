import type { ProtocolDigest } from '@sealed-lattice/types';

import { fieldModulus } from '../../plaintext-oracle/field.js';

import type {
    BallotPrivacyAlgebraicRelationRow,
    BallotPrivacyBackendProofComponentId,
    BallotPrivacyBackendStatementBound,
    BallotPrivacyBackendStatementExplicitRow,
    BallotPrivacyBackendStatementReceiverEncryptionRowDescriptor,
    BallotPrivacyBackendStatementRowBatch,
    BallotPrivacyBackendStatementVariableColumn,
    BallotPrivacyLinearRelationBound,
    BallotPrivacyLinearRelationRow,
    BallotPrivacyRelationBackendPublicContext,
    ReceiverReference,
} from './backend-contracts.js';
import {
    digestExpandedBackendMatrixDigestPurpose,
    digestExpandedBackendTargetVectorDigestPurpose,
    explicitBackendMatrixDigestPurpose,
    explicitBackendTargetVectorDigestPurpose,
    receiverEncryptionFirstNoiseVariableName,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    receiverEncryptionRandomnessVariableName,
    receiverEncryptionSecondNoiseVariableName,
    receiverOpeningRandomnessBitLength,
    receiverPayloadPlaintextBitVariableNameForLayout,
    receiverShareRepresentativeBitLength,
    shareCommitmentModuleRank,
    shareCommitmentModulus,
    shareCommitmentOpeningDimension,
    structuredShareCommitmentBackendMatrixDigestPurpose,
    structuredShareCommitmentBackendTargetVectorDigestPurpose,
} from './backend-contracts.js';
import {
    backendTermsForLinearRow,
    compactReceiverEncryptionWitnessVariableColumns,
    decimalString,
    deriveBackendDigest,
    referencesByReceiver,
    requireColumnIndex,
    validateReceiverPayloadCiphertextChunks,
    validateReceiverPublicKeyVector,
} from './backend-row-helpers.js';
import { receiverReferenceKey } from './relation-row-builders.js';

const buildExplicitShareCommitmentRowBatch = (input: {
    readonly rowOffset: number;
    readonly rows: readonly BallotPrivacyBackendStatementExplicitRow[];
}): BallotPrivacyBackendStatementRowBatch => {
    const variableColumnIndices = [
        ...new Set(
            input.rows.flatMap((row) =>
                row.terms.map((term) => term.columnIndex),
            ),
        ),
    ].sort((leftColumn, rightColumn) => leftColumn - rightColumn);

    return {
        batchKind: 'ExplicitSparseRows',
        batchName: 'share_commitment_equation_rows',
        matrixDigest: deriveBackendDigest(explicitBackendMatrixDigestPurpose, {
            rows: input.rows.map(({ rowIndex, rowKind, rowName, terms }) => ({
                rowIndex,
                rowKind,
                rowName,
                terms,
            })),
        }),
        modulus: shareCommitmentModulus,
        rowCount: input.rows.length,
        rowKind: 'ShareCommitmentEquationRows',
        rowOffset: input.rowOffset,
        rows: input.rows,
        targetVectorDigest: deriveBackendDigest(
            explicitBackendTargetVectorDigestPurpose,
            {
                targets: input.rows.map(
                    ({ rowIndex, rowKind, rowName, target }) => ({
                        rowIndex,
                        rowKind,
                        rowName,
                        target,
                    }),
                ),
            },
        ),
        variableColumnIndices,
    };
};

const shouldUseStructuredShareCommitmentRows = (input: {
    readonly shareVectorWidth: number;
}): boolean => input.shareVectorWidth > 64;

const shouldUseCompactReceiverEncryptionWitnessColumns = (input: {
    readonly shareVectorWidth: number;
}): boolean => input.shareVectorWidth > 64;

const buildStructuredShareCommitmentRowBatch = (input: {
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly rowOffset: number;
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly shareCommitmentRows: readonly BallotPrivacyAlgebraicRelationRow[];
    readonly shareVectorWidth: number;
}): BallotPrivacyBackendStatementRowBatch => {
    const shareCommitmentRows = input.shareCommitmentRows.map(
        (shareCommitmentRow, receiverIndex) => {
            if (
                shareCommitmentRow.shareCommitmentPolynomialVector?.length !==
                shareCommitmentModuleRank
            ) {
                throw new Error(
                    'Structured share-commitment rows require explicit commitment polynomial vectors.',
                );
            }

            return {
                commitmentBodyDigest:
                    shareCommitmentRow.publicInputDigests.commitmentBodyDigest,
                commitmentPolynomialVectorDigest:
                    shareCommitmentRow.publicInputDigests
                        .commitmentPolynomialVectorDigest,
                receiverIdentity: shareCommitmentRow.receiverIdentity,
                receiverRosterPosition:
                    shareCommitmentRow.receiverRosterPosition,
                rowCount: shareCommitmentModuleRank,
                rowOffsetWithinBatch: receiverIndex * shareCommitmentModuleRank,
                shareCommitmentDigest:
                    shareCommitmentRow.publicInputDigests.shareCommitmentDigest,
            };
        },
    );
    const variableColumnIndices = [
        ...new Set(
            input.shareCommitmentRows.flatMap((row) =>
                row.variableNames.map((variableName) =>
                    requireColumnIndex(input.columnLookup, variableName),
                ),
            ),
        ),
    ].sort((leftColumn, rightColumn) => leftColumn - rightColumn);
    const targetRows = input.shareCommitmentRows.flatMap(
        (shareCommitmentRow, receiverIndex) =>
            (shareCommitmentRow.shareCommitmentPolynomialVector ?? []).map(
                (polynomialCoefficients, moduleRowIndex) => ({
                    polynomialCoefficients,
                    receiverIdentity: shareCommitmentRow.receiverIdentity,
                    receiverRosterPosition:
                        shareCommitmentRow.receiverRosterPosition,
                    rowIndex:
                        receiverIndex * shareCommitmentModuleRank +
                        moduleRowIndex,
                }),
            ),
    );

    return {
        batchKind: 'StructuredModuleSisShareCommitmentRows',
        batchName: 'share_commitment_equation_rows',
        matrixDigest: deriveBackendDigest(
            structuredShareCommitmentBackendMatrixDigestPurpose,
            {
                matrixDerivation:
                    'share-commitment-profile-digest-expanded-polynomial-matrix',
                rowCount:
                    input.shareCommitmentRows.length *
                    shareCommitmentModuleRank,
                shareCommitmentProfileDigest:
                    input.shareCommitmentProfileDigest,
                shareCommitmentRows,
                shareVectorWidth: input.shareVectorWidth,
                variableColumnIndices,
            },
        ),
        modulus: shareCommitmentModulus,
        rowCount: input.shareCommitmentRows.length * shareCommitmentModuleRank,
        rowKind: 'ShareCommitmentEquationRows',
        rowOffset: input.rowOffset,
        shareCommitmentRows,
        targetVectorDigest: deriveBackendDigest(
            structuredShareCommitmentBackendTargetVectorDigestPurpose,
            {
                targetRows,
            },
        ),
        variableColumnIndices,
    };
};

const buildExplicitBackendRowBatch = (input: {
    readonly batchName:
        | 'receiver_key_binding_rows'
        | 'receiver_payload_encryption_equation_rows'
        | 'receiver_payload_plaintext_bit_decomposition_rows';
    readonly modulus: string;
    readonly rowKind:
        | 'ReceiverKeyBindingRows'
        | 'ReceiverPayloadEncryptionEquationRows'
        | 'ReceiverPayloadPlaintextBitDecompositionRows';
    readonly rowOffset: number;
    readonly rows: readonly BallotPrivacyBackendStatementExplicitRow[];
}): BallotPrivacyBackendStatementRowBatch => {
    const variableColumnIndices = [
        ...new Set(
            input.rows.flatMap((row) =>
                row.terms.map((term) => term.columnIndex),
            ),
        ),
    ].sort((leftColumn, rightColumn) => leftColumn - rightColumn);

    return {
        batchKind: 'ExplicitSparseRows',
        batchName: input.batchName,
        matrixDigest: deriveBackendDigest(explicitBackendMatrixDigestPurpose, {
            rows: input.rows.map(({ rowIndex, rowKind, rowName, terms }) => ({
                rowIndex,
                rowKind,
                rowName,
                terms,
            })),
        }),
        modulus: input.modulus,
        rowCount: input.rows.length,
        rowKind: input.rowKind,
        rowOffset: input.rowOffset,
        rows: input.rows,
        targetVectorDigest: deriveBackendDigest(
            explicitBackendTargetVectorDigestPurpose,
            {
                targets: input.rows.map(
                    ({ rowIndex, rowKind, rowName, target }) => ({
                        rowIndex,
                        rowKind,
                        rowName,
                        target,
                    }),
                ),
            },
        ),
        variableColumnIndices,
    };
};

const buildReceiverPayloadPlaintextBitDecompositionRowBatch = (input: {
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly rowOffset: number;
    readonly rows: readonly BallotPrivacyLinearRelationRow[];
}): BallotPrivacyBackendStatementRowBatch => {
    const rows = input.rows.map((row, rowIndex) => ({
        modulus: decimalString(row.modulus),
        rowIndex,
        rowKind: row.rowKind,
        rowName: row.rowName,
        target: decimalString(row.target),
        terms: backendTermsForLinearRow(row, input.columnLookup),
    }));

    return buildExplicitBackendRowBatch({
        batchName: 'receiver_payload_plaintext_bit_decomposition_rows',
        modulus: decimalString(fieldModulus),
        rowKind: 'ReceiverPayloadPlaintextBitDecompositionRows',
        rowOffset: input.rowOffset,
        rows,
    });
};

const receiverPayloadEncryptionVariableColumnIndices = (input: {
    readonly ciphertextChunkCount: number;
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly plaintextBitLength: number;
    readonly receiverRosterPosition: number;
    readonly shareVectorWidth: number;
}): readonly number[] => {
    const variableNames: string[] = [];
    for (
        let plaintextBitIndex = 0;
        plaintextBitIndex < input.plaintextBitLength;
        plaintextBitIndex += 1
    ) {
        variableNames.push(
            receiverPayloadPlaintextBitVariableNameForLayout(
                input.receiverRosterPosition,
                input.shareVectorWidth,
                plaintextBitIndex,
            ),
        );
    }
    for (
        let chunkIndex = 0;
        chunkIndex < input.ciphertextChunkCount;
        chunkIndex += 1
    ) {
        for (
            let vectorIndex = 0;
            vectorIndex < receiverEncryptionModuleRank;
            vectorIndex += 1
        ) {
            for (
                let coefficientIndex = 0;
                coefficientIndex < receiverEncryptionModuleDegree;
                coefficientIndex += 1
            ) {
                variableNames.push(
                    receiverEncryptionRandomnessVariableName(
                        input.receiverRosterPosition,
                        chunkIndex,
                        vectorIndex,
                        coefficientIndex,
                    ),
                    receiverEncryptionFirstNoiseVariableName(
                        input.receiverRosterPosition,
                        chunkIndex,
                        vectorIndex,
                        coefficientIndex,
                    ),
                );
            }
        }
        for (
            let coefficientIndex = 0;
            coefficientIndex < receiverEncryptionModuleDegree;
            coefficientIndex += 1
        ) {
            variableNames.push(
                receiverEncryptionSecondNoiseVariableName(
                    input.receiverRosterPosition,
                    chunkIndex,
                    coefficientIndex,
                ),
            );
        }
    }

    return [
        ...new Set(
            variableNames.map((variableName) =>
                requireColumnIndex(input.columnLookup, variableName),
            ),
        ),
    ].sort((leftColumn, rightColumn) => leftColumn - rightColumn);
};

const buildReceiverPayloadEncryptionRowBatch = (input: {
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly firstCompactWitnessColumnIndex: number;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly receivers: readonly ReceiverReference[];
    readonly rowOffset: number;
    readonly shareVectorWidth: number;
}):
    | {
          readonly compactWitnessVariableColumns: readonly BallotPrivacyBackendStatementVariableColumn[];
          readonly rowBatch: BallotPrivacyBackendStatementRowBatch;
      }
    | undefined => {
    const publicKeysByReceiver = referencesByReceiver(
        input.publicContext.receiverPublicKeys,
    );
    const payloadsByReceiver = referencesByReceiver(
        input.publicContext.receiverPayloads,
    );
    const receiverRows: BallotPrivacyBackendStatementReceiverEncryptionRowDescriptor[] =
        [];
    const variableColumnIndices: number[] = [];
    const compactWitnessVariableColumns: BallotPrivacyBackendStatementVariableColumn[] =
        [];
    let nextCompactWitnessColumnIndex = input.firstCompactWitnessColumnIndex;
    let rowOffsetWithinBatch = 0;

    for (const receiver of input.receivers) {
        const receiverKey = receiverReferenceKey(receiver);
        const publicKey = publicKeysByReceiver.get(receiverKey);
        const receiverPayload = payloadsByReceiver.get(receiverKey);
        if (
            publicKey?.publicKeyVector === undefined ||
            publicKey.publicMatrixSeedDigest === undefined ||
            receiverPayload?.ciphertextChunks === undefined
        ) {
            continue;
        }
        validateReceiverPublicKeyVector({
            publicKeyVector: publicKey.publicKeyVector,
            receiverRosterPosition: receiver.receiverRosterPosition,
        });
        validateReceiverPayloadCiphertextChunks({
            ciphertextChunks: receiverPayload.ciphertextChunks,
            receiverRosterPosition: receiver.receiverRosterPosition,
        });
        const plaintextBitLength =
            receiverPayload.plaintextBitLength ??
            input.shareVectorWidth * receiverShareRepresentativeBitLength +
                shareCommitmentOpeningDimension *
                    receiverOpeningRandomnessBitLength;
        if (
            plaintextBitLength >
            receiverPayload.ciphertextChunks.length *
                receiverEncryptionModuleDegree
        ) {
            throw new RangeError(
                `Receiver ${receiver.receiverRosterPosition} ciphertext chunks do not cover the declared plaintext bit length.`,
            );
        }
        const rowCount =
            receiverPayload.ciphertextChunks.length *
            (receiverEncryptionModuleRank + 1) *
            receiverEncryptionModuleDegree;
        if (
            shouldUseCompactReceiverEncryptionWitnessColumns({
                shareVectorWidth: input.shareVectorWidth,
            })
        ) {
            const receiverCompactWitnessVariableColumns =
                compactReceiverEncryptionWitnessVariableColumns({
                    ciphertextChunkCount:
                        receiverPayload.ciphertextChunks.length,
                    firstColumnIndex: nextCompactWitnessColumnIndex,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                });
            compactWitnessVariableColumns.push(
                ...receiverCompactWitnessVariableColumns,
            );
            variableColumnIndices.push(
                ...receiverCompactWitnessVariableColumns.map(
                    (variableColumn) => variableColumn.columnIndex,
                ),
            );
            nextCompactWitnessColumnIndex +=
                receiverCompactWitnessVariableColumns.length;
        } else {
            variableColumnIndices.push(
                ...receiverPayloadEncryptionVariableColumnIndices({
                    ciphertextChunkCount:
                        receiverPayload.ciphertextChunks.length,
                    columnLookup: input.columnLookup,
                    plaintextBitLength,
                    receiverRosterPosition: receiver.receiverRosterPosition,
                    shareVectorWidth: input.shareVectorWidth,
                }),
            );
        }
        receiverRows.push({
            ciphertextChunkCount: receiverPayload.ciphertextChunks.length,
            plaintextBitLength,
            receiverIdentity: receiver.receiverIdentity,
            receiverPayloadDigest: receiverPayload.receiverPayloadDigest,
            receiverPublicKeyDigest: publicKey.receiverPublicKeyDigest,
            receiverRosterPosition: receiver.receiverRosterPosition,
            rowCount,
            rowOffsetWithinBatch,
        });
        rowOffsetWithinBatch += rowCount;
    }

    if (receiverRows.length === 0) {
        return undefined;
    }
    const sortedVariableColumnIndices = [
        ...new Set(variableColumnIndices),
    ].sort((leftColumn, rightColumn) => leftColumn - rightColumn);
    const digestPayload = {
        receiverEncryptionProfileDigest:
            input.publicContext.receiverEncryptionProfileDigest,
        receiverRows,
        variableColumnIndices: sortedVariableColumnIndices,
    };

    return {
        compactWitnessVariableColumns,
        rowBatch: {
            batchKind: 'StructuredModuleLweReceiverEncryptionRows',
            batchName: 'receiver_payload_encryption_equation_rows',
            matrixDigest: deriveBackendDigest(
                explicitBackendMatrixDigestPurpose,
                {
                    ...digestPayload,
                    matrixKind: 'module-lwe-receiver-encryption-rows',
                },
            ),
            modulus: decimalString(receiverEncryptionModulus),
            receiverRows,
            rowCount: rowOffsetWithinBatch,
            rowKind: 'ReceiverPayloadEncryptionEquationRows',
            rowOffset: input.rowOffset,
            targetVectorDigest: deriveBackendDigest(
                explicitBackendTargetVectorDigestPurpose,
                {
                    ciphertextChunks: input.publicContext.receiverPayloads.map(
                        (receiverPayload) => ({
                            ciphertextChunkDigest:
                                receiverPayload.ciphertextChunkDigest,
                            receiverIdentity: receiverPayload.receiverIdentity,
                            receiverPayloadCiphertextRoot:
                                receiverPayload.receiverPayloadCiphertextRoot,
                            receiverPayloadDigest:
                                receiverPayload.receiverPayloadDigest,
                            receiverRosterPosition:
                                receiverPayload.receiverRosterPosition,
                        }),
                    ),
                    ...digestPayload,
                    targetKind:
                        'module-lwe-receiver-encryption-ciphertext-rows',
                },
            ),
            variableColumnIndices: sortedVariableColumnIndices,
        },
    };
};

const buildReceiverKeyBindingRows = (input: {
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly receivers: readonly ReceiverReference[];
}): readonly BallotPrivacyBackendStatementExplicitRow[] => {
    const publicKeysByReceiver = referencesByReceiver(
        input.publicContext.receiverPublicKeys,
    );
    const rows: BallotPrivacyBackendStatementExplicitRow[] = [];

    for (const receiver of input.receivers) {
        const publicKey = publicKeysByReceiver.get(
            receiverReferenceKey(receiver),
        );
        if (
            publicKey?.publicKeyVector === undefined ||
            publicKey.publicMatrixSeedDigest === undefined
        ) {
            continue;
        }
        validateReceiverPublicKeyVector({
            publicKeyVector: publicKey.publicKeyVector,
            receiverRosterPosition: receiver.receiverRosterPosition,
        });
        for (
            let vectorIndex = 0;
            vectorIndex < receiverEncryptionModuleRank;
            vectorIndex += 1
        ) {
            for (
                let coefficientIndex = 0;
                coefficientIndex < receiverEncryptionModuleDegree;
                coefficientIndex += 1
            ) {
                rows.push({
                    modulus: decimalString(receiverEncryptionModulus),
                    rowIndex: rows.length,
                    rowKind: 'ReceiverKeyBinding',
                    rowName: `receiver_${receiver.receiverRosterPosition}_receiver_key_binding_vector_${vectorIndex}_coefficient_${coefficientIndex}`,
                    target: '0',
                    terms: [],
                });
            }
        }
    }

    return rows;
};

const buildDigestExpandedRowBatch = (input: {
    readonly algebraicRow: BallotPrivacyAlgebraicRelationRow;
    readonly columnLookup: ReadonlyMap<string, number>;
    readonly rowOffset: number;
}): BallotPrivacyBackendStatementRowBatch => {
    const variableColumnIndices = input.algebraicRow.variableNames.map(
        (variableName) => requireColumnIndex(input.columnLookup, variableName),
    );
    const coefficientExpansionDomain = `sealed.vote/internal/ballot-privacy/${input.algebraicRow.rowKind}/coefficient-expansion-v1`;
    const targetExpansionDomain = `sealed.vote/internal/ballot-privacy/${input.algebraicRow.rowKind}/target-expansion-v1`;
    const expansionPayload = {
        coefficientExpansionDomain,
        modulus: decimalString(input.algebraicRow.modulus),
        publicInputDigests: input.algebraicRow.publicInputDigests,
        receiverIdentity: input.algebraicRow.receiverIdentity,
        receiverRosterPosition: input.algebraicRow.receiverRosterPosition,
        rowCount: input.algebraicRow.equationCount,
        rowKind: input.algebraicRow.rowKind,
        sourceAlgebraicRowName: input.algebraicRow.rowName,
        targetDigest: input.algebraicRow.targetDigest,
        targetExpansionDomain,
        variableColumnIndices,
    };

    return {
        batchKind: 'DigestExpandedRows',
        batchName: `${input.algebraicRow.rowName}_backend_rows`,
        coefficientExpansionDomain,
        matrixDigest: deriveBackendDigest(
            digestExpandedBackendMatrixDigestPurpose,
            expansionPayload,
        ),
        modulus: decimalString(input.algebraicRow.modulus),
        publicInputDigests: input.algebraicRow.publicInputDigests,
        receiverIdentity: input.algebraicRow.receiverIdentity,
        receiverRosterPosition: input.algebraicRow.receiverRosterPosition,
        rowCount: input.algebraicRow.equationCount,
        rowKind: input.algebraicRow.rowKind,
        rowOffset: input.rowOffset,
        sourceAlgebraicRowName: input.algebraicRow.rowName,
        targetDigest: input.algebraicRow.targetDigest,
        targetExpansionDomain,
        targetVectorDigest: deriveBackendDigest(
            digestExpandedBackendTargetVectorDigestPurpose,
            expansionPayload,
        ),
        variableColumnIndices,
    };
};

const buildBackendBounds = (input: {
    readonly bounds: readonly BallotPrivacyLinearRelationBound[];
    readonly columnLookup: ReadonlyMap<string, number>;
}): readonly BallotPrivacyBackendStatementBound[] =>
    input.bounds.map((bound) => {
        const backendBound: BallotPrivacyBackendStatementBound = {
            boundKind: bound.boundKind,
            boundName: bound.boundName,
            variableColumnIndices: bound.variableNames.map((variableName) =>
                requireColumnIndex(input.columnLookup, variableName),
            ),
            variableNames: bound.variableNames,
        };

        if (bound.absoluteMaximum !== undefined) {
            return {
                ...backendBound,
                absoluteMaximum: decimalString(bound.absoluteMaximum),
            };
        }
        if (bound.minimum !== undefined && bound.maximum !== undefined) {
            return {
                ...backendBound,
                maximum: decimalString(bound.maximum),
                minimum: decimalString(bound.minimum),
            };
        }

        return backendBound;
    });

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

export const ballotPrivacyBackendProofComponentOrder: readonly BallotPrivacyBackendProofComponentId[] =
    [
        'score-and-shamir-field-component',
        'payload-plaintext-field-component',
        'share-commitment-component',
        'receiver-encryption-component',
        'receiver-key-binding-component',
    ];

export {
    buildExplicitShareCommitmentRowBatch,
    shouldUseStructuredShareCommitmentRows,
    shouldUseCompactReceiverEncryptionWitnessColumns,
    buildStructuredShareCommitmentRowBatch,
    buildExplicitBackendRowBatch,
    buildReceiverPayloadPlaintextBitDecompositionRowBatch,
    buildReceiverPayloadEncryptionRowBatch,
    buildReceiverKeyBindingRows,
    buildDigestExpandedRowBatch,
    buildBackendBounds,
    componentIdForBatch,
};
