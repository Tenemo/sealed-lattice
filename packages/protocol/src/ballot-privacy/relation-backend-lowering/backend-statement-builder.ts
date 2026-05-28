import type { ProtocolHash } from '@sealed-lattice/types';

import { fieldModulus } from '../../plaintext-oracle/field.js';

import {
    buildBackendBounds,
    buildHashExpandedRowBatch,
    buildExplicitBackendRowBatch,
    buildExplicitShareCommitmentRowBatch,
    buildReceiverKeyBindingRows,
    buildReceiverPayloadEncryptionRowBatch,
    buildReceiverPayloadPlaintextBitDecompositionRowBatch,
    buildStructuredShareCommitmentRowBatch,
    shouldUseStructuredShareCommitmentRows,
} from './backend-batches-and-bounds.js';
import type {
    BallotPrivacyAlgebraicRelationRow,
    BallotPrivacyBackendProofComponent,
    BallotPrivacyBackendProofComponentId,
    BallotPrivacyBackendStatementRowBatch,
    BallotPrivacyLinearRelationBound,
    BallotPrivacyLinearRelationRow,
    BallotPrivacyLinearRelationVariable,
    BallotPrivacyProofBackendStatement,
    BallotPrivacyRelationBackendPublicContext,
    ReceiverPayloadReference,
    ReceiverReference,
} from './backend-contracts.js';
import {
    backendBoundsHashPurpose,
    backendMatrixHashPurpose,
    backendProofComponentsHashPurpose,
    backendStatementHashPurpose,
    backendStatementFormat,
    backendTargetVectorHashPurpose,
    receiverEncryptionModulus,
    relationStatementFormat,
} from './backend-contracts.js';
import {
    ballotPrivacyBackendProofComponentOrder,
    componentIdForBatch,
} from './backend-proof-components.js';
import {
    backendVariableColumns,
    buildExplicitSparseRowBatch,
    buildShareCommitmentEquationRows,
    createVariableColumnLookup,
    decimalString,
    deriveBackendHash,
    referencesByReceiver,
} from './backend-row-helpers.js';
import { receiverReferenceKey } from './relation-row-builders.js';

const buildBackendProofComponents = (
    rowBatches: readonly BallotPrivacyBackendStatementRowBatch[],
): readonly BallotPrivacyBackendProofComponent[] => {
    const batchesByComponent = new Map<
        BallotPrivacyBackendProofComponentId,
        BallotPrivacyBackendStatementRowBatch[]
    >();
    for (const rowBatch of rowBatches) {
        const componentId = componentIdForBatch(rowBatch);
        const componentBatches = batchesByComponent.get(componentId) ?? [];
        componentBatches.push(rowBatch);
        batchesByComponent.set(componentId, componentBatches);
    }
    const proofComponents: BallotPrivacyBackendProofComponent[] = [];

    for (const componentId of ballotPrivacyBackendProofComponentOrder) {
        const componentBatches = batchesByComponent.get(componentId) ?? [];
        if (componentBatches.length === 0) {
            continue;
        }
        const variableColumnIndices = [
            ...new Set(
                componentBatches.flatMap(
                    (batch) => batch.variableColumnIndices,
                ),
            ),
        ].sort(
            (leftColumnIndex, rightColumnIndex) =>
                leftColumnIndex - rightColumnIndex,
        );
        const coefficientModuli = new Set(
            componentBatches.map((batch) => batch.modulus),
        );
        if (coefficientModuli.size !== 1) {
            throw new RangeError(
                'Backend proof component batches must share one modulus.',
            );
        }
        const proofLoweringStatus: BallotPrivacyBackendProofComponent['proofLoweringStatus'] =
            componentBatches.every(
                (batch) => batch.batchKind !== 'HashExpandedRows',
            )
                ? 'explicitRowsAvailable'
                : 'HashExpandedRowsPending';
        const componentPayload: Omit<
            BallotPrivacyBackendProofComponent,
            'componentHash'
        > = {
            coefficientModulus: componentBatches[0]?.modulus ?? '',
            componentId,
            proofLoweringStatus,
            rowBatchNames: componentBatches.map((batch) => batch.batchName),
            rowCount: componentBatches.reduce(
                (rowCount, batch) => rowCount + batch.rowCount,
                0,
            ),
            rowKinds: [
                ...new Set(componentBatches.map((batch) => batch.rowKind)),
            ],
            variableColumnCount: variableColumnIndices.length,
            variableColumnIndices,
        };

        proofComponents.push({
            ...componentPayload,
            componentHash: deriveBackendHash(
                backendProofComponentsHashPurpose,
                componentPayload,
            ),
        });
    }

    return proofComponents;
};

const explicitReceiverEncryptionRelationKeys = (input: {
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly receivers: readonly ReceiverReference[];
}): ReadonlySet<string> => {
    const publicKeysByReceiver = referencesByReceiver(
        input.publicContext.receiverPublicKeys,
    );
    const payloadsByReceiver = referencesByReceiver(
        input.publicContext.receiverPayloads,
    );

    return new Set(
        input.receivers.flatMap((receiver) => {
            const receiverKey = receiverReferenceKey(receiver);
            const publicKey = publicKeysByReceiver.get(receiverKey);
            const receiverPayload = payloadsByReceiver.get(receiverKey);

            return publicKey?.publicKeyVector !== undefined &&
                publicKey.publicMatrixSeedHash !== undefined &&
                receiverPayload?.ciphertextChunks !== undefined
                ? [receiverKey]
                : [];
        }),
    );
};

const explicitReceiverKeyRelationKeys = (input: {
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly receivers: readonly ReceiverReference[];
}): ReadonlySet<string> => {
    const publicKeysByReceiver = referencesByReceiver(
        input.publicContext.receiverPublicKeys,
    );

    return new Set(
        input.receivers.flatMap((receiver) => {
            const publicKey = publicKeysByReceiver.get(
                receiverReferenceKey(receiver),
            );

            return publicKey?.publicKeyVector !== undefined &&
                publicKey.publicMatrixSeedHash !== undefined
                ? [receiverReferenceKey(receiver)]
                : [];
        }),
    );
};

const buildBackendStatement = (input: {
    readonly algebraicRows: readonly BallotPrivacyAlgebraicRelationRow[];
    readonly bounds: readonly BallotPrivacyLinearRelationBound[];
    readonly encodedCoordinateCount: number;
    readonly linearRows: readonly BallotPrivacyLinearRelationRow[];
    readonly optionCount: number;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly pvssThreshold: number;
    readonly receivers: readonly ReceiverReference[];
    readonly rosterSize: number;
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly shareVectorWidth: number;
    readonly variables: readonly BallotPrivacyLinearRelationVariable[];
}): BallotPrivacyProofBackendStatement => {
    const columnLookup = createVariableColumnLookup(input.variables);
    const scoreAndShamirRows = input.linearRows.filter((row) =>
        [
            'OneHotSum',
            'ScalarScoreConsistency',
            'ShamirEvaluationQuotient',
        ].includes(row.rowKind),
    );
    const payloadPlaintextBindingRows = input.linearRows.filter((row) =>
        [
            'ReceiverPayloadSharePlaintextBinding',
            'ReceiverPayloadOpeningPlaintextBinding',
        ].includes(row.rowKind),
    );
    const payloadPlaintextBitRows = input.linearRows.filter((row) =>
        [
            'ReceiverPayloadShareBitDecomposition',
            'ReceiverPayloadOpeningBitDecomposition',
        ].includes(row.rowKind),
    );
    const explicitBatches: BallotPrivacyBackendStatementRowBatch[] = [];
    let nextExplicitRowOffset = 0;
    const explicitScoreFieldRowBatch = buildExplicitSparseRowBatch({
        batchName: 'encoded_score_field_rows',
        columnLookup,
        rowKind: 'EncodedScoreFieldRows',
        rowOffset: nextExplicitRowOffset,
        rows: scoreAndShamirRows,
    });
    explicitBatches.push(explicitScoreFieldRowBatch);
    nextExplicitRowOffset += explicitScoreFieldRowBatch.rowCount;
    const explicitPayloadPlaintextRowBatch = buildExplicitSparseRowBatch({
        batchName: 'receiver_payload_plaintext_binding_rows',
        columnLookup,
        rowKind: 'ReceiverPayloadPlaintextBindingRows',
        rowOffset: nextExplicitRowOffset,
        rows: payloadPlaintextBindingRows,
    });
    explicitBatches.push(explicitPayloadPlaintextRowBatch);
    nextExplicitRowOffset += explicitPayloadPlaintextRowBatch.rowCount;
    if (payloadPlaintextBitRows.length > 0) {
        const explicitPayloadPlaintextBitRowBatch =
            buildReceiverPayloadPlaintextBitDecompositionRowBatch({
                columnLookup,
                rowOffset: nextExplicitRowOffset,
                rows: payloadPlaintextBitRows,
            });
        explicitBatches.push(explicitPayloadPlaintextBitRowBatch);
        nextExplicitRowOffset += explicitPayloadPlaintextBitRowBatch.rowCount;
    }
    const shareCommitmentRowsWithPublicVectors = input.algebraicRows.filter(
        (algebraicRow) =>
            algebraicRow.rowKind === 'ShareCommitmentEquation' &&
            algebraicRow.shareCommitmentPolynomialVector !== undefined,
    );
    if (shareCommitmentRowsWithPublicVectors.length > 0) {
        if (
            shouldUseStructuredShareCommitmentRows({
                receiverCount: input.receivers.length,
                shareVectorWidth: input.shareVectorWidth,
            })
        ) {
            const structuredShareCommitmentRowBatch =
                buildStructuredShareCommitmentRowBatch({
                    columnLookup,
                    rowOffset: nextExplicitRowOffset,
                    shareCommitmentProfileHash:
                        input.shareCommitmentProfileHash,
                    shareCommitmentRows: shareCommitmentRowsWithPublicVectors,
                    shareVectorWidth: input.shareVectorWidth,
                });
            explicitBatches.push(structuredShareCommitmentRowBatch);
            nextExplicitRowOffset += structuredShareCommitmentRowBatch.rowCount;
        } else {
            const explicitShareCommitmentRows =
                buildShareCommitmentEquationRows({
                    columnLookup,
                    shareCommitmentProfileHash:
                        input.shareCommitmentProfileHash,
                    shareCommitmentRows: shareCommitmentRowsWithPublicVectors,
                    shareVectorWidth: input.shareVectorWidth,
                });
            const explicitShareCommitmentRowBatch =
                buildExplicitShareCommitmentRowBatch({
                    rowOffset: nextExplicitRowOffset,
                    rows: explicitShareCommitmentRows,
                });
            explicitBatches.push(explicitShareCommitmentRowBatch);
            nextExplicitRowOffset += explicitShareCommitmentRowBatch.rowCount;
        }
    }
    const explicitReceiverEncryptionRowBatch =
        buildReceiverPayloadEncryptionRowBatch({
            columnLookup,
            firstCompactWitnessColumnIndex: input.variables.length,
            publicContext: input.publicContext,
            receivers: input.receivers,
            rowOffset: nextExplicitRowOffset,
            shareVectorWidth: input.shareVectorWidth,
        });
    if (explicitReceiverEncryptionRowBatch !== undefined) {
        explicitBatches.push(explicitReceiverEncryptionRowBatch.rowBatch);
        nextExplicitRowOffset +=
            explicitReceiverEncryptionRowBatch.rowBatch.rowCount;
    }
    const explicitReceiverKeyRows = buildReceiverKeyBindingRows({
        publicContext: input.publicContext,
        receivers: input.receivers,
    });
    if (explicitReceiverKeyRows.length > 0) {
        const explicitReceiverKeyRowBatch = buildExplicitBackendRowBatch({
            batchName: 'receiver_key_binding_rows',
            modulus: decimalString(receiverEncryptionModulus),
            rowKind: 'ReceiverKeyBindingRows',
            rowOffset: nextExplicitRowOffset,
            rows: explicitReceiverKeyRows,
        });
        explicitBatches.push(explicitReceiverKeyRowBatch);
        nextExplicitRowOffset += explicitReceiverKeyRowBatch.rowCount;
    }
    const explicitlyLoweredReceiverEncryptionKeys =
        explicitReceiverEncryptionRelationKeys({
            publicContext: input.publicContext,
            receivers: input.receivers,
        });
    const explicitlyLoweredReceiverKeyKeys = explicitReceiverKeyRelationKeys({
        publicContext: input.publicContext,
        receivers: input.receivers,
    });
    let nextRowOffset = nextExplicitRowOffset;
    const hashExpandedBatches = input.algebraicRows
        .filter((algebraicRow) => {
            if (algebraicRow.rowKind === 'ShareCommitmentEquation') {
                return (
                    algebraicRow.shareCommitmentPolynomialVector === undefined
                );
            }
            const receiverKey = receiverReferenceKey(algebraicRow);
            if (algebraicRow.rowKind === 'ReceiverPayloadEncryptionEquation') {
                return !explicitlyLoweredReceiverEncryptionKeys.has(
                    receiverKey,
                );
            }
            if (algebraicRow.rowKind === 'ReceiverKeyBinding') {
                return !explicitlyLoweredReceiverKeyKeys.has(receiverKey);
            }

            return true;
        })
        .map((algebraicRow) => {
            const batch = buildHashExpandedRowBatch({
                algebraicRow,
                columnLookup,
                rowOffset: nextRowOffset,
            });
            nextRowOffset += batch.rowCount;

            return batch;
        });
    const rowBatches = [...explicitBatches, ...hashExpandedBatches] as const;
    const backendBounds = buildBackendBounds({
        bounds: input.bounds,
        columnLookup,
    });
    const proofComponents = buildBackendProofComponents(rowBatches);
    const explicitRowCount = explicitBatches.reduce(
        (rowCount, batch) => rowCount + batch.rowCount,
        0,
    );
    const hashExpandedRowCount = hashExpandedBatches.reduce(
        (rowCount, batch) => rowCount + batch.rowCount,
        0,
    );
    const matrixHash = deriveBackendHash(backendMatrixHashPurpose, {
        rowBatches: rowBatches.map((batch) => ({
            batchKind: batch.batchKind,
            batchName: batch.batchName,
            matrixHash: batch.matrixHash,
            rowCount: batch.rowCount,
            rowKind: batch.rowKind,
            rowOffset: batch.rowOffset,
        })),
    });
    const targetVectorHash = deriveBackendHash(backendTargetVectorHashPurpose, {
        rowBatches: rowBatches.map((batch) => ({
            batchKind: batch.batchKind,
            batchName: batch.batchName,
            rowCount: batch.rowCount,
            rowKind: batch.rowKind,
            rowOffset: batch.rowOffset,
            targetVectorHash: batch.targetVectorHash,
        })),
    });
    const boundsHash = deriveBackendHash(backendBoundsHashPurpose, {
        bounds: backendBounds,
    });
    const proofComponentsHash = deriveBackendHash(
        backendProofComponentsHashPurpose,
        {
            proofComponents,
        },
    );
    const variableColumns = [
        ...backendVariableColumns(input.variables),
        ...(explicitReceiverEncryptionRowBatch?.compactWitnessVariableColumns ??
            []),
    ];
    const backendStatementPayload: Omit<
        BallotPrivacyProofBackendStatement,
        'backendStatementHash'
    > = {
        backendStatementFormat,
        bounds: backendBounds,
        boundsHash,
        columnCount: variableColumns.length,
        hashExpandedRowCount,
        encodedCoordinateCount: input.encodedCoordinateCount,
        explicitRowCount,
        fieldModulus,
        matrixHash,
        objectType: 'BallotPrivacyProofBackendStatement',
        objectVersion: 1,
        optionCount: input.optionCount,
        proofComponents,
        proofComponentsHash,
        pvssThreshold: input.pvssThreshold,
        relationLabel: 'BallotPrivacyPvssRelation',
        rosterSize: input.rosterSize,
        rowBatches,
        rowCount: explicitRowCount + hashExpandedRowCount,
        shareVectorWidth: input.shareVectorWidth,
        sourceRelationStatementFormat: relationStatementFormat,
        targetVectorHash,
        variableColumns,
    };
    return {
        ...backendStatementPayload,
        backendStatementHash: deriveBackendHash(
            backendStatementHashPurpose,
            backendStatementPayload,
        ),
    };
};

const resolveCiphertextChunkCount = (
    receiverPayload: ReceiverPayloadReference | undefined,
): number =>
    receiverPayload?.ciphertextChunkCount ??
    receiverPayload?.ciphertextChunks?.length ??
    1;

export {
    explicitReceiverEncryptionRelationKeys,
    buildBackendStatement,
    resolveCiphertextChunkCount,
};
