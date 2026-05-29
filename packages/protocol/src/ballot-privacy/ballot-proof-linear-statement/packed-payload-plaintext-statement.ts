import type { ProtocolHash } from '@sealed-lattice/types';

import { fieldModulus } from '../plaintext-oracle-helpers.js';
import { type BallotPrivacyLoweredLinearRelationStatement } from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import { buildPackedScoreAndShamirFieldStatement } from './packed-score-shamir-statement.js';
import type { PackedFieldStatementAccumulator } from './sparse-component-statement.js';
import {
    createPackedFieldStatementAccumulator,
    encodedCoordinateChunkCount,
    encodedCoordinateCountForRelation,
    fieldVariableKey,
    fieldVariableLookupKey,
    requiredFieldVariableColumn,
} from './sparse-component-statement.js';
import type {
    BallotProofSparseComponentLinearProofStatement,
    FieldVariableColumn,
} from './statement-contracts.js';
import {
    linearProofRelation,
    receiverOpeningRandomnessBitLength,
    receiverPayloadOpeningEncodingOffset,
    receiverShareRepresentativeBitLength,
    shareCommitmentOpeningDimension,
} from './statement-contracts.js';
import {
    deriveSparseLinearStatementHash,
    deriveSparseStatementMatrixHash,
    deriveSparseTargetVectorHash,
} from './statement-hashes.js';
import {
    componentById,
    explicitRowBatchesForComponent,
    fieldVariableColumns,
} from './witness-accessors.js';

const buildPackedPayloadPlaintextFieldStatement = (input: {
    readonly accumulator: PackedFieldStatementAccumulator;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly sourceRingDegree: number;
    readonly variableColumnByKey: ReadonlyMap<string, FieldVariableColumn>;
}): number => {
    const encodedCoordinateCount = encodedCoordinateCountForRelation(
        input.relationInput,
    );
    const encodedChunkCount = encodedCoordinateChunkCount({
        encodedCoordinateCount,
        sourceRingDegree: input.sourceRingDegree,
    });
    const openingChunkCount = Math.ceil(
        shareCommitmentOpeningDimension / input.sourceRingDegree,
    );
    const columnByKindReceiverAndChunk = new Map<string, number>();
    const addCoordinatePackedColumn = (inputColumn: {
        readonly packingKind: string;
        readonly receiverRosterPosition: number;
        readonly variableRole: string;
    }): void => {
        for (
            let chunkIndex = 0;
            chunkIndex < encodedChunkCount;
            chunkIndex += 1
        ) {
            const firstCoordinateIndex = chunkIndex * input.sourceRingDegree;
            const coordinateCountInChunk = Math.min(
                input.sourceRingDegree,
                encodedCoordinateCount - firstCoordinateIndex,
            );
            const columnIndex = input.accumulator.addPackedColumn({
                bindings: Array.from(
                    { length: coordinateCountInChunk },
                    (_unusedValue, coefficientIndex) => {
                        const encodedCoordinateIndex =
                            firstCoordinateIndex + coefficientIndex;
                        const variableColumn = requiredFieldVariableColumn({
                            key: fieldVariableLookupKey({
                                encodedCoordinateIndex,
                                receiverRosterPosition:
                                    inputColumn.receiverRosterPosition,
                                variableRole: inputColumn.variableRole,
                            }),
                            label: `${inputColumn.variableRole} ${inputColumn.receiverRosterPosition}:${encodedCoordinateIndex}`,
                            variableColumnByKey: input.variableColumnByKey,
                        });

                        return {
                            backendColumnIndex: variableColumn.columnIndex,
                            coefficientIndex,
                        };
                    },
                ),
                packingKind: `${inputColumn.packingKind}-chunk-${chunkIndex}`,
            });
            columnByKindReceiverAndChunk.set(
                `${inputColumn.variableRole}:${inputColumn.receiverRosterPosition}:${chunkIndex}`,
                columnIndex,
            );
        }
    };
    const addOpeningPackedColumn = (inputColumn: {
        readonly packingKind: string;
        readonly receiverRosterPosition: number;
        readonly variableRole: string;
    }): void => {
        for (
            let chunkIndex = 0;
            chunkIndex < openingChunkCount;
            chunkIndex += 1
        ) {
            const firstOpeningIndex = chunkIndex * input.sourceRingDegree;
            const openingCountInChunk = Math.min(
                input.sourceRingDegree,
                shareCommitmentOpeningDimension - firstOpeningIndex,
            );
            const columnIndex = input.accumulator.addPackedColumn({
                bindings: Array.from(
                    { length: openingCountInChunk },
                    (_unusedValue, coefficientIndex) => {
                        const openingCoordinateIndex =
                            firstOpeningIndex + coefficientIndex;
                        const variableColumn = requiredFieldVariableColumn({
                            key: fieldVariableLookupKey({
                                openingCoordinateIndex,
                                receiverRosterPosition:
                                    inputColumn.receiverRosterPosition,
                                variableRole: inputColumn.variableRole,
                            }),
                            label: `${inputColumn.variableRole} ${inputColumn.receiverRosterPosition}:${openingCoordinateIndex}`,
                            variableColumnByKey: input.variableColumnByKey,
                        });

                        return {
                            backendColumnIndex: variableColumn.columnIndex,
                            coefficientIndex,
                        };
                    },
                ),
                packingKind: `${inputColumn.packingKind}-chunk-${chunkIndex}`,
            });
            columnByKindReceiverAndChunk.set(
                `${inputColumn.variableRole}:${inputColumn.receiverRosterPosition}:${chunkIndex}`,
                columnIndex,
            );
        }
    };
    const addCoordinateBitPackedColumns = (
        receiverRosterPosition: number,
    ): void => {
        for (
            let bitIndex = 0;
            bitIndex < receiverShareRepresentativeBitLength;
            bitIndex += 1
        ) {
            for (
                let chunkIndex = 0;
                chunkIndex < encodedChunkCount;
                chunkIndex += 1
            ) {
                const firstCoordinateIndex =
                    chunkIndex * input.sourceRingDegree;
                const coordinateCountInChunk = Math.min(
                    input.sourceRingDegree,
                    encodedCoordinateCount - firstCoordinateIndex,
                );
                const columnIndex = input.accumulator.addPackedColumn({
                    bindings: Array.from(
                        { length: coordinateCountInChunk },
                        (_unusedValue, coefficientIndex) => {
                            const encodedCoordinateIndex =
                                firstCoordinateIndex + coefficientIndex;
                            const variableColumn = requiredFieldVariableColumn({
                                key: fieldVariableLookupKey({
                                    bitIndex,
                                    encodedCoordinateIndex,
                                    receiverRosterPosition,
                                    variableRole: 'ReceiverPayloadPlaintextBit',
                                }),
                                label: `payload share bit ${receiverRosterPosition}:${encodedCoordinateIndex}:${bitIndex}`,
                                variableColumnByKey: input.variableColumnByKey,
                            });

                            return {
                                backendColumnIndex: variableColumn.columnIndex,
                                coefficientIndex,
                            };
                        },
                    ),
                    packingKind: `receiver-${receiverRosterPosition}-payload-share-bit-${bitIndex}-chunk-${chunkIndex}`,
                });
                columnByKindReceiverAndChunk.set(
                    `ReceiverPayloadPlaintextShareBit:${receiverRosterPosition}:${bitIndex}:${chunkIndex}`,
                    columnIndex,
                );
            }
        }
    };
    const addOpeningBitPackedColumns = (
        receiverRosterPosition: number,
    ): void => {
        for (
            let bitIndex = 0;
            bitIndex < receiverOpeningRandomnessBitLength;
            bitIndex += 1
        ) {
            for (
                let chunkIndex = 0;
                chunkIndex < openingChunkCount;
                chunkIndex += 1
            ) {
                const firstOpeningIndex = chunkIndex * input.sourceRingDegree;
                const openingCountInChunk = Math.min(
                    input.sourceRingDegree,
                    shareCommitmentOpeningDimension - firstOpeningIndex,
                );
                const columnIndex = input.accumulator.addPackedColumn({
                    bindings: Array.from(
                        { length: openingCountInChunk },
                        (_unusedValue, coefficientIndex) => {
                            const openingCoordinateIndex =
                                firstOpeningIndex + coefficientIndex;
                            const variableColumn = requiredFieldVariableColumn({
                                key: fieldVariableLookupKey({
                                    bitIndex,
                                    openingCoordinateIndex,
                                    receiverRosterPosition,
                                    variableRole: 'ReceiverPayloadPlaintextBit',
                                }),
                                label: `payload opening bit ${receiverRosterPosition}:${openingCoordinateIndex}:${bitIndex}`,
                                variableColumnByKey: input.variableColumnByKey,
                            });

                            return {
                                backendColumnIndex: variableColumn.columnIndex,
                                coefficientIndex,
                            };
                        },
                    ),
                    packingKind: `receiver-${receiverRosterPosition}-payload-opening-bit-${bitIndex}-chunk-${chunkIndex}`,
                });
                columnByKindReceiverAndChunk.set(
                    `ReceiverPayloadPlaintextOpeningBit:${receiverRosterPosition}:${bitIndex}:${chunkIndex}`,
                    columnIndex,
                );
            }
        }
    };

    for (const receiver of input.relationInput.receivers) {
        addCoordinatePackedColumn({
            packingKind: `receiver-${receiver.receiverRosterPosition}-payload-share`,
            receiverRosterPosition: receiver.receiverRosterPosition,
            variableRole: 'ReceiverPayloadPlaintextShare',
        });
        addCoordinatePackedColumn({
            packingKind: `receiver-${receiver.receiverRosterPosition}-receiver-share`,
            receiverRosterPosition: receiver.receiverRosterPosition,
            variableRole: 'ReceiverShare',
        });
        addOpeningPackedColumn({
            packingKind: `receiver-${receiver.receiverRosterPosition}-payload-opening`,
            receiverRosterPosition: receiver.receiverRosterPosition,
            variableRole: 'ReceiverPayloadPlaintextOpening',
        });
        addOpeningPackedColumn({
            packingKind: `receiver-${receiver.receiverRosterPosition}-share-opening`,
            receiverRosterPosition: receiver.receiverRosterPosition,
            variableRole: 'ShareCommitmentOpening',
        });
        addCoordinateBitPackedColumns(receiver.receiverRosterPosition);
        addOpeningBitPackedColumns(receiver.receiverRosterPosition);
    }

    const shareBindingRowOffset = 0;
    const openingBindingRowOffset =
        shareBindingRowOffset +
        input.relationInput.receivers.length * encodedChunkCount;
    const shareBitRowOffset =
        openingBindingRowOffset +
        input.relationInput.receivers.length * openingChunkCount;
    const openingBitRowOffset =
        shareBitRowOffset +
        input.relationInput.receivers.length * encodedChunkCount;
    for (const [
        receiverIndex,
        receiver,
    ] of input.relationInput.receivers.entries()) {
        for (
            let chunkIndex = 0;
            chunkIndex < encodedChunkCount;
            chunkIndex += 1
        ) {
            const shareBindingRowIndex =
                shareBindingRowOffset +
                receiverIndex * encodedChunkCount +
                chunkIndex;
            input.accumulator.addMatrixTerm({
                coefficient: 1n,
                columnIndex:
                    columnByKindReceiverAndChunk.get(
                        `ReceiverPayloadPlaintextShare:${receiver.receiverRosterPosition}:${chunkIndex}`,
                    ) ??
                    (() => {
                        throw new Error(
                            'Payload share packed column is missing.',
                        );
                    })(),
                monomialDegree: 0,
                rowIndex: shareBindingRowIndex,
            });
            input.accumulator.addMatrixTerm({
                coefficient: -1n,
                columnIndex:
                    columnByKindReceiverAndChunk.get(
                        `ReceiverShare:${receiver.receiverRosterPosition}:${chunkIndex}`,
                    ) ??
                    (() => {
                        throw new Error(
                            'Receiver share packed column is missing.',
                        );
                    })(),
                monomialDegree: 0,
                rowIndex: shareBindingRowIndex,
            });
            const shareBitRowIndex =
                shareBitRowOffset +
                receiverIndex * encodedChunkCount +
                chunkIndex;
            for (
                let bitIndex = 0;
                bitIndex < receiverShareRepresentativeBitLength;
                bitIndex += 1
            ) {
                input.accumulator.addMatrixTerm({
                    coefficient: 1n << BigInt(bitIndex),
                    columnIndex:
                        columnByKindReceiverAndChunk.get(
                            `ReceiverPayloadPlaintextShareBit:${receiver.receiverRosterPosition}:${bitIndex}:${chunkIndex}`,
                        ) ??
                        (() => {
                            throw new Error(
                                'Payload share-bit packed column is missing.',
                            );
                        })(),
                    monomialDegree: 0,
                    rowIndex: shareBitRowIndex,
                });
            }
            input.accumulator.addMatrixTerm({
                coefficient: -1n,
                columnIndex:
                    columnByKindReceiverAndChunk.get(
                        `ReceiverPayloadPlaintextShare:${receiver.receiverRosterPosition}:${chunkIndex}`,
                    ) ??
                    (() => {
                        throw new Error(
                            'Payload share packed column is missing.',
                        );
                    })(),
                monomialDegree: 0,
                rowIndex: shareBitRowIndex,
            });
        }
        for (
            let chunkIndex = 0;
            chunkIndex < openingChunkCount;
            chunkIndex += 1
        ) {
            const openingBindingRowIndex =
                openingBindingRowOffset +
                receiverIndex * openingChunkCount +
                chunkIndex;
            input.accumulator.addMatrixTerm({
                coefficient: 1n,
                columnIndex:
                    columnByKindReceiverAndChunk.get(
                        `ReceiverPayloadPlaintextOpening:${receiver.receiverRosterPosition}:${chunkIndex}`,
                    ) ??
                    (() => {
                        throw new Error(
                            'Payload opening packed column is missing.',
                        );
                    })(),
                monomialDegree: 0,
                rowIndex: openingBindingRowIndex,
            });
            input.accumulator.addMatrixTerm({
                coefficient: -1n,
                columnIndex:
                    columnByKindReceiverAndChunk.get(
                        `ShareCommitmentOpening:${receiver.receiverRosterPosition}:${chunkIndex}`,
                    ) ??
                    (() => {
                        throw new Error(
                            'Share opening packed column is missing.',
                        );
                    })(),
                monomialDegree: 0,
                rowIndex: openingBindingRowIndex,
            });
            const openingBitRowIndex =
                openingBitRowOffset +
                receiverIndex * openingChunkCount +
                chunkIndex;
            const firstOpeningIndex = chunkIndex * input.sourceRingDegree;
            const openingCountInChunk = Math.min(
                input.sourceRingDegree,
                shareCommitmentOpeningDimension - firstOpeningIndex,
            );
            for (
                let coefficientIndex = 0;
                coefficientIndex < openingCountInChunk;
                coefficientIndex += 1
            ) {
                input.accumulator.addTargetTerm({
                    coefficient: -BigInt(receiverPayloadOpeningEncodingOffset),
                    coefficientIndex,
                    rowIndex: openingBitRowIndex,
                });
            }
            for (
                let bitIndex = 0;
                bitIndex < receiverOpeningRandomnessBitLength;
                bitIndex += 1
            ) {
                input.accumulator.addMatrixTerm({
                    coefficient: 1n << BigInt(bitIndex),
                    columnIndex:
                        columnByKindReceiverAndChunk.get(
                            `ReceiverPayloadPlaintextOpeningBit:${receiver.receiverRosterPosition}:${bitIndex}:${chunkIndex}`,
                        ) ??
                        (() => {
                            throw new Error(
                                'Payload opening-bit packed column is missing.',
                            );
                        })(),
                    monomialDegree: 0,
                    rowIndex: openingBitRowIndex,
                });
            }
            input.accumulator.addMatrixTerm({
                coefficient: -1n,
                columnIndex:
                    columnByKindReceiverAndChunk.get(
                        `ReceiverPayloadPlaintextOpening:${receiver.receiverRosterPosition}:${chunkIndex}`,
                    ) ??
                    (() => {
                        throw new Error(
                            'Payload opening packed column is missing.',
                        );
                    })(),
                monomialDegree: 0,
                rowIndex: openingBitRowIndex,
            });
        }
    }

    return (
        openingBitRowOffset +
        input.relationInput.receivers.length * openingChunkCount
    );
};

const packedFieldProjectionCoverage = (
    componentId:
        | 'score-and-shamir-field-component'
        | 'payload-plaintext-field-component',
): 'encoded-score-field-rows-only' | 'payload-plaintext-field-rows-only' => {
    switch (componentId) {
        case 'score-and-shamir-field-component':
            return 'encoded-score-field-rows-only';
        case 'payload-plaintext-field-component':
            return 'payload-plaintext-field-rows-only';
    }
};

export const buildPackedFieldSparseComponentLinearProofStatement = (input: {
    readonly ballotProofStatementHash?: ProtocolHash;
    readonly componentId:
        | 'score-and-shamir-field-component'
        | 'payload-plaintext-field-component';
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterProfileId: string;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly sourceRingDegree: 64;
    readonly witnessL2BoundSquared: string;
}): BallotProofSparseComponentLinearProofStatement => {
    const component = componentById({
        componentId: input.componentId,
        loweredStatement: input.loweredStatement,
    });
    if (component.coefficientModulus !== fieldModulus.toString()) {
        throw new Error(
            `Packed field statements require the GF(${fieldModulus}) modulus.`,
        );
    }
    const rowBatches = explicitRowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    const invalidModulusBatch = rowBatches.find(
        (rowBatch) => rowBatch.modulus !== component.coefficientModulus,
    );
    if (invalidModulusBatch !== undefined) {
        throw new Error(
            `Proof component ${input.componentId} row batch ${invalidModulusBatch.batchName} uses a mismatched modulus.`,
        );
    }
    const variableColumnByBackendColumn = new Map(
        fieldVariableColumns(input.loweredStatement).map((variableColumn) => [
            variableColumn.columnIndex,
            variableColumn,
        ]),
    );
    const variableColumnByKey = new Map(
        fieldVariableColumns(input.loweredStatement).map((variableColumn) => [
            fieldVariableKey(variableColumn),
            variableColumn,
        ]),
    );
    const accumulator = createPackedFieldStatementAccumulator({
        coefficientModulus: BigInt(fieldModulus),
        sourceRingDegree: input.sourceRingDegree,
        variableColumnByBackendColumn,
    });
    const statementRows =
        input.componentId === 'score-and-shamir-field-component'
            ? buildPackedScoreAndShamirFieldStatement({
                  accumulator,
                  relationInput: input.relationInput,
                  sourceRingDegree: input.sourceRingDegree,
                  variableColumnByKey,
              })
            : buildPackedPayloadPlaintextFieldStatement({
                  accumulator,
                  relationInput: input.relationInput,
                  sourceRingDegree: input.sourceRingDegree,
                  variableColumnByKey,
              });
    const sparseStatementMatrixEntries = accumulator.matrixEntries();
    const targetVectorEntries = accumulator.targetEntries();
    const sparseStatementMatrixHash = deriveSparseStatementMatrixHash(
        sparseStatementMatrixEntries,
    );
    const targetVectorHash = deriveSparseTargetVectorHash(targetVectorEntries);
    const statementPayload: Omit<
        BallotProofSparseComponentLinearProofStatement,
        'statementHash'
    > = {
        backendStatementHash:
            input.loweredStatement.backendStatement.backendStatementHash,
        ...(input.ballotProofStatementHash === undefined
            ? {}
            : {
                  ballotProofStatementHash: input.ballotProofStatementHash,
              }),
        coefficientModulus: component.coefficientModulus,
        objectType: 'BallotProofSparseComponentLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: input.parameterProfileId,
        proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
        projectionCoverage: packedFieldProjectionCoverage(input.componentId),
        relation: linearProofRelation,
        relationStatementHash: input.loweredStatement.relationStatementHash,
        sourceBackendColumnIndices: accumulator.sourceBackendColumnIndices(),
        sourceColumnPackings: accumulator.sourceColumnPackings(),
        sourceRingDegree: input.sourceRingDegree,
        sparseStatementMatrixHash,
        sparseStatementMatrixEntries,
        sparseStatementTermCount:
            sparseStatementMatrixEntries.length.toString(),
        statementColumns: accumulator.statementColumns(),
        statementRows,
        matrixCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetVectorHash,
        targetVectorEntries,
        targetVectorEntryCount: targetVectorEntries.length.toString(),
        witnessL2BoundSquared: input.witnessL2BoundSquared,
    };

    return {
        ...statementPayload,
        statementHash: deriveSparseLinearStatementHash(statementPayload),
    };
};
