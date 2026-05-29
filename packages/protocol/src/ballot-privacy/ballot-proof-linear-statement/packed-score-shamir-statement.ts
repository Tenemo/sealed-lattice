import { fieldModulus } from '../plaintext-oracle-helpers.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import type { PackedFieldStatementAccumulator } from './sparse-component-statement.js';
import {
    encodedCoordinateChunkCount,
    encodedCoordinateCountForRelation,
    fieldVariableLookupKey,
    requiredFieldVariableColumn,
} from './sparse-component-statement.js';
import type { FieldVariableColumn } from './statement-contracts.js';
import { fieldPowerForReceiver } from './witness-accessors.js';

const buildPackedScoreAndShamirFieldStatement = (input: {
    readonly accumulator: PackedFieldStatementAccumulator;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly sourceRingDegree: number;
    readonly variableColumnByKey: ReadonlyMap<string, FieldVariableColumn>;
}): number => {
    const encodedCoordinateCount = encodedCoordinateCountForRelation(
        input.relationInput,
    );
    const chunkCount = encodedCoordinateChunkCount({
        encodedCoordinateCount,
        sourceRingDegree: input.sourceRingDegree,
    });
    const scoreColumnByEncodedCoordinate = new Map<number, number>();
    for (
        let encodedCoordinateIndex = 0;
        encodedCoordinateIndex < encodedCoordinateCount;
        encodedCoordinateIndex += 1
    ) {
        const optionIndex = Math.floor(encodedCoordinateIndex / 11);
        const coordinateOffset = encodedCoordinateIndex % 11;
        const variableColumn =
            coordinateOffset === 0
                ? requiredFieldVariableColumn({
                      key: fieldVariableLookupKey({
                          encodedCoordinateIndex,
                          optionIndex,
                          variableRole: 'ScalarScoreConstant',
                      }),
                      label: `scalar score ${optionIndex}`,
                      variableColumnByKey: input.variableColumnByKey,
                  })
                : requiredFieldVariableColumn({
                      key: fieldVariableLookupKey({
                          encodedCoordinateIndex,
                          optionIndex,
                          scoreBucketValue: coordinateOffset,
                          variableRole: 'ScoreBucketConstant',
                      }),
                      label: `score bucket ${optionIndex}:${coordinateOffset}`,
                      variableColumnByKey: input.variableColumnByKey,
                  });
        scoreColumnByEncodedCoordinate.set(
            encodedCoordinateIndex,
            input.accumulator.addPackedColumn({
                bindings: [
                    {
                        backendColumnIndex: variableColumn.columnIndex,
                        coefficientIndex: 0,
                    },
                ],
                packingKind: `score-coordinate-${encodedCoordinateIndex}`,
            }),
        );
    }
    const coefficientColumnByDegreeAndChunk = new Map<string, number>();
    for (
        let coefficientDegree = 1;
        coefficientDegree < input.relationInput.pvssThreshold;
        coefficientDegree += 1
    ) {
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            const firstCoordinateIndex = chunkIndex * input.sourceRingDegree;
            const bindings = Array.from(
                {
                    length: Math.min(
                        input.sourceRingDegree,
                        encodedCoordinateCount - firstCoordinateIndex,
                    ),
                },
                (_unusedValue, coefficientIndex) => {
                    const encodedCoordinateIndex =
                        firstCoordinateIndex + coefficientIndex;
                    const variableColumn = requiredFieldVariableColumn({
                        key: fieldVariableLookupKey({
                            coefficientDegree,
                            encodedCoordinateIndex,
                            variableRole: 'ShamirCoefficient',
                        }),
                        label: `Shamir coefficient ${encodedCoordinateIndex}:${coefficientDegree}`,
                        variableColumnByKey: input.variableColumnByKey,
                    });

                    return {
                        backendColumnIndex: variableColumn.columnIndex,
                        coefficientIndex,
                    };
                },
            );
            coefficientColumnByDegreeAndChunk.set(
                `${coefficientDegree}:${chunkIndex}`,
                input.accumulator.addPackedColumn({
                    bindings,
                    packingKind: `shamir-coefficient-degree-${coefficientDegree}-chunk-${chunkIndex}`,
                }),
            );
        }
    }
    const receiverShareColumnByReceiverAndChunk = new Map<string, number>();
    const quotientColumnByReceiverAndChunk = new Map<string, number>();
    for (const receiver of input.relationInput.receivers) {
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            const firstCoordinateIndex = chunkIndex * input.sourceRingDegree;
            const coordinateCountInChunk = Math.min(
                input.sourceRingDegree,
                encodedCoordinateCount - firstCoordinateIndex,
            );
            receiverShareColumnByReceiverAndChunk.set(
                `${receiver.receiverRosterPosition}:${chunkIndex}`,
                input.accumulator.addPackedColumn({
                    bindings: Array.from(
                        { length: coordinateCountInChunk },
                        (_unusedValue, coefficientIndex) => {
                            const encodedCoordinateIndex =
                                firstCoordinateIndex + coefficientIndex;
                            const variableColumn = requiredFieldVariableColumn({
                                key: fieldVariableLookupKey({
                                    encodedCoordinateIndex,
                                    receiverRosterPosition:
                                        receiver.receiverRosterPosition,
                                    variableRole: 'ReceiverShare',
                                }),
                                label: `receiver share ${receiver.receiverRosterPosition}:${encodedCoordinateIndex}`,
                                variableColumnByKey: input.variableColumnByKey,
                            });

                            return {
                                backendColumnIndex: variableColumn.columnIndex,
                                coefficientIndex,
                            };
                        },
                    ),
                    packingKind: `receiver-${receiver.receiverRosterPosition}-share-chunk-${chunkIndex}`,
                }),
            );
            quotientColumnByReceiverAndChunk.set(
                `${receiver.receiverRosterPosition}:${chunkIndex}`,
                input.accumulator.addPackedColumn({
                    bindings: Array.from(
                        { length: coordinateCountInChunk },
                        (_unusedValue, coefficientIndex) => {
                            const encodedCoordinateIndex =
                                firstCoordinateIndex + coefficientIndex;
                            const variableColumn = requiredFieldVariableColumn({
                                key: fieldVariableLookupKey({
                                    encodedCoordinateIndex,
                                    receiverRosterPosition:
                                        receiver.receiverRosterPosition,
                                    variableRole: 'ShamirQuotient',
                                }),
                                label: `Shamir quotient ${receiver.receiverRosterPosition}:${encodedCoordinateIndex}`,
                                variableColumnByKey: input.variableColumnByKey,
                            });

                            return {
                                backendColumnIndex: variableColumn.columnIndex,
                                coefficientIndex,
                            };
                        },
                    ),
                    packingKind: `receiver-${receiver.receiverRosterPosition}-quotient-chunk-${chunkIndex}`,
                }),
            );
        }
    }

    for (
        let optionIndex = 0;
        optionIndex < input.relationInput.optionCount;
        optionIndex += 1
    ) {
        input.accumulator.addTargetTerm({
            coefficient: -1n,
            coefficientIndex: optionIndex,
            rowIndex: 0,
        });
        for (
            let scoreBucketValue = 1;
            scoreBucketValue <= 10;
            scoreBucketValue += 1
        ) {
            const encodedCoordinateIndex = optionIndex * 11 + scoreBucketValue;
            input.accumulator.addMatrixTerm({
                coefficient: 1n,
                columnIndex:
                    scoreColumnByEncodedCoordinate.get(
                        encodedCoordinateIndex,
                    ) ??
                    (() => {
                        throw new Error('Score coordinate column is missing.');
                    })(),
                monomialDegree: optionIndex,
                rowIndex: 0,
            });
            input.accumulator.addMatrixTerm({
                coefficient: -BigInt(scoreBucketValue),
                columnIndex:
                    scoreColumnByEncodedCoordinate.get(
                        encodedCoordinateIndex,
                    ) ??
                    (() => {
                        throw new Error('Score coordinate column is missing.');
                    })(),
                monomialDegree: optionIndex,
                rowIndex: 1,
            });
        }
        input.accumulator.addMatrixTerm({
            coefficient: 1n,
            columnIndex:
                scoreColumnByEncodedCoordinate.get(optionIndex * 11) ??
                (() => {
                    throw new Error('Scalar score column is missing.');
                })(),
            monomialDegree: optionIndex,
            rowIndex: 1,
        });
    }

    const shamirRowOffset = 2;
    for (const [
        receiverIndex,
        receiver,
    ] of input.relationInput.receivers.entries()) {
        for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
            const rowIndex =
                shamirRowOffset + receiverIndex * chunkCount + chunkIndex;
            const firstCoordinateIndex = chunkIndex * input.sourceRingDegree;
            const coordinateCountInChunk = Math.min(
                input.sourceRingDegree,
                encodedCoordinateCount - firstCoordinateIndex,
            );
            for (
                let coefficientIndex = 0;
                coefficientIndex < coordinateCountInChunk;
                coefficientIndex += 1
            ) {
                const encodedCoordinateIndex =
                    firstCoordinateIndex + coefficientIndex;
                input.accumulator.addMatrixTerm({
                    coefficient: 1n,
                    columnIndex:
                        scoreColumnByEncodedCoordinate.get(
                            encodedCoordinateIndex,
                        ) ??
                        (() => {
                            throw new Error(
                                'Score coordinate column is missing.',
                            );
                        })(),
                    monomialDegree: coefficientIndex,
                    rowIndex,
                });
            }
            for (
                let coefficientDegree = 1;
                coefficientDegree < input.relationInput.pvssThreshold;
                coefficientDegree += 1
            ) {
                input.accumulator.addMatrixTerm({
                    coefficient: BigInt(
                        fieldPowerForReceiver(
                            receiver.receiverRosterPosition,
                            coefficientDegree,
                        ),
                    ),
                    columnIndex:
                        coefficientColumnByDegreeAndChunk.get(
                            `${coefficientDegree}:${chunkIndex}`,
                        ) ??
                        (() => {
                            throw new Error(
                                'Shamir coefficient packed column is missing.',
                            );
                        })(),
                    monomialDegree: 0,
                    rowIndex,
                });
            }
            input.accumulator.addMatrixTerm({
                coefficient: -1n,
                columnIndex:
                    receiverShareColumnByReceiverAndChunk.get(
                        `${receiver.receiverRosterPosition}:${chunkIndex}`,
                    ) ??
                    (() => {
                        throw new Error(
                            'Receiver share packed column is missing.',
                        );
                    })(),
                monomialDegree: 0,
                rowIndex,
            });
            input.accumulator.addMatrixTerm({
                coefficient: -BigInt(fieldModulus),
                columnIndex:
                    quotientColumnByReceiverAndChunk.get(
                        `${receiver.receiverRosterPosition}:${chunkIndex}`,
                    ) ??
                    (() => {
                        throw new Error(
                            'Shamir quotient packed column is missing.',
                        );
                    })(),
                monomialDegree: 0,
                rowIndex,
            });
        }
    }

    return shamirRowOffset + input.relationInput.receivers.length * chunkCount;
};

export { buildPackedScoreAndShamirFieldStatement };
