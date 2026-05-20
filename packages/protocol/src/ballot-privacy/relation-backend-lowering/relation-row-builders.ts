import { fieldModulus } from '../../plaintext-oracle/field.js';
import {
    ballotPrivacyEncodedCoordinatesPerOption,
    ballotPrivacyScoreBucketCount,
    getBallotPrivacyEncodedShareVectorWidth,
    getBallotPrivacyScalarCoordinateIndex,
    getBallotPrivacyScoreBucketCoordinateIndex,
} from '../encoded-share-layout.js';
import { type BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import type {
    BallotPrivacyLinearRelationRow,
    ReceiverReference,
    VariableRegistry,
} from './backend-contracts.js';
import {
    digestExpandedReceiverEncryptionNoiseVariableName,
    digestExpandedReceiverEncryptionRandomnessVariableName,
    receiverEncryptionFirstNoiseVariableName,
    receiverEncryptionModuleDegree,
    receiverEncryptionRandomnessVariableName,
    receiverEncryptionSecondNoiseVariableName,
    receiverOpeningRandomnessBitLength,
    receiverPayloadPlaintextOpeningBitVariableName,
    receiverPayloadPlaintextOpeningVariableName,
    receiverPayloadPlaintextShareBitVariableName,
    receiverPayloadPlaintextShareVariableName,
    receiverShareRepresentativeBitLength,
    receiverShareVariableName,
    scalarConstantVariableName,
    scoreBucketConstantVariableName,
    shamirCoefficientVariableName,
    shamirQuotientVariableName,
    shareCommitmentOpeningDimension,
    shareCommitmentOpeningInfinityNormBound,
    shareCommitmentOpeningVariableName,
} from './backend-contracts.js';

const addScalarConstantVariable = (
    registry: VariableRegistry,
    optionIndex: number,
): string => {
    const encodedCoordinateIndex =
        getBallotPrivacyScalarCoordinateIndex(optionIndex);

    return registry.add({
        encodedCoordinateIndex,
        optionIndex,
        variableName: scalarConstantVariableName(optionIndex),
        variableRole: 'ScalarScoreConstant',
    }).variableName;
};

const addScoreBucketConstantVariable = (
    registry: VariableRegistry,
    optionIndex: number,
    scoreBucketValue: number,
): string => {
    const encodedCoordinateIndex = getBallotPrivacyScoreBucketCoordinateIndex(
        optionIndex,
        scoreBucketValue,
    );

    return registry.add({
        encodedCoordinateIndex,
        optionIndex,
        scoreBucketValue,
        variableName: scoreBucketConstantVariableName(
            optionIndex,
            scoreBucketValue,
        ),
        variableRole: 'ScoreBucketConstant',
    }).variableName;
};

const addShamirCoefficientVariable = (
    registry: VariableRegistry,
    encodedCoordinateIndex: number,
    coefficientDegree: number,
): string =>
    registry.add({
        coefficientDegree,
        encodedCoordinateIndex,
        variableName: shamirCoefficientVariableName(
            encodedCoordinateIndex,
            coefficientDegree,
        ),
        variableRole: 'ShamirCoefficient',
    }).variableName;

const addReceiverShareVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    registry.add({
        encodedCoordinateIndex,
        receiverRosterPosition,
        variableName: receiverShareVariableName(
            receiverRosterPosition,
            encodedCoordinateIndex,
        ),
        variableRole: 'ReceiverShare',
    }).variableName;

const addShamirQuotientVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    registry.add({
        encodedCoordinateIndex,
        receiverRosterPosition,
        variableName: shamirQuotientVariableName(
            receiverRosterPosition,
            encodedCoordinateIndex,
        ),
        variableRole: 'ShamirQuotient',
    }).variableName;

const addShareCommitmentOpeningVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): string =>
    registry.add({
        openingCoordinateIndex,
        receiverRosterPosition,
        variableName: shareCommitmentOpeningVariableName(
            receiverRosterPosition,
            openingCoordinateIndex,
        ),
        variableRole: 'ShareCommitmentOpening',
    }).variableName;

const addReceiverPayloadPlaintextShareVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    registry.add({
        encodedCoordinateIndex,
        receiverRosterPosition,
        variableName: receiverPayloadPlaintextShareVariableName(
            receiverRosterPosition,
            encodedCoordinateIndex,
        ),
        variableRole: 'ReceiverPayloadPlaintextShare',
    }).variableName;

const addReceiverPayloadPlaintextOpeningVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): string =>
    registry.add({
        openingCoordinateIndex,
        receiverRosterPosition,
        variableName: receiverPayloadPlaintextOpeningVariableName(
            receiverRosterPosition,
            openingCoordinateIndex,
        ),
        variableRole: 'ReceiverPayloadPlaintextOpening',
    }).variableName;

const addReceiverPayloadPlaintextShareBitVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
    bitIndex: number,
): string => {
    const plaintextBitIndex =
        encodedCoordinateIndex * receiverShareRepresentativeBitLength +
        bitIndex;

    return registry.add({
        bitIndex,
        encodedCoordinateIndex,
        polynomialCoefficientIndex:
            plaintextBitIndex % receiverEncryptionModuleDegree,
        receiverRosterPosition,
        variableName: receiverPayloadPlaintextShareBitVariableName(
            receiverRosterPosition,
            encodedCoordinateIndex,
            bitIndex,
        ),
        variableRole: 'ReceiverPayloadPlaintextBit',
    }).variableName;
};

const addReceiverPayloadPlaintextOpeningBitVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    shareVectorWidth: number,
    openingCoordinateIndex: number,
    bitIndex: number,
): string => {
    const plaintextBitIndex =
        shareVectorWidth * receiverShareRepresentativeBitLength +
        openingCoordinateIndex * receiverOpeningRandomnessBitLength +
        bitIndex;

    return registry.add({
        bitIndex,
        openingCoordinateIndex,
        polynomialCoefficientIndex:
            plaintextBitIndex % receiverEncryptionModuleDegree,
        receiverRosterPosition,
        variableName: receiverPayloadPlaintextOpeningBitVariableName(
            receiverRosterPosition,
            openingCoordinateIndex,
            bitIndex,
        ),
        variableRole: 'ReceiverPayloadPlaintextBit',
    }).variableName;
};

const addReceiverEncryptionRandomnessVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    chunkIndex: number,
    ciphertextVectorIndex: number,
    polynomialCoefficientIndex: number,
): string =>
    registry.add({
        chunkIndex,
        ciphertextVectorIndex,
        polynomialCoefficientIndex,
        receiverRosterPosition,
        variableName: receiverEncryptionRandomnessVariableName(
            receiverRosterPosition,
            chunkIndex,
            ciphertextVectorIndex,
            polynomialCoefficientIndex,
        ),
        variableRole: 'ReceiverEncryptionRandomness',
    }).variableName;

const addReceiverEncryptionFirstNoiseVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    chunkIndex: number,
    ciphertextVectorIndex: number,
    polynomialCoefficientIndex: number,
): string =>
    registry.add({
        chunkIndex,
        ciphertextVectorIndex,
        polynomialCoefficientIndex,
        receiverRosterPosition,
        variableName: receiverEncryptionFirstNoiseVariableName(
            receiverRosterPosition,
            chunkIndex,
            ciphertextVectorIndex,
            polynomialCoefficientIndex,
        ),
        variableRole: 'ReceiverEncryptionFirstNoise',
    }).variableName;

const addReceiverEncryptionSecondNoiseVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
    chunkIndex: number,
    polynomialCoefficientIndex: number,
): string =>
    registry.add({
        chunkIndex,
        polynomialCoefficientIndex,
        receiverRosterPosition,
        variableName: receiverEncryptionSecondNoiseVariableName(
            receiverRosterPosition,
            chunkIndex,
            polynomialCoefficientIndex,
        ),
        variableRole: 'ReceiverEncryptionSecondNoise',
    }).variableName;

const addDigestExpandedReceiverEncryptionRandomnessVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
): string =>
    registry.add({
        receiverRosterPosition,
        variableName: digestExpandedReceiverEncryptionRandomnessVariableName(
            receiverRosterPosition,
        ),
        variableRole: 'ReceiverEncryptionRandomness',
    }).variableName;

const addDigestExpandedReceiverEncryptionNoiseVariable = (
    registry: VariableRegistry,
    receiverRosterPosition: number,
): string =>
    registry.add({
        receiverRosterPosition,
        variableName: digestExpandedReceiverEncryptionNoiseVariableName(
            receiverRosterPosition,
        ),
        variableRole: 'ReceiverEncryptionNoise',
    }).variableName;

const getEncodedCoordinateOptionIndex = (
    encodedCoordinateIndex: number,
): number =>
    Math.floor(
        encodedCoordinateIndex / ballotPrivacyEncodedCoordinatesPerOption,
    );

const buildMembershipRows = (
    input: BallotPrivacyRelationCompilerInput,
    registry: VariableRegistry,
): readonly BallotPrivacyLinearRelationRow[] => {
    const rows: BallotPrivacyLinearRelationRow[] = [];

    for (
        let optionIndex = 0;
        optionIndex < input.optionCount;
        optionIndex += 1
    ) {
        const scoreBucketVariableNames = Array.from(
            { length: ballotPrivacyScoreBucketCount },
            (_unusedValue, scoreBucketOffset) =>
                addScoreBucketConstantVariable(
                    registry,
                    optionIndex,
                    scoreBucketOffset + 1,
                ),
        );
        const scalarVariableName = addScalarConstantVariable(
            registry,
            optionIndex,
        );

        rows.push({
            modulus: fieldModulus,
            optionIndex,
            rowKind: 'OneHotSum',
            rowName: `option_${optionIndex + 1}_one_hot_sum`,
            target: 1,
            terms: scoreBucketVariableNames.map((variableName) => ({
                coefficient: 1,
                variableName,
            })),
        });
        rows.push({
            modulus: fieldModulus,
            optionIndex,
            rowKind: 'ScalarScoreConsistency',
            rowName: `option_${optionIndex + 1}_scalar_score_consistency`,
            target: 0,
            terms: [
                {
                    coefficient: 1,
                    variableName: scalarVariableName,
                },
                ...scoreBucketVariableNames.map(
                    (variableName, scoreBucketOffset) => ({
                        coefficient: -(scoreBucketOffset + 1),
                        variableName,
                    }),
                ),
            ],
        });
    }

    return rows;
};

const fieldPower = (
    receiverRosterPosition: number,
    coefficientDegree: number,
): number => {
    let accumulatedPower = 1;
    for (
        let multipliedDegree = 0;
        multipliedDegree < coefficientDegree;
        multipliedDegree += 1
    ) {
        accumulatedPower =
            (accumulatedPower * receiverRosterPosition) % fieldModulus;
    }

    return accumulatedPower;
};

const buildShamirRows = (
    input: BallotPrivacyRelationCompilerInput,
    registry: VariableRegistry,
): readonly BallotPrivacyLinearRelationRow[] => {
    const rows: BallotPrivacyLinearRelationRow[] = [];
    const encodedCoordinateCount = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );

    for (
        let receiverRosterPosition = 1;
        receiverRosterPosition <= input.rosterSize;
        receiverRosterPosition += 1
    ) {
        for (
            let encodedCoordinateIndex = 0;
            encodedCoordinateIndex < encodedCoordinateCount;
            encodedCoordinateIndex += 1
        ) {
            const optionIndex = getEncodedCoordinateOptionIndex(
                encodedCoordinateIndex,
            );
            const constantVariableName =
                encodedCoordinateIndex %
                    ballotPrivacyEncodedCoordinatesPerOption ===
                0
                    ? addScalarConstantVariable(registry, optionIndex)
                    : addScoreBucketConstantVariable(
                          registry,
                          optionIndex,
                          encodedCoordinateIndex %
                              ballotPrivacyEncodedCoordinatesPerOption,
                      );
            const coefficientTerms = Array.from(
                { length: input.pvssThreshold - 1 },
                (_unusedValue, coefficientOffset) => {
                    const coefficientDegree = coefficientOffset + 1;

                    return {
                        coefficient: fieldPower(
                            receiverRosterPosition,
                            coefficientDegree,
                        ),
                        variableName: addShamirCoefficientVariable(
                            registry,
                            encodedCoordinateIndex,
                            coefficientDegree,
                        ),
                    };
                },
            );
            const receiverShareName = addReceiverShareVariable(
                registry,
                receiverRosterPosition,
                encodedCoordinateIndex,
            );
            const quotientName = addShamirQuotientVariable(
                registry,
                receiverRosterPosition,
                encodedCoordinateIndex,
            );

            rows.push({
                encodedCoordinateIndex,
                modulus: fieldModulus,
                optionIndex,
                receiverRosterPosition,
                rowKind: 'ShamirEvaluationQuotient',
                rowName: `receiver_${receiverRosterPosition}_encoded_coordinate_${encodedCoordinateIndex}_shamir_evaluation`,
                target: 0,
                terms: [
                    {
                        coefficient: 1,
                        variableName: constantVariableName,
                    },
                    ...coefficientTerms,
                    {
                        coefficient: -1,
                        variableName: receiverShareName,
                    },
                    {
                        coefficient: -fieldModulus,
                        variableName: quotientName,
                    },
                ],
            });
        }
    }

    return rows;
};

const buildReceiverPayloadPlaintextBindingRows = (
    input: BallotPrivacyRelationCompilerInput,
    registry: VariableRegistry,
): readonly BallotPrivacyLinearRelationRow[] => {
    const rows: BallotPrivacyLinearRelationRow[] = [];
    const encodedCoordinateCount = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );

    for (const receiver of input.receivers) {
        const receiverRosterPosition = receiver.receiverRosterPosition;

        for (
            let encodedCoordinateIndex = 0;
            encodedCoordinateIndex < encodedCoordinateCount;
            encodedCoordinateIndex += 1
        ) {
            rows.push({
                encodedCoordinateIndex,
                modulus: fieldModulus,
                optionIndex: getEncodedCoordinateOptionIndex(
                    encodedCoordinateIndex,
                ),
                receiverRosterPosition,
                rowKind: 'ReceiverPayloadSharePlaintextBinding',
                rowName: `receiver_${receiverRosterPosition}_payload_plaintext_encoded_coordinate_${encodedCoordinateIndex}_share_binding`,
                target: 0,
                terms: [
                    {
                        coefficient: 1,
                        variableName: addReceiverPayloadPlaintextShareVariable(
                            registry,
                            receiverRosterPosition,
                            encodedCoordinateIndex,
                        ),
                    },
                    {
                        coefficient: -1,
                        variableName: addReceiverShareVariable(
                            registry,
                            receiverRosterPosition,
                            encodedCoordinateIndex,
                        ),
                    },
                ],
            });
        }

        for (
            let openingCoordinateIndex = 0;
            openingCoordinateIndex < shareCommitmentOpeningDimension;
            openingCoordinateIndex += 1
        ) {
            rows.push({
                modulus: fieldModulus,
                openingCoordinateIndex,
                receiverRosterPosition,
                rowKind: 'ReceiverPayloadOpeningPlaintextBinding',
                rowName: `receiver_${receiverRosterPosition}_payload_plaintext_opening_coordinate_${openingCoordinateIndex}_binding`,
                target: 0,
                terms: [
                    {
                        coefficient: 1,
                        variableName:
                            addReceiverPayloadPlaintextOpeningVariable(
                                registry,
                                receiverRosterPosition,
                                openingCoordinateIndex,
                            ),
                    },
                    {
                        coefficient: -1,
                        variableName: addShareCommitmentOpeningVariable(
                            registry,
                            receiverRosterPosition,
                            openingCoordinateIndex,
                        ),
                    },
                ],
            });
        }
    }

    return rows;
};

const buildReceiverPayloadPlaintextBitDecompositionRows = (
    input: BallotPrivacyRelationCompilerInput,
    registry: VariableRegistry,
): readonly BallotPrivacyLinearRelationRow[] => {
    const rows: BallotPrivacyLinearRelationRow[] = [];
    const encodedCoordinateCount = getBallotPrivacyEncodedShareVectorWidth(
        input.optionCount,
    );

    for (const receiver of input.receivers) {
        const receiverRosterPosition = receiver.receiverRosterPosition;

        for (
            let encodedCoordinateIndex = 0;
            encodedCoordinateIndex < encodedCoordinateCount;
            encodedCoordinateIndex += 1
        ) {
            rows.push({
                encodedCoordinateIndex,
                modulus: fieldModulus,
                optionIndex: getEncodedCoordinateOptionIndex(
                    encodedCoordinateIndex,
                ),
                receiverRosterPosition,
                rowKind: 'ReceiverPayloadShareBitDecomposition',
                rowName: `receiver_${receiverRosterPosition}_payload_plaintext_encoded_coordinate_${encodedCoordinateIndex}_share_bit_decomposition`,
                target: 0,
                terms: [
                    ...Array.from(
                        { length: receiverShareRepresentativeBitLength },
                        (_unusedValue, bitIndex) => ({
                            coefficient: 2 ** bitIndex,
                            variableName:
                                addReceiverPayloadPlaintextShareBitVariable(
                                    registry,
                                    receiverRosterPosition,
                                    encodedCoordinateIndex,
                                    bitIndex,
                                ),
                        }),
                    ),
                    {
                        coefficient: -1,
                        variableName: addReceiverPayloadPlaintextShareVariable(
                            registry,
                            receiverRosterPosition,
                            encodedCoordinateIndex,
                        ),
                    },
                ],
            });
        }

        for (
            let openingCoordinateIndex = 0;
            openingCoordinateIndex < shareCommitmentOpeningDimension;
            openingCoordinateIndex += 1
        ) {
            rows.push({
                modulus: fieldModulus,
                openingCoordinateIndex,
                receiverRosterPosition,
                rowKind: 'ReceiverPayloadOpeningBitDecomposition',
                rowName: `receiver_${receiverRosterPosition}_payload_plaintext_opening_coordinate_${openingCoordinateIndex}_bit_decomposition`,
                target: shareCommitmentOpeningInfinityNormBound,
                terms: [
                    ...Array.from(
                        { length: receiverOpeningRandomnessBitLength },
                        (_unusedValue, bitIndex) => ({
                            coefficient: 2 ** bitIndex,
                            variableName:
                                addReceiverPayloadPlaintextOpeningBitVariable(
                                    registry,
                                    receiverRosterPosition,
                                    encodedCoordinateCount,
                                    openingCoordinateIndex,
                                    bitIndex,
                                ),
                        }),
                    ),
                    {
                        coefficient: -1,
                        variableName:
                            addReceiverPayloadPlaintextOpeningVariable(
                                registry,
                                receiverRosterPosition,
                                openingCoordinateIndex,
                            ),
                    },
                ],
            });
        }
    }

    return rows;
};

const receiverReferenceKey = (receiver: ReceiverReference): string =>
    `${receiver.receiverRosterPosition}:${receiver.receiverIdentity}`;

export {
    addReceiverShareVariable,
    addShareCommitmentOpeningVariable,
    addReceiverPayloadPlaintextShareVariable,
    addReceiverPayloadPlaintextOpeningVariable,
    addReceiverPayloadPlaintextShareBitVariable,
    addReceiverPayloadPlaintextOpeningBitVariable,
    addReceiverEncryptionRandomnessVariable,
    addReceiverEncryptionFirstNoiseVariable,
    addReceiverEncryptionSecondNoiseVariable,
    addDigestExpandedReceiverEncryptionRandomnessVariable,
    addDigestExpandedReceiverEncryptionNoiseVariable,
    buildMembershipRows,
    buildShamirRows,
    buildReceiverPayloadPlaintextBindingRows,
    buildReceiverPayloadPlaintextBitDecompositionRows,
    receiverReferenceKey,
};
