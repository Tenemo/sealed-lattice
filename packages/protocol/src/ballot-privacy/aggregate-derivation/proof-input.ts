import {
    aggregateDerivationProofEncodingProfileId,
    aggregateDerivationProofParameterProfileId,
    type AggregateDerivationProofVerificationInput,
} from '@sealed-lattice/types';

import type {
    DensePolynomial,
    SparseMatrixEntry,
    SparseTargetVectorEntry,
} from '../ballot-proof-linear-statement/statement-contracts.js';
import {
    linearProofRelation,
    polynomialCoefficient,
} from '../ballot-proof-linear-statement/statement-contracts.js';
import {
    deriveSparseStatementMatrixDigest,
    deriveSparseTargetVectorDigest,
} from '../ballot-proof-linear-statement/statement-digests.js';
import {
    deriveShareCommitmentMessageMatrix,
    deriveShareCommitmentRandomnessMatrix,
    modBigInt,
} from '../lattice-primitives/primitive-contracts.js';
import { createBallotPrivacyProfileSet } from '../profiles.js';
import {
    ballotPrivacyEncodedCoordinatesPerOption,
    ballotPrivacyFieldModulus,
    ballotPrivacyMaximumCanonicalFieldElement,
    shareCommitmentModulus,
    shareCommitmentModulusDecimal,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentOpeningDimension,
} from '../protocol-parameters.js';

import {
    aggregateDerivationComponentId,
    aggregateDerivationProofCoefficientModulus,
    aggregateDerivationProofSystemRingDegree,
    aggregateDerivationSourceRingDegree,
    aggregateDerivationWitnessL2BoundSquared,
} from './constants.js';
import { deriveAggregateSparseLinearStatementDigest } from './digests.js';
import type {
    AggregateDerivationProofBuildInput,
    AggregateDerivationProofBuildOutput,
    AggregateDerivationProofEncoding,
    AggregateDerivationProofParameterSet,
    AggregateDerivationProofStatement,
    AggregateDerivationWitnessInput,
} from './types.js';
const sourcePolynomialSplitFactor = (): number =>
    aggregateDerivationSourceRingDegree /
    aggregateDerivationProofSystemRingDegree;

const aggregateStatementRows = (shareVectorWidth: number): number =>
    shareCommitmentModuleRank + shareVectorWidth;

const aggregateStatementColumns = (shareVectorWidth: number): number =>
    3 * shareVectorWidth + shareCommitmentOpeningDimension;

const aggregateShortResponseVectorLength = (statementColumns: number): number =>
    statementColumns * sourcePolynomialSplitFactor() + 1;

const coefficient = (value: bigint): string | number =>
    polynomialCoefficient({
        coefficient: value,
        coefficientModulus: shareCommitmentModulus,
    });

const shareColumnIndex = (coordinateIndex: number): number => coordinateIndex;

const openingColumnIndex = (
    shareVectorWidth: number,
    openingCoordinateIndex: number,
): number => shareVectorWidth + openingCoordinateIndex;

const reducedFieldColumnIndex = (
    shareVectorWidth: number,
    coordinateIndex: number,
): number =>
    shareVectorWidth + shareCommitmentOpeningDimension + coordinateIndex;

const quotientColumnIndex = (
    shareVectorWidth: number,
    coordinateIndex: number,
): number =>
    2 * shareVectorWidth + shareCommitmentOpeningDimension + coordinateIndex;

const shareCommitmentMessageEntryPolynomial = (input: {
    readonly messageMatrixPolynomial: readonly bigint[];
    readonly shareCoordinateIndex: number;
}): readonly bigint[] =>
    Array.from(
        { length: shareCommitmentModuleDegree },
        (_unusedValue, outputCoefficientIndex) => {
            if (outputCoefficientIndex >= input.shareCoordinateIndex) {
                return modBigInt(
                    input.messageMatrixPolynomial[
                        outputCoefficientIndex - input.shareCoordinateIndex
                    ] ?? 0n,
                    shareCommitmentModulus,
                );
            }

            return modBigInt(
                -(
                    input.messageMatrixPolynomial[
                        shareCommitmentModuleDegree +
                            outputCoefficientIndex -
                            input.shareCoordinateIndex
                    ] ?? 0n
                ),
                shareCommitmentModulus,
            );
        },
    );

const sparsePolynomialEntry = (input: {
    readonly columnIndex: number;
    readonly polynomial: readonly bigint[];
    readonly rowIndex: number;
}): SparseMatrixEntry => {
    const nonzeroIndices = input.polynomial.flatMap(
        (entryCoefficient, coefficientIndex) =>
            entryCoefficient === 0n ? [] : [coefficientIndex],
    );
    if (nonzeroIndices.length === 1 && nonzeroIndices[0] === 0) {
        return {
            columnIndex: input.columnIndex,
            constantCoefficient: coefficient(input.polynomial[0] ?? 0n),
            rowIndex: input.rowIndex,
        };
    }

    return {
        columnIndex: input.columnIndex,
        polynomialCoefficients: input.polynomial.map(coefficient),
        rowIndex: input.rowIndex,
    };
};

const sparseTargetEntry = (input: {
    readonly polynomial: readonly bigint[];
    readonly rowIndex: number;
}): SparseTargetVectorEntry => {
    const nonzeroIndices = input.polynomial.flatMap(
        (entryCoefficient, coefficientIndex) =>
            entryCoefficient === 0n ? [] : [coefficientIndex],
    );
    if (nonzeroIndices.length === 1 && nonzeroIndices[0] === 0) {
        return {
            constantCoefficient: coefficient(input.polynomial[0] ?? 0n),
            rowIndex: input.rowIndex,
        };
    }

    return {
        polynomialCoefficients: input.polynomial.map(coefficient),
        rowIndex: input.rowIndex,
    };
};

const validateAggregateWitness = (input: {
    readonly canonicalTurnout: number;
    readonly shareVectorWidth: number;
    readonly witness: AggregateDerivationWitnessInput;
}): void => {
    if (
        input.witness.aggregateIntegerShareVector.length !==
            input.shareVectorWidth ||
        input.witness.aggregateOpeningRandomness.length !==
            shareCommitmentOpeningDimension
    ) {
        throw new RangeError(
            'Aggregate derivation witness shape does not match the statement.',
        );
    }
    const maximumAggregateInteger =
        input.canonicalTurnout * ballotPrivacyMaximumCanonicalFieldElement;
    for (const shareCoordinate of input.witness.aggregateIntegerShareVector) {
        if (
            !Number.isSafeInteger(shareCoordinate) ||
            shareCoordinate < 0 ||
            shareCoordinate > maximumAggregateInteger
        ) {
            throw new RangeError(
                'Aggregate integer share coordinates must satisfy the no-wraparound certificate bound.',
            );
        }
    }
    const maximumOpeningRandomness =
        input.canonicalTurnout *
        createBallotPrivacyProfileSet({
            optionCount:
                input.shareVectorWidth /
                ballotPrivacyEncodedCoordinatesPerOption,
        }).shareCommitmentProfile.openingRandomnessInfinityNormBound;
    for (const openingCoordinate of input.witness.aggregateOpeningRandomness) {
        if (
            !Number.isSafeInteger(openingCoordinate) ||
            Math.abs(openingCoordinate) > maximumOpeningRandomness
        ) {
            throw new RangeError(
                'Aggregate opening randomness exceeds the no-wraparound certificate bound.',
            );
        }
    }
};

const constantWitnessPolynomial = (
    coefficientValue: number,
): DensePolynomial => [
    coefficientValue,
    ...Array.from({ length: aggregateDerivationSourceRingDegree - 1 }, () => 0),
];

export const buildAggregateDerivationProofInput = (
    input: AggregateDerivationProofBuildInput,
): AggregateDerivationProofBuildOutput => {
    const statement = input.statement;
    const shareVectorWidth = statement.shareVectorWidth;
    validateAggregateWitness({
        canonicalTurnout: statement.canonicalTurnout,
        shareVectorWidth,
        witness: input.witness,
    });
    const proofParameterSet: AggregateDerivationProofParameterSet = {
        coefficientModulus: shareCommitmentModulusDecimal,
        profileId: aggregateDerivationProofParameterProfileId,
        proofSystemRingDegree: aggregateDerivationProofSystemRingDegree,
        relation: linearProofRelation,
        ringDegree: aggregateDerivationSourceRingDegree,
        source: 'sealed-lattice/linear-proof/aggregate-derivation-parameters-v1',
        statementColumns: aggregateStatementColumns(shareVectorWidth),
        statementRows: aggregateStatementRows(shareVectorWidth),
        witnessL2BoundSquared: aggregateDerivationWitnessL2BoundSquared,
    };
    const proofEncoding: AggregateDerivationProofEncoding = {
        challengeCoefficientBitLength: 5,
        challengeCoefficientModulus: 17,
        coefficientModulus: aggregateDerivationProofCoefficientModulus,
        compressedCoefficientBitLength: 35,
        compressedCommitmentVectorLength: 18,
        euclideanResponseLog2StandardDeviation: 14,
        euclideanResponseVectorLength: 4,
        fullSizeCoefficientBitLength: 47,
        hashMaskVectorLength: 2,
        hintVectorLength: 18,
        infinityResponseLog2StandardDeviation: 22,
        infinityResponseVectorLength: 4,
        profileId: aggregateDerivationProofEncodingProfileId,
        randomnessResponseLog2StandardDeviation: 12,
        randomnessResponseVectorLength: 41,
        ringDegree: aggregateDerivationProofSystemRingDegree,
        shortResponseLog2StandardDeviation: 18,
        shortResponseVectorLength: aggregateShortResponseVectorLength(
            proofParameterSet.statementColumns,
        ),
        source: 'sealed-lattice/linear-proof/aggregate-derivation-encoding-v1',
        targetCommitmentVectorLength: 12,
    };
    const matrixEntries: SparseMatrixEntry[] = [];
    const targetEntries: SparseTargetVectorEntry[] = [];
    const messageMatrix = deriveShareCommitmentMessageMatrix(
        statement.shareCommitmentProfileDigest,
    );
    const randomnessMatrix = deriveShareCommitmentRandomnessMatrix(
        statement.shareCommitmentProfileDigest,
    );

    for (
        let rowIndex = 0;
        rowIndex < shareCommitmentModuleRank;
        rowIndex += 1
    ) {
        const aggregateCommitmentPolynomial =
            input.aggregateCommitment.commitmentPolynomialVector[rowIndex];
        if (
            aggregateCommitmentPolynomial?.length !==
            shareCommitmentModuleDegree
        ) {
            throw new RangeError(
                'Aggregate commitment polynomial vector has an invalid shape.',
            );
        }
        for (
            let coordinateIndex = 0;
            coordinateIndex < shareVectorWidth;
            coordinateIndex += 1
        ) {
            matrixEntries.push(
                sparsePolynomialEntry({
                    columnIndex: shareColumnIndex(coordinateIndex),
                    polynomial: shareCommitmentMessageEntryPolynomial({
                        messageMatrixPolynomial: messageMatrix[rowIndex] ?? [],
                        shareCoordinateIndex: coordinateIndex,
                    }),
                    rowIndex,
                }),
            );
        }
        for (
            let openingCoordinateIndex = 0;
            openingCoordinateIndex < shareCommitmentOpeningDimension;
            openingCoordinateIndex += 1
        ) {
            matrixEntries.push(
                sparsePolynomialEntry({
                    columnIndex: openingColumnIndex(
                        shareVectorWidth,
                        openingCoordinateIndex,
                    ),
                    polynomial:
                        randomnessMatrix[rowIndex]?.[openingCoordinateIndex] ??
                        [],
                    rowIndex,
                }),
            );
        }
        targetEntries.push(
            sparseTargetEntry({
                polynomial: aggregateCommitmentPolynomial.map((entry) =>
                    modBigInt(-BigInt(entry), shareCommitmentModulus),
                ),
                rowIndex,
            }),
        );
    }

    for (
        let coordinateIndex = 0;
        coordinateIndex < shareVectorWidth;
        coordinateIndex += 1
    ) {
        const rowIndex = shareCommitmentModuleRank + coordinateIndex;
        matrixEntries.push(
            {
                columnIndex: shareColumnIndex(coordinateIndex),
                constantCoefficient: 1,
                rowIndex,
            },
            {
                columnIndex: reducedFieldColumnIndex(
                    shareVectorWidth,
                    coordinateIndex,
                ),
                constantCoefficient: coefficient(-1n),
                rowIndex,
            },
            {
                columnIndex: quotientColumnIndex(
                    shareVectorWidth,
                    coordinateIndex,
                ),
                constantCoefficient: coefficient(
                    -BigInt(ballotPrivacyFieldModulus),
                ),
                rowIndex,
            },
        );
    }

    const sparseStatementMatrixDigest =
        deriveSparseStatementMatrixDigest(matrixEntries);
    const targetVectorDigest = deriveSparseTargetVectorDigest(targetEntries);
    const proofStatementPayload: Omit<
        AggregateDerivationProofStatement,
        'statementDigest'
    > = {
        aggregateDerivationStatementDigest:
            statement.aggregateDerivationStatementDigest,
        aggregateShareCommitmentDigest:
            input.aggregateCommitment.aggregateShareCommitmentDigest,
        coefficientModulus: shareCommitmentModulusDecimal,
        componentId: aggregateDerivationComponentId,
        matrixCoefficientRepresentation: 'centeredSignedSourceModulus',
        objectType: 'AggregateDerivationSparseLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: aggregateDerivationProofParameterProfileId,
        proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
        projectionCoverage: 'aggregate-derivation-full-encoded-layout',
        relation: linearProofRelation,
        sourceRingDegree: aggregateDerivationSourceRingDegree,
        sparseStatementMatrixDigest,
        sparseStatementMatrixEntries: matrixEntries,
        sparseStatementTermCount: String(matrixEntries.length),
        statementColumns: proofParameterSet.statementColumns,
        statementRows: proofParameterSet.statementRows,
        targetCoefficientRepresentation: 'centeredSignedSourceModulus',
        targetVectorDigest,
        targetVectorEntries: targetEntries,
        targetVectorEntryCount: String(targetEntries.length),
        witnessL2BoundSquared: String(aggregateDerivationWitnessL2BoundSquared),
    };
    const proofStatement: AggregateDerivationProofStatement = {
        ...proofStatementPayload,
        statementDigest: deriveAggregateSparseLinearStatementDigest(
            proofStatementPayload,
        ),
    };
    const aggregateIntegerShareVector =
        input.witness.aggregateIntegerShareVector;
    const reducedFieldVector = aggregateIntegerShareVector.map(
        (shareCoordinate) => shareCoordinate % ballotPrivacyFieldModulus,
    );
    const quotientVector = aggregateIntegerShareVector.map(
        (shareCoordinate, coordinateIndex) => {
            const reducedFieldCoordinate =
                reducedFieldVector[coordinateIndex] ?? 0;
            const quotient =
                (shareCoordinate - reducedFieldCoordinate) /
                ballotPrivacyFieldModulus;
            if (
                !Number.isSafeInteger(quotient) ||
                quotient < 0 ||
                quotient > statement.canonicalTurnout
            ) {
                throw new RangeError(
                    'Aggregate derivation quotient exceeds the turnout bound.',
                );
            }

            return quotient;
        },
    );
    const secretState = {
        sourceWitnessCoefficients: [
            ...aggregateIntegerShareVector.map(constantWitnessPolynomial),
            ...input.witness.aggregateOpeningRandomness.map(
                constantWitnessPolynomial,
            ),
            ...reducedFieldVector.map(constantWitnessPolynomial),
            ...quotientVector.map(constantWitnessPolynomial),
        ],
    };
    const proofInput = {
        componentId: aggregateDerivationComponentId,
        componentProofStatementDigest: proofStatement.statementDigest,
        proofEncoding,
        proofParameterSet,
        proofStatement,
        proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
        publicRandomnessHex: statement.challengeDomainDigest.slice(0, 64),
        statementDigest: statement.aggregateDerivationStatementDigest,
    } satisfies Omit<
        AggregateDerivationProofVerificationInput,
        'proofBytesHex'
    >;

    return {
        proofEncoding,
        proofInput,
        proofParameterSet,
        proofStatement,
        secretState,
    };
};
