import { fieldModulus } from '../../plaintext-oracle/field.js';
import {
    type BallotPrivacyBackendProofComponent,
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
} from '../relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from '../relation-compiler.js';

import type {
    BallotProofComponentProjectionWitness,
    BallotProofExplicitComponentId,
    BallotProofLinearProofStatement,
    DensePolynomial,
    DensePolynomialCoefficient,
    ExplicitFieldRow,
    ExplicitFieldRowBatch,
    FieldVariableColumn,
    ReceiverEncryptionChunkProjectionWitness,
    StructuredShareCommitmentRowBatch,
} from './statement-contracts.js';
import {
    polynomialCoefficient,
    positiveModulo,
} from './statement-contracts.js';

const signedPolynomialCoefficient = (
    coefficient: bigint,
): DensePolynomialCoefficient => {
    if (
        coefficient >= BigInt(Number.MIN_SAFE_INTEGER) &&
        coefficient <= BigInt(Number.MAX_SAFE_INTEGER)
    ) {
        return Number(coefficient);
    }

    return coefficient.toString();
};

const polynomialCoefficientBigInt = (
    coefficient: DensePolynomialCoefficient | undefined,
): bigint => {
    if (coefficient === undefined) {
        return 0n;
    }
    if (typeof coefficient === 'number') {
        if (!Number.isSafeInteger(coefficient)) {
            throw new Error('Polynomial coefficient must be a safe integer.');
        }

        return BigInt(coefficient);
    }
    if (!/^-?(0|[1-9][0-9]*)$/u.test(coefficient)) {
        throw new Error(
            'Polynomial coefficient string must be a canonical decimal integer.',
        );
    }

    return BigInt(coefficient);
};

const zeroPolynomial = (
    sourceRingDegree: number,
): DensePolynomialCoefficient[] =>
    Array.from({ length: sourceRingDegree }, () => 0);

const constantPolynomial = (input: {
    readonly coefficient: bigint;
    readonly coefficientModulus: bigint;
    readonly sourceRingDegree: number;
}): DensePolynomial => {
    const polynomial = zeroPolynomial(input.sourceRingDegree);
    polynomial[0] = polynomialCoefficient({
        coefficient: input.coefficient,
        coefficientModulus: input.coefficientModulus,
    });

    return polynomial;
};

const centeredFieldRepresentative = (value: number): number => {
    const canonicalValue = positiveModulo(value, fieldModulus);
    const midpoint = Math.floor(fieldModulus / 2);

    return canonicalValue > midpoint
        ? canonicalValue - fieldModulus
        : canonicalValue;
};

const signedConstantPolynomial = (input: {
    readonly coefficient: bigint;
    readonly sourceRingDegree: number;
}): DensePolynomial => {
    const polynomial = zeroPolynomial(input.sourceRingDegree);
    polynomial[0] = signedPolynomialCoefficient(input.coefficient);

    return polynomial;
};

const decimalBigInt = (value: string, fieldName: string): bigint => {
    if (!/^-?(0|[1-9][0-9]*)$/u.test(value)) {
        throw new Error(`${fieldName} must be a canonical decimal integer.`);
    }

    return BigInt(value);
};

const fieldVariableColumns = (
    loweredStatement: BallotPrivacyLoweredLinearRelationStatement,
): readonly FieldVariableColumn[] =>
    loweredStatement.backendStatement
        .variableColumns as readonly FieldVariableColumn[];

const explicitRowBatchByName = (
    loweredStatement: BallotPrivacyLoweredLinearRelationStatement,
    batchName: ExplicitFieldRowBatch['batchName'],
): ExplicitFieldRowBatch => {
    const batch = loweredStatement.backendStatement.rowBatches.find(
        (candidate) => candidate.batchName === batchName,
    );
    if (batch?.batchKind !== 'ExplicitSparseRows') {
        throw new Error(`The explicit row batch ${batchName} is missing.`);
    }

    return batch as ExplicitFieldRowBatch;
};

const structuredShareCommitmentRowBatchByName = (
    loweredStatement: BallotPrivacyLoweredLinearRelationStatement,
    batchName: 'share_commitment_equation_rows',
): StructuredShareCommitmentRowBatch => {
    const batch = loweredStatement.backendStatement.rowBatches.find(
        (candidate) => candidate.batchName === batchName,
    );
    if (batch?.batchKind !== 'StructuredModuleSisShareCommitmentRows') {
        throw new Error(
            `The structured share-commitment row batch ${batchName} is missing.`,
        );
    }

    return batch as StructuredShareCommitmentRowBatch;
};

const componentById = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): BallotPrivacyBackendProofComponent => {
    const component =
        input.loweredStatement.backendStatement.proofComponents.find(
            (candidate) => candidate.componentId === input.componentId,
        );
    if (component === undefined) {
        throw new Error(
            `Proof component ${input.componentId} is missing from the backend statement.`,
        );
    }

    return component;
};

const projectionCoverageForComponent = (
    componentId: BallotProofExplicitComponentId,
): BallotProofLinearProofStatement['projectionCoverage'] => {
    switch (componentId) {
        case 'score-and-shamir-field-component':
            return 'encoded-score-field-rows-only';
        case 'payload-plaintext-field-component':
            return 'payload-plaintext-field-rows-only';
        case 'share-commitment-component':
            return 'share-commitment-rows-only';
        case 'receiver-encryption-component':
            return 'receiver-encryption-rows-only';
        case 'receiver-key-binding-component':
            return 'receiver-key-binding-rows-only';
    }
};

const explicitRowBatchesForComponent = (input: {
    readonly component: BallotPrivacyBackendProofComponent;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): readonly ExplicitFieldRowBatch[] => {
    if (input.component.proofLoweringStatus !== 'explicitRowsAvailable') {
        throw new Error(
            `Proof component ${input.component.componentId} is not fully lowered to explicit rows.`,
        );
    }

    return input.component.rowBatchNames.map((batchName) =>
        explicitRowBatchByName(
            input.loweredStatement,
            batchName as ExplicitFieldRowBatch['batchName'],
        ),
    );
};

const usedBackendColumnIndices = (
    fieldRows: readonly ExplicitFieldRow[],
): readonly number[] =>
    [
        ...new Set(
            fieldRows.flatMap((fieldRow) =>
                fieldRow.terms.map((term) => term.columnIndex),
            ),
        ),
    ].sort((left, right) => left - right);

const receiverShareValue = (
    relationInput: BallotPrivacyRelationCompilerInput,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): number => {
    const receiver = relationInput.receivers.find(
        (candidate) =>
            candidate.receiverRosterPosition === receiverRosterPosition,
    );
    const shareRepresentative =
        receiver?.receiverShareVector[encodedCoordinateIndex];
    if (shareRepresentative === undefined) {
        throw new Error('Receiver share witness is missing.');
    }

    return shareRepresentative;
};

const fieldPowerForReceiver = (
    receiverRosterPosition: number,
    coefficientDegree: number,
): number => {
    let fieldPower = 1;
    for (
        let multipliedDegree = 0;
        multipliedDegree < coefficientDegree;
        multipliedDegree += 1
    ) {
        fieldPower = (fieldPower * receiverRosterPosition) % fieldModulus;
    }

    return fieldPower;
};

const quotientValue = (
    relationInput: BallotPrivacyRelationCompilerInput,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): number => {
    const constantTerm =
        encodedCoordinateIndex % 11 === 0
            ? relationInput.normalizedScores[
                  Math.floor(encodedCoordinateIndex / 11)
              ]
            : relationInput.scoreOneHotWitnesses[
                  Math.floor(encodedCoordinateIndex / 11)
              ]?.[(encodedCoordinateIndex % 11) - 1];
    if (constantTerm === undefined) {
        throw new Error('Encoded coordinate constant witness is missing.');
    }

    const coefficientRow =
        relationInput.encodedCoordinateShamirCoefficients[
            encodedCoordinateIndex
        ] ?? [];
    let evaluatedInteger = constantTerm;
    for (
        let coefficientOffset = 0;
        coefficientOffset < coefficientRow.length;
        coefficientOffset += 1
    ) {
        const coefficientDegree = coefficientOffset + 1;
        const fieldPower = fieldPowerForReceiver(
            receiverRosterPosition,
            coefficientDegree,
        );
        evaluatedInteger += coefficientRow[coefficientOffset] * fieldPower;
    }

    const shareRepresentative = receiverShareValue(
        relationInput,
        receiverRosterPosition,
        encodedCoordinateIndex,
    );
    const quotientNumerator = evaluatedInteger - shareRepresentative;
    if (quotientNumerator % fieldModulus !== 0) {
        throw new Error('Shamir quotient witness is not exact.');
    }

    return quotientNumerator / fieldModulus;
};

const shareCommitmentOpeningValue = (
    projectionWitness: BallotProofComponentProjectionWitness | undefined,
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): bigint => {
    const receiverOpening = projectionWitness?.shareCommitmentOpenings.find(
        (candidate) =>
            candidate.receiverRosterPosition === receiverRosterPosition,
    );
    const openingCoordinate =
        receiverOpening?.openingRandomness[openingCoordinateIndex];
    if (openingCoordinate === undefined) {
        throw new Error(
            'Share commitment opening witness is missing for an explicit proof component.',
        );
    }
    if (!Number.isSafeInteger(openingCoordinate)) {
        throw new Error(
            'Share commitment opening witness coordinate must be a safe integer.',
        );
    }

    return BigInt(openingCoordinate);
};

const receiverPayloadPlaintext = (
    projectionWitness: BallotProofComponentProjectionWitness | undefined,
    receiverRosterPosition: number,
):
    | {
          readonly openingRandomness: readonly number[];
          readonly receiverRosterPosition: number;
          readonly receiverShareVector: readonly number[];
      }
    | undefined =>
    projectionWitness?.receiverPayloadPlaintexts?.find(
        (candidate) =>
            candidate.receiverRosterPosition === receiverRosterPosition,
    );

const receiverPayloadPlaintextShareValue = (
    relationInput: BallotPrivacyRelationCompilerInput,
    projectionWitness: BallotProofComponentProjectionWitness | undefined,
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): bigint => {
    const plaintextShareVector = receiverPayloadPlaintext(
        projectionWitness,
        receiverRosterPosition,
    )?.receiverShareVector;
    const shareRepresentative =
        plaintextShareVector?.[encodedCoordinateIndex] ??
        receiverShareValue(
            relationInput,
            receiverRosterPosition,
            encodedCoordinateIndex,
        );
    if (!Number.isSafeInteger(shareRepresentative)) {
        throw new Error(
            'Receiver payload plaintext share coordinate must be a safe integer.',
        );
    }

    return BigInt(shareRepresentative);
};

const receiverPayloadPlaintextOpeningValue = (
    projectionWitness: BallotProofComponentProjectionWitness | undefined,
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): bigint => {
    const plaintextOpening = receiverPayloadPlaintext(
        projectionWitness,
        receiverRosterPosition,
    )?.openingRandomness;
    const openingCoordinate = plaintextOpening?.[openingCoordinateIndex];
    if (openingCoordinate === undefined) {
        return shareCommitmentOpeningValue(
            projectionWitness,
            receiverRosterPosition,
            openingCoordinateIndex,
        );
    }
    if (!Number.isSafeInteger(openingCoordinate)) {
        throw new Error(
            'Receiver payload plaintext opening coordinate must be a safe integer.',
        );
    }

    return BigInt(openingCoordinate);
};

const integerBit = (input: {
    readonly bitIndex: number;
    readonly integerValue: bigint;
}): bigint => {
    if (input.integerValue < 0n) {
        throw new Error('Bit decomposition input must be non-negative.');
    }

    return (input.integerValue >> BigInt(input.bitIndex)) & 1n;
};

const receiverPayloadPlaintextBitValue = (
    relationInput: BallotPrivacyRelationCompilerInput,
    projectionWitness: BallotProofComponentProjectionWitness | undefined,
    variableColumn: FieldVariableColumn,
): bigint => {
    if (
        variableColumn.receiverRosterPosition === undefined ||
        variableColumn.bitIndex === undefined
    ) {
        throw new Error(
            'Receiver payload plaintext bit variable is missing its receiver or bit index.',
        );
    }
    if (variableColumn.encodedCoordinateIndex !== undefined) {
        return integerBit({
            bitIndex: variableColumn.bitIndex,
            integerValue: receiverPayloadPlaintextShareValue(
                relationInput,
                projectionWitness,
                variableColumn.receiverRosterPosition,
                variableColumn.encodedCoordinateIndex,
            ),
        });
    }
    if (variableColumn.openingCoordinateIndex !== undefined) {
        return integerBit({
            bitIndex: variableColumn.bitIndex,
            integerValue:
                receiverPayloadPlaintextOpeningValue(
                    projectionWitness,
                    variableColumn.receiverRosterPosition,
                    variableColumn.openingCoordinateIndex,
                ) + 1024n,
        });
    }

    throw new Error(
        'Receiver payload plaintext bit variable is missing its plaintext coordinate index.',
    );
};

const receiverEncryptionChunkWitness = (
    projectionWitness: BallotProofComponentProjectionWitness | undefined,
    receiverRosterPosition: number,
    chunkIndex: number,
): ReceiverEncryptionChunkProjectionWitness => {
    const receiverWitness =
        projectionWitness?.receiverEncryptionWitnesses?.find(
            (candidate) =>
                candidate.receiverRosterPosition === receiverRosterPosition,
        );
    const chunkWitness = receiverWitness?.chunkWitnesses.find(
        (candidate) => candidate.chunkIndex === chunkIndex,
    );
    if (chunkWitness === undefined) {
        throw new Error(
            'Receiver encryption witness is missing for an explicit proof component.',
        );
    }

    return chunkWitness;
};

const receiverEncryptionVectorCoefficient = (input: {
    readonly coefficientIndex: number;
    readonly vector: readonly (readonly number[])[];
    readonly vectorIndex: number;
}): bigint => {
    const coefficient =
        input.vector[input.vectorIndex]?.[input.coefficientIndex];
    if (coefficient === undefined || !Number.isSafeInteger(coefficient)) {
        throw new Error(
            'Receiver encryption vector witness coordinate is missing or non-canonical.',
        );
    }

    return BigInt(coefficient);
};

const receiverEncryptionPolynomialCoefficient = (input: {
    readonly coefficientIndex: number;
    readonly polynomial: readonly number[];
}): bigint => {
    const coefficient = input.polynomial[input.coefficientIndex];
    if (coefficient === undefined || !Number.isSafeInteger(coefficient)) {
        throw new Error(
            'Receiver encryption polynomial witness coordinate is missing or non-canonical.',
        );
    }

    return BigInt(coefficient);
};

export {
    signedPolynomialCoefficient,
    polynomialCoefficientBigInt,
    zeroPolynomial,
    constantPolynomial,
    centeredFieldRepresentative,
    signedConstantPolynomial,
    decimalBigInt,
    fieldVariableColumns,
    structuredShareCommitmentRowBatchByName,
    componentById,
    projectionCoverageForComponent,
    explicitRowBatchesForComponent,
    usedBackendColumnIndices,
    receiverShareValue,
    fieldPowerForReceiver,
    quotientValue,
    shareCommitmentOpeningValue,
    receiverPayloadPlaintextShareValue,
    receiverPayloadPlaintextOpeningValue,
    receiverPayloadPlaintextBitValue,
    receiverEncryptionChunkWitness,
    receiverEncryptionVectorCoefficient,
    receiverEncryptionPolynomialCoefficient,
};
