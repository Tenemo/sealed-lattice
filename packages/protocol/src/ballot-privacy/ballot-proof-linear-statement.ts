import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type { ProtocolDigest } from '@sealed-lattice/types';

import { fieldModulus } from '../plaintext-oracle/field.js';

import type { BallotPrivacyLoweredLinearRelationStatement } from './relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from './relation-compiler.js';

type DensePolynomial = readonly number[];
type DensePolynomialMatrix = readonly (readonly DensePolynomial[])[];
type DensePolynomialVector = readonly DensePolynomial[];

type FieldVariableColumn = {
    readonly coefficientDegree?: number;
    readonly columnIndex: number;
    readonly encodedCoordinateIndex?: number;
    readonly optionIndex?: number;
    readonly receiverRosterPosition?: number;
    readonly scoreBucketValue?: number;
    readonly variableName: string;
    readonly variableRole: string;
};

type ExplicitFieldRow = {
    readonly rowIndex: number;
    readonly rowName: string;
    readonly target: string;
    readonly terms: readonly {
        readonly coefficient: string;
        readonly columnIndex: number;
        readonly variableName: string;
    }[];
};

type ExplicitFieldRowBatch = {
    readonly batchKind: 'ExplicitSparseRows';
    readonly batchName: 'encoded_score_field_rows';
    readonly rows: readonly ExplicitFieldRow[];
};

type BallotProofLinearProofStatement = {
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly objectType: 'BallotProofLinearProofStatement';
    readonly objectVersion: 1;
    readonly parameterProfileId: string;
    readonly relation: 'A*w + t = 0';
    readonly relationStatementDigest: ProtocolDigest;
    readonly ringDegree: number;
    readonly statementColumns: number;
    readonly statementDigest: ProtocolDigest;
    readonly statementMatrixCoefficients: DensePolynomialMatrix;
    readonly statementMatrixDigest: ProtocolDigest;
    readonly statementRows: number;
    readonly targetCoefficientRepresentation: 'canonicalUnsignedSourceModulus';
    readonly targetVectorCoefficients: DensePolynomialVector;
    readonly targetVectorDigest: ProtocolDigest;
    readonly witnessL2BoundSquared: string;
};

type EncodedScoreFieldLinearProofProjection = {
    readonly linearStatement: BallotProofLinearProofStatement;
    readonly privateWitnessVectorCoefficients: DensePolynomialVector;
    readonly sourceBackendColumnIndices: readonly number[];
    readonly sourceRowBatchName: 'encoded_score_field_rows';
};

const linearProofRelation = 'A*w + t = 0' as const;

const positiveModulo = (value: number, modulus: number): number => {
    const remainder = value % modulus;
    if (Object.is(remainder, -0)) {
        return 0;
    }

    return remainder < 0 ? remainder + modulus : remainder;
};

const zeroPolynomial = (sourceRingDegree: number): number[] =>
    Array.from({ length: sourceRingDegree }, () => 0);

const constantPolynomial = (input: {
    readonly coefficient: number;
    readonly sourceRingDegree: number;
}): DensePolynomial => {
    const polynomial = zeroPolynomial(input.sourceRingDegree);
    polynomial[0] = positiveModulo(input.coefficient, fieldModulus);

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
    readonly coefficient: number;
    readonly sourceRingDegree: number;
}): DensePolynomial => {
    const polynomial = zeroPolynomial(input.sourceRingDegree);
    polynomial[0] = centeredFieldRepresentative(input.coefficient);

    return polynomial;
};

const decimalInteger = (value: string, fieldName: string): number => {
    if (!/^-?(0|[1-9][0-9]*)$/u.test(value)) {
        throw new Error(`${fieldName} must be a canonical decimal integer.`);
    }

    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) {
        throw new Error(`${fieldName} must fit in a safe integer.`);
    }

    return parsed;
};

const fieldVariableColumns = (
    loweredStatement: BallotPrivacyLoweredLinearRelationStatement,
): readonly FieldVariableColumn[] =>
    loweredStatement.backendStatement
        .variableColumns as readonly FieldVariableColumn[];

const explicitFieldRowBatch = (
    loweredStatement: BallotPrivacyLoweredLinearRelationStatement,
): ExplicitFieldRowBatch => {
    const batch = loweredStatement.backendStatement.rowBatches[0];
    if (batch?.batchKind !== 'ExplicitSparseRows') {
        throw new Error('The encoded-score field row batch is missing.');
    }

    return batch as ExplicitFieldRowBatch;
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
        let fieldPower = 1;
        for (
            let multipliedDegree = 0;
            multipliedDegree < coefficientDegree;
            multipliedDegree += 1
        ) {
            fieldPower = (fieldPower * receiverRosterPosition) % fieldModulus;
        }
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

const witnessValueForVariable = (
    relationInput: BallotPrivacyRelationCompilerInput,
    variableColumn: FieldVariableColumn,
): number => {
    switch (variableColumn.variableRole) {
        case 'ScalarScoreConstant':
            if (variableColumn.optionIndex === undefined) {
                throw new Error(
                    'Scalar score variable is missing its option index.',
                );
            }

            return (
                relationInput.normalizedScores[variableColumn.optionIndex] ?? 0
            );
        case 'ScoreBucketConstant':
            if (
                variableColumn.optionIndex === undefined ||
                variableColumn.scoreBucketValue === undefined
            ) {
                throw new Error(
                    'Score bucket variable is missing its indexes.',
                );
            }

            return (
                relationInput.scoreOneHotWitnesses[
                    variableColumn.optionIndex
                ]?.[variableColumn.scoreBucketValue - 1] ?? 0
            );
        case 'ShamirCoefficient':
            if (
                variableColumn.encodedCoordinateIndex === undefined ||
                variableColumn.coefficientDegree === undefined
            ) {
                throw new Error(
                    'Shamir coefficient variable is missing its indexes.',
                );
            }

            return (
                relationInput.encodedCoordinateShamirCoefficients[
                    variableColumn.encodedCoordinateIndex
                ]?.[variableColumn.coefficientDegree - 1] ?? 0
            );
        case 'ReceiverShare':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.encodedCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Receiver share variable is missing its indexes.',
                );
            }

            return receiverShareValue(
                relationInput,
                variableColumn.receiverRosterPosition,
                variableColumn.encodedCoordinateIndex,
            );
        case 'ShamirQuotient':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.encodedCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Shamir quotient variable is missing its indexes.',
                );
            }

            return quotientValue(
                relationInput,
                variableColumn.receiverRosterPosition,
                variableColumn.encodedCoordinateIndex,
            );
        default:
            return 0;
    }
};

const deriveLinearStatementDigest = (
    statementPayload: Omit<BallotProofLinearProofStatement, 'statementDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-linear-proof-statement-v1',
    });

const deriveStatementMatrixDigest = (
    statementMatrixCoefficients: DensePolynomialMatrix,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-linear-statement-matrix-v1',
        statementMatrixCoefficients,
    });

const deriveTargetVectorDigest = (
    targetVectorCoefficients: DensePolynomialVector,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-linear-target-vector-v1',
        targetVectorCoefficients,
    });

const assertProjectionSatisfiesRows = (input: {
    readonly matrix: DensePolynomialMatrix;
    readonly targetVector: DensePolynomialVector;
    readonly witnessVector: DensePolynomialVector;
}): void => {
    for (let rowIndex = 0; rowIndex < input.matrix.length; rowIndex += 1) {
        let rowSum = input.targetVector[rowIndex]?.[0] ?? 0;
        const matrixRow = input.matrix[rowIndex] ?? [];
        for (
            let columnIndex = 0;
            columnIndex < matrixRow.length;
            columnIndex += 1
        ) {
            rowSum +=
                (matrixRow[columnIndex]?.[0] ?? 0) *
                (input.witnessVector[columnIndex]?.[0] ?? 0);
        }

        if (positiveModulo(rowSum, fieldModulus) !== 0) {
            throw new Error(
                `Encoded-score field row ${rowIndex.toString()} is not satisfied by the private witness.`,
            );
        }
    }
};

export const buildEncodedScoreFieldLinearProofProjection = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterProfileId: string;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly sourceRingDegree: number;
    readonly witnessL2BoundSquared: string;
}): EncodedScoreFieldLinearProofProjection => {
    if (
        !Number.isSafeInteger(input.sourceRingDegree) ||
        input.sourceRingDegree <= 0 ||
        !Number.isInteger(Math.log2(input.sourceRingDegree))
    ) {
        throw new Error('Source ring degree must be a positive power of two.');
    }
    const fieldRowBatch = explicitFieldRowBatch(input.loweredStatement);
    const sourceBackendColumnIndices = usedBackendColumnIndices(
        fieldRowBatch.rows,
    );
    const projectedColumnByBackendColumn = new Map(
        sourceBackendColumnIndices.map((backendColumnIndex, projectedIndex) => [
            backendColumnIndex,
            projectedIndex,
        ]),
    );
    const variableColumnByBackendColumn = new Map(
        fieldVariableColumns(input.loweredStatement).map((variableColumn) => [
            variableColumn.columnIndex,
            variableColumn,
        ]),
    );
    const statementMatrixCoefficients = fieldRowBatch.rows.map((fieldRow) => {
        const row = Array.from(
            { length: sourceBackendColumnIndices.length },
            () => zeroPolynomial(input.sourceRingDegree),
        );
        for (const term of fieldRow.terms) {
            const projectedColumn = projectedColumnByBackendColumn.get(
                term.columnIndex,
            );
            if (projectedColumn === undefined) {
                throw new Error('Projection column lookup is incomplete.');
            }
            row[projectedColumn][0] = positiveModulo(
                decimalInteger(term.coefficient, 'linear term coefficient'),
                fieldModulus,
            );
        }

        return row;
    });
    const targetVectorCoefficients = fieldRowBatch.rows.map((fieldRow) =>
        constantPolynomial({
            coefficient: -decimalInteger(fieldRow.target, 'linear row target'),
            sourceRingDegree: input.sourceRingDegree,
        }),
    );
    const privateWitnessVectorCoefficients = sourceBackendColumnIndices.map(
        (backendColumnIndex) => {
            const variableColumn =
                variableColumnByBackendColumn.get(backendColumnIndex);
            if (variableColumn === undefined) {
                throw new Error('Projection variable lookup is incomplete.');
            }

            return signedConstantPolynomial({
                coefficient: witnessValueForVariable(
                    input.relationInput,
                    variableColumn,
                ),
                sourceRingDegree: input.sourceRingDegree,
            });
        },
    );

    assertProjectionSatisfiesRows({
        matrix: statementMatrixCoefficients,
        targetVector: targetVectorCoefficients,
        witnessVector: privateWitnessVectorCoefficients,
    });

    const statementMatrixDigest = deriveStatementMatrixDigest(
        statementMatrixCoefficients,
    );
    const targetVectorDigest = deriveTargetVectorDigest(
        targetVectorCoefficients,
    );
    const statementPayload: Omit<
        BallotProofLinearProofStatement,
        'statementDigest'
    > = {
        backendStatementDigest:
            input.loweredStatement.backendStatement.backendStatementDigest,
        ...(input.ballotProofStatementDigest === undefined
            ? {}
            : {
                  ballotProofStatementDigest: input.ballotProofStatementDigest,
              }),
        coefficientModulus: fieldModulus.toString(),
        objectType: 'BallotProofLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: input.parameterProfileId,
        relation: linearProofRelation,
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
        ringDegree: input.sourceRingDegree,
        statementColumns: sourceBackendColumnIndices.length,
        statementMatrixCoefficients,
        statementMatrixDigest,
        statementRows: fieldRowBatch.rows.length,
        targetCoefficientRepresentation: 'canonicalUnsignedSourceModulus',
        targetVectorCoefficients,
        targetVectorDigest,
        witnessL2BoundSquared: input.witnessL2BoundSquared,
    };

    return {
        linearStatement: {
            ...statementPayload,
            statementDigest: deriveLinearStatementDigest(statementPayload),
        },
        privateWitnessVectorCoefficients,
        sourceBackendColumnIndices,
        sourceRowBatchName: fieldRowBatch.batchName,
    };
};
