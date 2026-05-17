import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofComponentProofRecord,
    ProtocolDigest,
} from '@sealed-lattice/types';

import { fieldModulus } from '../plaintext-oracle/field.js';

import {
    ballotPrivacyBackendProofComponentOrder,
    type BallotPrivacyBackendProofComponent,
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
} from './relation-backend-lowering.js';
import type { BallotPrivacyRelationCompilerInput } from './relation-compiler.js';

type DensePolynomialCoefficient = number | string;
type DensePolynomial = readonly DensePolynomialCoefficient[];
type DensePolynomialMatrix = readonly (readonly DensePolynomial[])[];
type DensePolynomialVector = readonly DensePolynomial[];

type FieldVariableColumn = {
    readonly coefficientDegree?: number;
    readonly columnIndex: number;
    readonly encodedCoordinateIndex?: number;
    readonly optionIndex?: number;
    readonly openingCoordinateIndex?: number;
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
    readonly batchName:
        | 'encoded_score_field_rows'
        | 'receiver_payload_plaintext_binding_rows'
        | 'share_commitment_equation_rows';
    readonly modulus: string;
    readonly rows: readonly ExplicitFieldRow[];
};

type BallotProofLinearProofStatement = {
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly objectType: 'BallotProofLinearProofStatement';
    readonly objectVersion: 1;
    readonly parameterProfileId: string;
    readonly projectionCoverage:
        | 'encoded-score-field-rows-only'
        | 'payload-plaintext-field-rows-only'
        | 'share-commitment-rows-only';
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

type BallotProofExplicitComponentId =
    | 'score-and-shamir-field-component'
    | 'payload-plaintext-field-component'
    | 'share-commitment-component';

export type BallotProofComponentProjectionWitness = {
    readonly receiverPayloadPlaintexts?: readonly {
        readonly openingRandomness: readonly number[];
        readonly receiverRosterPosition: number;
        readonly receiverShareVector: readonly number[];
    }[];
    readonly shareCommitmentOpenings: readonly {
        readonly openingRandomness: readonly number[];
        readonly receiverRosterPosition: number;
    }[];
};

type BallotProofComponentLinearProofProjection = {
    readonly componentId: BallotProofExplicitComponentId;
    readonly linearStatement: BallotProofLinearProofStatement;
    readonly privateWitnessVectorCoefficients: DensePolynomialVector;
    readonly sourceBackendColumnIndices: readonly number[];
    readonly sourceRowBatchNames: readonly ExplicitFieldRowBatch['batchName'][];
};

type BackendRowBatchForComponentStatement =
    BallotPrivacyLoweredLinearRelationStatement['backendStatement']['rowBatches'][number];
type BallotProofComponentProofRecordPayload = Omit<
    BallotProofComponentProofRecord,
    'componentProofRecordDigest'
>;
type BallotProofComponentProofBundlePayload = Omit<
    BallotProofComponentProofBundle,
    'componentProofBundleDigest'
>;

export type BallotProofComponentStatement = {
    readonly objectType: 'BallotProofComponentStatement';
    readonly objectVersion: 1;
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly componentDigest: ProtocolDigest;
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly componentStatementDigest: ProtocolDigest;
    readonly matrixDigest: ProtocolDigest;
    readonly proofLoweringStatus: BallotPrivacyBackendProofComponent['proofLoweringStatus'];
    readonly relationStatementDigest: ProtocolDigest;
    readonly rowBatchMatrixDigests: readonly ProtocolDigest[];
    readonly rowBatchNames: readonly string[];
    readonly rowBatchTargetVectorDigests: readonly ProtocolDigest[];
    readonly rowCount: number;
    readonly rowKinds: readonly string[];
    readonly targetVectorDigest: ProtocolDigest;
    readonly variableColumnCount: number;
    readonly variableColumnIndices: readonly number[];
};

export type BallotProofComponentBundleCoverage =
    | 'component-bundle-incomplete'
    | 'full-encoded-score-ballot-relation';

export type BallotProofComponentBundleStatement = {
    readonly objectType: 'BallotProofComponentBundleStatement';
    readonly objectVersion: 1;
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly bundleCoverage: BallotProofComponentBundleCoverage;
    readonly componentBundleStatementDigest: ProtocolDigest;
    readonly componentStatements: readonly BallotProofComponentStatement[];
    readonly relationLabel: 'BallotPrivacyPvssRelation';
    readonly relationStatementDigest: ProtocolDigest;
    readonly requiredComponentIds: readonly BallotPrivacyBackendProofComponentId[];
};

const linearProofRelation = 'A*w + t = 0' as const;

const positiveModulo = (value: number, modulus: number): number => {
    const remainder = value % modulus;
    if (Object.is(remainder, -0)) {
        return 0;
    }

    return remainder < 0 ? remainder + modulus : remainder;
};

const positiveModuloBigInt = (value: bigint, modulus: bigint): bigint => {
    const remainder = value % modulus;

    return remainder < 0n ? remainder + modulus : remainder;
};

const polynomialCoefficient = (input: {
    readonly coefficient: bigint;
    readonly coefficientModulus: bigint;
}): DensePolynomialCoefficient => {
    const canonicalCoefficient = positiveModuloBigInt(
        input.coefficient,
        input.coefficientModulus,
    );
    const maximumSafeInteger = BigInt(Number.MAX_SAFE_INTEGER);
    if (
        canonicalCoefficient <= maximumSafeInteger &&
        input.coefficientModulus <= maximumSafeInteger
    ) {
        return Number(canonicalCoefficient);
    }

    return canonicalCoefficient.toString();
};

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

const witnessValueForVariable = (
    relationInput: BallotPrivacyRelationCompilerInput,
    projectionWitness: BallotProofComponentProjectionWitness | undefined,
    variableColumn: FieldVariableColumn,
): bigint => {
    switch (variableColumn.variableRole) {
        case 'ScalarScoreConstant':
            if (variableColumn.optionIndex === undefined) {
                throw new Error(
                    'Scalar score variable is missing its option index.',
                );
            }

            return BigInt(
                relationInput.normalizedScores[variableColumn.optionIndex] ?? 0,
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

            return BigInt(
                relationInput.scoreOneHotWitnesses[
                    variableColumn.optionIndex
                ]?.[variableColumn.scoreBucketValue - 1] ?? 0,
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

            return BigInt(
                relationInput.encodedCoordinateShamirCoefficients[
                    variableColumn.encodedCoordinateIndex
                ]?.[variableColumn.coefficientDegree - 1] ?? 0,
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

            return BigInt(
                receiverShareValue(
                    relationInput,
                    variableColumn.receiverRosterPosition,
                    variableColumn.encodedCoordinateIndex,
                ),
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

            return BigInt(
                quotientValue(
                    relationInput,
                    variableColumn.receiverRosterPosition,
                    variableColumn.encodedCoordinateIndex,
                ),
            );
        case 'ReceiverPayloadPlaintextShare':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.encodedCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Receiver payload plaintext share variable is missing its indexes.',
                );
            }

            return receiverPayloadPlaintextShareValue(
                relationInput,
                projectionWitness,
                variableColumn.receiverRosterPosition,
                variableColumn.encodedCoordinateIndex,
            );
        case 'ReceiverPayloadPlaintextOpening':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.openingCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Opening variable is missing its receiver or coordinate index.',
                );
            }

            return receiverPayloadPlaintextOpeningValue(
                projectionWitness,
                variableColumn.receiverRosterPosition,
                variableColumn.openingCoordinateIndex,
            );
        case 'ShareCommitmentOpening':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.openingCoordinateIndex === undefined
            ) {
                throw new Error(
                    'Opening variable is missing its receiver or coordinate index.',
                );
            }

            return shareCommitmentOpeningValue(
                projectionWitness,
                variableColumn.receiverRosterPosition,
                variableColumn.openingCoordinateIndex,
            );
        default:
            return 0n;
    }
};

const deriveLinearStatementDigest = (
    statementPayload: Omit<BallotProofLinearProofStatement, 'statementDigest'>,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-linear-proof-statement-v1',
    });

const deriveComponentStatementDigest = (
    statementPayload: Omit<
        BallotProofComponentStatement,
        'componentStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-statement-v1',
    });

const deriveComponentBundleStatementDigest = (
    statementPayload: Omit<
        BallotProofComponentBundleStatement,
        'componentBundleStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-bundle-statement-v1',
    });

const deriveComponentProofRecordDigest = (
    proofRecordPayload: BallotProofComponentProofRecordPayload,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: proofRecordPayload,
        purpose: 'ballot-proof-component-proof-record-v1',
    });

const deriveComponentProofBundleDigest = (
    proofBundlePayload: BallotProofComponentProofBundlePayload,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: proofBundlePayload,
        purpose: 'ballot-proof-component-proof-bundle-v1',
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

const deriveComponentMatrixDigest = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly rowBatchMatrixDigests: readonly ProtocolDigest[];
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        componentId: input.componentId,
        purpose: 'ballot-proof-component-matrix-v1',
        rowBatchMatrixDigests: input.rowBatchMatrixDigests,
    });

const deriveComponentTargetVectorDigest = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly rowBatchTargetVectorDigests: readonly ProtocolDigest[];
}): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        componentId: input.componentId,
        purpose: 'ballot-proof-component-target-vector-v1',
        rowBatchTargetVectorDigests: input.rowBatchTargetVectorDigests,
    });

const rowBatchesForComponent = (input: {
    readonly component: BallotPrivacyBackendProofComponent;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): readonly BackendRowBatchForComponentStatement[] => {
    const rowBatchByName = new Map(
        input.loweredStatement.backendStatement.rowBatches.map((rowBatch) => [
            rowBatch.batchName,
            rowBatch,
        ]),
    );

    return input.component.rowBatchNames.map((rowBatchName) => {
        const rowBatch = rowBatchByName.get(rowBatchName);
        if (rowBatch === undefined) {
            throw new Error(
                `Proof component ${input.component.componentId} references missing row batch ${rowBatchName}.`,
            );
        }

        return rowBatch;
    });
};

const buildComponentStatement = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly component: BallotPrivacyBackendProofComponent;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): BallotProofComponentStatement => {
    const componentRowBatches = rowBatchesForComponent(input);
    const rowBatchMatrixDigests = componentRowBatches.map(
        (rowBatch) => rowBatch.matrixDigest,
    );
    const rowBatchTargetVectorDigests = componentRowBatches.map(
        (rowBatch) => rowBatch.targetVectorDigest,
    );
    const matrixDigest = deriveComponentMatrixDigest({
        componentId: input.component.componentId,
        rowBatchMatrixDigests,
    });
    const targetVectorDigest = deriveComponentTargetVectorDigest({
        componentId: input.component.componentId,
        rowBatchTargetVectorDigests,
    });
    const statementPayload: Omit<
        BallotProofComponentStatement,
        'componentStatementDigest'
    > = {
        backendStatementDigest:
            input.loweredStatement.backendStatement.backendStatementDigest,
        ...(input.ballotProofStatementDigest === undefined
            ? {}
            : {
                  ballotProofStatementDigest: input.ballotProofStatementDigest,
              }),
        coefficientModulus: input.component.coefficientModulus,
        componentDigest: input.component.componentDigest,
        componentId: input.component.componentId,
        matrixDigest,
        objectType: 'BallotProofComponentStatement',
        objectVersion: 1,
        proofLoweringStatus: input.component.proofLoweringStatus,
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
        rowBatchMatrixDigests,
        rowBatchNames: input.component.rowBatchNames,
        rowBatchTargetVectorDigests,
        rowCount: input.component.rowCount,
        rowKinds: input.component.rowKinds,
        targetVectorDigest,
        variableColumnCount: input.component.variableColumnCount,
        variableColumnIndices: input.component.variableColumnIndices,
    };

    return {
        ...statementPayload,
        componentStatementDigest:
            deriveComponentStatementDigest(statementPayload),
    };
};

const resolveBundleCoverage = (
    componentStatements: readonly BallotProofComponentStatement[],
): BallotProofComponentBundleCoverage => {
    const hasCompleteOrderedComponentSet =
        componentStatements.length ===
            ballotPrivacyBackendProofComponentOrder.length &&
        componentStatements.every(
            (componentStatement, componentIndex) =>
                componentStatement.componentId ===
                ballotPrivacyBackendProofComponentOrder[componentIndex],
        );
    const allComponentsLowered = componentStatements.every(
        (componentStatement) =>
            componentStatement.proofLoweringStatus === 'explicitRowsAvailable',
    );

    return hasCompleteOrderedComponentSet && allComponentsLowered
        ? 'full-encoded-score-ballot-relation'
        : 'component-bundle-incomplete';
};

export const buildBallotProofComponentBundleStatement = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): BallotProofComponentBundleStatement => {
    const statementComponentById = new Map(
        input.loweredStatement.backendStatement.proofComponents.map(
            (component) => [component.componentId, component],
        ),
    );
    const componentStatements = ballotPrivacyBackendProofComponentOrder.flatMap(
        (componentId) => {
            const component = statementComponentById.get(componentId);

            return component === undefined
                ? []
                : [
                      buildComponentStatement({
                          ballotProofStatementDigest:
                              input.ballotProofStatementDigest,
                          component,
                          loweredStatement: input.loweredStatement,
                      }),
                  ];
        },
    );
    const statementPayload: Omit<
        BallotProofComponentBundleStatement,
        'componentBundleStatementDigest'
    > = {
        backendStatementDigest:
            input.loweredStatement.backendStatement.backendStatementDigest,
        ...(input.ballotProofStatementDigest === undefined
            ? {}
            : {
                  ballotProofStatementDigest: input.ballotProofStatementDigest,
              }),
        bundleCoverage: resolveBundleCoverage(componentStatements),
        componentStatements,
        objectType: 'BallotProofComponentBundleStatement',
        objectVersion: 1,
        relationLabel: 'BallotPrivacyPvssRelation',
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
        requiredComponentIds: ballotPrivacyBackendProofComponentOrder,
    };

    return {
        ...statementPayload,
        componentBundleStatementDigest:
            deriveComponentBundleStatementDigest(statementPayload),
    };
};

export const createBallotProofComponentProofRecord = (input: {
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly componentId: BallotProofComponentId;
    readonly componentStatementDigest: ProtocolDigest;
    readonly proofBytesDigest: ProtocolDigest;
    readonly proofEncodingProfileDigest: ProtocolDigest;
    readonly proofParameterSetDigest: ProtocolDigest;
    readonly proofRoot: ProtocolDigest;
    readonly proofSizeBytes: number;
    readonly publicRandomnessDigest: ProtocolDigest;
    readonly relationStatementDigest: ProtocolDigest;
}): BallotProofComponentProofRecord => {
    const proofRecordPayload: BallotProofComponentProofRecordPayload = {
        backendStatementDigest: input.backendStatementDigest,
        ...(input.ballotProofStatementDigest === undefined
            ? {}
            : {
                  ballotProofStatementDigest: input.ballotProofStatementDigest,
              }),
        componentId: input.componentId,
        componentStatementDigest: input.componentStatementDigest,
        objectType: 'BallotProofComponentProofRecord',
        objectVersion: 1,
        proofBackend: 'LaZerStyleLocalLatticeRelation',
        proofBytesDigest: input.proofBytesDigest,
        proofEncodingProfileDigest: input.proofEncodingProfileDigest,
        proofParameterSetDigest: input.proofParameterSetDigest,
        proofRoot: input.proofRoot,
        proofSizeBytes: input.proofSizeBytes,
        publicRandomnessDigest: input.publicRandomnessDigest,
        relationStatementDigest: input.relationStatementDigest,
    };

    return {
        ...proofRecordPayload,
        componentProofRecordDigest:
            deriveComponentProofRecordDigest(proofRecordPayload),
    };
};

export const createBallotProofComponentProofBundle = (input: {
    readonly componentBundleStatement: BallotProofComponentBundleStatement;
    readonly componentProofs: readonly BallotProofComponentProofRecord[];
}): BallotProofComponentProofBundle => {
    if (
        input.componentBundleStatement.bundleCoverage !==
        'full-encoded-score-ballot-relation'
    ) {
        throw new Error(
            'Component proof bundles require full encoded-score ballot relation coverage.',
        );
    }

    const proofBundlePayload: BallotProofComponentProofBundlePayload = {
        backendStatementDigest:
            input.componentBundleStatement.backendStatementDigest,
        ...(input.componentBundleStatement.ballotProofStatementDigest ===
        undefined
            ? {}
            : {
                  ballotProofStatementDigest:
                      input.componentBundleStatement.ballotProofStatementDigest,
              }),
        bundleCoverage: input.componentBundleStatement.bundleCoverage,
        componentBundleStatementDigest:
            input.componentBundleStatement.componentBundleStatementDigest,
        componentProofs: input.componentProofs,
        objectType: 'BallotProofComponentProofBundle',
        objectVersion: 1,
        relationStatementDigest:
            input.componentBundleStatement.relationStatementDigest,
        requiredComponentIds: input.componentBundleStatement
            .requiredComponentIds as readonly BallotProofComponentId[],
    };

    return {
        ...proofBundlePayload,
        componentProofBundleDigest:
            deriveComponentProofBundleDigest(proofBundlePayload),
    };
};

const assertProjectionSatisfiesRows = (input: {
    readonly coefficientModulus: bigint;
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly matrix: DensePolynomialMatrix;
    readonly targetVector: DensePolynomialVector;
    readonly witnessVector: DensePolynomialVector;
}): void => {
    for (let rowIndex = 0; rowIndex < input.matrix.length; rowIndex += 1) {
        let rowSum = polynomialCoefficientBigInt(
            input.targetVector[rowIndex]?.[0],
        );
        const matrixRow = input.matrix[rowIndex] ?? [];
        for (
            let columnIndex = 0;
            columnIndex < matrixRow.length;
            columnIndex += 1
        ) {
            rowSum +=
                polynomialCoefficientBigInt(matrixRow[columnIndex]?.[0]) *
                polynomialCoefficientBigInt(
                    input.witnessVector[columnIndex]?.[0],
                );
        }

        if (positiveModuloBigInt(rowSum, input.coefficientModulus) !== 0n) {
            throw new Error(
                `Proof component ${input.componentId} row ${rowIndex.toString()} is not satisfied by the private witness.`,
            );
        }
    }
};

const validateSourceRingDegree = (sourceRingDegree: number): void => {
    if (
        !Number.isSafeInteger(sourceRingDegree) ||
        sourceRingDegree <= 0 ||
        !Number.isInteger(Math.log2(sourceRingDegree))
    ) {
        throw new Error('Source ring degree must be a positive power of two.');
    }
};

const projectedWitnessValue = (input: {
    readonly componentId: BallotProofExplicitComponentId;
    readonly rawWitnessValue: bigint;
}): bigint => {
    if (input.componentId !== 'score-and-shamir-field-component') {
        return input.rawWitnessValue;
    }
    if (
        input.rawWitnessValue < BigInt(Number.MIN_SAFE_INTEGER) ||
        input.rawWitnessValue > BigInt(Number.MAX_SAFE_INTEGER)
    ) {
        throw new Error(
            'Encoded-score field witness must fit in a safe integer.',
        );
    }

    return BigInt(centeredFieldRepresentative(Number(input.rawWitnessValue)));
};

export const buildBallotProofComponentLinearProofProjection = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly componentId: BallotProofExplicitComponentId;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterProfileId: string;
    readonly projectionWitness?: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly sourceRingDegree: number;
    readonly witnessL2BoundSquared: string;
}): BallotProofComponentLinearProofProjection => {
    validateSourceRingDegree(input.sourceRingDegree);
    const component = componentById({
        componentId: input.componentId,
        loweredStatement: input.loweredStatement,
    });
    const rowBatches = explicitRowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    const coefficientModulus = decimalBigInt(
        component.coefficientModulus,
        'component coefficient modulus',
    );
    const invalidModulusBatch = rowBatches.find(
        (rowBatch) => rowBatch.modulus !== component.coefficientModulus,
    );
    if (invalidModulusBatch !== undefined) {
        throw new Error(
            `Proof component ${input.componentId} row batch ${invalidModulusBatch.batchName} uses a mismatched modulus.`,
        );
    }
    const explicitRows = rowBatches.flatMap((rowBatch) => rowBatch.rows);
    const sourceBackendColumnIndices = usedBackendColumnIndices(explicitRows);
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
    const statementMatrixCoefficients = explicitRows.map((fieldRow) => {
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
            row[projectedColumn][0] = polynomialCoefficient({
                coefficient: decimalBigInt(
                    term.coefficient,
                    'linear term coefficient',
                ),
                coefficientModulus,
            });
        }

        return row;
    });
    const targetVectorCoefficients = explicitRows.map((fieldRow) =>
        constantPolynomial({
            coefficient: -decimalBigInt(fieldRow.target, 'linear row target'),
            coefficientModulus,
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
                coefficient: projectedWitnessValue({
                    componentId: input.componentId,
                    rawWitnessValue: witnessValueForVariable(
                        input.relationInput,
                        input.projectionWitness,
                        variableColumn,
                    ),
                }),
                sourceRingDegree: input.sourceRingDegree,
            });
        },
    );

    assertProjectionSatisfiesRows({
        coefficientModulus,
        componentId: input.componentId,
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
        coefficientModulus: component.coefficientModulus,
        objectType: 'BallotProofLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: input.parameterProfileId,
        projectionCoverage: projectionCoverageForComponent(input.componentId),
        relation: linearProofRelation,
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
        ringDegree: input.sourceRingDegree,
        statementColumns: sourceBackendColumnIndices.length,
        statementMatrixCoefficients,
        statementMatrixDigest,
        statementRows: explicitRows.length,
        targetCoefficientRepresentation: 'canonicalUnsignedSourceModulus',
        targetVectorCoefficients,
        targetVectorDigest,
        witnessL2BoundSquared: input.witnessL2BoundSquared,
    };

    return {
        componentId: input.componentId,
        linearStatement: {
            ...statementPayload,
            statementDigest: deriveLinearStatementDigest(statementPayload),
        },
        privateWitnessVectorCoefficients,
        sourceBackendColumnIndices,
        sourceRowBatchNames: rowBatches.map((rowBatch) => rowBatch.batchName),
    };
};

export const buildEncodedScoreFieldLinearProofProjection = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterProfileId: string;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly sourceRingDegree: number;
    readonly witnessL2BoundSquared: string;
}): EncodedScoreFieldLinearProofProjection => {
    const projection = buildBallotProofComponentLinearProofProjection({
        ...input,
        componentId: 'score-and-shamir-field-component',
    });
    const sourceRowBatchName = projection.sourceRowBatchNames[0];
    if (sourceRowBatchName !== 'encoded_score_field_rows') {
        throw new Error('Encoded-score projection used the wrong row batch.');
    }

    return {
        linearStatement: projection.linearStatement,
        privateWitnessVectorCoefficients:
            projection.privateWitnessVectorCoefficients,
        sourceBackendColumnIndices: projection.sourceBackendColumnIndices,
        sourceRowBatchName,
    };
};
