import { deriveProtocolDigest } from '@sealed-lattice/crypto';
import type {
    BallotProofComponentId,
    BallotProofComponentProofBundle,
    BallotProofComponentProofRecord,
    ProtocolDigest,
} from '@sealed-lattice/types';

import { fieldModulus } from '../plaintext-oracle/field.js';

import { deriveReceiverPublicMatrix } from './lattice-primitives.js';
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

type ConstantSparseMatrixEntry = {
    readonly rowIndex: number;
    readonly columnIndex: number;
    readonly constantCoefficient: DensePolynomialCoefficient;
};

type ConstantSparseTargetVectorEntry = {
    readonly rowIndex: number;
    readonly constantCoefficient: DensePolynomialCoefficient;
};

type FieldVariableColumn = {
    readonly bitIndex?: number;
    readonly chunkIndex?: number;
    readonly ciphertextVectorIndex?: number;
    readonly coefficientDegree?: number;
    readonly columnIndex: number;
    readonly encodedCoordinateIndex?: number;
    readonly optionIndex?: number;
    readonly openingCoordinateIndex?: number;
    readonly polynomialCoefficientIndex?: number;
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
        | 'receiver_payload_plaintext_bit_decomposition_rows'
        | 'receiver_payload_encryption_equation_rows'
        | 'receiver_key_binding_rows'
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
        | 'share-commitment-rows-only'
        | 'receiver-encryption-rows-only'
        | 'receiver-key-binding-rows-only';
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

export type BallotProofSparseComponentLinearProofStatement = {
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly objectType: 'BallotProofSparseComponentLinearProofStatement';
    readonly objectVersion: 1;
    readonly parameterProfileId: string;
    readonly proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1';
    readonly projectionCoverage:
        | 'payload-plaintext-field-rows-only'
        | 'share-commitment-rows-only';
    readonly relation: 'A*w + t = 0';
    readonly relationStatementDigest: ProtocolDigest;
    readonly sourceBackendColumnIndices: readonly number[];
    readonly sourceRingDegree: number;
    readonly sparseStatementMatrixDigest: ProtocolDigest;
    readonly sparseStatementMatrixEntries: readonly ConstantSparseMatrixEntry[];
    readonly sparseStatementTermCount: string;
    readonly statementColumns: number;
    readonly statementDigest: ProtocolDigest;
    readonly statementRows: number;
    readonly targetCoefficientRepresentation: 'canonicalUnsignedSourceModulus';
    readonly targetVectorDigest: ProtocolDigest;
    readonly targetVectorEntries: readonly ConstantSparseTargetVectorEntry[];
    readonly targetVectorEntryCount: string;
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
    | 'share-commitment-component'
    | 'receiver-encryption-component'
    | 'receiver-key-binding-component';

export type BallotProofComponentProjectionWitness = {
    readonly receiverEncryptionWitnesses?: readonly {
        readonly chunkWitnesses: readonly {
            readonly chunkIndex: number;
            readonly encryptionRandomnessVector: readonly (readonly number[])[];
            readonly firstNoiseVector: readonly (readonly number[])[];
            readonly secondNoisePolynomial: readonly number[];
        }[];
        readonly receiverRosterPosition: number;
    }[];
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

type ReceiverEncryptionChunkProjectionWitness = NonNullable<
    NonNullable<
        BallotProofComponentProjectionWitness['receiverEncryptionWitnesses']
    >[number]['chunkWitnesses']
>[number];

type BallotProofComponentLinearProofProjection = {
    readonly componentId: BallotProofExplicitComponentId;
    readonly linearStatement: BallotProofLinearProofStatement;
    readonly privateWitnessVectorCoefficients: DensePolynomialVector;
    readonly sourceBackendColumnIndices: readonly number[];
    readonly sourceRowBatchNames: readonly ExplicitFieldRowBatch['batchName'][];
};

type BallotProofExplicitComponentWitnessVerification = {
    readonly checkedRowBatchNames: readonly string[];
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly objectType: 'BallotProofExplicitComponentWitnessVerification';
    readonly objectVersion: 1;
    readonly relation: 'A*w + t = 0';
    readonly rowCount: number;
    readonly verificationStatus: 'explicitRowsSatisfied';
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

export type BallotProofComponentProofStatementFormat =
    | 'dense-polynomial-matrix-linear-proof-v1'
    | 'sparse-polynomial-matrix-linear-proof-v1'
    | 'structured-module-lwe-linear-proof-v1'
    | 'public-zero-witness-binding-check-v1';

export type BallotProofComponentProofBytesAvailability =
    | 'available-for-small-dense-oracle'
    | 'requires-sparse-proof-statement'
    | 'requires-structured-proof-statement'
    | 'public-zero-witness-binding-check';

export type BallotProofComponentProofStatementPlan = {
    readonly objectType: 'BallotProofComponentProofStatementPlan';
    readonly objectVersion: 1;
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly componentProofStatementDigest: ProtocolDigest;
    readonly componentStatementDigest: ProtocolDigest;
    readonly denseCoefficientCount: string | null;
    readonly matrixDigest: ProtocolDigest;
    readonly proofBytesAvailability: BallotProofComponentProofBytesAvailability;
    readonly proofLoweringStatus: BallotPrivacyBackendProofComponent['proofLoweringStatus'];
    readonly proofStatementFormat: BallotProofComponentProofStatementFormat;
    readonly proofSystemRingDegree: number | null;
    readonly relation: 'A*w + t = 0';
    readonly relationStatementDigest: ProtocolDigest;
    readonly rowBatchMatrixDigests: readonly ProtocolDigest[];
    readonly rowBatchNames: readonly string[];
    readonly rowBatchTargetVectorDigests: readonly ProtocolDigest[];
    readonly rowBatchTermCounts: readonly string[];
    readonly rowCount: number;
    readonly sparseTermCount: string | null;
    readonly sourceRingDegree: number | null;
    readonly structuredCiphertextChunkCount: number | null;
    readonly structuredReceiverCount: number | null;
    readonly structuredWitnessTermCount: string | null;
    readonly targetVectorDigest: ProtocolDigest;
    readonly variableColumnCount: number;
    readonly variableColumnIndices: readonly number[];
};

const linearProofRelation = 'A*w + t = 0' as const;
const receiverEncryptionModulus = 12_289;
const receiverEncryptionModuleRank = 4;
const receiverEncryptionModuleDegree = 256;
const receiverEncryptionMessageScale = Math.floor(
    receiverEncryptionModulus / 2,
);
const receiverShareRepresentativeBitLength = 17;
const receiverOpeningRandomnessBitLength = 12;
const receiverPayloadOpeningEncodingOffset = 1024;

const positiveModulo = (value: number, modulus: number): number => {
    const remainder = value % modulus;
    if (Object.is(remainder, -0)) {
        return 0;
    }

    return remainder < 0 ? remainder + modulus : remainder;
};

const negacyclicNumberCoefficient = (input: {
    readonly outputCoefficientIndex: number;
    readonly polynomial: readonly number[];
    readonly witnessCoefficientIndex: number;
}): number => {
    if (input.outputCoefficientIndex >= input.witnessCoefficientIndex) {
        return positiveModulo(
            input.polynomial[
                input.outputCoefficientIndex - input.witnessCoefficientIndex
            ] ?? 0,
            receiverEncryptionModulus,
        );
    }

    return positiveModulo(
        -(
            input.polynomial[
                receiverEncryptionModuleDegree +
                    input.outputCoefficientIndex -
                    input.witnessCoefficientIndex
            ] ?? 0
        ),
        receiverEncryptionModulus,
    );
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
        case 'ReceiverPayloadPlaintextBit':
            return receiverPayloadPlaintextBitValue(
                relationInput,
                projectionWitness,
                variableColumn,
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
        case 'ReceiverEncryptionRandomness':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.chunkIndex === undefined ||
                variableColumn.ciphertextVectorIndex === undefined ||
                variableColumn.polynomialCoefficientIndex === undefined
            ) {
                throw new Error(
                    'Receiver encryption randomness variable is missing its indexes.',
                );
            }

            return receiverEncryptionVectorCoefficient({
                coefficientIndex: variableColumn.polynomialCoefficientIndex,
                vector: receiverEncryptionChunkWitness(
                    projectionWitness,
                    variableColumn.receiverRosterPosition,
                    variableColumn.chunkIndex,
                ).encryptionRandomnessVector,
                vectorIndex: variableColumn.ciphertextVectorIndex,
            });
        case 'ReceiverEncryptionFirstNoise':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.chunkIndex === undefined ||
                variableColumn.ciphertextVectorIndex === undefined ||
                variableColumn.polynomialCoefficientIndex === undefined
            ) {
                throw new Error(
                    'Receiver encryption first-noise variable is missing its indexes.',
                );
            }

            return receiverEncryptionVectorCoefficient({
                coefficientIndex: variableColumn.polynomialCoefficientIndex,
                vector: receiverEncryptionChunkWitness(
                    projectionWitness,
                    variableColumn.receiverRosterPosition,
                    variableColumn.chunkIndex,
                ).firstNoiseVector,
                vectorIndex: variableColumn.ciphertextVectorIndex,
            });
        case 'ReceiverEncryptionSecondNoise':
            if (
                variableColumn.receiverRosterPosition === undefined ||
                variableColumn.chunkIndex === undefined ||
                variableColumn.polynomialCoefficientIndex === undefined
            ) {
                throw new Error(
                    'Receiver encryption second-noise variable is missing its indexes.',
                );
            }

            return receiverEncryptionPolynomialCoefficient({
                coefficientIndex: variableColumn.polynomialCoefficientIndex,
                polynomial: receiverEncryptionChunkWitness(
                    projectionWitness,
                    variableColumn.receiverRosterPosition,
                    variableColumn.chunkIndex,
                ).secondNoisePolynomial,
            });
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

const deriveSparseLinearStatementDigest = (
    statementPayload: Omit<
        BallotProofSparseComponentLinearProofStatement,
        'statementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-sparse-linear-proof-statement-v1',
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

const deriveSparseStatementMatrixDigest = (
    sparseStatementMatrixEntries: readonly ConstantSparseMatrixEntry[],
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-sparse-linear-statement-matrix-v1',
        sparseStatementMatrixEntries,
    });

const deriveTargetVectorDigest = (
    targetVectorCoefficients: DensePolynomialVector,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-linear-target-vector-v1',
        targetVectorCoefficients,
    });

const deriveSparseTargetVectorDigest = (
    targetVectorEntries: readonly ConstantSparseTargetVectorEntry[],
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        purpose: 'ballot-proof-sparse-linear-target-vector-v1',
        targetVectorEntries,
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

const deriveComponentProofStatementDigest = (
    statementPayload: Omit<
        BallotProofComponentProofStatementPlan,
        'componentProofStatementDigest'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ChallengeDomainDigest', {
        payload: statementPayload,
        purpose: 'ballot-proof-component-proof-statement-plan-v1',
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
        input.component.rowBatchNames.length === 1 &&
        input.component.rowBatchNames[0] === 'encoded_score_field_rows'
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

const rowBatchTermCount = (
    rowBatch: BackendRowBatchForComponentStatement,
): bigint => {
    if (rowBatch.batchKind === 'ExplicitSparseRows') {
        return explicitRowBatchTermCount(rowBatch);
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

const buildBallotProofComponentProofStatementPlan = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly componentStatement: BallotProofComponentStatement;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): BallotProofComponentProofStatementPlan => {
    const component = componentById({
        componentId: input.componentStatement.componentId,
        loweredStatement: input.loweredStatement,
    });
    const rowBatches = rowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    const proofStatementFormat = proofStatementFormatForComponent({
        component,
        rowBatches,
    });
    const sourceRingDegree = sourceRingDegreeForComponentProofStatement(
        component.componentId,
    );
    const structuredCounts = rowBatches
        .filter(
            (
                rowBatch,
            ): rowBatch is Extract<
                BackendRowBatchForComponentStatement,
                {
                    readonly batchKind: 'StructuredModuleLweReceiverEncryptionRows';
                }
            > =>
                rowBatch.batchKind ===
                'StructuredModuleLweReceiverEncryptionRows',
        )
        .map(structuredReceiverEncryptionWitnessTermCounts);
    const rowBatchTermCounts = rowBatches.map((rowBatch) =>
        rowBatchTermCount(rowBatch).toString(),
    );
    const sparseTermCount =
        proofStatementFormat === 'sparse-polynomial-matrix-linear-proof-v1'
            ? rowBatches
                  .reduce(
                      (termCount, rowBatch) =>
                          termCount + rowBatchTermCount(rowBatch),
                      0n,
                  )
                  .toString()
            : null;
    const structuredWitnessTermCount =
        proofStatementFormat === 'structured-module-lwe-linear-proof-v1'
            ? structuredCounts
                  .reduce(
                      (termCount, counts) =>
                          termCount + counts.witnessTermCount,
                      0n,
                  )
                  .toString()
            : null;
    const statementPayload: Omit<
        BallotProofComponentProofStatementPlan,
        'componentProofStatementDigest'
    > = {
        backendStatementDigest:
            input.loweredStatement.backendStatement.backendStatementDigest,
        ...(input.ballotProofStatementDigest === undefined
            ? {}
            : {
                  ballotProofStatementDigest: input.ballotProofStatementDigest,
              }),
        coefficientModulus: component.coefficientModulus,
        componentId: component.componentId,
        componentStatementDigest:
            input.componentStatement.componentStatementDigest,
        denseCoefficientCount: denseCoefficientCountForComponentProofStatement({
            rowCount: component.rowCount,
            sourceRingDegree,
            variableColumnCount: component.variableColumnCount,
        }),
        matrixDigest: input.componentStatement.matrixDigest,
        objectType: 'BallotProofComponentProofStatementPlan',
        objectVersion: 1,
        proofBytesAvailability:
            proofBytesAvailabilityForStatementFormat(proofStatementFormat),
        proofLoweringStatus: component.proofLoweringStatus,
        proofStatementFormat,
        proofSystemRingDegree: proofSystemRingDegreeForComponentProofStatement(
            component.componentId,
        ),
        relation: linearProofRelation,
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
        rowBatchMatrixDigests: input.componentStatement.rowBatchMatrixDigests,
        rowBatchNames: component.rowBatchNames,
        rowBatchTargetVectorDigests:
            input.componentStatement.rowBatchTargetVectorDigests,
        rowBatchTermCounts,
        rowCount: component.rowCount,
        sparseTermCount,
        sourceRingDegree,
        structuredCiphertextChunkCount:
            proofStatementFormat === 'structured-module-lwe-linear-proof-v1'
                ? structuredCounts.reduce(
                      (count, counts) => count + counts.ciphertextChunkCount,
                      0,
                  )
                : null,
        structuredReceiverCount:
            proofStatementFormat === 'structured-module-lwe-linear-proof-v1'
                ? structuredCounts.reduce(
                      (count, counts) => count + counts.receiverCount,
                      0,
                  )
                : null,
        structuredWitnessTermCount,
        targetVectorDigest: input.componentStatement.targetVectorDigest,
        variableColumnCount: component.variableColumnCount,
        variableColumnIndices: component.variableColumnIndices,
    };

    return {
        ...statementPayload,
        componentProofStatementDigest:
            deriveComponentProofStatementDigest(statementPayload),
    };
};

export const buildBallotProofComponentProofStatementPlans = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly componentBundleStatement: BallotProofComponentBundleStatement;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
}): readonly BallotProofComponentProofStatementPlan[] => {
    if (
        input.componentBundleStatement.backendStatementDigest !==
            input.loweredStatement.backendStatement.backendStatementDigest ||
        input.componentBundleStatement.relationStatementDigest !==
            input.loweredStatement.relationStatementDigest
    ) {
        throw new Error(
            'Component proof statement plans require a bundle statement bound to the lowered relation.',
        );
    }

    return input.componentBundleStatement.componentStatements.map(
        (componentStatement) =>
            buildBallotProofComponentProofStatementPlan({
                ballotProofStatementDigest: input.ballotProofStatementDigest,
                componentStatement,
                loweredStatement: input.loweredStatement,
            }),
    );
};

export const createBallotProofComponentProofRecord = (input: {
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly componentId: BallotProofComponentId;
    readonly componentProofStatementDigest?: ProtocolDigest;
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
        ...(input.componentProofStatementDigest === undefined
            ? {}
            : {
                  componentProofStatementDigest:
                      input.componentProofStatementDigest,
              }),
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

const receiverReferenceKey = (receiver: {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
}): string => `${receiver.receiverRosterPosition}:${receiver.receiverIdentity}`;

const receiverPayloadPlaintextBits = (input: {
    readonly plaintextBitLength: number;
    readonly projectionWitness:
        | BallotProofComponentProjectionWitness
        | undefined;
    readonly receiverRosterPosition: number;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): readonly number[] => {
    const bits: number[] = [];
    const pushUnsignedBits = (value: bigint, bitLength: number): void => {
        if (value < 0n || value >= 1n << BigInt(bitLength)) {
            throw new Error(
                'Receiver payload plaintext value does not fit its bit width.',
            );
        }
        for (let bitIndex = 0; bitIndex < bitLength; bitIndex += 1) {
            bits.push(Number((value >> BigInt(bitIndex)) & 1n));
        }
    };
    const receiver = input.relationInput.receivers.find(
        (candidate) =>
            candidate.receiverRosterPosition === input.receiverRosterPosition,
    );
    if (receiver === undefined) {
        throw new Error('Receiver share witness is missing.');
    }

    for (
        let encodedCoordinateIndex = 0;
        encodedCoordinateIndex < receiver.receiverShareVector.length;
        encodedCoordinateIndex += 1
    ) {
        pushUnsignedBits(
            receiverPayloadPlaintextShareValue(
                input.relationInput,
                input.projectionWitness,
                input.receiverRosterPosition,
                encodedCoordinateIndex,
            ),
            receiverShareRepresentativeBitLength,
        );
    }
    for (
        let openingCoordinateIndex = 0;
        openingCoordinateIndex < 64;
        openingCoordinateIndex += 1
    ) {
        pushUnsignedBits(
            receiverPayloadPlaintextOpeningValue(
                input.projectionWitness,
                input.receiverRosterPosition,
                openingCoordinateIndex,
            ) + BigInt(receiverPayloadOpeningEncodingOffset),
            receiverOpeningRandomnessBitLength,
        );
    }
    if (bits.length < input.plaintextBitLength) {
        throw new Error(
            'Receiver payload plaintext bits do not cover the structured encryption statement.',
        );
    }

    return bits.slice(0, input.plaintextBitLength);
};

const numberVectorCoefficient = (input: {
    readonly coefficientIndex: number;
    readonly vector: readonly (readonly number[])[];
    readonly vectorIndex: number;
}): number => {
    const coefficient =
        input.vector[input.vectorIndex]?.[input.coefficientIndex];
    if (coefficient === undefined || !Number.isSafeInteger(coefficient)) {
        throw new Error(
            'Receiver encryption vector coordinate is missing or non-canonical.',
        );
    }

    return coefficient;
};

const numberPolynomialCoefficient = (input: {
    readonly coefficientIndex: number;
    readonly polynomial: readonly number[];
}): number => {
    const coefficient = input.polynomial[input.coefficientIndex];
    if (coefficient === undefined || !Number.isSafeInteger(coefficient)) {
        throw new Error(
            'Receiver encryption polynomial coordinate is missing or non-canonical.',
        );
    }

    return coefficient;
};

const addModularProduct = (input: {
    readonly coefficient: number;
    readonly currentValue: number;
    readonly witness: number;
}): number =>
    positiveModulo(
        input.currentValue + input.coefficient * input.witness,
        receiverEncryptionModulus,
    );

const verifyStructuredReceiverEncryptionRowBatch = (input: {
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly projectionWitness:
        | BallotProofComponentProjectionWitness
        | undefined;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
    readonly rowBatch: Extract<
        BackendRowBatchForComponentStatement,
        { readonly batchKind: 'StructuredModuleLweReceiverEncryptionRows' }
    >;
    readonly startingRowIndex: number;
}): number => {
    const publicKeysByReceiver = new Map(
        input.loweredStatement.publicContext.receiverPublicKeys.map(
            (publicKey) => [receiverReferenceKey(publicKey), publicKey],
        ),
    );
    const payloadsByReceiver = new Map(
        input.loweredStatement.publicContext.receiverPayloads.map(
            (receiverPayload) => [
                receiverReferenceKey(receiverPayload),
                receiverPayload,
            ],
        ),
    );
    let checkedRowCount = 0;

    for (const receiverRow of input.rowBatch.receiverRows) {
        const receiverKey = receiverReferenceKey(receiverRow);
        const publicKey = publicKeysByReceiver.get(receiverKey);
        const receiverPayload = payloadsByReceiver.get(receiverKey);
        if (
            publicKey?.publicKeyVector === undefined ||
            publicKey.publicMatrixSeedDigest === undefined ||
            receiverPayload?.ciphertextChunks === undefined
        ) {
            throw new Error(
                'Structured receiver encryption rows are missing public key or ciphertext material.',
            );
        }
        const publicMatrix = deriveReceiverPublicMatrix(
            input.loweredStatement.publicContext
                .receiverEncryptionProfileDigest,
            publicKey.publicMatrixSeedDigest,
        );
        const plaintextBits = receiverPayloadPlaintextBits({
            plaintextBitLength: receiverRow.plaintextBitLength,
            projectionWitness: input.projectionWitness,
            receiverRosterPosition: receiverRow.receiverRosterPosition,
            relationInput: input.relationInput,
        });

        for (const ciphertextChunk of receiverPayload.ciphertextChunks) {
            const chunkWitness = receiverEncryptionChunkWitness(
                input.projectionWitness,
                receiverRow.receiverRosterPosition,
                ciphertextChunk.chunkIndex,
            );
            for (
                let ciphertextVectorIndex = 0;
                ciphertextVectorIndex < receiverEncryptionModuleRank;
                ciphertextVectorIndex += 1
            ) {
                for (
                    let outputCoefficientIndex = 0;
                    outputCoefficientIndex < receiverEncryptionModuleDegree;
                    outputCoefficientIndex += 1
                ) {
                    let rowSum = positiveModulo(
                        -numberVectorCoefficient({
                            coefficientIndex: outputCoefficientIndex,
                            vector: ciphertextChunk.firstCiphertextVector,
                            vectorIndex: ciphertextVectorIndex,
                        }),
                        receiverEncryptionModulus,
                    );
                    for (
                        let randomnessVectorIndex = 0;
                        randomnessVectorIndex < receiverEncryptionModuleRank;
                        randomnessVectorIndex += 1
                    ) {
                        for (
                            let randomnessCoefficientIndex = 0;
                            randomnessCoefficientIndex <
                            receiverEncryptionModuleDegree;
                            randomnessCoefficientIndex += 1
                        ) {
                            rowSum = addModularProduct({
                                coefficient: negacyclicNumberCoefficient({
                                    outputCoefficientIndex,
                                    polynomial:
                                        publicMatrix[randomnessVectorIndex]?.[
                                            ciphertextVectorIndex
                                        ] ?? [],
                                    witnessCoefficientIndex:
                                        randomnessCoefficientIndex,
                                }),
                                currentValue: rowSum,
                                witness: numberVectorCoefficient({
                                    coefficientIndex:
                                        randomnessCoefficientIndex,
                                    vector: chunkWitness.encryptionRandomnessVector,
                                    vectorIndex: randomnessVectorIndex,
                                }),
                            });
                        }
                    }
                    rowSum = positiveModulo(
                        rowSum +
                            numberVectorCoefficient({
                                coefficientIndex: outputCoefficientIndex,
                                vector: chunkWitness.firstNoiseVector,
                                vectorIndex: ciphertextVectorIndex,
                            }),
                        receiverEncryptionModulus,
                    );
                    if (rowSum !== 0) {
                        throw new Error(
                            `Proof component receiver-encryption-component row ${(input.startingRowIndex + checkedRowCount).toString()} is not satisfied by the private witness.`,
                        );
                    }
                    checkedRowCount += 1;
                }
            }

            for (
                let outputCoefficientIndex = 0;
                outputCoefficientIndex < receiverEncryptionModuleDegree;
                outputCoefficientIndex += 1
            ) {
                let rowSum = positiveModulo(
                    -numberPolynomialCoefficient({
                        coefficientIndex: outputCoefficientIndex,
                        polynomial: ciphertextChunk.secondCiphertextPolynomial,
                    }),
                    receiverEncryptionModulus,
                );
                for (
                    let randomnessVectorIndex = 0;
                    randomnessVectorIndex < receiverEncryptionModuleRank;
                    randomnessVectorIndex += 1
                ) {
                    for (
                        let randomnessCoefficientIndex = 0;
                        randomnessCoefficientIndex <
                        receiverEncryptionModuleDegree;
                        randomnessCoefficientIndex += 1
                    ) {
                        rowSum = addModularProduct({
                            coefficient: negacyclicNumberCoefficient({
                                outputCoefficientIndex,
                                polynomial:
                                    publicKey.publicKeyVector[
                                        randomnessVectorIndex
                                    ] ?? [],
                                witnessCoefficientIndex:
                                    randomnessCoefficientIndex,
                            }),
                            currentValue: rowSum,
                            witness: numberVectorCoefficient({
                                coefficientIndex: randomnessCoefficientIndex,
                                vector: chunkWitness.encryptionRandomnessVector,
                                vectorIndex: randomnessVectorIndex,
                            }),
                        });
                    }
                }
                rowSum = positiveModulo(
                    rowSum +
                        numberPolynomialCoefficient({
                            coefficientIndex: outputCoefficientIndex,
                            polynomial: chunkWitness.secondNoisePolynomial,
                        }),
                    receiverEncryptionModulus,
                );
                const plaintextBitIndex =
                    ciphertextChunk.chunkIndex *
                        receiverEncryptionModuleDegree +
                    outputCoefficientIndex;
                if (plaintextBitIndex < plaintextBits.length) {
                    rowSum = positiveModulo(
                        rowSum +
                            receiverEncryptionMessageScale *
                                (plaintextBits[plaintextBitIndex] ?? 0),
                        receiverEncryptionModulus,
                    );
                }
                if (rowSum !== 0) {
                    throw new Error(
                        `Proof component receiver-encryption-component row ${(input.startingRowIndex + checkedRowCount).toString()} is not satisfied by the private witness.`,
                    );
                }
                checkedRowCount += 1;
            }
        }
    }

    return checkedRowCount;
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

export const buildBallotProofSparseComponentLinearProofStatement = (input: {
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly componentId:
        | 'payload-plaintext-field-component'
        | 'share-commitment-component';
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterProfileId: string;
    readonly sourceRingDegree: number;
    readonly witnessL2BoundSquared: string;
}): BallotProofSparseComponentLinearProofStatement => {
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
    const matrixCoefficientByPosition = new Map<
        string,
        {
            readonly columnIndex: number;
            coefficient: bigint;
            readonly rowIndex: number;
        }
    >();
    const targetCoefficientByRow = new Map<number, bigint>();

    for (const fieldRow of explicitRows) {
        const targetCoefficient = positiveModuloBigInt(
            -decimalBigInt(fieldRow.target, 'linear row target'),
            coefficientModulus,
        );
        if (targetCoefficient !== 0n) {
            targetCoefficientByRow.set(fieldRow.rowIndex, targetCoefficient);
        }
        for (const term of fieldRow.terms) {
            const projectedColumn = projectedColumnByBackendColumn.get(
                term.columnIndex,
            );
            if (projectedColumn === undefined) {
                throw new Error(
                    'Sparse projection column lookup is incomplete.',
                );
            }
            const positionKey = `${fieldRow.rowIndex}:${projectedColumn}`;
            const existingCoefficient =
                matrixCoefficientByPosition.get(positionKey);
            const nextCoefficient = positiveModuloBigInt(
                (existingCoefficient?.coefficient ?? 0n) +
                    decimalBigInt(term.coefficient, 'linear term coefficient'),
                coefficientModulus,
            );
            if (nextCoefficient === 0n) {
                matrixCoefficientByPosition.delete(positionKey);
            } else if (existingCoefficient === undefined) {
                matrixCoefficientByPosition.set(positionKey, {
                    coefficient: nextCoefficient,
                    columnIndex: projectedColumn,
                    rowIndex: fieldRow.rowIndex,
                });
            } else {
                existingCoefficient.coefficient = nextCoefficient;
            }
        }
    }

    const sparseStatementMatrixEntries = [
        ...matrixCoefficientByPosition.values(),
    ]
        .sort((left, right) =>
            left.rowIndex === right.rowIndex
                ? left.columnIndex - right.columnIndex
                : left.rowIndex - right.rowIndex,
        )
        .map(
            (entry): ConstantSparseMatrixEntry => ({
                columnIndex: entry.columnIndex,
                constantCoefficient: polynomialCoefficient({
                    coefficient: entry.coefficient,
                    coefficientModulus,
                }),
                rowIndex: entry.rowIndex,
            }),
        );
    const targetVectorEntries = [...targetCoefficientByRow.entries()]
        .sort(([leftRowIndex], [rightRowIndex]) => leftRowIndex - rightRowIndex)
        .map(
            ([rowIndex, coefficient]): ConstantSparseTargetVectorEntry => ({
                constantCoefficient: polynomialCoefficient({
                    coefficient,
                    coefficientModulus,
                }),
                rowIndex,
            }),
        );
    const sparseStatementMatrixDigest = deriveSparseStatementMatrixDigest(
        sparseStatementMatrixEntries,
    );
    const targetVectorDigest =
        deriveSparseTargetVectorDigest(targetVectorEntries);
    const projectionCoverage = projectionCoverageForComponent(
        input.componentId,
    );
    if (
        projectionCoverage !== 'payload-plaintext-field-rows-only' &&
        projectionCoverage !== 'share-commitment-rows-only'
    ) {
        throw new Error(
            `Proof component ${input.componentId} is not a sparse component.`,
        );
    }
    const statementPayload: Omit<
        BallotProofSparseComponentLinearProofStatement,
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
        objectType: 'BallotProofSparseComponentLinearProofStatement',
        objectVersion: 1,
        parameterProfileId: input.parameterProfileId,
        proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1',
        projectionCoverage,
        relation: linearProofRelation,
        relationStatementDigest: input.loweredStatement.relationStatementDigest,
        sourceBackendColumnIndices,
        sourceRingDegree: input.sourceRingDegree,
        sparseStatementMatrixDigest,
        sparseStatementMatrixEntries,
        sparseStatementTermCount:
            sparseStatementMatrixEntries.length.toString(),
        statementColumns: sourceBackendColumnIndices.length,
        statementRows: explicitRows.length,
        targetCoefficientRepresentation: 'canonicalUnsignedSourceModulus',
        targetVectorDigest,
        targetVectorEntries,
        targetVectorEntryCount: targetVectorEntries.length.toString(),
        witnessL2BoundSquared: input.witnessL2BoundSquared,
    };

    return {
        ...statementPayload,
        statementDigest: deriveSparseLinearStatementDigest(statementPayload),
    };
};

export const verifyBallotProofComponentExplicitRows = (input: {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly projectionWitness?: BallotProofComponentProjectionWitness;
    readonly relationInput: BallotPrivacyRelationCompilerInput;
}): BallotProofExplicitComponentWitnessVerification => {
    const component = componentById({
        componentId: input.componentId,
        loweredStatement: input.loweredStatement,
    });
    if (component.proofLoweringStatus !== 'explicitRowsAvailable') {
        throw new Error(
            `Proof component ${component.componentId} is not fully lowered to explicit rows.`,
        );
    }
    const rowBatches = rowBatchesForComponent({
        component,
        loweredStatement: input.loweredStatement,
    });
    const coefficientModulus = decimalBigInt(
        component.coefficientModulus,
        'component coefficient modulus',
    );
    const variableColumnByBackendColumn = new Map(
        fieldVariableColumns(input.loweredStatement).map((variableColumn) => [
            variableColumn.columnIndex,
            variableColumn,
        ]),
    );
    let checkedRowCount = 0;

    for (const rowBatch of rowBatches) {
        if (rowBatch.batchKind === 'DigestExpandedRows') {
            throw new Error(
                `Proof component ${input.componentId} is not fully lowered to explicit rows.`,
            );
        }
        if (
            rowBatch.batchKind === 'StructuredModuleLweReceiverEncryptionRows'
        ) {
            checkedRowCount += verifyStructuredReceiverEncryptionRowBatch({
                loweredStatement: input.loweredStatement,
                projectionWitness: input.projectionWitness,
                relationInput: input.relationInput,
                rowBatch,
                startingRowIndex: checkedRowCount,
            });
            continue;
        }
        if (rowBatch.modulus !== component.coefficientModulus) {
            throw new Error(
                `Proof component ${input.componentId} row batch ${rowBatch.batchName} uses a mismatched modulus.`,
            );
        }
        for (const row of rowBatch.rows) {
            let rowSum = -decimalBigInt(row.target, 'linear row target');
            for (const term of row.terms) {
                const variableColumn = variableColumnByBackendColumn.get(
                    term.columnIndex,
                );
                if (variableColumn === undefined) {
                    throw new Error(
                        'Explicit row variable lookup is incomplete.',
                    );
                }
                rowSum +=
                    decimalBigInt(term.coefficient, 'linear term coefficient') *
                    witnessValueForVariable(
                        input.relationInput,
                        input.projectionWitness,
                        variableColumn,
                    );
            }
            if (positiveModuloBigInt(rowSum, coefficientModulus) !== 0n) {
                throw new Error(
                    `Proof component ${input.componentId} row ${checkedRowCount.toString()} is not satisfied by the private witness.`,
                );
            }
            checkedRowCount += 1;
        }
    }

    return {
        checkedRowBatchNames: rowBatches.map((rowBatch) => rowBatch.batchName),
        componentId: input.componentId,
        objectType: 'BallotProofExplicitComponentWitnessVerification',
        objectVersion: 1,
        relation: linearProofRelation,
        rowCount: checkedRowCount,
        verificationStatus: 'explicitRowsSatisfied',
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
