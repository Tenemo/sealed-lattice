import type {
    BallotProofComponentProofBundle,
    BallotProofComponentProofRecord,
    BallotProofStatement,
    ProtocolDigest,
} from '@sealed-lattice/types';

import {
    receiverEncryptionMessageScale,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    receiverOpeningRandomnessBitLength,
    receiverShareRepresentativeBitLength,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentOpeningDimension,
} from '../protocol-parameters.js';
import {
    type BallotPrivacyBackendProofComponent,
    type BallotPrivacyBackendProofComponentId,
    type BallotPrivacyLoweredLinearRelationStatement,
} from '../relation-backend-lowering.js';

type DensePolynomialCoefficient = number | string;

type DensePolynomial = readonly DensePolynomialCoefficient[];

type DensePolynomialMatrix = readonly (readonly DensePolynomial[])[];

type DensePolynomialVector = readonly DensePolynomial[];

type BallotProofTargetCoefficientRepresentation =
    | 'canonicalUnsignedSourceModulus'
    | 'centeredSignedSourceModulus';

type BallotProofMatrixCoefficientRepresentation =
    BallotProofTargetCoefficientRepresentation;

type ConstantSparseMatrixEntry = {
    readonly rowIndex: number;
    readonly columnIndex: number;
    readonly constantCoefficient: DensePolynomialCoefficient;
};

type PolynomialSparseMatrixEntry = {
    readonly rowIndex: number;
    readonly columnIndex: number;
    readonly polynomialCoefficients: DensePolynomial;
};

type SparseMatrixEntry =
    | ConstantSparseMatrixEntry
    | PolynomialSparseMatrixEntry;

type ConstantSparseTargetVectorEntry = {
    readonly rowIndex: number;
    readonly constantCoefficient: DensePolynomialCoefficient;
};

type PolynomialSparseTargetVectorEntry = {
    readonly rowIndex: number;
    readonly polynomialCoefficients: DensePolynomial;
};

type SparseTargetVectorEntry =
    | ConstantSparseTargetVectorEntry
    | PolynomialSparseTargetVectorEntry;

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

type StructuredShareCommitmentRowBatch = {
    readonly batchKind: 'StructuredModuleSisShareCommitmentRows';
    readonly batchName: 'share_commitment_equation_rows';
    readonly matrixDigest: ProtocolDigest;
    readonly modulus: string;
    readonly rowCount: number;
    readonly shareCommitmentRows: readonly {
        readonly receiverIdentity: string;
        readonly receiverRosterPosition: number;
        readonly rowCount: number;
        readonly rowOffsetWithinBatch: number;
    }[];
    readonly targetVectorDigest: ProtocolDigest;
    readonly variableColumnIndices: readonly number[];
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
        | 'receiver-key-binding-rows-only'
        | 'full-encoded-score-ballot-relation';
    readonly relation: 'A*w + t = 0';
    readonly relationStatementDigest: ProtocolDigest;
    readonly ringDegree: number;
    readonly statementColumns: number;
    readonly statementDigest: ProtocolDigest;
    readonly statementMatrixCoefficients: DensePolynomialMatrix;
    readonly statementMatrixDigest: ProtocolDigest;
    readonly statementRows: number;
    readonly matrixCoefficientRepresentation: BallotProofMatrixCoefficientRepresentation;
    readonly targetCoefficientRepresentation: BallotProofTargetCoefficientRepresentation;
    readonly targetVectorCoefficients: DensePolynomialVector;
    readonly targetVectorDigest: ProtocolDigest;
    readonly witnessL2BoundSquared: string;
};

type BallotProofFullRelationLinearProofStatement =
    BallotProofLinearProofStatement & {
        readonly componentBundleStatementDigest: ProtocolDigest;
        readonly relationBindingDigest: ProtocolDigest;
        readonly relationBindingKind: 'component-bundle-and-lowered-relation';
        readonly projectionCoverage: 'full-encoded-score-ballot-relation';
    };

type BallotProofSparseComponentLinearProofStatement = {
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly objectType: 'BallotProofSparseComponentLinearProofStatement';
    readonly objectVersion: 1;
    readonly parameterProfileId: string;
    readonly proofStatementFormat: 'sparse-polynomial-matrix-linear-proof-v1';
    readonly projectionCoverage:
        | 'encoded-score-field-rows-only'
        | 'payload-plaintext-field-rows-only'
        | 'share-commitment-rows-only';
    readonly relation: 'A*w + t = 0';
    readonly relationStatementDigest: ProtocolDigest;
    readonly sourceBackendColumnIndices: readonly number[];
    readonly sourceColumnPackings?: readonly PackedFieldSourceColumn[];
    readonly sourceRingDegree: number;
    readonly sparseStatementMatrixDigest: ProtocolDigest;
    readonly sparseStatementMatrixEntries: readonly SparseMatrixEntry[];
    readonly sparseStatementTermCount: string;
    readonly statementColumns: number;
    readonly statementDigest: ProtocolDigest;
    readonly statementRows: number;
    readonly matrixCoefficientRepresentation: BallotProofMatrixCoefficientRepresentation;
    readonly targetCoefficientRepresentation: BallotProofTargetCoefficientRepresentation;
    readonly targetVectorDigest: ProtocolDigest;
    readonly targetVectorEntries: readonly SparseTargetVectorEntry[];
    readonly targetVectorEntryCount: string;
    readonly witnessL2BoundSquared: string;
};

type PackedFieldSourceColumn = {
    readonly bindings: readonly {
        readonly backendColumnIndex: number;
        readonly coefficientIndex: number;
        readonly variableName: string;
        readonly variableRole: string;
    }[];
    readonly columnIndex: number;
    readonly packingKind: string;
};

type StructuredShareCommitmentReceiverStatement = {
    readonly commitmentPolynomialVector: readonly (readonly string[])[];
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly rowCount: number;
    readonly rowOffsetWithinStatement: number;
};

type BallotProofStructuredShareCommitmentProofStatement = {
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly componentId: 'share-commitment-component';
    readonly matrixDigest: ProtocolDigest;
    readonly objectType: 'BallotProofStructuredShareCommitmentProofStatement';
    readonly objectVersion: 1;
    readonly parameterProfileId: string;
    readonly proofStatementFormat: 'structured-module-sis-share-commitment-v1';
    readonly proofSystemRingDegree: 64;
    readonly projectionCoverage: 'share-commitment-rows-only';
    readonly receiverRows: readonly StructuredShareCommitmentReceiverStatement[];
    readonly relation: 'A*w + t = 0';
    readonly relationStatementDigest: ProtocolDigest;
    readonly shareCommitmentProfileDigest: ProtocolDigest;
    readonly shareVectorWidth: number;
    readonly sourceBackendColumnIndices: readonly number[];
    readonly sourceRingDegree: 64 | 256;
    readonly statementColumns: number;
    readonly statementDigest: ProtocolDigest;
    readonly statementRows: number;
    readonly matrixCoefficientRepresentation: BallotProofMatrixCoefficientRepresentation;
    readonly targetCoefficientRepresentation: BallotProofTargetCoefficientRepresentation;
    readonly targetVectorDigest: ProtocolDigest;
    readonly witnessL2BoundSquared: string;
};

type StructuredReceiverEncryptionCiphertextChunkStatement = {
    readonly chunkIndex: number;
    readonly firstCiphertextVector: readonly (readonly number[])[];
    readonly firstNoisePolynomialColumnIndices: readonly number[];
    readonly plaintextPolynomialColumnIndex: number;
    readonly randomnessPolynomialColumnIndices: readonly number[];
    readonly secondCiphertextPolynomial: readonly number[];
    readonly secondNoiseColumnIndex: number;
};

type StructuredReceiverEncryptionReceiverStatement = {
    readonly ciphertextChunkCount: number;
    readonly ciphertextChunks: readonly StructuredReceiverEncryptionCiphertextChunkStatement[];
    readonly plaintextBitLength: number;
    readonly publicKeyVector: readonly (readonly number[])[];
    readonly publicMatrixSeedDigest: ProtocolDigest;
    readonly receiverIdentity: string;
    readonly receiverPayloadDigest: ProtocolDigest;
    readonly receiverPublicKeyDigest: ProtocolDigest;
    readonly receiverRosterPosition: number;
    readonly rowCount: number;
    readonly rowOffsetWithinStatement: number;
};

type BallotProofStructuredReceiverEncryptionProofStatement = {
    readonly backendStatementDigest: ProtocolDigest;
    readonly ballotProofStatementDigest?: ProtocolDigest;
    readonly coefficientModulus: string;
    readonly componentId: 'receiver-encryption-component';
    readonly componentStatementDigest: ProtocolDigest;
    readonly matrixDigest: ProtocolDigest;
    readonly objectType: 'BallotProofStructuredReceiverEncryptionProofStatement';
    readonly objectVersion: 1;
    readonly parameterProfileId: string;
    readonly proofStatementFormat: 'structured-module-lwe-linear-proof-v1';
    readonly proofSystemRingDegree: 64;
    readonly receiverEncryptionProfileDigest: ProtocolDigest;
    readonly receiverRows: readonly StructuredReceiverEncryptionReceiverStatement[];
    readonly relation: 'A*w + t = 0';
    readonly relationStatementDigest: ProtocolDigest;
    readonly sourceBackendColumnIndices: readonly number[];
    readonly sourceRingDegree: 256;
    readonly statementColumns: number;
    readonly statementDigest: ProtocolDigest;
    readonly statementRows: number;
    readonly matrixCoefficientRepresentation: BallotProofMatrixCoefficientRepresentation;
    readonly targetCoefficientRepresentation: BallotProofTargetCoefficientRepresentation;
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
    | 'structured-module-sis-share-commitment-v1'
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

type BallotProofRecordGenerationSecretState = {
    readonly sourceWitnessCoefficients: DensePolynomialVector;
};

type BallotProofRecordGenerationComponentProofInput = {
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly componentProofStatementDigest: ProtocolDigest;
    readonly proofEncoding: unknown;
    readonly proofParameterSet: unknown;
    readonly proofStatement: unknown;
    readonly proofStatementFormat: BallotProofComponentProofStatementFormat;
    readonly publicRandomnessHex: string;
    readonly statementDigest: ProtocolDigest;
};

export type BallotProofRecordGenerationProofContracts = {
    readonly ballotProofEncoding: unknown;
    readonly ballotProofParameterSet: unknown;
    readonly componentProofEncodings: Readonly<
        Record<BallotPrivacyBackendProofComponentId, unknown>
    >;
    readonly componentProofParameterSets: Readonly<
        Record<BallotPrivacyBackendProofComponentId, unknown>
    >;
};

export type BallotProofRecordGenerationRandomness = {
    readonly componentProverRandomnessHexes: Readonly<
        Partial<Record<BallotPrivacyBackendProofComponentId, string>>
    >;
    readonly componentPublicRandomnessHexes: Readonly<
        Record<BallotPrivacyBackendProofComponentId, string>
    >;
    readonly proverRandomnessHex: string;
    readonly publicRandomnessHex: string;
};

export type BallotProofRecordGenerationRequest = {
    readonly componentBundleStatement: BallotProofComponentBundleStatement;
    readonly componentProofInputs: readonly BallotProofRecordGenerationComponentProofInput[];
    readonly componentSecretStates: Readonly<
        Partial<
            Record<
                BallotPrivacyBackendProofComponentId,
                BallotProofRecordGenerationSecretState
            >
        >
    >;
    readonly componentStatementPlans: readonly BallotProofComponentProofStatementPlan[];
    readonly componentProverRandomnessHexes: Readonly<
        Partial<Record<BallotPrivacyBackendProofComponentId, string>>
    >;
    readonly linearStatement: BallotProofFullRelationLinearProofStatement;
    readonly loweredStatement: BallotPrivacyLoweredLinearRelationStatement;
    readonly parameterSet: unknown;
    readonly proofEncoding: unknown;
    readonly proverRandomnessHex: string;
    readonly publicRandomnessHex: string;
    readonly secretState: BallotProofRecordGenerationSecretState;
    readonly statement: BallotProofStatement;
    readonly unsafeSmallRosterAcknowledged?: boolean;
};

const linearProofRelation = 'A*w + t = 0' as const;

const receiverPayloadOpeningEncodingOffset = 1024;

const fullBallotProofParameterProfileId =
    'full-encoded-score-ballot-linear-compatibility-v1';

const fullBallotProofEncodingProfileId =
    'full-encoded-score-ballot-linear-proof-encoding-v1';

const componentProofParameterProfileIds: Readonly<
    Record<BallotPrivacyBackendProofComponentId, string>
> = {
    'payload-plaintext-field-component':
        'payload-plaintext-field-linear-compatibility-v1',
    'receiver-encryption-component':
        'receiver-encryption-linear-compatibility-v1',
    'receiver-key-binding-component':
        'receiver-key-binding-linear-compatibility-v1',
    'score-and-shamir-field-component':
        'encoded-score-field-linear-compatibility-v1',
    'share-commitment-component': 'share-commitment-linear-compatibility-v1',
};

const componentProofEncodingProfileIds: Readonly<
    Record<BallotPrivacyBackendProofComponentId, string>
> = {
    'payload-plaintext-field-component':
        'payload-plaintext-field-linear-proof-encoding-v1',
    'receiver-encryption-component':
        'receiver-encryption-linear-proof-encoding-v1',
    'receiver-key-binding-component':
        'receiver-encryption-linear-proof-encoding-v1',
    'score-and-shamir-field-component':
        'encoded-score-field-linear-proof-encoding-v1',
    'share-commitment-component': 'share-commitment-linear-proof-encoding-v1',
};

const thirtyTwoByteLowercaseHexPattern = /^[a-f0-9]{64}$/u;

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

export {
    linearProofRelation,
    shareCommitmentModuleRank,
    shareCommitmentModuleDegree,
    shareCommitmentOpeningDimension,
    receiverEncryptionModulus,
    receiverEncryptionModuleRank,
    receiverEncryptionModuleDegree,
    receiverEncryptionMessageScale,
    receiverShareRepresentativeBitLength,
    receiverOpeningRandomnessBitLength,
    receiverPayloadOpeningEncodingOffset,
    fullBallotProofParameterProfileId,
    fullBallotProofEncodingProfileId,
    componentProofParameterProfileIds,
    componentProofEncodingProfileIds,
    thirtyTwoByteLowercaseHexPattern,
    positiveModulo,
    negacyclicNumberCoefficient,
    positiveModuloBigInt,
    polynomialCoefficient,
};
export type {
    DensePolynomialCoefficient,
    DensePolynomial,
    DensePolynomialMatrix,
    DensePolynomialVector,
    ConstantSparseMatrixEntry,
    SparseMatrixEntry,
    ConstantSparseTargetVectorEntry,
    SparseTargetVectorEntry,
    FieldVariableColumn,
    ExplicitFieldRow,
    ExplicitFieldRowBatch,
    StructuredShareCommitmentRowBatch,
    BallotProofLinearProofStatement,
    BallotProofFullRelationLinearProofStatement,
    BallotProofSparseComponentLinearProofStatement,
    PackedFieldSourceColumn,
    StructuredShareCommitmentReceiverStatement,
    BallotProofStructuredShareCommitmentProofStatement,
    StructuredReceiverEncryptionCiphertextChunkStatement,
    StructuredReceiverEncryptionReceiverStatement,
    BallotProofStructuredReceiverEncryptionProofStatement,
    EncodedScoreFieldLinearProofProjection,
    BallotProofExplicitComponentId,
    ReceiverEncryptionChunkProjectionWitness,
    BallotProofComponentLinearProofProjection,
    BallotProofExplicitComponentWitnessVerification,
    BackendRowBatchForComponentStatement,
    BallotProofComponentProofRecordPayload,
    BallotProofComponentProofBundlePayload,
    BallotProofRecordGenerationSecretState,
    BallotProofRecordGenerationComponentProofInput,
};
