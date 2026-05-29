import type { ProtocolHash, RefusalRecord } from '@sealed-lattice/types';

import {
    ballotPrivacyFieldModulus,
    receiverEncryptionModuleDegree,
    receiverEncryptionModuleRank,
    receiverEncryptionModulus,
    receiverEncryptionShortVectorInfinityNormBound,
    receiverOpeningRandomnessBitLength,
    receiverShareRepresentativeBitLength,
    shareCommitmentModuleDegree,
    shareCommitmentModuleRank,
    shareCommitmentModulusDecimal as shareCommitmentModulus,
    shareCommitmentOpeningDimension,
    shareCommitmentOpeningInfinityNormBound,
} from '../protocol-parameters.js';

const relationStatementFormat =
    'SparseIntegerRowsModuloGF65537WithBoundGadgets-v1';

const relationStatementHashPurpose =
    'ballot-privacy-linear-relation-statement-v1';

const backendStatementFormat = 'SparseSignedIntegerBackendStatement-v1';

const backendStatementHashPurpose = 'ballot-privacy-backend-statement-v1';

const explicitBackendMatrixHashPurpose =
    'ballot-privacy-backend-explicit-matrix-v1';

const explicitBackendTargetVectorHashPurpose =
    'ballot-privacy-backend-explicit-target-vector-v1';

const hashExpandedBackendMatrixHashPurpose =
    'ballot-privacy-backend-hash-expanded-matrix-v1';

const hashExpandedBackendTargetVectorHashPurpose =
    'ballot-privacy-backend-hash-expanded-target-vector-v1';

const structuredShareCommitmentBackendMatrixHashPurpose =
    'ballot-privacy-backend-structured-share-commitment-matrix-v1';

const structuredShareCommitmentBackendTargetVectorHashPurpose =
    'ballot-privacy-backend-structured-share-commitment-target-vector-v1';

const backendMatrixHashPurpose = 'ballot-privacy-backend-matrix-v1';

const backendTargetVectorHashPurpose =
    'ballot-privacy-backend-target-vector-v1';

const backendBoundsHashPurpose = 'ballot-privacy-backend-bounds-v1';

const backendProofComponentsHashPurpose =
    'ballot-privacy-backend-proof-components-v1';

type ReceiverReference = {
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
};

type ReceiverPublicKeyReference = ReceiverReference & {
    readonly keyMaterialHash?: ProtocolHash;
    readonly publicMatrixSeedHash?: ProtocolHash;
    readonly publicKeyVector?: readonly (readonly number[])[];
    readonly receiverPublicKeyHash: ProtocolHash;
};

type ReceiverPayloadReference = ReceiverReference & {
    readonly ciphertextBodyHash?: ProtocolHash;
    readonly ciphertextChunks?: readonly {
        readonly chunkIndex: number;
        readonly firstCiphertextVector: readonly (readonly number[])[];
        readonly secondCiphertextPolynomial: readonly number[];
    }[];
    readonly ciphertextChunkHash?: ProtocolHash;
    readonly ciphertextChunkCount?: number;
    readonly plaintextBitLength?: number;
    readonly receiverPayloadHash: ProtocolHash;
    readonly receiverPayloadCiphertextRoot: ProtocolHash;
};

type ReceiverPayloadCiphertextChunkReference = NonNullable<
    ReceiverPayloadReference['ciphertextChunks']
>[number];

type ShareCommitmentReference = ReceiverReference & {
    readonly commitmentBodyHash?: ProtocolHash;
    readonly commitmentPolynomialVector?: readonly (readonly string[])[];
    readonly commitmentPolynomialVectorHash?: ProtocolHash;
    readonly shareCommitmentHash: ProtocolHash;
};

export type BallotPrivacyRelationBackendPublicContext = {
    readonly ceremonyId: string;
    readonly manifestHash: ProtocolHash;
    readonly rosterHash: ProtocolHash;
    readonly pollSpecHash: ProtocolHash;
    readonly actionContextHash: ProtocolHash;
    readonly rosterExternalAcceptanceHash: ProtocolHash;
    readonly ballotProofStatementHash?: ProtocolHash;
    readonly receiverKeyRoot: ProtocolHash;
    readonly receiverKeyProofRoot: ProtocolHash;
    readonly receiverPublicKeys: readonly ReceiverPublicKeyReference[];
    readonly receiverPayloads: readonly ReceiverPayloadReference[];
    readonly shareCommitments: readonly ShareCommitmentReference[];
    readonly shareCommitmentProfileHash: ProtocolHash;
    readonly receiverEncryptionProfileHash: ProtocolHash;
    readonly ballotProofProfileHash: ProtocolHash;
    readonly scoreMembershipProfileHash: ProtocolHash;
    readonly ballotScoreEncodingProfileHash: ProtocolHash;
    readonly ballotShareLayoutProfileHash: ProtocolHash;
    readonly aggregateInputEncodingProfileHash: ProtocolHash;
    readonly encodedShareVectorLayoutHash: ProtocolHash;
    readonly encodedAggregateLayoutHash: ProtocolHash;
    readonly shareCommitmentMessageBoundCertHash: ProtocolHash;
};

type BallotPrivacyLinearRelationVariableRole =
    | 'ScalarScoreConstant'
    | 'ScoreBucketConstant'
    | 'ShamirCoefficient'
    | 'ReceiverShare'
    | 'ShamirQuotient'
    | 'ReceiverPayloadPlaintextShare'
    | 'ReceiverPayloadPlaintextOpening'
    | 'ReceiverPayloadPlaintextBit'
    | 'ShareCommitmentOpening'
    | 'ReceiverEncryptionRandomness'
    | 'ReceiverEncryptionFirstNoise'
    | 'ReceiverEncryptionSecondNoise'
    | 'ReceiverEncryptionRandomnessPolynomial'
    | 'ReceiverEncryptionFirstNoisePolynomial'
    | 'ReceiverEncryptionSecondNoisePolynomial'
    | 'ReceiverPayloadPlaintextPolynomial'
    | 'ReceiverEncryptionNoise';

type BallotPrivacyLinearRelationVariable = {
    readonly variableName: string;
    readonly variableRole: BallotPrivacyLinearRelationVariableRole;
    readonly encodedCoordinateIndex?: number;
    readonly optionIndex?: number;
    readonly scoreBucketValue?: number;
    readonly coefficientDegree?: number;
    readonly chunkIndex?: number;
    readonly ciphertextVectorIndex?: number;
    readonly bitIndex?: number;
    readonly openingCoordinateIndex?: number;
    readonly polynomialCoefficientIndex?: number;
    readonly receiverRosterPosition?: number;
};

type BallotPrivacyLinearRelationTerm = {
    readonly coefficient: number;
    readonly variableName: string;
};

type BallotPrivacyLinearRelationRowKind =
    | 'OneHotSum'
    | 'ScalarScoreConsistency'
    | 'ShamirEvaluationQuotient'
    | 'ShareCommitmentEquation'
    | 'ReceiverPayloadSharePlaintextBinding'
    | 'ReceiverPayloadOpeningPlaintextBinding'
    | 'ReceiverPayloadShareBitDecomposition'
    | 'ReceiverPayloadOpeningBitDecomposition'
    | 'ReceiverPayloadEncryptionEquation'
    | 'ReceiverKeyBinding';

type BallotPrivacyLinearRelationRow = {
    readonly rowName: string;
    readonly rowKind: BallotPrivacyLinearRelationRowKind;
    readonly modulus: typeof ballotPrivacyFieldModulus;
    readonly terms: readonly BallotPrivacyLinearRelationTerm[];
    readonly target: number;
    readonly encodedCoordinateIndex?: number;
    readonly openingCoordinateIndex?: number;
    readonly optionIndex?: number;
    readonly receiverRosterPosition?: number;
};

type BallotPrivacyLinearRelationBoundKind =
    | 'Boolean'
    | 'CanonicalFieldElement'
    | 'SignedIntegerAbsoluteBound';

type BallotPrivacyLinearRelationBound = {
    readonly boundName: string;
    readonly boundKind: BallotPrivacyLinearRelationBoundKind;
    readonly variableNames: readonly string[];
    readonly minimum?: number;
    readonly maximum?: number;
    readonly absoluteMaximum?: number;
};

type BallotPrivacyAlgebraicRelationRowKind =
    | 'ShareCommitmentEquation'
    | 'ReceiverPayloadEncryptionEquation'
    | 'ReceiverKeyBinding';

type BallotPrivacyAlgebraicRelationRow = {
    readonly rowName: string;
    readonly rowKind: BallotPrivacyAlgebraicRelationRowKind;
    readonly modulus: number | string;
    readonly equationCount: number;
    readonly shareCommitmentPolynomialVector?: readonly (readonly string[])[];
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly targetHash: ProtocolHash;
    readonly publicInputHashes: Record<string, ProtocolHash>;
    readonly variableNames: readonly string[];
};

type BallotPrivacyBackendStatementVariableColumn =
    BallotPrivacyLinearRelationVariable & {
        readonly columnIndex: number;
    };

type BallotPrivacyBackendStatementTerm = {
    readonly coefficient: string;
    readonly columnIndex: number;
    readonly variableName: string;
};

type BallotPrivacyBackendStatementExplicitRow = {
    readonly rowIndex: number;
    readonly rowKind: BallotPrivacyLinearRelationRowKind;
    readonly rowName: string;
    readonly modulus: string;
    readonly target: string;
    readonly terms: readonly BallotPrivacyBackendStatementTerm[];
};

type BallotPrivacyBackendStatementReceiverEncryptionRowDescriptor = {
    readonly ciphertextChunkCount: number;
    readonly plaintextBitLength: number;
    readonly receiverIdentity: string;
    readonly receiverPayloadHash: ProtocolHash;
    readonly receiverRosterPosition: number;
    readonly receiverPublicKeyHash: ProtocolHash;
    readonly rowCount: number;
    readonly rowOffsetWithinBatch: number;
};

type BallotPrivacyBackendStatementShareCommitmentRowDescriptor = {
    readonly commitmentBodyHash: ProtocolHash;
    readonly commitmentPolynomialVectorHash: ProtocolHash;
    readonly receiverIdentity: string;
    readonly receiverRosterPosition: number;
    readonly rowCount: number;
    readonly rowOffsetWithinBatch: number;
    readonly shareCommitmentHash: ProtocolHash;
};

type BallotPrivacyBackendStatementRowBatch =
    | {
          readonly batchKind: 'ExplicitSparseRows';
          readonly batchName:
              | 'encoded_score_field_rows'
              | 'receiver_key_binding_rows'
              | 'receiver_payload_encryption_equation_rows'
              | 'receiver_payload_plaintext_bit_decomposition_rows'
              | 'share_commitment_equation_rows'
              | 'receiver_payload_plaintext_binding_rows';
          readonly matrixHash: ProtocolHash;
          readonly modulus: string;
          readonly rowCount: number;
          readonly rowKind:
              | 'EncodedScoreFieldRows'
              | 'ReceiverKeyBindingRows'
              | 'ReceiverPayloadEncryptionEquationRows'
              | 'ReceiverPayloadPlaintextBitDecompositionRows'
              | 'ShareCommitmentEquationRows'
              | 'ReceiverPayloadPlaintextBindingRows';
          readonly rowOffset: number;
          readonly rows: readonly BallotPrivacyBackendStatementExplicitRow[];
          readonly targetVectorHash: ProtocolHash;
          readonly variableColumnIndices: readonly number[];
      }
    | {
          readonly batchKind: 'StructuredModuleSisShareCommitmentRows';
          readonly batchName: 'share_commitment_equation_rows';
          readonly matrixHash: ProtocolHash;
          readonly modulus: string;
          readonly rowCount: number;
          readonly rowKind: 'ShareCommitmentEquationRows';
          readonly rowOffset: number;
          readonly shareCommitmentRows: readonly BallotPrivacyBackendStatementShareCommitmentRowDescriptor[];
          readonly targetVectorHash: ProtocolHash;
          readonly variableColumnIndices: readonly number[];
      }
    | {
          readonly batchKind: 'StructuredModuleLweReceiverEncryptionRows';
          readonly batchName: 'receiver_payload_encryption_equation_rows';
          readonly matrixHash: ProtocolHash;
          readonly modulus: string;
          readonly receiverRows: readonly BallotPrivacyBackendStatementReceiverEncryptionRowDescriptor[];
          readonly rowCount: number;
          readonly rowKind: 'ReceiverPayloadEncryptionEquationRows';
          readonly rowOffset: number;
          readonly targetVectorHash: ProtocolHash;
          readonly variableColumnIndices: readonly number[];
      }
    | {
          readonly batchKind: 'HashExpandedRows';
          readonly batchName: string;
          readonly coefficientExpansionDomain: string;
          readonly matrixHash: ProtocolHash;
          readonly modulus: string;
          readonly publicInputHashes: Record<string, ProtocolHash>;
          readonly receiverIdentity: string;
          readonly receiverRosterPosition: number;
          readonly rowCount: number;
          readonly rowKind: BallotPrivacyAlgebraicRelationRowKind;
          readonly rowOffset: number;
          readonly sourceAlgebraicRowName: string;
          readonly targetHash: ProtocolHash;
          readonly targetExpansionDomain: string;
          readonly targetVectorHash: ProtocolHash;
          readonly variableColumnIndices: readonly number[];
      };

type BallotPrivacyBackendStatementBound = Omit<
    BallotPrivacyLinearRelationBound,
    'absoluteMaximum' | 'maximum' | 'minimum'
> & {
    readonly absoluteMaximum?: string;
    readonly maximum?: string;
    readonly minimum?: string;
    readonly variableColumnIndices: readonly number[];
};

export type BallotPrivacyBackendProofComponentId =
    | 'score-and-shamir-field-component'
    | 'payload-plaintext-field-component'
    | 'share-commitment-component'
    | 'receiver-encryption-component'
    | 'receiver-key-binding-component';

export type BallotPrivacyBackendProofComponent = {
    readonly componentHash: ProtocolHash;
    readonly componentId: BallotPrivacyBackendProofComponentId;
    readonly coefficientModulus: string;
    readonly proofLoweringStatus:
        | 'explicitRowsAvailable'
        | 'HashExpandedRowsPending';
    readonly rowBatchNames: readonly string[];
    readonly rowCount: number;
    readonly rowKinds: readonly string[];
    readonly variableColumnCount: number;
    readonly variableColumnIndices: readonly number[];
};

export type BallotPrivacyProofBackendStatement = {
    readonly objectType: 'BallotPrivacyProofBackendStatement';
    readonly objectVersion: 1;
    readonly backendStatementHash: ProtocolHash;
    readonly backendStatementFormat: typeof backendStatementFormat;
    readonly relationLabel: 'BallotPrivacyPvssRelation';
    readonly sourceRelationStatementFormat: typeof relationStatementFormat;
    readonly optionCount: number;
    readonly rosterSize: number;
    readonly pvssThreshold: number;
    readonly shareVectorWidth: number;
    readonly encodedCoordinateCount: number;
    readonly fieldModulus: typeof ballotPrivacyFieldModulus;
    readonly columnCount: number;
    readonly rowCount: number;
    readonly explicitRowCount: number;
    readonly hashExpandedRowCount: number;
    readonly variableColumns: readonly BallotPrivacyBackendStatementVariableColumn[];
    readonly rowBatches: readonly BallotPrivacyBackendStatementRowBatch[];
    readonly bounds: readonly BallotPrivacyBackendStatementBound[];
    readonly proofComponents: readonly BallotPrivacyBackendProofComponent[];
    readonly proofComponentsHash: ProtocolHash;
    readonly matrixHash: ProtocolHash;
    readonly targetVectorHash: ProtocolHash;
    readonly boundsHash: ProtocolHash;
};

export type BallotPrivacyLoweredLinearRelationStatement = {
    readonly objectType: 'BallotPrivacyLinearRelationStatement';
    readonly objectVersion: 1;
    readonly relationStatementFormat: typeof relationStatementFormat;
    readonly relationLabel: 'BallotPrivacyPvssRelation';
    readonly relationStatementHash: ProtocolHash;
    readonly optionCount: number;
    readonly rosterSize: number;
    readonly pvssThreshold: number;
    readonly shareVectorWidth: number;
    readonly encodedCoordinateCount: number;
    readonly fieldModulus: typeof ballotPrivacyFieldModulus;
    readonly publicContext: BallotPrivacyRelationBackendPublicContext;
    readonly variables: readonly BallotPrivacyLinearRelationVariable[];
    readonly linearRows: readonly BallotPrivacyLinearRelationRow[];
    readonly algebraicRows: readonly BallotPrivacyAlgebraicRelationRow[];
    readonly bounds: readonly BallotPrivacyLinearRelationBound[];
    readonly backendStatement: BallotPrivacyProofBackendStatement;
};

export type BallotPrivacyRelationBackendLoweringResult =
    | {
          readonly ok: true;
          readonly statement: BallotPrivacyLoweredLinearRelationStatement;
      }
    | {
          readonly ok: false;
          readonly refusedObjects: readonly RefusalRecord[];
          readonly unresolvedReason: 'BallotPrivacyRelationInvalid';
      };

type VariableRegistry = {
    readonly add: (
        variable: BallotPrivacyLinearRelationVariable,
    ) => BallotPrivacyLinearRelationVariable;
    readonly values: () => readonly BallotPrivacyLinearRelationVariable[];
};

const createVariableRegistry = (): VariableRegistry => {
    const variablesByName = new Map<
        string,
        BallotPrivacyLinearRelationVariable
    >();

    return {
        add: (variable) => {
            const existingVariable = variablesByName.get(variable.variableName);
            if (existingVariable !== undefined) {
                return existingVariable;
            }
            variablesByName.set(variable.variableName, variable);

            return variable;
        },
        values: () => [...variablesByName.values()],
    };
};

const scalarConstantVariableName = (optionIndex: number): string =>
    `option_${optionIndex + 1}_scalar_constant`;

const scoreBucketConstantVariableName = (
    optionIndex: number,
    scoreBucketValue: number,
): string => `option_${optionIndex + 1}_score_bucket_${scoreBucketValue}`;

const shamirCoefficientVariableName = (
    encodedCoordinateIndex: number,
    coefficientDegree: number,
): string =>
    `encoded_coordinate_${encodedCoordinateIndex}_coefficient_degree_${coefficientDegree}`;

const receiverShareVariableName = (
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_encoded_coordinate_${encodedCoordinateIndex}_share`;

const shamirQuotientVariableName = (
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_encoded_coordinate_${encodedCoordinateIndex}_quotient`;

const shareCommitmentOpeningVariableName = (
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_share_commitment_opening_coordinate_${openingCoordinateIndex}`;

const receiverPayloadPlaintextShareVariableName = (
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_payload_plaintext_encoded_coordinate_${encodedCoordinateIndex}_share`;

const receiverPayloadPlaintextOpeningVariableName = (
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_payload_plaintext_opening_coordinate_${openingCoordinateIndex}`;

const receiverPayloadPlaintextShareBitVariableName = (
    receiverRosterPosition: number,
    encodedCoordinateIndex: number,
    bitIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_payload_plaintext_encoded_coordinate_${encodedCoordinateIndex}_bit_${bitIndex}`;

const receiverPayloadPlaintextOpeningBitVariableName = (
    receiverRosterPosition: number,
    openingCoordinateIndex: number,
    bitIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_payload_plaintext_opening_coordinate_${openingCoordinateIndex}_bit_${bitIndex}`;

const receiverPayloadPlaintextBitVariableNameForLayout = (
    receiverRosterPosition: number,
    shareVectorWidth: number,
    plaintextBitIndex: number,
): string => {
    const shareBitCount =
        shareVectorWidth * receiverShareRepresentativeBitLength;
    if (plaintextBitIndex < shareBitCount) {
        return receiverPayloadPlaintextShareBitVariableName(
            receiverRosterPosition,
            Math.floor(
                plaintextBitIndex / receiverShareRepresentativeBitLength,
            ),
            plaintextBitIndex % receiverShareRepresentativeBitLength,
        );
    }

    const openingBitIndex = plaintextBitIndex - shareBitCount;

    return receiverPayloadPlaintextOpeningBitVariableName(
        receiverRosterPosition,
        Math.floor(openingBitIndex / receiverOpeningRandomnessBitLength),
        openingBitIndex % receiverOpeningRandomnessBitLength,
    );
};

const hashExpandedReceiverEncryptionRandomnessVariableName = (
    receiverRosterPosition: number,
): string =>
    `receiver_${receiverRosterPosition}_receiver_encryption_randomness`;

const hashExpandedReceiverEncryptionNoiseVariableName = (
    receiverRosterPosition: number,
): string => `receiver_${receiverRosterPosition}_receiver_encryption_noise`;

const receiverEncryptionRandomnessVariableName = (
    receiverRosterPosition: number,
    chunkIndex: number,
    ciphertextVectorIndex: number,
    polynomialCoefficientIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_receiver_encryption_chunk_${chunkIndex}_randomness_vector_${ciphertextVectorIndex}_coefficient_${polynomialCoefficientIndex}`;

const receiverEncryptionFirstNoiseVariableName = (
    receiverRosterPosition: number,
    chunkIndex: number,
    ciphertextVectorIndex: number,
    polynomialCoefficientIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_receiver_encryption_chunk_${chunkIndex}_first_noise_vector_${ciphertextVectorIndex}_coefficient_${polynomialCoefficientIndex}`;

const receiverEncryptionSecondNoiseVariableName = (
    receiverRosterPosition: number,
    chunkIndex: number,
    polynomialCoefficientIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_receiver_encryption_chunk_${chunkIndex}_second_noise_coefficient_${polynomialCoefficientIndex}`;

const receiverEncryptionRandomnessPolynomialVariableName = (
    receiverRosterPosition: number,
    chunkIndex: number,
    ciphertextVectorIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_receiver_encryption_chunk_${chunkIndex}_randomness_vector_${ciphertextVectorIndex}_polynomial`;

const receiverEncryptionFirstNoisePolynomialVariableName = (
    receiverRosterPosition: number,
    chunkIndex: number,
    ciphertextVectorIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_receiver_encryption_chunk_${chunkIndex}_first_noise_vector_${ciphertextVectorIndex}_polynomial`;

const receiverEncryptionSecondNoisePolynomialVariableName = (
    receiverRosterPosition: number,
    chunkIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_receiver_encryption_chunk_${chunkIndex}_second_noise_polynomial`;

const receiverPayloadPlaintextPolynomialVariableName = (
    receiverRosterPosition: number,
    chunkIndex: number,
): string =>
    `receiver_${receiverRosterPosition}_receiver_encryption_chunk_${chunkIndex}_payload_plaintext_polynomial`;

export {
    relationStatementFormat,
    relationStatementHashPurpose,
    backendStatementFormat,
    backendStatementHashPurpose,
    explicitBackendMatrixHashPurpose,
    explicitBackendTargetVectorHashPurpose,
    hashExpandedBackendMatrixHashPurpose,
    hashExpandedBackendTargetVectorHashPurpose,
    structuredShareCommitmentBackendMatrixHashPurpose,
    structuredShareCommitmentBackendTargetVectorHashPurpose,
    backendMatrixHashPurpose,
    backendTargetVectorHashPurpose,
    backendBoundsHashPurpose,
    backendProofComponentsHashPurpose,
    shareCommitmentModulus,
    shareCommitmentModuleRank,
    shareCommitmentModuleDegree,
    shareCommitmentOpeningDimension,
    shareCommitmentOpeningInfinityNormBound,
    receiverEncryptionModulus,
    receiverEncryptionModuleRank,
    receiverEncryptionModuleDegree,
    receiverEncryptionShortVectorInfinityNormBound,
    receiverShareRepresentativeBitLength,
    receiverOpeningRandomnessBitLength,
    createVariableRegistry,
    scalarConstantVariableName,
    scoreBucketConstantVariableName,
    shamirCoefficientVariableName,
    receiverShareVariableName,
    shamirQuotientVariableName,
    shareCommitmentOpeningVariableName,
    receiverPayloadPlaintextShareVariableName,
    receiverPayloadPlaintextOpeningVariableName,
    receiverPayloadPlaintextShareBitVariableName,
    receiverPayloadPlaintextOpeningBitVariableName,
    receiverPayloadPlaintextBitVariableNameForLayout,
    hashExpandedReceiverEncryptionRandomnessVariableName,
    hashExpandedReceiverEncryptionNoiseVariableName,
    receiverEncryptionRandomnessVariableName,
    receiverEncryptionFirstNoiseVariableName,
    receiverEncryptionSecondNoiseVariableName,
    receiverEncryptionRandomnessPolynomialVariableName,
    receiverEncryptionFirstNoisePolynomialVariableName,
    receiverEncryptionSecondNoisePolynomialVariableName,
    receiverPayloadPlaintextPolynomialVariableName,
};
export type {
    ReceiverReference,
    ReceiverPayloadReference,
    ReceiverPayloadCiphertextChunkReference,
    BallotPrivacyLinearRelationVariable,
    BallotPrivacyLinearRelationRow,
    BallotPrivacyLinearRelationBound,
    BallotPrivacyAlgebraicRelationRow,
    BallotPrivacyBackendStatementVariableColumn,
    BallotPrivacyBackendStatementTerm,
    BallotPrivacyBackendStatementExplicitRow,
    BallotPrivacyBackendStatementReceiverEncryptionRowDescriptor,
    BallotPrivacyBackendStatementRowBatch,
    BallotPrivacyBackendStatementBound,
    VariableRegistry,
};
