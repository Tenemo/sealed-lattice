import { deriveProtocolHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { acceptedBgvProfileRingDegree } from './vss-coefficient-commitments.js';
import type { VssSourceTrusteeCoefficientOpeningState } from './vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

const twoToTheSixtyFourth = 1n << 64n;

export const compactVssCommitmentProfileId =
    'SealedLattice-CompactLinearCommitment-Development-v1';
export const compactVssCommitmentDevelopmentScope =
    'development-only-not-certified-for-production-use';
export const compactVssCommitmentOutputCoordinateCount = 16;
export const compactVssCommitmentRandomnessColumnCount = 2;
export const compactVssProjectionWeight = 32;
export const compactVssCommitmentModulusLimbIndices = [0, 1, 2] as const;
export const compactVssCommitmentBinaryFormat =
    'sealed-lattice-compact-vss-commitment-binary-v1';
const compactVssShareLinkageStatementRelation =
    'recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments';
const compactVssShareLinkageStatementProofBoundary =
    'statement binding only; zero-knowledge linkage proof backend is not implemented yet';
const compactVssPublicSetupDownloadBudgetBytes = 64 * 1024 * 1024;
const compactVssSourceTrusteeUploadBudgetBytes = 256 * 1024 * 1024;
const compactVssLargestSingleObjectBudgetBytes = 16 * 1024 * 1024;
const compactVssLargestWasmBoundaryCopyBudgetBytes = 1_572_864;
export const compactVssShareLinkageProofBatchingRule =
    'one public share-linkage statement record is bound per source trustee, batching every recipient and target-basis limb for that source';
export const compactVssShareLinkageShamirEvaluationRule =
    'recipient-share commitments must open to the Shamir evaluation of the source trustee coefficient commitments at the recipient trustee point';
export const compactVssShareLinkageAggregateThresholdRule =
    'aggregate threshold commitments must be the public sum of source-to-recipient share commitments for the same recipient and target-basis limb';
export const compactVssShareLinkageCommonKeyRule =
    'coefficient, recipient-share, and aggregate threshold compact commitments must use the same public matrix seed hash and compact commitment profile';
export const compactVssShareLinkageRecipientApprovalBoundary =
    'recipient signatures or acknowledgements are not accepted as evidence for an invalid public recipient-share commitment';

export type CompactVssCommitmentRole =
    | 'coefficient'
    | 'recipient-share'
    | 'aggregate-threshold-share';

export type CompactVssCommitmentOpeningInput = Readonly<{
    readonly commitmentRole: CompactVssCommitmentRole;
    readonly commitmentContext: JsonRecord;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly messageCoefficients: readonly number[];
    readonly messageCoefficientBound?: number;
    readonly randomnessByColumn: readonly (readonly number[])[];
}>;

export type CompactVssCommitmentLimb = Readonly<{
    readonly commitmentModulusIndex: number;
    readonly modulus: number;
    readonly coordinates: readonly number[];
}>;

export type CompactVssCommitmentValue = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssCommitment';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly commitmentRole: CompactVssCommitmentRole;
        readonly commitmentContextHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly outputCoordinateCount: typeof compactVssCommitmentOutputCoordinateCount;
        readonly randomnessColumnCount: typeof compactVssCommitmentRandomnessColumnCount;
        readonly messageVectorHash512: string;
        readonly openingRandomnessHash512: string;
        readonly commitmentLimbs: readonly CompactVssCommitmentLimb[];
    }
>;

type CompactVssCommitmentComputation = Readonly<{
    readonly ok: true;
    readonly operation: 'computeCompactVssCommitmentFromOpening';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly commitment: CompactVssCommitmentValue;
    readonly commitmentRoot: ProtocolHash;
    readonly commitmentContextHash: ProtocolHash;
    readonly openingRoot: ProtocolHash;
    readonly encodedCommitmentByteLength: number;
}>;

export type CompactVssCommitmentBodyMetadata = Readonly<{
    readonly commitmentRole: CompactVssCommitmentRole;
    readonly commitmentContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly messageVectorHash512: string;
    readonly openingRandomnessHash512: string;
}>;

type CompactVssCommitmentOpeningVerification = Readonly<{
    readonly ok: true;
    readonly operation: 'verifyCompactVssCommitmentOpening';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly commitmentRoot: ProtocolHash;
    readonly openingRoot: ProtocolHash;
}>;

type CompactVssCommitmentHomomorphicCombinationInput = Readonly<{
    readonly commitmentRole: CompactVssCommitmentRole;
    readonly commitmentContext: JsonRecord;
    readonly combinedMessageVectorHash512?: string;
    readonly combinedOpeningRandomnessHash512?: string;
    readonly terms: readonly {
        readonly commitment: CompactVssCommitmentValue;
        readonly scalar: number;
    }[];
}>;

type CompactVssCommitmentMeasurement = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssCommitmentMeasurement';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly participantCount: number;
        readonly sourceRnsLimbCount: number;
        readonly targetRnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly ringDegree: number;
        readonly projectionWeight: typeof compactVssProjectionWeight;
        readonly outputCoordinateCount: typeof compactVssCommitmentOutputCoordinateCount;
        readonly commitmentModulusLimbCount: number;
        readonly singleCompactCommitmentBytes: number;
        readonly fullCoefficientCommitmentBytes: number;
        readonly recipientShareCommitmentBytes: number;
        readonly aggregateThresholdCommitmentBytes: number;
        readonly totalCompactPublicCommitmentBytes: number;
        readonly currentFullCoefficientTransportBytes: number;
        readonly byteAccountingScope: string;
        readonly measuredPublicCommitmentRoles: readonly string[];
        readonly excludedByteCategories: readonly string[];
        readonly byteReduction: Readonly<{
            readonly removedBytes: number;
            readonly compactFractionOfCurrent: number;
            readonly reductionFactor: number;
        }>;
        readonly largestSingleObjectBytes: number;
        readonly largestWasmBoundaryCopyBytes: number;
        readonly budgetComparison: Readonly<{
            readonly budgetScope: string;
            readonly publicSetupDownloadBudgetBytes: number;
            readonly totalCompactPublicCommitmentFractionOfDownloadBudget: number;
            readonly sourceTrusteeUploadBudgetBytes: number;
            readonly oneSourcePublicCommitmentUploadBytes: number;
            readonly oneSourcePublicCommitmentUploadFractionOfBudget: number;
            readonly largestSingleObjectBudgetBytes: number;
            readonly largestSingleObjectFractionOfBudget: number;
            readonly largestWasmBoundaryCopyBudgetBytes: number;
            readonly largestWasmBoundaryCopyFractionOfBudget: number;
        }>;
        readonly cpuWorkModel: Readonly<{
            readonly residueMultiplyAddsPerCommitment: number;
            readonly sourceCoefficientCommitments: number;
            readonly recipientShareCommitments: number;
            readonly aggregateThresholdCommitments: number;
            readonly totalCommitments: number;
            readonly totalResidueMultiplyAdds: number;
            readonly aggregatePublicSumResidueAdditions: number;
            readonly totalResidueArithmeticOperations: number;
            readonly aggregatePublicSumFractionOfCommitmentWork: number;
        }>;
    }
>;

type CompactVssMatrixExpansionProfile = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssMatrixExpansionProfile';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly matrixKind: 'compact-vss-commitment-key';
        readonly keyScope: string;
        readonly ringDegree: number;
        readonly commitmentModulusLimbIndices: readonly number[];
        readonly outputCoordinateCount: typeof compactVssCommitmentOutputCoordinateCount;
        readonly projectionWeight: typeof compactVssProjectionWeight;
        readonly randomnessColumnCount: typeof compactVssCommitmentRandomnessColumnCount;
        readonly inputColumnLabels: readonly string[];
        readonly matrixResidueHashDomain: string;
        readonly projectionIndexHashDomain: string;
        readonly rejectionSamplingRule: string;
        readonly matrixResiduePreimageFields: readonly string[];
        readonly projectionIndexPreimageFields: readonly string[];
        readonly biasBoundary: string;
        readonly coordinateCountPerCommitment: number;
        readonly sampledMatrixResiduesPerCoordinate: number;
        readonly sampledProjectionIndicesPerCoordinate: number;
        readonly sampledMatrixResiduesPerCommitment: number;
        readonly sampledProjectionIndicesPerCommitment: number;
        readonly residueMultiplyAddsPerCommitment: number;
        readonly certificateBoundary: string;
    }
>;

export type CompactVssParameterCertificateInputBinding = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssParameterCertificateInputBinding';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly compactVssParameterCertificateInputBindingHash: ProtocolHash;
        readonly participantCount: number;
        readonly sourceRnsLimbCount: number;
        readonly targetRnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly ringDegree: number;
        readonly commitmentRelation: Readonly<Record<string, unknown>>;
        readonly commonCommitmentKey: Readonly<Record<string, unknown>>;
        readonly messageEncoding: Readonly<Record<string, unknown>>;
        readonly normInputClasses: readonly Readonly<Record<string, unknown>>[];
        readonly estimatorInputRows: readonly Readonly<
            Record<string, unknown>
        >[];
        readonly proofCoverageInputs: Readonly<Record<string, unknown>>;
        readonly structuredRingDisclosure: string;
        readonly sameSecretBridgeInput: Readonly<Record<string, unknown>>;
    }
>;

type CompactVssPrivateWitnessPayloadMeasurement = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssPrivateWitnessPayloadMeasurement';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly participantCount: number;
        readonly targetRnsLimbCount: number;
        readonly ringDegree: number;
        readonly bytesPerResidue: 8;
        readonly randomnessColumnCount: typeof compactVssCommitmentRandomnessColumnCount;
        readonly oneSourceRecipientCredentialPayloadBytes: number;
        readonly oneAggregateCredentialPayloadBytes: number;
        readonly oneRecipientPrivateMailboxCredentialPayloadBytes: number;
        readonly oneRecipientPersistentAggregateCredentialPayloadBytes: number;
        readonly allRecipientsPrivateMailboxCredentialPayloadBytes: number;
        readonly allRecipientsPersistentAggregateCredentialPayloadBytes: number;
        readonly largestSingleCredentialPayloadBytes: number;
        readonly byteAccountingScope: string;
        readonly excludedByteCategories: readonly string[];
    }
>;

type CompactVssTrusteeReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
}>;

type CompactVssShareOpeningRandomnessProviderInput =
    CompactVssTrusteeReference &
        Readonly<{
            readonly recipientIdentity: string;
            readonly recipientRosterPosition: number;
            readonly rnsLimbIndex: number;
            readonly rnsPrime: number;
            readonly ringDegree: number;
        }>;

type CompactVssShareOpeningRandomnessProvider = (
    input: CompactVssShareOpeningRandomnessProviderInput,
) => readonly (readonly number[])[];

type CompactVssCoefficientOpeningRandomnessProviderInput =
    CompactVssTrusteeReference &
        Readonly<{
            readonly rnsLimbIndex: number;
            readonly rnsPrime: number;
            readonly shamirCoefficientIndex: number;
            readonly ringDegree: number;
        }>;

type CompactVssCoefficientOpeningRandomnessProvider = (
    input: CompactVssCoefficientOpeningRandomnessProviderInput,
) => readonly (readonly number[])[];

type CompactVssCoefficientCommitmentRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssCoefficientCommitment';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shamirCoefficientIndex: number;
        readonly coefficientCommitmentRoot: ProtocolHash;
        readonly coefficientVectorHash512: string;
        readonly commitment: CompactVssCommitmentValue;
    }
>;

type CompactVssSourceCoefficientCommitments = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSourceCoefficientCommitments';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly coefficientCommitments: readonly CompactVssCoefficientCommitmentRecord[];
        readonly sourceCoefficientCommitmentRoot: ProtocolHash;
    }
>;

export type CompactVssCoefficientCommitmentSet = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssCoefficientCommitmentSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly ringDegree: number;
        readonly sourceTrusteeRecords: readonly CompactVssSourceCoefficientCommitments[];
        readonly coefficientCommitmentRoot: ProtocolHash;
    }
>;

type CompactVssRecipientShareCommitmentRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssRecipientShareCommitment';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly recipientTrusteePoint: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shareCommitmentRoot: ProtocolHash;
        readonly shareOpeningRoot: ProtocolHash;
        readonly shareVectorHash512: string;
        readonly commitment: CompactVssCommitmentValue;
    }
>;

type CompactVssSourceRecipientShareCommitments = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSourceRecipientShareCommitments';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientShareCommitments: readonly CompactVssRecipientShareCommitmentRecord[];
        readonly sourceRecipientShareCommitmentRoot: ProtocolHash;
    }
>;

export type CompactVssRecipientShareCommitmentSet = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssRecipientShareCommitmentSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly sourceTrusteeRecords: readonly CompactVssSourceRecipientShareCommitments[];
        readonly recipientShareCommitmentRoot: ProtocolHash;
    }
>;

export type CompactVssRecipientShareOpeningCredential = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssRecipientShareOpeningCredential';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly recipientTrusteePoint: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shareValues: readonly number[];
        readonly randomnessByColumn: readonly (readonly number[])[];
        readonly shareCommitmentRoot: ProtocolHash;
        readonly shareOpeningRoot: ProtocolHash;
    }
>;

type CompactVssRecipientShareCommitmentBundle = Readonly<{
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly recipientShareOpeningCredentials: readonly CompactVssRecipientShareOpeningCredential[];
}>;

export type CompactVssAggregateThresholdCommitmentRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssAggregateThresholdCommitment';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly recipientTrusteePoint: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly aggregateCommitmentRoot: ProtocolHash;
        readonly aggregateOpeningRoot: ProtocolHash;
        readonly commitment: CompactVssCommitmentValue;
        readonly sourceShareCommitmentRoots: readonly ProtocolHash[];
    }
>;

export type CompactVssAggregateThresholdCommitmentSet = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssAggregateThresholdCommitmentSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly participantCount: number;
        readonly rnsLimbCount: number;
        readonly ringDegree: number;
        readonly recipientRecords: readonly CompactVssAggregateThresholdCommitmentRecord[];
        readonly aggregateThresholdCommitmentRoot: ProtocolHash;
    }
>;

export type CompactVssAggregateThresholdOpeningCredential = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssAggregateThresholdOpeningCredential';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly recipientTrusteePoint: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly aggregateShareValues: readonly number[];
        readonly aggregateCommitmentMessageValues: readonly number[];
        readonly aggregateShareCarryValues: readonly number[];
        readonly aggregateRandomnessByColumn: readonly (readonly number[])[];
        readonly aggregateCommitmentRoot: ProtocolHash;
        readonly aggregateOpeningRoot: ProtocolHash;
        readonly sourceShareOpeningRoots: readonly ProtocolHash[];
    }
>;

type CompactVssAggregateThresholdCommitmentBundle = Readonly<{
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly aggregateThresholdOpeningCredentials: readonly CompactVssAggregateThresholdOpeningCredential[];
}>;

export type CompactVssShareLinkageStatement = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssShareLinkageStatement';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly targetBasisHash: ProtocolHash;
        readonly participantCount: number;
        readonly targetRnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly coefficientCommitmentRoot: ProtocolHash;
        readonly recipientShareCommitmentRoot: ProtocolHash;
        readonly aggregateThresholdCommitmentRoot: ProtocolHash;
        readonly relation: typeof compactVssShareLinkageStatementRelation;
        readonly proofBatchingRule: typeof compactVssShareLinkageProofBatchingRule;
        readonly shamirEvaluationRule: typeof compactVssShareLinkageShamirEvaluationRule;
        readonly aggregateThresholdRule: typeof compactVssShareLinkageAggregateThresholdRule;
        readonly commonKeyRule: typeof compactVssShareLinkageCommonKeyRule;
        readonly recipientApprovalBoundary: typeof compactVssShareLinkageRecipientApprovalBoundary;
        readonly proofBoundary: typeof compactVssShareLinkageStatementProofBoundary;
        readonly sourceStatementRecords: readonly CompactVssShareLinkageSourceStatementRecord[];
        readonly statementRoot: ProtocolHash;
    }
>;

export type CompactVssShareLinkageSourceStatementRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssShareLinkageSourceStatement';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly developmentScope: typeof compactVssCommitmentDevelopmentScope;
        readonly ceremonyId: string;
        readonly manifestHash: ProtocolHash;
        readonly rosterHash: ProtocolHash;
        readonly setupProfileHash: ProtocolHash;
        readonly qShareHash: ProtocolHash;
        readonly carryAwareVssShareRelationProfileHash: ProtocolHash;
        readonly commitmentProfileHash: ProtocolHash;
        readonly setupEpoch: string;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly targetBasisHash: ProtocolHash;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly participantCount: number;
        readonly targetRnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly coefficientCommitmentRoot: ProtocolHash;
        readonly sourceCoefficientCommitmentRoot: ProtocolHash;
        readonly sourceRecipientShareCommitmentRoot: ProtocolHash;
        readonly aggregateThresholdCommitmentRoot: ProtocolHash;
        readonly relation: typeof compactVssShareLinkageStatementRelation;
        readonly proofBatchingRule: typeof compactVssShareLinkageProofBatchingRule;
        readonly shamirEvaluationRule: typeof compactVssShareLinkageShamirEvaluationRule;
        readonly aggregateThresholdRule: typeof compactVssShareLinkageAggregateThresholdRule;
        readonly commonKeyRule: typeof compactVssShareLinkageCommonKeyRule;
        readonly recipientApprovalBoundary: typeof compactVssShareLinkageRecipientApprovalBoundary;
        readonly proofBoundary: typeof compactVssShareLinkageStatementProofBoundary;
        readonly sourceStatementRoot: ProtocolHash;
    }
>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertHash512Hex = (value: string, fieldName: string): void => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(
            `${fieldName} must be a 512-bit lowercase hex hash.`,
        );
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const assertExactStringField = (
    value: string,
    fieldName: string,
    expectedValue: string,
): void => {
    if (value !== expectedValue) {
        throw new TypeError(`${fieldName} is not supported.`);
    }
};

const assertCompactVssCommitmentRole: (
    value: string,
    fieldName: string,
) => asserts value is CompactVssCommitmentRole = (
    value: string,
    fieldName: string,
): asserts value is CompactVssCommitmentRole => {
    if (
        value !== 'coefficient' &&
        value !== 'recipient-share' &&
        value !== 'aggregate-threshold-share'
    ) {
        throw new TypeError(`${fieldName} is not supported.`);
    }
};

const assertPositiveSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value) || value <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
};

const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

const assertSignedSafeInteger = (value: number, fieldName: string): void => {
    if (!Number.isSafeInteger(value)) {
        throw new TypeError(`${fieldName} must be a safe integer.`);
    }
};

const assertResidueVector = (
    values: readonly number[],
    modulus: number,
    ringDegree: number,
    fieldName: string,
): void => {
    if (values.length !== ringDegree) {
        throw new Error(`${fieldName} length must match ringDegree.`);
    }
    values.forEach((value, valueIndex) => {
        if (!Number.isSafeInteger(value) || value < 0 || value >= modulus) {
            throw new TypeError(
                `${fieldName}.${String(valueIndex)} must be a residue below the declared modulus.`,
            );
        }
    });
};

const assertOpeningRandomness = (
    randomnessByColumn: readonly (readonly number[])[],
    ringDegree: number,
): void => {
    if (
        randomnessByColumn.length !== compactVssCommitmentRandomnessColumnCount
    ) {
        throw new Error(
            'randomnessByColumn must contain the compact commitment randomness column count.',
        );
    }
    randomnessByColumn.forEach((randomnessColumn, columnIndex) => {
        if (randomnessColumn.length !== ringDegree) {
            throw new Error(
                `randomnessByColumn.${String(columnIndex)} length must match ringDegree.`,
            );
        }
        randomnessColumn.forEach((coefficient, coefficientIndex) =>
            assertSignedSafeInteger(
                coefficient,
                `randomnessByColumn.${String(columnIndex)}.${String(coefficientIndex)}`,
            ),
        );
    });
};

const littleEndianU64 = (bytes: Uint8Array, offset: number): bigint => {
    let value = 0n;
    for (let byteIndex = 7; byteIndex >= 0; byteIndex -= 1) {
        value = (value << 8n) | BigInt(bytes[offset + byteIndex] ?? 0);
    }

    return value;
};

const writeLittleEndianU64 = (
    bytes: Uint8Array,
    offset: number,
    value: number,
): void => {
    let remainingValue = BigInt(value);
    for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
        bytes[offset + byteIndex] = Number(remainingValue & 0xffn);
        remainingValue >>= 8n;
    }
};

const hexToBytes = (hex: string): Uint8Array => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

const reduceUnbiasedU64 = (
    value: bigint,
    modulus: number,
): number | undefined => {
    const modulusWide = BigInt(modulus);
    const limit = twoToTheSixtyFourth - (twoToTheSixtyFourth % modulusWide);
    if (value >= limit) {
        return undefined;
    }

    return Number(value % modulusWide);
};

const sampleCompactMatrixResidue = (input: {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly commitmentModulusIndex: number;
    readonly outputCoordinateIndex: number;
    readonly inputColumn: string;
    readonly projectionTermIndex: number;
    readonly modulus: number;
}): number => {
    let blockIndex = 0;
    for (;;) {
        const digestBytes = hexToBytes(
            hash512Hex(
                'sealed-lattice-compact-vss-commitment/matrix-residue-v1',
                [
                    new TextEncoder().encode(
                        [
                            input.publicMatrixSeedHash,
                            compactVssCommitmentProfileId,
                            String(input.rnsLimbIndex),
                            String(input.commitmentModulusIndex),
                            String(input.outputCoordinateIndex),
                            input.inputColumn,
                            String(input.projectionTermIndex),
                            String(input.modulus),
                            String(blockIndex),
                        ].join('|'),
                    ),
                ],
            ),
        );
        for (let offset = 0; offset < digestBytes.byteLength; offset += 8) {
            const reduced = reduceUnbiasedU64(
                littleEndianU64(digestBytes, offset),
                input.modulus,
            );
            if (reduced !== undefined) {
                return reduced;
            }
        }
        blockIndex += 1;
    }
};

const sampleCompactProjectionIndex = (input: {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly commitmentModulusIndex: number;
    readonly outputCoordinateIndex: number;
    readonly inputColumn: string;
    readonly projectionTermIndex: number;
    readonly ringDegree: number;
}): number => {
    let blockIndex = 0;
    for (;;) {
        const digestBytes = hexToBytes(
            hash512Hex(
                'sealed-lattice-compact-vss-commitment/projection-index-v1',
                [
                    new TextEncoder().encode(
                        [
                            input.publicMatrixSeedHash,
                            compactVssCommitmentProfileId,
                            String(input.rnsLimbIndex),
                            String(input.commitmentModulusIndex),
                            String(input.outputCoordinateIndex),
                            input.inputColumn,
                            String(input.projectionTermIndex),
                            String(input.ringDegree),
                            String(blockIndex),
                        ].join('|'),
                    ),
                ],
            ),
        );
        for (let offset = 0; offset < digestBytes.byteLength; offset += 8) {
            const reduced = reduceUnbiasedU64(
                littleEndianU64(digestBytes, offset),
                input.ringDegree,
            );
            if (reduced !== undefined) {
                return reduced;
            }
        }
        blockIndex += 1;
    }
};

type CompactProjectionTerm = Readonly<{
    readonly ringCoefficientIndex: number;
    readonly matrixResidue: number;
}>;

const compactProjectionTermCache = new Map<
    string,
    readonly CompactProjectionTerm[]
>();

const compactProjectionTermCacheKey = (input: {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly commitmentModulusIndex: number;
    readonly outputCoordinateIndex: number;
    readonly inputColumn: string;
    readonly ringDegree: number;
    readonly modulus: number;
}): string =>
    [
        input.publicMatrixSeedHash,
        compactVssCommitmentProfileId,
        String(input.rnsLimbIndex),
        String(input.commitmentModulusIndex),
        String(input.outputCoordinateIndex),
        input.inputColumn,
        String(input.ringDegree),
        String(input.modulus),
    ].join('|');

const compactProjectionTerms = (input: {
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly commitmentModulusIndex: number;
    readonly outputCoordinateIndex: number;
    readonly inputColumn: string;
    readonly ringDegree: number;
    readonly modulus: number;
}): readonly CompactProjectionTerm[] => {
    const cacheKey = compactProjectionTermCacheKey(input);
    const cachedTerms = compactProjectionTermCache.get(cacheKey);
    if (cachedTerms !== undefined) {
        return cachedTerms;
    }

    const terms = Array.from(
        { length: compactVssProjectionWeight },
        (_unused, projectionTermIndex) => ({
            ringCoefficientIndex: sampleCompactProjectionIndex({
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                rnsLimbIndex: input.rnsLimbIndex,
                commitmentModulusIndex: input.commitmentModulusIndex,
                outputCoordinateIndex: input.outputCoordinateIndex,
                inputColumn: input.inputColumn,
                projectionTermIndex,
                ringDegree: input.ringDegree,
            }),
            matrixResidue: sampleCompactMatrixResidue({
                publicMatrixSeedHash: input.publicMatrixSeedHash,
                rnsLimbIndex: input.rnsLimbIndex,
                commitmentModulusIndex: input.commitmentModulusIndex,
                outputCoordinateIndex: input.outputCoordinateIndex,
                inputColumn: input.inputColumn,
                projectionTermIndex,
                modulus: input.modulus,
            }),
        }),
    );
    compactProjectionTermCache.set(cacheKey, terms);

    return terms;
};

const signedIntegerToResidue = (value: number, modulus: number): number => {
    const modulusWide = BigInt(modulus);
    const residue = BigInt(value) % modulusWide;

    return Number(residue < 0n ? residue + modulusWide : residue);
};

const setupContextFields = (
    setupContext: CollectiveBgvSetupContext,
): CollectiveBgvSetupContext => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupProfileHash: setupContext.setupProfileHash,
    qShareHash: setupContext.qShareHash,
    carryAwareVssShareRelationProfileHash:
        setupContext.carryAwareVssShareRelationProfileHash,
    commitmentProfileHash: setupContext.commitmentProfileHash,
    setupEpoch: setupContext.setupEpoch,
});

const openingCoordinateKey = (
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): string => `${String(rnsLimbIndex)}:${String(shamirCoefficientIndex)}`;

const sortedSourceTrusteeOpeningStates = (input: {
    readonly participantCount: number;
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
}): VssSourceTrusteeCoefficientOpeningState[] => {
    if (input.sourceTrusteeOpeningStates.length !== input.participantCount) {
        throw new Error(
            'compact VSS source trustee opening states must cover every participant.',
        );
    }
    const sourceTrusteeOpeningStates = [
        ...input.sourceTrusteeOpeningStates,
    ].sort(
        (leftState, rightState) =>
            leftState.sourceTrusteeRosterPosition -
            rightState.sourceTrusteeRosterPosition,
    );
    sourceTrusteeOpeningStates.forEach(
        (sourceTrusteeOpeningState, expectedRosterPosition) => {
            assertNonEmptyString(
                sourceTrusteeOpeningState.sourceTrusteeIdentity,
                'sourceTrusteeOpeningState.sourceTrusteeIdentity',
            );
            if (
                sourceTrusteeOpeningState.sourceTrusteeRosterPosition !==
                expectedRosterPosition
            ) {
                throw new Error(
                    'compact VSS source trustee opening state roster positions must be contiguous from zero.',
                );
            }
        },
    );

    return sourceTrusteeOpeningStates;
};

const evaluateSourceShareForRecipient = (input: {
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly thresholdDegree: number;
    readonly ringDegree: number;
}): readonly number[] => {
    const openingsByCoordinate = new Map(
        input.sourceTrusteeOpeningState.coefficientOpenings.map((opening) => [
            openingCoordinateKey(
                opening.rnsLimbIndex,
                opening.shamirCoefficientIndex,
            ),
            opening,
        ]),
    );
    const shareValues = Array.from({ length: input.ringDegree }, () => 0n);
    let pointPower = 1n;
    const modulusWide = BigInt(input.rnsPrime);
    for (
        let shamirCoefficientIndex = 0;
        shamirCoefficientIndex < input.thresholdDegree;
        shamirCoefficientIndex += 1
    ) {
        const opening = openingsByCoordinate.get(
            openingCoordinateKey(input.rnsLimbIndex, shamirCoefficientIndex),
        );
        if (opening === undefined) {
            throw new Error(
                'source trustee coefficient openings must cover every compact VSS share coordinate.',
            );
        }
        assertResidueVector(
            opening.coefficientMessage,
            input.rnsPrime,
            input.ringDegree,
            'coefficientMessage',
        );
        opening.coefficientMessage.forEach((coefficient, coefficientIndex) => {
            shareValues[coefficientIndex] =
                ((shareValues[coefficientIndex] ?? 0n) +
                    BigInt(coefficient) * pointPower) %
                modulusWide;
        });
        pointPower =
            (pointPower * BigInt(input.recipientTrusteePoint)) % modulusWide;
    }

    return shareValues.map((shareValue) => Number(shareValue));
};

type CompactVssAggregateShareSum = Readonly<{
    readonly aggregateShareValues: readonly number[];
    readonly aggregateCommitmentMessageValues: readonly number[];
    readonly aggregateShareCarryValues: readonly number[];
}>;

const safeNumberFromBigInt = (value: bigint, fieldName: string): number => {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`${fieldName} exceeds the safe integer range.`);
    }

    return Number(value);
};

export const compactVssAggregateMessageCoefficientBound = (input: {
    readonly rnsPrime: number;
    readonly participantCount: number;
}): number => {
    assertPositiveSafeInteger(input.rnsPrime, 'rnsPrime');
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    const bound = BigInt(input.rnsPrime) * BigInt(input.participantCount);

    return safeNumberFromBigInt(
        bound,
        'compact VSS aggregate message coefficient bound',
    );
};

const sumShareVectorsWithCarries = (
    vectors: readonly (readonly number[])[],
    modulus: number,
    ringDegree: number,
): CompactVssAggregateShareSum => {
    const sums = Array.from({ length: ringDegree }, () => 0n);
    vectors.forEach((vector, vectorIndex) => {
        assertResidueVector(
            vector,
            modulus,
            ringDegree,
            `vectors.${vectorIndex}`,
        );
        vector.forEach((coefficient, coefficientIndex) => {
            sums[coefficientIndex] =
                (sums[coefficientIndex] ?? 0n) + BigInt(coefficient);
        });
    });

    const modulusWide = BigInt(modulus);

    return {
        aggregateShareValues: sums.map((sum, coefficientIndex) =>
            safeNumberFromBigInt(
                sum % modulusWide,
                `aggregateShareValues.${String(coefficientIndex)}`,
            ),
        ),
        aggregateCommitmentMessageValues: sums.map((sum, coefficientIndex) =>
            safeNumberFromBigInt(
                sum,
                `aggregateCommitmentMessageValues.${String(coefficientIndex)}`,
            ),
        ),
        aggregateShareCarryValues: sums.map((sum, coefficientIndex) =>
            safeNumberFromBigInt(
                sum / modulusWide,
                `aggregateShareCarryValues.${String(coefficientIndex)}`,
            ),
        ),
    };
};

export const verifyCompactVssAggregateOpeningCredential = (input: {
    readonly credential: CompactVssAggregateThresholdOpeningCredential;
    readonly participantCount: number;
    readonly ringDegree: number;
}): CompactVssAggregateThresholdOpeningCredential => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    const messageCoefficientBound = compactVssAggregateMessageCoefficientBound({
        rnsPrime: input.credential.rnsPrime,
        participantCount: input.participantCount,
    });
    assertResidueVector(
        input.credential.aggregateShareValues,
        input.credential.rnsPrime,
        input.ringDegree,
        'aggregateShareValues',
    );
    assertResidueVector(
        input.credential.aggregateCommitmentMessageValues,
        messageCoefficientBound,
        input.ringDegree,
        'aggregateCommitmentMessageValues',
    );
    assertResidueVector(
        input.credential.aggregateShareCarryValues,
        input.participantCount,
        input.ringDegree,
        'aggregateShareCarryValues',
    );
    input.credential.aggregateShareValues.forEach(
        (aggregateShareValue, coefficientIndex) => {
            const aggregateCommitmentMessageValue =
                input.credential.aggregateCommitmentMessageValues[
                    coefficientIndex
                ];
            const aggregateShareCarryValue =
                input.credential.aggregateShareCarryValues[coefficientIndex];
            if (
                aggregateCommitmentMessageValue === undefined ||
                aggregateShareCarryValue === undefined
            ) {
                throw new Error(
                    'compact VSS aggregate opening credential carry vectors must match ringDegree.',
                );
            }
            if (
                BigInt(aggregateCommitmentMessageValue) !==
                BigInt(aggregateShareValue) +
                    BigInt(aggregateShareCarryValue) *
                        BigInt(input.credential.rnsPrime)
            ) {
                throw new Error(
                    'compact VSS aggregate opening credential carry relation does not match the reduced aggregate share.',
                );
            }
        },
    );

    return input.credential;
};

const sumRandomnessColumns = (
    randomnessByCredential: readonly (readonly (readonly number[])[])[],
    ringDegree: number,
): readonly (readonly number[])[] => {
    const sums = Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        () => Array.from({ length: ringDegree }, () => 0),
    );
    randomnessByCredential.forEach((randomnessByColumn) => {
        assertOpeningRandomness(randomnessByColumn, ringDegree);
        randomnessByColumn.forEach((randomnessColumn, columnIndex) => {
            randomnessColumn.forEach((coefficient, coefficientIndex) => {
                const column = sums[columnIndex];
                if (column === undefined) {
                    throw new Error(
                        'compact VSS randomness column is outside the selected profile.',
                    );
                }
                column[coefficientIndex] =
                    (column[coefficientIndex] ?? 0) + coefficient;
            });
        });
    });

    return sums;
};

const addProductMod = (
    accumulatedValue: bigint,
    leftValue: number,
    rightValue: number,
    modulus: number,
): bigint =>
    (accumulatedValue + BigInt(leftValue) * BigInt(rightValue)) %
    BigInt(modulus);

const coefficientVectorHash = (
    domain: string,
    coefficients: readonly number[],
): string => {
    const bytes = new Uint8Array(coefficients.length * 8);
    coefficients.forEach((coefficient, coefficientIndex) => {
        let value = BigInt(coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(value & 0xffn);
            value >>= 8n;
        }
    });

    return hash512Hex(domain, [bytes]);
};

const randomnessHash = (
    randomnessByColumn: readonly (readonly number[])[],
): string => {
    const flattenedCoefficients = randomnessByColumn.flatMap((column) =>
        column.map((coefficient) => BigInt(coefficient)),
    );
    const bytes = new Uint8Array(flattenedCoefficients.length * 8);
    flattenedCoefficients.forEach((coefficient, coefficientIndex) => {
        let value = BigInt.asUintN(64, coefficient);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            bytes[coefficientIndex * 8 + byteIndex] = Number(value & 0xffn);
            value >>= 8n;
        }
    });

    return hash512Hex(
        'sealed-lattice-compact-vss-commitment/opening-randomness-v1',
        [bytes],
    );
};

const commitmentRoot = (commitment: CompactVssCommitmentValue): ProtocolHash =>
    deriveProtocolHash('SetupCommitmentRoot', commitment);

const compactVssCommitmentModuli = [
    140_737_487_306_753, 140_737_486_716_929, 140_737_486_520_321,
] as const;

const assertStandaloneCompactVssCommitmentBody = (
    commitment: CompactVssCommitmentValue,
    fieldName: string,
): void => {
    assertExactStringField(
        commitment.objectType,
        `${fieldName}.objectType`,
        'CompactVssCommitment',
    );
    if (commitment.objectVersion !== 1) {
        throw new TypeError(`${fieldName}.objectVersion is not supported.`);
    }
    assertExactStringField(
        commitment.profileId,
        `${fieldName}.profileId`,
        compactVssCommitmentProfileId,
    );
    assertExactStringField(
        commitment.developmentScope,
        `${fieldName}.developmentScope`,
        compactVssCommitmentDevelopmentScope,
    );
    assertCompactVssCommitmentRole(
        commitment.commitmentRole,
        `${fieldName}.commitmentRole`,
    );
    assertProtocolHash(
        commitment.commitmentContextHash,
        `${fieldName}.commitmentContextHash`,
    );
    assertProtocolHash(
        commitment.publicMatrixSeedHash,
        `${fieldName}.publicMatrixSeedHash`,
    );
    assertNonNegativeSafeInteger(
        commitment.rnsLimbIndex,
        `${fieldName}.rnsLimbIndex`,
    );
    assertPositiveSafeInteger(commitment.rnsPrime, `${fieldName}.rnsPrime`);
    assertPositiveSafeInteger(commitment.ringDegree, `${fieldName}.ringDegree`);
    if (
        commitment.outputCoordinateCount !==
            compactVssCommitmentOutputCoordinateCount ||
        commitment.randomnessColumnCount !==
            compactVssCommitmentRandomnessColumnCount
    ) {
        throw new Error(
            `${fieldName} compact commitment dimensions do not match the profile.`,
        );
    }
    assertHash512Hex(
        commitment.messageVectorHash512,
        `${fieldName}.messageVectorHash512`,
    );
    assertHash512Hex(
        commitment.openingRandomnessHash512,
        `${fieldName}.openingRandomnessHash512`,
    );
    if (
        commitment.commitmentLimbs.length !==
        compactVssCommitmentModulusLimbIndices.length
    ) {
        throw new Error(
            `${fieldName}.commitmentLimbs must cover the compact commitment modulus limbs.`,
        );
    }
    commitment.commitmentLimbs.forEach((limb, limbIndex) => {
        const expectedCommitmentModulusIndex =
            compactVssCommitmentModulusLimbIndices[limbIndex];
        if (
            expectedCommitmentModulusIndex === undefined ||
            limb.commitmentModulusIndex !== expectedCommitmentModulusIndex
        ) {
            throw new Error(
                `${fieldName}.commitmentLimbs.${String(limbIndex)} commitment modulus index is not canonical.`,
            );
        }
        const expectedModulus =
            compactVssCommitmentModuli[expectedCommitmentModulusIndex];
        if (expectedModulus === undefined) {
            throw new Error(
                `${fieldName}.commitmentLimbs.${String(limbIndex)} modulus index is outside the selected profile.`,
            );
        }
        if (limb.modulus !== expectedModulus) {
            throw new Error(
                `${fieldName}.commitmentLimbs.${String(limbIndex)} modulus does not match the profile.`,
            );
        }
        if (
            limb.coordinates.length !==
            compactVssCommitmentOutputCoordinateCount
        ) {
            throw new Error(
                `${fieldName}.commitmentLimbs.${String(limbIndex)} coordinates length must match the compact output count.`,
            );
        }
        limb.coordinates.forEach((coordinate, coordinateIndex) => {
            if (
                !Number.isSafeInteger(coordinate) ||
                coordinate < 0 ||
                coordinate >= expectedModulus
            ) {
                throw new TypeError(
                    `${fieldName}.commitmentLimbs.${String(limbIndex)}.coordinates.${String(coordinateIndex)} must be a residue below the commitment modulus.`,
                );
            }
        });
    });
};

const assertCompactVssCommitmentBody = (input: {
    readonly commitment: CompactVssCommitmentValue;
    readonly expectedCommitmentRole: CompactVssCommitmentRole;
    readonly expectedCommitmentRoot: ProtocolHash;
    readonly expectedPublicMatrixSeedHash: ProtocolHash;
    readonly expectedRnsLimbIndex: number;
    readonly expectedRnsPrime: number;
    readonly expectedMessageVectorHash512?: string;
    readonly fieldName: string;
}): void => {
    const { commitment } = input;
    assertStandaloneCompactVssCommitmentBody(commitment, input.fieldName);
    assertExactStringField(
        commitment.commitmentRole,
        `${input.fieldName}.commitmentRole`,
        input.expectedCommitmentRole,
    );
    if (
        commitment.publicMatrixSeedHash !== input.expectedPublicMatrixSeedHash
    ) {
        throw new Error(
            `${input.fieldName}.publicMatrixSeedHash must match the containing commitment set.`,
        );
    }
    if (
        commitment.rnsLimbIndex !== input.expectedRnsLimbIndex ||
        commitment.rnsPrime !== input.expectedRnsPrime
    ) {
        throw new Error(
            `${input.fieldName} source limb metadata must match the containing record.`,
        );
    }
    if (
        input.expectedMessageVectorHash512 !== undefined &&
        commitment.messageVectorHash512 !== input.expectedMessageVectorHash512
    ) {
        throw new Error(
            `${input.fieldName}.messageVectorHash512 must match the containing record.`,
        );
    }
    if (commitmentRoot(commitment) !== input.expectedCommitmentRoot) {
        throw new Error(
            `${input.fieldName} canonical root must match the containing record.`,
        );
    }
};

const openingRoot = (input: CompactVssCommitmentOpeningInput): ProtocolHash =>
    deriveProtocolHash('SetupCommitmentRoot', {
        objectType: 'CompactVssCommitmentOpening',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        commitmentRole: input.commitmentRole,
        commitmentContext: input.commitmentContext,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        rnsLimbIndex: input.rnsLimbIndex,
        rnsPrime: input.rnsPrime,
        ringDegree: input.ringDegree,
        messageVectorHash512: coefficientVectorHash(
            'sealed-lattice-compact-vss-commitment/message-vector-v1',
            input.messageCoefficients,
        ),
        openingRandomnessHash512: randomnessHash(input.randomnessByColumn),
    });

export const compactVssEncodedCommitmentByteLength = (): number =>
    compactVssCommitmentModulusLimbIndices.length *
    compactVssCommitmentOutputCoordinateCount *
    8;

export const encodeCompactVssCommitmentBody = (
    commitment: CompactVssCommitmentValue,
): Uint8Array => {
    assertStandaloneCompactVssCommitmentBody(
        commitment,
        'compact VSS commitment',
    );
    const commitmentBodyBytes = new Uint8Array(
        compactVssEncodedCommitmentByteLength(),
    );
    let offset = 0;
    commitment.commitmentLimbs.forEach((limb) => {
        limb.coordinates.forEach((coordinate) => {
            writeLittleEndianU64(commitmentBodyBytes, offset, coordinate);
            offset += 8;
        });
    });

    return commitmentBodyBytes;
};

export const decodeCompactVssCommitmentBody = (input: {
    readonly metadata: CompactVssCommitmentBodyMetadata;
    readonly commitmentBodyBytes: Uint8Array;
}): CompactVssCommitmentValue => {
    const { metadata, commitmentBodyBytes } = input;
    assertCompactVssCommitmentRole(
        metadata.commitmentRole,
        'metadata.commitmentRole',
    );
    assertProtocolHash(
        metadata.commitmentContextHash,
        'metadata.commitmentContextHash',
    );
    assertProtocolHash(
        metadata.publicMatrixSeedHash,
        'metadata.publicMatrixSeedHash',
    );
    assertNonNegativeSafeInteger(
        metadata.rnsLimbIndex,
        'metadata.rnsLimbIndex',
    );
    assertPositiveSafeInteger(metadata.rnsPrime, 'metadata.rnsPrime');
    assertPositiveSafeInteger(metadata.ringDegree, 'metadata.ringDegree');
    assertHash512Hex(
        metadata.messageVectorHash512,
        'metadata.messageVectorHash512',
    );
    assertHash512Hex(
        metadata.openingRandomnessHash512,
        'metadata.openingRandomnessHash512',
    );
    if (!(commitmentBodyBytes instanceof Uint8Array)) {
        throw new TypeError(
            'compact VSS encoded commitment body must be bytes.',
        );
    }
    if (
        commitmentBodyBytes.byteLength !==
        compactVssEncodedCommitmentByteLength()
    ) {
        throw new Error(
            'compact VSS encoded commitment body length must match the compact commitment profile.',
        );
    }

    let offset = 0;
    const commitmentLimbs = compactVssCommitmentModulusLimbIndices.map(
        (commitmentModulusIndex): CompactVssCommitmentLimb => {
            const modulus = compactVssCommitmentModuli[commitmentModulusIndex];
            if (modulus === undefined) {
                throw new Error(
                    'compact VSS commitment modulus index is outside the selected profile.',
                );
            }
            const coordinates = Array.from(
                { length: compactVssCommitmentOutputCoordinateCount },
                (_unused, coordinateIndex) => {
                    const coordinateWide = littleEndianU64(
                        commitmentBodyBytes,
                        offset,
                    );
                    offset += 8;
                    if (
                        coordinateWide > BigInt(Number.MAX_SAFE_INTEGER) ||
                        coordinateWide >= BigInt(modulus)
                    ) {
                        throw new TypeError(
                            `compact VSS encoded commitment body coordinate ${String(coordinateIndex)} must be a residue below the commitment modulus.`,
                        );
                    }

                    return Number(coordinateWide);
                },
            );

            return {
                commitmentModulusIndex,
                modulus,
                coordinates,
            };
        },
    );

    return {
        objectType: 'CompactVssCommitment',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        commitmentRole: metadata.commitmentRole,
        commitmentContextHash: metadata.commitmentContextHash,
        publicMatrixSeedHash: metadata.publicMatrixSeedHash,
        rnsLimbIndex: metadata.rnsLimbIndex,
        rnsPrime: metadata.rnsPrime,
        ringDegree: metadata.ringDegree,
        outputCoordinateCount: compactVssCommitmentOutputCoordinateCount,
        randomnessColumnCount: compactVssCommitmentRandomnessColumnCount,
        messageVectorHash512: metadata.messageVectorHash512,
        openingRandomnessHash512: metadata.openingRandomnessHash512,
        commitmentLimbs,
    };
};

const compactVssShamirScalarL1Amplification = (
    maximumTrusteePoint: number,
    thresholdDegree: number,
): number => {
    assertPositiveSafeInteger(maximumTrusteePoint, 'maximumTrusteePoint');
    assertPositiveSafeInteger(thresholdDegree, 'thresholdDegree');
    let sum = 0n;
    let pointPower = 1n;
    const maximumTrusteePointWide = BigInt(maximumTrusteePoint);
    for (
        let coefficientIndex = 0;
        coefficientIndex < thresholdDegree;
        coefficientIndex += 1
    ) {
        sum += pointPower;
        pointPower *= maximumTrusteePointWide;
    }
    const result = Number(sum);
    if (!Number.isSafeInteger(result)) {
        throw new RangeError(
            'compact VSS Shamir scalar L1 amplification exceeds safe integer range.',
        );
    }

    return result;
};

const acceptedCommitmentModulus = (commitmentModulusIndex: number): number => {
    const modulus = compactVssCommitmentModuli[commitmentModulusIndex];
    if (modulus === undefined) {
        throw new Error(
            'compact VSS commitment modulus index is outside the selected profile.',
        );
    }

    return modulus;
};

export const computeCompactVssCommitmentFromOpening = (
    input: CompactVssCommitmentOpeningInput,
): CompactVssCommitmentComputation => {
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertNonNegativeSafeInteger(input.rnsLimbIndex, 'rnsLimbIndex');
    assertPositiveSafeInteger(input.rnsPrime, 'rnsPrime');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    const messageCoefficientBound =
        input.messageCoefficientBound ?? input.rnsPrime;
    assertPositiveSafeInteger(
        messageCoefficientBound,
        'messageCoefficientBound',
    );
    assertResidueVector(
        input.messageCoefficients,
        messageCoefficientBound,
        input.ringDegree,
        'messageCoefficients',
    );
    assertOpeningRandomness(input.randomnessByColumn, input.ringDegree);

    const commitmentContextHash = deriveProtocolHash('SetupCommitmentRoot', {
        objectType: 'CompactVssCommitmentContext',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        commitmentRole: input.commitmentRole,
        commitmentContext: input.commitmentContext,
    });
    const commitmentLimbs = compactVssCommitmentModulusLimbIndices.map(
        (commitmentModulusIndex): CompactVssCommitmentLimb => {
            const modulus = acceptedCommitmentModulus(commitmentModulusIndex);
            const coordinates = Array.from(
                { length: compactVssCommitmentOutputCoordinateCount },
                (_unused, outputCoordinateIndex) => {
                    let accumulator = 0n;
                    compactProjectionTerms({
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        rnsLimbIndex: input.rnsLimbIndex,
                        commitmentModulusIndex,
                        outputCoordinateIndex,
                        inputColumn: 'message',
                        ringDegree: input.ringDegree,
                        modulus,
                    }).forEach(({ ringCoefficientIndex, matrixResidue }) => {
                        accumulator = addProductMod(
                            accumulator,
                            (input.messageCoefficients[ringCoefficientIndex] ??
                                0) % modulus,
                            matrixResidue,
                            modulus,
                        );
                    });
                    input.randomnessByColumn.forEach(
                        (randomnessColumn, randomnessColumnIndex) => {
                            const inputColumn = `randomness:${String(randomnessColumnIndex)}`;
                            compactProjectionTerms({
                                publicMatrixSeedHash:
                                    input.publicMatrixSeedHash,
                                rnsLimbIndex: input.rnsLimbIndex,
                                commitmentModulusIndex,
                                outputCoordinateIndex,
                                inputColumn,
                                ringDegree: input.ringDegree,
                                modulus,
                            }).forEach(
                                ({ ringCoefficientIndex, matrixResidue }) => {
                                    const randomnessCoefficient =
                                        randomnessColumn[
                                            ringCoefficientIndex
                                        ] ?? 0;
                                    accumulator = addProductMod(
                                        accumulator,
                                        signedIntegerToResidue(
                                            randomnessCoefficient,
                                            modulus,
                                        ),
                                        matrixResidue,
                                        modulus,
                                    );
                                },
                            );
                        },
                    );

                    return Number(accumulator);
                },
            );

            return {
                commitmentModulusIndex,
                modulus,
                coordinates,
            };
        },
    );
    const commitment = {
        objectType: 'CompactVssCommitment',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        commitmentRole: input.commitmentRole,
        commitmentContextHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        rnsLimbIndex: input.rnsLimbIndex,
        rnsPrime: input.rnsPrime,
        ringDegree: input.ringDegree,
        outputCoordinateCount: compactVssCommitmentOutputCoordinateCount,
        randomnessColumnCount: compactVssCommitmentRandomnessColumnCount,
        messageVectorHash512: coefficientVectorHash(
            'sealed-lattice-compact-vss-commitment/message-vector-v1',
            input.messageCoefficients,
        ),
        openingRandomnessHash512: randomnessHash(input.randomnessByColumn),
        commitmentLimbs,
    } satisfies CompactVssCommitmentValue;

    return {
        ok: true,
        operation: 'computeCompactVssCommitmentFromOpening',
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitment,
        commitmentRoot: commitmentRoot(commitment),
        commitmentContextHash,
        openingRoot: openingRoot(input),
        encodedCommitmentByteLength: compactVssEncodedCommitmentByteLength(),
    };
};

export const verifyCompactVssCommitmentOpening = (input: {
    readonly opening: CompactVssCommitmentOpeningInput;
    readonly expectedCommitmentRoot: ProtocolHash;
}): CompactVssCommitmentOpeningVerification => {
    const computation = computeCompactVssCommitmentFromOpening(input.opening);
    if (computation.commitmentRoot !== input.expectedCommitmentRoot) {
        throw new Error(
            'compact VSS commitment opening does not match the expected commitment root.',
        );
    }

    return {
        ok: true,
        operation: 'verifyCompactVssCommitmentOpening',
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentRoot: computation.commitmentRoot,
        openingRoot: computation.openingRoot,
    };
};

export const createCompactVssCoefficientCommitmentSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
    readonly coefficientOpeningRandomness: CompactVssCoefficientOpeningRandomnessProvider;
}): CompactVssCoefficientCommitmentSet => {
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) =>
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        ),
    );

    const sourceTrusteeRecords = sortedSourceTrusteeOpeningStates({
        participantCount: input.participantCount,
        sourceTrusteeOpeningStates: input.sourceTrusteeOpeningStates,
    }).map((sourceTrusteeOpeningState) => {
        const openingsByCoordinate = new Map(
            sourceTrusteeOpeningState.coefficientOpenings.map((opening) => [
                openingCoordinateKey(
                    opening.rnsLimbIndex,
                    opening.shamirCoefficientIndex,
                ),
                opening,
            ]),
        );
        const coefficientCommitments: CompactVssCoefficientCommitmentRecord[] =
            [];
        input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
            for (
                let shamirCoefficientIndex = 0;
                shamirCoefficientIndex < input.thresholdDegree;
                shamirCoefficientIndex += 1
            ) {
                const coefficientOpening = openingsByCoordinate.get(
                    openingCoordinateKey(rnsLimbIndex, shamirCoefficientIndex),
                );
                if (coefficientOpening === undefined) {
                    throw new Error(
                        'source trustee coefficient openings must cover every compact VSS coefficient coordinate.',
                    );
                }
                if (coefficientOpening.rnsPrime !== rnsPrime) {
                    throw new Error(
                        'source trustee coefficient opening RNS primes must match qSharePrimes.',
                    );
                }
                const randomnessByColumn = input.coefficientOpeningRandomness({
                    trusteeIdentity:
                        sourceTrusteeOpeningState.sourceTrusteeIdentity,
                    trusteeRosterPosition:
                        sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex,
                    ringDegree: input.ringDegree,
                });
                const commitmentContext = {
                    objectType: 'CompactVssCoefficientCommitmentContext',
                    objectVersion: 1,
                    ...setupContextFields(input.setupContext),
                    sourceTrusteeIdentity:
                        sourceTrusteeOpeningState.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex,
                };
                const commitment = computeCompactVssCommitmentFromOpening({
                    commitmentRole: 'coefficient',
                    commitmentContext,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    rnsLimbIndex,
                    rnsPrime,
                    ringDegree: input.ringDegree,
                    messageCoefficients: coefficientOpening.coefficientMessage,
                    randomnessByColumn,
                });
                coefficientCommitments.push({
                    objectType: 'CompactVssCoefficientCommitment',
                    objectVersion: 1,
                    profileId: compactVssCommitmentProfileId,
                    developmentScope: compactVssCommitmentDevelopmentScope,
                    sourceTrusteeIdentity:
                        sourceTrusteeOpeningState.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex,
                    coefficientCommitmentRoot: commitment.commitmentRoot,
                    coefficientVectorHash512:
                        commitment.commitment.messageVectorHash512,
                    commitment: commitment.commitment,
                });
            }
        });

        const sourceRecordWithoutRoot = {
            objectType: 'CompactVssSourceCoefficientCommitments',
            objectVersion: 1,
            profileId: compactVssCommitmentProfileId,
            developmentScope: compactVssCommitmentDevelopmentScope,
            sourceTrusteeIdentity:
                sourceTrusteeOpeningState.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
            publicMatrixSeedHash: input.publicMatrixSeedHash,
            coefficientCommitments,
        } as const satisfies Omit<
            CompactVssSourceCoefficientCommitments,
            'sourceCoefficientCommitmentRoot'
        >;

        return {
            ...sourceRecordWithoutRoot,
            sourceCoefficientCommitmentRoot: deriveProtocolHash(
                'VssCoefficientCommitmentRoot',
                sourceRecordWithoutRoot,
            ),
        };
    });

    const setWithoutRoot = {
        objectType: 'CompactVssCoefficientCommitmentSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        thresholdDegree: input.thresholdDegree,
        ringDegree: input.ringDegree,
        sourceTrusteeRecords,
    } as const satisfies Omit<
        CompactVssCoefficientCommitmentSet,
        'coefficientCommitmentRoot'
    >;

    return {
        ...setWithoutRoot,
        coefficientCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
            setWithoutRoot,
        ),
    };
};

export const verifyCompactVssCoefficientCommitmentSet = (input: {
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
}): CompactVssCoefficientCommitmentSet => {
    const coefficientCommitmentSet = input.coefficientCommitmentSet;
    assertExactStringField(
        coefficientCommitmentSet.objectType,
        'compact VSS coefficient commitment set objectType',
        'CompactVssCoefficientCommitmentSet',
    );
    if (coefficientCommitmentSet.objectVersion !== 1) {
        throw new TypeError(
            'compact VSS coefficient commitment set objectVersion is not supported.',
        );
    }
    assertExactStringField(
        coefficientCommitmentSet.setupProfileId,
        'compact VSS coefficient commitment set setupProfileId',
        'CollectiveBgvSetup-v1',
    );
    assertExactStringField(
        coefficientCommitmentSet.profileId,
        'compact VSS coefficient commitment set profileId',
        compactVssCommitmentProfileId,
    );
    assertExactStringField(
        coefficientCommitmentSet.developmentScope,
        'compact VSS coefficient commitment set developmentScope',
        compactVssCommitmentDevelopmentScope,
    );
    assertProtocolHash(
        coefficientCommitmentSet.publicMatrixSeedHash,
        'compact VSS coefficient commitment set publicMatrixSeedHash',
    );
    assertPositiveSafeInteger(
        coefficientCommitmentSet.participantCount,
        'compact VSS coefficient commitment set participantCount',
    );
    assertPositiveSafeInteger(
        coefficientCommitmentSet.rnsLimbCount,
        'compact VSS coefficient commitment set rnsLimbCount',
    );
    assertPositiveSafeInteger(
        coefficientCommitmentSet.thresholdDegree,
        'compact VSS coefficient commitment set thresholdDegree',
    );
    assertPositiveSafeInteger(
        coefficientCommitmentSet.ringDegree,
        'compact VSS coefficient commitment set ringDegree',
    );
    if (
        coefficientCommitmentSet.sourceTrusteeRecords.length !==
        coefficientCommitmentSet.participantCount
    ) {
        throw new Error(
            'compact VSS coefficient commitment set must contain one source record per participant.',
        );
    }
    coefficientCommitmentSet.sourceTrusteeRecords.forEach(
        (sourceTrusteeRecord, expectedRosterPosition) => {
            assertExactStringField(
                sourceTrusteeRecord.objectType,
                'compact VSS source coefficient commitments objectType',
                'CompactVssSourceCoefficientCommitments',
            );
            if (sourceTrusteeRecord.objectVersion !== 1) {
                throw new TypeError(
                    'compact VSS source coefficient commitments objectVersion is not supported.',
                );
            }
            assertExactStringField(
                sourceTrusteeRecord.profileId,
                'compact VSS source coefficient commitments profileId',
                compactVssCommitmentProfileId,
            );
            assertExactStringField(
                sourceTrusteeRecord.developmentScope,
                'compact VSS source coefficient commitments developmentScope',
                compactVssCommitmentDevelopmentScope,
            );
            assertNonEmptyString(
                sourceTrusteeRecord.sourceTrusteeIdentity,
                'compact VSS source coefficient commitments sourceTrusteeIdentity',
            );
            if (
                sourceTrusteeRecord.sourceTrusteeRosterPosition !==
                expectedRosterPosition
            ) {
                throw new Error(
                    'compact VSS source coefficient commitment roster positions must be contiguous from zero.',
                );
            }
            if (
                sourceTrusteeRecord.publicMatrixSeedHash !==
                coefficientCommitmentSet.publicMatrixSeedHash
            ) {
                throw new Error(
                    'compact VSS source coefficient commitments must use the set public matrix seed hash.',
                );
            }
            const expectedCoefficientCount =
                coefficientCommitmentSet.rnsLimbCount *
                coefficientCommitmentSet.thresholdDegree;
            if (
                sourceTrusteeRecord.coefficientCommitments.length !==
                expectedCoefficientCount
            ) {
                throw new Error(
                    'compact VSS source coefficient commitments must cover every RNS limb and Shamir coefficient.',
                );
            }
            sourceTrusteeRecord.coefficientCommitments.forEach(
                (coefficientCommitment, coefficientRecordIndex) => {
                    const expectedRnsLimbIndex = Math.floor(
                        coefficientRecordIndex /
                            coefficientCommitmentSet.thresholdDegree,
                    );
                    const expectedShamirCoefficientIndex =
                        coefficientRecordIndex %
                        coefficientCommitmentSet.thresholdDegree;
                    assertExactStringField(
                        coefficientCommitment.objectType,
                        'compact VSS coefficient commitment objectType',
                        'CompactVssCoefficientCommitment',
                    );
                    if (coefficientCommitment.objectVersion !== 1) {
                        throw new TypeError(
                            'compact VSS coefficient commitment objectVersion is not supported.',
                        );
                    }
                    assertExactStringField(
                        coefficientCommitment.profileId,
                        'compact VSS coefficient commitment profileId',
                        compactVssCommitmentProfileId,
                    );
                    assertExactStringField(
                        coefficientCommitment.developmentScope,
                        'compact VSS coefficient commitment developmentScope',
                        compactVssCommitmentDevelopmentScope,
                    );
                    if (
                        coefficientCommitment.sourceTrusteeIdentity !==
                            sourceTrusteeRecord.sourceTrusteeIdentity ||
                        coefficientCommitment.sourceTrusteeRosterPosition !==
                            sourceTrusteeRecord.sourceTrusteeRosterPosition
                    ) {
                        throw new Error(
                            'compact VSS coefficient commitment trustee binding must match its source record.',
                        );
                    }
                    if (
                        coefficientCommitment.publicMatrixSeedHash !==
                        coefficientCommitmentSet.publicMatrixSeedHash
                    ) {
                        throw new Error(
                            'compact VSS coefficient commitment must use the set public matrix seed hash.',
                        );
                    }
                    if (
                        coefficientCommitment.rnsLimbIndex !==
                            expectedRnsLimbIndex ||
                        coefficientCommitment.shamirCoefficientIndex !==
                            expectedShamirCoefficientIndex
                    ) {
                        throw new Error(
                            'compact VSS coefficient commitment coordinates must be canonical.',
                        );
                    }
                    assertPositiveSafeInteger(
                        coefficientCommitment.rnsPrime,
                        'compact VSS coefficient commitment rnsPrime',
                    );
                    assertProtocolHash(
                        coefficientCommitment.coefficientCommitmentRoot,
                        'compact VSS coefficient commitment coefficientCommitmentRoot',
                    );
                    assertHash512Hex(
                        coefficientCommitment.coefficientVectorHash512,
                        'compact VSS coefficient commitment coefficientVectorHash512',
                    );
                    assertCompactVssCommitmentBody({
                        commitment: coefficientCommitment.commitment,
                        expectedCommitmentRole: 'coefficient',
                        expectedCommitmentRoot:
                            coefficientCommitment.coefficientCommitmentRoot,
                        expectedPublicMatrixSeedHash:
                            coefficientCommitmentSet.publicMatrixSeedHash,
                        expectedRnsLimbIndex,
                        expectedRnsPrime: coefficientCommitment.rnsPrime,
                        expectedMessageVectorHash512:
                            coefficientCommitment.coefficientVectorHash512,
                        fieldName:
                            'compact VSS coefficient commitment commitment',
                    });
                },
            );
            assertProtocolHash(
                sourceTrusteeRecord.sourceCoefficientCommitmentRoot,
                'compact VSS source coefficient commitments sourceCoefficientCommitmentRoot',
            );
            const {
                sourceCoefficientCommitmentRoot:
                    _sourceCoefficientCommitmentRoot,
                ...sourceRecordWithoutRoot
            } = sourceTrusteeRecord;
            const expectedSourceRoot = deriveProtocolHash(
                'VssCoefficientCommitmentRoot',
                sourceRecordWithoutRoot,
            );
            if (
                sourceTrusteeRecord.sourceCoefficientCommitmentRoot !==
                expectedSourceRoot
            ) {
                throw new Error(
                    'compact VSS source coefficient commitment root does not match its records.',
                );
            }
        },
    );
    assertProtocolHash(
        coefficientCommitmentSet.coefficientCommitmentRoot,
        'compact VSS coefficient commitment set coefficientCommitmentRoot',
    );
    const {
        coefficientCommitmentRoot: _coefficientCommitmentRoot,
        ...setWithoutRoot
    } = coefficientCommitmentSet;
    const expectedSetRoot = deriveProtocolHash(
        'VssCoefficientCommitmentRoot',
        setWithoutRoot,
    );
    if (
        coefficientCommitmentSet.coefficientCommitmentRoot !== expectedSetRoot
    ) {
        throw new Error(
            'compact VSS coefficient commitment set root does not match its source records.',
        );
    }

    return coefficientCommitmentSet;
};

export const createCompactVssRecipientShareCommitmentBundle = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
    readonly recipientTrustees: readonly CompactVssTrusteeReference[];
    readonly shareOpeningRandomness: CompactVssShareOpeningRandomnessProvider;
}): CompactVssRecipientShareCommitmentBundle => {
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    input.qSharePrimes.forEach((qSharePrime, rnsLimbIndex) =>
        assertPositiveSafeInteger(
            qSharePrime,
            `qSharePrimes.${String(rnsLimbIndex)}`,
        ),
    );
    const sourceTrusteeRecords: CompactVssSourceRecipientShareCommitments[] =
        [];
    const recipientShareOpeningCredentials: CompactVssRecipientShareOpeningCredential[] =
        [];

    sortedSourceTrusteeOpeningStates({
        participantCount: input.participantCount,
        sourceTrusteeOpeningStates: input.sourceTrusteeOpeningStates,
    }).forEach((sourceTrusteeOpeningState) => {
        const sourceRecordCommitments: CompactVssRecipientShareCommitmentRecord[] =
            [];
        input.recipientTrustees
            .slice()
            .sort(
                (leftTrustee, rightTrustee) =>
                    leftTrustee.trusteeRosterPosition -
                    rightTrustee.trusteeRosterPosition,
            )
            .forEach((recipientTrustee) => {
                const recipientTrusteePoint =
                    recipientTrustee.trusteeRosterPosition + 1;
                input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
                    const shareValues = evaluateSourceShareForRecipient({
                        sourceTrusteeOpeningState,
                        recipientTrusteePoint,
                        rnsLimbIndex,
                        rnsPrime,
                        thresholdDegree: input.thresholdDegree,
                        ringDegree: input.ringDegree,
                    });
                    const randomnessByColumn = input.shareOpeningRandomness({
                        trusteeIdentity:
                            sourceTrusteeOpeningState.sourceTrusteeIdentity,
                        trusteeRosterPosition:
                            sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                        recipientIdentity: recipientTrustee.trusteeIdentity,
                        recipientRosterPosition:
                            recipientTrustee.trusteeRosterPosition,
                        rnsLimbIndex,
                        rnsPrime,
                        ringDegree: input.ringDegree,
                    });
                    const commitmentContext = {
                        objectType: 'CompactVssRecipientShareCommitmentContext',
                        objectVersion: 1,
                        ...setupContextFields(input.setupContext),
                        sourceTrusteeIdentity:
                            sourceTrusteeOpeningState.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                        recipientIdentity: recipientTrustee.trusteeIdentity,
                        recipientRosterPosition:
                            recipientTrustee.trusteeRosterPosition,
                        rnsLimbIndex,
                        rnsPrime,
                    };
                    const commitment = computeCompactVssCommitmentFromOpening({
                        commitmentRole: 'recipient-share',
                        commitmentContext,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        rnsLimbIndex,
                        rnsPrime,
                        ringDegree: input.ringDegree,
                        messageCoefficients: shareValues,
                        randomnessByColumn,
                    });
                    const recordWithoutRoot = {
                        objectType: 'CompactVssRecipientShareCommitment',
                        objectVersion: 1,
                        profileId: compactVssCommitmentProfileId,
                        developmentScope: compactVssCommitmentDevelopmentScope,
                        sourceTrusteeIdentity:
                            sourceTrusteeOpeningState.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                        recipientIdentity: recipientTrustee.trusteeIdentity,
                        recipientRosterPosition:
                            recipientTrustee.trusteeRosterPosition,
                        recipientTrusteePoint,
                        rnsLimbIndex,
                        rnsPrime,
                        shareCommitmentRoot: commitment.commitmentRoot,
                        shareOpeningRoot: commitment.openingRoot,
                        shareVectorHash512:
                            commitment.commitment.messageVectorHash512,
                        commitment: commitment.commitment,
                    } satisfies CompactVssRecipientShareCommitmentRecord;
                    sourceRecordCommitments.push(recordWithoutRoot);
                    recipientShareOpeningCredentials.push({
                        objectType: 'CompactVssRecipientShareOpeningCredential',
                        objectVersion: 1,
                        profileId: compactVssCommitmentProfileId,
                        sourceTrusteeIdentity:
                            sourceTrusteeOpeningState.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                        recipientIdentity: recipientTrustee.trusteeIdentity,
                        recipientRosterPosition:
                            recipientTrustee.trusteeRosterPosition,
                        recipientTrusteePoint,
                        rnsLimbIndex,
                        rnsPrime,
                        shareValues,
                        randomnessByColumn,
                        shareCommitmentRoot: commitment.commitmentRoot,
                        shareOpeningRoot: commitment.openingRoot,
                    });
                });
            });
        const sourceRecordWithoutRoot = {
            objectType: 'CompactVssSourceRecipientShareCommitments',
            objectVersion: 1,
            profileId: compactVssCommitmentProfileId,
            developmentScope: compactVssCommitmentDevelopmentScope,
            sourceTrusteeIdentity:
                sourceTrusteeOpeningState.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
            recipientShareCommitments: sourceRecordCommitments,
        } as const satisfies Omit<
            CompactVssSourceRecipientShareCommitments,
            'sourceRecipientShareCommitmentRoot'
        >;
        sourceTrusteeRecords.push({
            ...sourceRecordWithoutRoot,
            sourceRecipientShareCommitmentRoot: deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                sourceRecordWithoutRoot,
            ),
        });
    });

    const setWithoutRoot = {
        objectType: 'CompactVssRecipientShareCommitmentSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        sourceTrusteeRecords,
    } as const satisfies Omit<
        CompactVssRecipientShareCommitmentSet,
        'recipientShareCommitmentRoot'
    >;

    return {
        recipientShareCommitmentSet: {
            ...setWithoutRoot,
            recipientShareCommitmentRoot: deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                setWithoutRoot,
            ),
        },
        recipientShareOpeningCredentials,
    };
};

export const verifyCompactVssRecipientShareCommitmentSet = (input: {
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
}): CompactVssRecipientShareCommitmentSet => {
    const recipientShareCommitmentSet = input.recipientShareCommitmentSet;
    assertExactStringField(
        recipientShareCommitmentSet.objectType,
        'compact VSS recipient-share commitment set objectType',
        'CompactVssRecipientShareCommitmentSet',
    );
    if (recipientShareCommitmentSet.objectVersion !== 1) {
        throw new TypeError(
            'compact VSS recipient-share commitment set objectVersion is not supported.',
        );
    }
    assertExactStringField(
        recipientShareCommitmentSet.setupProfileId,
        'compact VSS recipient-share commitment set setupProfileId',
        'CollectiveBgvSetup-v1',
    );
    assertExactStringField(
        recipientShareCommitmentSet.profileId,
        'compact VSS recipient-share commitment set profileId',
        compactVssCommitmentProfileId,
    );
    assertExactStringField(
        recipientShareCommitmentSet.developmentScope,
        'compact VSS recipient-share commitment set developmentScope',
        compactVssCommitmentDevelopmentScope,
    );
    assertProtocolHash(
        recipientShareCommitmentSet.publicMatrixSeedHash,
        'compact VSS recipient-share commitment set publicMatrixSeedHash',
    );
    assertPositiveSafeInteger(
        recipientShareCommitmentSet.participantCount,
        'compact VSS recipient-share commitment set participantCount',
    );
    assertPositiveSafeInteger(
        recipientShareCommitmentSet.rnsLimbCount,
        'compact VSS recipient-share commitment set rnsLimbCount',
    );
    assertPositiveSafeInteger(
        recipientShareCommitmentSet.ringDegree,
        'compact VSS recipient-share commitment set ringDegree',
    );
    if (
        recipientShareCommitmentSet.sourceTrusteeRecords.length !==
        recipientShareCommitmentSet.participantCount
    ) {
        throw new Error(
            'compact VSS recipient-share commitment set must contain one source record per participant.',
        );
    }
    recipientShareCommitmentSet.sourceTrusteeRecords.forEach(
        (sourceTrusteeRecord, expectedSourceRosterPosition) => {
            assertExactStringField(
                sourceTrusteeRecord.objectType,
                'compact VSS source recipient-share commitments objectType',
                'CompactVssSourceRecipientShareCommitments',
            );
            if (sourceTrusteeRecord.objectVersion !== 1) {
                throw new TypeError(
                    'compact VSS source recipient-share commitments objectVersion is not supported.',
                );
            }
            assertExactStringField(
                sourceTrusteeRecord.profileId,
                'compact VSS source recipient-share commitments profileId',
                compactVssCommitmentProfileId,
            );
            assertExactStringField(
                sourceTrusteeRecord.developmentScope,
                'compact VSS source recipient-share commitments developmentScope',
                compactVssCommitmentDevelopmentScope,
            );
            assertNonEmptyString(
                sourceTrusteeRecord.sourceTrusteeIdentity,
                'compact VSS source recipient-share commitments sourceTrusteeIdentity',
            );
            if (
                sourceTrusteeRecord.sourceTrusteeRosterPosition !==
                expectedSourceRosterPosition
            ) {
                throw new Error(
                    'compact VSS source recipient-share commitment roster positions must be contiguous from zero.',
                );
            }
            const expectedRecipientShareCount =
                recipientShareCommitmentSet.participantCount *
                recipientShareCommitmentSet.rnsLimbCount;
            if (
                sourceTrusteeRecord.recipientShareCommitments.length !==
                expectedRecipientShareCount
            ) {
                throw new Error(
                    'compact VSS source recipient-share commitments must cover every recipient and RNS limb.',
                );
            }
            sourceTrusteeRecord.recipientShareCommitments.forEach(
                (recipientShareCommitment, recipientShareRecordIndex) => {
                    const expectedRecipientRosterPosition = Math.floor(
                        recipientShareRecordIndex /
                            recipientShareCommitmentSet.rnsLimbCount,
                    );
                    const expectedRnsLimbIndex =
                        recipientShareRecordIndex %
                        recipientShareCommitmentSet.rnsLimbCount;
                    assertExactStringField(
                        recipientShareCommitment.objectType,
                        'compact VSS recipient-share commitment objectType',
                        'CompactVssRecipientShareCommitment',
                    );
                    if (recipientShareCommitment.objectVersion !== 1) {
                        throw new TypeError(
                            'compact VSS recipient-share commitment objectVersion is not supported.',
                        );
                    }
                    assertExactStringField(
                        recipientShareCommitment.profileId,
                        'compact VSS recipient-share commitment profileId',
                        compactVssCommitmentProfileId,
                    );
                    assertExactStringField(
                        recipientShareCommitment.developmentScope,
                        'compact VSS recipient-share commitment developmentScope',
                        compactVssCommitmentDevelopmentScope,
                    );
                    if (
                        recipientShareCommitment.sourceTrusteeIdentity !==
                            sourceTrusteeRecord.sourceTrusteeIdentity ||
                        recipientShareCommitment.sourceTrusteeRosterPosition !==
                            sourceTrusteeRecord.sourceTrusteeRosterPosition
                    ) {
                        throw new Error(
                            'compact VSS recipient-share commitment source binding must match its source record.',
                        );
                    }
                    assertNonEmptyString(
                        recipientShareCommitment.recipientIdentity,
                        'compact VSS recipient-share commitment recipientIdentity',
                    );
                    if (
                        recipientShareCommitment.recipientRosterPosition !==
                            expectedRecipientRosterPosition ||
                        recipientShareCommitment.recipientTrusteePoint !==
                            expectedRecipientRosterPosition + 1
                    ) {
                        throw new Error(
                            'compact VSS recipient-share commitment recipient coordinates must be canonical.',
                        );
                    }
                    if (
                        recipientShareCommitment.rnsLimbIndex !==
                        expectedRnsLimbIndex
                    ) {
                        throw new Error(
                            'compact VSS recipient-share commitment RNS coordinates must be canonical.',
                        );
                    }
                    assertPositiveSafeInteger(
                        recipientShareCommitment.rnsPrime,
                        'compact VSS recipient-share commitment rnsPrime',
                    );
                    assertProtocolHash(
                        recipientShareCommitment.shareCommitmentRoot,
                        'compact VSS recipient-share commitment shareCommitmentRoot',
                    );
                    assertProtocolHash(
                        recipientShareCommitment.shareOpeningRoot,
                        'compact VSS recipient-share commitment shareOpeningRoot',
                    );
                    assertHash512Hex(
                        recipientShareCommitment.shareVectorHash512,
                        'compact VSS recipient-share commitment shareVectorHash512',
                    );
                    assertCompactVssCommitmentBody({
                        commitment: recipientShareCommitment.commitment,
                        expectedCommitmentRole: 'recipient-share',
                        expectedCommitmentRoot:
                            recipientShareCommitment.shareCommitmentRoot,
                        expectedPublicMatrixSeedHash:
                            recipientShareCommitmentSet.publicMatrixSeedHash,
                        expectedRnsLimbIndex,
                        expectedRnsPrime: recipientShareCommitment.rnsPrime,
                        expectedMessageVectorHash512:
                            recipientShareCommitment.shareVectorHash512,
                        fieldName:
                            'compact VSS recipient-share commitment commitment',
                    });
                },
            );
            assertProtocolHash(
                sourceTrusteeRecord.sourceRecipientShareCommitmentRoot,
                'compact VSS source recipient-share commitments sourceRecipientShareCommitmentRoot',
            );
            const {
                sourceRecipientShareCommitmentRoot:
                    _sourceRecipientShareCommitmentRoot,
                ...sourceRecordWithoutRoot
            } = sourceTrusteeRecord;
            const expectedSourceRoot = deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                sourceRecordWithoutRoot,
            );
            if (
                sourceTrusteeRecord.sourceRecipientShareCommitmentRoot !==
                expectedSourceRoot
            ) {
                throw new Error(
                    'compact VSS source recipient-share commitment root does not match its records.',
                );
            }
        },
    );
    assertProtocolHash(
        recipientShareCommitmentSet.recipientShareCommitmentRoot,
        'compact VSS recipient-share commitment set recipientShareCommitmentRoot',
    );
    const {
        recipientShareCommitmentRoot: _recipientShareCommitmentRoot,
        ...setWithoutRoot
    } = recipientShareCommitmentSet;
    const expectedSetRoot = deriveProtocolHash(
        'ThresholdShareCommitmentRoot',
        setWithoutRoot,
    );
    if (
        recipientShareCommitmentSet.recipientShareCommitmentRoot !==
        expectedSetRoot
    ) {
        throw new Error(
            'compact VSS recipient-share commitment set root does not match its source records.',
        );
    }

    return recipientShareCommitmentSet;
};

const assertCompatibleCommitment = (
    leftCommitment: CompactVssCommitmentValue,
    rightCommitment: CompactVssCommitmentValue,
): void => {
    const fields: (keyof CompactVssCommitmentValue)[] = [
        'profileId',
        'developmentScope',
        'publicMatrixSeedHash',
        'rnsLimbIndex',
        'rnsPrime',
        'ringDegree',
        'outputCoordinateCount',
        'randomnessColumnCount',
    ];
    fields.forEach((fieldName) => {
        if (leftCommitment[fieldName] !== rightCommitment[fieldName]) {
            throw new Error(
                `compact VSS commitments must agree on ${String(fieldName)} before homomorphic combination.`,
            );
        }
    });
};

export const combineCompactVssCommitments = (
    input: CompactVssCommitmentHomomorphicCombinationInput,
): CompactVssCommitmentComputation => {
    if (input.terms.length === 0) {
        throw new Error('compact VSS commitment combination needs terms.');
    }
    const firstCommitment = input.terms[0]?.commitment;
    if (firstCommitment === undefined) {
        throw new Error('compact VSS commitment combination needs terms.');
    }
    const commitmentContextHash = deriveProtocolHash('SetupCommitmentRoot', {
        objectType: 'CompactVssCommitmentContext',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        commitmentRole: input.commitmentRole,
        commitmentContext: input.commitmentContext,
    });
    const commitmentLimbs = firstCommitment.commitmentLimbs.map(
        (firstLimb, limbIndex): CompactVssCommitmentLimb => {
            const coordinates = firstLimb.coordinates.map(
                (_unused, coordinateIndex) => {
                    let accumulator = 0n;
                    input.terms.forEach((term, termIndex) => {
                        const limb = term.commitment.commitmentLimbs[limbIndex];
                        if (limb === undefined) {
                            throw new Error(
                                `compact commitment term ${String(termIndex)} is missing a commitment limb.`,
                            );
                        }
                        assertCompatibleCommitment(
                            firstCommitment,
                            term.commitment,
                        );
                        accumulator =
                            (accumulator +
                                BigInt(limb.coordinates[coordinateIndex] ?? 0) *
                                    BigInt(term.scalar)) %
                            BigInt(firstLimb.modulus);
                    });

                    return Number(
                        accumulator < 0n
                            ? accumulator + BigInt(firstLimb.modulus)
                            : accumulator,
                    );
                },
            );

            return {
                commitmentModulusIndex: firstLimb.commitmentModulusIndex,
                modulus: firstLimb.modulus,
                coordinates,
            };
        },
    );
    const commitment = {
        ...firstCommitment,
        commitmentRole: input.commitmentRole,
        commitmentContextHash,
        messageVectorHash512:
            input.combinedMessageVectorHash512 ??
            hash512Hex(
                'sealed-lattice-compact-vss-commitment/combined-message-vector-v1',
                [
                    new TextEncoder().encode(
                        input.terms
                            .map(
                                (term) =>
                                    `${term.scalar}:${term.commitment.messageVectorHash512}`,
                            )
                            .join('|'),
                    ),
                ],
            ),
        openingRandomnessHash512:
            input.combinedOpeningRandomnessHash512 ??
            hash512Hex(
                'sealed-lattice-compact-vss-commitment/combined-opening-randomness-v1',
                [
                    new TextEncoder().encode(
                        input.terms
                            .map(
                                (term) =>
                                    `${term.scalar}:${term.commitment.openingRandomnessHash512}`,
                            )
                            .join('|'),
                    ),
                ],
            ),
        commitmentLimbs,
    } satisfies CompactVssCommitmentValue;

    return {
        ok: true,
        operation: 'computeCompactVssCommitmentFromOpening',
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitment,
        commitmentRoot: commitmentRoot(commitment),
        commitmentContextHash,
        openingRoot: deriveProtocolHash('SetupCommitmentRoot', {
            objectType: 'CompactVssCombinedOpeningReference',
            objectVersion: 1,
            profileId: compactVssCommitmentProfileId,
            commitmentRole: input.commitmentRole,
            commitmentContext: input.commitmentContext,
            terms: input.terms.map((term) => ({
                scalar: term.scalar,
                messageVectorHash512: term.commitment.messageVectorHash512,
                openingRandomnessHash512:
                    term.commitment.openingRandomnessHash512,
            })),
        }),
        encodedCommitmentByteLength: compactVssEncodedCommitmentByteLength(),
    };
};

const assertAggregateCompactVssCommitmentsArePublicSums = (input: {
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
}): void => {
    input.aggregateThresholdCommitmentSet.recipientRecords.forEach(
        (aggregateRecord) => {
            const sourceShareRecords =
                input.recipientShareCommitmentSet.sourceTrusteeRecords.map(
                    (sourceRecord) => {
                        const recipientShareRecordIndex =
                            aggregateRecord.recipientRosterPosition *
                                input.recipientShareCommitmentSet.rnsLimbCount +
                            aggregateRecord.rnsLimbIndex;
                        const recipientShareRecord =
                            sourceRecord.recipientShareCommitments[
                                recipientShareRecordIndex
                            ];
                        if (recipientShareRecord === undefined) {
                            throw new Error(
                                'compact VSS aggregate threshold commitment references a missing recipient-share commitment.',
                            );
                        }
                        if (
                            recipientShareRecord.recipientRosterPosition !==
                                aggregateRecord.recipientRosterPosition ||
                            recipientShareRecord.rnsLimbIndex !==
                                aggregateRecord.rnsLimbIndex ||
                            recipientShareRecord.rnsPrime !==
                                aggregateRecord.rnsPrime
                        ) {
                            throw new Error(
                                'compact VSS aggregate threshold commitment source coordinates do not match the recipient-share set.',
                            );
                        }

                        return recipientShareRecord;
                    },
                );
            const sourceShareRoots = sourceShareRecords.map(
                (recipientShareRecord) =>
                    recipientShareRecord.shareCommitmentRoot,
            );
            if (
                sourceShareRoots.length !==
                    aggregateRecord.sourceShareCommitmentRoots.length ||
                sourceShareRoots.some(
                    (sourceShareRoot, sourceRosterPosition) =>
                        sourceShareRoot !==
                        aggregateRecord.sourceShareCommitmentRoots[
                            sourceRosterPosition
                        ],
                )
            ) {
                throw new Error(
                    'compact VSS aggregate threshold commitment source roots must match the recipient-share commitment set.',
                );
            }
            aggregateRecord.commitment.commitmentLimbs.forEach(
                (aggregateLimb, limbIndex) => {
                    aggregateLimb.coordinates.forEach(
                        (aggregateCoordinate, coordinateIndex) => {
                            const summedCoordinate = sourceShareRecords.reduce(
                                (sum, sourceRecord) => {
                                    const sourceLimb =
                                        sourceRecord.commitment.commitmentLimbs[
                                            limbIndex
                                        ];
                                    const sourceCoordinate =
                                        sourceLimb?.coordinates[
                                            coordinateIndex
                                        ];
                                    if (
                                        sourceLimb === undefined ||
                                        sourceCoordinate === undefined ||
                                        sourceLimb.modulus !==
                                            aggregateLimb.modulus ||
                                        sourceLimb.commitmentModulusIndex !==
                                            aggregateLimb.commitmentModulusIndex
                                    ) {
                                        throw new Error(
                                            'compact VSS aggregate threshold commitment source body shape does not match the aggregate body.',
                                        );
                                    }

                                    return (
                                        (sum + BigInt(sourceCoordinate)) %
                                        BigInt(aggregateLimb.modulus)
                                    );
                                },
                                0n,
                            );
                            if (
                                Number(summedCoordinate) !== aggregateCoordinate
                            ) {
                                throw new Error(
                                    'compact VSS aggregate threshold commitment body is not the public sum of recipient-share commitments.',
                                );
                            }
                        },
                    );
                },
            );
        },
    );
};

export const aggregateCompactVssThresholdShareCommitments = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly recipientTrustees: readonly CompactVssTrusteeReference[];
    readonly recipientShareOpeningCredentials: readonly CompactVssRecipientShareOpeningCredential[];
}): CompactVssAggregateThresholdCommitmentBundle => {
    const recipientRecords: CompactVssAggregateThresholdCommitmentRecord[] = [];
    const aggregateThresholdOpeningCredentials: CompactVssAggregateThresholdOpeningCredential[] =
        [];

    input.recipientTrustees
        .slice()
        .sort(
            (leftTrustee, rightTrustee) =>
                leftTrustee.trusteeRosterPosition -
                rightTrustee.trusteeRosterPosition,
        )
        .forEach((recipientTrustee) => {
            const recipientTrusteePoint =
                recipientTrustee.trusteeRosterPosition + 1;
            input.qSharePrimes.forEach((rnsPrime, rnsLimbIndex) => {
                const credentials = input.recipientShareOpeningCredentials
                    .filter(
                        (credential) =>
                            credential.recipientIdentity ===
                                recipientTrustee.trusteeIdentity &&
                            credential.recipientRosterPosition ===
                                recipientTrustee.trusteeRosterPosition &&
                            credential.rnsLimbIndex === rnsLimbIndex,
                    )
                    .sort(
                        (leftCredential, rightCredential) =>
                            leftCredential.sourceTrusteeRosterPosition -
                            rightCredential.sourceTrusteeRosterPosition,
                    );
                if (credentials.length !== input.participantCount) {
                    throw new Error(
                        'compact VSS aggregate threshold commitment needs one source credential per participant.',
                    );
                }
                const aggregateShareSum = sumShareVectorsWithCarries(
                    credentials.map((credential) => credential.shareValues),
                    rnsPrime,
                    input.ringDegree,
                );
                const aggregateMessageCoefficientBound =
                    compactVssAggregateMessageCoefficientBound({
                        rnsPrime,
                        participantCount: input.participantCount,
                    });
                const aggregateRandomnessByColumn = sumRandomnessColumns(
                    credentials.map(
                        (credential) => credential.randomnessByColumn,
                    ),
                    input.ringDegree,
                );
                const aggregateOpening = {
                    commitmentRole: 'aggregate-threshold-share',
                    commitmentContext: {
                        objectType:
                            'CompactVssAggregateThresholdShareCommitmentContext',
                        objectVersion: 1,
                        ...setupContextFields(input.setupContext),
                        recipientIdentity: recipientTrustee.trusteeIdentity,
                        recipientRosterPosition:
                            recipientTrustee.trusteeRosterPosition,
                        rnsLimbIndex,
                        rnsPrime,
                    },
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    rnsLimbIndex,
                    rnsPrime,
                    ringDegree: input.ringDegree,
                    messageCoefficients:
                        aggregateShareSum.aggregateCommitmentMessageValues,
                    messageCoefficientBound: aggregateMessageCoefficientBound,
                    randomnessByColumn: aggregateRandomnessByColumn,
                } satisfies CompactVssCommitmentOpeningInput;
                const directAggregateCommitment =
                    computeCompactVssCommitmentFromOpening(aggregateOpening);
                const sourceCommitments = credentials.map((credential) =>
                    computeCompactVssCommitmentFromOpening({
                        commitmentRole: 'recipient-share',
                        commitmentContext: {
                            objectType:
                                'CompactVssRecipientShareCommitmentContext',
                            objectVersion: 1,
                            ...setupContextFields(input.setupContext),
                            sourceTrusteeIdentity:
                                credential.sourceTrusteeIdentity,
                            sourceTrusteeRosterPosition:
                                credential.sourceTrusteeRosterPosition,
                            recipientIdentity: credential.recipientIdentity,
                            recipientRosterPosition:
                                credential.recipientRosterPosition,
                            rnsLimbIndex,
                            rnsPrime,
                        },
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        rnsLimbIndex,
                        rnsPrime,
                        ringDegree: input.ringDegree,
                        messageCoefficients: credential.shareValues,
                        randomnessByColumn: credential.randomnessByColumn,
                    }),
                );
                sourceCommitments.forEach((commitment, commitmentIndex) => {
                    const credential = credentials[commitmentIndex];
                    if (
                        commitment.commitmentRoot !==
                            credential?.shareCommitmentRoot ||
                        commitment.openingRoot !== credential.shareOpeningRoot
                    ) {
                        throw new Error(
                            'compact VSS recipient share credential does not match its public commitment roots.',
                        );
                    }
                });
                const combinedAggregateCommitment =
                    combineCompactVssCommitments({
                        commitmentRole: 'aggregate-threshold-share',
                        commitmentContext: aggregateOpening.commitmentContext,
                        combinedMessageVectorHash512:
                            directAggregateCommitment.commitment
                                .messageVectorHash512,
                        combinedOpeningRandomnessHash512:
                            directAggregateCommitment.commitment
                                .openingRandomnessHash512,
                        terms: sourceCommitments.map((commitment) => ({
                            commitment: commitment.commitment,
                            scalar: 1,
                        })),
                    });
                if (
                    combinedAggregateCommitment.commitmentRoot !==
                    directAggregateCommitment.commitmentRoot
                ) {
                    throw new Error(
                        'compact VSS aggregate commitment combination does not match the aggregate opening.',
                    );
                }
                recipientRecords.push({
                    objectType: 'CompactVssAggregateThresholdCommitment',
                    objectVersion: 1,
                    profileId: compactVssCommitmentProfileId,
                    developmentScope: compactVssCommitmentDevelopmentScope,
                    recipientIdentity: recipientTrustee.trusteeIdentity,
                    recipientRosterPosition:
                        recipientTrustee.trusteeRosterPosition,
                    recipientTrusteePoint,
                    rnsLimbIndex,
                    rnsPrime,
                    aggregateCommitmentRoot:
                        directAggregateCommitment.commitmentRoot,
                    aggregateOpeningRoot: directAggregateCommitment.openingRoot,
                    commitment: directAggregateCommitment.commitment,
                    sourceShareCommitmentRoots: credentials.map(
                        (credential) => credential.shareCommitmentRoot,
                    ),
                });
                aggregateThresholdOpeningCredentials.push({
                    objectType: 'CompactVssAggregateThresholdOpeningCredential',
                    objectVersion: 1,
                    profileId: compactVssCommitmentProfileId,
                    recipientIdentity: recipientTrustee.trusteeIdentity,
                    recipientRosterPosition:
                        recipientTrustee.trusteeRosterPosition,
                    recipientTrusteePoint,
                    rnsLimbIndex,
                    rnsPrime,
                    aggregateShareValues:
                        aggregateShareSum.aggregateShareValues,
                    aggregateCommitmentMessageValues:
                        aggregateShareSum.aggregateCommitmentMessageValues,
                    aggregateShareCarryValues:
                        aggregateShareSum.aggregateShareCarryValues,
                    aggregateRandomnessByColumn,
                    aggregateCommitmentRoot:
                        directAggregateCommitment.commitmentRoot,
                    aggregateOpeningRoot: directAggregateCommitment.openingRoot,
                    sourceShareOpeningRoots: credentials.map(
                        (credential) => credential.shareOpeningRoot,
                    ),
                });
            });
        });

    const setWithoutRoot = {
        objectType: 'CompactVssAggregateThresholdCommitmentSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: input.participantCount,
        rnsLimbCount: input.qSharePrimes.length,
        ringDegree: input.ringDegree,
        recipientRecords,
    } as const satisfies Omit<
        CompactVssAggregateThresholdCommitmentSet,
        'aggregateThresholdCommitmentRoot'
    >;

    return {
        aggregateThresholdCommitmentSet: {
            ...setWithoutRoot,
            aggregateThresholdCommitmentRoot: deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                setWithoutRoot,
            ),
        },
        aggregateThresholdOpeningCredentials,
    };
};

export const verifyCompactVssAggregateThresholdCommitmentSet = (input: {
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
}): CompactVssAggregateThresholdCommitmentSet => {
    const aggregateThresholdCommitmentSet =
        input.aggregateThresholdCommitmentSet;
    assertExactStringField(
        aggregateThresholdCommitmentSet.objectType,
        'compact VSS aggregate threshold commitment set objectType',
        'CompactVssAggregateThresholdCommitmentSet',
    );
    if (aggregateThresholdCommitmentSet.objectVersion !== 1) {
        throw new TypeError(
            'compact VSS aggregate threshold commitment set objectVersion is not supported.',
        );
    }
    assertExactStringField(
        aggregateThresholdCommitmentSet.setupProfileId,
        'compact VSS aggregate threshold commitment set setupProfileId',
        'CollectiveBgvSetup-v1',
    );
    assertExactStringField(
        aggregateThresholdCommitmentSet.profileId,
        'compact VSS aggregate threshold commitment set profileId',
        compactVssCommitmentProfileId,
    );
    assertExactStringField(
        aggregateThresholdCommitmentSet.developmentScope,
        'compact VSS aggregate threshold commitment set developmentScope',
        compactVssCommitmentDevelopmentScope,
    );
    assertProtocolHash(
        aggregateThresholdCommitmentSet.publicMatrixSeedHash,
        'compact VSS aggregate threshold commitment set publicMatrixSeedHash',
    );
    assertPositiveSafeInteger(
        aggregateThresholdCommitmentSet.participantCount,
        'compact VSS aggregate threshold commitment set participantCount',
    );
    assertPositiveSafeInteger(
        aggregateThresholdCommitmentSet.rnsLimbCount,
        'compact VSS aggregate threshold commitment set rnsLimbCount',
    );
    assertPositiveSafeInteger(
        aggregateThresholdCommitmentSet.ringDegree,
        'compact VSS aggregate threshold commitment set ringDegree',
    );
    const expectedRecipientRecordCount =
        aggregateThresholdCommitmentSet.participantCount *
        aggregateThresholdCommitmentSet.rnsLimbCount;
    if (
        aggregateThresholdCommitmentSet.recipientRecords.length !==
        expectedRecipientRecordCount
    ) {
        throw new Error(
            'compact VSS aggregate threshold commitment set must cover every recipient and RNS limb.',
        );
    }
    aggregateThresholdCommitmentSet.recipientRecords.forEach(
        (recipientRecord, recipientRecordIndex) => {
            const expectedRecipientRosterPosition = Math.floor(
                recipientRecordIndex /
                    aggregateThresholdCommitmentSet.rnsLimbCount,
            );
            const expectedRnsLimbIndex =
                recipientRecordIndex %
                aggregateThresholdCommitmentSet.rnsLimbCount;
            assertExactStringField(
                recipientRecord.objectType,
                'compact VSS aggregate threshold commitment objectType',
                'CompactVssAggregateThresholdCommitment',
            );
            if (recipientRecord.objectVersion !== 1) {
                throw new TypeError(
                    'compact VSS aggregate threshold commitment objectVersion is not supported.',
                );
            }
            assertExactStringField(
                recipientRecord.profileId,
                'compact VSS aggregate threshold commitment profileId',
                compactVssCommitmentProfileId,
            );
            assertExactStringField(
                recipientRecord.developmentScope,
                'compact VSS aggregate threshold commitment developmentScope',
                compactVssCommitmentDevelopmentScope,
            );
            assertNonEmptyString(
                recipientRecord.recipientIdentity,
                'compact VSS aggregate threshold commitment recipientIdentity',
            );
            if (
                recipientRecord.recipientRosterPosition !==
                    expectedRecipientRosterPosition ||
                recipientRecord.recipientTrusteePoint !==
                    expectedRecipientRosterPosition + 1
            ) {
                throw new Error(
                    'compact VSS aggregate threshold commitment recipient coordinates must be canonical.',
                );
            }
            if (recipientRecord.rnsLimbIndex !== expectedRnsLimbIndex) {
                throw new Error(
                    'compact VSS aggregate threshold commitment RNS coordinates must be canonical.',
                );
            }
            assertPositiveSafeInteger(
                recipientRecord.rnsPrime,
                'compact VSS aggregate threshold commitment rnsPrime',
            );
            assertProtocolHash(
                recipientRecord.aggregateCommitmentRoot,
                'compact VSS aggregate threshold commitment aggregateCommitmentRoot',
            );
            assertProtocolHash(
                recipientRecord.aggregateOpeningRoot,
                'compact VSS aggregate threshold commitment aggregateOpeningRoot',
            );
            assertCompactVssCommitmentBody({
                commitment: recipientRecord.commitment,
                expectedCommitmentRole: 'aggregate-threshold-share',
                expectedCommitmentRoot: recipientRecord.aggregateCommitmentRoot,
                expectedPublicMatrixSeedHash:
                    aggregateThresholdCommitmentSet.publicMatrixSeedHash,
                expectedRnsLimbIndex,
                expectedRnsPrime: recipientRecord.rnsPrime,
                fieldName:
                    'compact VSS aggregate threshold commitment commitment',
            });
            if (
                recipientRecord.sourceShareCommitmentRoots.length !==
                aggregateThresholdCommitmentSet.participantCount
            ) {
                throw new Error(
                    'compact VSS aggregate threshold commitment must bind one source share commitment root per participant.',
                );
            }
            recipientRecord.sourceShareCommitmentRoots.forEach(
                (sourceShareCommitmentRoot, sourceRosterPosition) =>
                    assertProtocolHash(
                        sourceShareCommitmentRoot,
                        `compact VSS aggregate threshold commitment sourceShareCommitmentRoots.${String(sourceRosterPosition)}`,
                    ),
            );
        },
    );
    assertProtocolHash(
        aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
        'compact VSS aggregate threshold commitment set aggregateThresholdCommitmentRoot',
    );
    const {
        aggregateThresholdCommitmentRoot: _aggregateThresholdCommitmentRoot,
        ...setWithoutRoot
    } = aggregateThresholdCommitmentSet;
    const expectedSetRoot = deriveProtocolHash(
        'ThresholdShareCommitmentRoot',
        setWithoutRoot,
    );
    if (
        aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot !==
        expectedSetRoot
    ) {
        throw new Error(
            'compact VSS aggregate threshold commitment set root does not match its recipient records.',
        );
    }

    return aggregateThresholdCommitmentSet;
};

export const createCompactVssShareLinkageStatement = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetBasisHash: ProtocolHash;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
}): CompactVssShareLinkageStatement => {
    assertProtocolHash(input.publicMatrixSeedHash, 'publicMatrixSeedHash');
    assertProtocolHash(input.targetBasisHash, 'targetBasisHash');
    const coefficientCommitmentSet = verifyCompactVssCoefficientCommitmentSet({
        coefficientCommitmentSet: input.coefficientCommitmentSet,
    });
    const recipientShareCommitmentSet =
        verifyCompactVssRecipientShareCommitmentSet({
            recipientShareCommitmentSet: input.recipientShareCommitmentSet,
        });
    const aggregateThresholdCommitmentSet =
        verifyCompactVssAggregateThresholdCommitmentSet({
            aggregateThresholdCommitmentSet:
                input.aggregateThresholdCommitmentSet,
        });
    if (
        coefficientCommitmentSet.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        recipientShareCommitmentSet.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        aggregateThresholdCommitmentSet.publicMatrixSeedHash !==
            input.publicMatrixSeedHash
    ) {
        throw new Error(
            'compact VSS share linkage statement inputs must use one public matrix seed hash.',
        );
    }
    if (
        coefficientCommitmentSet.participantCount !==
            recipientShareCommitmentSet.participantCount ||
        coefficientCommitmentSet.participantCount !==
            aggregateThresholdCommitmentSet.participantCount ||
        coefficientCommitmentSet.rnsLimbCount !==
            recipientShareCommitmentSet.rnsLimbCount ||
        coefficientCommitmentSet.rnsLimbCount !==
            aggregateThresholdCommitmentSet.rnsLimbCount ||
        coefficientCommitmentSet.ringDegree !==
            recipientShareCommitmentSet.ringDegree ||
        coefficientCommitmentSet.ringDegree !==
            aggregateThresholdCommitmentSet.ringDegree
    ) {
        throw new Error(
            'compact VSS share linkage statement inputs must use one participant count, target basis, and ring degree.',
        );
    }
    assertAggregateCompactVssCommitmentsArePublicSums({
        recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
    });
    const sourceStatementRecords =
        coefficientCommitmentSet.sourceTrusteeRecords.map(
            (coefficientSourceRecord, sourceRecordIndex) => {
                const recipientSourceRecord =
                    recipientShareCommitmentSet.sourceTrusteeRecords[
                        sourceRecordIndex
                    ];
                if (recipientSourceRecord === undefined) {
                    throw new Error(
                        'compact VSS share linkage statement inputs must contain matching source records.',
                    );
                }
                if (
                    coefficientSourceRecord.sourceTrusteeIdentity !==
                        recipientSourceRecord.sourceTrusteeIdentity ||
                    coefficientSourceRecord.sourceTrusteeRosterPosition !==
                        recipientSourceRecord.sourceTrusteeRosterPosition
                ) {
                    throw new Error(
                        'compact VSS share linkage source records must bind one source trustee.',
                    );
                }
                const sourceStatementWithoutRoot = {
                    objectType: 'CompactVssShareLinkageSourceStatement',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    profileId: compactVssCommitmentProfileId,
                    developmentScope: compactVssCommitmentDevelopmentScope,
                    ...setupContextFields(input.setupContext),
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    targetBasisHash: input.targetBasisHash,
                    sourceTrusteeIdentity:
                        coefficientSourceRecord.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        coefficientSourceRecord.sourceTrusteeRosterPosition,
                    participantCount: coefficientCommitmentSet.participantCount,
                    targetRnsLimbCount: coefficientCommitmentSet.rnsLimbCount,
                    thresholdDegree: coefficientCommitmentSet.thresholdDegree,
                    coefficientCommitmentRoot:
                        coefficientCommitmentSet.coefficientCommitmentRoot,
                    sourceCoefficientCommitmentRoot:
                        coefficientSourceRecord.sourceCoefficientCommitmentRoot,
                    sourceRecipientShareCommitmentRoot:
                        recipientSourceRecord.sourceRecipientShareCommitmentRoot,
                    aggregateThresholdCommitmentRoot:
                        aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
                    relation: compactVssShareLinkageStatementRelation,
                    proofBatchingRule: compactVssShareLinkageProofBatchingRule,
                    shamirEvaluationRule:
                        compactVssShareLinkageShamirEvaluationRule,
                    aggregateThresholdRule:
                        compactVssShareLinkageAggregateThresholdRule,
                    commonKeyRule: compactVssShareLinkageCommonKeyRule,
                    recipientApprovalBoundary:
                        compactVssShareLinkageRecipientApprovalBoundary,
                    proofBoundary: compactVssShareLinkageStatementProofBoundary,
                } as const satisfies Omit<
                    CompactVssShareLinkageSourceStatementRecord,
                    'sourceStatementRoot'
                >;

                return {
                    ...sourceStatementWithoutRoot,
                    sourceStatementRoot: deriveProtocolHash(
                        'SetupProofRecordBindingHash',
                        sourceStatementWithoutRoot,
                    ),
                };
            },
        );
    const statementWithoutRoot = {
        objectType: 'CompactVssShareLinkageStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        ...setupContextFields(input.setupContext),
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        targetBasisHash: input.targetBasisHash,
        participantCount: coefficientCommitmentSet.participantCount,
        targetRnsLimbCount: coefficientCommitmentSet.rnsLimbCount,
        thresholdDegree: coefficientCommitmentSet.thresholdDegree,
        coefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        recipientShareCommitmentRoot:
            recipientShareCommitmentSet.recipientShareCommitmentRoot,
        aggregateThresholdCommitmentRoot:
            aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
        relation: compactVssShareLinkageStatementRelation,
        proofBatchingRule: compactVssShareLinkageProofBatchingRule,
        shamirEvaluationRule: compactVssShareLinkageShamirEvaluationRule,
        aggregateThresholdRule: compactVssShareLinkageAggregateThresholdRule,
        commonKeyRule: compactVssShareLinkageCommonKeyRule,
        recipientApprovalBoundary:
            compactVssShareLinkageRecipientApprovalBoundary,
        proofBoundary: compactVssShareLinkageStatementProofBoundary,
        sourceStatementRecords,
    } as const satisfies Omit<CompactVssShareLinkageStatement, 'statementRoot'>;

    return {
        ...statementWithoutRoot,
        statementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementWithoutRoot,
        ),
    };
};

const assertCompactVssShareLinkageEvidenceMatchesStatement = (input: {
    readonly statement: CompactVssShareLinkageStatement;
    readonly coefficientCommitmentSet?: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet?: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet?: CompactVssAggregateThresholdCommitmentSet;
}): void => {
    const evidenceSets = [
        input.coefficientCommitmentSet,
        input.recipientShareCommitmentSet,
        input.aggregateThresholdCommitmentSet,
    ];
    if (
        evidenceSets.some((evidenceSet) => evidenceSet === undefined) &&
        evidenceSets.some((evidenceSet) => evidenceSet !== undefined)
    ) {
        throw new Error(
            'compact VSS share linkage evidence verification requires coefficient, recipient-share, and aggregate-threshold commitment sets.',
        );
    }
    if (
        input.coefficientCommitmentSet === undefined ||
        input.recipientShareCommitmentSet === undefined ||
        input.aggregateThresholdCommitmentSet === undefined
    ) {
        return;
    }

    const coefficientCommitmentSet = verifyCompactVssCoefficientCommitmentSet({
        coefficientCommitmentSet: input.coefficientCommitmentSet,
    });
    const recipientShareCommitmentSet =
        verifyCompactVssRecipientShareCommitmentSet({
            recipientShareCommitmentSet: input.recipientShareCommitmentSet,
        });
    const aggregateThresholdCommitmentSet =
        verifyCompactVssAggregateThresholdCommitmentSet({
            aggregateThresholdCommitmentSet:
                input.aggregateThresholdCommitmentSet,
        });
    if (
        coefficientCommitmentSet.coefficientCommitmentRoot !==
            input.statement.coefficientCommitmentRoot ||
        recipientShareCommitmentSet.recipientShareCommitmentRoot !==
            input.statement.recipientShareCommitmentRoot ||
        aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot !==
            input.statement.aggregateThresholdCommitmentRoot
    ) {
        throw new Error(
            'compact VSS share linkage evidence roots must match the statement.',
        );
    }
    if (
        coefficientCommitmentSet.publicMatrixSeedHash !==
            input.statement.publicMatrixSeedHash ||
        recipientShareCommitmentSet.publicMatrixSeedHash !==
            input.statement.publicMatrixSeedHash ||
        aggregateThresholdCommitmentSet.publicMatrixSeedHash !==
            input.statement.publicMatrixSeedHash ||
        coefficientCommitmentSet.participantCount !==
            input.statement.participantCount ||
        recipientShareCommitmentSet.participantCount !==
            input.statement.participantCount ||
        aggregateThresholdCommitmentSet.participantCount !==
            input.statement.participantCount ||
        coefficientCommitmentSet.rnsLimbCount !==
            input.statement.targetRnsLimbCount ||
        recipientShareCommitmentSet.rnsLimbCount !==
            input.statement.targetRnsLimbCount ||
        aggregateThresholdCommitmentSet.rnsLimbCount !==
            input.statement.targetRnsLimbCount ||
        coefficientCommitmentSet.thresholdDegree !==
            input.statement.thresholdDegree
    ) {
        throw new Error(
            'compact VSS share linkage evidence dimensions must match the statement.',
        );
    }
    if (
        coefficientCommitmentSet.sourceTrusteeRecords.length !==
            input.statement.participantCount ||
        recipientShareCommitmentSet.sourceTrusteeRecords.length !==
            input.statement.participantCount
    ) {
        throw new Error(
            'compact VSS share linkage evidence source records must cover every participant.',
        );
    }
    assertAggregateCompactVssCommitmentsArePublicSums({
        recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
    });
    input.statement.sourceStatementRecords.forEach(
        (sourceStatement, sourceRecordIndex) => {
            const coefficientSourceRecord =
                coefficientCommitmentSet.sourceTrusteeRecords[
                    sourceRecordIndex
                ];
            const recipientSourceRecord =
                recipientShareCommitmentSet.sourceTrusteeRecords[
                    sourceRecordIndex
                ];
            if (
                coefficientSourceRecord === undefined ||
                recipientSourceRecord === undefined
            ) {
                throw new Error(
                    'compact VSS share linkage evidence source records must cover every source statement.',
                );
            }
            if (
                sourceStatement.sourceTrusteeIdentity !==
                    coefficientSourceRecord.sourceTrusteeIdentity ||
                sourceStatement.sourceTrusteeIdentity !==
                    recipientSourceRecord.sourceTrusteeIdentity ||
                sourceStatement.sourceTrusteeRosterPosition !==
                    coefficientSourceRecord.sourceTrusteeRosterPosition ||
                sourceStatement.sourceTrusteeRosterPosition !==
                    recipientSourceRecord.sourceTrusteeRosterPosition ||
                sourceStatement.sourceTrusteeRosterPosition !==
                    sourceRecordIndex
            ) {
                throw new Error(
                    'compact VSS share linkage evidence source records must bind the same trustee order.',
                );
            }
            if (
                sourceStatement.sourceCoefficientCommitmentRoot !==
                    coefficientSourceRecord.sourceCoefficientCommitmentRoot ||
                sourceStatement.sourceRecipientShareCommitmentRoot !==
                    recipientSourceRecord.sourceRecipientShareCommitmentRoot ||
                sourceStatement.aggregateThresholdCommitmentRoot !==
                    aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot
            ) {
                throw new Error(
                    'compact VSS share linkage evidence source roots must match each source statement.',
                );
            }
        },
    );
};

export const verifyCompactVssShareLinkageStatement = (input: {
    readonly statement: CompactVssShareLinkageStatement;
    readonly coefficientCommitmentSet?: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet?: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet?: CompactVssAggregateThresholdCommitmentSet;
}): CompactVssShareLinkageStatement => {
    assertExactStringField(
        input.statement.objectType,
        'compact VSS share linkage statement objectType',
        'CompactVssShareLinkageStatement',
    );
    if (input.statement.objectVersion !== 1) {
        throw new TypeError(
            'compact VSS share linkage statement objectVersion is not supported.',
        );
    }
    assertExactStringField(
        input.statement.setupProfileId,
        'compact VSS share linkage statement setupProfileId',
        'CollectiveBgvSetup-v1',
    );
    assertExactStringField(
        input.statement.profileId,
        'compact VSS share linkage statement profileId',
        compactVssCommitmentProfileId,
    );
    assertExactStringField(
        input.statement.developmentScope,
        'compact VSS share linkage statement developmentScope',
        compactVssCommitmentDevelopmentScope,
    );
    assertNonEmptyString(
        input.statement.ceremonyId,
        'compact VSS share linkage statement ceremonyId',
    );
    assertNonEmptyString(
        input.statement.setupEpoch,
        'compact VSS share linkage statement setupEpoch',
    );
    assertProtocolHash(
        input.statement.manifestHash,
        'compact VSS share linkage statement manifestHash',
    );
    assertProtocolHash(
        input.statement.rosterHash,
        'compact VSS share linkage statement rosterHash',
    );
    assertProtocolHash(
        input.statement.setupProfileHash,
        'compact VSS share linkage statement setupProfileHash',
    );
    assertProtocolHash(
        input.statement.qShareHash,
        'compact VSS share linkage statement qShareHash',
    );
    assertProtocolHash(
        input.statement.carryAwareVssShareRelationProfileHash,
        'compact VSS share linkage statement carryAwareVssShareRelationProfileHash',
    );
    assertProtocolHash(
        input.statement.commitmentProfileHash,
        'compact VSS share linkage statement commitmentProfileHash',
    );
    assertProtocolHash(
        input.statement.publicMatrixSeedHash,
        'compact VSS share linkage statement publicMatrixSeedHash',
    );
    assertProtocolHash(
        input.statement.targetBasisHash,
        'compact VSS share linkage statement targetBasisHash',
    );
    assertProtocolHash(
        input.statement.coefficientCommitmentRoot,
        'compact VSS share linkage statement coefficientCommitmentRoot',
    );
    assertProtocolHash(
        input.statement.recipientShareCommitmentRoot,
        'compact VSS share linkage statement recipientShareCommitmentRoot',
    );
    assertProtocolHash(
        input.statement.aggregateThresholdCommitmentRoot,
        'compact VSS share linkage statement aggregateThresholdCommitmentRoot',
    );
    assertPositiveSafeInteger(
        input.statement.participantCount,
        'compact VSS share linkage statement participantCount',
    );
    assertPositiveSafeInteger(
        input.statement.targetRnsLimbCount,
        'compact VSS share linkage statement targetRnsLimbCount',
    );
    assertPositiveSafeInteger(
        input.statement.thresholdDegree,
        'compact VSS share linkage statement thresholdDegree',
    );
    assertExactStringField(
        input.statement.relation,
        'compact VSS share linkage statement relation',
        compactVssShareLinkageStatementRelation,
    );
    assertExactStringField(
        input.statement.proofBatchingRule,
        'compact VSS share linkage statement proofBatchingRule',
        compactVssShareLinkageProofBatchingRule,
    );
    assertExactStringField(
        input.statement.shamirEvaluationRule,
        'compact VSS share linkage statement shamirEvaluationRule',
        compactVssShareLinkageShamirEvaluationRule,
    );
    assertExactStringField(
        input.statement.aggregateThresholdRule,
        'compact VSS share linkage statement aggregateThresholdRule',
        compactVssShareLinkageAggregateThresholdRule,
    );
    assertExactStringField(
        input.statement.commonKeyRule,
        'compact VSS share linkage statement commonKeyRule',
        compactVssShareLinkageCommonKeyRule,
    );
    assertExactStringField(
        input.statement.recipientApprovalBoundary,
        'compact VSS share linkage statement recipientApprovalBoundary',
        compactVssShareLinkageRecipientApprovalBoundary,
    );
    assertExactStringField(
        input.statement.proofBoundary,
        'compact VSS share linkage statement proofBoundary',
        compactVssShareLinkageStatementProofBoundary,
    );
    if (
        input.statement.sourceStatementRecords.length !==
        input.statement.participantCount
    ) {
        throw new Error(
            'compact VSS share linkage statement must contain one source statement per participant.',
        );
    }
    input.statement.sourceStatementRecords.forEach(
        (sourceStatementRecord, expectedSourcePosition) => {
            assertExactStringField(
                sourceStatementRecord.objectType,
                'compact VSS share linkage source statement objectType',
                'CompactVssShareLinkageSourceStatement',
            );
            if (sourceStatementRecord.objectVersion !== 1) {
                throw new TypeError(
                    'compact VSS share linkage source statement objectVersion is not supported.',
                );
            }
            for (const [fieldName, expectedValue] of [
                ['setupProfileId', input.statement.setupProfileId],
                ['profileId', input.statement.profileId],
                ['developmentScope', input.statement.developmentScope],
                ['ceremonyId', input.statement.ceremonyId],
                ['manifestHash', input.statement.manifestHash],
                ['rosterHash', input.statement.rosterHash],
                ['setupProfileHash', input.statement.setupProfileHash],
                ['qShareHash', input.statement.qShareHash],
                [
                    'carryAwareVssShareRelationProfileHash',
                    input.statement.carryAwareVssShareRelationProfileHash,
                ],
                [
                    'commitmentProfileHash',
                    input.statement.commitmentProfileHash,
                ],
                ['setupEpoch', input.statement.setupEpoch],
                ['publicMatrixSeedHash', input.statement.publicMatrixSeedHash],
                ['targetBasisHash', input.statement.targetBasisHash],
                [
                    'coefficientCommitmentRoot',
                    input.statement.coefficientCommitmentRoot,
                ],
                [
                    'aggregateThresholdCommitmentRoot',
                    input.statement.aggregateThresholdCommitmentRoot,
                ],
                ['relation', input.statement.relation],
                ['proofBatchingRule', input.statement.proofBatchingRule],
                ['shamirEvaluationRule', input.statement.shamirEvaluationRule],
                [
                    'aggregateThresholdRule',
                    input.statement.aggregateThresholdRule,
                ],
                ['commonKeyRule', input.statement.commonKeyRule],
                [
                    'recipientApprovalBoundary',
                    input.statement.recipientApprovalBoundary,
                ],
                ['proofBoundary', input.statement.proofBoundary],
            ] as const) {
                if (sourceStatementRecord[fieldName] !== expectedValue) {
                    throw new Error(
                        `compact VSS share linkage source statement ${fieldName} must match the statement set.`,
                    );
                }
            }
            assertNonEmptyString(
                sourceStatementRecord.sourceTrusteeIdentity,
                'compact VSS share linkage source statement sourceTrusteeIdentity',
            );
            if (
                sourceStatementRecord.sourceTrusteeRosterPosition !==
                expectedSourcePosition
            ) {
                throw new Error(
                    'compact VSS share linkage source statement roster positions must be contiguous from zero.',
                );
            }
            if (
                sourceStatementRecord.participantCount !==
                    input.statement.participantCount ||
                sourceStatementRecord.targetRnsLimbCount !==
                    input.statement.targetRnsLimbCount ||
                sourceStatementRecord.thresholdDegree !==
                    input.statement.thresholdDegree
            ) {
                throw new Error(
                    'compact VSS share linkage source statement dimensions must match the statement set.',
                );
            }
            assertProtocolHash(
                sourceStatementRecord.sourceCoefficientCommitmentRoot,
                'compact VSS share linkage source statement sourceCoefficientCommitmentRoot',
            );
            assertProtocolHash(
                sourceStatementRecord.sourceRecipientShareCommitmentRoot,
                'compact VSS share linkage source statement sourceRecipientShareCommitmentRoot',
            );
            assertProtocolHash(
                sourceStatementRecord.sourceStatementRoot,
                'compact VSS share linkage source statement sourceStatementRoot',
            );
            const {
                sourceStatementRoot: _sourceStatementRoot,
                ...sourceStatementWithoutRoot
            } = sourceStatementRecord;
            const expectedSourceStatementRoot = deriveProtocolHash(
                'SetupProofRecordBindingHash',
                sourceStatementWithoutRoot,
            );
            if (
                sourceStatementRecord.sourceStatementRoot !==
                expectedSourceStatementRoot
            ) {
                throw new Error(
                    'compact VSS share linkage source statement root does not match its bound roots.',
                );
            }
        },
    );
    assertProtocolHash(
        input.statement.statementRoot,
        'compact VSS share linkage statement statementRoot',
    );
    const { statementRoot: _statementRoot, ...statementWithoutRoot } =
        input.statement;
    const expectedStatementRoot = deriveProtocolHash(
        'SetupProofRecordBindingHash',
        statementWithoutRoot,
    );
    if (expectedStatementRoot !== input.statement.statementRoot) {
        throw new Error(
            'compact VSS share linkage statement root does not match its bound public roots.',
        );
    }
    assertCompactVssShareLinkageEvidenceMatchesStatement({
        statement: input.statement,
        coefficientCommitmentSet: input.coefficientCommitmentSet,
        recipientShareCommitmentSet: input.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet: input.aggregateThresholdCommitmentSet,
    });

    return input.statement;
};

export const compactVssCommitmentMeasurement = (input: {
    readonly participantCount: number;
    readonly sourceRnsLimbCount: number;
    readonly targetRnsLimbCount: number;
    readonly thresholdDegree: number;
    readonly ringDegree?: number;
    readonly currentFullCoefficientTransportBytes: number;
}): CompactVssCommitmentMeasurement => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.sourceRnsLimbCount, 'sourceRnsLimbCount');
    assertPositiveSafeInteger(input.targetRnsLimbCount, 'targetRnsLimbCount');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    const ringDegree = input.ringDegree ?? acceptedBgvProfileRingDegree;
    assertPositiveSafeInteger(ringDegree, 'ringDegree');
    assertPositiveSafeInteger(
        input.currentFullCoefficientTransportBytes,
        'currentFullCoefficientTransportBytes',
    );
    const sourceCoefficientCommitments =
        input.participantCount *
        input.sourceRnsLimbCount *
        input.thresholdDegree;
    const recipientShareCommitments =
        input.participantCount *
        input.participantCount *
        input.targetRnsLimbCount;
    const aggregateThresholdCommitments =
        input.participantCount * input.targetRnsLimbCount;
    const singleCompactCommitmentBytes =
        compactVssEncodedCommitmentByteLength();
    const fullCoefficientCommitmentBytes =
        sourceCoefficientCommitments * singleCompactCommitmentBytes;
    const recipientShareCommitmentBytes =
        recipientShareCommitments * singleCompactCommitmentBytes;
    const aggregateThresholdCommitmentBytes =
        aggregateThresholdCommitments * singleCompactCommitmentBytes;
    const totalCompactPublicCommitmentBytes =
        fullCoefficientCommitmentBytes +
        recipientShareCommitmentBytes +
        aggregateThresholdCommitmentBytes;
    const oneSourcePublicCommitmentUploadBytes =
        (input.sourceRnsLimbCount * input.thresholdDegree +
            input.participantCount * input.targetRnsLimbCount) *
        singleCompactCommitmentBytes;
    const removedBytes =
        input.currentFullCoefficientTransportBytes -
        totalCompactPublicCommitmentBytes;
    const totalCommitments =
        sourceCoefficientCommitments +
        recipientShareCommitments +
        aggregateThresholdCommitments;
    const residueMultiplyAddsPerCommitment =
        compactVssCommitmentModulusLimbIndices.length *
        compactVssCommitmentOutputCoordinateCount *
        compactVssProjectionWeight *
        (1 + compactVssCommitmentRandomnessColumnCount);
    const aggregatePublicSumResidueAdditions =
        aggregateThresholdCommitments *
        input.participantCount *
        compactVssCommitmentModulusLimbIndices.length *
        compactVssCommitmentOutputCoordinateCount;
    const totalResidueMultiplyAdds =
        residueMultiplyAddsPerCommitment * totalCommitments;
    const totalResidueArithmeticOperations =
        totalResidueMultiplyAdds + aggregatePublicSumResidueAdditions;

    return {
        objectType: 'CompactVssCommitmentMeasurement',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        participantCount: input.participantCount,
        sourceRnsLimbCount: input.sourceRnsLimbCount,
        targetRnsLimbCount: input.targetRnsLimbCount,
        thresholdDegree: input.thresholdDegree,
        ringDegree,
        projectionWeight: compactVssProjectionWeight,
        outputCoordinateCount: compactVssCommitmentOutputCoordinateCount,
        commitmentModulusLimbCount:
            compactVssCommitmentModulusLimbIndices.length,
        singleCompactCommitmentBytes,
        fullCoefficientCommitmentBytes,
        recipientShareCommitmentBytes,
        aggregateThresholdCommitmentBytes,
        totalCompactPublicCommitmentBytes,
        currentFullCoefficientTransportBytes:
            input.currentFullCoefficientTransportBytes,
        byteAccountingScope:
            'compact public commitment bodies only: source coefficient commitments, source-to-recipient share commitments, and recipient aggregate-threshold commitments',
        measuredPublicCommitmentRoles: [
            'source coefficient commitments',
            'source-to-recipient share commitments',
            'recipient aggregate-threshold commitments',
        ],
        excludedByteCategories: [
            'compact commitment transport framing and container metadata',
            'public share-linkage zero-knowledge proof bytes',
            'compact same-secret bridge proof bytes',
            'private mailbox share and opening-credential bytes',
            'encrypted persistent local-state witness bytes',
            'target-decryption proof bytes, production smudging proof bytes, and recombination proof material',
        ],
        byteReduction: {
            removedBytes,
            compactFractionOfCurrent:
                totalCompactPublicCommitmentBytes /
                input.currentFullCoefficientTransportBytes,
            reductionFactor:
                input.currentFullCoefficientTransportBytes /
                totalCompactPublicCommitmentBytes,
        },
        largestSingleObjectBytes: singleCompactCommitmentBytes,
        largestWasmBoundaryCopyBytes: singleCompactCommitmentBytes,
        budgetComparison: {
            budgetScope:
                'compact public commitment bodies are compared with public setup download, source upload, largest-object, and WASM-copy budgets; excluded proof and transport categories are not counted here',
            publicSetupDownloadBudgetBytes:
                compactVssPublicSetupDownloadBudgetBytes,
            totalCompactPublicCommitmentFractionOfDownloadBudget:
                totalCompactPublicCommitmentBytes /
                compactVssPublicSetupDownloadBudgetBytes,
            sourceTrusteeUploadBudgetBytes:
                compactVssSourceTrusteeUploadBudgetBytes,
            oneSourcePublicCommitmentUploadBytes,
            oneSourcePublicCommitmentUploadFractionOfBudget:
                oneSourcePublicCommitmentUploadBytes /
                compactVssSourceTrusteeUploadBudgetBytes,
            largestSingleObjectBudgetBytes:
                compactVssLargestSingleObjectBudgetBytes,
            largestSingleObjectFractionOfBudget:
                singleCompactCommitmentBytes /
                compactVssLargestSingleObjectBudgetBytes,
            largestWasmBoundaryCopyBudgetBytes:
                compactVssLargestWasmBoundaryCopyBudgetBytes,
            largestWasmBoundaryCopyFractionOfBudget:
                singleCompactCommitmentBytes /
                compactVssLargestWasmBoundaryCopyBudgetBytes,
        },
        cpuWorkModel: {
            residueMultiplyAddsPerCommitment,
            sourceCoefficientCommitments,
            recipientShareCommitments,
            aggregateThresholdCommitments,
            totalCommitments,
            totalResidueMultiplyAdds,
            aggregatePublicSumResidueAdditions,
            totalResidueArithmeticOperations,
            aggregatePublicSumFractionOfCommitmentWork:
                aggregatePublicSumResidueAdditions / totalResidueMultiplyAdds,
        },
    };
};

export const compactVssMatrixExpansionProfile = (input?: {
    readonly ringDegree?: number;
}): CompactVssMatrixExpansionProfile => {
    const ringDegree = input?.ringDegree ?? acceptedBgvProfileRingDegree;
    assertPositiveSafeInteger(ringDegree, 'ringDegree');
    const inputColumnLabels = [
        'message',
        ...Array.from(
            { length: compactVssCommitmentRandomnessColumnCount },
            (_unused, randomnessColumnIndex) =>
                `randomness:${String(randomnessColumnIndex)}`,
        ),
    ];
    const coordinateCountPerCommitment =
        compactVssCommitmentModulusLimbIndices.length *
        compactVssCommitmentOutputCoordinateCount;
    const sampledMatrixResiduesPerCoordinate =
        inputColumnLabels.length * compactVssProjectionWeight;
    const sampledProjectionIndicesPerCoordinate =
        sampledMatrixResiduesPerCoordinate;
    const sampledMatrixResiduesPerCommitment =
        coordinateCountPerCommitment * sampledMatrixResiduesPerCoordinate;
    const sampledProjectionIndicesPerCommitment =
        coordinateCountPerCommitment * sampledProjectionIndicesPerCoordinate;

    return {
        objectType: 'CompactVssMatrixExpansionProfile',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        matrixKind: 'compact-vss-commitment-key',
        keyScope:
            'one common public matrix seed hash is used for compact coefficient, recipient-share, and aggregate threshold commitments',
        ringDegree,
        commitmentModulusLimbIndices: compactVssCommitmentModulusLimbIndices,
        outputCoordinateCount: compactVssCommitmentOutputCoordinateCount,
        projectionWeight: compactVssProjectionWeight,
        randomnessColumnCount: compactVssCommitmentRandomnessColumnCount,
        inputColumnLabels,
        matrixResidueHashDomain:
            'sealed-lattice-compact-vss-commitment/matrix-residue-v1',
        projectionIndexHashDomain:
            'sealed-lattice-compact-vss-commitment/projection-index-v1',
        rejectionSamplingRule:
            'sample little-endian 64-bit chunks and reject values at or above 2^64 - (2^64 mod modulus or ringDegree)',
        matrixResiduePreimageFields: [
            'publicMatrixSeedHash',
            'profileId',
            'rnsLimbIndex',
            'commitmentModulusIndex',
            'outputCoordinateIndex',
            'inputColumn',
            'projectionTermIndex',
            'modulus',
            'blockIndex',
        ],
        projectionIndexPreimageFields: [
            'publicMatrixSeedHash',
            'profileId',
            'rnsLimbIndex',
            'commitmentModulusIndex',
            'outputCoordinateIndex',
            'inputColumn',
            'projectionTermIndex',
            'ringDegree',
            'blockIndex',
        ],
        biasBoundary:
            'matrix residues and projection indices use rejection sampling; direct modulo reduction without rejection is not part of this profile',
        coordinateCountPerCommitment,
        sampledMatrixResiduesPerCoordinate,
        sampledProjectionIndicesPerCoordinate,
        sampledMatrixResiduesPerCommitment,
        sampledProjectionIndicesPerCommitment,
        residueMultiplyAddsPerCommitment: sampledMatrixResiduesPerCommitment,
        certificateBoundary:
            'deterministic matrix-expansion profile only; binding and hiding still require reviewed Module-SIS and MLWE estimator evidence',
    };
};

export const compactVssParameterCertificateInputBinding = (input: {
    readonly participantCount: number;
    readonly sourceRnsPrimes: readonly number[];
    readonly targetRnsPrimes: readonly number[];
    readonly thresholdDegree: number;
    readonly targetBasisHash: ProtocolHash;
    readonly sameSecretProofFamilyBindingRoot: ProtocolHash;
    readonly ringDegree?: number;
}): CompactVssParameterCertificateInputBinding => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    assertProtocolHash(input.targetBasisHash, 'targetBasisHash');
    assertProtocolHash(
        input.sameSecretProofFamilyBindingRoot,
        'sameSecretProofFamilyBindingRoot',
    );
    if (input.sourceRnsPrimes.length === 0) {
        throw new Error('sourceRnsPrimes must contain at least one prime.');
    }
    const largestCommitmentModulusIndex = Math.max(
        ...compactVssCommitmentModulusLimbIndices,
    );
    if (input.sourceRnsPrimes.length <= largestCommitmentModulusIndex) {
        throw new Error(
            'sourceRnsPrimes must cover every compact VSS commitment modulus limb index.',
        );
    }
    if (input.targetRnsPrimes.length === 0) {
        throw new Error('targetRnsPrimes must contain at least one prime.');
    }
    input.sourceRnsPrimes.forEach((sourceRnsPrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            sourceRnsPrime,
            `sourceRnsPrimes.${String(rnsLimbIndex)}`,
        );
    });
    input.targetRnsPrimes.forEach((targetRnsPrime, rnsLimbIndex) => {
        assertPositiveSafeInteger(
            targetRnsPrime,
            `targetRnsPrimes.${String(rnsLimbIndex)}`,
        );
    });
    const ringDegree = input.ringDegree ?? acceptedBgvProfileRingDegree;
    assertPositiveSafeInteger(ringDegree, 'ringDegree');
    const maximumOneSourceShamirScalarL1 =
        compactVssShamirScalarL1Amplification(
            input.participantCount,
            input.thresholdDegree,
        );
    const oneRecipientAggregateShamirScalarL1 =
        maximumOneSourceShamirScalarL1 * input.participantCount;
    if (!Number.isSafeInteger(oneRecipientAggregateShamirScalarL1)) {
        throw new RangeError(
            'compact VSS aggregate Shamir scalar L1 amplification exceeds safe integer range.',
        );
    }
    const inputColumnLabels = [
        'message',
        ...Array.from(
            { length: compactVssCommitmentRandomnessColumnCount },
            (_unused, randomnessColumnIndex) =>
                `randomness:${String(randomnessColumnIndex)}`,
        ),
    ];
    const certificateInputBody = {
        objectType: 'CompactVssParameterCertificateInputBinding',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        participantCount: input.participantCount,
        sourceRnsLimbCount: input.sourceRnsPrimes.length,
        targetRnsLimbCount: input.targetRnsPrimes.length,
        thresholdDegree: input.thresholdDegree,
        ringDegree,
        commitmentRelation: {
            relation: 'C = A0 * m + A1 * r mod q_c',
            coefficientRing: 'Z_q[X]/(X^N+1)',
            commitmentModulusLimbIndices:
                compactVssCommitmentModulusLimbIndices,
            commitmentModulusLimbs: compactVssCommitmentModulusLimbIndices.map(
                (commitmentModulusIndex) => ({
                    commitmentModulusIndex,
                    modulus: input.sourceRnsPrimes[commitmentModulusIndex],
                }),
            ),
            outputCoordinateCount: compactVssCommitmentOutputCoordinateCount,
            messageWidth: 1,
            randomnessWidth: compactVssCommitmentRandomnessColumnCount,
            inputColumnLabels,
            homomorphicAdditionRule:
                'commitments combine linearly only when profile, public matrix seed, source limb, and commitment modulus order match',
            homomorphicScalarRule:
                'public Shamir and aggregation scalars multiply both message and randomness columns over the same commitment key',
        },
        commonCommitmentKey: {
            keyScope:
                'one common public matrix seed hash is used for coefficient, recipient-share, and aggregate threshold commitments',
            matrixResidueHashDomain:
                'sealed-lattice-compact-vss-commitment/matrix-residue-v1',
            projectionIndexHashDomain:
                'sealed-lattice-compact-vss-commitment/projection-index-v1',
            rejectionSamplingRule:
                'sample little-endian 64-bit chunks and reject values at or above 2^64 - (2^64 mod modulus or ringDegree)',
            matrixResiduePreimageFields: [
                'publicMatrixSeedHash',
                'profileId',
                'rnsLimbIndex',
                'commitmentModulusIndex',
                'outputCoordinateIndex',
                'inputColumn',
                'projectionTermIndex',
                'modulus',
                'blockIndex',
            ],
            projectionIndexPreimageFields: [
                'publicMatrixSeedHash',
                'profileId',
                'rnsLimbIndex',
                'commitmentModulusIndex',
                'outputCoordinateIndex',
                'inputColumn',
                'projectionTermIndex',
                'ringDegree',
                'blockIndex',
            ],
            statementBindingRule:
                'source trustee, recipient trustee, coefficient index, limb, and setup context are bound in statement roots, not by deriving incompatible matrices',
        },
        messageEncoding: {
            sourceCoefficientRepresentation:
                'canonical residue modulo the selected source RNS prime',
            targetCoefficientRepresentation:
                'canonical residue modulo the selected target RNS prime',
            signedRepresentativeConvention:
                'same-secret bridge witnesses use the setup proof signed representative convention before reduction into each RNS prime',
            digitBase: 'none',
            digitCount: 1,
            paddingAndBlockOrder:
                'one coefficient-domain residue vector per commitment, ordered by coefficient index',
            freshEncodingRule: 'exact canonical residue encoding',
            linearDecoder: 'identity over the selected RNS limb',
            derivedEncodingRule:
                'Shamir recipient-share encodings are exact residues; aggregate threshold openings bind the carried public-sum message together with the reduced share and non-negative carry witness',
        },
        normInputClasses: [
            {
                className: 'shamirScalarL1Amplification',
                maximumRecipientTrusteePoint: input.participantCount,
                shamirCoefficientCount: input.thresholdDegree,
                maximumOneSourceShamirScalarL1,
                oneRecipientAggregateShamirScalarL1,
            },
            {
                className: 'messageEncodingNorm',
                coefficientRange:
                    'source and recipient-share messages satisfy 0 <= messageCoefficient < selectedRnsPrime; aggregate commitment messages satisfy 0 <= messageCoefficient < participantCount * selectedRnsPrime',
                compressionRule:
                    'no low-bit compression or CRT packing is part of this development profile',
            },
            {
                className: 'openingRandomnessNorm',
                randomnessColumnCount:
                    compactVssCommitmentRandomnessColumnCount,
                requiredCertificateInput:
                    'certificate must bind distribution and accepted norm for every opening column',
            },
            {
                className: 'aggregateDealerCount',
                sourceTrusteeCount: input.participantCount,
                aggregationRule:
                    'one recipient aggregate threshold commitment combines every source trustee contribution for that recipient and active target limb',
            },
            {
                className: 'proofExtractedOpeningNorm',
                requiredCertificateInput:
                    'public linkage proof backend must emit extractor-bound opening norms',
            },
            {
                className: 'targetDecryptionOpeningNorm',
                requiredCertificateInput:
                    'target-decryption proof backend must bind restored compact aggregate openings for the accepted target basis',
            },
            {
                className:
                    'targetDecryptionRecombinationCoefficientAmplification',
                requiredCertificateInput:
                    'target recombination proof must bind denominator-cleared Lagrange coefficients and decoding margin',
            },
        ],
        estimatorInputRows: [
            {
                rowId: 'compact-vss-module-sis-binding-input',
                problem: 'Module-SIS',
                targetSecurityBits: 128,
                ringDegree,
                commitmentModulusLimbIndices:
                    compactVssCommitmentModulusLimbIndices,
                outputCoordinateCount:
                    compactVssCommitmentOutputCoordinateCount,
                shortVectorBoundSource:
                    'openingRandomnessNorm plus proofExtractedOpeningNorm plus aggregate Shamir scalar L1 amplification',
            },
            {
                rowId: 'compact-vss-module-lwe-hiding-input',
                problem: 'Module-LWE',
                targetSecurityBits: 128,
                ringDegree,
                commitmentModulusLimbIndices:
                    compactVssCommitmentModulusLimbIndices,
                openingDistributionSource:
                    'openingRandomnessNorm with recipient-hidden opening leakage boundary',
            },
        ],
        proofCoverageInputs: {
            shareLinkageProof:
                'one public proof per source trustee should batch every recipient and target limb for coefficient-to-recipient-share linkage',
            sameSecretBridgeProof:
                'target-basis compact constant coefficient commitments must bind to the same signed ternary trustee secret as data-basis setup proof roots',
            targetDecryptionProof:
                'recipient-owned restored compact aggregate opening material must generate the target-bound decryption share proof without dealer state',
            smudging:
                'released smudged target-decryption shares require zero-knowledge proof coverage before production activation',
            recombination:
                'target result acceptance requires denominator-cleared Lagrange recombination and decoding-margin verification',
        },
        structuredRingDisclosure:
            'structured-ring attack cost must be reviewed for the selected ring, module shape, modulus limbs, sparse projection, and common-key reuse',
        sameSecretBridgeInput: {
            targetBasisHash: input.targetBasisHash,
            targetRnsPrimes: input.targetRnsPrimes,
            sameSecretProofFamilyBindingRoot:
                input.sameSecretProofFamilyBindingRoot,
            compactCommitmentEncoding:
                'target-basis compact commitments use exact canonical residues and the shared compact matrix key',
            targetBasisLimbOrder: 'profile-order-prefix',
        },
    } as const;

    return {
        ...certificateInputBody,
        compactVssParameterCertificateInputBindingHash: deriveProtocolHash(
            'CompactVssParameterCertificateInputBindingHash',
            certificateInputBody,
        ),
    };
};

export const compactVssPrivateWitnessPayloadMeasurement = (input: {
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
    readonly ringDegree?: number;
}): CompactVssPrivateWitnessPayloadMeasurement => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.targetRnsLimbCount, 'targetRnsLimbCount');
    const ringDegree = input.ringDegree ?? acceptedBgvProfileRingDegree;
    assertPositiveSafeInteger(ringDegree, 'ringDegree');
    const bytesPerResidue = 8;
    const payloadVectorsPerCredential =
        1 + compactVssCommitmentRandomnessColumnCount;
    const aggregatePayloadVectorsPerCredential =
        3 + compactVssCommitmentRandomnessColumnCount;
    const oneSourceRecipientCredentialPayloadBytes =
        payloadVectorsPerCredential * ringDegree * bytesPerResidue;
    const oneAggregateCredentialPayloadBytes =
        aggregatePayloadVectorsPerCredential * ringDegree * bytesPerResidue;
    const oneRecipientPrivateMailboxCredentialPayloadBytes =
        input.participantCount *
        input.targetRnsLimbCount *
        oneSourceRecipientCredentialPayloadBytes;
    const oneRecipientPersistentAggregateCredentialPayloadBytes =
        input.targetRnsLimbCount * oneAggregateCredentialPayloadBytes;

    return {
        objectType: 'CompactVssPrivateWitnessPayloadMeasurement',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        developmentScope: compactVssCommitmentDevelopmentScope,
        participantCount: input.participantCount,
        targetRnsLimbCount: input.targetRnsLimbCount,
        ringDegree,
        bytesPerResidue,
        randomnessColumnCount: compactVssCommitmentRandomnessColumnCount,
        oneSourceRecipientCredentialPayloadBytes,
        oneAggregateCredentialPayloadBytes,
        oneRecipientPrivateMailboxCredentialPayloadBytes,
        oneRecipientPersistentAggregateCredentialPayloadBytes,
        allRecipientsPrivateMailboxCredentialPayloadBytes:
            input.participantCount *
            oneRecipientPrivateMailboxCredentialPayloadBytes,
        allRecipientsPersistentAggregateCredentialPayloadBytes:
            input.participantCount *
            oneRecipientPersistentAggregateCredentialPayloadBytes,
        largestSingleCredentialPayloadBytes: Math.max(
            oneSourceRecipientCredentialPayloadBytes,
            oneAggregateCredentialPayloadBytes,
        ),
        byteAccountingScope:
            'compact private opening payload vectors only: one share vector plus opening-randomness vectors for each source-recipient target limb, and one reduced share vector, one carried commitment-message vector, one carry vector, and opening-randomness vectors per persisted aggregate limb',
        excludedByteCategories: [
            'private-envelope JSON and canonical-encoding overhead',
            'mailbox KEM, AEAD, nonce, tag, and associated-data overhead',
            'source and recipient metadata fields',
            'source share and opening roots',
            'encrypted local-state wrapper overhead',
            'future target-decryption proof bytes',
        ],
    };
};
