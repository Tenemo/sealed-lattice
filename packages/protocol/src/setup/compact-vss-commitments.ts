import { deriveProtocolHash, hash512Hex } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import {
    bytesFromStandardBase64,
    bytesToStandardBase64,
} from './proof-byte-encoding.js';
import {
    acceptedBgvProfileRingDegree,
    acceptedBgvSetupQSharePrimes,
} from './vss-coefficient-commitments.js';
import type { VssSourceTrusteeCoefficientOpeningState } from './vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

type JsonRecord = Record<string, unknown>;

const twoToTheSixtyFourth = 1n << 64n;

export const compactVssCommitmentProfileId =
    'sealed-lattice-compact-vss-sparse-linear-v1';
export const compactVssCommitmentOutputCoordinateCount = 16;
export const compactVssMessageDigitCount = 2;
export const compactVssMessageDigitTritCount = 17;
export const compactVssMessageDigitBase = 3n ** 17n;
export const compactVssCommitmentRandomnessColumnCount = 2;
export const compactVssProjectionWeight = 32;
export const compactVssClaimMaskRadix = 3;
export const setupClaimMaskDigitCount = 58;
export const compactVssCarryClaimMaskDigitCount = 75;
export const compactVssDigitClaimMaskDigitCount = 87;
export const targetDecryptionAggregateMessageClaimMaskDigitCount = 142;
export const targetDecryptionSmudgingMessageClaimMaskDigitCount = 114;
export const targetDecryptionRandomnessClaimMaskDigitCount = 114;
const setupConsistencyRepetitions = 20;
const setupConsistencyCoefficientBits = 8;
const compactVssConsistencyRepetitions = 4;
const compactVssConsistencyCoefficientBits = 40;
const targetDecryptionSmudgingCoefficientBound = 16;
const targetDecryptionSmudgingMessageCoefficientBound =
    targetDecryptionSmudgingCoefficientBound * 2 + 1;
const compactVssCommitmentModulusLimbIndices = [0, 1, 2] as const;
export const compactVssCommitmentBinaryFormat =
    'sealed-lattice-compact-vss-commitment-binary-v1';
const compactVssShareLinkageStatementRelation =
    'recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments';
const setupProofProfileId = 'SealedLattice-SetupProof-v1';
const compactVssShareLinkageProofFamily = 'compact-vss-share-linkage';
const compactVssShareLinkageProofBytesHashDomain =
    'sealed-lattice/setup/compact-vss-share-linkage/proof-bytes-v1';
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

export type CompactVssCommitmentRole =
    | 'coefficient'
    | 'recipient-share'
    | 'aggregate-threshold-share'
    | 'target-decryption-smudging-polynomial-coefficient';

type CompactVssMessageCoefficient = number | bigint;

export type CompactVssCommitmentOpeningInput = Readonly<{
    readonly commitmentRole: CompactVssCommitmentRole;
    readonly commitmentContext: JsonRecord;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly messageCoefficients: readonly CompactVssMessageCoefficient[];
    readonly messageDigitColumns?: readonly (readonly CompactVssMessageCoefficient[])[];
    readonly messageCoefficientBound?: CompactVssMessageCoefficient;
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
        readonly commitmentRole: CompactVssCommitmentRole;
        readonly commitmentContextHash: ProtocolHash;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly ringDegree: number;
        readonly outputCoordinateCount: typeof compactVssCommitmentOutputCoordinateCount;
        readonly randomnessColumnCount: typeof compactVssCommitmentRandomnessColumnCount;
        readonly commitmentLimbs: readonly CompactVssCommitmentLimb[];
    }
>;

type CompactVssCommitmentComputation = Readonly<{
    readonly ok: true;
    readonly operation: 'computeCompactVssCommitmentFromOpening';
    readonly setupProfileId: 'CollectiveBgvSetup-v1';
    readonly commitment: CompactVssCommitmentValue;
    readonly commitmentRoot: ProtocolHash;
    readonly openingRoot: ProtocolHash;
    readonly commitmentContextHash: ProtocolHash;
    readonly encodedCommitmentByteLength: number;
}>;

type CompactVssCommitmentPublicComputation = Omit<
    CompactVssCommitmentComputation,
    'openingRoot'
>;

export type CompactVssCommitmentBodyMetadata = Readonly<{
    readonly commitmentRole: CompactVssCommitmentRole;
    readonly commitmentContextHash: ProtocolHash;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
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
        readonly byteReduction: Readonly<{
            readonly removedBytes: number;
            readonly compactFractionOfCurrent: number;
            readonly reductionFactor: number;
        }>;
        readonly largestSingleObjectBytes: number;
        readonly largestWasmBoundaryCopyBytes: number;
        readonly budgetComparison: Readonly<{
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
        readonly matrixKind: 'compact-vss-commitment-key';
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
        readonly coordinateCountPerCommitment: number;
        readonly sampledMatrixResiduesPerCoordinate: number;
        readonly sampledProjectionIndicesPerCoordinate: number;
        readonly sampledMatrixResiduesPerCommitment: number;
        readonly sampledProjectionIndicesPerCommitment: number;
        readonly residueMultiplyAddsPerCommitment: number;
    }
>;

export type CompactVssParameterCertificateInputBinding = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssParameterCertificateInputBinding';
        readonly objectVersion: 3;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
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
        readonly parameterReviewInputs: Readonly<Record<string, unknown>>;
        readonly estimatorInputRows: readonly Readonly<
            Record<string, unknown>
        >[];
        readonly sameSecretBridgeInput: Readonly<Record<string, unknown>>;
    }
>;

type CompactVssTrusteeReference = Readonly<{
    readonly trusteeIdentity: string;
    readonly trusteeRosterPosition: number;
}>;

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
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly publicMatrixSeedHash: ProtocolHash;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shamirCoefficientIndex: number;
        readonly coefficientCommitmentRoot: ProtocolHash;
        readonly coefficientOpeningRoot: ProtocolHash;
        readonly commitment: CompactVssCommitmentValue;
    }
>;

type CompactVssSourceCoefficientCommitments = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSourceCoefficientCommitments';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
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
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly recipientTrusteePoint: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly shareCommitmentRoot: ProtocolHash;
        readonly shareOpeningRoot: ProtocolHash;
        readonly commitment: CompactVssCommitmentValue;
    }
>;

type CompactVssSourceRecipientShareCommitments = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssSourceRecipientShareCommitments';
        readonly objectVersion: 1;
        readonly profileId: typeof compactVssCommitmentProfileId;
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
        readonly shareCommitmentMessageCarryValues: readonly number[];
        readonly shareCommitmentMessageDigitColumns?: readonly (readonly CompactVssMessageCoefficient[])[];
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
        readonly recipientIdentity: string;
        readonly recipientRosterPosition: number;
        readonly recipientTrusteePoint: number;
        readonly rnsLimbIndex: number;
        readonly rnsPrime: number;
        readonly aggregateCommitmentRoot: ProtocolHash;
        readonly aggregateOpeningRoot: ProtocolHash;
        readonly commitment: CompactVssCommitmentValue;
        readonly sourceShareCommitmentRoots: readonly ProtocolHash[];
        readonly sourceShareOpeningRoots: readonly ProtocolHash[];
    }
>;

export type CompactVssAggregateThresholdCommitmentSet = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssAggregateThresholdCommitmentSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
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
        readonly aggregateCommitmentMessageCarryValues: readonly number[];
        readonly aggregateCommitmentMessageDigitColumns: readonly (readonly CompactVssMessageCoefficient[])[];
        readonly aggregateRandomnessByColumn: readonly (readonly number[])[];
        readonly aggregateCommitmentRoot: ProtocolHash;
        readonly aggregateOpeningRoot: ProtocolHash;
        readonly sourceShareOpeningRoots: readonly ProtocolHash[];
    }
>;

type CompactVssAggregateThresholdCommitmentBundle = Readonly<{
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
}>;

export type CompactVssShareLinkageStatement = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssShareLinkageStatement';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
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
        readonly coefficientOpeningRoots: readonly ProtocolHash[];
        readonly recipientShareOpeningRoots: readonly ProtocolHash[];
        readonly aggregateThresholdCommitmentRoot: ProtocolHash;
        readonly relation: typeof compactVssShareLinkageStatementRelation;
        readonly proofBatchingRule: typeof compactVssShareLinkageProofBatchingRule;
        readonly shamirEvaluationRule: typeof compactVssShareLinkageShamirEvaluationRule;
        readonly aggregateThresholdRule: typeof compactVssShareLinkageAggregateThresholdRule;
        readonly commonKeyRule: typeof compactVssShareLinkageCommonKeyRule;
        readonly sourceStatementRoot: ProtocolHash;
    }
>;

export type CompactVssShareLinkageProofStatementItem = Readonly<{
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly sourceRnsLimbIndex: number;
    readonly sourceMessageModulus: number;
    readonly coefficientCommitmentRoots: readonly ProtocolHash[];
    readonly coefficientOpeningRoots: readonly ProtocolHash[];
    readonly coefficientCommitments: readonly CompactVssCommitmentValue[];
    readonly recipientShareCommitmentRoot: ProtocolHash;
    readonly recipientShareOpeningRoot: ProtocolHash;
    readonly recipientShareCommitment: CompactVssCommitmentValue;
}>;

export type CompactVssShareLinkageProofStatement =
    CompactVssShareLinkageProofStatementItem &
        Readonly<{
            readonly publicMatrixSeedHash: ProtocolHash;
            readonly sourceTrusteeIdentity: string;
            readonly sourceTrusteeRosterPosition: number;
            readonly sourceCoefficientCommitmentRoot: ProtocolHash;
            readonly sourceRecipientShareCommitmentRoot: ProtocolHash;
            readonly additionalLinkageItems?: readonly CompactVssShareLinkageProofStatementItem[];
        }>;

export type CompactVssShareLinkageCoverageItem = Readonly<{
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly sourceRnsLimbIndex: number;
    readonly itemIndex: number;
}>;

export type CompactVssShareLinkageProofRecordInput = Readonly<{
    readonly sourceStatementRoot: ProtocolHash;
    readonly compactVssShareLinkage: CompactVssShareLinkageProofStatement;
    readonly proofBytesHex: string;
}>;

export type CompactVssShareLinkageProofRecord = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssShareLinkageProofRecord';
        readonly objectVersion: 1;
        readonly proofFamily: typeof compactVssShareLinkageProofFamily;
        readonly sourceStatementRoot: ProtocolHash;
        readonly sourceTrusteeIdentity: string;
        readonly sourceTrusteeRosterPosition: number;
        readonly linkageItems: readonly CompactVssShareLinkageCoverageItem[];
        readonly compactVssShareLinkage: CompactVssShareLinkageProofStatement;
        readonly proofBytesHash: ProtocolHash;
        readonly proofBytesBase64: string;
        readonly proofRecordRoot: ProtocolHash;
    }
>;

export type CompactVssShareLinkageProofMaterialSet = Readonly<
    JsonRecord & {
        readonly objectType: 'CompactVssShareLinkageProofMaterialSet';
        readonly objectVersion: 1;
        readonly setupProfileId: 'CollectiveBgvSetup-v1';
        readonly profileId: typeof compactVssCommitmentProfileId;
        readonly setupProofProfileId: typeof setupProofProfileId;
        readonly proofFamily: typeof compactVssShareLinkageProofFamily;
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
        readonly ringDegree: number;
        readonly participantCount: number;
        readonly targetRnsLimbCount: number;
        readonly thresholdDegree: number;
        readonly coefficientCommitmentRoot: ProtocolHash;
        readonly recipientShareCommitmentRoot: ProtocolHash;
        readonly aggregateThresholdCommitmentRoot: ProtocolHash;
        readonly statementRoot: ProtocolHash;
        readonly proofRecords: readonly CompactVssShareLinkageProofRecord[];
        readonly proofMaterialSetRoot: ProtocolHash;
    }
>;

const protocolHashPattern = /^[0-9a-f]{128}$/u;

const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/u.test(hex)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }

    return Uint8Array.from(
        Array.from({ length: hex.length / 2 }, (_unused, byteIndex) =>
            Number.parseInt(hex.slice(byteIndex * 2, byteIndex * 2 + 2), 16),
        ),
    );
};

const compactVssShareLinkageProofBytesHash = (
    proofBytes: Uint8Array,
): ProtocolHash =>
    hash512Hex(compactVssShareLinkageProofBytesHashDomain, [proofBytes]);

const assertProtocolHash = (value: string, fieldName: string): void => {
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertProtocolHashArray = (
    value: readonly ProtocolHash[],
    expectedLength: number,
    fieldName: string,
): void => {
    const arrayValue: unknown = value;
    if (!Array.isArray(arrayValue) || value.length !== expectedLength) {
        throw new TypeError(
            `${fieldName} must contain ${String(expectedLength)} protocol hashes.`,
        );
    }
    value.forEach((entry, entryIndex) =>
        assertProtocolHash(entry, `${fieldName}.${String(entryIndex)}`),
    );
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
        value !== 'aggregate-threshold-share' &&
        value !== 'target-decryption-smudging-polynomial-coefficient'
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

const integerToBigInt = (
    value: CompactVssMessageCoefficient,
    fieldName: string,
): bigint => {
    if (typeof value === 'bigint') {
        return value;
    }
    if (!Number.isSafeInteger(value)) {
        throw new TypeError(`${fieldName} must be a safe integer.`);
    }

    return BigInt(value);
};

const assertU64Integer = (
    value: CompactVssMessageCoefficient,
    fieldName: string,
): bigint => {
    const valueWide = integerToBigInt(value, fieldName);
    if (valueWide < 0n || valueWide >= twoToTheSixtyFourth) {
        throw new TypeError(`${fieldName} must fit unsigned 64-bit encoding.`);
    }

    return valueWide;
};

const assertResidueVector = (
    values: readonly CompactVssMessageCoefficient[],
    modulus: CompactVssMessageCoefficient,
    ringDegree: number,
    fieldName: string,
): void => {
    if (values.length !== ringDegree) {
        throw new Error(`${fieldName} length must match ringDegree.`);
    }
    const modulusWide = integerToBigInt(modulus, 'modulus');
    if (modulusWide <= 0n) {
        throw new TypeError('modulus must be positive.');
    }
    values.forEach((value, valueIndex) => {
        const valueWide = integerToBigInt(
            value,
            `${fieldName}.${String(valueIndex)}`,
        );
        if (valueWide < 0n || valueWide >= modulusWide) {
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
    value: CompactVssMessageCoefficient,
): void => {
    let remainingValue = assertU64Integer(value, 'little-endian u64 value');
    for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
        bytes[offset + byteIndex] = Number(remainingValue & 0xffn);
        remainingValue >>= 8n;
    }
};

const writeLittleEndianI64 = (
    bytes: Uint8Array,
    offset: number,
    value: number,
): void => {
    let remainingValue = BigInt.asUintN(64, BigInt(value));
    for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
        bytes[offset + byteIndex] = Number(remainingValue & 0xffn);
        remainingValue >>= 8n;
    }
};

const compactVssOpeningPayloadHash = (input: {
    readonly messageCoefficients: readonly CompactVssMessageCoefficient[];
    readonly randomnessByColumn: readonly (readonly number[])[];
}): string => {
    const wordCount =
        2 +
        input.messageCoefficients.length +
        input.randomnessByColumn.reduce(
            (total, column) => total + 1 + column.length,
            0,
        );
    const bytes = new Uint8Array(wordCount * 8);
    let offset = 0;
    writeLittleEndianU64(bytes, offset, input.messageCoefficients.length);
    offset += 8;
    input.messageCoefficients.forEach((coefficient) => {
        writeLittleEndianU64(bytes, offset, coefficient);
        offset += 8;
    });
    writeLittleEndianU64(bytes, offset, input.randomnessByColumn.length);
    offset += 8;
    input.randomnessByColumn.forEach((column) => {
        writeLittleEndianU64(bytes, offset, column.length);
        offset += 8;
        column.forEach((coefficient) => {
            writeLittleEndianI64(bytes, offset, coefficient);
            offset += 8;
        });
    });

    return hash512Hex(
        'sealed-lattice-compact-vss-commitment/opening-payload-v1',
        [bytes],
    );
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

const bytesToHex = (bytes: Uint8Array): string =>
    [...bytes].map((byte) => byte.toString(16).padStart(2, '0')).join('');

const assertLowercaseHexBytes = (value: string, fieldName: string): void => {
    if (value.length === 0 || value.length % 2 !== 0) {
        throw new TypeError(
            `${fieldName} must be non-empty whole-byte lowercase hex.`,
        );
    }
    if (!/^[0-9a-f]+$/u.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex.`);
    }
};

const compactTernaryCode = (coefficient: number, fieldName: string): number => {
    if (coefficient === -1) {
        return 0;
    }
    if (coefficient === 0) {
        return 1;
    }
    if (coefficient === 1) {
        return 2;
    }

    throw new TypeError(`${fieldName} must be a ternary coefficient.`);
};

export const encodeCompactVssTernaryRandomnessColumnsHex = (
    randomnessByColumn: readonly (readonly number[])[],
    ringDegree: number,
): readonly string[] => {
    assertPositiveSafeInteger(ringDegree, 'ringDegree');
    assertOpeningRandomness(randomnessByColumn, ringDegree);
    const byteLength = Math.ceil(ringDegree / 4);

    return randomnessByColumn.map((randomnessColumn, columnIndex) => {
        const bytes = new Uint8Array(byteLength);
        randomnessColumn.forEach((coefficient, coefficientIndex) => {
            const packedByteIndex = Math.floor(coefficientIndex / 4);
            const packedBitShift = (coefficientIndex % 4) * 2;
            bytes[packedByteIndex] =
                (bytes[packedByteIndex] ?? 0) |
                (compactTernaryCode(
                    coefficient,
                    `randomnessByColumn.${String(columnIndex)}.${String(coefficientIndex)}`,
                ) <<
                    packedBitShift);
        });

        return bytesToHex(bytes);
    });
};

export const decodeCompactVssTernaryRandomnessColumnsHex = (
    packedColumnsHex: readonly string[],
    ringDegree: number,
): readonly (readonly number[])[] => {
    assertPositiveSafeInteger(ringDegree, 'ringDegree');
    if (packedColumnsHex.length !== compactVssCommitmentRandomnessColumnCount) {
        throw new Error(
            'packed compact VSS randomness must contain the compact commitment randomness column count.',
        );
    }
    const byteLength = Math.ceil(ringDegree / 4);
    const expectedHexLength = byteLength * 2;

    return packedColumnsHex.map((packedColumnHex, columnIndex) => {
        if (packedColumnHex.length !== expectedHexLength) {
            throw new Error(
                `packed compact VSS randomness column ${String(columnIndex)} length must match ringDegree.`,
            );
        }
        assertLowercaseHexBytes(
            packedColumnHex,
            `randomnessByColumnPackedTernaryHex.${String(columnIndex)}`,
        );
        const bytes = hexToBytes(packedColumnHex);
        const randomnessColumn = Array.from({ length: ringDegree }, () => 0);
        for (
            let packedCoefficientIndex = 0;
            packedCoefficientIndex < byteLength * 4;
            packedCoefficientIndex += 1
        ) {
            const packedByte = bytes[Math.floor(packedCoefficientIndex / 4)];
            if (packedByte === undefined) {
                throw new Error(
                    'packed compact VSS randomness column is shorter than expected.',
                );
            }
            const code =
                (packedByte >> ((packedCoefficientIndex % 4) * 2)) & 0b11;
            if (packedCoefficientIndex >= ringDegree) {
                if (code !== 0) {
                    throw new Error(
                        'packed compact VSS randomness padding must be zero.',
                    );
                }
                continue;
            }
            if (code === 0) {
                randomnessColumn[packedCoefficientIndex] = -1;
            } else if (code === 1) {
                randomnessColumn[packedCoefficientIndex] = 0;
            } else if (code === 2) {
                randomnessColumn[packedCoefficientIndex] = 1;
            } else {
                throw new Error(
                    `packed compact VSS randomness column ${String(columnIndex)} contains an invalid ternary code.`,
                );
            }
        }

        return randomnessColumn;
    });
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

type CompactVssRecipientShareEvaluation = Readonly<{
    readonly shareValues: readonly number[];
    readonly shareCommitmentMessageValues: readonly bigint[];
    readonly shareCommitmentMessageCarryValues: readonly number[];
}>;

const safeNumberFromBigInt = (value: bigint, fieldName: string): number => {
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(`${fieldName} exceeds the safe integer range.`);
    }

    return Number(value);
};

const maskedClaimClearBoundDecimal = (input: {
    readonly witnessInfinityBound: bigint;
    readonly ringDegree: number;
    readonly consistencyCoefficientBits: number;
}): string =>
    (
        input.witnessInfinityBound *
        BigInt(input.ringDegree) *
        ((1n << BigInt(input.consistencyCoefficientBits)) - 1n)
    ).toString();

const compactVssMessageDigitBoundExclusive = (
    messageBoundExclusive: bigint,
    digitIndex: number,
): bigint => {
    if (messageBoundExclusive <= 0n) {
        throw new Error('compact VSS message bound must be positive.');
    }
    const maximumCoefficient =
        compactVssMessageDigitBase ** BigInt(compactVssMessageDigitCount);
    if (messageBoundExclusive > maximumCoefficient) {
        throw new Error(
            'compact VSS message bound exceeds the selected two-digit range.',
        );
    }

    switch (digitIndex) {
        case 0:
            return messageBoundExclusive < compactVssMessageDigitBase
                ? messageBoundExclusive
                : compactVssMessageDigitBase;
        case 1:
            return (
                (messageBoundExclusive + compactVssMessageDigitBase - 1n) /
                compactVssMessageDigitBase
            );
        default:
            throw new Error(
                'compact VSS message digit index is outside the selected profile.',
            );
    }
};

const compactVssMaximumDigitValueForMessageBound = (
    messageBoundExclusive: bigint,
): bigint => {
    let maximumDigitValue = 0n;
    for (
        let digitIndex = 0;
        digitIndex < compactVssMessageDigitCount;
        digitIndex += 1
    ) {
        const digitMaximum =
            compactVssMessageDigitBoundExclusive(
                messageBoundExclusive,
                digitIndex,
            ) - 1n;
        if (digitMaximum > maximumDigitValue) {
            maximumDigitValue = digitMaximum;
        }
    }

    return maximumDigitValue;
};

const evaluateSourceShareForRecipient = (input: {
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly thresholdDegree: number;
    readonly ringDegree: number;
}): CompactVssRecipientShareEvaluation => {
    const openingsByCoordinate = new Map(
        input.sourceTrusteeOpeningState.coefficientOpenings.map((opening) => [
            openingCoordinateKey(
                opening.rnsLimbIndex,
                opening.shamirCoefficientIndex,
            ),
            opening,
        ]),
    );
    const shareCommitmentMessageValues = Array.from(
        { length: input.ringDegree },
        () => 0n,
    );
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
            shareCommitmentMessageValues[coefficientIndex] =
                (shareCommitmentMessageValues[coefficientIndex] ?? 0n) +
                BigInt(coefficient) * pointPower;
        });
        pointPower *= BigInt(input.recipientTrusteePoint);
    }

    const shareValues = shareCommitmentMessageValues.map(
        (shareCommitmentMessageValue, coefficientIndex) =>
            safeNumberFromBigInt(
                shareCommitmentMessageValue % modulusWide,
                `shareValues.${String(coefficientIndex)}`,
            ),
    );
    const shareCommitmentMessageCarryValues = shareCommitmentMessageValues.map(
        (shareCommitmentMessageValue, coefficientIndex) =>
            safeNumberFromBigInt(
                (shareCommitmentMessageValue -
                    BigInt(shareValues[coefficientIndex] ?? 0)) /
                    modulusWide,
                `shareCommitmentMessageCarryValues.${String(coefficientIndex)}`,
            ),
    );

    return {
        shareValues,
        shareCommitmentMessageValues,
        shareCommitmentMessageCarryValues,
    };
};

const messageValuesFromReducedResiduesAndCarries = (input: {
    readonly residues: readonly number[];
    readonly carryValues: readonly number[];
    readonly rnsPrime: number;
    readonly ringDegree: number;
    readonly fieldName: string;
}): readonly bigint[] => {
    assertResidueVector(
        input.residues,
        input.rnsPrime,
        input.ringDegree,
        `${input.fieldName}.residues`,
    );
    if (input.carryValues.length !== input.ringDegree) {
        throw new Error(`${input.fieldName}.carryValues length must match.`);
    }
    const rnsPrimeWide = BigInt(input.rnsPrime);

    return input.carryValues.map((carryValue, coefficientIndex) => {
        assertNonNegativeSafeInteger(
            carryValue,
            `${input.fieldName}.carryValues.${String(coefficientIndex)}`,
        );

        return (
            BigInt(input.residues[coefficientIndex] ?? 0) +
            BigInt(carryValue) * rnsPrimeWide
        );
    });
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
    leftValue: CompactVssMessageCoefficient,
    rightValue: number,
    modulus: number,
): bigint =>
    (accumulatedValue +
        integerToBigInt(leftValue, 'leftValue') * BigInt(rightValue)) %
    BigInt(modulus);

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
    if (commitmentRoot(commitment) !== input.expectedCommitmentRoot) {
        throw new Error(
            `${input.fieldName} canonical root must match the containing record.`,
        );
    }
};

export const compactVssCommitmentPrivateOpeningRoot = (
    input: CompactVssCommitmentOpeningInput,
): ProtocolHash =>
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
        openingPayloadHash512: compactVssOpeningPayloadHash(input),
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
        commitmentRole: metadata.commitmentRole,
        commitmentContextHash: metadata.commitmentContextHash,
        publicMatrixSeedHash: metadata.publicMatrixSeedHash,
        rnsLimbIndex: metadata.rnsLimbIndex,
        rnsPrime: metadata.rnsPrime,
        ringDegree: metadata.ringDegree,
        outputCoordinateCount: compactVssCommitmentOutputCoordinateCount,
        randomnessColumnCount: compactVssCommitmentRandomnessColumnCount,
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

const compactVssInputColumnLabels = (): readonly string[] => [
    ...Array.from(
        { length: compactVssMessageDigitCount },
        (_unused, digitIndex) => `message:${String(digitIndex)}`,
    ),
    ...Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        (_unused, randomnessColumnIndex) =>
            `randomness:${String(randomnessColumnIndex)}`,
    ),
];

const compactVssMessageDigits = (
    coefficient: CompactVssMessageCoefficient,
): readonly bigint[] => {
    const coefficientWide = integerToBigInt(coefficient, 'coefficient');
    const maximumCoefficient =
        compactVssMessageDigitBase ** BigInt(compactVssMessageDigitCount);
    if (coefficientWide < 0n || coefficientWide >= maximumCoefficient) {
        throw new Error(
            'compact VSS message coefficient exceeds the full-message coordinate range.',
        );
    }

    let remainingCoefficient = coefficientWide;
    return Array.from({ length: compactVssMessageDigitCount }, () => {
        const digit = remainingCoefficient % compactVssMessageDigitBase;
        remainingCoefficient /= compactVssMessageDigitBase;
        return digit;
    });
};

function compactVssMessageDigitColumnsForOpening(input: {
    readonly messageCoefficients: readonly CompactVssMessageCoefficient[];
    readonly messageDigitColumns: readonly (readonly CompactVssMessageCoefficient[])[];
    readonly messageCoefficientBound: CompactVssMessageCoefficient;
    readonly ringDegree: number;
}): readonly (readonly bigint[])[] {
    if (input.messageDigitColumns.length !== compactVssMessageDigitCount) {
        throw new Error(
            'compact VSS messageDigitColumns must contain the selected message digit count.',
        );
    }
    const normalizedColumns = input.messageDigitColumns.map(
        (column, digitIndex) => {
            if (column.length !== input.ringDegree) {
                throw new Error(
                    `compact VSS messageDigitColumns.${String(digitIndex)} length must match ringDegree.`,
                );
            }

            return column.map((coefficient, coefficientIndex) =>
                assertU64Integer(
                    coefficient,
                    `messageDigitColumns.${String(digitIndex)}.${String(coefficientIndex)}`,
                ),
            );
        },
    );

    input.messageCoefficients.forEach((coefficient, coefficientIndex) => {
        let decoded = 0n;
        let digitWeight = 1n;
        normalizedColumns.forEach((column) => {
            decoded += (column[coefficientIndex] ?? 0n) * digitWeight;
            digitWeight *= compactVssMessageDigitBase;
        });
        const expected = integerToBigInt(
            coefficient,
            `messageCoefficients.${String(coefficientIndex)}`,
        );
        const messageCoefficientBound = integerToBigInt(
            input.messageCoefficientBound,
            'messageCoefficientBound',
        );
        if (
            decoded !== expected ||
            decoded < 0n ||
            decoded >= messageCoefficientBound
        ) {
            throw new Error(
                `compact VSS message digit columns do not decode to messageCoefficients.${String(coefficientIndex)}.`,
            );
        }
    });

    return normalizedColumns;
}

const compactVssDerivedRecipientMessageCoefficientBound = (
    rnsPrime: number,
    recipientTrusteePoint: number,
    thresholdDegree: number,
): bigint =>
    BigInt(rnsPrime) *
    BigInt(
        compactVssShamirScalarL1Amplification(
            recipientTrusteePoint,
            thresholdDegree,
        ),
    );

const compactVssMessageCoefficientBoundFromValues = (
    messageCoefficients: readonly CompactVssMessageCoefficient[],
): bigint => {
    const maximumValue = messageCoefficients.reduce<bigint>(
        (currentMaximum, coefficient, coefficientIndex) => {
            const coefficientValue = integerToBigInt(
                coefficient,
                `messageCoefficients.${String(coefficientIndex)}`,
            );
            return coefficientValue > currentMaximum
                ? coefficientValue
                : currentMaximum;
        },
        0n,
    );
    const bound = maximumValue + 1n;
    if (bound > twoToTheSixtyFourth) {
        throw new RangeError(
            'compact VSS explicit message coefficient bound exceeds unsigned 64-bit encoding.',
        );
    }

    return bound;
};

export const verifyCompactVssAggregateOpeningCredential = (input: {
    readonly credential: CompactVssAggregateThresholdOpeningCredential;
    readonly participantCount: number;
    readonly ringDegree: number;
}): CompactVssAggregateThresholdOpeningCredential => {
    assertPositiveSafeInteger(input.participantCount, 'participantCount');
    assertPositiveSafeInteger(input.ringDegree, 'ringDegree');
    assertResidueVector(
        input.credential.aggregateShareValues,
        input.credential.rnsPrime,
        input.ringDegree,
        'aggregateShareValues',
    );
    const aggregateCommitmentMessageValues =
        messageValuesFromReducedResiduesAndCarries({
            residues: input.credential.aggregateShareValues,
            carryValues: input.credential.aggregateCommitmentMessageCarryValues,
            rnsPrime: input.credential.rnsPrime,
            ringDegree: input.ringDegree,
            fieldName: 'aggregateCommitmentMessage',
        });
    compactVssMessageDigitColumnsForOpening({
        messageCoefficients: aggregateCommitmentMessageValues,
        messageDigitColumns:
            input.credential.aggregateCommitmentMessageDigitColumns,
        messageCoefficientBound: compactVssMessageCoefficientBoundFromValues(
            aggregateCommitmentMessageValues,
        ),
        ringDegree: input.ringDegree,
    });
    return input.credential;
};

const emptyCompactVssMessageDigitColumnSums = (
    ringDegree: number,
): bigint[][] =>
    Array.from({ length: compactVssMessageDigitCount }, () =>
        Array.from({ length: ringDegree }, () => 0n),
    );

const addCanonicalMessageDigitsToColumnSums = (
    columnSums: bigint[][],
    messageCoefficients: readonly CompactVssMessageCoefficient[],
): void => {
    messageCoefficients.forEach((coefficient, coefficientIndex) => {
        const digits = compactVssMessageDigits(coefficient);
        digits.forEach((digit, digitIndex) => {
            const column = columnSums[digitIndex];
            if (column === undefined) {
                throw new Error(
                    'compact VSS message digit column is outside the selected profile.',
                );
            }
            column[coefficientIndex] = (column[coefficientIndex] ?? 0n) + digit;
        });
    });
};

const addMessageDigitColumnsToColumnSums = (
    columnSums: bigint[][],
    messageDigitColumns: readonly (readonly CompactVssMessageCoefficient[])[],
    ringDegree: number,
): void => {
    if (messageDigitColumns.length !== compactVssMessageDigitCount) {
        throw new Error(
            'compact VSS message digit columns must contain the selected digit count.',
        );
    }
    messageDigitColumns.forEach((column, digitIndex) => {
        if (column.length !== ringDegree) {
            throw new Error(
                `compact VSS message digit columns.${String(digitIndex)} length must match ringDegree.`,
            );
        }
        const targetColumn = columnSums[digitIndex];
        if (targetColumn === undefined) {
            throw new Error(
                'compact VSS message digit column is outside the selected profile.',
            );
        }
        column.forEach((digit, coefficientIndex) => {
            targetColumn[coefficientIndex] =
                (targetColumn[coefficientIndex] ?? 0n) +
                assertU64Integer(
                    digit,
                    `messageDigitColumns.${String(digitIndex)}.${String(coefficientIndex)}`,
                );
        });
    });
};

const compactVssMessageDigitColumnLabel = (digitIndex: number): string => {
    if (
        !Number.isSafeInteger(digitIndex) ||
        digitIndex < 0 ||
        digitIndex >= compactVssMessageDigitCount
    ) {
        throw new Error(
            'compact VSS message digit index is outside the selected profile.',
        );
    }

    return `message:${String(digitIndex)}`;
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
    if (
        integerToBigInt(messageCoefficientBound, 'messageCoefficientBound') <=
        0n
    ) {
        throw new TypeError('messageCoefficientBound must be positive.');
    }
    assertResidueVector(
        input.messageCoefficients,
        messageCoefficientBound,
        input.ringDegree,
        'messageCoefficients',
    );
    const explicitMessageDigitColumns =
        input.messageDigitColumns === undefined
            ? undefined
            : compactVssMessageDigitColumnsForOpening({
                  messageCoefficients: input.messageCoefficients,
                  messageDigitColumns: input.messageDigitColumns,
                  messageCoefficientBound,
                  ringDegree: input.ringDegree,
              });
    if (explicitMessageDigitColumns === undefined) {
        input.messageCoefficients.forEach((coefficient) => {
            compactVssMessageDigits(coefficient);
        });
    }
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
                    for (
                        let digitIndex = 0;
                        digitIndex < compactVssMessageDigitCount;
                        digitIndex += 1
                    ) {
                        compactProjectionTerms({
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            rnsLimbIndex: input.rnsLimbIndex,
                            commitmentModulusIndex,
                            outputCoordinateIndex,
                            inputColumn:
                                compactVssMessageDigitColumnLabel(digitIndex),
                            ringDegree: input.ringDegree,
                            modulus,
                        }).forEach(
                            ({ ringCoefficientIndex, matrixResidue }) => {
                                const messageDigit =
                                    explicitMessageDigitColumns === undefined
                                        ? (compactVssMessageDigits(
                                              input.messageCoefficients[
                                                  ringCoefficientIndex
                                              ] ?? 0,
                                          )[digitIndex] ?? 0n)
                                        : (explicitMessageDigitColumns[
                                              digitIndex
                                          ]?.[ringCoefficientIndex] ?? 0n);
                                accumulator = addProductMod(
                                    accumulator,
                                    messageDigit,
                                    matrixResidue,
                                    modulus,
                                );
                            },
                        );
                    }
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
        commitmentRole: input.commitmentRole,
        commitmentContextHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        rnsLimbIndex: input.rnsLimbIndex,
        rnsPrime: input.rnsPrime,
        ringDegree: input.ringDegree,
        outputCoordinateCount: compactVssCommitmentOutputCoordinateCount,
        randomnessColumnCount: compactVssCommitmentRandomnessColumnCount,
        commitmentLimbs,
    } satisfies CompactVssCommitmentValue;

    return {
        ok: true,
        operation: 'computeCompactVssCommitmentFromOpening',
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitment,
        commitmentRoot: commitmentRoot(commitment),
        openingRoot: compactVssCommitmentPrivateOpeningRoot(input),
        commitmentContextHash,
        encodedCommitmentByteLength: compactVssEncodedCommitmentByteLength(),
    };
};

export const verifyCompactVssCommitmentOpening = (input: {
    readonly opening: CompactVssCommitmentOpeningInput;
    readonly expectedCommitmentRoot: ProtocolHash;
    readonly expectedOpeningRoot: ProtocolHash;
}): CompactVssCommitmentOpeningVerification => {
    const computation = computeCompactVssCommitmentFromOpening(input.opening);
    if (computation.commitmentRoot !== input.expectedCommitmentRoot) {
        throw new Error(
            'compact VSS commitment opening does not match the expected commitment root.',
        );
    }
    if (computation.openingRoot !== input.expectedOpeningRoot) {
        throw new Error(
            'compact VSS commitment opening does not match the expected opening root.',
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
                const compactCoefficientOpening = {
                    commitmentRole: 'coefficient',
                    commitmentContext,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    rnsLimbIndex,
                    rnsPrime,
                    ringDegree: input.ringDegree,
                    messageCoefficients: coefficientOpening.coefficientMessage,
                    randomnessByColumn,
                } satisfies CompactVssCommitmentOpeningInput;
                const commitment = computeCompactVssCommitmentFromOpening(
                    compactCoefficientOpening,
                );
                const coefficientOpeningRoot =
                    compactVssCommitmentPrivateOpeningRoot(
                        compactCoefficientOpening,
                    );
                coefficientCommitments.push({
                    objectType: 'CompactVssCoefficientCommitment',
                    objectVersion: 1,
                    profileId: compactVssCommitmentProfileId,
                    sourceTrusteeIdentity:
                        sourceTrusteeOpeningState.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex,
                    coefficientCommitmentRoot: commitment.commitmentRoot,
                    coefficientOpeningRoot,
                    commitment: commitment.commitment,
                });
            }
        });

        const sourceRecordWithoutRoot = {
            objectType: 'CompactVssSourceCoefficientCommitments',
            objectVersion: 1,
            profileId: compactVssCommitmentProfileId,
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
                    assertProtocolHash(
                        coefficientCommitment.coefficientOpeningRoot,
                        'compact VSS coefficient commitment coefficientOpeningRoot',
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

const shamirEvaluationScalars = (input: {
    readonly recipientTrusteePoint: number;
    readonly thresholdDegree: number;
}): readonly number[] => {
    assertPositiveSafeInteger(
        input.recipientTrusteePoint,
        'recipientTrusteePoint',
    );
    assertPositiveSafeInteger(input.thresholdDegree, 'thresholdDegree');
    const scalars: number[] = [];
    let pointPower = 1n;
    const recipientTrusteePointWide = BigInt(input.recipientTrusteePoint);
    for (
        let shamirCoefficientIndex = 0;
        shamirCoefficientIndex < input.thresholdDegree;
        shamirCoefficientIndex += 1
    ) {
        scalars.push(
            safeNumberFromBigInt(
                pointPower,
                `shamirScalars.${String(shamirCoefficientIndex)}`,
            ),
        );
        pointPower *= recipientTrusteePointWide;
    }

    return scalars;
};

const recipientShareCommitmentContext = (input: {
    readonly setupContextFields: JsonRecord;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
}): JsonRecord => ({
    objectType: 'CompactVssRecipientShareCommitmentContext',
    objectVersion: 1,
    ...input.setupContextFields,
    sourceTrusteeIdentity: input.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
    recipientIdentity: input.recipientIdentity,
    recipientRosterPosition: input.recipientRosterPosition,
    rnsLimbIndex: input.rnsLimbIndex,
    rnsPrime: input.rnsPrime,
});

const derivedRecipientShareCommitmentContext = (input: {
    readonly setupContextFields: JsonRecord;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
}): JsonRecord => ({
    objectType: 'CompactVssDerivedRecipientShareCommitmentContext',
    objectVersion: 1,
    ...input.setupContextFields,
    sourceTrusteeIdentity: input.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
    recipientIdentity: input.recipientIdentity,
    recipientRosterPosition: input.recipientRosterPosition,
    rnsLimbIndex: input.rnsLimbIndex,
    rnsPrime: input.rnsPrime,
});

const deriveRecipientShareRandomnessColumns = (input: {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly thresholdDegree: number;
    readonly ringDegree: number;
    readonly coefficientOpeningRandomness: CompactVssCoefficientOpeningRandomnessProvider;
}): readonly (readonly number[])[] => {
    const sums = Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        () => Array.from({ length: input.ringDegree }, () => 0),
    );
    const scalars = shamirEvaluationScalars({
        recipientTrusteePoint: input.recipientTrusteePoint,
        thresholdDegree: input.thresholdDegree,
    });
    scalars.forEach((scalar, shamirCoefficientIndex) => {
        const randomnessByColumn = input.coefficientOpeningRandomness({
            trusteeIdentity: input.sourceTrusteeIdentity,
            trusteeRosterPosition: input.sourceTrusteeRosterPosition,
            rnsLimbIndex: input.rnsLimbIndex,
            rnsPrime: input.rnsPrime,
            shamirCoefficientIndex,
            ringDegree: input.ringDegree,
        });
        assertOpeningRandomness(randomnessByColumn, input.ringDegree);
        randomnessByColumn.forEach((randomnessColumn, columnIndex) => {
            const targetColumn = sums[columnIndex];
            if (targetColumn === undefined) {
                throw new Error(
                    'compact VSS randomness column is outside the selected profile.',
                );
            }
            randomnessColumn.forEach((coefficient, coefficientIndex) => {
                const combinedCoefficient =
                    (targetColumn[coefficientIndex] ?? 0) +
                    coefficient * scalar;
                assertSignedSafeInteger(
                    combinedCoefficient,
                    `recipientShareRandomness.${String(columnIndex)}.${String(coefficientIndex)}`,
                );
                targetColumn[coefficientIndex] = combinedCoefficient;
            });
        });
    });

    return sums;
};

const recipientShareFreshRandomnessColumns = (input: {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly ringDegree: number;
}): readonly (readonly number[])[] => {
    let blockIndex = 0;
    let digestBytes: Uint8Array<ArrayBufferLike> = new Uint8Array();
    let digestOffset = 0;
    const nextTernaryCoefficient = (): number => {
        for (;;) {
            if (digestOffset >= digestBytes.byteLength) {
                digestBytes = bytesFromHex(
                    hash512Hex(
                        'sealed-lattice/compact-vss/recipient-share-randomness-v1',
                        [
                            new TextEncoder().encode(
                                [
                                    input.sourceTrusteeIdentity,
                                    String(input.sourceTrusteeRosterPosition),
                                    input.recipientIdentity,
                                    String(input.recipientRosterPosition),
                                    String(input.recipientTrusteePoint),
                                    String(input.rnsLimbIndex),
                                    String(input.rnsPrime),
                                    String(input.ringDegree),
                                    String(blockIndex),
                                ].join('|'),
                            ),
                        ],
                    ),
                    'recipient share randomness digest',
                );
                digestOffset = 0;
                blockIndex += 1;
            }
            const candidate = digestBytes[digestOffset];
            digestOffset += 1;
            if (candidate !== undefined && candidate < 252) {
                return (candidate % 3) - 1;
            }
        }
    };

    return Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        () =>
            Array.from({ length: input.ringDegree }, () =>
                nextTernaryCoefficient(),
            ),
    );
};

const coefficientOpeningsByCoordinate = (
    sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState,
): ReadonlyMap<
    string,
    VssSourceTrusteeCoefficientOpeningState['coefficientOpenings'][number]
> =>
    new Map(
        sourceTrusteeOpeningState.coefficientOpenings.map((opening) => [
            openingCoordinateKey(
                opening.rnsLimbIndex,
                opening.shamirCoefficientIndex,
            ),
            opening,
        ]),
    );

const deriveRecipientShareMessageDigitColumns = (input: {
    readonly sourceTrusteeOpeningState: VssSourceTrusteeCoefficientOpeningState;
    readonly recipientTrusteePoint: number;
    readonly rnsLimbIndex: number;
    readonly rnsPrime: number;
    readonly thresholdDegree: number;
    readonly ringDegree: number;
}): readonly (readonly bigint[])[] => {
    const openingsByCoordinate = coefficientOpeningsByCoordinate(
        input.sourceTrusteeOpeningState,
    );
    const columnSums = emptyCompactVssMessageDigitColumnSums(input.ringDegree);
    const scalars = shamirEvaluationScalars({
        recipientTrusteePoint: input.recipientTrusteePoint,
        thresholdDegree: input.thresholdDegree,
    });
    scalars.forEach((scalar, shamirCoefficientIndex) => {
        const opening = openingsByCoordinate.get(
            openingCoordinateKey(input.rnsLimbIndex, shamirCoefficientIndex),
        );
        if (opening === undefined) {
            throw new Error(
                'source trustee coefficient openings must cover every derived compact VSS share coordinate.',
            );
        }
        assertResidueVector(
            opening.coefficientMessage,
            input.rnsPrime,
            input.ringDegree,
            'coefficientMessage',
        );
        opening.coefficientMessage.forEach((coefficient, coefficientIndex) => {
            compactVssMessageDigits(coefficient).forEach(
                (digit, digitIndex) => {
                    const column = columnSums[digitIndex];
                    if (column === undefined) {
                        throw new Error(
                            'compact VSS message digit column is outside the selected profile.',
                        );
                    }
                    column[coefficientIndex] =
                        (column[coefficientIndex] ?? 0n) +
                        digit * BigInt(scalar);
                },
            );
        });
    });

    return columnSums;
};

const recipientShareOpeningFromCredential = (input: {
    readonly setupContextFields: JsonRecord;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly credential: CompactVssRecipientShareOpeningCredential;
    readonly ringDegree: number;
}): CompactVssCommitmentOpeningInput => {
    const messageCoefficients =
        input.credential.shareCommitmentMessageDigitColumns === undefined
            ? input.credential.shareValues
            : messageValuesFromReducedResiduesAndCarries({
                  residues: input.credential.shareValues,
                  carryValues:
                      input.credential.shareCommitmentMessageCarryValues,
                  rnsPrime: input.credential.rnsPrime,
                  ringDegree: input.ringDegree,
                  fieldName: 'recipientShareOpeningCredential',
              });
    return {
        commitmentRole: 'recipient-share',
        commitmentContext:
            input.credential.shareCommitmentMessageDigitColumns === undefined
                ? recipientShareCommitmentContext({
                      setupContextFields: input.setupContextFields,
                      sourceTrusteeIdentity:
                          input.credential.sourceTrusteeIdentity,
                      sourceTrusteeRosterPosition:
                          input.credential.sourceTrusteeRosterPosition,
                      recipientIdentity: input.credential.recipientIdentity,
                      recipientRosterPosition:
                          input.credential.recipientRosterPosition,
                      rnsLimbIndex: input.credential.rnsLimbIndex,
                      rnsPrime: input.credential.rnsPrime,
                  })
                : derivedRecipientShareCommitmentContext({
                      setupContextFields: input.setupContextFields,
                      sourceTrusteeIdentity:
                          input.credential.sourceTrusteeIdentity,
                      sourceTrusteeRosterPosition:
                          input.credential.sourceTrusteeRosterPosition,
                      recipientIdentity: input.credential.recipientIdentity,
                      recipientRosterPosition:
                          input.credential.recipientRosterPosition,
                      rnsLimbIndex: input.credential.rnsLimbIndex,
                      rnsPrime: input.credential.rnsPrime,
                  }),
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        rnsLimbIndex: input.credential.rnsLimbIndex,
        rnsPrime: input.credential.rnsPrime,
        ringDegree: input.ringDegree,
        messageCoefficients,
        messageDigitColumns:
            input.credential.shareCommitmentMessageDigitColumns,
        messageCoefficientBound:
            input.credential.shareCommitmentMessageDigitColumns === undefined
                ? input.credential.rnsPrime
                : compactVssMessageCoefficientBoundFromValues(
                      messageCoefficients,
                  ),
        randomnessByColumn: input.credential.randomnessByColumn,
    };
};

const assertCompatibleCommitment = (
    leftCommitment: CompactVssCommitmentValue,
    rightCommitment: CompactVssCommitmentValue,
): void => {
    const fields: (keyof CompactVssCommitmentValue)[] = [
        'profileId',
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

export function combineCompactVssCommitments(
    input: CompactVssCommitmentHomomorphicCombinationInput,
): CompactVssCommitmentPublicComputation {
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
        commitmentLimbs,
    } satisfies CompactVssCommitmentValue;

    return {
        ok: true,
        operation: 'computeCompactVssCommitmentFromOpening',
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitment,
        commitmentRoot: commitmentRoot(commitment),
        commitmentContextHash,
        encodedCommitmentByteLength: compactVssEncodedCommitmentByteLength(),
    };
}

export const createCompactVssRecipientShareCommitmentBundle = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
    readonly recipientTrustees: readonly CompactVssTrusteeReference[];
    readonly coefficientOpeningRandomness: CompactVssCoefficientOpeningRandomnessProvider;
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
    const coefficientCommitmentSet = verifyCompactVssCoefficientCommitmentSet({
        coefficientCommitmentSet: input.coefficientCommitmentSet,
    });
    if (
        coefficientCommitmentSet.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        coefficientCommitmentSet.participantCount !== input.participantCount ||
        coefficientCommitmentSet.rnsLimbCount !== input.qSharePrimes.length ||
        coefficientCommitmentSet.thresholdDegree !== input.thresholdDegree ||
        coefficientCommitmentSet.ringDegree !== input.ringDegree
    ) {
        throw new Error(
            'compact VSS coefficient commitment set must match the recipient-share commitment inputs.',
        );
    }
    const sourceTrusteeRecords: CompactVssSourceRecipientShareCommitments[] =
        [];
    const recipientShareOpeningCredentials: CompactVssRecipientShareOpeningCredential[] =
        [];

    sortedSourceTrusteeOpeningStates({
        participantCount: input.participantCount,
        sourceTrusteeOpeningStates: input.sourceTrusteeOpeningStates,
    }).forEach((sourceTrusteeOpeningState, sourceRecordIndex) => {
        const coefficientSourceRecord =
            coefficientCommitmentSet.sourceTrusteeRecords[sourceRecordIndex];
        if (
            coefficientSourceRecord?.sourceTrusteeIdentity !==
                sourceTrusteeOpeningState.sourceTrusteeIdentity ||
            coefficientSourceRecord.sourceTrusteeRosterPosition !==
                sourceTrusteeOpeningState.sourceTrusteeRosterPosition
        ) {
            throw new Error(
                'compact VSS recipient-share commitments must use matching source coefficient commitment records.',
            );
        }
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
                    const shareEvaluation = evaluateSourceShareForRecipient({
                        sourceTrusteeOpeningState,
                        recipientTrusteePoint,
                        rnsLimbIndex,
                        rnsPrime,
                        thresholdDegree: input.thresholdDegree,
                        ringDegree: input.ringDegree,
                    });
                    const randomnessByColumn =
                        recipientShareFreshRandomnessColumns({
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
                            ringDegree: input.ringDegree,
                        });
                    const commitmentContext = recipientShareCommitmentContext({
                        setupContextFields: setupContextFields(
                            input.setupContext,
                        ),
                        sourceTrusteeIdentity:
                            sourceTrusteeOpeningState.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                        recipientIdentity: recipientTrustee.trusteeIdentity,
                        recipientRosterPosition:
                            recipientTrustee.trusteeRosterPosition,
                        rnsLimbIndex,
                        rnsPrime,
                    });
                    const recipientShareOpening = {
                        commitmentRole: 'recipient-share',
                        commitmentContext,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        rnsLimbIndex,
                        rnsPrime,
                        ringDegree: input.ringDegree,
                        messageCoefficients: shareEvaluation.shareValues,
                        messageCoefficientBound: rnsPrime,
                        randomnessByColumn,
                    } satisfies CompactVssCommitmentOpeningInput;
                    const directCommitment =
                        computeCompactVssCommitmentFromOpening(
                            recipientShareOpening,
                        );
                    const shareOpeningRoot =
                        compactVssCommitmentPrivateOpeningRoot(
                            recipientShareOpening,
                        );
                    const recordWithoutRoot = {
                        objectType: 'CompactVssRecipientShareCommitment',
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
                        shareCommitmentRoot: directCommitment.commitmentRoot,
                        shareOpeningRoot,
                        commitment: directCommitment.commitment,
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
                        shareValues: shareEvaluation.shareValues,
                        shareCommitmentMessageCarryValues:
                            shareEvaluation.shareCommitmentMessageCarryValues,
                        randomnessByColumn,
                        shareCommitmentRoot: directCommitment.commitmentRoot,
                        shareOpeningRoot,
                    });
                });
            });
        const sourceRecordWithoutRoot = {
            objectType: 'CompactVssSourceRecipientShareCommitments',
            objectVersion: 1,
            profileId: compactVssCommitmentProfileId,
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

export const createCompactVssDerivedRecipientShareCommitmentBundle = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly participantCount: number;
    readonly qSharePrimes: readonly number[];
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly derivedRnsLimbCount?: number;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly sourceTrusteeOpeningStates: readonly VssSourceTrusteeCoefficientOpeningState[];
    readonly recipientTrustees: readonly CompactVssTrusteeReference[];
    readonly coefficientOpeningRandomness: CompactVssCoefficientOpeningRandomnessProvider;
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
    const derivedRnsLimbCount =
        input.derivedRnsLimbCount ?? input.qSharePrimes.length;
    if (
        !Number.isSafeInteger(derivedRnsLimbCount) ||
        derivedRnsLimbCount <= 0 ||
        derivedRnsLimbCount > input.qSharePrimes.length
    ) {
        throw new TypeError(
            'derivedRnsLimbCount must be a positive safe integer within the Q_share limb count.',
        );
    }
    const coefficientCommitmentSet = verifyCompactVssCoefficientCommitmentSet({
        coefficientCommitmentSet: input.coefficientCommitmentSet,
    });
    if (
        coefficientCommitmentSet.publicMatrixSeedHash !==
            input.publicMatrixSeedHash ||
        coefficientCommitmentSet.participantCount !== input.participantCount ||
        coefficientCommitmentSet.rnsLimbCount !== input.qSharePrimes.length ||
        coefficientCommitmentSet.thresholdDegree !== input.thresholdDegree ||
        coefficientCommitmentSet.ringDegree !== input.ringDegree
    ) {
        throw new Error(
            'compact VSS coefficient commitment set must match the derived recipient-share commitment inputs.',
        );
    }

    const setupFields = setupContextFields(input.setupContext);
    const sourceTrusteeRecords: CompactVssSourceRecipientShareCommitments[] =
        [];
    const recipientShareOpeningCredentials: CompactVssRecipientShareOpeningCredential[] =
        [];

    sortedSourceTrusteeOpeningStates({
        participantCount: input.participantCount,
        sourceTrusteeOpeningStates: input.sourceTrusteeOpeningStates,
    }).forEach((sourceTrusteeOpeningState, sourceRecordIndex) => {
        const coefficientSourceRecord =
            coefficientCommitmentSet.sourceTrusteeRecords[sourceRecordIndex];
        if (
            coefficientSourceRecord?.sourceTrusteeIdentity !==
                sourceTrusteeOpeningState.sourceTrusteeIdentity ||
            coefficientSourceRecord.sourceTrusteeRosterPosition !==
                sourceTrusteeOpeningState.sourceTrusteeRosterPosition
        ) {
            throw new Error(
                'compact VSS derived recipient-share commitments must use matching source coefficient commitment records.',
            );
        }
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
                const shamirScalars = shamirEvaluationScalars({
                    recipientTrusteePoint,
                    thresholdDegree: input.thresholdDegree,
                });
                input.qSharePrimes
                    .slice(0, derivedRnsLimbCount)
                    .forEach((rnsPrime, rnsLimbIndex) => {
                        const shareEvaluation = evaluateSourceShareForRecipient(
                            {
                                sourceTrusteeOpeningState,
                                recipientTrusteePoint,
                                rnsLimbIndex,
                                rnsPrime,
                                thresholdDegree: input.thresholdDegree,
                                ringDegree: input.ringDegree,
                            },
                        );
                        const messageDigitColumns =
                            deriveRecipientShareMessageDigitColumns({
                                sourceTrusteeOpeningState,
                                recipientTrusteePoint,
                                rnsLimbIndex,
                                rnsPrime,
                                thresholdDegree: input.thresholdDegree,
                                ringDegree: input.ringDegree,
                            });
                        const randomnessByColumn =
                            deriveRecipientShareRandomnessColumns({
                                sourceTrusteeIdentity:
                                    sourceTrusteeOpeningState.sourceTrusteeIdentity,
                                sourceTrusteeRosterPosition:
                                    sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                                recipientTrusteePoint,
                                rnsLimbIndex,
                                rnsPrime,
                                thresholdDegree: input.thresholdDegree,
                                ringDegree: input.ringDegree,
                                coefficientOpeningRandomness:
                                    input.coefficientOpeningRandomness,
                            });
                        const commitmentContext =
                            derivedRecipientShareCommitmentContext({
                                setupContextFields: setupFields,
                                sourceTrusteeIdentity:
                                    sourceTrusteeOpeningState.sourceTrusteeIdentity,
                                sourceTrusteeRosterPosition:
                                    sourceTrusteeOpeningState.sourceTrusteeRosterPosition,
                                recipientIdentity:
                                    recipientTrustee.trusteeIdentity,
                                recipientRosterPosition:
                                    recipientTrustee.trusteeRosterPosition,
                                rnsLimbIndex,
                                rnsPrime,
                            });
                        const recipientShareOpening = {
                            commitmentRole: 'recipient-share',
                            commitmentContext,
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            rnsLimbIndex,
                            rnsPrime,
                            ringDegree: input.ringDegree,
                            messageCoefficients:
                                shareEvaluation.shareCommitmentMessageValues,
                            messageDigitColumns,
                            messageCoefficientBound:
                                compactVssDerivedRecipientMessageCoefficientBound(
                                    rnsPrime,
                                    recipientTrusteePoint,
                                    input.thresholdDegree,
                                ),
                            randomnessByColumn,
                        } satisfies CompactVssCommitmentOpeningInput;
                        const directCommitment =
                            computeCompactVssCommitmentFromOpening(
                                recipientShareOpening,
                            );
                        const coefficientCommitments =
                            coefficientSourceRecord.coefficientCommitments
                                .filter(
                                    (record) =>
                                        record.rnsLimbIndex === rnsLimbIndex,
                                )
                                .sort(
                                    (leftRecord, rightRecord) =>
                                        leftRecord.shamirCoefficientIndex -
                                        rightRecord.shamirCoefficientIndex,
                                );
                        if (
                            coefficientCommitments.length !==
                            input.thresholdDegree
                        ) {
                            throw new Error(
                                'compact VSS derived recipient-share commitments need every source coefficient commitment for the selected limb.',
                            );
                        }
                        const combinedCommitment = combineCompactVssCommitments(
                            {
                                commitmentRole: 'recipient-share',
                                commitmentContext,
                                terms: coefficientCommitments.map(
                                    (
                                        coefficientCommitment,
                                        coefficientIndex,
                                    ) => {
                                        if (
                                            coefficientCommitment.shamirCoefficientIndex !==
                                            coefficientIndex
                                        ) {
                                            throw new Error(
                                                'compact VSS source coefficient commitments must be ordered by Shamir coefficient.',
                                            );
                                        }

                                        return {
                                            commitment:
                                                coefficientCommitment.commitment,
                                            scalar:
                                                shamirScalars[
                                                    coefficientIndex
                                                ] ?? 0,
                                        };
                                    },
                                ),
                            },
                        );
                        if (
                            combinedCommitment.commitmentRoot !==
                            directCommitment.commitmentRoot
                        ) {
                            throw new Error(
                                'compact VSS derived recipient-share commitment does not match the homomorphic coefficient commitment combination.',
                            );
                        }
                        const shareOpeningRoot =
                            compactVssCommitmentPrivateOpeningRoot(
                                recipientShareOpening,
                            );
                        sourceRecordCommitments.push({
                            objectType: 'CompactVssRecipientShareCommitment',
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
                            shareCommitmentRoot:
                                directCommitment.commitmentRoot,
                            shareOpeningRoot,
                            commitment: directCommitment.commitment,
                        });
                        recipientShareOpeningCredentials.push({
                            objectType:
                                'CompactVssRecipientShareOpeningCredential',
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
                            shareValues: shareEvaluation.shareValues,
                            shareCommitmentMessageCarryValues:
                                shareEvaluation.shareCommitmentMessageCarryValues,
                            shareCommitmentMessageDigitColumns:
                                messageDigitColumns,
                            randomnessByColumn,
                            shareCommitmentRoot:
                                directCommitment.commitmentRoot,
                            shareOpeningRoot,
                        });
                    });
            });
        const sourceRecordWithoutRoot = {
            objectType: 'CompactVssSourceRecipientShareCommitments',
            objectVersion: 1,
            profileId: compactVssCommitmentProfileId,
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
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        participantCount: input.participantCount,
        rnsLimbCount: derivedRnsLimbCount,
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
                    assertCompactVssCommitmentBody({
                        commitment: recipientShareCommitment.commitment,
                        expectedCommitmentRole: 'recipient-share',
                        expectedCommitmentRoot:
                            recipientShareCommitment.shareCommitmentRoot,
                        expectedPublicMatrixSeedHash:
                            recipientShareCommitmentSet.publicMatrixSeedHash,
                        expectedRnsLimbIndex,
                        expectedRnsPrime: recipientShareCommitment.rnsPrime,
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

export const verifyCompactVssDerivedRecipientShareCommitmentSet = (input: {
    readonly setupContext: CollectiveBgvSetupContext;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly derivedRnsLimbCount?: number;
}): CompactVssRecipientShareCommitmentSet => {
    const coefficientCommitmentSet = verifyCompactVssCoefficientCommitmentSet({
        coefficientCommitmentSet: input.coefficientCommitmentSet,
    });
    const recipientShareCommitmentSet =
        verifyCompactVssRecipientShareCommitmentSet({
            recipientShareCommitmentSet: input.recipientShareCommitmentSet,
        });
    if (
        coefficientCommitmentSet.publicMatrixSeedHash !==
            recipientShareCommitmentSet.publicMatrixSeedHash ||
        coefficientCommitmentSet.participantCount !==
            recipientShareCommitmentSet.participantCount ||
        coefficientCommitmentSet.ringDegree !==
            recipientShareCommitmentSet.ringDegree
    ) {
        throw new Error(
            'compact VSS derived recipient-share verification requires matching coefficient and recipient-share commitment dimensions.',
        );
    }
    const derivedRnsLimbCount =
        input.derivedRnsLimbCount ?? recipientShareCommitmentSet.rnsLimbCount;
    if (
        !Number.isSafeInteger(derivedRnsLimbCount) ||
        derivedRnsLimbCount <= 0 ||
        derivedRnsLimbCount > coefficientCommitmentSet.rnsLimbCount
    ) {
        throw new TypeError(
            'derivedRnsLimbCount must be a positive safe integer within the compact VSS limb count.',
        );
    }
    if (recipientShareCommitmentSet.rnsLimbCount !== derivedRnsLimbCount) {
        throw new Error(
            'compact VSS derived recipient-share verification requires the recipient-share set to use the derived limb count.',
        );
    }

    const setupFields = setupContextFields(input.setupContext);
    coefficientCommitmentSet.sourceTrusteeRecords.forEach(
        (coefficientSourceRecord, sourceRecordIndex) => {
            const recipientSourceRecord =
                recipientShareCommitmentSet.sourceTrusteeRecords[
                    sourceRecordIndex
                ];
            if (
                recipientSourceRecord?.sourceTrusteeIdentity !==
                    coefficientSourceRecord.sourceTrusteeIdentity ||
                recipientSourceRecord.sourceTrusteeRosterPosition !==
                    coefficientSourceRecord.sourceTrusteeRosterPosition
            ) {
                throw new Error(
                    'compact VSS derived recipient-share source records must match coefficient source records.',
                );
            }

            recipientSourceRecord.recipientShareCommitments.forEach(
                (recipientShareRecord) => {
                    const coefficientCommitments =
                        coefficientSourceRecord.coefficientCommitments
                            .filter(
                                (coefficientCommitment) =>
                                    coefficientCommitment.rnsLimbIndex ===
                                    recipientShareRecord.rnsLimbIndex,
                            )
                            .sort(
                                (leftRecord, rightRecord) =>
                                    leftRecord.shamirCoefficientIndex -
                                    rightRecord.shamirCoefficientIndex,
                            );
                    if (
                        coefficientCommitments.length !==
                        coefficientCommitmentSet.thresholdDegree
                    ) {
                        throw new Error(
                            'compact VSS derived recipient-share verification requires every source coefficient commitment for the selected limb.',
                        );
                    }
                    const shamirScalars = shamirEvaluationScalars({
                        recipientTrusteePoint:
                            recipientShareRecord.recipientTrusteePoint,
                        thresholdDegree:
                            coefficientCommitmentSet.thresholdDegree,
                    });
                    const commitmentContext =
                        derivedRecipientShareCommitmentContext({
                            setupContextFields: setupFields,
                            sourceTrusteeIdentity:
                                coefficientSourceRecord.sourceTrusteeIdentity,
                            sourceTrusteeRosterPosition:
                                coefficientSourceRecord.sourceTrusteeRosterPosition,
                            recipientIdentity:
                                recipientShareRecord.recipientIdentity,
                            recipientRosterPosition:
                                recipientShareRecord.recipientRosterPosition,
                            rnsLimbIndex: recipientShareRecord.rnsLimbIndex,
                            rnsPrime: recipientShareRecord.rnsPrime,
                        });
                    const combinedCommitment = combineCompactVssCommitments({
                        commitmentRole: 'recipient-share',
                        commitmentContext,
                        terms: coefficientCommitments.map(
                            (coefficientCommitment, coefficientIndex) => {
                                if (
                                    coefficientCommitment.shamirCoefficientIndex !==
                                        coefficientIndex ||
                                    coefficientCommitment.rnsPrime !==
                                        recipientShareRecord.rnsPrime
                                ) {
                                    throw new Error(
                                        'compact VSS source coefficient commitments must match the derived recipient-share coordinates.',
                                    );
                                }

                                return {
                                    commitment:
                                        coefficientCommitment.commitment,
                                    scalar:
                                        shamirScalars[coefficientIndex] ?? 0,
                                };
                            },
                        ),
                    });
                    if (
                        combinedCommitment.commitmentRoot !==
                        recipientShareRecord.shareCommitmentRoot
                    ) {
                        throw new Error(
                            'compact VSS derived recipient-share commitment does not match the public coefficient commitment combination.',
                        );
                    }
                },
            );
        },
    );

    return recipientShareCommitmentSet;
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
            const sourceShareOpeningRoots = sourceShareRecords.map(
                (recipientShareRecord) => recipientShareRecord.shareOpeningRoot,
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
            if (
                sourceShareOpeningRoots.length !==
                    aggregateRecord.sourceShareOpeningRoots.length ||
                sourceShareOpeningRoots.some(
                    (sourceShareOpeningRoot, sourceRosterPosition) =>
                        sourceShareOpeningRoot !==
                        aggregateRecord.sourceShareOpeningRoots[
                            sourceRosterPosition
                        ],
                )
            ) {
                throw new Error(
                    'compact VSS aggregate threshold commitment source opening roots must match the recipient-share commitment set.',
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
                const aggregateCommitmentMessageValues = Array.from(
                    { length: input.ringDegree },
                    () => 0n,
                );
                const aggregateCommitmentMessageDigitColumns =
                    emptyCompactVssMessageDigitColumnSums(input.ringDegree);
                credentials.forEach((credential) => {
                    assertResidueVector(
                        credential.shareValues,
                        rnsPrime,
                        input.ringDegree,
                        'recipientShareOpeningCredential.shareValues',
                    );
                    const recipientShareOpening =
                        recipientShareOpeningFromCredential({
                            setupContextFields: setupContextFields(
                                input.setupContext,
                            ),
                            publicMatrixSeedHash: input.publicMatrixSeedHash,
                            credential,
                            ringDegree: input.ringDegree,
                        });
                    if (
                        credential.shareCommitmentMessageDigitColumns ===
                        undefined
                    ) {
                        addCanonicalMessageDigitsToColumnSums(
                            aggregateCommitmentMessageDigitColumns,
                            credential.shareValues,
                        );
                    } else {
                        const recipientMessageCoefficientBound =
                            recipientShareOpening.messageCoefficientBound;
                        if (recipientMessageCoefficientBound === undefined) {
                            throw new Error(
                                'compact VSS recipient share opening with explicit digit columns must carry a message coefficient bound.',
                            );
                        }
                        compactVssMessageDigitColumnsForOpening({
                            messageCoefficients:
                                recipientShareOpening.messageCoefficients,
                            messageDigitColumns:
                                credential.shareCommitmentMessageDigitColumns,
                            messageCoefficientBound:
                                recipientMessageCoefficientBound,
                            ringDegree: input.ringDegree,
                        });
                        addMessageDigitColumnsToColumnSums(
                            aggregateCommitmentMessageDigitColumns,
                            credential.shareCommitmentMessageDigitColumns,
                            input.ringDegree,
                        );
                    }
                    recipientShareOpening.messageCoefficients.forEach(
                        (messageValue, coefficientIndex) => {
                            aggregateCommitmentMessageValues[coefficientIndex] =
                                (aggregateCommitmentMessageValues[
                                    coefficientIndex
                                ] ?? 0n) +
                                integerToBigInt(
                                    messageValue,
                                    `recipientShareOpening.messageCoefficients.${String(coefficientIndex)}`,
                                );
                        },
                    );
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
                    messageCoefficients: aggregateCommitmentMessageValues,
                    messageDigitColumns: aggregateCommitmentMessageDigitColumns,
                    messageCoefficientBound:
                        compactVssMessageCoefficientBoundFromValues(
                            aggregateCommitmentMessageValues,
                        ),
                    randomnessByColumn: aggregateRandomnessByColumn,
                } satisfies CompactVssCommitmentOpeningInput;
                const directAggregateCommitment =
                    computeCompactVssCommitmentFromOpening(aggregateOpening);
                const sourceCommitments = credentials.map((credential) => {
                    const opening = recipientShareOpeningFromCredential({
                        setupContextFields: setupContextFields(
                            input.setupContext,
                        ),
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        credential,
                        ringDegree: input.ringDegree,
                    });
                    return {
                        computation:
                            computeCompactVssCommitmentFromOpening(opening),
                        openingRoot:
                            compactVssCommitmentPrivateOpeningRoot(opening),
                    };
                });
                sourceCommitments.forEach(
                    (sourceCommitment, commitmentIndex) => {
                        const credential = credentials[commitmentIndex];
                        if (
                            sourceCommitment.computation.commitmentRoot !==
                                credential?.shareCommitmentRoot ||
                            sourceCommitment.openingRoot !==
                                credential.shareOpeningRoot
                        ) {
                            throw new Error(
                                'compact VSS recipient share credential does not match its public commitment roots.',
                            );
                        }
                    },
                );
                const combinedAggregateCommitment =
                    combineCompactVssCommitments({
                        commitmentRole: 'aggregate-threshold-share',
                        commitmentContext: aggregateOpening.commitmentContext,
                        terms: sourceCommitments.map((sourceCommitment) => ({
                            commitment: sourceCommitment.computation.commitment,
                            scalar: 1,
                        })),
                    });
                const aggregateOpeningRoot =
                    compactVssCommitmentPrivateOpeningRoot(aggregateOpening);
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
                    recipientIdentity: recipientTrustee.trusteeIdentity,
                    recipientRosterPosition:
                        recipientTrustee.trusteeRosterPosition,
                    recipientTrusteePoint,
                    rnsLimbIndex,
                    rnsPrime,
                    aggregateCommitmentRoot:
                        directAggregateCommitment.commitmentRoot,
                    aggregateOpeningRoot,
                    commitment: directAggregateCommitment.commitment,
                    sourceShareCommitmentRoots: credentials.map(
                        (credential) => credential.shareCommitmentRoot,
                    ),
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
            if (
                recipientRecord.sourceShareOpeningRoots.length !==
                aggregateThresholdCommitmentSet.participantCount
            ) {
                throw new Error(
                    'compact VSS aggregate threshold commitment must bind one source share opening root per participant.',
                );
            }
            recipientRecord.sourceShareOpeningRoots.forEach(
                (sourceShareOpeningRoot, sourceRosterPosition) =>
                    assertProtocolHash(
                        sourceShareOpeningRoot,
                        `compact VSS aggregate threshold commitment sourceShareOpeningRoots.${String(sourceRosterPosition)}`,
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
        recipientShareCommitmentSet.rnsLimbCount !==
            aggregateThresholdCommitmentSet.rnsLimbCount ||
        coefficientCommitmentSet.rnsLimbCount <
            recipientShareCommitmentSet.rnsLimbCount ||
        coefficientCommitmentSet.ringDegree !==
            recipientShareCommitmentSet.ringDegree ||
        coefficientCommitmentSet.ringDegree !==
            aggregateThresholdCommitmentSet.ringDegree
    ) {
        throw new Error(
            'compact VSS share linkage statement inputs must use one participant count, target basis, and ring degree.',
        );
    }
    const targetRnsLimbCount = recipientShareCommitmentSet.rnsLimbCount;
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
                const targetCoefficientCommitments =
                    coefficientSourceRecord.coefficientCommitments.filter(
                        (coefficientCommitment) =>
                            coefficientCommitment.rnsLimbIndex <
                            targetRnsLimbCount,
                    );
                const coefficientOpeningRoots =
                    targetCoefficientCommitments.map(
                        (coefficientCommitment) =>
                            coefficientCommitment.coefficientOpeningRoot,
                    );
                const recipientShareOpeningRoots =
                    recipientSourceRecord.recipientShareCommitments.map(
                        (recipientShareCommitment) =>
                            recipientShareCommitment.shareOpeningRoot,
                    );
                const sourceStatementWithoutRoot = {
                    objectType: 'CompactVssShareLinkageSourceStatement',
                    objectVersion: 1,
                    setupProfileId: 'CollectiveBgvSetup-v1',
                    profileId: compactVssCommitmentProfileId,
                    ...setupContextFields(input.setupContext),
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                    targetBasisHash: input.targetBasisHash,
                    sourceTrusteeIdentity:
                        coefficientSourceRecord.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        coefficientSourceRecord.sourceTrusteeRosterPosition,
                    participantCount: coefficientCommitmentSet.participantCount,
                    targetRnsLimbCount,
                    thresholdDegree: coefficientCommitmentSet.thresholdDegree,
                    coefficientCommitmentRoot:
                        coefficientCommitmentSet.coefficientCommitmentRoot,
                    sourceCoefficientCommitmentRoot:
                        coefficientSourceRecord.sourceCoefficientCommitmentRoot,
                    sourceRecipientShareCommitmentRoot:
                        recipientSourceRecord.sourceRecipientShareCommitmentRoot,
                    coefficientOpeningRoots,
                    recipientShareOpeningRoots,
                    aggregateThresholdCommitmentRoot:
                        aggregateThresholdCommitmentSet.aggregateThresholdCommitmentRoot,
                    relation: compactVssShareLinkageStatementRelation,
                    proofBatchingRule: compactVssShareLinkageProofBatchingRule,
                    shamirEvaluationRule:
                        compactVssShareLinkageShamirEvaluationRule,
                    aggregateThresholdRule:
                        compactVssShareLinkageAggregateThresholdRule,
                    commonKeyRule: compactVssShareLinkageCommonKeyRule,
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
        ...setupContextFields(input.setupContext),
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        targetBasisHash: input.targetBasisHash,
        participantCount: coefficientCommitmentSet.participantCount,
        targetRnsLimbCount,
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
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
}): void => {
    if (
        input.coefficientCommitmentSet === undefined ||
        input.recipientShareCommitmentSet === undefined ||
        input.aggregateThresholdCommitmentSet === undefined
    ) {
        throw new Error(
            'compact VSS share linkage evidence verification requires coefficient, recipient-share, and aggregate-threshold commitment sets.',
        );
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
        coefficientCommitmentSet.rnsLimbCount <
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
            const expectedCoefficientOpeningRoots =
                coefficientSourceRecord.coefficientCommitments
                    .filter(
                        (coefficientCommitment) =>
                            coefficientCommitment.rnsLimbIndex <
                            input.statement.targetRnsLimbCount,
                    )
                    .map(
                        (coefficientCommitment) =>
                            coefficientCommitment.coefficientOpeningRoot,
                    );
            const expectedRecipientShareOpeningRoots =
                recipientSourceRecord.recipientShareCommitments.map(
                    (recipientShareCommitment) =>
                        recipientShareCommitment.shareOpeningRoot,
                );
            if (
                sourceStatement.coefficientOpeningRoots.length !==
                    expectedCoefficientOpeningRoots.length ||
                sourceStatement.recipientShareOpeningRoots.length !==
                    expectedRecipientShareOpeningRoots.length ||
                sourceStatement.coefficientOpeningRoots.some(
                    (openingRoot, openingRootIndex) =>
                        openingRoot !==
                        expectedCoefficientOpeningRoots[openingRootIndex],
                ) ||
                sourceStatement.recipientShareOpeningRoots.some(
                    (openingRoot, openingRootIndex) =>
                        openingRoot !==
                        expectedRecipientShareOpeningRoots[openingRootIndex],
                )
            ) {
                throw new Error(
                    'compact VSS share linkage evidence opening roots must match each source statement.',
                );
            }
        },
    );
};

export const verifyCompactVssShareLinkageStatement = (input: {
    readonly statement: CompactVssShareLinkageStatement;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
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
            assertProtocolHashArray(
                sourceStatementRecord.coefficientOpeningRoots,
                input.statement.targetRnsLimbCount *
                    input.statement.thresholdDegree,
                'compact VSS share linkage source statement coefficientOpeningRoots',
            );
            assertProtocolHashArray(
                sourceStatementRecord.recipientShareOpeningRoots,
                input.statement.participantCount *
                    input.statement.targetRnsLimbCount,
                'compact VSS share linkage source statement recipientShareOpeningRoots',
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

const compactVssShareLinkageProofItems = (
    proofStatement: CompactVssShareLinkageProofStatement,
): readonly CompactVssShareLinkageProofStatementItem[] => [
    proofStatement,
    ...(proofStatement.additionalLinkageItems ?? []),
];

const compactVssShareLinkageCoverageKey = (
    sourceTrusteeRosterPosition: number,
    recipientRosterPosition: number,
    sourceRnsLimbIndex: number,
): string =>
    [
        sourceTrusteeRosterPosition,
        recipientRosterPosition,
        sourceRnsLimbIndex,
    ].join(':');

const verifyCompactVssShareLinkageProofStatementCoverage = (input: {
    readonly proofStatement: CompactVssShareLinkageProofStatement;
    readonly sourceStatement: CompactVssShareLinkageSourceStatementRecord;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
}): readonly CompactVssShareLinkageCoverageItem[] => {
    const proofStatement = input.proofStatement;
    const sourceStatement = input.sourceStatement;
    for (const [fieldName, expectedValue] of [
        ['publicMatrixSeedHash', sourceStatement.publicMatrixSeedHash],
        ['sourceTrusteeIdentity', sourceStatement.sourceTrusteeIdentity],
        [
            'sourceTrusteeRosterPosition',
            sourceStatement.sourceTrusteeRosterPosition,
        ],
        [
            'sourceCoefficientCommitmentRoot',
            sourceStatement.sourceCoefficientCommitmentRoot,
        ],
        [
            'sourceRecipientShareCommitmentRoot',
            sourceStatement.sourceRecipientShareCommitmentRoot,
        ],
    ] as const) {
        if (proofStatement[fieldName] !== expectedValue) {
            throw new Error(
                `compact VSS share-linkage proof statement ${fieldName} must match the source statement.`,
            );
        }
    }

    const coefficientSourceRecord =
        input.coefficientCommitmentSet.sourceTrusteeRecords[
            sourceStatement.sourceTrusteeRosterPosition
        ];
    const recipientSourceRecord =
        input.recipientShareCommitmentSet.sourceTrusteeRecords[
            sourceStatement.sourceTrusteeRosterPosition
        ];
    if (
        coefficientSourceRecord === undefined ||
        recipientSourceRecord === undefined
    ) {
        throw new Error(
            'compact VSS share-linkage proof statement source is outside the public commitment records.',
        );
    }
    if (
        coefficientSourceRecord.sourceTrusteeIdentity !==
            sourceStatement.sourceTrusteeIdentity ||
        recipientSourceRecord.sourceTrusteeIdentity !==
            sourceStatement.sourceTrusteeIdentity ||
        coefficientSourceRecord.sourceCoefficientCommitmentRoot !==
            sourceStatement.sourceCoefficientCommitmentRoot ||
        recipientSourceRecord.sourceRecipientShareCommitmentRoot !==
            sourceStatement.sourceRecipientShareCommitmentRoot
    ) {
        throw new Error(
            'compact VSS share-linkage proof statement source roots must match the public records.',
        );
    }

    return compactVssShareLinkageProofItems(proofStatement).map(
        (item, itemIndex) => {
            assertNonEmptyString(
                item.recipientIdentity,
                'compact VSS share-linkage proof item recipientIdentity',
            );
            assertPositiveSafeInteger(
                item.sourceMessageModulus,
                'compact VSS share-linkage proof item sourceMessageModulus',
            );
            if (
                item.recipientRosterPosition < 0 ||
                item.recipientRosterPosition >= sourceStatement.participantCount
            ) {
                throw new Error(
                    'compact VSS share-linkage proof item recipientRosterPosition is outside the statement.',
                );
            }
            if (
                item.sourceRnsLimbIndex < 0 ||
                item.sourceRnsLimbIndex >= sourceStatement.targetRnsLimbCount
            ) {
                throw new Error(
                    'compact VSS share-linkage proof item sourceRnsLimbIndex is outside the target basis.',
                );
            }
            if (
                item.coefficientCommitmentRoots.length !==
                    sourceStatement.thresholdDegree ||
                item.coefficientOpeningRoots.length !==
                    sourceStatement.thresholdDegree ||
                item.coefficientCommitments.length !==
                    sourceStatement.thresholdDegree
            ) {
                throw new Error(
                    'compact VSS share-linkage proof item must carry one coefficient commitment per threshold coefficient.',
                );
            }
            item.coefficientCommitments.forEach(
                (commitment, coefficientIndex) => {
                    const coefficientRecordIndex =
                        item.sourceRnsLimbIndex *
                            sourceStatement.thresholdDegree +
                        coefficientIndex;
                    const coefficientRecord =
                        coefficientSourceRecord.coefficientCommitments[
                            coefficientRecordIndex
                        ];
                    if (coefficientRecord === undefined) {
                        throw new Error(
                            'compact VSS share-linkage proof item is missing a matching coefficient record.',
                        );
                    }
                    if (
                        coefficientRecord.rnsLimbIndex !==
                            item.sourceRnsLimbIndex ||
                        coefficientRecord.rnsPrime !==
                            item.sourceMessageModulus ||
                        coefficientRecord.shamirCoefficientIndex !==
                            coefficientIndex ||
                        coefficientRecord.coefficientCommitmentRoot !==
                            item.coefficientCommitmentRoots[coefficientIndex] ||
                        coefficientRecord.coefficientOpeningRoot !==
                            item.coefficientOpeningRoots[coefficientIndex] ||
                        sourceStatement.coefficientOpeningRoots[
                            coefficientRecordIndex
                        ] !== item.coefficientOpeningRoots[coefficientIndex]
                    ) {
                        throw new Error(
                            'compact VSS share-linkage proof item coefficient roots must match the public source statement.',
                        );
                    }
                    if (
                        deriveProtocolHash(
                            'SetupCommitmentRoot',
                            commitment,
                        ) !== coefficientRecord.coefficientCommitmentRoot
                    ) {
                        throw new Error(
                            'compact VSS share-linkage proof item coefficient commitment body must match its public root.',
                        );
                    }
                },
            );

            const recipientRecordIndex =
                item.recipientRosterPosition *
                    sourceStatement.targetRnsLimbCount +
                item.sourceRnsLimbIndex;
            const recipientRecord =
                recipientSourceRecord.recipientShareCommitments[
                    recipientRecordIndex
                ];
            if (recipientRecord === undefined) {
                throw new Error(
                    'compact VSS share-linkage proof item is missing a matching recipient-share record.',
                );
            }
            if (
                recipientRecord.recipientIdentity !== item.recipientIdentity ||
                recipientRecord.recipientRosterPosition !==
                    item.recipientRosterPosition ||
                recipientRecord.rnsLimbIndex !== item.sourceRnsLimbIndex ||
                recipientRecord.rnsPrime !== item.sourceMessageModulus ||
                recipientRecord.shareCommitmentRoot !==
                    item.recipientShareCommitmentRoot ||
                recipientRecord.shareOpeningRoot !==
                    item.recipientShareOpeningRoot ||
                sourceStatement.recipientShareOpeningRoots[
                    recipientRecordIndex
                ] !== item.recipientShareOpeningRoot
            ) {
                throw new Error(
                    'compact VSS share-linkage proof item recipient roots must match the public source statement.',
                );
            }
            if (
                deriveProtocolHash(
                    'SetupCommitmentRoot',
                    item.recipientShareCommitment,
                ) !== recipientRecord.shareCommitmentRoot
            ) {
                throw new Error(
                    'compact VSS share-linkage proof item recipient commitment body must match its public root.',
                );
            }

            return {
                sourceTrusteeRosterPosition:
                    sourceStatement.sourceTrusteeRosterPosition,
                recipientRosterPosition: item.recipientRosterPosition,
                sourceRnsLimbIndex: item.sourceRnsLimbIndex,
                itemIndex,
            };
        },
    );
};

const assertCompactVssShareLinkageProofMaterialCoverage = (
    proofRecords: readonly CompactVssShareLinkageProofRecord[],
    participantCount: number,
    targetRnsLimbCount: number,
): void => {
    const coverage = new Set<string>();
    proofRecords.forEach((proofRecord) => {
        proofRecord.linkageItems.forEach((item) => {
            const key = compactVssShareLinkageCoverageKey(
                item.sourceTrusteeRosterPosition,
                item.recipientRosterPosition,
                item.sourceRnsLimbIndex,
            );
            if (coverage.has(key)) {
                throw new Error(
                    'compact VSS share-linkage proof material repeats a source recipient-limb item.',
                );
            }
            coverage.add(key);
        });
    });
    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < participantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        for (
            let recipientRosterPosition = 0;
            recipientRosterPosition < participantCount;
            recipientRosterPosition += 1
        ) {
            for (
                let sourceRnsLimbIndex = 0;
                sourceRnsLimbIndex < targetRnsLimbCount;
                sourceRnsLimbIndex += 1
            ) {
                const key = compactVssShareLinkageCoverageKey(
                    sourceTrusteeRosterPosition,
                    recipientRosterPosition,
                    sourceRnsLimbIndex,
                );
                if (!coverage.has(key)) {
                    throw new Error(
                        'compact VSS share-linkage proof material must cover every source, recipient, and target limb.',
                    );
                }
            }
        }
    }
};

export const createCompactVssShareLinkageProofMaterialSet = (input: {
    readonly statement: CompactVssShareLinkageStatement;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly ringDegree: number;
    readonly proofRecordInputs: readonly CompactVssShareLinkageProofRecordInput[];
}): CompactVssShareLinkageProofMaterialSet => {
    const statement = verifyCompactVssShareLinkageStatement({
        statement: input.statement,
        coefficientCommitmentSet: input.coefficientCommitmentSet,
        recipientShareCommitmentSet: input.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet: input.aggregateThresholdCommitmentSet,
    });
    assertPositiveSafeInteger(
        input.ringDegree,
        'compact VSS share-linkage proof material ringDegree',
    );
    const sourceStatementsByRoot = new Map(
        statement.sourceStatementRecords.map((sourceStatement) => [
            sourceStatement.sourceStatementRoot,
            sourceStatement,
        ]),
    );
    const proofRecords = input.proofRecordInputs.map((proofRecordInput) => {
        const sourceStatement = sourceStatementsByRoot.get(
            proofRecordInput.sourceStatementRoot,
        );
        if (sourceStatement === undefined) {
            throw new Error(
                'compact VSS share-linkage proof record input sourceStatementRoot is not part of the statement.',
            );
        }
        const linkageItems = verifyCompactVssShareLinkageProofStatementCoverage(
            {
                proofStatement: proofRecordInput.compactVssShareLinkage,
                sourceStatement,
                coefficientCommitmentSet: input.coefficientCommitmentSet,
                recipientShareCommitmentSet: input.recipientShareCommitmentSet,
            },
        );
        const proofBytes = bytesFromHex(
            proofRecordInput.proofBytesHex,
            'compact VSS share-linkage proofBytesHex',
        );
        const proofRecordWithoutRoot = {
            objectType: 'CompactVssShareLinkageProofRecord',
            objectVersion: 1,
            proofFamily: compactVssShareLinkageProofFamily,
            sourceStatementRoot: sourceStatement.sourceStatementRoot,
            sourceTrusteeIdentity: sourceStatement.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                sourceStatement.sourceTrusteeRosterPosition,
            linkageItems,
            compactVssShareLinkage: proofRecordInput.compactVssShareLinkage,
            proofBytesHash: compactVssShareLinkageProofBytesHash(proofBytes),
            proofBytesBase64: bytesToStandardBase64(proofBytes),
        } as const satisfies Omit<
            CompactVssShareLinkageProofRecord,
            'proofRecordRoot'
        >;

        return {
            ...proofRecordWithoutRoot,
            proofRecordRoot: deriveProtocolHash(
                'SetupProofRecordBindingHash',
                proofRecordWithoutRoot,
            ),
        };
    });
    assertCompactVssShareLinkageProofMaterialCoverage(
        proofRecords,
        statement.participantCount,
        statement.targetRnsLimbCount,
    );
    const proofMaterialSetWithoutRoot = {
        objectType: 'CompactVssShareLinkageProofMaterialSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        setupProofProfileId,
        proofFamily: compactVssShareLinkageProofFamily,
        ceremonyId: statement.ceremonyId,
        manifestHash: statement.manifestHash,
        rosterHash: statement.rosterHash,
        setupProfileHash: statement.setupProfileHash,
        qShareHash: statement.qShareHash,
        carryAwareVssShareRelationProfileHash:
            statement.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: statement.commitmentProfileHash,
        setupEpoch: statement.setupEpoch,
        publicMatrixSeedHash: statement.publicMatrixSeedHash,
        targetBasisHash: statement.targetBasisHash,
        ringDegree: input.ringDegree,
        participantCount: statement.participantCount,
        targetRnsLimbCount: statement.targetRnsLimbCount,
        thresholdDegree: statement.thresholdDegree,
        coefficientCommitmentRoot: statement.coefficientCommitmentRoot,
        recipientShareCommitmentRoot: statement.recipientShareCommitmentRoot,
        aggregateThresholdCommitmentRoot:
            statement.aggregateThresholdCommitmentRoot,
        statementRoot: statement.statementRoot,
        proofRecords,
    } as const satisfies Omit<
        CompactVssShareLinkageProofMaterialSet,
        'proofMaterialSetRoot'
    >;

    return {
        ...proofMaterialSetWithoutRoot,
        proofMaterialSetRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            proofMaterialSetWithoutRoot,
        ),
    };
};

export const verifyCompactVssShareLinkageProofMaterialSet = (input: {
    readonly statement: CompactVssShareLinkageStatement;
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly proofMaterialSet: CompactVssShareLinkageProofMaterialSet;
}): CompactVssShareLinkageProofMaterialSet => {
    const statement = verifyCompactVssShareLinkageStatement({
        statement: input.statement,
        coefficientCommitmentSet: input.coefficientCommitmentSet,
        recipientShareCommitmentSet: input.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet: input.aggregateThresholdCommitmentSet,
    });
    const proofMaterialSet = input.proofMaterialSet;
    assertExactStringField(
        proofMaterialSet.objectType,
        'compact VSS share-linkage proof material set objectType',
        'CompactVssShareLinkageProofMaterialSet',
    );
    if (proofMaterialSet.objectVersion !== 1) {
        throw new TypeError(
            'compact VSS share-linkage proof material set objectVersion is not supported.',
        );
    }
    for (const [fieldName, expectedValue] of [
        ['setupProfileId', statement.setupProfileId],
        ['profileId', statement.profileId],
        ['setupProofProfileId', setupProofProfileId],
        ['proofFamily', compactVssShareLinkageProofFamily],
        ['ceremonyId', statement.ceremonyId],
        ['manifestHash', statement.manifestHash],
        ['rosterHash', statement.rosterHash],
        ['setupProfileHash', statement.setupProfileHash],
        ['qShareHash', statement.qShareHash],
        [
            'carryAwareVssShareRelationProfileHash',
            statement.carryAwareVssShareRelationProfileHash,
        ],
        ['commitmentProfileHash', statement.commitmentProfileHash],
        ['setupEpoch', statement.setupEpoch],
        ['publicMatrixSeedHash', statement.publicMatrixSeedHash],
        ['targetBasisHash', statement.targetBasisHash],
        ['coefficientCommitmentRoot', statement.coefficientCommitmentRoot],
        [
            'recipientShareCommitmentRoot',
            statement.recipientShareCommitmentRoot,
        ],
        [
            'aggregateThresholdCommitmentRoot',
            statement.aggregateThresholdCommitmentRoot,
        ],
        ['statementRoot', statement.statementRoot],
    ] as const) {
        if (proofMaterialSet[fieldName] !== expectedValue) {
            throw new Error(
                `compact VSS share-linkage proof material set ${fieldName} must match the statement.`,
            );
        }
    }
    if (
        proofMaterialSet.participantCount !== statement.participantCount ||
        proofMaterialSet.targetRnsLimbCount !== statement.targetRnsLimbCount ||
        proofMaterialSet.thresholdDegree !== statement.thresholdDegree
    ) {
        throw new Error(
            'compact VSS share-linkage proof material set dimensions must match the statement.',
        );
    }
    assertPositiveSafeInteger(
        proofMaterialSet.ringDegree,
        'compact VSS share-linkage proof material set ringDegree',
    );
    proofMaterialSet.proofRecords.forEach((proofRecord, proofRecordIndex) => {
        const sourceStatement = statement.sourceStatementRecords.find(
            (record) =>
                record.sourceStatementRoot === proofRecord.sourceStatementRoot,
        );
        if (sourceStatement === undefined) {
            throw new Error(
                'compact VSS share-linkage proof record sourceStatementRoot is not part of the statement.',
            );
        }
        assertExactStringField(
            proofRecord.objectType,
            'compact VSS share-linkage proof record objectType',
            'CompactVssShareLinkageProofRecord',
        );
        if (proofRecord.objectVersion !== 1) {
            throw new TypeError(
                'compact VSS share-linkage proof record objectVersion is not supported.',
            );
        }
        if (
            proofRecord.proofFamily !== proofMaterialSet.proofFamily ||
            proofRecord.sourceTrusteeIdentity !==
                sourceStatement.sourceTrusteeIdentity ||
            proofRecord.sourceTrusteeRosterPosition !==
                sourceStatement.sourceTrusteeRosterPosition
        ) {
            throw new Error(
                'compact VSS share-linkage proof record must match its source statement.',
            );
        }
        const expectedLinkageItems =
            verifyCompactVssShareLinkageProofStatementCoverage({
                proofStatement: proofRecord.compactVssShareLinkage,
                sourceStatement,
                coefficientCommitmentSet: input.coefficientCommitmentSet,
                recipientShareCommitmentSet: input.recipientShareCommitmentSet,
            });
        if (
            JSON.stringify(proofRecord.linkageItems) !==
            JSON.stringify(expectedLinkageItems)
        ) {
            throw new Error(
                'compact VSS share-linkage proof record linkageItems must match the proof statement coverage.',
            );
        }
        const proofBytes = bytesFromStandardBase64(
            proofRecord.proofBytesBase64,
            'compact VSS share-linkage proof record proofBytesBase64',
        );
        if (
            proofRecord.proofBytesHash !==
            compactVssShareLinkageProofBytesHash(proofBytes)
        ) {
            throw new Error(
                'compact VSS share-linkage proof record proofBytesHash must match proofBytesBase64.',
            );
        }
        const { proofRecordRoot: _proofRecordRoot, ...proofRecordWithoutRoot } =
            proofRecord;
        if (
            proofRecord.proofRecordRoot !==
            deriveProtocolHash(
                'SetupProofRecordBindingHash',
                proofRecordWithoutRoot,
            )
        ) {
            throw new Error(
                `compact VSS share-linkage proof record ${String(proofRecordIndex)} root does not match its bound proof bytes.`,
            );
        }
    });
    assertCompactVssShareLinkageProofMaterialCoverage(
        proofMaterialSet.proofRecords,
        statement.participantCount,
        statement.targetRnsLimbCount,
    );
    const {
        proofMaterialSetRoot: _proofMaterialSetRoot,
        ...proofMaterialSetWithoutRoot
    } = proofMaterialSet;
    if (
        proofMaterialSet.proofMaterialSetRoot !==
        deriveProtocolHash(
            'SetupProofRecordBindingHash',
            proofMaterialSetWithoutRoot,
        )
    ) {
        throw new Error(
            'compact VSS share-linkage proof material set root does not match its bound proof records.',
        );
    }

    return proofMaterialSet;
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
        compactVssInputColumnLabels().length;
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
    const inputColumnLabels = compactVssInputColumnLabels();
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
        matrixKind: 'compact-vss-commitment-key',
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
        coordinateCountPerCommitment,
        sampledMatrixResiduesPerCoordinate,
        sampledProjectionIndicesPerCoordinate,
        sampledMatrixResiduesPerCommitment,
        sampledProjectionIndicesPerCommitment,
        residueMultiplyAddsPerCommitment: sampledMatrixResiduesPerCommitment,
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
    if (input.targetRnsPrimes.length > acceptedBgvSetupQSharePrimes.length) {
        throw new Error(
            'targetRnsPrimes must be a prefix of the canonical target basis.',
        );
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
        if (targetRnsPrime !== acceptedBgvSetupQSharePrimes[rnsLimbIndex]) {
            throw new Error(
                'targetRnsPrimes must match the canonical target basis prefix.',
            );
        }
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
    const inputColumnLabels = compactVssInputColumnLabels();
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
    const freshOpeningWitnessCoefficientCount = safeNumberFromBigInt(
        BigInt(inputColumnLabels.length) * BigInt(ringDegree),
        'fresh compact VSS opening witness coefficient count',
    );
    const aggregateRandomnessDifferenceInfinityBound = safeNumberFromBigInt(
        BigInt(input.participantCount) * 2n,
        'aggregate compact VSS randomness difference bound',
    );
    const recipientShamirRelationL1 = safeNumberFromBigInt(
        BigInt(maximumOneSourceShamirScalarL1) + 1n,
        'recipient Shamir relation L1',
    );
    const aggregateSumRelationL1 = safeNumberFromBigInt(
        BigInt(input.participantCount) + 1n,
        'aggregate sum relation L1',
    );
    const compactVssMessageDigitMaximum = compactVssMessageDigitBase - 1n;
    const setupConsistencyCoefficientMaximum =
        (1n << BigInt(setupConsistencyCoefficientBits)) - 1n;
    const compactVssConsistencyCoefficientMaximum =
        (1n << BigInt(compactVssConsistencyCoefficientBits)) - 1n;
    const largestTargetRnsPrime = input.targetRnsPrimes.reduce(
        (largest, targetRnsPrime) => Math.max(largest, targetRnsPrime),
        0,
    );
    const aggregateTargetMessageCoefficientBound =
        BigInt(largestTargetRnsPrime) * BigInt(input.participantCount);
    const aggregateTargetMessageDigitMaximum =
        compactVssMaximumDigitValueForMessageBound(
            aggregateTargetMessageCoefficientBound,
        );
    const smudgingTargetMessageDigitMaximum =
        compactVssMaximumDigitValueForMessageBound(
            BigInt(targetDecryptionSmudgingMessageCoefficientBound),
        );
    const compactShareLinkageCarryClearClaimBoundDecimal =
        maskedClaimClearBoundDecimal({
            witnessInfinityBound: BigInt(maximumOneSourceShamirScalarL1),
            ringDegree,
            consistencyCoefficientBits: compactVssConsistencyCoefficientBits,
        });
    const compactShareLinkageDigitClearClaimBoundDecimal =
        maskedClaimClearBoundDecimal({
            witnessInfinityBound: compactVssMessageDigitMaximum,
            ringDegree,
            consistencyCoefficientBits: compactVssConsistencyCoefficientBits,
        });
    const bridgeNonDigitClearClaimBoundDecimal = maskedClaimClearBoundDecimal({
        witnessInfinityBound: 2n,
        ringDegree,
        consistencyCoefficientBits: setupConsistencyCoefficientBits,
    });
    const bridgeDigitClearClaimBoundDecimal = maskedClaimClearBoundDecimal({
        witnessInfinityBound: compactVssMessageDigitMaximum,
        ringDegree,
        consistencyCoefficientBits: setupConsistencyCoefficientBits,
    });
    const aggregateTargetMessageClearClaimBoundDecimal =
        maskedClaimClearBoundDecimal({
            witnessInfinityBound: aggregateTargetMessageDigitMaximum,
            ringDegree,
            consistencyCoefficientBits: setupConsistencyCoefficientBits,
        });
    const smudgingTargetMessageClearClaimBoundDecimal =
        maskedClaimClearBoundDecimal({
            witnessInfinityBound: smudgingTargetMessageDigitMaximum,
            ringDegree,
            consistencyCoefficientBits: setupConsistencyCoefficientBits,
        });
    const targetRandomnessClearClaimBoundDecimal = maskedClaimClearBoundDecimal(
        {
            witnessInfinityBound: 1n,
            ringDegree,
            consistencyCoefficientBits: setupConsistencyCoefficientBits,
        },
    );
    const commitmentModulusLimbs = compactVssCommitmentModulusLimbIndices.map(
        (commitmentModulusIndex) => ({
            commitmentModulusIndex,
            modulus: input.sourceRnsPrimes[commitmentModulusIndex],
        }),
    );
    const certificateInputBody = {
        objectType: 'CompactVssParameterCertificateInputBinding',
        objectVersion: 3,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        participantCount: input.participantCount,
        sourceRnsLimbCount: input.sourceRnsPrimes.length,
        targetRnsLimbCount: input.targetRnsPrimes.length,
        thresholdDegree: input.thresholdDegree,
        ringDegree,
        commitmentRelation: {
            relation: 'C = A_message * m + A_randomness * r mod q_c',
            coefficientRing: 'Z_q[X]/(X^N+1)',
            commitmentModulusLimbIndices:
                compactVssCommitmentModulusLimbIndices,
            commitmentModulusLimbs,
            outputCoordinateCount: compactVssCommitmentOutputCoordinateCount,
            messageWidth: compactVssMessageDigitCount,
            randomnessWidth: compactVssCommitmentRandomnessColumnCount,
            projectionWeight: compactVssProjectionWeight,
            coordinateCountPerCommitment,
            inputColumnLabels,
            homomorphicAdditionRule:
                'commitments combine linearly only when profile, public matrix seed, source limb, and commitment modulus order match',
            homomorphicScalarRule:
                'public Shamir and aggregation scalars multiply both message and randomness columns over the same commitment key',
        },
        commonCommitmentKey: {
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
            sparseProjectionShape: {
                inputColumnCount: inputColumnLabels.length,
                projectionWeight: compactVssProjectionWeight,
                coordinateCountPerCommitment,
                sampledMatrixResiduesPerCoordinate,
                sampledProjectionIndicesPerCoordinate,
                sampledMatrixResiduesPerCommitment,
                sampledProjectionIndicesPerCommitment,
            },
        },
        messageEncoding: {
            sourceCoefficientRepresentation:
                'canonical residue modulo the selected source RNS prime',
            targetCoefficientRepresentation:
                'canonical residue modulo the selected target RNS prime',
            signedRepresentativeConvention:
                'same-secret bridge witnesses use the setup proof signed representative convention before reduction into each RNS prime',
            paddingAndBlockOrder:
                'two base-3^17 little-endian digit coefficients per message ring position',
            freshEncodingRule:
                'exact canonical residue encoding into two message digit columns',
            proofRangeEncodingRule:
                'share-linkage, same-secret bridge, and target-decryption rows bind message digit columns directly with masked consistency claims',
            derivedEncodingRule:
                'Shamir recipient-share and aggregate threshold openings bind carried public-sum messages through decoded message digit columns and private carry witnesses',
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
                sourceCoefficientUpperBoundMultiplier: 1,
                recipientShareCoefficientUpperBoundMultiplier:
                    maximumOneSourceShamirScalarL1,
                aggregateCoefficientUpperBoundMultiplier:
                    oneRecipientAggregateShamirScalarL1,
            },
            {
                className: 'openingRandomnessNorm',
                randomnessColumnCount:
                    compactVssCommitmentRandomnessColumnCount,
            },
            {
                className: 'aggregateDealerCount',
                sourceTrusteeCount: input.participantCount,
            },
        ],
        parameterReviewInputs: {
            inputVersion: 1,
            coefficientRing: {
                ringPolynomial: 'X^N+1',
                ringDegree,
                commitmentModulusLimbIndices:
                    compactVssCommitmentModulusLimbIndices,
                commitmentModulusLimbs,
            },
            openingWitnessRows: [
                {
                    rowId: 'compact-vss-fresh-opening-witness',
                    commitmentRoles: ['coefficient', 'recipient-share'],
                    messageCoefficientBound:
                        'selectedRnsPrime times the recipient Shamir scalar L1 for recipient-share openings',
                    messageCoefficientUpperBoundMultiplier:
                        maximumOneSourceShamirScalarL1,
                    messageDifferenceUpperBoundMultiplier:
                        maximumOneSourceShamirScalarL1,
                    randomnessDistribution:
                        'balanced-ternary-per-column-coefficient',
                    randomnessCoefficientInfinityBound: 1,
                    randomnessDifferenceInfinityBound: 2,
                    messageColumnCount: compactVssMessageDigitCount,
                    randomnessColumnCount:
                        compactVssCommitmentRandomnessColumnCount,
                    witnessColumnCount: inputColumnLabels.length,
                    witnessCoefficientCount:
                        freshOpeningWitnessCoefficientCount,
                },
                {
                    rowId: 'compact-vss-aggregate-opening-witness',
                    commitmentRoles: ['aggregate-threshold-share'],
                    messageCoefficientBound:
                        'selectedRnsPrime times the all-source recipient Shamir scalar L1',
                    messageCoefficientUpperBoundMultiplier:
                        oneRecipientAggregateShamirScalarL1,
                    messageDifferenceUpperBoundMultiplier:
                        oneRecipientAggregateShamirScalarL1,
                    randomnessDistribution:
                        'sum-of-source-balanced-ternary-openings',
                    randomnessCoefficientInfinityBound: input.participantCount,
                    randomnessDifferenceInfinityBound:
                        aggregateRandomnessDifferenceInfinityBound,
                    messageColumnCount: compactVssMessageDigitCount,
                    randomnessColumnCount:
                        compactVssCommitmentRandomnessColumnCount,
                    witnessColumnCount: inputColumnLabels.length,
                    witnessCoefficientCount:
                        freshOpeningWitnessCoefficientCount,
                },
            ],
            linearRelationRows: [
                {
                    rowId: 'compact-vss-recipient-share-shamir-evaluation',
                    relation:
                        'recipient share opening equals Shamir evaluation of source coefficient openings',
                    sourceOpeningCount: input.thresholdDegree,
                    recipientOpeningTermCount: 1,
                    maximumRecipientTrusteePoint: input.participantCount,
                    sourceShamirScalarL1: maximumOneSourceShamirScalarL1,
                    combinedRelationTermL1: recipientShamirRelationL1,
                    appliesToColumns: inputColumnLabels,
                },
                {
                    rowId: 'compact-vss-aggregate-threshold-public-sum',
                    relation:
                        'aggregate threshold opening equals public sum of source-recipient openings',
                    sourceTrusteeCount: input.participantCount,
                    aggregateOpeningTermCount: 1,
                    sourceOpeningScalarL1: input.participantCount,
                    combinedRelationTermL1: aggregateSumRelationL1,
                    appliesToColumns: inputColumnLabels,
                },
                {
                    rowId: 'compact-vss-one-recipient-aggregate-from-source-coefficients',
                    relation:
                        'one recipient aggregate opening as a sum of all source Shamir evaluations',
                    sourceTrusteeCount: input.participantCount,
                    sourceCoefficientCountPerTrustee: input.thresholdDegree,
                    oneRecipientAggregateShamirScalarL1,
                    appliesToColumns: inputColumnLabels,
                },
            ],
            maskedClaimNormRows: [
                {
                    rowId: 'compact-vss-share-linkage-carry-claim',
                    proofFamily: compactVssShareLinkageProofFamily,
                    claimVectorClass: 'packed-opening-carry',
                    appliesToRelations: [
                        'compact-vss-recipient-share-shamir-evaluation',
                        'compact-vss-aggregate-threshold-public-sum',
                        'compact-vss-one-recipient-aggregate-from-source-coefficients',
                    ],
                    witnessInfinityBound: maximumOneSourceShamirScalarL1,
                    clearClaimBoundDecimal:
                        compactShareLinkageCarryClearClaimBoundDecimal,
                    consistencyRepetitions: compactVssConsistencyRepetitions,
                    consistencyCoefficientBits:
                        compactVssConsistencyCoefficientBits,
                    consistencyCoefficientMaximumDecimal:
                        compactVssConsistencyCoefficientMaximum.toString(),
                    claimMaskRadix: compactVssClaimMaskRadix,
                    maskDigitCount: compactVssCarryClaimMaskDigitCount,
                    rangeEvidenceRule:
                        'carry claims use the lifted Shamir carry bound for each packed item',
                },
                {
                    rowId: 'compact-vss-share-linkage-message-digit-claim',
                    proofFamily: compactVssShareLinkageProofFamily,
                    claimVectorClass: 'message-digit',
                    appliesToRelations: [
                        'compact-vss-recipient-share-shamir-evaluation',
                        'compact-vss-aggregate-threshold-public-sum',
                        'compact-vss-one-recipient-aggregate-from-source-coefficients',
                    ],
                    messageDigitBaseDecimal:
                        compactVssMessageDigitBase.toString(),
                    messageDigitCount: compactVssMessageDigitCount,
                    witnessInfinityBoundDecimal:
                        compactVssMessageDigitMaximum.toString(),
                    clearClaimBoundDecimal:
                        compactShareLinkageDigitClearClaimBoundDecimal,
                    consistencyRepetitions: compactVssConsistencyRepetitions,
                    consistencyCoefficientBits:
                        compactVssConsistencyCoefficientBits,
                    consistencyCoefficientMaximumDecimal:
                        compactVssConsistencyCoefficientMaximum.toString(),
                    claimMaskRadix: compactVssClaimMaskRadix,
                    maskDigitCount: compactVssDigitClaimMaskDigitCount,
                    rangeEvidenceRule:
                        'direct masked claims bind committed base-3^17 digit columns without trit decoder columns',
                },
                {
                    rowId: 'compact-vss-same-secret-bridge-non-digit-claim',
                    proofFamily: 'compact-same-secret-bridge',
                    claimVectorClass: 'secret-indicator-or-randomness',
                    appliesToRelations: [
                        'compact-vss-same-secret-bridge-target-reduction',
                    ],
                    witnessInfinityBound: 2,
                    clearClaimBoundDecimal:
                        bridgeNonDigitClearClaimBoundDecimal,
                    consistencyRepetitions: setupConsistencyRepetitions,
                    consistencyCoefficientBits: setupConsistencyCoefficientBits,
                    consistencyCoefficientMaximumDecimal:
                        setupConsistencyCoefficientMaximum.toString(),
                    claimMaskRadix: compactVssClaimMaskRadix,
                    maskDigitCount: setupClaimMaskDigitCount,
                    rangeEvidenceRule:
                        'non-digit bridge claims keep the setup-family consistency mask',
                },
                {
                    rowId: 'compact-vss-same-secret-bridge-message-digit-claim',
                    proofFamily: 'compact-same-secret-bridge',
                    claimVectorClass: 'target-message-digit',
                    appliesToRelations: [
                        'compact-vss-same-secret-bridge-target-reduction',
                    ],
                    targetRnsLimbCount: input.targetRnsPrimes.length,
                    messageDigitBaseDecimal:
                        compactVssMessageDigitBase.toString(),
                    messageDigitCount: compactVssMessageDigitCount,
                    directDigitVectorCount:
                        input.targetRnsPrimes.length *
                        compactVssMessageDigitCount,
                    witnessInfinityBoundDecimal:
                        compactVssMessageDigitMaximum.toString(),
                    clearClaimBoundDecimal: bridgeDigitClearClaimBoundDecimal,
                    consistencyRepetitions: setupConsistencyRepetitions,
                    consistencyCoefficientBits: setupConsistencyCoefficientBits,
                    consistencyCoefficientMaximumDecimal:
                        setupConsistencyCoefficientMaximum.toString(),
                    claimMaskRadix: compactVssClaimMaskRadix,
                    maskDigitCount: compactVssDigitClaimMaskDigitCount,
                    rangeEvidenceRule:
                        'bridge target messages use direct digit claims and do not add message trit decoder columns',
                },
                {
                    rowId: 'compact-vss-target-decryption-aggregate-message-claim',
                    proofFamily: 'target-decryption-share',
                    claimVectorClass: 'aggregate-opening-message-digit',
                    appliesToRelations: ['target-decryption-share-proof'],
                    targetRnsLimbCount: input.targetRnsPrimes.length,
                    largestTargetRnsPrime,
                    aggregateMessageCoefficientBoundDecimal:
                        aggregateTargetMessageCoefficientBound.toString(),
                    messageDigitBaseDecimal:
                        compactVssMessageDigitBase.toString(),
                    messageDigitCount: compactVssMessageDigitCount,
                    witnessInfinityBoundDecimal:
                        aggregateTargetMessageDigitMaximum.toString(),
                    clearClaimBoundDecimal:
                        aggregateTargetMessageClearClaimBoundDecimal,
                    consistencyRepetitions: setupConsistencyRepetitions,
                    consistencyCoefficientBits: setupConsistencyCoefficientBits,
                    consistencyCoefficientMaximumDecimal:
                        setupConsistencyCoefficientMaximum.toString(),
                    claimMaskRadix: compactVssClaimMaskRadix,
                    maskDigitCount:
                        targetDecryptionAggregateMessageClaimMaskDigitCount,
                    rangeEvidenceRule:
                        'target aggregate messages use direct masked claims for each committed base-3^17 digit without trit decoder columns',
                },
                {
                    rowId: 'compact-vss-target-decryption-smudging-message-claim',
                    proofFamily: 'target-decryption-share',
                    claimVectorClass: 'smudging-opening-message-digit',
                    appliesToRelations: ['target-decryption-share-proof'],
                    smudgingMessageCoefficientBound:
                        targetDecryptionSmudgingMessageCoefficientBound,
                    messageDigitBaseDecimal:
                        compactVssMessageDigitBase.toString(),
                    messageDigitCount: compactVssMessageDigitCount,
                    witnessInfinityBoundDecimal:
                        smudgingTargetMessageDigitMaximum.toString(),
                    clearClaimBoundDecimal:
                        smudgingTargetMessageClearClaimBoundDecimal,
                    consistencyRepetitions: setupConsistencyRepetitions,
                    consistencyCoefficientBits: setupConsistencyCoefficientBits,
                    consistencyCoefficientMaximumDecimal:
                        setupConsistencyCoefficientMaximum.toString(),
                    claimMaskRadix: compactVssClaimMaskRadix,
                    maskDigitCount:
                        targetDecryptionSmudgingMessageClaimMaskDigitCount,
                    rangeEvidenceRule:
                        'target smudging messages use direct masked claims for each committed base-3^17 digit without trit decoder columns',
                },
                {
                    rowId: 'compact-vss-target-decryption-randomness-claim',
                    proofFamily: 'target-decryption-share',
                    claimVectorClass: 'target-opening-randomness',
                    appliesToRelations: ['target-decryption-share-proof'],
                    witnessInfinityBound: 1,
                    clearClaimBoundDecimal:
                        targetRandomnessClearClaimBoundDecimal,
                    consistencyRepetitions: setupConsistencyRepetitions,
                    consistencyCoefficientBits: setupConsistencyCoefficientBits,
                    consistencyCoefficientMaximumDecimal:
                        setupConsistencyCoefficientMaximum.toString(),
                    claimMaskRadix: compactVssClaimMaskRadix,
                    maskDigitCount:
                        targetDecryptionRandomnessClaimMaskDigitCount,
                    rangeEvidenceRule:
                        'target opening randomness claims use ternary witness columns and the target randomness mask',
                },
            ],
            targetBasisReductionRows: [
                {
                    rowId: 'compact-vss-same-secret-bridge-target-reduction',
                    sourceSecretDistribution: 'standard-ternary',
                    sourceSignedRepresentativeInfinityBound: 1,
                    targetRnsLimbCount: input.targetRnsPrimes.length,
                    targetRnsPrimes: input.targetRnsPrimes,
                    targetBasisHash: input.targetBasisHash,
                    targetBasisLimbOrder: 'profile-order-prefix',
                    sameSecretProofFamilyBindingRoot:
                        input.sameSecretProofFamilyBindingRoot,
                },
            ],
            reviewReductionRows: [
                {
                    rowId: 'compact-vss-module-sis-binding-review-input',
                    problem: 'Module-SIS',
                    openingWitnessRows: [
                        'compact-vss-fresh-opening-witness',
                        'compact-vss-aggregate-opening-witness',
                    ],
                    linearRelationRows: [
                        'compact-vss-recipient-share-shamir-evaluation',
                        'compact-vss-aggregate-threshold-public-sum',
                        'compact-vss-one-recipient-aggregate-from-source-coefficients',
                    ],
                    maskedClaimNormRows: [
                        'compact-vss-share-linkage-carry-claim',
                        'compact-vss-share-linkage-message-digit-claim',
                        'compact-vss-same-secret-bridge-non-digit-claim',
                        'compact-vss-same-secret-bridge-message-digit-claim',
                        'compact-vss-target-decryption-aggregate-message-claim',
                        'compact-vss-target-decryption-smudging-message-claim',
                        'compact-vss-target-decryption-randomness-claim',
                    ],
                    collisionDifferenceRule:
                        'subtract two accepted openings over the integers before reducing to the commitment modulus',
                },
                {
                    rowId: 'compact-vss-module-lwe-hiding-review-input',
                    problem: 'Module-LWE',
                    openingWitnessRows: [
                        'compact-vss-fresh-opening-witness',
                        'compact-vss-aggregate-opening-witness',
                    ],
                    maskedClaimNormRows: [
                        'compact-vss-share-linkage-carry-claim',
                        'compact-vss-share-linkage-message-digit-claim',
                        'compact-vss-same-secret-bridge-non-digit-claim',
                        'compact-vss-same-secret-bridge-message-digit-claim',
                        'compact-vss-target-decryption-aggregate-message-claim',
                        'compact-vss-target-decryption-smudging-message-claim',
                        'compact-vss-target-decryption-randomness-claim',
                    ],
                    randomnessSource:
                        'balanced-ternary opening columns before public linear aggregation',
                    sampledProjectionIndicesPerCommitment,
                },
            ],
        },
        estimatorInputRows: [
            {
                rowId: 'compact-vss-module-sis-binding-input',
                problem: 'Module-SIS',
                targetSecurityBits: 128,
                ringDegree,
                commitmentModulusLimbIndices:
                    compactVssCommitmentModulusLimbIndices,
                commitmentModulusLimbs,
                outputCoordinateCount:
                    compactVssCommitmentOutputCoordinateCount,
                messageWidth: compactVssMessageDigitCount,
                randomnessWidth: compactVssCommitmentRandomnessColumnCount,
                projectionWeight: compactVssProjectionWeight,
                sampledMatrixResiduesPerCommitment,
                sampledProjectionIndicesPerCommitment,
            },
            {
                rowId: 'compact-vss-module-lwe-hiding-input',
                problem: 'Module-LWE',
                targetSecurityBits: 128,
                ringDegree,
                commitmentModulusLimbIndices:
                    compactVssCommitmentModulusLimbIndices,
                commitmentModulusLimbs,
                outputCoordinateCount:
                    compactVssCommitmentOutputCoordinateCount,
                messageWidth: compactVssMessageDigitCount,
                randomnessWidth: compactVssCommitmentRandomnessColumnCount,
                projectionWeight: compactVssProjectionWeight,
                sampledMatrixResiduesPerCommitment,
                sampledProjectionIndicesPerCommitment,
            },
        ],
        sameSecretBridgeInput: {
            targetBasisHash: input.targetBasisHash,
            targetRnsPrimes: input.targetRnsPrimes,
            sameSecretProofFamilyBindingRoot:
                input.sameSecretProofFamilyBindingRoot,
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
