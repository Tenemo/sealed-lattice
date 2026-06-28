import { performance } from 'node:perf_hooks';

import {
    createPrivateVssMailboxKeyPair,
    deriveProtocolHash,
    hash512Hex,
} from '#packages/crypto/src/index.js';
import {
    aggregateCompactVssThresholdShareCommitments,
    compactVssCommitmentBinaryFormat,
    compactVssCommitmentRandomnessColumnCount,
    compactVssCommitmentProfileId,
    compactVssCommitmentMeasurement,
    compactVssCommitmentPrivateOpeningRoot,
    compactVssMessageDigitCount,
    compactVssMessageDigitBase,
    compactVssMessageDigitTritCount,
    compactVssShareLinkageAggregateThresholdRule,
    compactVssShareLinkageCommonKeyRule,
    compactVssShareLinkageProofBatchingRule,
    compactVssShareLinkageShamirEvaluationRule,
    computeCompactVssCommitmentFromOpening,
    createCompactVssCoefficientCommitmentSet,
    createCompactVssRecipientShareCommitmentBundle,
    createCompactVssShareLinkageProofMaterialSet,
    createCompactVssShareLinkageStatement,
    decodeCompactVssCommitmentBody,
    encodeCompactVssShareLinkageProofMaterialSetBinary,
    encodeCompactVssCommitmentBody,
    verifyCompactVssCommitmentOpening,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssCommitmentBodyMetadata,
    type CompactVssCommitmentOpeningInput,
    type CompactVssCommitmentValue,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssShareLinkageProofMaterialInput,
    type CompactVssShareLinkageStatement,
} from '#packages/protocol/src/setup/compact-vss-commitments.js';
import {
    createEncryptedLocalTrusteeSetupStateFromVerifiedShares,
    type GeneratedLocalTrusteeSetupStateInput,
    type GeneratedLocalTrusteeSetupStateResult,
} from '#packages/protocol/src/setup/local-trustee-setup-state.js';
import {
    createPrivateVssMailboxDeliverySet,
    type PrivateVssMailboxDeliveryKernel,
    type PrivateVssMailboxDeliverySet,
    type PrivateVssSourceTrusteeContributionState,
} from '#packages/protocol/src/setup/private-vss-mailbox-delivery.js';
import {
    compactVssSameSecretBridgeIntegerSupport,
    compactVssSameSecretBridgeRelation,
    compactVssSameSecretBridgeSignedRepresentativeConvention,
    compactVssSameSecretBridgeTargetBasisLimbOrder,
    createCompactVssSameSecretBridgeProofMaterialSet,
    sameSecretProofFamily,
    sameSecretRelation,
    setupProofProfileId,
    type CompactVssSameSecretBridgeStatementSet,
} from '#packages/protocol/src/setup/same-secret-consistency-records.js';
import {
    acceptedBgvProfileRingDegree,
    acceptedBgvSetupQSharePrimes,
} from '#packages/protocol/src/setup/vss-coefficient-commitments.js';
import type { CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records.js';
import { encodeBgvTargetDecryptionShareProofMaterialBinary } from '#packages/protocol/src/target-decryption/proof-material-transport.js';
import type { ProtocolHash } from '#packages/types/src/index.js';
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index.js';
import type {
    BgvCompactVssCommitmentBodyMetadata,
    BgvCompactVssCommitmentOpeningInput,
    BgvCompactSameSecretBridgeProofStatement,
    BgvCompactVssShareLinkageProofStatement,
    BgvTrusteeEvaluationKeyStatementContext,
    TranscriptCoreKernel,
} from '#packages/wasm/src/transcript-core-bridge.js';

const warmRunCount = 5;
const firstProfileParticipantCount = 10;
const firstProfileThresholdDegree = 4;
const currentFullCoefficientTransportBytes = 1_604_341_697;
const targetRnsLimbCount = 7;
const canonicalTargetCiphertextLevel = targetRnsLimbCount - 1;
const selectedEvaluatorWorkingLevel = 15;
const restrictedProofRingDegree = 128;
const restrictedProofSourceMessageModulus = 140_737_487_306_753;
const compactVssShareLinkageStatementRelation =
    'recipient share commitments open to Shamir evaluations of the coefficient commitments, and aggregate threshold commitments are the public sum of recipient share commitments';
const restrictedProofSourceMessageModulusForLimb = (
    sourceRnsLimbIndex: number,
): number =>
    acceptedBgvSetupQSharePrimes[sourceRnsLimbIndex] ??
    restrictedProofSourceMessageModulus;
const restrictedProofCoefficientCount = 3;
const minimumPublicCommitmentReductionFactor = 2_800;
const publicSetupDownloadBudgetBytes = 64 * 1024 * 1024;
const maximumRecipientPrivateMailboxDownloadBytes = 128 * 1024 * 1024;
const maximumSourceTrusteePrivateMailboxUploadBytes = 256 * 1024 * 1024;
const maximumPersistentLocalStateBytes = 16 * 1024 * 1024;
const maximumPrivateStateBuildSeconds = 10;
const maximumRestrictedProofPayloadBytes = 8 * 1024 * 1024;
const maximumTargetProofMaterialJsonBytes = 16 * 1024 * 1024;
const maximumTargetProofMaterialBinaryFrameBytes = 8 * 1024 * 1024;
const maximumTargetProofMaterialRawProofBytes = 12 * 1024 * 1024;
const maximumTargetProofMaterialGenerationSeconds = 180;
const maximumTargetProofMaterialVerificationSeconds = 30;
const maximumWarmWasmFullProfileGenerationSeconds = 30;
const maximumWarmWasmFullProfileVerificationSeconds = 30;
const maximumMeasuredDevelopmentArtifactJsonBytes = 16 * 1024 * 1024;
const privateVssShareProofFramingSampleBytes = 32;
const proofFieldResidueBitWidth = 47;
const proofFormatMarkerByteLength = 8;
const proofLengthPrefixByteLength = 8;
const proofMerkleDigestByteLength = 32;
const proofLeafSaltByteLength = 32;
const proofChallengeExtensionDegree = 4;
const proofTraceSplit = 2;
const proofDomainBlowup = 4;
const proofCommitmentBoundFactor = 2;
const proofPhaseTwoColumnCount = 4;
const proofDeepEvaluationPointCount = 3;
const proofLowDegreeQueryCount = 156;
const proofLowDegreeMinimumFinalCoefficientCount = 32;
const proofLowDegreeMaximumFinalCoefficientCount = 1024;
const proofConsistencyRepetitions = 20;
const compactShareLinkageConsistencyRepetitions = 4;
const proofSetupCommitmentLimbCount = 3;
const compactShareLinkageCarryClaimMaskDigitCount = 75;
const targetDecryptionAggregateMessageClaimMaskDigitCount = 142;
const targetDecryptionSmudgingMessageClaimMaskDigitCount = 114;
const targetDecryptionRandomnessClaimMaskDigitCount = 114;
const targetProofMaterialMeasurementRequested =
    process.env.SEALED_LATTICE_MEASURE_TARGET_PROOF_MATERIAL === '1';

const isPowerOfTwo = (value: number): boolean =>
    Number.isSafeInteger(value) &&
    value > 0 &&
    Number.isInteger(Math.log2(value));

type CompactVssMessageEncodingLayout = Readonly<{
    readonly highDigitTritCount: number;
    readonly encodingColumnCount: number;
    readonly totalTritCount: number;
}>;

const compactVssTritCountForBound = (boundExclusive: number): number => {
    if (!Number.isSafeInteger(boundExclusive) || boundExclusive <= 0) {
        throw new Error('compact VSS message bound must be positive.');
    }
    let representedBound = 1;
    let tritCount = 0;
    while (representedBound < boundExclusive) {
        representedBound *= 3;
        if (!Number.isSafeInteger(representedBound)) {
            throw new Error(
                'compact VSS trit bound exceeds safe integer range.',
            );
        }
        tritCount += 1;
    }

    return tritCount;
};

const compactVssMessageEncodingLayoutForBound = (
    messageBoundExclusive: number,
): CompactVssMessageEncodingLayout => {
    if (
        !Number.isSafeInteger(messageBoundExclusive) ||
        messageBoundExclusive <= 0
    ) {
        throw new Error('compact VSS message bound must be positive.');
    }
    const highDigitBoundExclusive = Math.ceil(
        messageBoundExclusive / compactVssMessageDigitBase,
    );
    const highDigitTritCount = compactVssTritCountForBound(
        highDigitBoundExclusive,
    );
    const totalTritCount = compactVssMessageDigitTritCount + highDigitTritCount;

    return {
        highDigitTritCount,
        totalTritCount,
        encodingColumnCount: compactVssMessageDigitCount + totalTritCount,
    };
};

type JsonRecord = Readonly<Record<string, unknown>>;

const canonicalTargetBasis = {
    objectType: 'CanonicalTargetBasis',
    objectVersion: 1,
    basisId: 'sealed-lattice-bgv-rns-data-basis-v1',
    targetLevel: canonicalTargetCiphertextLevel,
    primeOrder: 'profile-order-prefix',
    targetPrimes: acceptedBgvSetupQSharePrimes.slice(0, targetRnsLimbCount),
    modulusSwitchSchedule: {
        sourceWorkingLevel: selectedEvaluatorWorkingLevel,
        terminalLevel: canonicalTargetCiphertextLevel,
        rule: 'drop trailing data-basis primes until the terminal target level is reached',
    },
    scalingNormalization:
        'normalize ciphertext decrypt scaling to one before target roots are computed',
    targetCiphertextRule:
        'target id and target order ciphertexts must both use the canonical target level',
} as const satisfies JsonRecord;

const canonicalTargetBasisHash = deriveProtocolHash(
    'TargetBasisHash',
    canonicalTargetBasis,
);

type TimedSamples = Readonly<{
    readonly coldMilliseconds: number;
    readonly warmMedianMilliseconds: number;
    readonly warmSamplesMilliseconds: readonly number[];
}>;

type MeasuredOperation<Result> = Readonly<{
    readonly samples: TimedSamples;
    readonly lastResult: Result;
}>;

type TypeScriptPathMeasurement = Readonly<{
    readonly generation: MeasuredOperation<
        ReturnType<typeof computeCompactVssCommitmentFromOpening>
    >;
    readonly bodyEncoding: MeasuredOperation<Uint8Array>;
    readonly bodyDecoding: MeasuredOperation<CompactVssCommitmentValue>;
    readonly verification: MeasuredOperation<
        ReturnType<typeof verifyCompactVssCommitmentOpening>
    >;
}>;

type WasmPathMeasurement = Readonly<{
    readonly generation: MeasuredOperation<
        ReturnType<
            TranscriptCoreKernel['computeCompactVssCommitmentFromOpening']
        >
    >;
    readonly bodyEncoding: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['encodeCompactVssCommitmentBody']>
    >;
    readonly bodyDecoding: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['decodeCompactVssCommitmentBody']>
    >;
    readonly verification: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['verifyCompactVssCommitmentOpening']>
    >;
}>;

type RestrictedCompactShareLinkageProofFixture = Readonly<{
    readonly context: BgvTrusteeEvaluationKeyStatementContext;
    readonly compactVssShareLinkage: BgvCompactVssShareLinkageProofStatement;
    readonly fullSourceBatch: boolean;
    readonly proofItemCount: number;
    readonly coefficientWitnessColumnCount: number;
    readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
    readonly recipientShareMessages: readonly number[];
    readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
    readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
    readonly carryWitnesses: readonly number[];
    readonly recipientShareMessagesByItem: readonly (readonly number[])[];
    readonly recipientShareOpeningRandomnessByItem: readonly (readonly (readonly number[])[])[];
    readonly carryWitnessesByItem: readonly (readonly number[])[];
}>;

type RestrictedShareLinkageProofItem =
    | BgvCompactVssShareLinkageProofStatement
    | NonNullable<
          BgvCompactVssShareLinkageProofStatement['additionalLinkageItems']
      >[number];

type RestrictedShareLinkageProofFixtureItem = RestrictedShareLinkageProofItem &
    Readonly<{
        readonly sourceMessageModulus: number;
        readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
        readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
        readonly recipientShareMessages: readonly number[];
        readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
        readonly carryWitnesses: readonly number[];
    }>;

type CompactVssCommitmentWithOpeningRoot = ReturnType<
    typeof computeCompactVssCommitmentFromOpening
> &
    Readonly<{
        readonly openingRoot: ProtocolHash;
    }>;

type RestrictedSourceLimbFixture = Readonly<{
    readonly sourceRnsLimbIndex: number;
    readonly sourceMessageModulus: number;
    readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
    readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
    readonly coefficientComputations: readonly CompactVssCommitmentWithOpeningRoot[];
}>;

type RestrictedCompactShareLinkageProofMeasurement = Readonly<{
    readonly generation: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['generateCompactVssShareLinkageProof']>
    >;
    readonly verification: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['verifyCompactVssShareLinkageProof']>
    >;
    readonly proofByteBreakdown: EncodedTargetProofByteBreakdown;
}>;

type RestrictedCompactShareLinkageProofMaterialMeasured = Readonly<{
    readonly measurementMode: 'full-source-material-set';
    readonly proofMaterialSetJsonBytes: number;
    readonly binaryProofMaterialTransportBytes: number;
    readonly binaryProofMaterialTransportChunkCount: number;
    readonly binaryProofMaterialTransportChunkRoot: ProtocolHash;
    readonly binaryProofMaterialTransportFullObjectHash: ProtocolHash;
    readonly binaryProofMaterialTransportSavingsBytes: number;
    readonly binaryProofMaterialTransportPublicSetupDownloadHeadroomBytes: number;
    readonly generatedSourceProofCount: number;
    readonly additionalGeneratedSourceProofCount: number;
    readonly sourceZeroWarmGenerationMilliseconds: number;
    readonly additionalProofGenerationMilliseconds: number;
    readonly estimatedAllSourceProofGenerationMilliseconds: number;
    readonly verificationMilliseconds: number;
    readonly verification: ReturnType<
        TranscriptCoreKernel['verifyCompactVssShareLinkageProofMaterialSet']
    >;
}>;

type RestrictedCompactShareLinkageProofMaterialNotMeasured = Readonly<{
    readonly measurementMode: 'not-measured';
    readonly reason: string;
}>;

type RestrictedCompactShareLinkageProofMaterialMeasurement =
    | RestrictedCompactShareLinkageProofMaterialMeasured
    | RestrictedCompactShareLinkageProofMaterialNotMeasured;

const restrictedShareLinkageProofMaterialWasMeasured = (
    measurement: RestrictedCompactShareLinkageProofMaterialMeasurement,
): measurement is RestrictedCompactShareLinkageProofMaterialMeasured =>
    measurement.measurementMode === 'full-source-material-set';

type FirstProfileRestrictedProofCoverageEstimate = Readonly<{
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
    readonly shareLinkageProofItemsPerSource: number;
    readonly measuredShareLinkageProofItemsPerRecord: number;
    readonly measuredShareLinkageCoefficientWitnessColumnsPerRecord: number;
    readonly sourceBatchMeasurementMode: string;
    readonly proofPayloadConclusion: string;
    readonly setupTransportConclusion: string;
    readonly shareLinkageProofRecordsPerSource: number;
    readonly shareLinkageProofRecordCount: number;
    readonly shareLinkageRepeatedProofPayloadBytes: number;
    readonly sameSecretBridgeProofRecordCount: number;
    readonly sameSecretBridgeRepeatedProofPayloadBytes: number;
    readonly sameSecretBridgeRepeatedProofMaterialJsonBytes: number;
    readonly combinedRepeatedProofPayloadBytes: number;
    readonly activationBoundary: string;
}>;

type RestrictedCompactSameSecretBridgeProofFixture = Readonly<{
    readonly context: BgvTrusteeEvaluationKeyStatementContext;
    readonly compactSameSecretBridge: BgvCompactSameSecretBridgeProofStatement;
    readonly secretCoefficients: readonly number[];
    readonly negativeIndicatorCoefficients: readonly number[];
    readonly openingRandomnessByLimb: readonly (readonly (readonly number[])[])[];
}>;

type RestrictedCompactSameSecretBridgeProofMeasurement = Readonly<{
    readonly generation: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['generateCompactSameSecretBridgeProof']>
    >;
    readonly verification: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['verifyCompactSameSecretBridgeProof']>
    >;
}>;

type RestrictedCompactSameSecretBridgeProofMaterialMeasurement = Readonly<{
    readonly proofMaterialSetJsonBytes: number;
    readonly verification: MeasuredOperation<
        ReturnType<
            TranscriptCoreKernel['verifyCompactVssSameSecretBridgeProofMaterialSet']
        >
    >;
}>;

type TargetDecryptionDevelopmentArtifactMeasurement = Readonly<{
    readonly localTargetShareWitnessJsonBytes: number;
    readonly targetDecryptionSmudgingWitnessJsonBytes: number;
    readonly compactAggregateOpeningWitnessJsonBytes: number;
    readonly compactAggregateOpeningCredentialCount: number;
    readonly compactAggregateOpeningCredentialsJsonBytes: number;
    readonly targetShareJsonBytes: number;
    readonly targetSharePayloadJsonBytes: number;
    readonly smudgingInputReportJsonBytes: number;
    readonly proofStatementJsonBytes: number;
    readonly statementBindingVerificationJsonBytes: number;
    readonly largestSingleObjectJsonBytes: number;
}>;

type EncodedTargetProofByteBreakdown = Readonly<{
    readonly totalBytes: number;
    readonly formatAndLengthPrefixBytes: number;
    readonly commitmentRootBytes: number;
    readonly maskedConsistencyClaimBytes: number;
    readonly deepEvaluationBytes: number;
    readonly lowDegreeFoldRootBytes: number;
    readonly lowDegreeFinalCoefficientBytes: number;
    readonly lowDegreeQuerySiblingBytes: number;
    readonly lowDegreeQueryPathBytes: number;
    readonly phaseOneRowBytes: number;
    readonly phaseOnePathBytes: number;
    readonly phaseTwoRowBytes: number;
    readonly phaseTwoPathBytes: number;
    readonly leafSaltBytes: number;
    readonly fieldResidueBytes: number;
    readonly merkleHashBytes: number;
}>;

type TargetProofMaterialBinaryFrameMeasurement = Readonly<{
    readonly proofMaterialBinaryFrameBytesByShare: readonly number[];
    readonly proofMaterialBinaryFrameBytesTotal: number;
    readonly proofMaterialBinaryFrameChunkCountByShare: readonly number[];
    readonly proofMaterialBinaryFrameChunkRootByShare: readonly ProtocolHash[];
    readonly proofMaterialBinaryFrameFullObjectHashByShare: readonly ProtocolHash[];
    readonly proofMaterialBinaryFrameSavingsBytes: number;
    readonly proofMaterialBinaryFrameOverRawProofBytes: number;
}>;

type TargetDecryptionProofMaterialMeasurement = Readonly<{
    readonly measurementMode: string;
    readonly shareCount: number;
    readonly proofMaterialJsonBytesByShare: readonly number[];
    readonly proofMaterialJsonBytesTotal: number;
    readonly binaryFrame: TargetProofMaterialBinaryFrameMeasurement;
    readonly proofMaterialProofRecordCountByShare: readonly number[];
    readonly proofMaterialTotalProofByteLengthByShare: readonly number[];
    readonly proofMaterialTotalProofByteLength: number;
    readonly proofMaterialProofByteBreakdownByShare: readonly EncodedTargetProofByteBreakdown[];
    readonly proofMaterialProofByteBreakdownTotal: EncodedTargetProofByteBreakdown;
    readonly proofMaterialGenerationMilliseconds: number;
    readonly proofMaterialVerificationJsonBytesByShare: readonly number[];
    readonly proofMaterialVerificationJsonBytesTotal: number;
    readonly proofMaterialVerificationMilliseconds: number;
    readonly proofMaterialBinaryVerificationJsonBytesByShare: readonly number[];
    readonly proofMaterialBinaryVerificationJsonBytesTotal: number;
    readonly proofMaterialBinaryVerificationMilliseconds: number;
    readonly largestSingleObjectJsonBytes: number;
}>;

type TargetDecryptionProofMaterialNotMeasured = Readonly<{
    readonly measurementMode: string;
}>;

const targetProofMaterialWasMeasured = (
    measurement:
        | TargetDecryptionProofMaterialMeasurement
        | TargetDecryptionProofMaterialNotMeasured,
): measurement is TargetDecryptionProofMaterialMeasurement =>
    'proofMaterialJsonBytesTotal' in measurement;

type TargetDecryptionDevelopmentMeasurements = Readonly<{
    readonly artifacts: TargetDecryptionDevelopmentArtifactMeasurement;
    readonly proofMaterial:
        | TargetDecryptionProofMaterialMeasurement
        | TargetDecryptionProofMaterialNotMeasured;
}>;

type TargetDecryptionShareMeasurementBundle = Readonly<{
    readonly trusteeIdentity: string;
    readonly localTargetShareWitness: JsonRecord;
    readonly targetShare: ReturnType<
        TranscriptCoreKernel['generateBgvTargetDecryptionShareFromLocalShare']
    >;
    readonly proofStatement: ReturnType<
        TranscriptCoreKernel['deriveBgvTargetDecryptionShareProofStatement']
    >;
}>;

type PrivateMailboxDevelopmentArtifactMeasurement = Readonly<{
    readonly qShareLimbCount: number;
    readonly ringDegree: number;
    readonly thresholdDegree: number;
    readonly sourceRecipientEnvelopeCountInFirstProfile: number;
    readonly sourceRecipientEnvelopeCountPerSourceInFirstProfile: number;
    readonly buildMilliseconds: number;
    readonly privateShareProofFramingSampleBytesPerLimb: number;
    readonly privateShareProofFramingSampleBytesTotal: number;
    readonly compactRecipientShareOpeningCredentialCount: number;
    readonly compactRecipientShareOpeningCredentialsJsonBytes: number;
    readonly privateEnvelopeJsonBytes: number;
    readonly transportedPrivateVssShareProofMaterialJsonBytes: number;
    readonly privateEnvelopeAadJsonBytes: number;
    readonly encryptedEnvelopeJsonBytes: number;
    readonly envelopeReferenceJsonBytes: number;
    readonly deliverySetJsonBytes: number;
    readonly envelopeReferenceJsonBytesExtrapolatedToFirstProfile: number;
    readonly sourceTrusteeEnvelopeReferenceJsonBytesExtrapolatedToFirstProfile: number;
    readonly sourceTrusteeUploadBudgetMarginBytes: number;
    readonly largestSingleObjectJsonBytes: number;
}>;

type EncryptedLocalStateDevelopmentArtifactMeasurement = Readonly<{
    readonly qShareLimbCount: number;
    readonly ringDegree: number;
    readonly sourceEnvelopeCount: number;
    readonly buildMilliseconds: number;
    readonly aggregateThresholdSharePlaintextBytes: number;
    readonly targetDecryptionProofWitnessPlaintextBytes: number;
    readonly localStateManifestPlaintextBytes: number;
    readonly encryptedLocalStateJsonBytes: number;
    readonly localStateCommitmentJsonBytes: number;
    readonly sealedAggregateThresholdShareJsonBytes: number;
    readonly sealedTargetDecryptionProofWitnessJsonBytes: number;
    readonly largestSingleObjectJsonBytes: number;
}>;

type PrivateStateDevelopmentArtifactMeasurement = Readonly<{
    readonly privateMailbox: PrivateMailboxDevelopmentArtifactMeasurement;
    readonly encryptedLocalState: EncryptedLocalStateDevelopmentArtifactMeasurement;
    readonly largestSingleObjectJsonBytes: number;
}>;

type FullRingPrivateStateFixture = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly vssCoefficientCommitmentRoot: ProtocolHash;
    readonly sourceTrusteeContributionState: PrivateVssSourceTrusteeContributionState;
    readonly recipientTrustees: readonly {
        readonly trusteeIdentity: string;
        readonly trusteeRosterPosition: number;
    }[];
    readonly mailboxPublicKeyBytesHex: string;
    readonly compactRecipientShareOpeningCredentials: ReturnType<
        typeof createCompactVssRecipientShareCommitmentBundle
    >['recipientShareOpeningCredentials'];
    readonly compactRecipientShareOpeningCredentialsJsonBytes: number;
    readonly coefficientCommitmentSet: ReturnType<
        typeof createCompactVssCoefficientCommitmentSet
    >;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly shareLinkageStatement: CompactVssShareLinkageStatement;
}>;

const median = (samples: readonly number[]): number => {
    const sortedSamples = [...samples].sort((left, right) => left - right);
    const middleIndex = Math.floor(sortedSamples.length / 2);
    const middleValue = sortedSamples[middleIndex];
    if (middleValue === undefined) {
        throw new Error('measurement requires at least one sample.');
    }

    return middleValue;
};

const timed = <Result>(
    operation: () => Result,
): Readonly<{
    readonly result: Result;
    readonly milliseconds: number;
}> => {
    const startedAtMilliseconds = performance.now();
    const result = operation();
    const milliseconds = performance.now() - startedAtMilliseconds;

    return { result, milliseconds };
};

const fullRingOpening = (): CompactVssCommitmentOpeningInput => {
    const publicMatrixSeedHash = deriveProtocolHash(
        'SetupPublicMatrixSeedHash',
        {
            measurement: 'compact-vss',
            label: 'manual-cpu-sanity',
        },
    );
    const rnsPrime = acceptedBgvSetupQSharePrimes[0];
    if (rnsPrime === undefined) {
        throw new Error('accepted profile must define at least one RNS prime.');
    }
    const messageCoefficients = Array.from(
        { length: acceptedBgvProfileRingDegree },
        (_unused, coefficientIndex) =>
            (coefficientIndex * 65_537 + 17) % rnsPrime,
    );
    const randomnessByColumn = [0, 1].map((columnIndex) =>
        Array.from(
            { length: acceptedBgvProfileRingDegree },
            (_unused, coefficientIndex) => {
                const residue = (coefficientIndex + columnIndex * 2) % 5;

                return residue - 2;
            },
        ),
    );

    return {
        commitmentRole: 'aggregate-threshold-share',
        commitmentContext: {
            objectType: 'CompactVssAggregateThresholdShareCommitmentContext',
            objectVersion: 1,
            ceremonyId: 'compact-vss-measurement',
            recipientIdentity: 'trustee-1',
            recipientRosterPosition: 0,
            rnsLimbIndex: 0,
            rnsPrime,
        },
        publicMatrixSeedHash,
        rnsLimbIndex: 0,
        rnsPrime,
        ringDegree: acceptedBgvProfileRingDegree,
        messageCoefficients,
        randomnessByColumn,
    };
};

const repeatedProtocolHash = (hexDigit: string): string => hexDigit.repeat(128);

const restrictedProofTernaryRandomness = (
    seedOffset: number,
): readonly (readonly number[])[] =>
    Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        (_unusedColumn, columnIndex) =>
            Array.from(
                { length: restrictedProofRingDegree },
                (_unusedCoefficient, coefficientIndex) =>
                    ((seedOffset + columnIndex * 5 + coefficientIndex * 7) %
                        3) -
                    1,
            ),
    );

const compactShareLinkageSourceCoefficientRecordFromProofItems = (input: {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly targetRnsLimbCountForStatement: number;
    readonly proofItems: readonly RestrictedShareLinkageProofItem[];
}): CompactVssCoefficientCommitmentSet['sourceTrusteeRecords'][number] => {
    const proofItemsBySourceLimb = new Map(
        input.proofItems.map((proofItem) => [
            proofItem.sourceRnsLimbIndex,
            proofItem,
        ]),
    );
    const coefficientCommitments = Array.from(
        { length: input.targetRnsLimbCountForStatement },
        (_unusedLimb, sourceRnsLimbIndex) => {
            const proofItem = proofItemsBySourceLimb.get(sourceRnsLimbIndex);
            if (proofItem === undefined) {
                throw new Error(
                    'compact share-linkage public coefficient set is missing a source limb.',
                );
            }

            return Array.from(
                { length: restrictedProofCoefficientCount },
                (_unusedCoefficient, shamirCoefficientIndex) =>
                    ({
                        objectType: 'CompactVssCoefficientCommitment',
                        objectVersion: 1,
                        profileId: compactVssCommitmentProfileId,
                        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            input.sourceTrusteeRosterPosition,
                        publicMatrixSeedHash: input.publicMatrixSeedHash,
                        rnsLimbIndex: sourceRnsLimbIndex,
                        rnsPrime: proofItem.sourceMessageModulus,
                        shamirCoefficientIndex,
                        coefficientCommitmentRoot:
                            proofItem.coefficientCommitmentRoots[
                                shamirCoefficientIndex
                            ],
                        coefficientOpeningRoot:
                            proofItem.coefficientOpeningRoots[
                                shamirCoefficientIndex
                            ],
                        commitment: proofItem.coefficientCommitments[
                            shamirCoefficientIndex
                        ] as CompactVssCommitmentValue,
                    }) as const,
            );
        },
    ).flat();
    const sourceRecordWithoutRoot = {
        objectType: 'CompactVssSourceCoefficientCommitments',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        coefficientCommitments,
    } as const;

    return {
        ...sourceRecordWithoutRoot,
        sourceCoefficientCommitmentRoot: deriveProtocolHash(
            'VssCoefficientCommitmentRoot',
            sourceRecordWithoutRoot,
        ),
    };
};

const compactShareLinkageSourceRecipientShareRecordFromProofItems = (input: {
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly participantCount: number;
    readonly targetRnsLimbCountForStatement: number;
    readonly proofItems: readonly RestrictedShareLinkageProofItem[];
}): CompactVssRecipientShareCommitmentSet['sourceTrusteeRecords'][number] => {
    const proofItemsByCoverage = new Map(
        input.proofItems.map((proofItem) => [
            `${String(proofItem.recipientRosterPosition)}:${String(proofItem.sourceRnsLimbIndex)}`,
            proofItem,
        ]),
    );
    const recipientShareCommitments = Array.from(
        { length: input.participantCount },
        (_unusedRecipient, recipientRosterPosition) =>
            Array.from(
                { length: input.targetRnsLimbCountForStatement },
                (_unusedLimb, sourceRnsLimbIndex) => {
                    const proofItem = proofItemsByCoverage.get(
                        `${String(recipientRosterPosition)}:${String(sourceRnsLimbIndex)}`,
                    );
                    if (proofItem === undefined) {
                        throw new Error(
                            'compact share-linkage public recipient-share set is missing a recipient target-limb item.',
                        );
                    }

                    return {
                        objectType: 'CompactVssRecipientShareCommitment',
                        objectVersion: 1,
                        profileId: compactVssCommitmentProfileId,
                        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
                        sourceTrusteeRosterPosition:
                            input.sourceTrusteeRosterPosition,
                        recipientIdentity: proofItem.recipientIdentity,
                        recipientRosterPosition,
                        recipientTrusteePoint: recipientRosterPosition + 1,
                        rnsLimbIndex: sourceRnsLimbIndex,
                        rnsPrime: proofItem.sourceMessageModulus,
                        shareCommitmentRoot:
                            proofItem.recipientShareCommitmentRoot,
                        shareOpeningRoot: proofItem.recipientShareOpeningRoot,
                        commitment:
                            proofItem.recipientShareCommitment as CompactVssCommitmentValue,
                    } as const;
                },
            ),
    ).flat();
    const sourceRecordWithoutRoot = {
        objectType: 'CompactVssSourceRecipientShareCommitments',
        objectVersion: 1,
        profileId: compactVssCommitmentProfileId,
        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        recipientShareCommitments,
    } as const;

    return {
        ...sourceRecordWithoutRoot,
        sourceRecipientShareCommitmentRoot: deriveProtocolHash(
            'ThresholdShareCommitmentRoot',
            sourceRecordWithoutRoot,
        ),
    };
};

const restrictedCompactShareLinkageProofFixture = (
    input: {
        readonly fullSourceBatch?: boolean;
        readonly sourceTrusteeRosterPosition?: number;
    } = {},
): RestrictedCompactShareLinkageProofFixture => {
    const fullSourceBatch = input.fullSourceBatch === true;
    const sourceTrusteeRosterPosition = input.sourceTrusteeRosterPosition ?? 0;
    const publicMatrixSeedHash = repeatedProtocolHash('7');
    const coefficientComputationsForSourceLimb = (
        sourceRnsLimbIndex: number,
        sourceMessageModulus: number,
        coefficientMessagesByShamirIndex: readonly (readonly number[])[],
        coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[],
    ): readonly CompactVssCommitmentWithOpeningRoot[] =>
        coefficientMessagesByShamirIndex.map(
            (messages, shamirCoefficientIndex) => {
                const opening = {
                    commitmentRole: 'coefficient',
                    commitmentContext: {
                        objectType:
                            'CompactVssMeasurementCoefficientCommitmentContext',
                        objectVersion: 1,
                        sourceTrusteeRosterPosition,
                        shamirCoefficientIndex,
                    },
                    publicMatrixSeedHash,
                    rnsLimbIndex: sourceRnsLimbIndex,
                    rnsPrime: sourceMessageModulus,
                    ringDegree: restrictedProofRingDegree,
                    messageCoefficients: messages,
                    messageCoefficientBound: sourceMessageModulus,
                    randomnessByColumn:
                        coefficientOpeningRandomnessByShamirIndex[
                            shamirCoefficientIndex
                        ],
                } as const;

                return {
                    ...computeCompactVssCommitmentFromOpening(opening),
                    openingRoot:
                        compactVssCommitmentPrivateOpeningRoot(opening),
                };
            },
        );
    const sourceForLimb = (
        sourceRnsLimbIndex: number,
    ): RestrictedSourceLimbFixture => {
        const sourceMessageModulus =
            restrictedProofSourceMessageModulusForLimb(sourceRnsLimbIndex);
        const coefficientMessagesByShamirIndex = Array.from(
            { length: restrictedProofCoefficientCount },
            (_unused, shamirCoefficientIndex) =>
                Array.from(
                    { length: restrictedProofRingDegree },
                    (_unusedCoefficient, coefficientIndex) =>
                        coefficientIndex % 11 === shamirCoefficientIndex
                            ? sourceMessageModulus - 4 - shamirCoefficientIndex
                            : (17 +
                                  sourceRnsLimbIndex * 29 +
                                  19 * shamirCoefficientIndex +
                                  23 * coefficientIndex) %
                              sourceMessageModulus,
                ),
        );
        const coefficientOpeningRandomnessByShamirIndex =
            coefficientMessagesByShamirIndex.map(
                (_messages, shamirCoefficientIndex) =>
                    restrictedProofTernaryRandomness(
                        10 + sourceRnsLimbIndex * 23 + shamirCoefficientIndex,
                    ),
            );
        const coefficientComputations = coefficientComputationsForSourceLimb(
            sourceRnsLimbIndex,
            sourceMessageModulus,
            coefficientMessagesByShamirIndex,
            coefficientOpeningRandomnessByShamirIndex,
        );

        return {
            sourceRnsLimbIndex,
            sourceMessageModulus,
            coefficientMessagesByShamirIndex,
            coefficientOpeningRandomnessByShamirIndex,
            coefficientComputations,
        };
    };
    const proofItemForSourceAndRecipient = (
        source: RestrictedSourceLimbFixture,
        recipientRosterPosition: number,
    ): RestrictedShareLinkageProofFixtureItem => {
        const trusteePoint = recipientRosterPosition + 1;
        const trusteePointPowers = Array.from(
            { length: restrictedProofCoefficientCount },
            (_unusedPower, shamirCoefficientIndex) =>
                BigInt(trusteePoint) ** BigInt(shamirCoefficientIndex),
        );
        const recipientShareMessages: number[] = [];
        const carryWitnesses: number[] = [];
        for (
            let coefficientIndex = 0;
            coefficientIndex < restrictedProofRingDegree;
            coefficientIndex += 1
        ) {
            const liftedShare = source.coefficientMessagesByShamirIndex.reduce(
                (sum, messages, shamirCoefficientIndex): bigint => {
                    const trusteePointPower =
                        trusteePointPowers[shamirCoefficientIndex];
                    if (trusteePointPower === undefined) {
                        throw new Error(
                            'restricted proof fixture is missing a trustee-point power.',
                        );
                    }

                    const message = messages[coefficientIndex];
                    if (message === undefined) {
                        throw new Error(
                            'restricted proof fixture is missing a coefficient message.',
                        );
                    }

                    return sum + BigInt(message) * trusteePointPower;
                },
                0n,
            );
            recipientShareMessages.push(
                Number(liftedShare % BigInt(source.sourceMessageModulus)),
            );
            carryWitnesses.push(
                Number(liftedShare / BigInt(source.sourceMessageModulus)),
            );
        }
        const recipientShareOpeningRandomness =
            restrictedProofTernaryRandomness(
                41 +
                    source.sourceRnsLimbIndex * 17 +
                    recipientRosterPosition * 31,
            );
        const recipientShareOpening = {
            commitmentRole: 'recipient-share',
            commitmentContext: {
                objectType:
                    'CompactVssMeasurementRecipientShareCommitmentContext',
                objectVersion: 1,
                sourceTrusteeRosterPosition,
                recipientRosterPosition,
                sourceRnsLimbIndex: source.sourceRnsLimbIndex,
            },
            publicMatrixSeedHash,
            rnsLimbIndex: source.sourceRnsLimbIndex,
            rnsPrime: source.sourceMessageModulus,
            ringDegree: restrictedProofRingDegree,
            messageCoefficients: recipientShareMessages,
            messageCoefficientBound: source.sourceMessageModulus,
            randomnessByColumn: recipientShareOpeningRandomness,
        } as const;
        const recipientShareComputation = {
            ...computeCompactVssCommitmentFromOpening(recipientShareOpening),
            openingRoot: compactVssCommitmentPrivateOpeningRoot(
                recipientShareOpening,
            ),
        };

        return {
            recipientIdentity: `trustee-${recipientRosterPosition}`,
            recipientRosterPosition,
            sourceRnsLimbIndex: source.sourceRnsLimbIndex,
            sourceMessageModulus: source.sourceMessageModulus,
            coefficientCommitmentRoots: source.coefficientComputations.map(
                (computation) => computation.commitmentRoot,
            ),
            coefficientOpeningRoots: source.coefficientComputations.map(
                (computation) => computation.openingRoot,
            ),
            coefficientCommitments: source.coefficientComputations.map(
                (computation) => computation.commitment,
            ),
            recipientShareCommitmentRoot:
                recipientShareComputation.commitmentRoot,
            recipientShareOpeningRoot: recipientShareComputation.openingRoot,
            recipientShareCommitment: recipientShareComputation.commitment,
            recipientShareMessages,
            recipientShareOpeningRandomness,
            carryWitnesses,
            coefficientMessagesByShamirIndex:
                source.coefficientMessagesByShamirIndex,
            coefficientOpeningRandomnessByShamirIndex:
                source.coefficientOpeningRandomnessByShamirIndex,
        };
    };
    const measuredSourceLimbCount = fullSourceBatch ? targetRnsLimbCount : 2;
    const sourceFixtures = Array.from(
        { length: measuredSourceLimbCount },
        (_unused, sourceRnsLimbIndex) => sourceForLimb(sourceRnsLimbIndex),
    );
    const firstSourceFixture = sourceFixtures[0];
    const secondSourceFixture = sourceFixtures[1];
    if (firstSourceFixture === undefined || secondSourceFixture === undefined) {
        throw new Error(
            'restricted compact share-linkage proof fixture requires at least two source limbs.',
        );
    }
    const proofItems: readonly RestrictedShareLinkageProofFixtureItem[] =
        fullSourceBatch
            ? sourceFixtures.flatMap((source) =>
                  Array.from(
                      { length: firstProfileParticipantCount },
                      (_unusedRecipient, recipientRosterPosition) =>
                          proofItemForSourceAndRecipient(
                              source,
                              recipientRosterPosition,
                          ),
                  ),
              )
            : [
                  proofItemForSourceAndRecipient(firstSourceFixture, 0),
                  proofItemForSourceAndRecipient(firstSourceFixture, 1),
                  proofItemForSourceAndRecipient(secondSourceFixture, 0),
              ];
    const primaryProofItem = proofItems[0];
    if (primaryProofItem === undefined) {
        throw new Error(
            'restricted compact share-linkage proof fixture did not create a primary item.',
        );
    }
    const additionalProofItems = proofItems.slice(1);
    let sourceCoefficientCommitmentRoot = deriveProtocolHash(
        'SetupProofRecordBindingHash',
        {
            fixture: 'compact-vss-proof-measurement',
            rootKind: 'sourceCoefficientCommitmentRoot',
            sourceTrusteeRosterPosition,
        },
    );
    let sourceRecipientShareCommitmentRoot = deriveProtocolHash(
        'SetupProofRecordBindingHash',
        {
            fixture: 'compact-vss-proof-measurement',
            rootKind: 'sourceRecipientShareCommitmentRoot',
            sourceTrusteeRosterPosition,
        },
    );
    const sourceTrusteeIdentity = `trustee-${sourceTrusteeRosterPosition}`;
    if (fullSourceBatch) {
        sourceCoefficientCommitmentRoot =
            compactShareLinkageSourceCoefficientRecordFromProofItems({
                sourceTrusteeIdentity,
                sourceTrusteeRosterPosition,
                publicMatrixSeedHash,
                targetRnsLimbCountForStatement: targetRnsLimbCount,
                proofItems,
            }).sourceCoefficientCommitmentRoot;
        sourceRecipientShareCommitmentRoot =
            compactShareLinkageSourceRecipientShareRecordFromProofItems({
                sourceTrusteeIdentity,
                sourceTrusteeRosterPosition,
                participantCount: firstProfileParticipantCount,
                targetRnsLimbCountForStatement: targetRnsLimbCount,
                proofItems,
            }).sourceRecipientShareCommitmentRoot;
    }

    return {
        context: {
            ceremonyId: 'compact-vss-proof-measurement',
            manifestHash: repeatedProtocolHash('1'),
            rosterHash: repeatedProtocolHash('2'),
            trusteeIdentity: sourceTrusteeIdentity,
            trusteeRosterPosition: sourceTrusteeRosterPosition,
            setupEpoch: 'setup-epoch-1',
            sourceCoefficientCommitmentRoot,
            sourceRecipientShareCommitmentRoot,
        },
        fullSourceBatch,
        proofItemCount: proofItems.length,
        coefficientWitnessColumnCount:
            measuredSourceLimbCount * restrictedProofCoefficientCount,
        compactVssShareLinkage: {
            publicMatrixSeedHash,
            sourceTrusteeIdentity,
            sourceTrusteeRosterPosition,
            sourceCoefficientCommitmentRoot,
            sourceRecipientShareCommitmentRoot,
            ...primaryProofItem,
            additionalLinkageItems: additionalProofItems,
        },
        coefficientMessagesByShamirIndex: sourceFixtures.flatMap(
            (source) => source.coefficientMessagesByShamirIndex,
        ),
        recipientShareMessages: primaryProofItem.recipientShareMessages,
        coefficientOpeningRandomnessByShamirIndex: sourceFixtures.flatMap(
            (source) => source.coefficientOpeningRandomnessByShamirIndex,
        ),
        recipientShareOpeningRandomness:
            primaryProofItem.recipientShareOpeningRandomness,
        carryWitnesses: primaryProofItem.carryWitnesses,
        recipientShareMessagesByItem: proofItems.map(
            (proofItem) => proofItem.recipientShareMessages,
        ),
        recipientShareOpeningRandomnessByItem: proofItems.map(
            (proofItem) => proofItem.recipientShareOpeningRandomness,
        ),
        carryWitnessesByItem: proofItems.map(
            (proofItem) => proofItem.carryWitnesses,
        ),
    };
};

const restrictedCompactSameSecretBridgeProofFixture =
    (): RestrictedCompactSameSecretBridgeProofFixture => {
        const publicMatrixSeedHash = repeatedProtocolHash('8');
        const targetRnsPrimes = acceptedBgvSetupQSharePrimes.slice(
            0,
            targetRnsLimbCount,
        );
        const secretCoefficients = Array.from(
            { length: restrictedProofRingDegree },
            (_unusedCoefficient, coefficientIndex) => {
                if (coefficientIndex % 3 === 0) {
                    return -1;
                }
                return coefficientIndex % 3 === 1 ? 0 : 1;
            },
        );
        const negativeIndicatorCoefficients = secretCoefficients.map(
            (coefficient) => (coefficient < 0 ? 1 : 0),
        );
        const openingRandomnessByLimb = targetRnsPrimes.map(
            (_targetRnsPrime, targetRnsLimbIndex) =>
                restrictedProofTernaryRandomness(67 + targetRnsLimbIndex),
        );
        const targetConstantComputations = targetRnsPrimes.map(
            (targetRnsPrime, targetRnsLimbIndex) => {
                const messageCoefficients = secretCoefficients.map(
                    (coefficient, coefficientIndex) =>
                        coefficient +
                        negativeIndicatorCoefficients[coefficientIndex] *
                            targetRnsPrime,
                );

                return computeCompactVssCommitmentFromOpening({
                    commitmentRole: 'coefficient',
                    commitmentContext: {
                        objectType: 'CompactSameSecretBridgeMeasurementContext',
                        objectVersion: 1,
                        targetRnsLimbIndex,
                    },
                    publicMatrixSeedHash,
                    rnsLimbIndex: targetRnsLimbIndex,
                    rnsPrime: targetRnsPrime,
                    ringDegree: restrictedProofRingDegree,
                    messageCoefficients,
                    messageCoefficientBound: targetRnsPrime,
                    randomnessByColumn:
                        openingRandomnessByLimb[targetRnsLimbIndex],
                });
            },
        );
        const sameSecretStatementRoot = repeatedProtocolHash('d');
        const sameSecretProofRoot = repeatedProtocolHash('e');
        const sameSecretProofFamilyBindingRoot = repeatedProtocolHash('f');
        const targetBasisHash = canonicalTargetBasisHash;
        const targetConstantCoefficientCommitmentRoots = targetRnsPrimes.map(
            (rnsPrime, rnsLimbIndex) => {
                const targetConstantComputation =
                    targetConstantComputations[rnsLimbIndex];
                if (targetConstantComputation === undefined) {
                    throw new Error(
                        'restricted compact same-secret bridge fixture is missing a target commitment.',
                    );
                }

                return {
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex: 0 as const,
                    coefficientCommitmentRoot:
                        targetConstantComputation.commitmentRoot,
                };
            },
        );
        const targetConstantCoefficientCommitments = targetRnsPrimes.map(
            (rnsPrime, rnsLimbIndex) => {
                const targetConstantComputation =
                    targetConstantComputations[rnsLimbIndex];
                if (targetConstantComputation === undefined) {
                    throw new Error(
                        'restricted compact same-secret bridge fixture is missing a target commitment.',
                    );
                }

                return {
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex: 0 as const,
                    commitment: targetConstantComputation.commitment,
                };
            },
        );
        const compactSameSecretBridgeStatementRoot = deriveProtocolHash(
            'SetupProofRecordBindingHash',
            {
                objectType: 'CompactVssSameSecretBridgeStatement',
                objectVersion: 1,
                setupProfileId: 'CollectiveBgvSetup-v1',
                compactCommitmentProfileId: compactVssCommitmentProfileId,
                setupProofProfileId: 'SealedLattice-SetupProof-v1',
                proofFamily: 'same-secret-linkage-anchor',
                ceremonyId: 'compact-same-secret-bridge-proof-measurement',
                manifestHash: repeatedProtocolHash('1'),
                rosterHash: repeatedProtocolHash('2'),
                setupProfileHash: repeatedProtocolHash('3'),
                qShareHash: repeatedProtocolHash('4'),
                carryAwareVssShareRelationProfileHash:
                    repeatedProtocolHash('5'),
                commitmentProfileHash: repeatedProtocolHash('6'),
                setupEpoch: 'setup-epoch-1',
                targetBasisHash,
                publicMatrixSeedHash,
                ringDegree: restrictedProofRingDegree,
                trusteeIdentity: 'trustee-0',
                trusteeRosterPosition: 0,
                sameSecretStatementRoot,
                sameSecretProofRoot,
                trusteeSecretCommitmentRoot: repeatedProtocolHash('7'),
                sameSecretProofFamilyBindingRoot,
                dataBasisRelation:
                    'vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs',
                integerSupport: compactVssSameSecretBridgeIntegerSupport,
                signedRepresentativeConvention:
                    compactVssSameSecretBridgeSignedRepresentativeConvention,
                compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
                targetBasisLimbOrder:
                    compactVssSameSecretBridgeTargetBasisLimbOrder,
                targetConstantCoefficientCommitmentRoots,
                targetConstantCoefficientCommitments,
                relation: compactVssSameSecretBridgeRelation,
            },
        );

        return {
            context: {
                ceremonyId: 'compact-same-secret-bridge-proof-measurement',
                manifestHash: repeatedProtocolHash('1'),
                rosterHash: repeatedProtocolHash('2'),
                trusteeIdentity: 'trustee-0',
                trusteeRosterPosition: 0,
                setupEpoch: 'setup-epoch-1',
                compactSameSecretBridgeStatementRoot,
                sameSecretStatementRoot,
                sameSecretProofRoot,
                sameSecretProofFamilyBindingRoot,
            },
            compactSameSecretBridge: {
                compactSameSecretBridgeStatementRoot,
                sameSecretStatementRoot,
                sameSecretProofRoot,
                sameSecretProofFamilyBindingRoot,
                publicMatrixSeedHash,
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
                targetBasisHash,
                targetRnsPrimes,
                targetConstantCommitmentRoots:
                    targetConstantCoefficientCommitmentRoots.map(
                        (commitmentRoot) =>
                            commitmentRoot.coefficientCommitmentRoot,
                    ),
                targetConstantCommitments: targetConstantComputations.map(
                    (computation) => computation.commitment,
                ),
            },
            secretCoefficients,
            negativeIndicatorCoefficients,
            openingRandomnessByLimb,
        };
    };

const measureSyncOperation = <Result>(
    operation: () => Result,
): MeasuredOperation<Result> => {
    const cold = timed(operation);
    const warmMeasurements: number[] = [];
    let lastResult = cold.result;
    for (let runIndex = 0; runIndex < warmRunCount; runIndex += 1) {
        const warm = timed(operation);
        warmMeasurements.push(warm.milliseconds);
        lastResult = warm.result;
    }

    return {
        samples: {
            coldMilliseconds: cold.milliseconds,
            warmMedianMilliseconds: median(warmMeasurements),
            warmSamplesMilliseconds: warmMeasurements,
        },
        lastResult,
    };
};

const compactCommitmentBodyMetadata = (
    commitment: CompactVssCommitmentValue,
): CompactVssCommitmentBodyMetadata => ({
    commitmentRole: commitment.commitmentRole,
    commitmentContextHash: commitment.commitmentContextHash,
    publicMatrixSeedHash: commitment.publicMatrixSeedHash,
    rnsLimbIndex: commitment.rnsLimbIndex,
    rnsPrime: commitment.rnsPrime,
    ringDegree: commitment.ringDegree,
});

const measureTypeScriptPath = (
    opening: CompactVssCommitmentOpeningInput,
): TypeScriptPathMeasurement => {
    const generation = measureSyncOperation(() =>
        computeCompactVssCommitmentFromOpening(opening),
    );
    const metadata = compactCommitmentBodyMetadata(
        generation.lastResult.commitment,
    );
    const bodyEncoding = measureSyncOperation(() =>
        encodeCompactVssCommitmentBody(generation.lastResult.commitment),
    );
    const bodyDecoding = measureSyncOperation(() =>
        decodeCompactVssCommitmentBody({
            metadata,
            commitmentBodyBytes: bodyEncoding.lastResult,
        }),
    );
    const verification = measureSyncOperation(() =>
        verifyCompactVssCommitmentOpening({
            opening,
            expectedCommitmentRoot: generation.lastResult.commitmentRoot,
        }),
    );

    return { generation, bodyEncoding, bodyDecoding, verification };
};

const measureWasmPath = (
    kernel: TranscriptCoreKernel,
    opening: BgvCompactVssCommitmentOpeningInput,
    metadata: BgvCompactVssCommitmentBodyMetadata,
): WasmPathMeasurement => {
    const generation = measureSyncOperation(() =>
        kernel.computeCompactVssCommitmentFromOpening(opening),
    );
    const bodyEncoding = measureSyncOperation(() =>
        kernel.encodeCompactVssCommitmentBody({
            commitment: generation.lastResult.commitment,
        }),
    );
    const bodyDecoding = measureSyncOperation(() =>
        kernel.decodeCompactVssCommitmentBody({
            metadata,
            commitmentBodyBytes: bodyEncoding.lastResult.commitmentBodyBytes,
        }),
    );
    const verification = measureSyncOperation(() =>
        kernel.verifyCompactVssCommitmentOpening({
            opening,
            expectedCommitmentRoot: generation.lastResult.commitmentRoot,
        }),
    );

    return { generation, bodyEncoding, bodyDecoding, verification };
};

const restrictedShareLinkageProofItems = (
    fixture: RestrictedCompactShareLinkageProofFixture,
): readonly RestrictedShareLinkageProofItem[] => [
    fixture.compactVssShareLinkage,
    ...(fixture.compactVssShareLinkage.additionalLinkageItems ?? []),
];

const compactShareLinkageCommitmentSetsFromRestrictedProofFixtures = (
    fixtures: readonly RestrictedCompactShareLinkageProofFixture[],
    targetRnsLimbCountForStatement: number,
): {
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
} => {
    const participantCount = fixtures.length;
    const firstFixture = fixtures[0];
    if (firstFixture === undefined) {
        throw new Error(
            'compact share-linkage public commitment set measurement requires at least one source fixture.',
        );
    }
    const coefficientSourceRecords = fixtures.map((fixture, sourceIndex) => {
        if (
            fixture.compactVssShareLinkage.sourceTrusteeRosterPosition !==
            sourceIndex
        ) {
            throw new Error(
                'compact share-linkage public commitment source fixtures must be ordered by source roster position.',
            );
        }

        return compactShareLinkageSourceCoefficientRecordFromProofItems({
            sourceTrusteeIdentity:
                fixture.compactVssShareLinkage.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition: sourceIndex,
            publicMatrixSeedHash:
                fixture.compactVssShareLinkage.publicMatrixSeedHash,
            targetRnsLimbCountForStatement,
            proofItems: restrictedShareLinkageProofItems(fixture),
        });
    });
    const recipientShareSourceRecords = fixtures.map((fixture, sourceIndex) =>
        compactShareLinkageSourceRecipientShareRecordFromProofItems({
            sourceTrusteeIdentity:
                fixture.compactVssShareLinkage.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition: sourceIndex,
            participantCount,
            targetRnsLimbCountForStatement,
            proofItems: restrictedShareLinkageProofItems(fixture),
        }),
    );
    const coefficientSetWithoutRoot = {
        objectType: 'CompactVssCoefficientCommitmentSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        publicMatrixSeedHash:
            firstFixture.compactVssShareLinkage.publicMatrixSeedHash,
        participantCount,
        rnsLimbCount: targetRnsLimbCountForStatement,
        thresholdDegree: restrictedProofCoefficientCount,
        ringDegree: restrictedProofRingDegree,
        sourceTrusteeRecords: coefficientSourceRecords,
    } as const;
    const recipientSetWithoutRoot = {
        objectType: 'CompactVssRecipientShareCommitmentSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        publicMatrixSeedHash:
            firstFixture.compactVssShareLinkage.publicMatrixSeedHash,
        participantCount,
        rnsLimbCount: targetRnsLimbCountForStatement,
        ringDegree: restrictedProofRingDegree,
        sourceTrusteeRecords: recipientShareSourceRecords,
    } as const;

    return {
        coefficientCommitmentSet: {
            ...coefficientSetWithoutRoot,
            coefficientCommitmentRoot: deriveProtocolHash(
                'VssCoefficientCommitmentRoot',
                coefficientSetWithoutRoot,
            ),
        },
        recipientShareCommitmentSet: {
            ...recipientSetWithoutRoot,
            recipientShareCommitmentRoot: deriveProtocolHash(
                'ThresholdShareCommitmentRoot',
                recipientSetWithoutRoot,
            ),
        },
    };
};

const compactShareLinkageStatementFromRestrictedProofFixtures = (
    fixtures: readonly RestrictedCompactShareLinkageProofFixture[],
): CompactVssShareLinkageStatement => {
    if (fixtures.length === 0) {
        throw new Error(
            'compact share-linkage proof material measurement requires at least one source fixture.',
        );
    }
    const participantCount = fixtures.length;
    const firstFixture = fixtures[0];
    if (firstFixture === undefined) {
        throw new Error(
            'compact share-linkage proof material measurement fixture is missing.',
        );
    }
    const targetRnsLimbCountForStatement = firstFixture.fullSourceBatch
        ? targetRnsLimbCount
        : Math.max(
              ...restrictedShareLinkageProofItems(firstFixture).map(
                  (proofItem) => proofItem.sourceRnsLimbIndex,
              ),
          ) + 1;
    const { coefficientCommitmentSet, recipientShareCommitmentSet } =
        compactShareLinkageCommitmentSetsFromRestrictedProofFixtures(
            fixtures,
            targetRnsLimbCountForStatement,
        );
    const aggregateThresholdCommitmentRoot = deriveProtocolHash(
        'SetupProofRecordBindingHash',
        {
            fixture: 'compact-vss-proof-measurement',
            rootKind: 'aggregateThresholdCommitmentRoot',
            participantCount,
            targetRnsLimbCount: targetRnsLimbCountForStatement,
        },
    );
    const sourceStatementRecords = fixtures.map((fixture, sourceIndex) => {
        if (
            fixture.context.trusteeRosterPosition !== sourceIndex ||
            fixture.compactVssShareLinkage.sourceTrusteeRosterPosition !==
                sourceIndex
        ) {
            throw new Error(
                'compact share-linkage proof material fixtures must be ordered by source trustee roster position.',
            );
        }
        const proofItems = restrictedShareLinkageProofItems(fixture);
        const coefficientSourceRecord =
            coefficientCommitmentSet.sourceTrusteeRecords[sourceIndex];
        const recipientSourceRecord =
            recipientShareCommitmentSet.sourceTrusteeRecords[sourceIndex];
        if (
            coefficientSourceRecord === undefined ||
            recipientSourceRecord === undefined
        ) {
            throw new Error(
                'compact share-linkage public commitment set is missing a source record.',
            );
        }
        const proofItemsByCoverage = new Map(
            proofItems.map((proofItem) => [
                `${String(proofItem.recipientRosterPosition)}:${String(proofItem.sourceRnsLimbIndex)}`,
                proofItem,
            ]),
        );
        const proofItemsBySourceLimb = new Map(
            proofItems.map((proofItem) => [
                proofItem.sourceRnsLimbIndex,
                proofItem,
            ]),
        );
        const coefficientOpeningRoots = Array.from(
            { length: targetRnsLimbCountForStatement },
            (_unusedLimb, sourceRnsLimbIndex) => {
                const proofItem =
                    proofItemsBySourceLimb.get(sourceRnsLimbIndex);
                if (proofItem === undefined) {
                    throw new Error(
                        'compact share-linkage source proof material is missing a target-limb coefficient opening root batch.',
                    );
                }

                return [...proofItem.coefficientOpeningRoots];
            },
        ).flat();
        const recipientShareOpeningRoots = Array.from(
            { length: participantCount },
            (_unusedRecipient, recipientRosterPosition) =>
                Array.from(
                    { length: targetRnsLimbCountForStatement },
                    (_unusedLimb, sourceRnsLimbIndex) => {
                        const proofItem = proofItemsByCoverage.get(
                            `${String(recipientRosterPosition)}:${String(sourceRnsLimbIndex)}`,
                        );
                        if (proofItem === undefined) {
                            throw new Error(
                                'compact share-linkage source proof material is missing a recipient target-limb opening root.',
                            );
                        }

                        return proofItem.recipientShareOpeningRoot;
                    },
                ),
        ).flat();
        const sourceStatementWithoutRoot = {
            objectType: 'CompactVssShareLinkageSourceStatement',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            profileId: compactVssCommitmentProfileId,
            ceremonyId: fixture.context.ceremonyId,
            manifestHash: fixture.context.manifestHash,
            rosterHash: fixture.context.rosterHash,
            setupProfileHash: repeatedProtocolHash('3'),
            qShareHash: repeatedProtocolHash('4'),
            carryAwareVssShareRelationProfileHash: repeatedProtocolHash('5'),
            commitmentProfileHash: repeatedProtocolHash('6'),
            setupEpoch: fixture.context.setupEpoch,
            publicMatrixSeedHash:
                fixture.compactVssShareLinkage.publicMatrixSeedHash,
            targetBasisHash: canonicalTargetBasisHash,
            sourceTrusteeIdentity:
                fixture.compactVssShareLinkage.sourceTrusteeIdentity,
            sourceTrusteeRosterPosition:
                fixture.compactVssShareLinkage.sourceTrusteeRosterPosition,
            participantCount,
            targetRnsLimbCount: targetRnsLimbCountForStatement,
            thresholdDegree: restrictedProofCoefficientCount,
            coefficientCommitmentRoot:
                coefficientCommitmentSet.coefficientCommitmentRoot,
            sourceCoefficientCommitmentRoot:
                coefficientSourceRecord.sourceCoefficientCommitmentRoot,
            sourceRecipientShareCommitmentRoot:
                recipientSourceRecord.sourceRecipientShareCommitmentRoot,
            coefficientOpeningRoots,
            recipientShareOpeningRoots,
            aggregateThresholdCommitmentRoot,
            relation: compactVssShareLinkageStatementRelation,
            proofBatchingRule: compactVssShareLinkageProofBatchingRule,
            shamirEvaluationRule: compactVssShareLinkageShamirEvaluationRule,
            aggregateThresholdRule:
                compactVssShareLinkageAggregateThresholdRule,
            commonKeyRule: compactVssShareLinkageCommonKeyRule,
        } as const;

        return {
            ...sourceStatementWithoutRoot,
            sourceStatementRoot: deriveProtocolHash(
                'SetupProofRecordBindingHash',
                sourceStatementWithoutRoot,
            ),
        };
    });
    const statementWithoutRoot = {
        objectType: 'CompactVssShareLinkageStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: compactVssCommitmentProfileId,
        ceremonyId: firstFixture.context.ceremonyId,
        manifestHash: firstFixture.context.manifestHash,
        rosterHash: firstFixture.context.rosterHash,
        setupProfileHash: repeatedProtocolHash('3'),
        qShareHash: repeatedProtocolHash('4'),
        carryAwareVssShareRelationProfileHash: repeatedProtocolHash('5'),
        commitmentProfileHash: repeatedProtocolHash('6'),
        setupEpoch: firstFixture.context.setupEpoch,
        publicMatrixSeedHash:
            firstFixture.compactVssShareLinkage.publicMatrixSeedHash,
        targetBasisHash: canonicalTargetBasisHash,
        participantCount,
        targetRnsLimbCount: targetRnsLimbCountForStatement,
        thresholdDegree: restrictedProofCoefficientCount,
        coefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        recipientShareCommitmentRoot:
            recipientShareCommitmentSet.recipientShareCommitmentRoot,
        aggregateThresholdCommitmentRoot,
        relation: compactVssShareLinkageStatementRelation,
        proofBatchingRule: compactVssShareLinkageProofBatchingRule,
        shamirEvaluationRule: compactVssShareLinkageShamirEvaluationRule,
        aggregateThresholdRule: compactVssShareLinkageAggregateThresholdRule,
        commonKeyRule: compactVssShareLinkageCommonKeyRule,
        sourceStatementRecords,
    } as const;

    return {
        ...statementWithoutRoot,
        statementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementWithoutRoot,
        ),
    };
};

const compactShareLinkageProofMaterialInputs = (
    statement: CompactVssShareLinkageStatement,
    fixtures: readonly RestrictedCompactShareLinkageProofFixture[],
    proofGenerations: readonly ReturnType<
        TranscriptCoreKernel['generateCompactVssShareLinkageProof']
    >[],
): readonly CompactVssShareLinkageProofMaterialInput[] =>
    statement.sourceStatementRecords.map((sourceStatement, sourceIndex) => {
        const fixture = fixtures[sourceIndex];
        const generation = proofGenerations[sourceIndex];
        if (fixture === undefined || generation === undefined) {
            throw new Error(
                'compact share-linkage proof material inputs are missing a source proof generation.',
            );
        }
        const proofStatement = {
            proofStatementHash: generation.statementHash,
            context: fixture.context,
            ringDegree: restrictedProofRingDegree,
            compactVssShareLinkage: fixture.compactVssShareLinkage,
        } as const;

        return {
            sourceStatementRoot: sourceStatement.sourceStatementRoot,
            proofRecords: [
                {
                    proofStatementHash: generation.statementHash,
                    proofStatement,
                    proofBytesHex: generation.proofBytesHex,
                },
            ],
        };
    });

const measureRestrictedCompactShareLinkageProofMaterialSet = (
    kernel: TranscriptCoreKernel,
    sourceZeroFixture: RestrictedCompactShareLinkageProofFixture,
    sourceZeroGeneration: RestrictedCompactShareLinkageProofMeasurement['generation'],
): RestrictedCompactShareLinkageProofMaterialMeasurement => {
    if (!sourceZeroFixture.fullSourceBatch) {
        return {
            measurementMode: 'not-measured',
            reason: 'Full source-batch material assembly is measured only when SEALED_LATTICE_MEASURE_FULL_SHARE_LINKAGE_BATCH=1 selects the complete recipient and target-limb source batch.',
        };
    }
    const additionalSourceFixtures = Array.from(
        { length: firstProfileParticipantCount - 1 },
        (_unused, sourceOffset) =>
            restrictedCompactShareLinkageProofFixture({
                fullSourceBatch: true,
                sourceTrusteeRosterPosition: sourceOffset + 1,
            }),
    );
    const additionalProofGeneration = timed(() =>
        additionalSourceFixtures.map((fixture, sourceOffset) =>
            kernel.generateCompactVssShareLinkageProof({
                ...fixture,
                ringDegree: restrictedProofRingDegree,
                proofRandomnessSeedHex: 'ab'.repeat(64),
                proofRandomnessNonceHex: (sourceOffset + 1)
                    .toString(16)
                    .padStart(2, '0')
                    .repeat(64),
            }),
        ),
    );
    const fixtures = [sourceZeroFixture, ...additionalSourceFixtures];
    const proofGenerations = [
        sourceZeroGeneration.lastResult,
        ...additionalProofGeneration.result,
    ];
    const statement =
        compactShareLinkageStatementFromRestrictedProofFixtures(fixtures);
    const { coefficientCommitmentSet, recipientShareCommitmentSet } =
        compactShareLinkageCommitmentSetsFromRestrictedProofFixtures(
            fixtures,
            statement.targetRnsLimbCount,
        );
    const proofMaterialSet = createCompactVssShareLinkageProofMaterialSet({
        statement,
        proofMaterialInputs: compactShareLinkageProofMaterialInputs(
            statement,
            fixtures,
            proofGenerations,
        ),
    });
    const proofMaterialSetJsonBytes = Buffer.byteLength(
        JSON.stringify(proofMaterialSet),
        'utf8',
    );
    const binaryProofMaterialTransport =
        encodeCompactVssShareLinkageProofMaterialSetBinary(proofMaterialSet);
    const verification = timed(() =>
        kernel.verifyCompactVssShareLinkageProofMaterialSet({
            statement,
            proofMaterialSet,
            coefficientCommitmentSet,
            recipientShareCommitmentSet,
        }),
    );

    if (
        verification.result.proofRecordCount !== firstProfileParticipantCount ||
        verification.result.proofMaterialCount !== firstProfileParticipantCount
    ) {
        throw new Error(
            'compact share-linkage proof material set did not verify one proof per source trustee.',
        );
    }
    const expectedProofByteLength = proofGenerations.reduce(
        (totalBytes, generation) => totalBytes + generation.proofByteLength,
        0,
    );
    if (verification.result.totalProofByteLength !== expectedProofByteLength) {
        throw new Error(
            'compact share-linkage proof material set proof-byte accounting differs from generated proofs.',
        );
    }

    return {
        measurementMode: 'full-source-material-set',
        proofMaterialSetJsonBytes,
        binaryProofMaterialTransportBytes:
            binaryProofMaterialTransport.totalByteLength,
        binaryProofMaterialTransportChunkCount:
            binaryProofMaterialTransport.chunkCount,
        binaryProofMaterialTransportChunkRoot:
            binaryProofMaterialTransport.chunkRoot,
        binaryProofMaterialTransportFullObjectHash:
            binaryProofMaterialTransport.fullObjectHash,
        binaryProofMaterialTransportSavingsBytes:
            proofMaterialSetJsonBytes -
            binaryProofMaterialTransport.totalByteLength,
        binaryProofMaterialTransportPublicSetupDownloadHeadroomBytes:
            publicSetupDownloadBudgetBytes -
            binaryProofMaterialTransport.totalByteLength,
        generatedSourceProofCount: proofGenerations.length,
        additionalGeneratedSourceProofCount:
            additionalProofGeneration.result.length,
        sourceZeroWarmGenerationMilliseconds:
            sourceZeroGeneration.samples.warmMedianMilliseconds,
        additionalProofGenerationMilliseconds:
            additionalProofGeneration.milliseconds,
        estimatedAllSourceProofGenerationMilliseconds:
            sourceZeroGeneration.samples.warmMedianMilliseconds +
            additionalProofGeneration.milliseconds,
        verificationMilliseconds: verification.milliseconds,
        verification: verification.result,
    };
};

const measureRestrictedCompactSameSecretBridgeProof = (
    kernel: TranscriptCoreKernel,
    fixture: RestrictedCompactSameSecretBridgeProofFixture,
): RestrictedCompactSameSecretBridgeProofMeasurement => {
    const generation = measureSyncOperation(() =>
        kernel.generateCompactSameSecretBridgeProof({
            ...fixture,
            ringDegree: restrictedProofRingDegree,
            proofRandomnessSeedHex: '12'.repeat(64),
            proofRandomnessNonceHex: '34'.repeat(64),
        }),
    );
    const verification = measureSyncOperation(() =>
        kernel.verifyCompactSameSecretBridgeProof({
            context: fixture.context,
            ringDegree: restrictedProofRingDegree,
            compactSameSecretBridge: fixture.compactSameSecretBridge,
            proofBytesHex: generation.lastResult.proofBytesHex,
        }),
    );

    if (
        generation.lastResult.statementHash !==
        verification.lastResult.statementHash
    ) {
        throw new Error(
            'restricted compact same-secret bridge proof statement hashes differ.',
        );
    }
    if (
        generation.lastResult.proofByteLength !==
        verification.lastResult.proofByteLength
    ) {
        throw new Error(
            'restricted compact same-secret bridge proof byte lengths differ.',
        );
    }
    if (verification.lastResult.targetRnsLimbCount !== targetRnsLimbCount) {
        throw new Error(
            'restricted compact same-secret bridge proof target limb count differs.',
        );
    }

    return { generation, verification };
};

const restrictedCompactSameSecretBridgeStatementSet = (
    fixture: RestrictedCompactSameSecretBridgeProofFixture,
): CompactVssSameSecretBridgeStatementSet => {
    const targetConstantCoefficientCommitmentRoots =
        fixture.compactSameSecretBridge.targetRnsPrimes.map(
            (rnsPrime, rnsLimbIndex) => {
                const coefficientCommitmentRoot =
                    fixture.compactSameSecretBridge
                        .targetConstantCommitmentRoots[rnsLimbIndex];
                if (coefficientCommitmentRoot === undefined) {
                    throw new Error(
                        'restricted compact same-secret bridge fixture is missing a target commitment root.',
                    );
                }

                return {
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex: 0 as const,
                    coefficientCommitmentRoot,
                };
            },
        );
    const targetConstantCoefficientCommitments =
        fixture.compactSameSecretBridge.targetRnsPrimes.map(
            (rnsPrime, rnsLimbIndex) => {
                const commitment =
                    fixture.compactSameSecretBridge.targetConstantCommitments[
                        rnsLimbIndex
                    ];
                if (commitment === undefined) {
                    throw new Error(
                        'restricted compact same-secret bridge fixture is missing a target commitment.',
                    );
                }

                return {
                    rnsLimbIndex,
                    rnsPrime,
                    shamirCoefficientIndex: 0 as const,
                    commitment: commitment as CompactVssCommitmentValue,
                };
            },
        );
    const setupProfileHash = repeatedProtocolHash('3');
    const qShareHash = repeatedProtocolHash('4');
    const carryAwareVssShareRelationProfileHash = repeatedProtocolHash('5');
    const commitmentProfileHash = repeatedProtocolHash('6');
    const trusteeSecretCommitmentRoot = repeatedProtocolHash('7');
    const compactCoefficientCommitmentRoot = repeatedProtocolHash('9');
    const sameSecretConsistencyRoot = repeatedProtocolHash('a');
    const sameSecretProofSetRoot = repeatedProtocolHash('b');
    const statementRecordWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        compactCommitmentProfileId: compactVssCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        ceremonyId: fixture.context.ceremonyId,
        manifestHash: fixture.context.manifestHash,
        rosterHash: fixture.context.rosterHash,
        setupProfileHash,
        qShareHash,
        carryAwareVssShareRelationProfileHash,
        commitmentProfileHash,
        setupEpoch: fixture.context.setupEpoch,
        targetBasisHash: fixture.compactSameSecretBridge.targetBasisHash,
        publicMatrixSeedHash:
            fixture.compactSameSecretBridge.publicMatrixSeedHash,
        ringDegree: restrictedProofRingDegree,
        trusteeIdentity: fixture.context.trusteeIdentity,
        trusteeRosterPosition: fixture.context.trusteeRosterPosition,
        sameSecretStatementRoot:
            fixture.compactSameSecretBridge.sameSecretStatementRoot,
        sameSecretProofRoot:
            fixture.compactSameSecretBridge.sameSecretProofRoot,
        trusteeSecretCommitmentRoot,
        sameSecretProofFamilyBindingRoot:
            fixture.compactSameSecretBridge.sameSecretProofFamilyBindingRoot,
        dataBasisRelation: sameSecretRelation,
        integerSupport: compactVssSameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            compactVssSameSecretBridgeSignedRepresentativeConvention,
        compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
        targetBasisLimbOrder: compactVssSameSecretBridgeTargetBasisLimbOrder,
        targetConstantCoefficientCommitmentRoots,
        targetConstantCoefficientCommitments,
        relation: compactVssSameSecretBridgeRelation,
    } as const;
    const statementRecord = {
        ...statementRecordWithoutRoot,
        compactSameSecretBridgeStatementRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementRecordWithoutRoot,
        ),
    };
    const statementSetWithoutRoot = {
        objectType: 'CompactVssSameSecretBridgeStatementSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        compactCommitmentProfileId: compactVssCommitmentProfileId,
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        ceremonyId: fixture.context.ceremonyId,
        manifestHash: fixture.context.manifestHash,
        rosterHash: fixture.context.rosterHash,
        setupProfileHash,
        qShareHash,
        carryAwareVssShareRelationProfileHash,
        commitmentProfileHash,
        setupEpoch: fixture.context.setupEpoch,
        targetBasisHash: fixture.compactSameSecretBridge.targetBasisHash,
        publicMatrixSeedHash:
            fixture.compactSameSecretBridge.publicMatrixSeedHash,
        ringDegree: restrictedProofRingDegree,
        participantCount: 1,
        targetRnsLimbCount:
            fixture.compactSameSecretBridge.targetRnsPrimes.length,
        thresholdDegree: 1,
        compactCoefficientCommitmentRoot,
        sameSecretConsistencyRoot,
        sameSecretProofSetRoot,
        sameSecretProofFamilyBindingRoot:
            fixture.compactSameSecretBridge.sameSecretProofFamilyBindingRoot,
        integerSupport: compactVssSameSecretBridgeIntegerSupport,
        signedRepresentativeConvention:
            compactVssSameSecretBridgeSignedRepresentativeConvention,
        compactCommitmentEncoding: compactVssCommitmentBinaryFormat,
        targetBasisLimbOrder: compactVssSameSecretBridgeTargetBasisLimbOrder,
        statementRecords: [statementRecord],
    } as const;

    return {
        ...statementSetWithoutRoot,
        compactSameSecretBridgeStatementSetRoot: deriveProtocolHash(
            'SetupProofRecordBindingHash',
            statementSetWithoutRoot,
        ),
    };
};

const measureRestrictedCompactSameSecretBridgeProofMaterial = (
    kernel: TranscriptCoreKernel,
    fixture: RestrictedCompactSameSecretBridgeProofFixture,
    proofGeneration: RestrictedCompactSameSecretBridgeProofMeasurement['generation'],
): RestrictedCompactSameSecretBridgeProofMaterialMeasurement => {
    const statementSet = restrictedCompactSameSecretBridgeStatementSet(fixture);
    const proofMaterialSet = createCompactVssSameSecretBridgeProofMaterialSet({
        statementSet,
        proofRecordInputs: [
            {
                compactSameSecretBridgeStatementRoot:
                    fixture.compactSameSecretBridge
                        .compactSameSecretBridgeStatementRoot,
                proofBytesHex: proofGeneration.lastResult.proofBytesHex,
            },
        ],
    });
    const proofMaterialSetJsonBytes = Buffer.byteLength(
        JSON.stringify(proofMaterialSet),
        'utf8',
    );
    const verification = measureSyncOperation(() =>
        kernel.verifyCompactVssSameSecretBridgeProofMaterialSet({
            statementSet,
            proofMaterialSet,
        }),
    );

    if (verification.lastResult.proofRecordCount !== 1) {
        throw new Error(
            'restricted compact same-secret bridge proof material record count differs.',
        );
    }
    if (verification.lastResult.proofVerificationCount !== 1) {
        throw new Error(
            'restricted compact same-secret bridge proof material verification count differs.',
        );
    }
    if (
        verification.lastResult.totalProofByteLength !==
        proofGeneration.lastResult.proofByteLength
    ) {
        throw new Error(
            'restricted compact same-secret bridge proof material byte length differs.',
        );
    }

    return { proofMaterialSetJsonBytes, verification };
};

const firstProfileRestrictedProofCoverageEstimate = (
    restrictedProofMeasurement: RestrictedCompactShareLinkageProofMeasurement,
    restrictedBridgeProofMeasurement: RestrictedCompactSameSecretBridgeProofMeasurement,
    restrictedBridgeProofMaterialMeasurement: RestrictedCompactSameSecretBridgeProofMaterialMeasurement,
): FirstProfileRestrictedProofCoverageEstimate => {
    const shareLinkageProofItemsPerSource =
        firstProfileParticipantCount * targetRnsLimbCount;
    const measuredShareLinkageProofItemsPerRecord =
        restrictedProofMeasurement.generation.lastResult
            .coefficientCommitmentCount / restrictedProofCoefficientCount;
    const measuredShareLinkageCoefficientWitnessColumnsPerRecord =
        restrictedProofMeasurement.generation.lastResult
            .coefficientWitnessColumnCount;
    const shareLinkageProofRecordsPerSource = 1;
    const shareLinkageProofRecordCount =
        firstProfileParticipantCount * shareLinkageProofRecordsPerSource;
    const shareLinkageRepeatedProofPayloadBytes =
        shareLinkageProofRecordCount *
        restrictedProofMeasurement.generation.lastResult.proofByteLength;
    const sameSecretBridgeProofRecordCount = firstProfileParticipantCount;
    const sameSecretBridgeRepeatedProofPayloadBytes =
        sameSecretBridgeProofRecordCount *
        restrictedBridgeProofMeasurement.generation.lastResult.proofByteLength;
    const sameSecretBridgeRepeatedProofMaterialJsonBytes =
        sameSecretBridgeProofRecordCount *
        restrictedBridgeProofMaterialMeasurement.proofMaterialSetJsonBytes;
    const sourceBatchMeasurementMode =
        measuredShareLinkageProofItemsPerRecord ===
        shareLinkageProofItemsPerSource
            ? 'Measured one full restricted-ring source batch in this run.'
            : 'Measured a three-item restricted-ring dedupe sample in this run. Set SEALED_LATTICE_MEASURE_FULL_SHARE_LINKAGE_BATCH=1 to run one full source batch.';
    const oneSourceProofPayloadBytes =
        restrictedProofMeasurement.generation.lastResult.proofByteLength +
        restrictedBridgeProofMeasurement.generation.lastResult.proofByteLength;
    const proofPayloadConclusion =
        measuredShareLinkageProofItemsPerRecord ===
        shareLinkageProofItemsPerSource
            ? `This run measured one full source-batch share-linkage proof; the combined one-source share-linkage and bridge proof payload is ${oneSourceProofPayloadBytes} bytes, so it ${oneSourceProofPayloadBytes <= maximumRestrictedProofPayloadBytes ? 'fits' : 'exceeds'} the 8 MiB proof-payload guard.`
            : 'This run measured only a three-item share-linkage proof sample; it must not be used as evidence that first-profile share-linkage proof material fits the 8 MiB proof-payload guard.';
    const setupTransportConclusion =
        measuredShareLinkageProofItemsPerRecord ===
        shareLinkageProofItemsPerSource
            ? 'This source-batch proof measurement still is not the all-source setup-transport measurement; use the full source material-set lane for the 64 MiB setup download budget.'
            : 'This restricted sample is not setup-transport evidence; it does not measure the all-source share-linkage proof-material set against the 64 MiB setup download budget.';

    return {
        participantCount: firstProfileParticipantCount,
        targetRnsLimbCount,
        shareLinkageProofItemsPerSource,
        measuredShareLinkageProofItemsPerRecord,
        measuredShareLinkageCoefficientWitnessColumnsPerRecord,
        sourceBatchMeasurementMode,
        proofPayloadConclusion,
        setupTransportConclusion,
        shareLinkageProofRecordsPerSource,
        shareLinkageProofRecordCount,
        shareLinkageRepeatedProofPayloadBytes,
        sameSecretBridgeProofRecordCount,
        sameSecretBridgeRepeatedProofPayloadBytes,
        sameSecretBridgeRepeatedProofMaterialJsonBytes,
        combinedRepeatedProofPayloadBytes:
            shareLinkageRepeatedProofPayloadBytes +
            sameSecretBridgeRepeatedProofPayloadBytes,
        activationBoundary:
            'Share-linkage target coverage uses one proof record per source, with every recipient and target limb in the source batch. The public commitment-body ratio remains separate from proof payload accounting.',
    };
};

const scaledSeconds = (
    millisecondsPerCommitment: number,
    totalCommitments: number,
): number => (millisecondsPerCommitment * totalCommitments) / 1_000;

const assertAtMost = (
    measuredValue: number,
    maximumValue: number,
    description: string,
): void => {
    if (measuredValue > maximumValue) {
        throw new Error(
            `${description} exceeded: measured ${measuredValue}, budget ${maximumValue}.`,
        );
    }
};

const assertAtLeast = (
    measuredValue: number,
    minimumValue: number,
    description: string,
): void => {
    if (measuredValue < minimumValue) {
        throw new Error(
            `${description} missed: measured ${measuredValue}, required at least ${minimumValue}.`,
        );
    }
};

const equalBytes = (left: Uint8Array, right: Uint8Array): boolean =>
    left.byteLength === right.byteLength &&
    left.every((leftByte, byteIndex) => leftByte === right[byteIndex]);

const jsonByteLength = (value: unknown): number =>
    Buffer.byteLength(JSON.stringify(value), 'utf8');

const objectField = (
    value: unknown,
    fieldName: string,
): Readonly<Record<string, unknown>> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} parent must be an object.`);
    }
    const fieldValue = (value as Record<string, unknown>)[fieldName];
    if (
        typeof fieldValue !== 'object' ||
        fieldValue === null ||
        Array.isArray(fieldValue)
    ) {
        throw new Error(`${fieldName} must be an object.`);
    }

    return fieldValue as Readonly<Record<string, unknown>>;
};

const arrayField = (value: unknown, fieldName: string): readonly unknown[] => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} parent must be an object.`);
    }
    const fieldValue = (value as Record<string, unknown>)[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new Error(`${fieldName} must be an array.`);
    }

    return fieldValue;
};

const numberField = (value: unknown, fieldName: string): number => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} parent must be an object.`);
    }
    const fieldValue = (value as Record<string, unknown>)[fieldName];
    if (typeof fieldValue !== 'number') {
        throw new Error(`${fieldName} must be a number.`);
    }

    return fieldValue;
};

const stringField = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} parent must be an object.`);
    }
    const fieldValue = (value as Record<string, unknown>)[fieldName];
    if (typeof fieldValue !== 'string') {
        throw new Error(`${fieldName} must be a string.`);
    }

    return fieldValue;
};

const base64ByteLength = (base64Value: string, fieldName: string): number => {
    if (base64Value.length % 4 !== 0) {
        throw new Error(
            `${fieldName} must have a base64 length divisible by four.`,
        );
    }
    const paddingLength = base64Value.endsWith('==')
        ? 2
        : base64Value.endsWith('=')
          ? 1
          : 0;

    return (base64Value.length / 4) * 3 - paddingLength;
};

const targetProofRecords = (
    proofMaterial: ReturnType<
        TranscriptCoreKernel['generateBgvTargetDecryptionShareProofMaterialFromLocalWitness']
    >,
): readonly unknown[] => arrayField(proofMaterial, 'proofRecords');

const targetProofByteLength = (
    proofMaterial: ReturnType<
        TranscriptCoreKernel['generateBgvTargetDecryptionShareProofMaterialFromLocalWitness']
    >,
): number =>
    targetProofRecords(proofMaterial).reduce<number>(
        (totalBytes, proofRecord, proofRecordIndex) =>
            totalBytes +
            base64ByteLength(
                stringField(proofRecord, 'proofBytesBase64'),
                `proofRecords.${proofRecordIndex}.proofBytesBase64`,
            ),
        0,
    );

type TargetProofMessageClaimKind = 'aggregateOpening' | 'smudgingOpening';

type TargetProofStatementLayout = Readonly<{
    readonly ringDegree: number;
    readonly proofLimbIndices: readonly number[];
    readonly targetRnsLimbIndexByGlobalMessageIndex: readonly number[];
    readonly messageClaimKindByGlobalMessageIndex: readonly TargetProofMessageClaimKind[];
    readonly aggregateMessageCoefficientBound: number;
    readonly smudgingMessageCoefficientBound: number;
}>;

type TargetProofLimbLayout = Readonly<{
    readonly traceSize: number;
    readonly claimCount: number;
    readonly phaseOnePhysicalColumnCount: number;
}>;

type EncodedSetupProofLimbLayout = TargetProofLimbLayout;

const targetProofByteBreakdownSections = [
    'formatAndLengthPrefixBytes',
    'commitmentRootBytes',
    'maskedConsistencyClaimBytes',
    'deepEvaluationBytes',
    'lowDegreeFoldRootBytes',
    'lowDegreeFinalCoefficientBytes',
    'lowDegreeQuerySiblingBytes',
    'lowDegreeQueryPathBytes',
    'phaseOneRowBytes',
    'phaseOnePathBytes',
    'phaseTwoRowBytes',
    'phaseTwoPathBytes',
    'leafSaltBytes',
] as const;

type TargetProofByteBreakdownSection =
    (typeof targetProofByteBreakdownSections)[number];

type MutableEncodedTargetProofByteBreakdown = {
    -readonly [Field in keyof EncodedTargetProofByteBreakdown]: number;
};

type TargetProofByteParser = {
    readonly proofBytes: Uint8Array;
    readOffset: number;
    readonly breakdown: MutableEncodedTargetProofByteBreakdown;
};

const emptyTargetProofByteBreakdown =
    (): MutableEncodedTargetProofByteBreakdown => ({
        totalBytes: 0,
        formatAndLengthPrefixBytes: 0,
        commitmentRootBytes: 0,
        maskedConsistencyClaimBytes: 0,
        deepEvaluationBytes: 0,
        lowDegreeFoldRootBytes: 0,
        lowDegreeFinalCoefficientBytes: 0,
        lowDegreeQuerySiblingBytes: 0,
        lowDegreeQueryPathBytes: 0,
        phaseOneRowBytes: 0,
        phaseOnePathBytes: 0,
        phaseTwoRowBytes: 0,
        phaseTwoPathBytes: 0,
        leafSaltBytes: 0,
        fieldResidueBytes: 0,
        merkleHashBytes: 0,
    });

const finalizeTargetProofByteBreakdown = (
    breakdown: MutableEncodedTargetProofByteBreakdown,
): EncodedTargetProofByteBreakdown => {
    breakdown.fieldResidueBytes =
        breakdown.maskedConsistencyClaimBytes +
        breakdown.deepEvaluationBytes +
        breakdown.lowDegreeFinalCoefficientBytes +
        breakdown.lowDegreeQuerySiblingBytes +
        breakdown.phaseOneRowBytes +
        breakdown.phaseTwoRowBytes;
    breakdown.merkleHashBytes =
        breakdown.commitmentRootBytes +
        breakdown.lowDegreeFoldRootBytes +
        breakdown.lowDegreeQueryPathBytes +
        breakdown.phaseOnePathBytes +
        breakdown.phaseTwoPathBytes;

    return { ...breakdown };
};

const addTargetProofBreakdownBytes = (
    breakdown: MutableEncodedTargetProofByteBreakdown,
    section: TargetProofByteBreakdownSection,
    byteCount: number,
): void => {
    if (!Number.isSafeInteger(byteCount) || byteCount < 0) {
        throw new Error(
            'target proof byte breakdown received an invalid size.',
        );
    }
    breakdown[section] += byteCount;
    breakdown.totalBytes += byteCount;
};

const consumeTargetProofBytes = (
    parser: TargetProofByteParser,
    byteCount: number,
    section: TargetProofByteBreakdownSection,
    description: string,
): Uint8Array => {
    if (!Number.isSafeInteger(byteCount) || byteCount < 0) {
        throw new Error(`${description} has an invalid byte count.`);
    }
    const nextOffset = parser.readOffset + byteCount;
    if (nextOffset > parser.proofBytes.byteLength) {
        throw new Error(`${description} exceeds the encoded target proof.`);
    }
    const slice = parser.proofBytes.subarray(parser.readOffset, nextOffset);
    parser.readOffset = nextOffset;
    addTargetProofBreakdownBytes(parser.breakdown, section, byteCount);

    return slice;
};

const readTargetProofU64 = (
    parser: TargetProofByteParser,
    description: string,
): number => {
    const bytes = consumeTargetProofBytes(
        parser,
        proofLengthPrefixByteLength,
        'formatAndLengthPrefixBytes',
        description,
    );
    let value = 0n;
    for (const [byteIndex, byte] of bytes.entries()) {
        value += BigInt(byte) << BigInt(8 * byteIndex);
    }
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
        throw new Error(
            `${description} does not fit a safe JavaScript integer.`,
        );
    }

    return Number(value);
};

const packedProofResidueByteCount = (residueCount: number): number => {
    if (!Number.isSafeInteger(residueCount) || residueCount < 0) {
        throw new Error('proof residue count must be a non-negative integer.');
    }

    return Math.ceil((residueCount * proofFieldResidueBitWidth) / 8);
};

const proofExtensionSliceByteCount = (elementCount: number): number =>
    packedProofResidueByteCount(elementCount * proofChallengeExtensionDegree);

const lowDegreeSiblingReferenceBitWidth = (tableCount: number): number =>
    tableCount <= 1 ? 0 : Math.floor(Math.log2(tableCount - 1)) + 1;

const lowDegreeSiblingReferenceByteCount = (tableCount: number): number =>
    Math.ceil(
        (proofLowDegreeQueryCount *
            lowDegreeSiblingReferenceBitWidth(tableCount)) /
            8,
    );

const positiveIntegerField = (value: unknown, fieldName: string): number => {
    const fieldValue = numberField(value, fieldName);
    if (!Number.isSafeInteger(fieldValue) || fieldValue < 0) {
        throw new Error(`${fieldName} must be a non-negative integer.`);
    }

    return fieldValue;
};

const targetProofStatementLayout = (
    proofStatement: ReturnType<
        TranscriptCoreKernel['deriveBgvTargetDecryptionShareProofStatement']
    >,
): TargetProofStatementLayout => {
    const targetCiphertextLevel = positiveIntegerField(
        proofStatement,
        'targetCiphertextLevel',
    );
    const activeTargetRnsLimbCount = targetCiphertextLevel + 1;
    const smudgingCommitmentBinding = objectField(
        proofStatement,
        'smudgingCommitmentBinding',
    );
    const smudgingCommitmentSet = objectField(
        smudgingCommitmentBinding,
        'smudgingCommitmentSet',
    );
    const commitmentSetActiveLimbCount = positiveIntegerField(
        smudgingCommitmentSet,
        'activeRnsLimbCount',
    );
    if (commitmentSetActiveLimbCount !== activeTargetRnsLimbCount) {
        throw new Error(
            'target proof statement and smudging commitment set disagree on active limb count.',
        );
    }
    const participantCount = positiveIntegerField(
        proofStatement,
        'decryptionShareQuorum',
    );
    const aggregateMessageCoefficientBound = Math.max(
        ...acceptedBgvSetupQSharePrimes
            .slice(0, activeTargetRnsLimbCount)
            .map((targetRnsPrime) => targetRnsPrime * participantCount),
    );
    if (!Number.isSafeInteger(aggregateMessageCoefficientBound)) {
        throw new Error(
            'target proof aggregate message bound exceeds safe integer range.',
        );
    }
    const smudgingMessageCoefficientBound = positiveIntegerField(
        smudgingCommitmentSet,
        'messageCoefficientBound',
    );
    const smudgingMessageCountByTargetLimb = Array.from(
        { length: activeTargetRnsLimbCount },
        () => 0,
    );
    for (const [recordIndex, record] of arrayField(
        smudgingCommitmentSet,
        'commitmentRecords',
    ).entries()) {
        const targetRnsLimbIndex = positiveIntegerField(record, 'rnsLimbIndex');
        if (targetRnsLimbIndex >= activeTargetRnsLimbCount) {
            throw new Error(
                `smudging commitment record ${String(recordIndex)} is outside the active target limb set.`,
            );
        }
        positiveIntegerField(record, 'polynomialDegree');
        smudgingMessageCountByTargetLimb[targetRnsLimbIndex] += 1;
    }

    const targetRnsLimbIndexByGlobalMessageIndex: number[] = [];
    const messageClaimKindByGlobalMessageIndex: TargetProofMessageClaimKind[] =
        [];
    for (
        let targetRnsLimbIndex = 0;
        targetRnsLimbIndex < activeTargetRnsLimbCount;
        targetRnsLimbIndex += 1
    ) {
        targetRnsLimbIndexByGlobalMessageIndex.push(targetRnsLimbIndex);
        messageClaimKindByGlobalMessageIndex.push('aggregateOpening');
        const smudgingMessageCount =
            smudgingMessageCountByTargetLimb[targetRnsLimbIndex];
        if (smudgingMessageCount === undefined) {
            throw new Error(
                'target proof limb index is outside the message map.',
            );
        }
        for (
            let localSmudgingMessageIndex = 0;
            localSmudgingMessageIndex < smudgingMessageCount;
            localSmudgingMessageIndex += 1
        ) {
            targetRnsLimbIndexByGlobalMessageIndex.push(targetRnsLimbIndex);
            messageClaimKindByGlobalMessageIndex.push('smudgingOpening');
        }
    }

    const proofLimbIndices = Array.from(
        { length: proofSetupCommitmentLimbCount },
        (_unused, limbIndex) => limbIndex,
    );
    for (
        let targetRnsLimbIndex = 0;
        targetRnsLimbIndex < activeTargetRnsLimbCount;
        targetRnsLimbIndex += 1
    ) {
        if (!proofLimbIndices.includes(targetRnsLimbIndex)) {
            proofLimbIndices.push(targetRnsLimbIndex);
        }
    }

    return {
        ringDegree: acceptedBgvProfileRingDegree,
        proofLimbIndices,
        targetRnsLimbIndexByGlobalMessageIndex,
        messageClaimKindByGlobalMessageIndex,
        aggregateMessageCoefficientBound,
        smudgingMessageCoefficientBound,
    };
};

const targetProofMessageClaimLimbIndices = (
    layout: TargetProofStatementLayout,
    globalMessageIndex: number,
): readonly number[] => {
    const targetRnsLimbIndex =
        layout.targetRnsLimbIndexByGlobalMessageIndex[globalMessageIndex];
    const claimKind =
        layout.messageClaimKindByGlobalMessageIndex[globalMessageIndex];
    if (targetRnsLimbIndex === undefined || claimKind === undefined) {
        throw new Error(
            'target proof message index is outside the statement layout.',
        );
    }
    const fieldCount = claimKind === 'aggregateOpening' ? 5 : 4;
    const selectedLimbIndices = layout.proofLimbIndices.filter(
        (proofLimbIndex) => proofLimbIndex < proofSetupCommitmentLimbCount,
    );
    if (
        !selectedLimbIndices.includes(targetRnsLimbIndex) &&
        layout.proofLimbIndices.includes(targetRnsLimbIndex)
    ) {
        selectedLimbIndices.push(targetRnsLimbIndex);
    }
    for (const candidateLimbIndex of layout.proofLimbIndices) {
        if (selectedLimbIndices.length >= fieldCount) {
            break;
        }
        if (!selectedLimbIndices.includes(candidateLimbIndex)) {
            selectedLimbIndices.push(candidateLimbIndex);
        }
    }

    return selectedLimbIndices;
};

const targetProofMessageGlobalIndicesForLimb = (
    layout: TargetProofStatementLayout,
    proofLimbIndex: number,
): readonly number[] => {
    const globalMessageIndices: number[] = [];
    for (
        let globalMessageIndex = 0;
        globalMessageIndex < layout.messageClaimKindByGlobalMessageIndex.length;
        globalMessageIndex += 1
    ) {
        if (
            targetProofMessageClaimLimbIndices(
                layout,
                globalMessageIndex,
            ).includes(proofLimbIndex)
        ) {
            globalMessageIndices.push(globalMessageIndex);
        }
    }

    return globalMessageIndices;
};

const targetProofRandomnessColumnCountForLimb = (
    layout: TargetProofStatementLayout,
    proofLimbIndex: number,
): number =>
    layout.proofLimbIndices.slice(0, 4).includes(proofLimbIndex)
        ? layout.messageClaimKindByGlobalMessageIndex.length *
          compactVssCommitmentRandomnessColumnCount
        : 0;

const targetProofMaskDigitCountForClaim = (
    layout: TargetProofStatementLayout,
    localMessageGlobalIndices: readonly number[],
    localClaimIndex: number,
): number => {
    const vectorIndex = Math.floor(
        localClaimIndex / proofConsistencyRepetitions,
    );
    if (vectorIndex < localMessageGlobalIndices.length) {
        const globalMessageIndex = localMessageGlobalIndices[vectorIndex];
        if (globalMessageIndex === undefined) {
            throw new Error(
                'target proof local message index is outside the layout.',
            );
        }
        const claimKind =
            layout.messageClaimKindByGlobalMessageIndex[globalMessageIndex];
        if (claimKind === 'aggregateOpening') {
            return targetDecryptionAggregateMessageClaimMaskDigitCount;
        }
        if (claimKind === 'smudgingOpening') {
            return targetDecryptionSmudgingMessageClaimMaskDigitCount;
        }
        throw new Error('target proof message claim kind is unknown.');
    }

    return targetDecryptionRandomnessClaimMaskDigitCount;
};

const targetProofLimbLayout = (
    statementLayout: TargetProofStatementLayout,
    proofLimbIndex: number,
): TargetProofLimbLayout => {
    const localMessageGlobalIndices = targetProofMessageGlobalIndicesForLimb(
        statementLayout,
        proofLimbIndex,
    );
    const randomnessColumnCount = targetProofRandomnessColumnCountForLimb(
        statementLayout,
        proofLimbIndex,
    );
    const messageEncodingColumnCount = localMessageGlobalIndices.reduce(
        (totalColumns, globalMessageIndex) => {
            const claimKind =
                statementLayout.messageClaimKindByGlobalMessageIndex[
                    globalMessageIndex
                ];
            const messageBound =
                claimKind === 'aggregateOpening'
                    ? statementLayout.aggregateMessageCoefficientBound
                    : statementLayout.smudgingMessageCoefficientBound;

            return (
                totalColumns +
                compactVssMessageEncodingLayoutForBound(messageBound)
                    .encodingColumnCount
            );
        },
        0,
    );
    const logicalColumnCount =
        messageEncodingColumnCount + randomnessColumnCount;
    const claimCount = logicalColumnCount * proofConsistencyRepetitions;
    let maskSlotCount = 0;
    for (
        let localClaimIndex = 0;
        localClaimIndex < claimCount;
        localClaimIndex += 1
    ) {
        maskSlotCount += targetProofMaskDigitCountForClaim(
            statementLayout,
            localMessageGlobalIndices,
            localClaimIndex,
        );
    }
    const maskColumnCount = Math.ceil(
        maskSlotCount / statementLayout.ringDegree,
    );
    const traceSize = statementLayout.ringDegree / proofTraceSplit;
    if (!Number.isSafeInteger(traceSize)) {
        throw new Error('target proof trace size must be an integer.');
    }

    return {
        traceSize,
        claimCount,
        phaseOnePhysicalColumnCount:
            proofTraceSplit * (logicalColumnCount + maskColumnCount),
    };
};

const compactShareLinkageProofLimbLayout = (
    fixture: RestrictedCompactShareLinkageProofFixture,
): EncodedSetupProofLimbLayout => {
    const coefficientWitnessColumnCount = fixture.coefficientWitnessColumnCount;
    const itemColumnCount = fixture.proofItemCount;
    const randomnessColumnCount =
        (coefficientWitnessColumnCount + itemColumnCount) *
        compactVssCommitmentRandomnessColumnCount;
    const coefficientSlotMessageBounds: number[] = [];
    const coefficientSlotKeys = new Set<string>();
    for (const item of restrictedShareLinkageProofItems(fixture)) {
        for (
            let shamirCoefficientIndex = 0;
            shamirCoefficientIndex < item.coefficientCommitmentRoots.length;
            shamirCoefficientIndex += 1
        ) {
            const commitmentRoot =
                item.coefficientCommitmentRoots[shamirCoefficientIndex];
            const openingRoot =
                item.coefficientOpeningRoots[shamirCoefficientIndex];
            if (commitmentRoot === undefined || openingRoot === undefined) {
                throw new Error(
                    'compact share-linkage proof item has incomplete coefficient roots.',
                );
            }
            const slotKey = JSON.stringify([
                item.sourceRnsLimbIndex,
                item.sourceMessageModulus,
                shamirCoefficientIndex,
                commitmentRoot,
                openingRoot,
            ]);
            if (!coefficientSlotKeys.has(slotKey)) {
                coefficientSlotKeys.add(slotKey);
                coefficientSlotMessageBounds.push(item.sourceMessageModulus);
            }
        }
    }
    if (coefficientSlotMessageBounds.length !== coefficientWitnessColumnCount) {
        throw new Error(
            'compact share-linkage proof fixture witness count disagrees with deduplicated slots.',
        );
    }
    const coefficientMessageEncodingColumnCount =
        coefficientSlotMessageBounds.reduce(
            (totalColumns, messageBound) =>
                totalColumns +
                compactVssMessageEncodingLayoutForBound(messageBound)
                    .encodingColumnCount,
            0,
        );
    const recipientMessageEncodingColumnCount =
        restrictedShareLinkageProofItems(fixture).reduce(
            (totalColumns, item) =>
                totalColumns +
                compactVssMessageEncodingLayoutForBound(
                    item.sourceMessageModulus,
                ).encodingColumnCount,
            0,
        );
    const messageEncodingColumnCount =
        coefficientMessageEncodingColumnCount +
        recipientMessageEncodingColumnCount;
    const logicalColumnCount =
        messageEncodingColumnCount + itemColumnCount + randomnessColumnCount;
    const consistencyVectorCount = itemColumnCount;
    const claimCount =
        consistencyVectorCount * compactShareLinkageConsistencyRepetitions;
    const maskSlotCount =
        claimCount * compactShareLinkageCarryClaimMaskDigitCount;
    const maskColumnCount = Math.ceil(
        maskSlotCount / restrictedProofRingDegree,
    );
    const traceSize = restrictedProofRingDegree / proofTraceSplit;
    if (!Number.isSafeInteger(traceSize)) {
        throw new Error('compact share-linkage trace size must be an integer.');
    }

    return {
        traceSize,
        claimCount,
        phaseOnePhysicalColumnCount:
            proofTraceSplit * (logicalColumnCount + maskColumnCount),
    };
};

const lowDegreeFinalCoefficientCount = (initialDegreeBound: number): number => {
    if (
        !Number.isSafeInteger(initialDegreeBound) ||
        initialDegreeBound <= 0 ||
        !isPowerOfTwo(initialDegreeBound)
    ) {
        throw new Error('low-degree statement bound is not canonical.');
    }
    const largestStrictlySmallerBound = initialDegreeBound / 2;
    if (
        largestStrictlySmallerBound < proofLowDegreeMinimumFinalCoefficientCount
    ) {
        throw new Error(
            'low-degree statement bound does not reach the final coefficient layer.',
        );
    }

    return Math.min(
        proofLowDegreeMaximumFinalCoefficientCount,
        largestStrictlySmallerBound,
    );
};

const committedLowDegreeFoldCount = (initialDegreeBound: number): number => {
    const finalCoefficientCount =
        lowDegreeFinalCoefficientCount(initialDegreeBound);
    if (
        !Number.isSafeInteger(initialDegreeBound) ||
        initialDegreeBound % finalCoefficientCount !== 0
    ) {
        throw new Error('low-degree statement bound is not canonical.');
    }
    const foldRatio = initialDegreeBound / finalCoefficientCount;
    const committedFoldCount = Math.log2(foldRatio) - 1;
    if (!Number.isSafeInteger(committedFoldCount) || committedFoldCount < 0) {
        throw new Error('low-degree committed fold count is not canonical.');
    }

    return committedFoldCount;
};

const parseTargetLowDegreeProofBytes = (
    parser: TargetProofByteParser,
    extensionSize: number,
    initialDegreeBound: number,
): void => {
    const foldCount = readTargetProofU64(
        parser,
        'low-degree folded-layer-root count',
    );
    const expectedFoldCount = committedLowDegreeFoldCount(initialDegreeBound);
    if (foldCount !== expectedFoldCount) {
        throw new Error(
            'low-degree folded-layer-root count does not match the statement layout.',
        );
    }
    consumeTargetProofBytes(
        parser,
        foldCount * proofMerkleDigestByteLength,
        'lowDegreeFoldRootBytes',
        'low-degree folded-layer roots',
    );
    consumeTargetProofBytes(
        parser,
        proofExtensionSliceByteCount(
            lowDegreeFinalCoefficientCount(initialDegreeBound),
        ),
        'lowDegreeFinalCoefficientBytes',
        'low-degree final coefficients',
    );
    for (let foldIndex = 0; foldIndex < foldCount; foldIndex += 1) {
        const siblingTableCount = readTargetProofU64(
            parser,
            `low-degree fold ${String(foldIndex)} sibling table count`,
        );
        if (
            siblingTableCount <= 0 ||
            siblingTableCount > proofLowDegreeQueryCount
        ) {
            throw new Error(
                'low-degree sibling table count exceeds the statement bound.',
            );
        }
        consumeTargetProofBytes(
            parser,
            proofExtensionSliceByteCount(siblingTableCount),
            'lowDegreeQuerySiblingBytes',
            `low-degree fold ${String(foldIndex)} sibling table`,
        );
        if (siblingTableCount < proofLowDegreeQueryCount) {
            consumeTargetProofBytes(
                parser,
                lowDegreeSiblingReferenceByteCount(siblingTableCount),
                'formatAndLengthPrefixBytes',
                `low-degree fold ${String(foldIndex)} sibling references`,
            );
        }
    }
    for (let foldIndex = 0; foldIndex < foldCount; foldIndex += 1) {
        const foldedLayerNodeCount = readTargetProofU64(
            parser,
            `low-degree fold ${String(foldIndex)} batched opening node count`,
        );
        consumeTargetProofBytes(
            parser,
            foldedLayerNodeCount * proofMerkleDigestByteLength,
            'lowDegreeQueryPathBytes',
            `low-degree fold ${String(foldIndex)} batched opening nodes`,
        );
        const foldedLayerLeafCount = extensionSize >> (foldIndex + 2);
        const maximumFoldedLayerNodeCount =
            proofLowDegreeQueryCount * Math.log2(foldedLayerLeafCount);
        if (foldedLayerNodeCount > maximumFoldedLayerNodeCount) {
            throw new Error(
                'low-degree batched opening node count exceeds the statement bound.',
            );
        }
    }
};

const decodeBase64ProofBytes = (
    proofBytesBase64: string,
    fieldName: string,
): Uint8Array => {
    const expectedByteLength = base64ByteLength(proofBytesBase64, fieldName);
    const proofBytes = Buffer.from(proofBytesBase64, 'base64');
    if (proofBytes.byteLength !== expectedByteLength) {
        throw new Error(`${fieldName} decoded to a noncanonical byte length.`);
    }

    return proofBytes;
};

const decodeHexProofBytes = (
    proofBytesHex: string,
    fieldName: string,
): Uint8Array => {
    if (proofBytesHex.length % 2 !== 0) {
        throw new Error(`${fieldName} must have an even hex length.`);
    }
    if (!/^[0-9a-f]*$/u.test(proofBytesHex)) {
        throw new Error(`${fieldName} must be lowercase hexadecimal.`);
    }

    return Buffer.from(proofBytesHex, 'hex');
};

const encodedSetupProofByteBreakdownForProofBytes = (
    proofBytes: Uint8Array,
    limbLayouts: readonly EncodedSetupProofLimbLayout[],
    proofDescription: string,
): EncodedTargetProofByteBreakdown => {
    const parser: TargetProofByteParser = {
        proofBytes,
        readOffset: 0,
        breakdown: emptyTargetProofByteBreakdown(),
    };
    const formatMarker = Buffer.from(
        consumeTargetProofBytes(
            parser,
            proofFormatMarkerByteLength,
            'formatAndLengthPrefixBytes',
            `${proofDescription} format marker`,
        ),
    ).toString('ascii');
    if (formatMarker !== 'BGVPRF18') {
        throw new Error(
            `${proofDescription} byte stream uses an unexpected format marker.`,
        );
    }
    const proofLimbCount = readTargetProofU64(
        parser,
        `${proofDescription} limb count`,
    );
    if (proofLimbCount !== limbLayouts.length) {
        throw new Error(
            `${proofDescription} limb count does not match the statement layout.`,
        );
    }

    for (const [limbPosition, limbLayout] of limbLayouts.entries()) {
        const extensionSize = limbLayout.traceSize * proofDomainBlowup;
        const totalColumnCount =
            limbLayout.phaseOnePhysicalColumnCount + proofPhaseTwoColumnCount;
        consumeTargetProofBytes(
            parser,
            2 * proofMerkleDigestByteLength,
            'commitmentRootBytes',
            `${proofDescription} limb ${String(limbPosition)} commitment roots`,
        );
        consumeTargetProofBytes(
            parser,
            packedProofResidueByteCount(limbLayout.claimCount),
            'maskedConsistencyClaimBytes',
            `${proofDescription} limb ${String(limbPosition)} masked consistency claims`,
        );
        for (
            let evaluationPointIndex = 0;
            evaluationPointIndex < proofDeepEvaluationPointCount;
            evaluationPointIndex += 1
        ) {
            consumeTargetProofBytes(
                parser,
                proofExtensionSliceByteCount(totalColumnCount),
                'deepEvaluationBytes',
                `${proofDescription} limb ${String(limbPosition)} deep evaluation point ${String(evaluationPointIndex)}`,
            );
        }
        parseTargetLowDegreeProofBytes(
            parser,
            extensionSize,
            proofCommitmentBoundFactor * limbLayout.traceSize,
        );
        parseTargetLowDegreeProofBytes(
            parser,
            extensionSize,
            limbLayout.traceSize,
        );
        for (
            let queryIndex = 0;
            queryIndex < proofLowDegreeQueryCount;
            queryIndex += 1
        ) {
            for (let slotIndex = 0; slotIndex < 2; slotIndex += 1) {
                consumeTargetProofBytes(
                    parser,
                    packedProofResidueByteCount(
                        limbLayout.phaseOnePhysicalColumnCount,
                    ),
                    'phaseOneRowBytes',
                    `${proofDescription} limb ${String(limbPosition)} phase-one row query ${String(queryIndex)} slot ${String(slotIndex)}`,
                );
            }
            consumeTargetProofBytes(
                parser,
                proofLeafSaltByteLength,
                'leafSaltBytes',
                `${proofDescription} limb ${String(limbPosition)} phase-one pair salt query ${String(queryIndex)}`,
            );
            for (let slotIndex = 0; slotIndex < 2; slotIndex += 1) {
                consumeTargetProofBytes(
                    parser,
                    proofExtensionSliceByteCount(proofPhaseTwoColumnCount),
                    'phaseTwoRowBytes',
                    `${proofDescription} limb ${String(limbPosition)} phase-two row query ${String(queryIndex)} slot ${String(slotIndex)}`,
                );
            }
            consumeTargetProofBytes(
                parser,
                proofLeafSaltByteLength,
                'leafSaltBytes',
                `${proofDescription} limb ${String(limbPosition)} phase-two pair salt query ${String(queryIndex)}`,
            );
        }
        const witnessBatchNodeCount = readTargetProofU64(
            parser,
            `${proofDescription} limb ${String(limbPosition)} phase-one batched opening node count`,
        );
        consumeTargetProofBytes(
            parser,
            witnessBatchNodeCount * proofMerkleDigestByteLength,
            'phaseOnePathBytes',
            `${proofDescription} limb ${String(limbPosition)} phase-one batched opening nodes`,
        );
        const quotientBatchNodeCount = readTargetProofU64(
            parser,
            `${proofDescription} limb ${String(limbPosition)} phase-two batched opening node count`,
        );
        consumeTargetProofBytes(
            parser,
            quotientBatchNodeCount * proofMerkleDigestByteLength,
            'phaseTwoPathBytes',
            `${proofDescription} limb ${String(limbPosition)} phase-two batched opening nodes`,
        );
    }
    if (parser.readOffset !== proofBytes.byteLength) {
        throw new Error(
            `${proofDescription} byte parser did not consume the full stream.`,
        );
    }
    if (parser.breakdown.totalBytes !== proofBytes.byteLength) {
        throw new Error(
            `${proofDescription} byte breakdown does not add up to the proof size.`,
        );
    }

    return finalizeTargetProofByteBreakdown(parser.breakdown);
};

const compactShareLinkageProofByteBreakdown = (
    fixture: RestrictedCompactShareLinkageProofFixture,
    generation: ReturnType<
        TranscriptCoreKernel['generateCompactVssShareLinkageProof']
    >,
): EncodedTargetProofByteBreakdown => {
    const proofBytes = decodeHexProofBytes(
        generation.proofBytesHex,
        'restrictedCompactShareLinkageProof.proofBytesHex',
    );
    if (proofBytes.byteLength !== generation.proofByteLength) {
        throw new Error(
            'restricted compact share-linkage proof byte length differs from the decoded proof stream.',
        );
    }
    const limbLayout = compactShareLinkageProofLimbLayout(fixture);
    const limbLayouts = Array.from(
        { length: proofSetupCommitmentLimbCount },
        () => limbLayout,
    );

    return encodedSetupProofByteBreakdownForProofBytes(
        proofBytes,
        limbLayouts,
        'compact share-linkage proof',
    );
};

const measureRestrictedCompactShareLinkageProof = (
    kernel: TranscriptCoreKernel,
    fixture: RestrictedCompactShareLinkageProofFixture,
): RestrictedCompactShareLinkageProofMeasurement => {
    const generation = measureSyncOperation(() =>
        kernel.generateCompactVssShareLinkageProof({
            ...fixture,
            ringDegree: restrictedProofRingDegree,
            proofRandomnessSeedHex: 'ab'.repeat(64),
            proofRandomnessNonceHex: 'cd'.repeat(64),
        }),
    );
    const verification = measureSyncOperation(() =>
        kernel.verifyCompactVssShareLinkageProof({
            context: fixture.context,
            ringDegree: restrictedProofRingDegree,
            compactVssShareLinkage: fixture.compactVssShareLinkage,
            proofBytesHex: generation.lastResult.proofBytesHex,
        }),
    );

    if (
        generation.lastResult.statementHash !==
        verification.lastResult.statementHash
    ) {
        throw new Error(
            'restricted compact share-linkage proof statement hashes differ.',
        );
    }
    if (
        generation.lastResult.proofByteLength !==
        verification.lastResult.proofByteLength
    ) {
        throw new Error(
            'restricted compact share-linkage proof byte lengths differ.',
        );
    }
    if (
        verification.lastResult.coefficientCommitmentCount !==
        restrictedProofCoefficientCount * fixture.proofItemCount
    ) {
        throw new Error(
            'restricted compact share-linkage proof coefficient count differs.',
        );
    }
    if (
        verification.lastResult.coefficientWitnessColumnCount !==
        fixture.coefficientWitnessColumnCount
    ) {
        throw new Error(
            'restricted compact share-linkage proof witness-column count differs.',
        );
    }
    const proofByteBreakdown = compactShareLinkageProofByteBreakdown(
        fixture,
        generation.lastResult,
    );

    return { generation, verification, proofByteBreakdown };
};

const targetProofByteBreakdownForProofRecord = (
    proofRecord: unknown,
    statementLayout: TargetProofStatementLayout,
    proofRecordIndex: number,
): EncodedTargetProofByteBreakdown => {
    const proofBytes = decodeBase64ProofBytes(
        stringField(proofRecord, 'proofBytesBase64'),
        `proofRecords.${String(proofRecordIndex)}.proofBytesBase64`,
    );
    const limbLayouts = statementLayout.proofLimbIndices.map((proofLimbIndex) =>
        targetProofLimbLayout(statementLayout, proofLimbIndex),
    );

    return encodedSetupProofByteBreakdownForProofBytes(
        proofBytes,
        limbLayouts,
        'target proof',
    );
};

const sumTargetProofByteBreakdowns = (
    breakdowns: readonly EncodedTargetProofByteBreakdown[],
): EncodedTargetProofByteBreakdown => {
    const total = emptyTargetProofByteBreakdown();
    for (const breakdown of breakdowns) {
        total.totalBytes += breakdown.totalBytes;
        for (const section of targetProofByteBreakdownSections) {
            total[section] += breakdown[section];
        }
    }

    return finalizeTargetProofByteBreakdown(total);
};

const targetProofByteBreakdown = (
    proofMaterial: ReturnType<
        TranscriptCoreKernel['generateBgvTargetDecryptionShareProofMaterialFromLocalWitness']
    >,
    proofStatement: ReturnType<
        TranscriptCoreKernel['deriveBgvTargetDecryptionShareProofStatement']
    >,
): EncodedTargetProofByteBreakdown => {
    const statementLayout = targetProofStatementLayout(proofStatement);
    const proofRecordBreakdowns = targetProofRecords(proofMaterial).map(
        (proofRecord, proofRecordIndex) =>
            targetProofByteBreakdownForProofRecord(
                proofRecord,
                statementLayout,
                proofRecordIndex,
            ),
    );

    return sumTargetProofByteBreakdowns(proofRecordBreakdowns);
};

const protocolRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const measureTargetProofMaterialBinaryFrames = (input: {
    readonly proofMaterialBinaryFrames: readonly ReturnType<
        typeof encodeBgvTargetDecryptionShareProofMaterialBinary
    >[];
    readonly proofMaterialJsonBytesTotal: number;
    readonly proofMaterialTotalProofByteLength: number;
}): TargetProofMaterialBinaryFrameMeasurement => {
    const frames = input.proofMaterialBinaryFrames;
    const proofMaterialBinaryFrameBytesByShare = frames.map(
        (frame) => frame.totalByteLength,
    );
    const proofMaterialBinaryFrameBytesTotal =
        proofMaterialBinaryFrameBytesByShare.reduce(
            (totalBytes, frameBytes) => totalBytes + frameBytes,
            0,
        );

    return {
        proofMaterialBinaryFrameBytesByShare,
        proofMaterialBinaryFrameBytesTotal,
        proofMaterialBinaryFrameChunkCountByShare: frames.map(
            (frame) => frame.chunkCount,
        ),
        proofMaterialBinaryFrameChunkRootByShare: frames.map(
            (frame) => frame.chunkRoot,
        ),
        proofMaterialBinaryFrameFullObjectHashByShare: frames.map(
            (frame) => frame.fullObjectHash,
        ),
        proofMaterialBinaryFrameSavingsBytes:
            input.proofMaterialJsonBytesTotal -
            proofMaterialBinaryFrameBytesTotal,
        proofMaterialBinaryFrameOverRawProofBytes:
            proofMaterialBinaryFrameBytesTotal -
            input.proofMaterialTotalProofByteLength,
    };
};

const assertTargetStatementBindingIsProofless = (value: unknown): void => {
    const record = protocolRecord(
        value,
        'target-decryption statement-binding result',
    );
    if (
        record.ok !== false ||
        record.refusalReason !== 'TargetDecryptionProofUnavailable'
    ) {
        throw new Error(
            'Target-decryption statement binding must remain proof-unavailable and non-accepting until proof verification exists.',
        );
    }
};

const measurementHash = (label: string): ProtocolHash =>
    deriveProtocolHash('SetupProofRecordBindingHash', {
        objectType: 'CompactVssManualMeasurementReference',
        objectVersion: 1,
        label,
    });

const measurementSetupContext = (): CollectiveBgvSetupContext => ({
    ceremonyId: 'compact-vss-manual-measurement',
    manifestHash: measurementHash('manifest'),
    rosterHash: measurementHash('roster'),
    setupProfileHash: measurementHash('setup-profile'),
    qShareHash: measurementHash('q-share'),
    carryAwareVssShareRelationProfileHash: measurementHash(
        'carry-aware-vss-share-relation-profile',
    ),
    commitmentProfileHash: measurementHash('commitment-profile'),
    setupEpoch: 'compact-vss-measurement-epoch',
});

const deterministicResidueVector = (
    rnsPrime: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): readonly number[] => {
    const modulus = BigInt(rnsPrime);
    const limbOffset = BigInt(101 + rnsLimbIndex * 4_099);
    const coefficientOffset = BigInt(1_009 + shamirCoefficientIndex * 8_191);

    return Array.from(
        { length: acceptedBgvProfileRingDegree },
        (_unused, coefficientIndex) => {
            const residue =
                (BigInt(coefficientIndex + 1) * 65_537n +
                    limbOffset +
                    coefficientOffset) %
                modulus;

            return Number((modulus - 1n - residue) % modulus);
        },
    );
};

const deterministicRandomnessColumns = (
    seedOffset: number,
    ringDegree: number,
): readonly (readonly number[])[] =>
    Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        (_unusedColumn, columnIndex) =>
            Array.from(
                { length: ringDegree },
                (_unusedCoefficient, coefficientIndex) =>
                    ((seedOffset + columnIndex * 11 + coefficientIndex * 17) %
                        3) -
                    1,
            ),
    );

const sourceTrusteeContributionState = (
    setupContext: CollectiveBgvSetupContext,
    publicMatrixSeedHash: ProtocolHash,
): PrivateVssSourceTrusteeContributionState => {
    const sourceTrusteeIdentity = 'trustee-0';
    const sourceTrusteeRosterPosition = 0;
    const coefficientOpenings = acceptedBgvSetupQSharePrimes.flatMap(
        (rnsPrime, rnsLimbIndex) =>
            Array.from(
                { length: firstProfileThresholdDegree },
                (_unused, shamirCoefficientIndex) => {
                    const commitmentRoot = measurementHash(
                        `source-coefficient-${String(rnsLimbIndex)}-${String(
                            shamirCoefficientIndex,
                        )}`,
                    );

                    return {
                        rnsLimbIndex,
                        rnsPrime,
                        shamirCoefficientIndex,
                        commitmentRoot,
                        coefficientMessage: deterministicResidueVector(
                            rnsPrime,
                            rnsLimbIndex,
                            shamirCoefficientIndex,
                        ),
                        randomnessByColumn: [],
                    };
                },
            ),
    );
    const coefficientCommitments = coefficientOpenings.map((opening) => ({
        objectType: 'VssCoefficientCommitment',
        objectVersion: 1,
        ...setupContext,
        sourceTrusteeIdentity,
        sourceTrusteeRosterPosition,
        publicMatrixSeedHash,
        rnsLimbIndex: opening.rnsLimbIndex,
        rnsPrime: opening.rnsPrime,
        shamirCoefficientIndex: opening.shamirCoefficientIndex,
        commitmentRoot: opening.commitmentRoot,
    }));
    const sourceTrusteeRecordWithoutRoot = {
        objectType: 'VssSourceTrusteeCoefficientCommitments',
        objectVersion: 1,
        ...setupContext,
        sourceTrusteeIdentity,
        sourceTrusteeRosterPosition,
        publicMatrixSeedHash,
        coefficientCommitments,
    };
    const sourceTrusteeCommitmentRoot = deriveProtocolHash(
        'VssCoefficientCommitmentRoot',
        sourceTrusteeRecordWithoutRoot,
    );
    const sourceTrusteeCoefficientCommitmentRecord = {
        ...sourceTrusteeRecordWithoutRoot,
        sourceTrusteeCommitmentRoot,
    };

    return {
        sourceTrusteeIdentity,
        sourceTrusteeRosterPosition,
        sourceTrusteeCommitmentRoot,
        sourceTrusteeCoefficientCommitmentRecord,
        sourceTrusteeCoefficientCommitmentMaterialRecords: [],
        coefficientOpenings,
    };
};

const fullRingPrivateStateFixture = (): FullRingPrivateStateFixture => {
    const setupContext = measurementSetupContext();
    const publicMatrixSeedHash = measurementHash('public-matrix-seed');
    const sourceState = sourceTrusteeContributionState(
        setupContext,
        publicMatrixSeedHash,
    );
    const recipientTrustees = [
        {
            trusteeIdentity: 'trustee-0',
            trusteeRosterPosition: 0,
        },
    ] as const;
    const coefficientCommitmentSet = createCompactVssCoefficientCommitmentSet({
        setupContext,
        publicMatrixSeedHash,
        participantCount: 1,
        qSharePrimes: acceptedBgvSetupQSharePrimes,
        ringDegree: acceptedBgvProfileRingDegree,
        thresholdDegree: firstProfileThresholdDegree,
        sourceTrusteeOpeningStates: [sourceState],
        coefficientOpeningRandomness: ({
            rnsLimbIndex,
            shamirCoefficientIndex,
            ringDegree,
        }) =>
            deterministicRandomnessColumns(
                3 + rnsLimbIndex * 43 + shamirCoefficientIndex * 271,
                ringDegree,
            ),
    });
    const recipientShareBundle = createCompactVssRecipientShareCommitmentBundle(
        {
            setupContext,
            publicMatrixSeedHash,
            participantCount: 1,
            qSharePrimes: acceptedBgvSetupQSharePrimes,
            ringDegree: acceptedBgvProfileRingDegree,
            thresholdDegree: firstProfileThresholdDegree,
            sourceTrusteeOpeningStates: [sourceState],
            recipientTrustees,
            shareOpeningRandomness: ({ rnsLimbIndex, ringDegree }) =>
                deterministicRandomnessColumns(
                    19 + rnsLimbIndex * 71,
                    ringDegree,
                ),
        },
    );
    const aggregateBundle = aggregateCompactVssThresholdShareCommitments({
        setupContext,
        publicMatrixSeedHash,
        participantCount: 1,
        qSharePrimes: acceptedBgvSetupQSharePrimes,
        ringDegree: acceptedBgvProfileRingDegree,
        recipientTrustees,
        recipientShareOpeningCredentials:
            recipientShareBundle.recipientShareOpeningCredentials,
    });
    const shareLinkageStatement = createCompactVssShareLinkageStatement({
        setupContext,
        publicMatrixSeedHash,
        targetBasisHash: canonicalTargetBasisHash,
        coefficientCommitmentSet,
        recipientShareCommitmentSet:
            recipientShareBundle.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet:
            aggregateBundle.aggregateThresholdCommitmentSet,
    });
    const mailboxKeyPair = createPrivateVssMailboxKeyPair(
        measurementHash('mailbox-key'),
    );

    return {
        setupContext,
        publicMatrixSeedHash,
        vssCoefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        sourceTrusteeContributionState: sourceState,
        recipientTrustees,
        mailboxPublicKeyBytesHex: mailboxKeyPair.publicKeyBytesHex,
        compactRecipientShareOpeningCredentials:
            recipientShareBundle.recipientShareOpeningCredentials,
        compactRecipientShareOpeningCredentialsJsonBytes: jsonByteLength(
            recipientShareBundle.recipientShareOpeningCredentials,
        ),
        coefficientCommitmentSet,
        recipientShareCommitmentSet:
            recipientShareBundle.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet:
            aggregateBundle.aggregateThresholdCommitmentSet,
        shareLinkageStatement,
    };
};

const privateVssShareProofFramingSample = (
    rnsLimbIndex: number,
): JsonRecord => {
    const proofBytes = Uint8Array.from(
        { length: privateVssShareProofFramingSampleBytes },
        (_unused, byteIndex) => (rnsLimbIndex * 29 + byteIndex) % 256,
    );
    const proofBytesHex = Buffer.from(proofBytes).toString('hex');

    return {
        objectType: 'PrivateVssShareProof',
        objectVersion: 1,
        proofProfileId: 'sealed-lattice-private-vss-share-proof-succinct-v1',
        setupProofProfileId: setupProofProfileId,
        proofFamily: 'vss-opening-carry',
        proofBytesEncoding: 'embedded-binary-proof-bytes-hex',
        proofStatementRoot: measurementHash(
            `private-share-proof-statement-${String(rnsLimbIndex)}`,
        ),
        statementHash: measurementHash(
            `private-share-proof-statement-hash-${String(rnsLimbIndex)}`,
        ),
        proofAccountingHash: measurementHash(
            'private-share-proof-accounting-sample',
        ),
        proofSizeBytes: proofBytes.byteLength,
        proofBytesHash: hash512Hex(
            'sealed-lattice/setup/private-vss-share/succinct-proof-bytes-v1',
            [proofBytes],
        ),
        proofMaterialRoot: measurementHash(
            `private-share-proof-material-${String(rnsLimbIndex)}`,
        ),
        proofBytesHex,
    };
};

const privateMailboxMeasurementKernel = (
    observedPrivateEnvelopes: JsonRecord[],
    observedTransportedProofMaterials: JsonRecord[],
): PrivateVssMailboxDeliveryKernel => ({
    deriveProtocolHash: ({ namespace, value }) =>
        deriveProtocolHash(namespace, value),
    verifyPrivateVssShareEnvelope: (input) => {
        const privateEnvelope = protocolRecord(
            input.privateEnvelope,
            'privateEnvelope',
        );
        observedPrivateEnvelopes.push(privateEnvelope);
        if (input.transportedPrivateVssShareProofMaterial !== undefined) {
            observedTransportedProofMaterials.push(
                protocolRecord(
                    input.transportedPrivateVssShareProofMaterial,
                    'transportedPrivateVssShareProofMaterial',
                ),
            );
        }
        const privateEnvelopeHash = deriveProtocolHash(
            'PrivateVssShareEnvelopeHash',
            privateEnvelope,
        );

        return {
            ok: true,
            privateEnvelopeHash,
            localVerificationRoot: deriveProtocolHash(
                'PrivateVssLocalVerificationRoot',
                {
                    privateEnvelopeHash,
                    publicMatrixSeedHash: input.publicMatrixSeedHash,
                },
            ),
            verifiedPrivateVssShareProofCount:
                acceptedBgvSetupQSharePrimes.length,
            refusedObjects: [],
        };
    },
});

const firstEnvelopeReference = (
    deliverySet: PrivateVssMailboxDeliverySet,
): JsonRecord => {
    const envelopeReference = deliverySet.envelopeReferences[0];
    if (envelopeReference === undefined) {
        throw new Error('private mailbox measurement produced no envelope.');
    }

    return envelopeReference;
};

const localStateInputFromPrivateMailbox = (
    fixture: FullRingPrivateStateFixture,
    deliverySet: PrivateVssMailboxDeliverySet,
    verifiedPrivateEnvelope: JsonRecord,
): GeneratedLocalTrusteeSetupStateInput => {
    const envelopeReference = firstEnvelopeReference(deliverySet);
    const aggregateRecord =
        fixture.aggregateThresholdCommitmentSet.recipientRecords[0];
    if (aggregateRecord === undefined) {
        throw new Error(
            'compact aggregate measurement fixture produced no recipient record.',
        );
    }

    return {
        setupContext: fixture.setupContext,
        trusteeIdentity: 'trustee-0',
        trusteeRosterPosition: 0,
        deviceEpoch: 1,
        thresholdShareCommitments: {
            objectType: 'ThresholdShareCommitmentSet',
            objectVersion: 1,
            ...fixture.setupContext,
            recipientRecords: [
                {
                    objectType: 'ThresholdShareCommitmentRecipient',
                    objectVersion: 1,
                    recipientIdentity: 'trustee-0',
                    recipientRosterPosition: 0,
                    recipientCommitmentRoot:
                        aggregateRecord.aggregateCommitmentRoot,
                },
            ],
        },
        privateVssEnvelopeCommitments: deliverySet,
        verifiedPrivateVssShareEnvelopes: [verifiedPrivateEnvelope],
        vssShareAcceptances: {
            objectType: 'VssShareAcceptanceSet',
            objectVersion: 1,
            ...fixture.setupContext,
            acceptanceRecords: [
                {
                    objectType: 'VssShareAcceptance',
                    objectVersion: 1,
                    ...fixture.setupContext,
                    sourceTrusteeIdentity:
                        envelopeReference.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        envelopeReference.sourceTrusteeRosterPosition,
                    recipientIdentity: 'trustee-0',
                    recipientRosterPosition: 0,
                    privateVssEnvelopeCommitmentRoot:
                        deliverySet.privateVssEnvelopeCommitmentRoot,
                    privateEnvelopeHash: envelopeReference.privateEnvelopeHash,
                    localVerificationRoot:
                        envelopeReference.localVerificationRoot,
                    acceptanceRoot: measurementHash('acceptance-root'),
                },
            ],
        },
        storageKeyBytesHex: '61'.repeat(32),
        localStateAeadNonceBytesHex: '62'.repeat(12),
        sealedAggregateThresholdShareAeadNonceBytesHex: '63'.repeat(12),
        sealedTargetDecryptionProofWitnessAeadNonceBytesHex: '64'.repeat(12),
        compactVssTargetProofWitness: {
            aggregateThresholdCommitmentSet:
                fixture.aggregateThresholdCommitmentSet,
            targetDecryptionRnsLimbCount: targetRnsLimbCount,
            shareLinkageStatement: fixture.shareLinkageStatement,
        },
    };
};

const encryptedLocalStateMeasurement = (
    localState: GeneratedLocalTrusteeSetupStateResult,
    sourceEnvelopeCount: number,
    buildMilliseconds: number,
): EncryptedLocalStateDevelopmentArtifactMeasurement => {
    const sealedAggregateThresholdShare =
        localState.sealedAggregateThresholdShare;
    const sealedTargetDecryptionProofWitness =
        localState.sealedTargetDecryptionProofWitness;
    const localStateManifestPlaintextBytes =
        localState.encryptedLocalState.plaintextByteLength;
    const encryptedLocalStateJsonBytes = jsonByteLength(
        localState.encryptedLocalState,
    );
    const localStateCommitmentJsonBytes = jsonByteLength(
        localState.localStateCommitment,
    );
    const sealedAggregateThresholdShareJsonBytes = jsonByteLength(
        sealedAggregateThresholdShare,
    );
    const sealedTargetDecryptionProofWitnessJsonBytes = jsonByteLength(
        sealedTargetDecryptionProofWitness,
    );

    return {
        qShareLimbCount: acceptedBgvSetupQSharePrimes.length,
        ringDegree: acceptedBgvProfileRingDegree,
        sourceEnvelopeCount,
        buildMilliseconds,
        aggregateThresholdSharePlaintextBytes:
            sealedAggregateThresholdShare.encryptedMaterial.plaintextByteLength,
        targetDecryptionProofWitnessPlaintextBytes:
            sealedTargetDecryptionProofWitness.encryptedMaterial
                .plaintextByteLength,
        localStateManifestPlaintextBytes,
        encryptedLocalStateJsonBytes,
        localStateCommitmentJsonBytes,
        sealedAggregateThresholdShareJsonBytes,
        sealedTargetDecryptionProofWitnessJsonBytes,
        largestSingleObjectJsonBytes: Math.max(
            localStateManifestPlaintextBytes,
            encryptedLocalStateJsonBytes,
            localStateCommitmentJsonBytes,
            sealedAggregateThresholdShareJsonBytes,
            sealedTargetDecryptionProofWitnessJsonBytes,
        ),
    };
};

const measurePrivateStateDevelopmentArtifacts =
    async (): Promise<PrivateStateDevelopmentArtifactMeasurement> => {
        const fixture = fullRingPrivateStateFixture();
        const observedPrivateEnvelopes: JsonRecord[] = [];
        const observedTransportedProofMaterials: JsonRecord[] = [];
        const mailboxStartedAtMilliseconds = performance.now();
        const deliverySet = await createPrivateVssMailboxDeliverySet({
            kernel: privateMailboxMeasurementKernel(
                observedPrivateEnvelopes,
                observedTransportedProofMaterials,
            ),
            setupContext: fixture.setupContext,
            phaseOrderHash: measurementHash('phase-order'),
            publicMatrixSeedHash: fixture.publicMatrixSeedHash,
            vssCoefficientCommitmentRoot: fixture.vssCoefficientCommitmentRoot,
            qSharePrimes: acceptedBgvSetupQSharePrimes,
            ringDegree: acceptedBgvProfileRingDegree,
            participantCount: 1,
            deliveryPhaseNumber: 6,
            verificationPhaseNumber: 7,
            privateVssShareProofMaterialEncoding: 'binary-chunked-proof-bytes',
            privateVssShareProofFactory: ({ rnsLimbIndex }) =>
                privateVssShareProofFramingSample(rnsLimbIndex),
            compactVssRecipientShareOpeningCredentials:
                fixture.compactRecipientShareOpeningCredentials,
            sourceTrusteeContributionStates: [
                fixture.sourceTrusteeContributionState,
            ],
            recipients: [
                {
                    recipientIdentity: 'trustee-0',
                    recipientRosterPosition: 0,
                    mailboxPublicKeyBytesHex: fixture.mailboxPublicKeyBytesHex,
                },
            ],
        });
        const mailboxBuildMilliseconds =
            performance.now() - mailboxStartedAtMilliseconds;
        const envelopeReference = firstEnvelopeReference(deliverySet);
        const privateEnvelope = observedPrivateEnvelopes[0];
        if (privateEnvelope === undefined) {
            throw new Error(
                'private mailbox measurement did not observe the private envelope.',
            );
        }
        const transportedPrivateVssShareProofMaterial =
            observedTransportedProofMaterials[0];
        if (transportedPrivateVssShareProofMaterial === undefined) {
            throw new Error(
                'private mailbox measurement did not observe transported proof material.',
            );
        }
        const encryptedEnvelope = objectField(
            envelopeReference,
            'encryptedEnvelope',
        );
        const privateEnvelopeAad = objectField(
            envelopeReference,
            'privateEnvelopeAad',
        );
        const sourceRecipientEnvelopeCountInFirstProfile =
            firstProfileParticipantCount * firstProfileParticipantCount;
        const sourceRecipientEnvelopeCountPerSourceInFirstProfile =
            firstProfileParticipantCount;
        const envelopeReferenceJsonBytes = jsonByteLength(envelopeReference);
        const sourceTrusteeEnvelopeReferenceJsonBytesExtrapolatedToFirstProfile =
            envelopeReferenceJsonBytes *
            sourceRecipientEnvelopeCountPerSourceInFirstProfile;
        const privateMailbox: PrivateMailboxDevelopmentArtifactMeasurement = {
            qShareLimbCount: acceptedBgvSetupQSharePrimes.length,
            ringDegree: acceptedBgvProfileRingDegree,
            thresholdDegree: firstProfileThresholdDegree,
            sourceRecipientEnvelopeCountInFirstProfile,
            sourceRecipientEnvelopeCountPerSourceInFirstProfile,
            buildMilliseconds: mailboxBuildMilliseconds,
            privateShareProofFramingSampleBytesPerLimb:
                privateVssShareProofFramingSampleBytes,
            privateShareProofFramingSampleBytesTotal:
                privateVssShareProofFramingSampleBytes *
                acceptedBgvSetupQSharePrimes.length,
            compactRecipientShareOpeningCredentialCount:
                acceptedBgvSetupQSharePrimes.length,
            compactRecipientShareOpeningCredentialsJsonBytes:
                fixture.compactRecipientShareOpeningCredentialsJsonBytes,
            privateEnvelopeJsonBytes: jsonByteLength(privateEnvelope),
            transportedPrivateVssShareProofMaterialJsonBytes: jsonByteLength(
                transportedPrivateVssShareProofMaterial,
            ),
            privateEnvelopeAadJsonBytes: jsonByteLength(privateEnvelopeAad),
            encryptedEnvelopeJsonBytes: jsonByteLength(encryptedEnvelope),
            envelopeReferenceJsonBytes,
            deliverySetJsonBytes: jsonByteLength(deliverySet),
            envelopeReferenceJsonBytesExtrapolatedToFirstProfile:
                envelopeReferenceJsonBytes *
                sourceRecipientEnvelopeCountInFirstProfile,
            sourceTrusteeEnvelopeReferenceJsonBytesExtrapolatedToFirstProfile,
            sourceTrusteeUploadBudgetMarginBytes:
                268_435_456 -
                sourceTrusteeEnvelopeReferenceJsonBytesExtrapolatedToFirstProfile,
            largestSingleObjectJsonBytes: Math.max(
                jsonByteLength(privateEnvelope),
                jsonByteLength(transportedPrivateVssShareProofMaterial),
                jsonByteLength(encryptedEnvelope),
                envelopeReferenceJsonBytes,
                jsonByteLength(deliverySet),
            ),
        };
        const localStateInput = localStateInputFromPrivateMailbox(
            fixture,
            deliverySet,
            privateEnvelope,
        );
        const localStateStartedAtMilliseconds = performance.now();
        const localState =
            await createEncryptedLocalTrusteeSetupStateFromVerifiedShares(
                localStateInput,
            );
        const localStateBuildMilliseconds =
            performance.now() - localStateStartedAtMilliseconds;
        const encryptedLocalState = encryptedLocalStateMeasurement(
            localState,
            deliverySet.envelopeReferences.length,
            localStateBuildMilliseconds,
        );

        return {
            privateMailbox,
            encryptedLocalState,
            largestSingleObjectJsonBytes: Math.max(
                privateMailbox.largestSingleObjectJsonBytes,
                encryptedLocalState.largestSingleObjectJsonBytes,
            ),
        };
    };

const measureTargetDecryptionDevelopmentArtifacts = (
    kernel: TranscriptCoreKernel,
): TargetDecryptionDevelopmentMeasurements => {
    const fixture = kernel.generateBgvTargetDecryptionDevelopmentFixture();
    const minimumSharesForInterpolation = numberField(
        fixture.targetShareProfile,
        'minimumSharesForInterpolation',
    );
    const quorumWitnesses = arrayField(
        fixture,
        'quorumLocalTargetShareWitnesses',
    )
        .slice(0, minimumSharesForInterpolation)
        .map((quorumWitness, quorumWitnessIndex) => {
            const quorumWitnessRecord = protocolRecord(
                quorumWitness,
                `quorumLocalTargetShareWitnesses[${String(quorumWitnessIndex)}]`,
            );

            return {
                trusteeIdentity: stringField(
                    quorumWitnessRecord,
                    'trusteeIdentity',
                ),
                localTargetShareWitness: objectField(
                    quorumWitnessRecord,
                    'localTargetShareWitness',
                ),
            };
        });
    if (quorumWitnesses.length !== minimumSharesForInterpolation) {
        throw new Error(
            'target-decryption measurement fixture did not produce the interpolation quorum.',
        );
    }
    const targetShareBundles: readonly TargetDecryptionShareMeasurementBundle[] =
        quorumWitnesses.map((quorumWitness) => {
            const targetShare =
                kernel.generateBgvTargetDecryptionShareFromLocalShare({
                    setupPackage: fixture.setupPackage,
                    localTargetShareWitness:
                        quorumWitness.localTargetShareWitness,
                    targetAcceptedRecord: fixture.targetAcceptedRecord,
                    targetCiphertextBinding: fixture.targetCiphertextBinding,
                    targetCiphertexts: fixture.targetCiphertexts,
                    targetShareProfile: fixture.targetShareProfile,
                    trusteeIdentity: quorumWitness.trusteeIdentity,
                });
            const proofStatement =
                kernel.deriveBgvTargetDecryptionShareProofStatement({
                    setupPackage: fixture.setupPackage,
                    localTargetShareWitness:
                        quorumWitness.localTargetShareWitness,
                    targetAcceptedRecord: fixture.targetAcceptedRecord,
                    targetCiphertextBinding: fixture.targetCiphertextBinding,
                    targetCiphertexts: fixture.targetCiphertexts,
                    targetShareProfile: fixture.targetShareProfile,
                    trusteeIdentity: quorumWitness.trusteeIdentity,
                    targetDecryptionShare: targetShare,
                });

            return {
                trusteeIdentity: quorumWitness.trusteeIdentity,
                localTargetShareWitness: quorumWitness.localTargetShareWitness,
                targetShare,
                proofStatement,
            };
        });
    const firstTargetShareBundle = targetShareBundles[0];
    if (firstTargetShareBundle === undefined) {
        throw new Error(
            'target-decryption measurement fixture produced no target share bundle.',
        );
    }
    const statementBindingVerification =
        kernel.verifyBgvTargetDecryptionShareProofStatementBinding({
            setupPackage: fixture.setupPackage,
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetCiphertextBinding: fixture.targetCiphertextBinding,
            targetCiphertexts: fixture.targetCiphertexts,
            targetShareProfile: fixture.targetShareProfile,
            targetDecryptionShare: firstTargetShareBundle.targetShare,
            proofStatement: firstTargetShareBundle.proofStatement,
        });
    assertTargetStatementBindingIsProofless(statementBindingVerification);
    const targetShareJsonBytes = jsonByteLength(
        firstTargetShareBundle.targetShare,
    );
    const targetSharePayloadJsonBytes = jsonByteLength(
        firstTargetShareBundle.targetShare.sharePayload,
    );
    const smudgingInputReportJsonBytes = jsonByteLength(
        firstTargetShareBundle.targetShare.sharePayload.smudgingInputReport,
    );
    const proofStatementJsonBytes = jsonByteLength(
        firstTargetShareBundle.proofStatement,
    );
    const statementBindingVerificationJsonBytes = jsonByteLength(
        statementBindingVerification,
    );
    const localTargetShareWitnessJsonBytes = jsonByteLength(
        firstTargetShareBundle.localTargetShareWitness,
    );
    const targetDecryptionSmudgingWitness = objectField(
        firstTargetShareBundle.localTargetShareWitness,
        'targetDecryptionSmudging',
    );
    const compactAggregateOpeningWitness = objectField(
        firstTargetShareBundle.localTargetShareWitness,
        'compactAggregateOpening',
    );
    const compactAggregateOpeningCredentials = arrayField(
        compactAggregateOpeningWitness,
        'compactAggregateOpeningCredentials',
    );
    const artifacts: TargetDecryptionDevelopmentArtifactMeasurement = {
        localTargetShareWitnessJsonBytes,
        targetDecryptionSmudgingWitnessJsonBytes: jsonByteLength(
            targetDecryptionSmudgingWitness,
        ),
        compactAggregateOpeningWitnessJsonBytes: jsonByteLength(
            compactAggregateOpeningWitness,
        ),
        compactAggregateOpeningCredentialCount:
            compactAggregateOpeningCredentials.length,
        compactAggregateOpeningCredentialsJsonBytes: jsonByteLength(
            compactAggregateOpeningCredentials,
        ),
        targetShareJsonBytes,
        targetSharePayloadJsonBytes,
        smudgingInputReportJsonBytes,
        proofStatementJsonBytes,
        statementBindingVerificationJsonBytes,
        largestSingleObjectJsonBytes: Math.max(
            localTargetShareWitnessJsonBytes,
            jsonByteLength(targetDecryptionSmudgingWitness),
            jsonByteLength(compactAggregateOpeningWitness),
            jsonByteLength(compactAggregateOpeningCredentials),
            targetShareJsonBytes,
            proofStatementJsonBytes,
            statementBindingVerificationJsonBytes,
        ),
    };

    if (!targetProofMaterialMeasurementRequested) {
        return {
            artifacts,
            proofMaterial: {
                measurementMode:
                    'Set SEALED_LATTICE_MEASURE_TARGET_PROOF_MATERIAL=1 to run the heavy target-decryption proof-material measurement.',
            },
        };
    }

    const proofMaterialStartedAtMilliseconds = performance.now();
    const proofMaterials = targetShareBundles.map((targetShareBundle, index) =>
        kernel.generateBgvTargetDecryptionShareProofMaterialFromLocalWitness({
            setupPackage: fixture.setupPackage,
            localTargetShareWitness: targetShareBundle.localTargetShareWitness,
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetCiphertextBinding: fixture.targetCiphertextBinding,
            targetCiphertexts: fixture.targetCiphertexts,
            targetShareProfile: fixture.targetShareProfile,
            trusteeIdentity: targetShareBundle.trusteeIdentity,
            targetDecryptionShare: targetShareBundle.targetShare,
            proofStatement: targetShareBundle.proofStatement,
            proofRandomnessSeedHex: (0x21 + index * 2)
                .toString(16)
                .padStart(2, '0')
                .repeat(64),
            proofRandomnessNonceHex: (0x22 + index * 2)
                .toString(16)
                .padStart(2, '0')
                .repeat(64),
        }),
    );
    const proofMaterialGenerationMilliseconds =
        performance.now() - proofMaterialStartedAtMilliseconds;
    const proofMaterialBinaryFrames = proofMaterials.map((proofMaterial) =>
        encodeBgvTargetDecryptionShareProofMaterialBinary(proofMaterial),
    );

    const proofMaterialVerificationStartedAtMilliseconds = performance.now();
    const proofMaterialVerifications = proofMaterials.map(
        (proofMaterial, index) => {
            const targetShareBundle = targetShareBundles[index];
            if (targetShareBundle === undefined) {
                throw new Error(
                    'target-decryption proof material has no matching share bundle.',
                );
            }

            return kernel.verifyBgvTargetDecryptionShareProofMaterial({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: targetShareBundle.targetShare,
                proofStatement: targetShareBundle.proofStatement,
                proofMaterial,
            });
        },
    );
    const proofMaterialVerificationMilliseconds =
        performance.now() - proofMaterialVerificationStartedAtMilliseconds;

    const proofMaterialBinaryVerificationStartedAtMilliseconds =
        performance.now();
    const proofMaterialBinaryVerifications = proofMaterialBinaryFrames.map(
        (transportedProofMaterial, index) => {
            const targetShareBundle = targetShareBundles[index];
            if (targetShareBundle === undefined) {
                throw new Error(
                    'target-decryption binary proof material has no matching share bundle.',
                );
            }

            return kernel.verifyBgvTargetDecryptionShareBinaryProofMaterial({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: targetShareBundle.targetShare,
                proofStatement: targetShareBundle.proofStatement,
                transportedProofMaterial,
            });
        },
    );
    const proofMaterialBinaryVerificationMilliseconds =
        performance.now() -
        proofMaterialBinaryVerificationStartedAtMilliseconds;

    const proofMaterialJsonBytesByShare = proofMaterials.map(jsonByteLength);
    const proofMaterialJsonBytesTotal = proofMaterialJsonBytesByShare.reduce(
        (totalBytes, shareBytes) => totalBytes + shareBytes,
        0,
    );
    const proofMaterialVerificationJsonBytesByShare =
        proofMaterialVerifications.map(jsonByteLength);
    const proofMaterialBinaryVerificationJsonBytesByShare =
        proofMaterialBinaryVerifications.map(jsonByteLength);
    const proofMaterialProofByteBreakdownByShare = proofMaterials.map(
        (proofMaterial, proofMaterialIndex) => {
            const targetShareBundle = targetShareBundles[proofMaterialIndex];
            if (targetShareBundle === undefined) {
                throw new Error(
                    'target-decryption proof material has no matching share bundle for byte attribution.',
                );
            }

            return targetProofByteBreakdown(
                proofMaterial,
                targetShareBundle.proofStatement,
            );
        },
    );
    const proofMaterialProofByteBreakdownTotal = sumTargetProofByteBreakdowns(
        proofMaterialProofByteBreakdownByShare,
    );
    const proofMaterialTotalProofByteLength = proofMaterials.reduce(
        (totalBytes, proofMaterial) =>
            totalBytes + targetProofByteLength(proofMaterial),
        0,
    );
    const proofMaterialBinaryFrameMeasurement =
        measureTargetProofMaterialBinaryFrames({
            proofMaterialBinaryFrames,
            proofMaterialJsonBytesTotal,
            proofMaterialTotalProofByteLength,
        });
    if (
        proofMaterialProofByteBreakdownTotal.totalBytes !==
        proofMaterialTotalProofByteLength
    ) {
        throw new Error(
            'target-decryption proof byte attribution does not match the measured proof-byte total.',
        );
    }
    const proofMaterialMeasurement: TargetDecryptionProofMaterialMeasurement = {
        measurementMode: 'heavy target-decryption proof-material measurement',
        shareCount: targetShareBundles.length,
        proofMaterialJsonBytesByShare,
        proofMaterialJsonBytesTotal,
        binaryFrame: proofMaterialBinaryFrameMeasurement,
        proofMaterialProofRecordCountByShare: proofMaterials.map(
            (proofMaterial) => targetProofRecords(proofMaterial).length,
        ),
        proofMaterialTotalProofByteLengthByShare: proofMaterials.map(
            (proofMaterial) => targetProofByteLength(proofMaterial),
        ),
        proofMaterialTotalProofByteLength,
        proofMaterialProofByteBreakdownByShare,
        proofMaterialProofByteBreakdownTotal,
        proofMaterialGenerationMilliseconds,
        proofMaterialVerificationJsonBytesByShare,
        proofMaterialVerificationJsonBytesTotal:
            proofMaterialVerificationJsonBytesByShare.reduce(
                (totalBytes, verificationBytes) =>
                    totalBytes + verificationBytes,
                0,
            ),
        proofMaterialVerificationMilliseconds,
        proofMaterialBinaryVerificationJsonBytesByShare,
        proofMaterialBinaryVerificationJsonBytesTotal:
            proofMaterialBinaryVerificationJsonBytesByShare.reduce(
                (totalBytes, verificationBytes) =>
                    totalBytes + verificationBytes,
                0,
            ),
        proofMaterialBinaryVerificationMilliseconds,
        largestSingleObjectJsonBytes: Math.max(
            ...proofMaterialJsonBytesByShare,
            ...proofMaterialVerificationJsonBytesByShare,
            ...proofMaterialBinaryVerificationJsonBytesByShare,
        ),
    };

    return {
        artifacts,
        proofMaterial: proofMaterialMeasurement,
    };
};

const implementedDevelopmentArtifactByteAccounting = (
    measurement: ReturnType<typeof compactVssCommitmentMeasurement>,
    restrictedProofMeasurement: RestrictedCompactShareLinkageProofMeasurement,
    restrictedShareLinkageProofMaterialMeasurement: RestrictedCompactShareLinkageProofMaterialMeasurement,
    restrictedBridgeProofMeasurement: RestrictedCompactSameSecretBridgeProofMeasurement,
    restrictedBridgeProofMaterialMeasurement: RestrictedCompactSameSecretBridgeProofMaterialMeasurement,
    privateStateMeasurement: PrivateStateDevelopmentArtifactMeasurement,
    targetDecryptionMeasurement: TargetDecryptionDevelopmentMeasurements,
): Readonly<Record<string, unknown>> => {
    const restrictedShareLinkageProofByteLength =
        restrictedProofMeasurement.generation.lastResult.proofByteLength;
    const restrictedSameSecretBridgeProofByteLength =
        restrictedBridgeProofMeasurement.generation.lastResult.proofByteLength;
    const restrictedProofPayloadBytes =
        restrictedShareLinkageProofByteLength +
        restrictedSameSecretBridgeProofByteLength;
    const firstProfileCoverageEstimate =
        firstProfileRestrictedProofCoverageEstimate(
            restrictedProofMeasurement,
            restrictedBridgeProofMeasurement,
            restrictedBridgeProofMaterialMeasurement,
        );

    return {
        compactPublicCommitmentBodies: {
            byteLength: measurement.totalCompactPublicCommitmentBytes,
            byteReduction: measurement.byteReduction,
        },
        reducedRingProofSamples: {
            ringDegree: restrictedProofRingDegree,
            shareLinkageProofByteLength: restrictedShareLinkageProofByteLength,
            shareLinkageProofByteBreakdown:
                restrictedProofMeasurement.proofByteBreakdown,
            shareLinkageProofMaterialSet:
                restrictedShareLinkageProofMaterialMeasurement,
            sameSecretBridgeProofByteLength:
                restrictedSameSecretBridgeProofByteLength,
            combinedProofPayloadBytes: restrictedProofPayloadBytes,
            sameSecretBridgeProofMaterialJsonBytes:
                restrictedBridgeProofMaterialMeasurement.proofMaterialSetJsonBytes,
        },
        firstProfileRepeatedRestrictedProofCoverageEstimate:
            firstProfileCoverageEstimate,
        privateStateDevelopmentArtifacts: privateStateMeasurement,
        targetDecryptionDevelopmentArtifacts:
            targetDecryptionMeasurement.artifacts,
        targetDecryptionProofMaterialArtifacts:
            targetDecryptionMeasurement.proofMaterial,
    };
};

const enforceManualMeasurementBudgets = (input: {
    readonly measurement: ReturnType<typeof compactVssCommitmentMeasurement>;
    readonly restrictedProofFixture: RestrictedCompactShareLinkageProofFixture;
    readonly restrictedProofMeasurement: RestrictedCompactShareLinkageProofMeasurement;
    readonly restrictedShareLinkageProofMaterialMeasurement: RestrictedCompactShareLinkageProofMaterialMeasurement;
    readonly restrictedBridgeProofMeasurement: RestrictedCompactSameSecretBridgeProofMeasurement;
    readonly restrictedBridgeProofMaterialMeasurement: RestrictedCompactSameSecretBridgeProofMaterialMeasurement;
    readonly privateStateDevelopmentArtifactMeasurement: PrivateStateDevelopmentArtifactMeasurement;
    readonly wasmWarmGenerationExtrapolatedSeconds: number;
    readonly wasmWarmVerificationExtrapolatedSeconds: number;
    readonly targetDecryptionDevelopmentMeasurement: TargetDecryptionDevelopmentMeasurements;
}): void => {
    const privateMailbox =
        input.privateStateDevelopmentArtifactMeasurement.privateMailbox;
    const encryptedLocalState =
        input.privateStateDevelopmentArtifactMeasurement.encryptedLocalState;
    const restrictedProofPayloadBytes =
        input.restrictedProofMeasurement.generation.lastResult.proofByteLength +
        input.restrictedBridgeProofMeasurement.generation.lastResult
            .proofByteLength;

    assertAtMost(
        input.measurement.totalCompactPublicCommitmentBytes,
        input.measurement.budgetComparison.publicSetupDownloadBudgetBytes,
        'compact public commitment bodies',
    );
    assertAtMost(
        input.measurement.budgetComparison.oneSourcePublicCommitmentUploadBytes,
        input.measurement.budgetComparison.sourceTrusteeUploadBudgetBytes,
        'one source trustee public compact commitment upload body',
    );
    assertAtMost(
        input.measurement.largestSingleObjectBytes,
        input.measurement.budgetComparison.largestSingleObjectBudgetBytes,
        'largest compact public commitment body',
    );
    assertAtMost(
        input.measurement.largestWasmBoundaryCopyBytes,
        input.measurement.budgetComparison.largestWasmBoundaryCopyBudgetBytes,
        'largest compact public WASM boundary copy',
    );
    assertAtLeast(
        input.measurement.byteReduction.reductionFactor,
        minimumPublicCommitmentReductionFactor,
        'compact public commitment body reduction factor',
    );
    assertAtMost(
        input.wasmWarmGenerationExtrapolatedSeconds,
        maximumWarmWasmFullProfileGenerationSeconds,
        'WASM warm full-profile compact commitment generation extrapolation',
    );
    assertAtMost(
        input.wasmWarmVerificationExtrapolatedSeconds,
        maximumWarmWasmFullProfileVerificationSeconds,
        'WASM warm full-profile compact commitment verification extrapolation',
    );
    assertAtMost(
        input.targetDecryptionDevelopmentMeasurement.artifacts
            .largestSingleObjectJsonBytes,
        maximumMeasuredDevelopmentArtifactJsonBytes,
        'largest measured target-decryption development JSON artifact',
    );
    assertAtMost(
        privateMailbox.sourceTrusteeEnvelopeReferenceJsonBytesExtrapolatedToFirstProfile,
        maximumSourceTrusteePrivateMailboxUploadBytes,
        'one source trustee private mailbox upload references',
    );
    assertAtMost(
        privateMailbox.sourceTrusteeEnvelopeReferenceJsonBytesExtrapolatedToFirstProfile,
        maximumRecipientPrivateMailboxDownloadBytes,
        'one recipient private mailbox download references',
    );
    assertAtMost(
        input.privateStateDevelopmentArtifactMeasurement
            .largestSingleObjectJsonBytes,
        maximumMeasuredDevelopmentArtifactJsonBytes,
        'largest measured private-state JSON artifact',
    );
    assertAtMost(
        encryptedLocalState.sealedAggregateThresholdShareJsonBytes +
            encryptedLocalState.sealedTargetDecryptionProofWitnessJsonBytes +
            encryptedLocalState.encryptedLocalStateJsonBytes +
            encryptedLocalState.localStateCommitmentJsonBytes,
        maximumPersistentLocalStateBytes,
        'one recipient persistent local-state material',
    );
    assertAtMost(
        Math.max(
            privateMailbox.buildMilliseconds,
            encryptedLocalState.buildMilliseconds,
        ) / 1_000,
        maximumPrivateStateBuildSeconds,
        'private-state construction sample',
    );
    if (
        restrictedShareLinkageProofMaterialWasMeasured(
            input.restrictedShareLinkageProofMaterialMeasurement,
        )
    ) {
        assertAtMost(
            input.restrictedShareLinkageProofMaterialMeasurement
                .binaryProofMaterialTransportBytes,
            input.measurement.budgetComparison.publicSetupDownloadBudgetBytes,
            'full source compact share-linkage proof-material binary frame',
        );
    }
    assertAtMost(
        restrictedProofPayloadBytes,
        maximumRestrictedProofPayloadBytes,
        input.restrictedProofFixture.fullSourceBatch
            ? 'combined full source-batch compact proof payload'
            : 'combined reduced-ring compact proof sample payload',
    );
    assertAtMost(
        input.restrictedBridgeProofMaterialMeasurement
            .proofMaterialSetJsonBytes,
        maximumMeasuredDevelopmentArtifactJsonBytes,
        'reduced-ring compact bridge proof-material JSON sample',
    );
    if (
        targetProofMaterialWasMeasured(
            input.targetDecryptionDevelopmentMeasurement.proofMaterial,
        )
    ) {
        const proofMaterial =
            input.targetDecryptionDevelopmentMeasurement.proofMaterial;
        assertAtMost(
            proofMaterial.proofMaterialJsonBytesTotal,
            maximumTargetProofMaterialJsonBytes,
            'target-decryption proof-material JSON total',
        );
        assertAtMost(
            proofMaterial.binaryFrame.proofMaterialBinaryFrameBytesTotal,
            maximumTargetProofMaterialBinaryFrameBytes,
            'target-decryption proof-material binary frame total',
        );
        assertAtMost(
            proofMaterial.proofMaterialTotalProofByteLength,
            maximumTargetProofMaterialRawProofBytes,
            'target-decryption proof-material raw proof bytes',
        );
        assertAtMost(
            proofMaterial.proofMaterialGenerationMilliseconds / 1_000,
            maximumTargetProofMaterialGenerationSeconds,
            'target-decryption proof-material generation',
        );
        assertAtMost(
            proofMaterial.proofMaterialVerificationMilliseconds / 1_000,
            maximumTargetProofMaterialVerificationSeconds,
            'target-decryption proof-material verification',
        );
        assertAtMost(
            proofMaterial.proofMaterialBinaryVerificationMilliseconds / 1_000,
            maximumTargetProofMaterialVerificationSeconds,
            'target-decryption binary proof-material verification',
        );
    }
};

const main = async (): Promise<void> => {
    const opening = fullRingOpening();
    const measurement = compactVssCommitmentMeasurement({
        participantCount: firstProfileParticipantCount,
        sourceRnsLimbCount: acceptedBgvSetupQSharePrimes.length,
        targetRnsLimbCount,
        thresholdDegree: firstProfileThresholdDegree,
        currentFullCoefficientTransportBytes,
    });
    const typeScriptMeasurement = measureTypeScriptPath(opening);
    const kernel = await loadTranscriptCoreKernel();
    const metadata = compactCommitmentBodyMetadata(
        typeScriptMeasurement.generation.lastResult.commitment,
    );
    const wasmMeasurement = measureWasmPath(kernel, opening, metadata);
    const restrictedProofFixture = restrictedCompactShareLinkageProofFixture({
        fullSourceBatch:
            process.env.SEALED_LATTICE_MEASURE_FULL_SHARE_LINKAGE_BATCH === '1',
    });
    const restrictedProofMeasurement =
        measureRestrictedCompactShareLinkageProof(
            kernel,
            restrictedProofFixture,
        );
    const restrictedShareLinkageProofMaterialMeasurement =
        measureRestrictedCompactShareLinkageProofMaterialSet(
            kernel,
            restrictedProofFixture,
            restrictedProofMeasurement.generation,
        );
    const restrictedBridgeProofFixture =
        restrictedCompactSameSecretBridgeProofFixture();
    const restrictedBridgeProofMeasurement =
        measureRestrictedCompactSameSecretBridgeProof(
            kernel,
            restrictedBridgeProofFixture,
        );
    const restrictedBridgeProofMaterialMeasurement =
        measureRestrictedCompactSameSecretBridgeProofMaterial(
            kernel,
            restrictedBridgeProofFixture,
            restrictedBridgeProofMeasurement.generation,
        );
    const privateStateDevelopmentArtifactMeasurement =
        await measurePrivateStateDevelopmentArtifacts();
    const targetDecryptionDevelopmentArtifactMeasurement =
        measureTargetDecryptionDevelopmentArtifacts(kernel);
    if (
        typeScriptMeasurement.generation.lastResult.commitmentRoot !==
        wasmMeasurement.generation.lastResult.commitmentRoot
    ) {
        throw new Error(
            'TypeScript and WASM compact VSS commitment roots differ.',
        );
    }
    if (
        typeScriptMeasurement.bodyEncoding.lastResult.byteLength !==
            measurement.singleCompactCommitmentBytes ||
        wasmMeasurement.bodyEncoding.lastResult.commitmentBodyBytes
            .byteLength !== measurement.singleCompactCommitmentBytes
    ) {
        throw new Error(
            'compact VSS encoded commitment body length differs from the static byte accounting.',
        );
    }
    if (
        !equalBytes(
            typeScriptMeasurement.bodyEncoding.lastResult,
            wasmMeasurement.bodyEncoding.lastResult.commitmentBodyBytes,
        )
    ) {
        throw new Error(
            'TypeScript and WASM compact VSS encoded commitment bodies differ.',
        );
    }
    if (
        wasmMeasurement.bodyDecoding.lastResult.commitmentRoot !==
        typeScriptMeasurement.generation.lastResult.commitmentRoot
    ) {
        throw new Error(
            'WASM compact VSS decoded commitment root differs from the generated commitment root.',
        );
    }

    const totalCommitments =
        measurement.cpuWorkModel.sourceCoefficientCommitments +
        measurement.cpuWorkModel.recipientShareCommitments +
        measurement.cpuWorkModel.aggregateThresholdCommitments;
    const typeScriptWarmGenerationExtrapolatedSeconds = scaledSeconds(
        typeScriptMeasurement.generation.samples.warmMedianMilliseconds,
        totalCommitments,
    );
    const typeScriptWarmVerificationExtrapolatedSeconds = scaledSeconds(
        typeScriptMeasurement.verification.samples.warmMedianMilliseconds,
        totalCommitments,
    );
    const wasmWarmGenerationExtrapolatedSeconds = scaledSeconds(
        wasmMeasurement.generation.samples.warmMedianMilliseconds,
        totalCommitments,
    );
    const wasmWarmVerificationExtrapolatedSeconds = scaledSeconds(
        wasmMeasurement.verification.samples.warmMedianMilliseconds,
        totalCommitments,
    );
    try {
        enforceManualMeasurementBudgets({
            measurement,
            restrictedProofFixture,
            restrictedProofMeasurement,
            restrictedShareLinkageProofMaterialMeasurement,
            restrictedBridgeProofMeasurement,
            restrictedBridgeProofMaterialMeasurement,
            privateStateDevelopmentArtifactMeasurement,
            wasmWarmGenerationExtrapolatedSeconds,
            wasmWarmVerificationExtrapolatedSeconds,
            targetDecryptionDevelopmentMeasurement:
                targetDecryptionDevelopmentArtifactMeasurement,
        });
    } catch (error) {
        console.error(
            JSON.stringify(
                {
                    objectType: 'CompactVssManualMeasurementBudgetFailure',
                    objectVersion: 1,
                    developmentMeasurementBudgets: {
                        maximumWarmWasmFullProfileGenerationSeconds,
                        maximumWarmWasmFullProfileVerificationSeconds,
                        maximumMeasuredDevelopmentArtifactJsonBytes,
                        maximumRecipientPrivateMailboxDownloadBytes,
                        maximumSourceTrusteePrivateMailboxUploadBytes,
                        maximumPersistentLocalStateBytes,
                        maximumPrivateStateBuildSeconds,
                        maximumRestrictedProofPayloadBytes,
                        maximumTargetProofMaterialJsonBytes,
                        maximumTargetProofMaterialBinaryFrameBytes,
                        maximumTargetProofMaterialRawProofBytes,
                        maximumTargetProofMaterialGenerationSeconds,
                        maximumTargetProofMaterialVerificationSeconds,
                    },
                    wasm: {
                        generation: wasmMeasurement.generation.samples,
                        verification: wasmMeasurement.verification.samples,
                        warmGenerationExtrapolatedSeconds:
                            wasmWarmGenerationExtrapolatedSeconds,
                        warmVerificationExtrapolatedSeconds:
                            wasmWarmVerificationExtrapolatedSeconds,
                    },
                    restrictedCompactShareLinkageProof: {
                        fullSourceBatch: restrictedProofFixture.fullSourceBatch,
                        proofItemsPerRecord:
                            restrictedProofFixture.proofItemCount,
                        coefficientCommitmentCount:
                            restrictedProofMeasurement.generation.lastResult
                                .coefficientCommitmentCount,
                        coefficientWitnessColumnCount:
                            restrictedProofMeasurement.generation.lastResult
                                .coefficientWitnessColumnCount,
                        proofByteLength:
                            restrictedProofMeasurement.generation.lastResult
                                .proofByteLength,
                        proofByteBreakdown:
                            restrictedProofMeasurement.proofByteBreakdown,
                        generation:
                            restrictedProofMeasurement.generation.samples,
                        verification:
                            restrictedProofMeasurement.verification.samples,
                    },
                    restrictedCompactShareLinkageProofMaterialSet:
                        restrictedShareLinkageProofMaterialMeasurement,
                    restrictedCompactSameSecretBridgeProof: {
                        proofByteLength:
                            restrictedBridgeProofMeasurement.generation
                                .lastResult.proofByteLength,
                        generation:
                            restrictedBridgeProofMeasurement.generation.samples,
                        verification:
                            restrictedBridgeProofMeasurement.verification
                                .samples,
                    },
                    privateStateDevelopmentArtifactMeasurement,
                    targetDecryptionDevelopmentArtifactMeasurement,
                },
                null,
                2,
            ),
        );
        throw error;
    }

    console.log(
        JSON.stringify(
            {
                objectType: 'CompactVssManualMeasurementReport',
                objectVersion: 1,
                ringDegree: opening.ringDegree,
                warmRunCount,
                totalCommitments,
                developmentMeasurementBudgets: {
                    minimumPublicCommitmentReductionFactor,
                    publicSetupDownloadBudgetBytes:
                        measurement.budgetComparison
                            .publicSetupDownloadBudgetBytes,
                    sourceTrusteeUploadBudgetBytes:
                        measurement.budgetComparison
                            .sourceTrusteeUploadBudgetBytes,
                    largestSingleObjectBudgetBytes:
                        measurement.budgetComparison
                            .largestSingleObjectBudgetBytes,
                    largestWasmBoundaryCopyBudgetBytes:
                        measurement.budgetComparison
                            .largestWasmBoundaryCopyBudgetBytes,
                    maximumWarmWasmFullProfileGenerationSeconds,
                    maximumWarmWasmFullProfileVerificationSeconds,
                    maximumMeasuredDevelopmentArtifactJsonBytes,
                    maximumRecipientPrivateMailboxDownloadBytes,
                    maximumSourceTrusteePrivateMailboxUploadBytes,
                    maximumPersistentLocalStateBytes,
                    maximumPrivateStateBuildSeconds,
                    maximumRestrictedProofPayloadBytes,
                    maximumTargetProofMaterialJsonBytes,
                    maximumTargetProofMaterialBinaryFrameBytes,
                    maximumTargetProofMaterialRawProofBytes,
                    maximumTargetProofMaterialGenerationSeconds,
                    maximumTargetProofMaterialVerificationSeconds,
                },
                byteReduction: measurement.byteReduction,
                totalCompactPublicCommitmentBytes:
                    measurement.totalCompactPublicCommitmentBytes,
                currentFullCoefficientTransportBytes:
                    measurement.currentFullCoefficientTransportBytes,
                cpuWorkModel: measurement.cpuWorkModel,
                implementedDevelopmentArtifactByteAccounting:
                    implementedDevelopmentArtifactByteAccounting(
                        measurement,
                        restrictedProofMeasurement,
                        restrictedShareLinkageProofMaterialMeasurement,
                        restrictedBridgeProofMeasurement,
                        restrictedBridgeProofMaterialMeasurement,
                        privateStateDevelopmentArtifactMeasurement,
                        targetDecryptionDevelopmentArtifactMeasurement,
                    ),
                typeScript: {
                    generation: typeScriptMeasurement.generation.samples,
                    bodyEncoding: typeScriptMeasurement.bodyEncoding.samples,
                    bodyDecoding: typeScriptMeasurement.bodyDecoding.samples,
                    verification: typeScriptMeasurement.verification.samples,
                    warmGenerationExtrapolatedSeconds:
                        typeScriptWarmGenerationExtrapolatedSeconds,
                    warmVerificationExtrapolatedSeconds:
                        typeScriptWarmVerificationExtrapolatedSeconds,
                },
                wasm: {
                    generation: wasmMeasurement.generation.samples,
                    bodyEncoding: wasmMeasurement.bodyEncoding.samples,
                    bodyDecoding: wasmMeasurement.bodyDecoding.samples,
                    verification: wasmMeasurement.verification.samples,
                    warmGenerationExtrapolatedSeconds:
                        wasmWarmGenerationExtrapolatedSeconds,
                    warmVerificationExtrapolatedSeconds:
                        wasmWarmVerificationExtrapolatedSeconds,
                },
                restrictedCompactShareLinkageProof: {
                    ringDegree: restrictedProofRingDegree,
                    sourceMessageModulus: restrictedProofSourceMessageModulus,
                    fullSourceBatch: restrictedProofFixture.fullSourceBatch,
                    proofItemsPerRecord: restrictedProofFixture.proofItemCount,
                    targetRnsLimbCount,
                    coefficientCommitmentCount:
                        restrictedProofMeasurement.generation.lastResult
                            .coefficientCommitmentCount,
                    coefficientWitnessColumnCount:
                        restrictedProofMeasurement.generation.lastResult
                            .coefficientWitnessColumnCount,
                    proofByteLength:
                        restrictedProofMeasurement.generation.lastResult
                            .proofByteLength,
                    proofByteBreakdown:
                        restrictedProofMeasurement.proofByteBreakdown,
                    statementHash:
                        restrictedProofMeasurement.generation.lastResult
                            .statementHash,
                    generation: restrictedProofMeasurement.generation.samples,
                    verification:
                        restrictedProofMeasurement.verification.samples,
                },
                restrictedCompactShareLinkageProofMaterialSet:
                    restrictedShareLinkageProofMaterialWasMeasured(
                        restrictedShareLinkageProofMaterialMeasurement,
                    )
                        ? {
                              measurementMode:
                                  restrictedShareLinkageProofMaterialMeasurement.measurementMode,
                              proofMaterialSetJsonBytes:
                                  restrictedShareLinkageProofMaterialMeasurement.proofMaterialSetJsonBytes,
                              binaryProofMaterialTransportBytes:
                                  restrictedShareLinkageProofMaterialMeasurement.binaryProofMaterialTransportBytes,
                              binaryProofMaterialTransportChunkCount:
                                  restrictedShareLinkageProofMaterialMeasurement.binaryProofMaterialTransportChunkCount,
                              binaryProofMaterialTransportChunkRoot:
                                  restrictedShareLinkageProofMaterialMeasurement.binaryProofMaterialTransportChunkRoot,
                              binaryProofMaterialTransportFullObjectHash:
                                  restrictedShareLinkageProofMaterialMeasurement.binaryProofMaterialTransportFullObjectHash,
                              binaryProofMaterialTransportSavingsBytes:
                                  restrictedShareLinkageProofMaterialMeasurement.binaryProofMaterialTransportSavingsBytes,
                              binaryProofMaterialTransportPublicSetupDownloadHeadroomBytes:
                                  restrictedShareLinkageProofMaterialMeasurement.binaryProofMaterialTransportPublicSetupDownloadHeadroomBytes,
                              generatedSourceProofCount:
                                  restrictedShareLinkageProofMaterialMeasurement.generatedSourceProofCount,
                              additionalGeneratedSourceProofCount:
                                  restrictedShareLinkageProofMaterialMeasurement.additionalGeneratedSourceProofCount,
                              sourceZeroWarmGenerationMilliseconds:
                                  restrictedShareLinkageProofMaterialMeasurement.sourceZeroWarmGenerationMilliseconds,
                              additionalProofGenerationMilliseconds:
                                  restrictedShareLinkageProofMaterialMeasurement.additionalProofGenerationMilliseconds,
                              estimatedAllSourceProofGenerationMilliseconds:
                                  restrictedShareLinkageProofMaterialMeasurement.estimatedAllSourceProofGenerationMilliseconds,
                              verificationMilliseconds:
                                  restrictedShareLinkageProofMaterialMeasurement.verificationMilliseconds,
                              shareLinkageStatementRoot:
                                  restrictedShareLinkageProofMaterialMeasurement
                                      .verification.shareLinkageStatementRoot,
                              proofMaterialSetRoot:
                                  restrictedShareLinkageProofMaterialMeasurement
                                      .verification.proofMaterialSetRoot,
                              proofMaterialCount:
                                  restrictedShareLinkageProofMaterialMeasurement
                                      .verification.proofMaterialCount,
                              proofRecordCount:
                                  restrictedShareLinkageProofMaterialMeasurement
                                      .verification.proofRecordCount,
                              totalProofByteLength:
                                  restrictedShareLinkageProofMaterialMeasurement
                                      .verification.totalProofByteLength,
                              restrictedProofVerificationCount:
                                  restrictedShareLinkageProofMaterialMeasurement
                                      .verification
                                      .restrictedProofVerificationCount,
                          }
                        : restrictedShareLinkageProofMaterialMeasurement,
                restrictedCompactSameSecretBridgeProof: {
                    ringDegree: restrictedProofRingDegree,
                    targetRnsPrimes:
                        restrictedBridgeProofFixture.compactSameSecretBridge
                            .targetRnsPrimes,
                    targetRnsLimbCount:
                        restrictedBridgeProofMeasurement.generation.lastResult
                            .targetRnsLimbCount,
                    proofByteLength:
                        restrictedBridgeProofMeasurement.generation.lastResult
                            .proofByteLength,
                    statementHash:
                        restrictedBridgeProofMeasurement.generation.lastResult
                            .statementHash,
                    generation:
                        restrictedBridgeProofMeasurement.generation.samples,
                    verification:
                        restrictedBridgeProofMeasurement.verification.samples,
                },
                restrictedCompactSameSecretBridgeProofMaterial: {
                    proofMaterialSetJsonBytes:
                        restrictedBridgeProofMaterialMeasurement.proofMaterialSetJsonBytes,
                    compactSameSecretBridgeStatementSetRoot:
                        restrictedBridgeProofMaterialMeasurement.verification
                            .lastResult.compactSameSecretBridgeStatementSetRoot,
                    proofMaterialSetRoot:
                        restrictedBridgeProofMaterialMeasurement.verification
                            .lastResult.proofMaterialSetRoot,
                    proofRecordCount:
                        restrictedBridgeProofMaterialMeasurement.verification
                            .lastResult.proofRecordCount,
                    totalProofByteLength:
                        restrictedBridgeProofMaterialMeasurement.verification
                            .lastResult.totalProofByteLength,
                    proofVerificationCount:
                        restrictedBridgeProofMaterialMeasurement.verification
                            .lastResult.proofVerificationCount,
                    verification:
                        restrictedBridgeProofMaterialMeasurement.verification
                            .samples,
                },
            },
            null,
            2,
        ),
    );
};

await main();
