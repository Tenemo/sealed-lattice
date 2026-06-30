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
    compactVssMessageDigitCount,
    compactVssMessageDigitBase,
    compactVssMessageDigitTritCount,
    computeCompactVssCommitmentFromOpening,
    createCompactVssCoefficientCommitmentSet,
    createCompactVssDerivedRecipientShareCommitmentBundle,
    createCompactVssRecipientShareCommitmentBundle,
    createCompactVssShareLinkageProofMaterialSet,
    createCompactVssShareLinkageStatement,
    decodeCompactVssCommitmentBody,
    encodeCompactVssCommitmentBody,
    verifyCompactVssCommitmentOpening,
    verifyCompactVssDerivedRecipientShareCommitmentSet,
    verifyCompactVssRecipientShareCommitmentSet,
    verifyCompactVssShareLinkageProofMaterialSet,
    verifyCompactVssShareLinkageStatement,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCommitmentBodyMetadata,
    type CompactVssCommitmentOpeningInput,
    type CompactVssCommitmentValue,
    type CompactVssRecipientShareOpeningCredential,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssShareLinkageProofRecordInput,
    type CompactVssShareLinkageProofStatement,
    type CompactVssShareLinkageProofStatementItem,
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
    type SameSecretConsistencyStatementSet,
    type SameSecretProofSet,
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
    BgvTrusteeEvaluationKeyStatementContext,
    TranscriptCoreKernel,
} from '#packages/wasm/src/transcript-core-bridge.js';

const warmRunCount = 5;
const privateStateBuildRunCount = 3;
const firstProfileParticipantCount = 10;
const firstProfileThresholdDegree = 4;
const currentFullCoefficientTransportBytes = 1_604_341_697;
const targetRnsLimbCount = 7;
const canonicalTargetCiphertextLevel = targetRnsLimbCount - 1;
const selectedEvaluatorWorkingLevel = 15;
const restrictedProofRingDegree = 128;
const minimumPublicCommitmentReductionFactor = 2_800;
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
const proofSetupCommitmentLimbCount = 3;
const maximumCompactShareLinkagePublicVerificationSeconds = 10;
const targetDecryptionAggregateMessageClaimMaskDigitCount = 142;
const targetDecryptionSmudgingMessageClaimMaskDigitCount = 114;
const targetDecryptionRandomnessClaimMaskDigitCount = 114;
const targetProofMaterialMeasurementRequested =
    process.env.SEALED_LATTICE_MEASURE_TARGET_PROOF_MATERIAL === '1';
const fullShareLinkageBatchMeasurementRequested =
    process.env.SEALED_LATTICE_MEASURE_FULL_SHARE_LINKAGE_BATCH === '1';
const fullSameSecretBridgeMeasurementRequested =
    process.env.SEALED_LATTICE_MEASURE_FULL_SAME_SECRET_BRIDGE === '1';

const isPowerOfTwo = (value: number): boolean =>
    Number.isSafeInteger(value) &&
    value > 0 &&
    Number.isInteger(Math.log2(value));

type CompactVssMessageEncodingLayout = Readonly<{
    readonly highDigitTritCount: number;
    readonly encodingColumnCount: number;
    readonly totalTritCount: number;
}>;

const compactVssTritCountForBound = (
    boundExclusive: number | bigint,
): number => {
    const boundExclusiveWide =
        typeof boundExclusive === 'bigint'
            ? boundExclusive
            : Number.isSafeInteger(boundExclusive)
              ? BigInt(boundExclusive)
              : 0n;
    if (boundExclusiveWide <= 0n) {
        throw new Error('compact VSS message bound must be positive.');
    }
    let representedBound = 1n;
    let tritCount = 0;
    while (representedBound < boundExclusiveWide) {
        representedBound *= 3n;
        tritCount += 1;
    }

    return tritCount;
};

const compactVssMessageEncodingLayoutForBound = (
    messageBoundExclusive: number,
    rangeEvidence:
        | 'digit-and-trit-columns'
        | 'digit-columns-only' = 'digit-and-trit-columns',
): CompactVssMessageEncodingLayout => {
    if (
        !Number.isSafeInteger(messageBoundExclusive) ||
        messageBoundExclusive <= 0
    ) {
        throw new Error('compact VSS message bound must be positive.');
    }
    const messageBoundExclusiveWide = BigInt(messageBoundExclusive);
    const highDigitBoundExclusive =
        (messageBoundExclusiveWide + compactVssMessageDigitBase - 1n) /
        compactVssMessageDigitBase;
    const highDigitTritCount = compactVssTritCountForBound(
        highDigitBoundExclusive,
    );
    if (rangeEvidence === 'digit-columns-only') {
        return {
            highDigitTritCount,
            totalTritCount: 0,
            encodingColumnCount: compactVssMessageDigitCount,
        };
    }
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

type CompactShareLinkagePublicVerificationMeasurement = Readonly<{
    readonly proofByteLength: 0;
    readonly proofMaterialTransportBytes: 0;
    readonly verification: MeasuredOperation<
        ReturnType<typeof verifyCompactVssShareLinkageStatement>
    >;
}>;

type RestrictedCompactSameSecretBridgeProofFixture = Readonly<{
    readonly context: BgvTrusteeEvaluationKeyStatementContext;
    readonly compactSameSecretBridge: BgvCompactSameSecretBridgeProofStatement;
    readonly sameSecretConsistency: SameSecretConsistencyStatementSet;
    readonly sameSecretProofs: SameSecretProofSet;
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

type FullSameSecretBridgeProofMeasurementNotMeasured = Readonly<{
    readonly measurementMode: string;
}>;

type FullSameSecretBridgeProofMeasurementMeasured = Readonly<{
    readonly measurementMode: string;
    readonly ringDegree: number;
    readonly targetRnsLimbCount: number;
    readonly proofByteLength: number;
    readonly statementHash: ProtocolHash;
    readonly generation: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['generateCompactSameSecretBridgeProof']>
    >;
    readonly verification: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['verifyCompactSameSecretBridgeProof']>
    >;
}>;

type FullSameSecretBridgeProofMeasurement =
    | FullSameSecretBridgeProofMeasurementMeasured
    | FullSameSecretBridgeProofMeasurementNotMeasured;

const fullSameSecretBridgeProofWasMeasured = (
    measurement: FullSameSecretBridgeProofMeasurement,
): measurement is FullSameSecretBridgeProofMeasurementMeasured =>
    'proofByteLength' in measurement;

type FullShareLinkageBatchMeasurementNotMeasured = Readonly<{
    readonly measurementMode: string;
}>;

type FullShareLinkageBatchDerivedFixture = Readonly<{
    readonly setupContext: CollectiveBgvSetupContext;
    readonly publicMatrixSeedHash: ProtocolHash;
    readonly coefficientCommitmentSet: ReturnType<
        typeof createCompactVssCoefficientCommitmentSet
    >;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: CompactVssAggregateThresholdCommitmentSet;
    readonly shareLinkageStatement: CompactVssShareLinkageStatement;
    readonly sourceTrusteeOpeningStates: readonly PrivateVssSourceTrusteeContributionState[];
    readonly recipientShareOpeningCredentials: readonly CompactVssRecipientShareOpeningCredential[];
    readonly coefficientOpeningRandomness: (input: {
        readonly trusteeRosterPosition: number;
        readonly rnsLimbIndex: number;
        readonly shamirCoefficientIndex: number;
        readonly ringDegree: number;
    }) => readonly (readonly number[])[];
    readonly recipientShareOpeningCredentialCount: number;
}>;

type FullShareLinkageBatchDerivedMeasurement = Readonly<{
    readonly measurementMode: string;
    readonly participantCount: number;
    readonly targetRnsLimbCount: number;
    readonly sourceRecipientRecordCount: number;
    readonly aggregateThresholdRecordCount: number;
    readonly ringDegree: number;
    readonly oneSourceShareLinkageProofByteLength: number;
    readonly proofMaterialSetJsonBytes: number;
    readonly proofMaterialSetRoot: ProtocolHash;
    readonly oneSourcePayloadWithBridgeProofBytes: number;
    readonly repeatedAllSourceShareLinkageProofBytes: number;
    readonly repeatedAllSourcePayloadWithBridgeProofBytes: number;
    readonly coefficientCommitmentCount: number;
    readonly coefficientWitnessColumnCount: number;
    readonly recipientShareOpeningCredentialCount: number;
    readonly verification: Readonly<{
        readonly recipientShareCommitments: MeasuredOperation<
            ReturnType<typeof verifyCompactVssRecipientShareCommitmentSet>
        >;
        readonly shareLinkageStatement: MeasuredOperation<
            ReturnType<typeof verifyCompactVssShareLinkageStatement>
        >;
        readonly sourceProofGeneration: MeasuredOperation<
            ReturnType<
                TranscriptCoreKernel['generateCompactVssShareLinkageProof']
            >
        >;
        readonly sourceProofVerification: MeasuredOperation<
            ReturnType<
                TranscriptCoreKernel['verifyCompactVssShareLinkageProof']
            >
        >;
        readonly proofMaterialSet: MeasuredOperation<
            ReturnType<typeof verifyCompactVssShareLinkageProofMaterialSet>
        >;
        readonly wasmProofMaterialSet: MeasuredOperation<
            ReturnType<
                TranscriptCoreKernel['verifyCompactVssShareLinkageProofMaterialSet']
            >
        >;
    }>;
}>;

type FullShareLinkageBatchMeasurement =
    | FullShareLinkageBatchDerivedMeasurement
    | FullShareLinkageBatchMeasurementNotMeasured;

type CompactVssSourceBatchProofInput = Omit<
    Parameters<TranscriptCoreKernel['generateCompactVssShareLinkageProof']>[0],
    | 'compactVssShareLinkage'
    | 'proofRandomnessNonceHex'
    | 'proofRandomnessSeedHex'
    | 'ringDegree'
> &
    Readonly<{
        readonly sourceStatementRoot: ProtocolHash;
        readonly compactVssShareLinkage: CompactVssShareLinkageProofStatement;
    }>;

const fullShareLinkageBatchWasMeasured = (
    measurement: FullShareLinkageBatchMeasurement,
): measurement is FullShareLinkageBatchDerivedMeasurement =>
    'oneSourceShareLinkageProofByteLength' in measurement;

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
        typeof createCompactVssDerivedRecipientShareCommitmentBundle
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

const timedAsync = async <Result>(
    operation: () => Promise<Result>,
): Promise<
    Readonly<{
        readonly result: Result;
        readonly milliseconds: number;
    }>
> => {
    const startedAtMilliseconds = performance.now();
    const result = await operation();
    const milliseconds = performance.now() - startedAtMilliseconds;

    return { result, milliseconds };
};

const measureAsyncMedianResult = async <Result>(
    operation: () => Promise<Result>,
    sampleCount: number,
): Promise<
    Readonly<{
        readonly result: Result;
        readonly medianMilliseconds: number;
    }>
> => {
    if (!Number.isSafeInteger(sampleCount) || sampleCount <= 0) {
        throw new Error(
            'asynchronous measurement sample count must be positive.',
        );
    }
    const measurements: number[] = [];
    let lastResult: Result | undefined;
    for (let runIndex = 0; runIndex < sampleCount; runIndex += 1) {
        const measurement = await timedAsync(operation);
        measurements.push(measurement.milliseconds);
        lastResult = measurement.result;
    }
    if (lastResult === undefined) {
        throw new Error('asynchronous measurement did not produce a result.');
    }

    return {
        result: lastResult,
        medianMilliseconds: median(measurements),
    };
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
    ringDegree: number,
    seedOffset: number,
): readonly (readonly number[])[] =>
    Array.from(
        { length: compactVssCommitmentRandomnessColumnCount },
        (_unusedColumn, columnIndex) =>
            Array.from(
                { length: ringDegree },
                (_unusedCoefficient, coefficientIndex) =>
                    ((seedOffset + columnIndex * 5 + coefficientIndex * 7) %
                        3) -
                    1,
            ),
    );

const restrictedCompactSameSecretBridgeProofFixture = (
    ringDegree = restrictedProofRingDegree,
): RestrictedCompactSameSecretBridgeProofFixture => {
    const publicMatrixSeedHash = repeatedProtocolHash('8');
    const targetRnsPrimes = acceptedBgvSetupQSharePrimes.slice(
        0,
        targetRnsLimbCount,
    );
    const secretCoefficients = Array.from(
        { length: ringDegree },
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
            restrictedProofTernaryRandomness(
                ringDegree,
                67 + targetRnsLimbIndex,
            ),
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
                ringDegree,
                messageCoefficients,
                messageCoefficientBound: targetRnsPrime,
                randomnessByColumn: openingRandomnessByLimb[targetRnsLimbIndex],
            });
        },
    );
    const sameSecretProofFamilyBindingRoot = repeatedProtocolHash('f');
    const trusteeSecretCommitmentRoot = repeatedProtocolHash('7');
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
    const sameSecretContext = {
        ceremonyId: 'compact-same-secret-bridge-proof-measurement',
        manifestHash: repeatedProtocolHash('1'),
        rosterHash: repeatedProtocolHash('2'),
        setupProfileHash: repeatedProtocolHash('3'),
        qShareHash: repeatedProtocolHash('4'),
        carryAwareVssShareRelationProfileHash: repeatedProtocolHash('5'),
        commitmentProfileHash: repeatedProtocolHash('6'),
        setupEpoch: 'setup-epoch-1',
    } as const;
    const sameSecretStatementWithoutRoot = {
        objectType: 'SameSecretConsistencyStatement',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        ...sameSecretContext,
        trusteeIdentity: 'trustee-0',
        trusteeRosterPosition: 0,
        vssSourceTrusteeCommitmentRoot: repeatedProtocolHash('9'),
        constantCoefficientCommitmentRoots:
            targetConstantCoefficientCommitmentRoots.map(
                (targetConstantRoot) => ({
                    rnsLimbIndex: targetConstantRoot.rnsLimbIndex,
                    rnsPrime: targetConstantRoot.rnsPrime,
                    shamirCoefficientIndex: 0 as const,
                    commitmentRoot:
                        targetConstantRoot.coefficientCommitmentRoot,
                }),
            ),
        trusteeSecretCommitmentRoot,
        boundSecretDependentProofFamilies: [
            'vss-constant-relation',
            'public-key-share',
            'relinearization-key-share',
            'galois-key-share',
        ],
        sameSecretProofFamilyBindingRoot,
        sameSecretRelation,
    } as const;
    const sameSecretStatementRoot = deriveProtocolHash(
        'SameSecretConsistencyRoot',
        sameSecretStatementWithoutRoot,
    );
    const sameSecretStatementRecord = {
        ...sameSecretStatementWithoutRoot,
        sameSecretStatementRoot,
    } as const;
    const sameSecretProofRecordWithoutRoot = {
        objectType: 'SameSecretProof',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        ...sameSecretContext,
        trusteeIdentity: 'trustee-0',
        trusteeRosterPosition: 0,
        ringDegree,
        sameSecretStatementRoot,
        trusteeSecretCommitmentRoot,
        sameSecretProofFamilyBindingRoot,
        statementHash: deriveProtocolHash('SameSecretProofRoot', {
            fixture: 'same-secret-proof-statement',
        }),
        proofSizeBytes: 1,
        proofBytesHash: hash512Hex(
            'sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1',
            [Buffer.from('ab', 'hex')],
        ),
        proofBytesHex: 'ab',
    } as const;
    const sameSecretProofRoot = deriveProtocolHash(
        'SameSecretProofRoot',
        sameSecretProofRecordWithoutRoot,
    );
    const sameSecretProofRecord = {
        ...sameSecretProofRecordWithoutRoot,
        sameSecretProofRoot,
    } as const;
    const sameSecretConsistencyWithoutRoot = {
        objectType: 'SameSecretConsistencyStatementSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        ...sameSecretContext,
        participantCount: 1,
        rnsLimbCount: targetRnsPrimes.length,
        thresholdDegree: 1,
        vssCoefficientCommitmentRoot: repeatedProtocolHash('9'),
        sameSecretProofFamilyBindingRoot,
        trusteeSecretCommitmentRoots: [
            {
                trusteeIdentity: 'trustee-0',
                trusteeRosterPosition: 0,
                trusteeSecretCommitmentRoot,
            },
        ],
        statementRecords: [sameSecretStatementRecord],
    } as const;
    const sameSecretConsistency = {
        ...sameSecretConsistencyWithoutRoot,
        sameSecretConsistencyRoot: deriveProtocolHash(
            'SameSecretConsistencyRoot',
            sameSecretConsistencyWithoutRoot,
        ),
    } as SameSecretConsistencyStatementSet;
    const sameSecretProofsWithoutRoot = {
        objectType: 'SameSecretProofSet',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        commitmentProfileId: 'SealedLattice-BDLOP-Commitment-v1',
        setupProofProfileId,
        proofFamily: sameSecretProofFamily,
        proofAccountingHash: deriveProtocolHash('SameSecretProofRoot', {
            fixture: 'same-secret-proof-accounting',
        }),
        ...sameSecretContext,
        participantCount: 1,
        rnsLimbCount: targetRnsPrimes.length,
        sameSecretConsistencyRoot:
            sameSecretConsistency.sameSecretConsistencyRoot,
        sameSecretProofFamilyBindingRoot,
        vssCoefficientCommitmentMaterialRoot: repeatedProtocolHash('9'),
        sameSecretProofRoots: [
            {
                trusteeIdentity: 'trustee-0',
                trusteeRosterPosition: 0,
                sameSecretProofRoot,
            },
        ],
        proofRecords: [sameSecretProofRecord],
    } as const;
    const sameSecretProofs = {
        ...sameSecretProofsWithoutRoot,
        sameSecretProofSetRoot: deriveProtocolHash(
            'SameSecretProofRoot',
            sameSecretProofsWithoutRoot,
        ),
    } as SameSecretProofSet;
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
            carryAwareVssShareRelationProfileHash: repeatedProtocolHash('5'),
            commitmentProfileHash: repeatedProtocolHash('6'),
            setupEpoch: 'setup-epoch-1',
            targetBasisHash,
            publicMatrixSeedHash,
            ringDegree,
            trusteeIdentity: 'trustee-0',
            trusteeRosterPosition: 0,
            sameSecretStatementRoot,
            sameSecretProofRoot,
            trusteeSecretCommitmentRoot,
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
        sameSecretConsistency,
        sameSecretProofs,
        secretCoefficients,
        negativeIndicatorCoefficients,
        openingRandomnessByLimb,
    };
};

const measureSyncOperation = <Result>(
    operation: () => Result,
    warmRuns = warmRunCount,
): MeasuredOperation<Result> => {
    const cold = timed(operation);
    const warmMeasurements: number[] = [];
    let lastResult = cold.result;
    for (let runIndex = 0; runIndex < warmRuns; runIndex += 1) {
        const warm = timed(operation);
        warmMeasurements.push(warm.milliseconds);
        lastResult = warm.result;
    }

    return {
        samples: {
            coldMilliseconds: cold.milliseconds,
            warmMedianMilliseconds:
                warmMeasurements.length === 0
                    ? cold.milliseconds
                    : median(warmMeasurements),
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
            expectedOpeningRoot: generation.lastResult.openingRoot,
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
            expectedOpeningRoot: generation.lastResult.openingRoot,
        }),
    );

    return { generation, bodyEncoding, bodyDecoding, verification };
};

const measureCompactShareLinkagePublicVerification = (
    fixture: FullRingPrivateStateFixture,
): CompactShareLinkagePublicVerificationMeasurement => {
    const verification = measureSyncOperation(() => {
        const statement = verifyCompactVssShareLinkageStatement({
            statement: fixture.shareLinkageStatement,
            coefficientCommitmentSet: fixture.coefficientCommitmentSet,
            recipientShareCommitmentSet: fixture.recipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                fixture.aggregateThresholdCommitmentSet,
        });
        verifyCompactVssDerivedRecipientShareCommitmentSet({
            setupContext: fixture.setupContext,
            coefficientCommitmentSet: fixture.coefficientCommitmentSet,
            recipientShareCommitmentSet: fixture.recipientShareCommitmentSet,
            derivedRnsLimbCount: targetRnsLimbCount,
        });

        return statement;
    });

    if (
        verification.lastResult.statementRoot !==
        fixture.shareLinkageStatement.statementRoot
    ) {
        throw new Error(
            'compact share-linkage public verification returned a different statement root.',
        );
    }

    return {
        proofByteLength: 0,
        proofMaterialTransportBytes: 0,
        verification,
    };
};

const measureRestrictedCompactSameSecretBridgeProof = (
    kernel: TranscriptCoreKernel,
    fixture: RestrictedCompactSameSecretBridgeProofFixture,
    ringDegree = restrictedProofRingDegree,
): RestrictedCompactSameSecretBridgeProofMeasurement => {
    const generation = measureSyncOperation(() =>
        kernel.generateCompactSameSecretBridgeProof({
            ...fixture,
            ringDegree,
            proofRandomnessSeedHex: '12'.repeat(64),
            proofRandomnessNonceHex: '34'.repeat(64),
        }),
    );
    const verification = measureSyncOperation(() =>
        kernel.verifyCompactSameSecretBridgeProof({
            context: fixture.context,
            ringDegree,
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
    ringDegree = restrictedProofRingDegree,
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
    const sameSecretConsistencyRoot =
        fixture.sameSecretConsistency.sameSecretConsistencyRoot;
    const sameSecretProofSetRoot =
        fixture.sameSecretProofs.sameSecretProofSetRoot;
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
        ringDegree,
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
        ringDegree,
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
    ringDegree = restrictedProofRingDegree,
): RestrictedCompactSameSecretBridgeProofMaterialMeasurement => {
    const statementSet = restrictedCompactSameSecretBridgeStatementSet(
        fixture,
        ringDegree,
    );
    const proofMaterialSet = createCompactVssSameSecretBridgeProofMaterialSet({
        statementSet,
        sameSecretConsistency: fixture.sameSecretConsistency,
        sameSecretProofs: fixture.sameSecretProofs,
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
            sameSecretConsistency: fixture.sameSecretConsistency,
            sameSecretProofs: fixture.sameSecretProofs,
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

const measureFullSameSecretBridgeProof = (
    kernel: TranscriptCoreKernel,
): FullSameSecretBridgeProofMeasurement => {
    if (!fullSameSecretBridgeMeasurementRequested) {
        return {
            measurementMode:
                'Set SEALED_LATTICE_MEASURE_FULL_SAME_SECRET_BRIDGE=1 to run the accepted-ring compact same-secret bridge proof measurement.',
        };
    }

    const ringDegree = acceptedBgvProfileRingDegree;
    const fixture = restrictedCompactSameSecretBridgeProofFixture(ringDegree);
    const measurement = measureRestrictedCompactSameSecretBridgeProof(
        kernel,
        fixture,
        ringDegree,
    );

    return {
        measurementMode:
            'accepted-ring compact same-secret bridge proof measurement',
        ringDegree,
        targetRnsLimbCount:
            measurement.generation.lastResult.targetRnsLimbCount,
        proofByteLength: measurement.generation.lastResult.proofByteLength,
        statementHash: measurement.generation.lastResult.statementHash,
        generation: measurement.generation,
        verification: measurement.verification,
    };
};

const fullSameSecretBridgeProofReport = (
    measurement: FullSameSecretBridgeProofMeasurement,
): JsonRecord => {
    if (!fullSameSecretBridgeProofWasMeasured(measurement)) {
        return measurement;
    }

    return {
        measurementMode: measurement.measurementMode,
        ringDegree: measurement.ringDegree,
        targetRnsLimbCount: measurement.targetRnsLimbCount,
        proofByteLength: measurement.proofByteLength,
        statementHash: measurement.statementHash,
        generation: measurement.generation.samples,
        verification: measurement.verification.samples,
    };
};

function jsonByteLength(value: unknown): number {
    return Buffer.byteLength(
        JSON.stringify(value, (_key, entry: unknown) =>
            typeof entry === 'bigint' ? entry.toString() : entry,
        ),
        'utf8',
    );
}

function measurementHash(label: string): ProtocolHash {
    return deriveProtocolHash('SetupProofRecordBindingHash', {
        objectType: 'CompactVssManualMeasurementReference',
        objectVersion: 1,
        label,
    });
}

function measurementSetupContext(): CollectiveBgvSetupContext {
    return {
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
    };
}

function deterministicResidueVectorForRingDegree(
    rnsPrime: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    ringDegree: number,
): readonly number[] {
    const modulus = BigInt(rnsPrime);
    const limbOffset = BigInt(101 + rnsLimbIndex * 4_099);
    const coefficientOffset = BigInt(1_009 + shamirCoefficientIndex * 8_191);

    return Array.from({ length: ringDegree }, (_unused, coefficientIndex) => {
        const residue =
            (BigInt(coefficientIndex + 1) * 65_537n +
                limbOffset +
                coefficientOffset) %
            modulus;

        return Number((modulus - 1n - residue) % modulus);
    });
}

function deterministicRandomnessColumns(
    seedOffset: number,
    ringDegree: number,
): readonly (readonly number[])[] {
    return Array.from(
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
}

const restrictedFirstProfileSourceTrusteeState = (
    setupContext: CollectiveBgvSetupContext,
    publicMatrixSeedHash: ProtocolHash,
    sourceTrusteeRosterPosition: number,
    ringDegree: number,
): PrivateVssSourceTrusteeContributionState => {
    const sourceTrusteeIdentity = `trustee-${String(
        sourceTrusteeRosterPosition,
    )}`;
    const coefficientOpenings = acceptedBgvSetupQSharePrimes.flatMap(
        (rnsPrime, rnsLimbIndex) =>
            Array.from(
                { length: firstProfileThresholdDegree },
                (_unused, shamirCoefficientIndex) => {
                    const commitmentRoot = measurementHash(
                        `derived-source-coefficient-${String(
                            sourceTrusteeRosterPosition,
                        )}-${String(rnsLimbIndex)}-${String(
                            shamirCoefficientIndex,
                        )}`,
                    );

                    return {
                        rnsLimbIndex,
                        rnsPrime,
                        shamirCoefficientIndex,
                        commitmentRoot,
                        coefficientMessage:
                            deterministicResidueVectorForRingDegree(
                                rnsPrime,
                                rnsLimbIndex,
                                shamirCoefficientIndex +
                                    sourceTrusteeRosterPosition *
                                        firstProfileThresholdDegree,
                                ringDegree,
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

    return {
        sourceTrusteeIdentity,
        sourceTrusteeRosterPosition,
        sourceTrusteeCommitmentRoot,
        sourceTrusteeCoefficientCommitmentRecord: {
            ...sourceTrusteeRecordWithoutRoot,
            sourceTrusteeCommitmentRoot,
        },
        sourceTrusteeCoefficientCommitmentMaterialRecords: [],
        coefficientOpenings,
    };
};

const fullShareLinkageBatchDerivedFixture =
    (): FullShareLinkageBatchDerivedFixture => {
        const setupContext = measurementSetupContext();
        const publicMatrixSeedHash = measurementHash(
            'full-share-linkage-derived-public-matrix-seed',
        );
        const recipientTrustees = Array.from(
            { length: firstProfileParticipantCount },
            (_unused, trusteeRosterPosition) => ({
                trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
                trusteeRosterPosition,
            }),
        );
        const sourceTrusteeOpeningStates = recipientTrustees.map((trustee) =>
            restrictedFirstProfileSourceTrusteeState(
                setupContext,
                publicMatrixSeedHash,
                trustee.trusteeRosterPosition,
                restrictedProofRingDegree,
            ),
        );
        const proofRnsPrimes = acceptedBgvSetupQSharePrimes.slice(
            0,
            targetRnsLimbCount,
        );
        const coefficientOpeningRandomness = ({
            trusteeRosterPosition,
            rnsLimbIndex,
            shamirCoefficientIndex,
            ringDegree,
        }: {
            readonly trusteeRosterPosition: number;
            readonly rnsLimbIndex: number;
            readonly shamirCoefficientIndex: number;
            readonly ringDegree: number;
        }): readonly (readonly number[])[] =>
            deterministicRandomnessColumns(
                3 +
                    trusteeRosterPosition * 10_007 +
                    rnsLimbIndex * 43 +
                    shamirCoefficientIndex * 271,
                ringDegree,
            );
        const coefficientCommitmentSet =
            createCompactVssCoefficientCommitmentSet({
                setupContext,
                publicMatrixSeedHash,
                participantCount: firstProfileParticipantCount,
                qSharePrimes: proofRnsPrimes,
                ringDegree: restrictedProofRingDegree,
                thresholdDegree: firstProfileThresholdDegree,
                sourceTrusteeOpeningStates,
                coefficientOpeningRandomness,
            });
        const recipientShareBundle =
            createCompactVssRecipientShareCommitmentBundle({
                setupContext,
                publicMatrixSeedHash,
                participantCount: firstProfileParticipantCount,
                qSharePrimes: proofRnsPrimes,
                ringDegree: restrictedProofRingDegree,
                thresholdDegree: firstProfileThresholdDegree,
                coefficientCommitmentSet,
                sourceTrusteeOpeningStates,
                recipientTrustees,
                coefficientOpeningRandomness,
            });
        const aggregateBundle = aggregateCompactVssThresholdShareCommitments({
            setupContext,
            publicMatrixSeedHash,
            participantCount: firstProfileParticipantCount,
            qSharePrimes: proofRnsPrimes,
            ringDegree: restrictedProofRingDegree,
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

        return {
            setupContext,
            publicMatrixSeedHash,
            coefficientCommitmentSet,
            recipientShareCommitmentSet:
                recipientShareBundle.recipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                aggregateBundle.aggregateThresholdCommitmentSet,
            shareLinkageStatement,
            sourceTrusteeOpeningStates,
            recipientShareOpeningCredentials:
                recipientShareBundle.recipientShareOpeningCredentials,
            coefficientOpeningRandomness,
            recipientShareOpeningCredentialCount:
                recipientShareBundle.recipientShareOpeningCredentials.length,
        };
    };

const compactVssShareLinkageCredentialForItem = (
    fixture: FullShareLinkageBatchDerivedFixture,
    sourceTrusteeRosterPosition: number,
    recipientRosterPosition: number,
    sourceRnsLimbIndex: number,
): CompactVssRecipientShareOpeningCredential => {
    const credential = fixture.recipientShareOpeningCredentials.find(
        (candidate) =>
            candidate.sourceTrusteeRosterPosition ===
                sourceTrusteeRosterPosition &&
            candidate.recipientRosterPosition === recipientRosterPosition &&
            candidate.rnsLimbIndex === sourceRnsLimbIndex,
    );
    if (credential === undefined) {
        throw new Error(
            'compact share-linkage measurement fixture is missing a recipient-share opening credential.',
        );
    }

    return credential;
};

const compactVssShareLinkageProofItemForCredential = (
    fixture: FullShareLinkageBatchDerivedFixture,
    credential: CompactVssRecipientShareOpeningCredential,
): CompactVssShareLinkageProofStatementItem => {
    const coefficientSourceRecord =
        fixture.coefficientCommitmentSet.sourceTrusteeRecords[
            credential.sourceTrusteeRosterPosition
        ];
    const recipientSourceRecord =
        fixture.recipientShareCommitmentSet.sourceTrusteeRecords[
            credential.sourceTrusteeRosterPosition
        ];
    if (
        coefficientSourceRecord === undefined ||
        recipientSourceRecord === undefined
    ) {
        throw new Error(
            'compact share-linkage measurement fixture is missing source records.',
        );
    }
    const coefficientStart =
        credential.rnsLimbIndex * firstProfileThresholdDegree;
    const coefficientRecords =
        coefficientSourceRecord.coefficientCommitments.slice(
            coefficientStart,
            coefficientStart + firstProfileThresholdDegree,
        );
    if (coefficientRecords.length !== firstProfileThresholdDegree) {
        throw new Error(
            'compact share-linkage measurement fixture is missing coefficient records.',
        );
    }
    const recipientRecordIndex =
        credential.recipientRosterPosition * targetRnsLimbCount +
        credential.rnsLimbIndex;
    const recipientRecord =
        recipientSourceRecord.recipientShareCommitments[recipientRecordIndex];
    if (recipientRecord === undefined) {
        throw new Error(
            'compact share-linkage measurement fixture is missing a recipient-share record.',
        );
    }

    return {
        recipientIdentity: credential.recipientIdentity,
        recipientRosterPosition: credential.recipientRosterPosition,
        sourceRnsLimbIndex: credential.rnsLimbIndex,
        sourceMessageModulus: credential.rnsPrime,
        coefficientCommitmentRoots: coefficientRecords.map(
            (record) => record.coefficientCommitmentRoot,
        ),
        coefficientOpeningRoots: coefficientRecords.map(
            (record) => record.coefficientOpeningRoot,
        ),
        coefficientCommitments: coefficientRecords.map(
            (record) => record.commitment,
        ),
        recipientShareCommitmentRoot: recipientRecord.shareCommitmentRoot,
        recipientShareOpeningRoot: recipientRecord.shareOpeningRoot,
        recipientShareCommitment: recipientRecord.commitment,
    };
};

const compactVssSourceBatchProofInput = (
    fixture: FullShareLinkageBatchDerivedFixture,
    sourceTrusteeRosterPosition: number,
): CompactVssSourceBatchProofInput => {
    const sourceStatement =
        fixture.shareLinkageStatement.sourceStatementRecords[
            sourceTrusteeRosterPosition
        ];
    const sourceState =
        fixture.sourceTrusteeOpeningStates[sourceTrusteeRosterPosition];
    if (sourceStatement === undefined || sourceState === undefined) {
        throw new Error(
            'compact share-linkage source-batch fixture is missing a source statement.',
        );
    }
    const credentials = Array.from(
        { length: firstProfileParticipantCount },
        (_unusedRecipient, recipientRosterPosition) =>
            Array.from(
                { length: targetRnsLimbCount },
                (_unusedLimb, sourceRnsLimbIndex) =>
                    compactVssShareLinkageCredentialForItem(
                        fixture,
                        sourceTrusteeRosterPosition,
                        recipientRosterPosition,
                        sourceRnsLimbIndex,
                    ),
            ),
    ).flat();
    const proofItems = credentials.map((credential) =>
        compactVssShareLinkageProofItemForCredential(fixture, credential),
    );
    const primaryProofItem = proofItems[0];
    if (primaryProofItem === undefined) {
        throw new Error(
            'compact share-linkage source-batch fixture has no proof items.',
        );
    }
    const compactVssShareLinkage: CompactVssShareLinkageProofStatement = {
        publicMatrixSeedHash: fixture.publicMatrixSeedHash,
        sourceTrusteeIdentity: sourceStatement.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition,
        sourceCoefficientCommitmentRoot:
            sourceStatement.sourceCoefficientCommitmentRoot,
        sourceRecipientShareCommitmentRoot:
            sourceStatement.sourceRecipientShareCommitmentRoot,
        ...primaryProofItem,
        additionalLinkageItems: proofItems.slice(1),
    };
    const coefficientMessagesByShamirIndex: number[][] = [];
    const coefficientOpeningRandomnessByShamirIndex: number[][][] = [];
    const seenCoefficientOpenings = new Set<string>();
    proofItems.forEach((proofItem) => {
        proofItem.coefficientOpeningRoots.forEach(
            (coefficientOpeningRoot, shamirCoefficientIndex) => {
                const key = [
                    proofItem.sourceRnsLimbIndex,
                    shamirCoefficientIndex,
                    coefficientOpeningRoot,
                ].join(':');
                if (seenCoefficientOpenings.has(key)) {
                    return;
                }
                seenCoefficientOpenings.add(key);
                const coefficientOpening = sourceState.coefficientOpenings.find(
                    (candidate) =>
                        candidate.rnsLimbIndex ===
                            proofItem.sourceRnsLimbIndex &&
                        candidate.shamirCoefficientIndex ===
                            shamirCoefficientIndex,
                );
                if (coefficientOpening === undefined) {
                    throw new Error(
                        'compact share-linkage source-batch fixture is missing coefficient opening witness material.',
                    );
                }
                coefficientMessagesByShamirIndex.push([
                    ...coefficientOpening.coefficientMessage,
                ]);
                coefficientOpeningRandomnessByShamirIndex.push(
                    fixture
                        .coefficientOpeningRandomness({
                            trusteeRosterPosition: sourceTrusteeRosterPosition,
                            rnsLimbIndex: proofItem.sourceRnsLimbIndex,
                            shamirCoefficientIndex,
                            ringDegree: restrictedProofRingDegree,
                        })
                        .map((column) => [...column]),
                );
            },
        );
    });
    const recipientShareMessagesByItem = credentials.map((credential) => [
        ...credential.shareValues,
    ]);
    const recipientShareOpeningRandomnessByItem = credentials.map(
        (credential) =>
            credential.randomnessByColumn.map((column) => [...column]),
    );
    const carryWitnessesByItem = credentials.map((credential) => [
        ...credential.shareCommitmentMessageCarryValues,
    ]);
    const primaryCredential = credentials[0];
    if (primaryCredential === undefined) {
        throw new Error(
            'compact share-linkage source-batch fixture is missing the primary credential.',
        );
    }

    return {
        context: {
            ceremonyId: sourceStatement.ceremonyId,
            manifestHash: sourceStatement.manifestHash,
            rosterHash: sourceStatement.rosterHash,
            trusteeIdentity: sourceStatement.sourceTrusteeIdentity,
            trusteeRosterPosition: sourceTrusteeRosterPosition,
            setupEpoch: sourceStatement.setupEpoch,
            sourceCoefficientCommitmentRoot:
                sourceStatement.sourceCoefficientCommitmentRoot,
            sourceRecipientShareCommitmentRoot:
                sourceStatement.sourceRecipientShareCommitmentRoot,
        },
        compactVssShareLinkage,
        coefficientMessagesByShamirIndex,
        recipientShareMessages: [...primaryCredential.shareValues],
        coefficientOpeningRandomnessByShamirIndex,
        recipientShareOpeningRandomness:
            primaryCredential.randomnessByColumn.map((column) => [...column]),
        carryWitnesses: [
            ...primaryCredential.shareCommitmentMessageCarryValues,
        ],
        recipientShareMessagesByItem,
        recipientShareOpeningRandomnessByItem,
        carryWitnessesByItem,
        sourceStatementRoot: sourceStatement.sourceStatementRoot,
    };
};

const measureFullShareLinkageBatchDerived = (
    kernel: TranscriptCoreKernel,
    bridgeProofByteLength: number,
): FullShareLinkageBatchMeasurement => {
    void kernel;
    if (!fullShareLinkageBatchMeasurementRequested) {
        return {
            measurementMode:
                'Set SEALED_LATTICE_MEASURE_FULL_SHARE_LINKAGE_BATCH=1 to run the restricted-ring compact linkage proof-material measurement.',
        };
    }

    const fixture = fullShareLinkageBatchDerivedFixture();
    const recipientShareCommitments = measureSyncOperation(() =>
        verifyCompactVssRecipientShareCommitmentSet({
            recipientShareCommitmentSet: fixture.recipientShareCommitmentSet,
        }),
    );
    const shareLinkageStatement = measureSyncOperation(() =>
        verifyCompactVssShareLinkageStatement({
            statement: fixture.shareLinkageStatement,
            coefficientCommitmentSet: fixture.coefficientCommitmentSet,
            recipientShareCommitmentSet: fixture.recipientShareCommitmentSet,
            aggregateThresholdCommitmentSet:
                fixture.aggregateThresholdCommitmentSet,
        }),
    );
    if (
        shareLinkageStatement.lastResult.shareLinkageStatementRoot !==
        fixture.shareLinkageStatement.shareLinkageStatementRoot
    ) {
        throw new Error(
            'compact linkage statement root differs after verification.',
        );
    }
    const sourceZeroProofInput = compactVssSourceBatchProofInput(fixture, 0);
    const sourceZeroProofGeneration = measureSyncOperation(() =>
        kernel.generateCompactVssShareLinkageProof({
            ...sourceZeroProofInput,
            ringDegree: restrictedProofRingDegree,
            proofRandomnessSeedHex: '56'.repeat(64),
            proofRandomnessNonceHex: '78'.repeat(64),
        }),
    );
    const sourceZeroProofVerification = measureSyncOperation(() =>
        kernel.verifyCompactVssShareLinkageProof({
            context: sourceZeroProofInput.context,
            ringDegree: restrictedProofRingDegree,
            compactVssShareLinkage: sourceZeroProofInput.compactVssShareLinkage,
            proofBytesHex: sourceZeroProofGeneration.lastResult.proofBytesHex,
        }),
    );
    if (
        sourceZeroProofGeneration.lastResult.statementHash !==
        sourceZeroProofVerification.lastResult.statementHash
    ) {
        throw new Error(
            'compact linkage source-batch proof statement hashes differ.',
        );
    }
    const proofRecordInputs: CompactVssShareLinkageProofRecordInput[] = [
        {
            sourceStatementRoot: sourceZeroProofInput.sourceStatementRoot,
            compactVssShareLinkage: sourceZeroProofInput.compactVssShareLinkage,
            proofBytesHex: sourceZeroProofGeneration.lastResult.proofBytesHex,
        },
    ];
    for (
        let sourceTrusteeRosterPosition = 1;
        sourceTrusteeRosterPosition < firstProfileParticipantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        const sourceProofInput = compactVssSourceBatchProofInput(
            fixture,
            sourceTrusteeRosterPosition,
        );
        const sourceProofGeneration =
            kernel.generateCompactVssShareLinkageProof({
                ...sourceProofInput,
                ringDegree: restrictedProofRingDegree,
                proofRandomnessSeedHex: '56'.repeat(64),
                proofRandomnessNonceHex: '78'.repeat(64),
            });
        proofRecordInputs.push({
            sourceStatementRoot: sourceProofInput.sourceStatementRoot,
            compactVssShareLinkage: sourceProofInput.compactVssShareLinkage,
            proofBytesHex: sourceProofGeneration.proofBytesHex,
        });
    }
    const proofMaterialSet = createCompactVssShareLinkageProofMaterialSet({
        statement: fixture.shareLinkageStatement,
        coefficientCommitmentSet: fixture.coefficientCommitmentSet,
        recipientShareCommitmentSet: fixture.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet:
            fixture.aggregateThresholdCommitmentSet,
        ringDegree: restrictedProofRingDegree,
        proofRecordInputs,
    });
    const proofMaterialSetJsonBytes = jsonByteLength(proofMaterialSet);
    const proofMaterialSetVerification = measureSyncOperation(
        () =>
            verifyCompactVssShareLinkageProofMaterialSet({
                statement: fixture.shareLinkageStatement,
                coefficientCommitmentSet: fixture.coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    fixture.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    fixture.aggregateThresholdCommitmentSet,
                proofMaterialSet,
            }),
        0,
    );
    const wasmProofMaterialSetVerification = measureSyncOperation(
        () =>
            kernel.verifyCompactVssShareLinkageProofMaterialSet({
                statement: fixture.shareLinkageStatement,
                coefficientCommitmentSet: fixture.coefficientCommitmentSet,
                recipientShareCommitmentSet:
                    fixture.recipientShareCommitmentSet,
                aggregateThresholdCommitmentSet:
                    fixture.aggregateThresholdCommitmentSet,
                proofMaterialSet,
            }),
        0,
    );
    const oneSourceShareLinkageProofByteLength =
        sourceZeroProofGeneration.lastResult.proofByteLength;
    const oneSourcePayloadWithBridgeProofBytes =
        oneSourceShareLinkageProofByteLength + bridgeProofByteLength;
    const sourceRecipientRecordCount =
        firstProfileParticipantCount *
        firstProfileParticipantCount *
        targetRnsLimbCount;

    return {
        measurementMode:
            'restricted-ring compact linkage proof-material measurement',
        participantCount: firstProfileParticipantCount,
        targetRnsLimbCount,
        sourceRecipientRecordCount,
        aggregateThresholdRecordCount:
            firstProfileParticipantCount * targetRnsLimbCount,
        ringDegree: restrictedProofRingDegree,
        oneSourceShareLinkageProofByteLength,
        proofMaterialSetJsonBytes,
        proofMaterialSetRoot: proofMaterialSet.proofMaterialSetRoot,
        oneSourcePayloadWithBridgeProofBytes,
        repeatedAllSourceShareLinkageProofBytes:
            wasmProofMaterialSetVerification.lastResult.totalProofByteLength,
        repeatedAllSourcePayloadWithBridgeProofBytes:
            wasmProofMaterialSetVerification.lastResult.totalProofByteLength +
            bridgeProofByteLength,
        coefficientCommitmentCount:
            fixture.coefficientCommitmentSet.sourceTrusteeRecords.reduce(
                (totalCount, sourceRecord) =>
                    totalCount + sourceRecord.coefficientCommitments.length,
                0,
            ),
        coefficientWitnessColumnCount:
            sourceZeroProofGeneration.lastResult.coefficientWitnessColumnCount,
        recipientShareOpeningCredentialCount:
            fixture.recipientShareOpeningCredentialCount,
        verification: {
            recipientShareCommitments,
            shareLinkageStatement,
            sourceProofGeneration: sourceZeroProofGeneration,
            sourceProofVerification: sourceZeroProofVerification,
            proofMaterialSet: proofMaterialSetVerification,
            wasmProofMaterialSet: wasmProofMaterialSetVerification,
        },
    };
};

const fullShareLinkageBatchReport = (
    measurement: FullShareLinkageBatchMeasurement,
): JsonRecord => {
    if (!fullShareLinkageBatchWasMeasured(measurement)) {
        return measurement;
    }

    return {
        measurementMode: measurement.measurementMode,
        participantCount: measurement.participantCount,
        targetRnsLimbCount: measurement.targetRnsLimbCount,
        sourceRecipientRecordCount: measurement.sourceRecipientRecordCount,
        aggregateThresholdRecordCount:
            measurement.aggregateThresholdRecordCount,
        ringDegree: measurement.ringDegree,
        oneSourceShareLinkageProofByteLength:
            measurement.oneSourceShareLinkageProofByteLength,
        proofMaterialSetJsonBytes: measurement.proofMaterialSetJsonBytes,
        proofMaterialSetRoot: measurement.proofMaterialSetRoot,
        oneSourcePayloadWithBridgeProofBytes:
            measurement.oneSourcePayloadWithBridgeProofBytes,
        repeatedAllSourceShareLinkageProofBytes:
            measurement.repeatedAllSourceShareLinkageProofBytes,
        repeatedAllSourcePayloadWithBridgeProofBytes:
            measurement.repeatedAllSourcePayloadWithBridgeProofBytes,
        coefficientCommitmentCount: measurement.coefficientCommitmentCount,
        coefficientWitnessColumnCount:
            measurement.coefficientWitnessColumnCount,
        recipientShareOpeningCredentialCount:
            measurement.recipientShareOpeningCredentialCount,
        statementRoot:
            measurement.verification.shareLinkageStatement.lastResult
                .shareLinkageStatementRoot,
        verification: {
            recipientShareCommitments:
                measurement.verification.recipientShareCommitments.samples,
            shareLinkageStatement:
                measurement.verification.shareLinkageStatement.samples,
            sourceProofGeneration:
                measurement.verification.sourceProofGeneration.samples,
            sourceProofVerification:
                measurement.verification.sourceProofVerification.samples,
            proofMaterialSet: measurement.verification.proofMaterialSet.samples,
            wasmProofMaterialSet:
                measurement.verification.wasmProofMaterialSet.samples,
            coveredLinkageItemCount:
                measurement.verification.wasmProofMaterialSet.lastResult
                    .coveredLinkageItemCount,
            proofVerificationCount:
                measurement.verification.wasmProofMaterialSet.lastResult
                    .proofVerificationCount,
            totalProofByteLength:
                measurement.verification.wasmProofMaterialSet.lastResult
                    .totalProofByteLength,
        },
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
    const localMessageDigitVectorCount =
        localMessageGlobalIndices.length * compactVssMessageDigitCount;
    if (vectorIndex < localMessageDigitVectorCount) {
        const localMessageIndex = Math.floor(
            vectorIndex / compactVssMessageDigitCount,
        );
        const globalMessageIndex = localMessageGlobalIndices[localMessageIndex];
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
                compactVssMessageEncodingLayoutForBound(
                    messageBound,
                    'digit-columns-only',
                ).encodingColumnCount
            );
        },
        0,
    );
    const logicalColumnCount =
        messageEncodingColumnCount + randomnessColumnCount;
    const claimVectorCount =
        localMessageGlobalIndices.length * compactVssMessageDigitCount +
        randomnessColumnCount;
    const claimCount = claimVectorCount * proofConsistencyRepetitions;
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
    if (formatMarker !== 'BGVPRF19') {
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

const deterministicResidueVector = (
    rnsPrime: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): readonly number[] =>
    deterministicResidueVectorForRingDegree(
        rnsPrime,
        rnsLimbIndex,
        shamirCoefficientIndex,
        acceptedBgvProfileRingDegree,
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
    const coefficientOpeningRandomness = ({
        rnsLimbIndex,
        shamirCoefficientIndex,
        ringDegree,
    }: {
        readonly rnsLimbIndex: number;
        readonly shamirCoefficientIndex: number;
        readonly ringDegree: number;
    }): readonly (readonly number[])[] =>
        deterministicRandomnessColumns(
            3 + rnsLimbIndex * 43 + shamirCoefficientIndex * 271,
            ringDegree,
        );
    const coefficientCommitmentSet = createCompactVssCoefficientCommitmentSet({
        setupContext,
        publicMatrixSeedHash,
        participantCount: 1,
        qSharePrimes: acceptedBgvSetupQSharePrimes,
        ringDegree: acceptedBgvProfileRingDegree,
        thresholdDegree: firstProfileThresholdDegree,
        sourceTrusteeOpeningStates: [sourceState],
        coefficientOpeningRandomness,
    });
    const recipientShareBundle =
        createCompactVssDerivedRecipientShareCommitmentBundle({
            setupContext,
            publicMatrixSeedHash,
            participantCount: 1,
            qSharePrimes: acceptedBgvSetupQSharePrimes,
            ringDegree: acceptedBgvProfileRingDegree,
            thresholdDegree: firstProfileThresholdDegree,
            derivedRnsLimbCount: targetRnsLimbCount,
            coefficientCommitmentSet,
            sourceTrusteeOpeningStates: [sourceState],
            recipientTrustees,
            coefficientOpeningRandomness,
        });
    const aggregateBundle = aggregateCompactVssThresholdShareCommitments({
        setupContext,
        publicMatrixSeedHash,
        participantCount: 1,
        qSharePrimes: acceptedBgvSetupQSharePrimes.slice(0, targetRnsLimbCount),
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
    const compactRecipientShareOpeningCredentials =
        recipientShareBundle.recipientShareOpeningCredentials.filter(
            (credential) => credential.rnsLimbIndex < targetRnsLimbCount,
        );

    return {
        setupContext,
        publicMatrixSeedHash,
        vssCoefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        sourceTrusteeContributionState: sourceState,
        recipientTrustees,
        mailboxPublicKeyBytesHex: mailboxKeyPair.publicKeyBytesHex,
        compactRecipientShareOpeningCredentials,
        compactRecipientShareOpeningCredentialsJsonBytes: jsonByteLength(
            compactRecipientShareOpeningCredentials,
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
            coefficientCommitmentSet: fixture.coefficientCommitmentSet,
            recipientShareCommitmentSet: fixture.recipientShareCommitmentSet,
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

const measurePrivateStateDevelopmentArtifacts = async (
    fixture: FullRingPrivateStateFixture,
): Promise<PrivateStateDevelopmentArtifactMeasurement> => {
    const mailboxMeasurement = await measureAsyncMedianResult(async () => {
        const observedPrivateEnvelopes: JsonRecord[] = [];
        const observedTransportedProofMaterials: JsonRecord[] = [];
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

        return {
            deliverySet,
            observedPrivateEnvelopes,
            observedTransportedProofMaterials,
        };
    }, privateStateBuildRunCount);
    const {
        deliverySet,
        observedPrivateEnvelopes,
        observedTransportedProofMaterials,
    } = mailboxMeasurement.result;
    const mailboxBuildMilliseconds = mailboxMeasurement.medianMilliseconds;
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
            fixture.compactRecipientShareOpeningCredentials.length,
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
    const localStateMeasurement = await measureAsyncMedianResult(
        () =>
            createEncryptedLocalTrusteeSetupStateFromVerifiedShares(
                localStateInput,
            ),
        privateStateBuildRunCount,
    );
    const localState = localStateMeasurement.result;
    const localStateBuildMilliseconds =
        localStateMeasurement.medianMilliseconds;
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
    compactShareLinkagePublicVerification: CompactShareLinkagePublicVerificationMeasurement,
    fullShareLinkageBatchMeasurement: FullShareLinkageBatchMeasurement,
    restrictedBridgeProofMeasurement: RestrictedCompactSameSecretBridgeProofMeasurement,
    restrictedBridgeProofMaterialMeasurement: RestrictedCompactSameSecretBridgeProofMaterialMeasurement,
    fullSameSecretBridgeProofMeasurement: FullSameSecretBridgeProofMeasurement,
    privateStateMeasurement: PrivateStateDevelopmentArtifactMeasurement,
    targetDecryptionMeasurement: TargetDecryptionDevelopmentMeasurements,
): Readonly<Record<string, unknown>> => {
    const restrictedSameSecretBridgeProofByteLength =
        restrictedBridgeProofMeasurement.generation.lastResult.proofByteLength;

    return {
        compactPublicCommitmentBodies: {
            byteLength: measurement.totalCompactPublicCommitmentBytes,
            byteReduction: measurement.byteReduction,
        },
        compactShareLinkagePublicVerification: {
            proofByteLength:
                compactShareLinkagePublicVerification.proofByteLength,
            proofMaterialTransportBytes:
                compactShareLinkagePublicVerification.proofMaterialTransportBytes,
            verification:
                compactShareLinkagePublicVerification.verification.samples,
            statementRoot:
                compactShareLinkagePublicVerification.verification.lastResult
                    .statementRoot,
        },
        compactShareLinkageSourceBatchProof: fullShareLinkageBatchReport(
            fullShareLinkageBatchMeasurement,
        ),
        reducedRingBridgeProofSample: {
            ringDegree: restrictedProofRingDegree,
            sameSecretBridgeProofByteLength:
                restrictedSameSecretBridgeProofByteLength,
            sameSecretBridgeProofMaterialJsonBytes:
                restrictedBridgeProofMaterialMeasurement.proofMaterialSetJsonBytes,
        },
        targetReadySameSecretBridgeProof: fullSameSecretBridgeProofReport(
            fullSameSecretBridgeProofMeasurement,
        ),
        privateStateDevelopmentArtifacts: privateStateMeasurement,
        targetDecryptionDevelopmentArtifacts:
            targetDecryptionMeasurement.artifacts,
        targetDecryptionProofMaterialArtifacts:
            targetDecryptionMeasurement.proofMaterial,
    };
};

const enforceManualMeasurementBudgets = (input: {
    readonly measurement: ReturnType<typeof compactVssCommitmentMeasurement>;
    readonly compactShareLinkagePublicVerification: CompactShareLinkagePublicVerificationMeasurement;
    readonly fullShareLinkageBatchMeasurement: FullShareLinkageBatchMeasurement;
    readonly restrictedBridgeProofMeasurement: RestrictedCompactSameSecretBridgeProofMeasurement;
    readonly restrictedBridgeProofMaterialMeasurement: RestrictedCompactSameSecretBridgeProofMaterialMeasurement;
    readonly fullSameSecretBridgeProofMeasurement: FullSameSecretBridgeProofMeasurement;
    readonly privateStateDevelopmentArtifactMeasurement: PrivateStateDevelopmentArtifactMeasurement;
    readonly wasmWarmGenerationExtrapolatedSeconds: number;
    readonly wasmWarmVerificationExtrapolatedSeconds: number;
    readonly targetDecryptionDevelopmentMeasurement: TargetDecryptionDevelopmentMeasurements;
}): void => {
    const privateMailbox =
        input.privateStateDevelopmentArtifactMeasurement.privateMailbox;
    const encryptedLocalState =
        input.privateStateDevelopmentArtifactMeasurement.encryptedLocalState;
    const bridgeProofPayloadBytes =
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
        input.compactShareLinkagePublicVerification.verification.samples
            .warmMedianMilliseconds / 1_000,
        maximumCompactShareLinkagePublicVerificationSeconds,
        'compact share-linkage public verification',
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
    assertAtMost(
        bridgeProofPayloadBytes,
        maximumRestrictedProofPayloadBytes,
        'reduced-ring compact same-secret bridge proof sample payload',
    );
    assertAtMost(
        input.restrictedBridgeProofMaterialMeasurement
            .proofMaterialSetJsonBytes,
        maximumMeasuredDevelopmentArtifactJsonBytes,
        'reduced-ring compact bridge proof-material JSON sample',
    );
    if (
        fullShareLinkageBatchWasMeasured(input.fullShareLinkageBatchMeasurement)
    ) {
        assertAtMost(
            input.fullShareLinkageBatchMeasurement
                .oneSourcePayloadWithBridgeProofBytes,
            maximumRestrictedProofPayloadBytes,
            'one-source compact linkage source-batch plus bridge proof payload',
        );
        assertAtMost(
            input.fullShareLinkageBatchMeasurement
                .repeatedAllSourcePayloadWithBridgeProofBytes,
            input.measurement.budgetComparison.publicSetupDownloadBudgetBytes,
            'repeated all-source compact linkage source-batch plus bridge proof payload',
        );
    }
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
    const wasmOpening = {
        ...opening,
        messageCoefficientBound:
            typeof opening.messageCoefficientBound === 'bigint'
                ? (() => {
                      throw new Error(
                          'WASM compact VSS measurement opening bound exceeds the bridge number representation.',
                      );
                  })()
                : opening.messageCoefficientBound,
        messageCoefficients: opening.messageCoefficients.map(
            (coefficient, coefficientIndex) => {
                if (typeof coefficient === 'bigint') {
                    throw new Error(
                        `WASM compact VSS measurement opening coefficient ${String(coefficientIndex)} exceeds the bridge number representation.`,
                    );
                }

                return coefficient;
            },
        ),
    } satisfies BgvCompactVssCommitmentOpeningInput;
    const wasmMeasurement = measureWasmPath(kernel, wasmOpening, metadata);
    const fullRingFixture = fullRingPrivateStateFixture();
    const compactShareLinkagePublicVerification =
        measureCompactShareLinkagePublicVerification(fullRingFixture);
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
    const fullSameSecretBridgeProofMeasurement =
        measureFullSameSecretBridgeProof(kernel);
    const fullShareLinkageBatchMeasurement =
        measureFullShareLinkageBatchDerived(
            kernel,
            restrictedBridgeProofMeasurement.generation.lastResult
                .proofByteLength,
        );
    const privateStateDevelopmentArtifactMeasurement =
        await measurePrivateStateDevelopmentArtifacts(fullRingFixture);
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
            compactShareLinkagePublicVerification,
            fullShareLinkageBatchMeasurement,
            restrictedBridgeProofMeasurement,
            restrictedBridgeProofMaterialMeasurement,
            fullSameSecretBridgeProofMeasurement,
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
                        maximumCompactShareLinkagePublicVerificationSeconds,
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
                    compactShareLinkagePublicVerification: {
                        proofByteLength:
                            compactShareLinkagePublicVerification.proofByteLength,
                        proofMaterialTransportBytes:
                            compactShareLinkagePublicVerification.proofMaterialTransportBytes,
                        statementRoot:
                            compactShareLinkagePublicVerification.verification
                                .lastResult.statementRoot,
                        verification:
                            compactShareLinkagePublicVerification.verification
                                .samples,
                    },
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
                    targetReadySameSecretBridgeProof:
                        fullSameSecretBridgeProofReport(
                            fullSameSecretBridgeProofMeasurement,
                        ),
                    compactShareLinkageSourceBatchProof:
                        fullShareLinkageBatchReport(
                            fullShareLinkageBatchMeasurement,
                        ),
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
                    maximumCompactShareLinkagePublicVerificationSeconds,
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
                        compactShareLinkagePublicVerification,
                        fullShareLinkageBatchMeasurement,
                        restrictedBridgeProofMeasurement,
                        restrictedBridgeProofMaterialMeasurement,
                        fullSameSecretBridgeProofMeasurement,
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
                compactShareLinkagePublicVerification: {
                    proofByteLength:
                        compactShareLinkagePublicVerification.proofByteLength,
                    proofMaterialTransportBytes:
                        compactShareLinkagePublicVerification.proofMaterialTransportBytes,
                    participantCount:
                        compactShareLinkagePublicVerification.verification
                            .lastResult.participantCount,
                    targetRnsLimbCount:
                        compactShareLinkagePublicVerification.verification
                            .lastResult.targetRnsLimbCount,
                    thresholdDegree:
                        compactShareLinkagePublicVerification.verification
                            .lastResult.thresholdDegree,
                    statementRoot:
                        compactShareLinkagePublicVerification.verification
                            .lastResult.statementRoot,
                    verification:
                        compactShareLinkagePublicVerification.verification
                            .samples,
                },
                compactShareLinkageSourceBatchProof:
                    fullShareLinkageBatchReport(
                        fullShareLinkageBatchMeasurement,
                    ),
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
                targetReadySameSecretBridgeProof:
                    fullSameSecretBridgeProofReport(
                        fullSameSecretBridgeProofMeasurement,
                    ),
            },
            null,
            2,
        ),
    );
};

await main();
