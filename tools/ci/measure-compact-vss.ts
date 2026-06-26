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
    computeCompactVssCommitmentFromOpening,
    createCompactVssCoefficientCommitmentSet,
    createCompactVssRecipientShareCommitmentBundle,
    createCompactVssShareLinkageStatement,
    decodeCompactVssCommitmentBody,
    encodeCompactVssCommitmentBody,
    verifyCompactVssCommitmentOpening,
    type CompactVssAggregateThresholdCommitmentSet,
    type CompactVssCommitmentBodyMetadata,
    type CompactVssCommitmentOpeningInput,
    type CompactVssCommitmentValue,
    type CompactVssRecipientShareCommitmentSet,
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
import { loadTranscriptCoreKernel } from '#packages/wasm/src/index.js';
import type {
    BgvCompactVssCommitmentBodyMetadata,
    BgvCompactVssCommitmentOpeningInput,
    BgvCompactSameSecretBridgeProofStatement,
    BgvCompactVssShareLinkageProofStatement,
    BgvTrusteeEvaluationKeyStatementContext,
    TranscriptCoreKernel,
} from '#packages/wasm/src/transcript-core-bridge.js';
import type { ProtocolHash } from '@sealed-lattice/types';

const warmRunCount = 5;
const firstProfileParticipantCount = 10;
const firstProfileThresholdDegree = 4;
const currentFullCoefficientTransportBytes = 1_604_341_697;
const targetRnsLimbCount = 7;
const restrictedProofRingDegree = 128;
const restrictedProofSourceMessageModulus = 140_737_487_306_753;
const restrictedProofCoefficientCount = 3;
const restrictedProofRecipientRosterPosition = 2;
const minimumPublicCommitmentReductionFactor = 2_800;
const maximumWarmWasmFullProfileGenerationSeconds = 30;
const maximumWarmWasmFullProfileVerificationSeconds = 30;
const maximumMeasuredDevelopmentArtifactJsonBytes = 16 * 1024 * 1024;
const privateVssShareProofFramingSampleBytes = 32;
const targetProofMaterialMeasurementRequested =
    process.env.SEALED_LATTICE_MEASURE_TARGET_PROOF_MATERIAL === '1';

type JsonRecord = Readonly<Record<string, unknown>>;

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
    readonly coefficientMessagesByShamirIndex: readonly (readonly number[])[];
    readonly recipientShareMessages: readonly number[];
    readonly coefficientOpeningRandomnessByShamirIndex: readonly (readonly (readonly number[])[])[];
    readonly recipientShareOpeningRandomness: readonly (readonly number[])[];
    readonly carryWitnesses: readonly number[];
}>;

type RestrictedCompactShareLinkageProofMeasurement = Readonly<{
    readonly generation: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['generateCompactVssShareLinkageProof']>
    >;
    readonly verification: MeasuredOperation<
        ReturnType<TranscriptCoreKernel['verifyCompactVssShareLinkageProof']>
    >;
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

type TargetDecryptionProofMaterialAndRecombinationMeasurement = Readonly<{
    readonly measurementMode: string;
    readonly shareCount: number;
    readonly proofMaterialJsonBytesByShare: readonly number[];
    readonly proofMaterialJsonBytesTotal: number;
    readonly proofMaterialProofRecordCountByShare: readonly number[];
    readonly proofMaterialTotalProofByteLengthByShare: readonly number[];
    readonly proofMaterialTotalProofByteLength: number;
    readonly proofMaterialGenerationMilliseconds: number;
    readonly proofMaterialVerificationJsonBytesByShare: readonly number[];
    readonly proofMaterialVerificationJsonBytesTotal: number;
    readonly proofMaterialVerificationMilliseconds: number;
    readonly proofGatedRecombinationJsonBytes: number;
    readonly proofGatedRecombinationMilliseconds: number;
    readonly largestSingleObjectJsonBytes: number;
}>;

type TargetDecryptionProofMaterialAndRecombinationNotMeasured = Readonly<{
    readonly measurementMode: string;
}>;

type TargetDecryptionDevelopmentMeasurements = Readonly<{
    readonly artifacts: TargetDecryptionDevelopmentArtifactMeasurement;
    readonly proofMaterialAndRecombination:
        | TargetDecryptionProofMaterialAndRecombinationMeasurement
        | TargetDecryptionProofMaterialAndRecombinationNotMeasured;
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
    readonly localStatePlaintextJsonBytes: number;
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

const restrictedCompactShareLinkageProofFixture =
    (): RestrictedCompactShareLinkageProofFixture => {
        const publicMatrixSeedHash = repeatedProtocolHash('7');
        const coefficientMessagesByShamirIndex = Array.from(
            { length: restrictedProofCoefficientCount },
            (_unused, shamirCoefficientIndex) =>
                Array.from(
                    { length: restrictedProofRingDegree },
                    (_unusedCoefficient, coefficientIndex) =>
                        coefficientIndex % 11 === shamirCoefficientIndex
                            ? restrictedProofSourceMessageModulus -
                              4 -
                              shamirCoefficientIndex
                            : (17 +
                                  19 * shamirCoefficientIndex +
                                  23 * coefficientIndex) %
                              restrictedProofSourceMessageModulus,
                ),
        );
        const coefficientOpeningRandomnessByShamirIndex =
            coefficientMessagesByShamirIndex.map(
                (_messages, shamirCoefficientIndex) =>
                    restrictedProofTernaryRandomness(
                        10 + shamirCoefficientIndex,
                    ),
            );
        const recipientShareOpeningRandomness =
            restrictedProofTernaryRandomness(41);
        const trusteePointPowers = [1, 3, 9];
        const recipientShareMessages: number[] = [];
        const carryWitnesses: number[] = [];
        for (
            let coefficientIndex = 0;
            coefficientIndex < restrictedProofRingDegree;
            coefficientIndex += 1
        ) {
            const liftedShare = coefficientMessagesByShamirIndex.reduce(
                (sum, messages, shamirCoefficientIndex) => {
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

                    return sum + message * trusteePointPower;
                },
                0,
            );
            recipientShareMessages.push(
                liftedShare % restrictedProofSourceMessageModulus,
            );
            carryWitnesses.push(
                Math.floor(liftedShare / restrictedProofSourceMessageModulus),
            );
        }
        const coefficientComputations = coefficientMessagesByShamirIndex.map(
            (messages, shamirCoefficientIndex) =>
                computeCompactVssCommitmentFromOpening({
                    commitmentRole: 'coefficient',
                    commitmentContext: {
                        objectType:
                            'CompactVssMeasurementCoefficientCommitmentContext',
                        objectVersion: 1,
                        shamirCoefficientIndex,
                    },
                    publicMatrixSeedHash,
                    rnsLimbIndex: 0,
                    rnsPrime: restrictedProofSourceMessageModulus,
                    ringDegree: restrictedProofRingDegree,
                    messageCoefficients: messages,
                    messageCoefficientBound:
                        restrictedProofSourceMessageModulus,
                    randomnessByColumn:
                        coefficientOpeningRandomnessByShamirIndex[
                            shamirCoefficientIndex
                        ],
                }),
        );
        const recipientShareComputation =
            computeCompactVssCommitmentFromOpening({
                commitmentRole: 'recipient-share',
                commitmentContext: {
                    objectType:
                        'CompactVssMeasurementRecipientShareCommitmentContext',
                    objectVersion: 1,
                    recipientRosterPosition:
                        restrictedProofRecipientRosterPosition,
                },
                publicMatrixSeedHash,
                rnsLimbIndex: 0,
                rnsPrime: restrictedProofSourceMessageModulus,
                ringDegree: restrictedProofRingDegree,
                messageCoefficients: recipientShareMessages,
                messageCoefficientBound: restrictedProofSourceMessageModulus,
                randomnessByColumn: recipientShareOpeningRandomness,
            });
        const sourceCoefficientCommitmentRoot = repeatedProtocolHash('a');
        const sourceRecipientShareCommitmentRoot = repeatedProtocolHash('b');

        return {
            context: {
                ceremonyId: 'compact-vss-proof-measurement',
                manifestHash: repeatedProtocolHash('1'),
                rosterHash: repeatedProtocolHash('2'),
                trusteeIdentity: 'trustee-0',
                trusteeRosterPosition: 0,
                setupEpoch: 'setup-epoch-1',
                sourceCoefficientCommitmentRoot,
                sourceRecipientShareCommitmentRoot,
            },
            compactVssShareLinkage: {
                publicMatrixSeedHash,
                sourceTrusteeIdentity: 'trustee-0',
                sourceTrusteeRosterPosition: 0,
                recipientIdentity: 'trustee-2',
                recipientRosterPosition: restrictedProofRecipientRosterPosition,
                sourceCoefficientCommitmentRoot,
                sourceRecipientShareCommitmentRoot,
                sourceRnsLimbIndex: 0,
                sourceMessageModulus: restrictedProofSourceMessageModulus,
                coefficientCommitmentRoots: coefficientComputations.map(
                    (computation) => computation.commitmentRoot,
                ),
                coefficientCommitments: coefficientComputations.map(
                    (computation) => computation.commitment,
                ),
                recipientShareCommitmentRoot:
                    recipientShareComputation.commitmentRoot,
                recipientShareCommitment: recipientShareComputation.commitment,
            },
            coefficientMessagesByShamirIndex,
            recipientShareMessages,
            coefficientOpeningRandomnessByShamirIndex,
            recipientShareOpeningRandomness,
            carryWitnesses,
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
        const targetBasisHash = repeatedProtocolHash('9');
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

const measureRestrictedCompactShareLinkageProof = (
    kernel: TranscriptCoreKernel,
    fixture: RestrictedCompactShareLinkageProofFixture,
): RestrictedCompactShareLinkageProofMeasurement => {
    const generation = measureSyncOperation(() =>
        kernel.generateCompactVssShareLinkageProof({
            ...fixture,
            ringDegree: restrictedProofRingDegree,
            proofRandomnessSource: 'development-deterministic-fixture',
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
        restrictedProofCoefficientCount
    ) {
        throw new Error(
            'restricted compact share-linkage proof coefficient count differs.',
        );
    }

    return { generation, verification };
};

const measureRestrictedCompactSameSecretBridgeProof = (
    kernel: TranscriptCoreKernel,
    fixture: RestrictedCompactSameSecretBridgeProofFixture,
): RestrictedCompactSameSecretBridgeProofMeasurement => {
    const generation = measureSyncOperation(() =>
        kernel.generateCompactSameSecretBridgeProof({
            ...fixture,
            ringDegree: restrictedProofRingDegree,
            proofRandomnessSource: 'development-deterministic-fixture',
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
                proofStatementHash: proofGeneration.lastResult.statementHash,
                proofStatement: {
                    proofStatementHash:
                        proofGeneration.lastResult.statementHash,
                    context: fixture.context,
                    ringDegree: restrictedProofRingDegree,
                    compactSameSecretBridge: fixture.compactSameSecretBridge,
                },
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
    if (verification.lastResult.restrictedProofVerificationCount !== 1) {
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

const protocolRecord = (value: unknown, fieldName: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
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
        targetBasisHash: measurementHash('target-basis'),
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
        localState.localStatePlaintext.sealedAggregateThresholdShare;
    const sealedTargetDecryptionProofWitness =
        localState.localStatePlaintext.sealedTargetDecryptionProofWitness;
    const localStatePlaintextJsonBytes = jsonByteLength(
        localState.localStatePlaintext,
    );
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
        localStatePlaintextJsonBytes,
        encryptedLocalStateJsonBytes,
        localStateCommitmentJsonBytes,
        sealedAggregateThresholdShareJsonBytes,
        sealedTargetDecryptionProofWitnessJsonBytes,
        largestSingleObjectJsonBytes: Math.max(
            localStatePlaintextJsonBytes,
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
    const fixture = kernel.generateBgvTargetDecryptionFixture();
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
            proofMaterialAndRecombination: {
                measurementMode:
                    'Set SEALED_LATTICE_MEASURE_TARGET_PROOF_MATERIAL=1 to run the heavy target-decryption proof-material and proof-gated recombination measurement.',
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
            proofRandomnessSource: 'development-deterministic-fixture',
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

    const recombinationStartedAtMilliseconds = performance.now();
    const recombination = kernel.verifyAndRecombineBgvTargetDecryptionShares({
        setupPackage: fixture.setupPackage,
        targetAcceptedRecord: fixture.targetAcceptedRecord,
        targetCiphertextBinding: fixture.targetCiphertextBinding,
        targetCiphertexts: fixture.targetCiphertexts,
        targetShareProfile: fixture.targetShareProfile,
        targetDecryptionShares: targetShareBundles.map(
            (targetShareBundle) => targetShareBundle.targetShare,
        ),
        proofStatements: targetShareBundles.map(
            (targetShareBundle) => targetShareBundle.proofStatement,
        ),
        proofMaterials,
    });
    const proofGatedRecombinationMilliseconds =
        performance.now() - recombinationStartedAtMilliseconds;

    const proofMaterialJsonBytesByShare = proofMaterials.map(jsonByteLength);
    const proofMaterialVerificationJsonBytesByShare =
        proofMaterialVerifications.map(jsonByteLength);
    const proofGatedRecombinationJsonBytes = jsonByteLength(recombination);
    const proofMaterialAndRecombination: TargetDecryptionProofMaterialAndRecombinationMeasurement =
        {
            measurementMode:
                'heavy target-decryption proof-material and proof-gated recombination measurement',
            shareCount: targetShareBundles.length,
            proofMaterialJsonBytesByShare,
            proofMaterialJsonBytesTotal: proofMaterialJsonBytesByShare.reduce(
                (totalBytes, shareBytes) => totalBytes + shareBytes,
                0,
            ),
            proofMaterialProofRecordCountByShare: proofMaterials.map(
                (proofMaterial) =>
                    numberField(proofMaterial, 'proofRecordCount'),
            ),
            proofMaterialTotalProofByteLengthByShare: proofMaterials.map(
                (proofMaterial) =>
                    numberField(proofMaterial, 'totalProofByteLength'),
            ),
            proofMaterialTotalProofByteLength: proofMaterials.reduce(
                (totalBytes, proofMaterial) =>
                    totalBytes +
                    numberField(proofMaterial, 'totalProofByteLength'),
                0,
            ),
            proofMaterialGenerationMilliseconds,
            proofMaterialVerificationJsonBytesByShare,
            proofMaterialVerificationJsonBytesTotal:
                proofMaterialVerificationJsonBytesByShare.reduce(
                    (totalBytes, verificationBytes) =>
                        totalBytes + verificationBytes,
                    0,
                ),
            proofMaterialVerificationMilliseconds,
            proofGatedRecombinationJsonBytes,
            proofGatedRecombinationMilliseconds,
            largestSingleObjectJsonBytes: Math.max(
                ...proofMaterialJsonBytesByShare,
                ...proofMaterialVerificationJsonBytesByShare,
                proofGatedRecombinationJsonBytes,
            ),
        };

    return {
        artifacts,
        proofMaterialAndRecombination,
    };
};

const implementedDevelopmentArtifactByteAccounting = (
    measurement: ReturnType<typeof compactVssCommitmentMeasurement>,
    restrictedProofMeasurement: RestrictedCompactShareLinkageProofMeasurement,
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

    return {
        compactPublicCommitmentBodies: {
            byteLength: measurement.totalCompactPublicCommitmentBytes,
            byteReduction: measurement.byteReduction,
        },
        reducedRingProofSamples: {
            ringDegree: restrictedProofRingDegree,
            shareLinkageProofByteLength: restrictedShareLinkageProofByteLength,
            sameSecretBridgeProofByteLength:
                restrictedSameSecretBridgeProofByteLength,
            combinedProofPayloadBytes: restrictedProofPayloadBytes,
            sameSecretBridgeProofMaterialJsonBytes:
                restrictedBridgeProofMaterialMeasurement.proofMaterialSetJsonBytes,
        },
        privateStateDevelopmentArtifacts: privateStateMeasurement,
        targetDecryptionDevelopmentArtifacts:
            targetDecryptionMeasurement.artifacts,
        targetDecryptionProofMaterialAndRecombinationArtifacts:
            targetDecryptionMeasurement.proofMaterialAndRecombination,
    };
};

const enforceManualMeasurementBudgets = (input: {
    readonly measurement: ReturnType<typeof compactVssCommitmentMeasurement>;
    readonly wasmWarmGenerationExtrapolatedSeconds: number;
    readonly wasmWarmVerificationExtrapolatedSeconds: number;
    readonly targetDecryptionDevelopmentArtifactMeasurement: TargetDecryptionDevelopmentArtifactMeasurement;
}): void => {
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
        input.targetDecryptionDevelopmentArtifactMeasurement
            .largestSingleObjectJsonBytes,
        maximumMeasuredDevelopmentArtifactJsonBytes,
        'largest measured target-decryption development JSON artifact',
    );
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
    const restrictedProofFixture = restrictedCompactShareLinkageProofFixture();
    const restrictedProofMeasurement =
        measureRestrictedCompactShareLinkageProof(
            kernel,
            restrictedProofFixture,
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
            wasmWarmGenerationExtrapolatedSeconds,
            wasmWarmVerificationExtrapolatedSeconds,
            targetDecryptionDevelopmentArtifactMeasurement:
                targetDecryptionDevelopmentArtifactMeasurement.artifacts,
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
                    },
                    wasm: {
                        generation: wasmMeasurement.generation.samples,
                        verification: wasmMeasurement.verification.samples,
                        warmGenerationExtrapolatedSeconds:
                            wasmWarmGenerationExtrapolatedSeconds,
                        warmVerificationExtrapolatedSeconds:
                            wasmWarmVerificationExtrapolatedSeconds,
                    },
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
                    coefficientCommitmentCount:
                        restrictedProofMeasurement.generation.lastResult
                            .coefficientCommitmentCount,
                    proofByteLength:
                        restrictedProofMeasurement.generation.lastResult
                            .proofByteLength,
                    statementHash:
                        restrictedProofMeasurement.generation.lastResult
                            .statementHash,
                    generation: restrictedProofMeasurement.generation.samples,
                    verification:
                        restrictedProofMeasurement.verification.samples,
                },
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
                    restrictedProofVerificationCount:
                        restrictedBridgeProofMaterialMeasurement.verification
                            .lastResult.restrictedProofVerificationCount,
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
