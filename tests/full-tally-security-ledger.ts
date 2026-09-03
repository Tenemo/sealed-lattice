import {
    compileCompletionPreparationModel,
    enumerateCorruptProjectionCensuses,
} from './complete-preparation-model.js';
import {
    compileIndependentLocalRecordCensus,
    enumerateFullTallyLocalRecordSeals,
    localRecordContextByteLength,
} from './local-record-context-model.js';
import { compileIndependentPaddedTallyModel } from './padded-tally-transcript-model.js';

const participantCount = 10;
const maximumCorruptParticipantCount = 3;
const adversarialCoherentQueryBudgetBitLength = 80;
const operationKeyBitLength = 320;
const operationKeyByteLength = operationKeyBitLength / 8;
const allocationNonceBitLength = 256;
const localRecordDerivedKeyBitLength = 256;
const mailboxKmacImplementationInvocationCount = 360;
const directRowPadInputByteLength = 223;
const continuationRowPadInputByteLength = 230;
const localRowPadOutputByteLength = 41;
const jointRowPadOutputByteLength = 40;
const continuationRowPadOutputByteLength = 81;

type ExactStatisticalTerm = Readonly<{
    event: string;
    numerator: bigint;
    denominatorBitLength: number;
    consequence: 'pending' | 'security';
}>;

type ExactDeterministicTerm = Readonly<{
    event: string;
    acceptedFailureCount: 0;
    consequence: 'pending' | 'security';
}>;

export type OperationKmacHistogramEntry = Readonly<{
    phase: 'generation' | 'selected-evaluation';
    family: 'continuation-row' | 'joint-row' | 'local-row';
    keyClass: 'conditionally-derived-continuation' | 'independent-label';
    keyByteLength: number;
    messageByteLength: number;
    outputByteLength: number;
    invocationCount: number;
}>;

type CorruptionSetChallengeCensus = Readonly<{
    corruptParticipantCount: number;
    honestReceiverCount: number;
    sampledHonestDirectLabelKeyCount: number;
    inaccessibleHonestDirectLabelKeyCount: number;
    nonemptyDirectChallengeKeyCount: number;
    sampledHonestContinuationKeyCount: number;
    sampledHonestOperationKeyCount: number;
    directKmacTargetOutputCount: number;
    alternativeKeyChallengeCount: number;
    knownKeySecondPreimageTargetCount: number;
    zeroContinuationDifferenceNumerator: number;
}>;

type CorrectnessFailure =
    | Readonly<{
          event: string;
          numerator: bigint;
          denominatorBitLength: number;
          consequence: 'pending';
      }>
    | Readonly<{
          event: string;
          primitiveOwner: 'A_KEM correctness';
          consequence: 'pending';
      }>;

export type FullTallySecurityLedger = Readonly<{
    topCount: number;
    circuit: Readonly<{
        inputWireCount: number;
        constantCount: number;
        linearCount: number;
        conjunctionCount: number;
        negationCount: number;
        outputCount: number;
    }>;
    adversaryWork: Readonly<{
        coherentPrimitiveQueries: Readonly<{
            symbol: 'q_A';
            configuredMaximum: bigint;
            configuredMaximumBitLength: number;
            countingRule: string;
        }>;
        acceptedOnlineContinuationVerifierInvocations: Readonly<{
            symbol: 'v_online';
            maximumHonestReceiverTargetsPerCompleteInventory: number;
            countingRule: string;
        }>;
        adversarialOfflineCandidateTests: Readonly<{
            symbol: 'v_offline';
            countingRule: string;
        }>;
        adversarialStorageStateCandidates: Readonly<{
            symbol: 'v_state';
            countingRule: string;
        }>;
    }>;
    unionMultiplicities: Readonly<{
        participantCount: number;
        maximumCorruptParticipantCount: number;
        actionCountPerTheorem: 1;
        directLabelKeyCount: number;
        continuationKeyCount: number;
        emittedContinuationTargetCountPerCompleteInventory: number;
        sessionAndForkAttempts: 'counted individually in v_online or v_offline';
    }>;
    foundation: Readonly<{
        signatureKeyCount: number;
        signaturePurposeQueriesPerKey: number;
        signatureCount: number;
        mailboxKemKeyCount: number;
        mailboxCiphertextCount: number;
        maximumAuthenticatedCorruptSenderDecapsulationCount: number;
        mailboxKmacDistinctOutputCount: number;
        mailboxKmacImplementationInvocationCount: number;
        mailboxAeadKeyCount: number;
        mailboxPlaintextByteLength: number;
        mailboxAssociatedDataByteLength: number;
    }>;
    preparation: Readonly<{
        contributionCommitmentCount: number;
        contributionOpeningOccurrenceCount: number;
        remoteContributionOpeningOccurrenceCount: number;
        distinctDerivedSubkeyCount: number;
        scalarDerivedSubkeyInvocationCount: number;
        distinctAesAddressBlockCount: number;
        scalarAesBlockInvocationCount: number;
        privateSourceBitCount: number;
        hiddenHonestSourceBitCountAtMaximumCorruption: number;
        extractableCorruptSourceBitCountAtMaximumCorruption: number;
    }>;
    operation: Readonly<{
        directRowHiding: Readonly<{
            assumption: 'A_KMAC-DIRECT';
            sampledIndependentKeyCount: number;
            maximumInaccessibleLabelCount: number;
            maximumNonemptyChallengeKeyCount: number;
            generatedOutputCount: number;
            selectedEvaluationCallCountPerCompleteInventory: number;
            maximumChallengeOutputCount: number;
            maximumKeyFanOut: number;
        }>;
        alternativeKeyHiding: Readonly<{
            assumption: 'A_KMAC-ALT';
            maximumConditionallyFreshKeyCountPerSelectedTranscript: number;
            generatedContinuationOutputCount: number;
            maximumChallengeOutputCount: number;
        }>;
        knownKeySecondPreimage: Readonly<{
            assumption: 'A_KMAC-2P';
            authenticatorByteLength: number;
            maximumHonestReceiverTargetCountPerCompleteInventory: number;
            acceptedCandidateCountSymbol: 'v_online';
            offlineCandidateCountSymbol: 'v_offline';
        }>;
        challengeCensusByCorruptParticipantCount: readonly CorruptionSetChallengeCensus[];
        selectedContinuationKeyCountPerCompleteInventory: number;
        alternativeContinuationKeyCountPerCompleteInventory: number;
        totalContinuationKeyCount: number;
        totalOperationKeyCount: number;
        generationKmacInvocationCount: number;
        selectedEvaluationKmacInvocationCountPerCompleteInventory: number;
    }>;
    honestWork: Readonly<{
        symbol: 'sigma_honest';
        operationKmacHistogram: readonly OperationKmacHistogramEntry[];
        operationGenerationKmacInvocationCount: number;
        operationGenerationKmacInputByteLength: number;
        operationGenerationKmacOutputByteLength: number;
        selectedEvaluationKmacInvocationCountPerCompleteInventory: number;
        selectedEvaluationKmacInputByteLengthPerCompleteInventory: number;
        selectedEvaluationKmacOutputByteLengthPerCompleteInventory: number;
        preparationKdfScalarInvocationCount: number;
        mailboxKdfScalarInvocationCount: number;
        preparationAesScalarInvocationCount: number;
        activationChunkCorpusByteLength: number;
        directLabelAllocationByteLength: number;
        localRecordAssociatedDataByteLength: number;
        accountingRule: string;
    }>;
    randomness: Readonly<{
        signatureKeyGenerationSeedByteLength: number;
        mailboxKeyGenerationSeedByteLength: number;
        preparationContributionAndSaltByteLength: number;
        directedPairwiseMasterByteLength: number;
        mailboxEncapsulationCoinByteLength: number;
        signatureCoinByteLength: number;
        checkpointKeyByteLength: number;
        allocationNonceByteLength: number;
        directLabelByteLength: number;
        directPointBitAllocationByteLength: number;
        directLabelAllocationByteLength: number;
        localRecordNonceByteLength: number;
        explicitByteDrawLength: number;
        nonexportableLocalRootCount: number;
        nonexportableLocalRootBitLength: number;
    }>;
    localRecord: Readonly<{
        storageVisibleSealCount: number;
        inMemoryProposalSealCount: number;
        implementationEncryptionCallCount: number;
        inventoryCommitCount: number;
        retainedRecordCount: number;
        maximumSealsPerExactContext: number;
        distinctContextCount: number;
        maximumEncryptionsPerExactContext: number;
        encryptionKeyDerivationInputCount: number;
        noncePrefixDerivationInputCount: number;
        inventoryAuthenticatorInputCount: number;
        totalDistinctHmacInputCount: number;
        inventoryAuthenticatorByteLength: number;
        inventoryGenerationBitLength: number;
        contextByteLength: number;
        storageVisibleAssociatedDataByteLength: number;
        implementationEncryptionAssociatedDataByteLength: number;
    }>;
    computationalAdvantageTerms: readonly string[];
    securityStatisticalTerms: readonly ExactStatisticalTerm[];
    correctnessFailures: readonly CorrectnessFailure[];
    deterministicTerms: readonly ExactDeterministicTerm[];
    environmentalAssumptions: readonly string[];
    randomFunctionQromHeuristic: Readonly<{
        classification: 'heuristic only; not a fixed-KMAC theorem';
        expression: '((2*q_A+1)^2+v_online+v_offline)/2^320';
        coherentQueryContributionNumeratorAtConfiguredMaximum: bigint;
        denominatorBitLength: 320;
        verifierCountsAreNotBoundedByHonestWork: true;
    }>;
}>;

const binomialTwo = (value: bigint): bigint =>
    value < 2n ? 0n : (value * (value - 1n)) / 2n;

export const compileFullTallySecurityLedger = (
    topCount: number,
): FullTallySecurityLedger => {
    const tally = compileIndependentPaddedTallyModel(topCount);
    const preparation = compileCompletionPreparationModel(tally);
    const localRecord = compileIndependentLocalRecordCensus(
        enumerateFullTallyLocalRecordSeals(tally),
    );
    const operation = tally.kmacCensus;
    const maximumCorruptProjection = enumerateCorruptProjectionCensuses(
        maximumCorruptParticipantCount,
    )[0];
    if (maximumCorruptProjection === undefined) {
        throw new Error('The maximum-corruption projection is absent.');
    }

    const continuationTargetCount = tally.conjunctionCount * participantCount;
    const directLabelKeyCountPerParticipant =
        operation.labelKeyCount / participantCount;
    const continuationKeyCountPerParticipant =
        operation.continuationKeyCount / participantCount;
    const unavailableLabelReplacementCountPerParticipant =
        operation.unavailableLabelReplacementCount / participantCount;
    const zeroFanOutDirectLabelKeyCount =
        operation.labelFanOutDistribution.find(
            ([outputCount]) => outputCount === 0,
        )?.[1] ?? 0;
    const zeroFanOutInactiveLabelCountPerParticipant =
        zeroFanOutDirectLabelKeyCount / (2 * participantCount);
    if (
        !Number.isSafeInteger(directLabelKeyCountPerParticipant) ||
        !Number.isSafeInteger(continuationKeyCountPerParticipant) ||
        !Number.isSafeInteger(unavailableLabelReplacementCountPerParticipant) ||
        !Number.isSafeInteger(zeroFanOutInactiveLabelCountPerParticipant) ||
        directLabelKeyCountPerParticipant % 2 !== 0
    ) {
        throw new Error(
            'The operation census does not partition exactly by participant and label pair.',
        );
    }
    const challengeCensusByCorruptParticipantCount = Array.from(
        { length: maximumCorruptParticipantCount + 1 },
        (_, corruptParticipantCount): CorruptionSetChallengeCensus => {
            const honestReceiverCount =
                participantCount - corruptParticipantCount;
            const sampledHonestDirectLabelKeyCount =
                honestReceiverCount * directLabelKeyCountPerParticipant;
            const sampledHonestContinuationKeyCount =
                honestReceiverCount * continuationKeyCountPerParticipant;
            const honestReceiverTargetCount =
                honestReceiverCount * tally.conjunctionCount;
            return {
                corruptParticipantCount,
                honestReceiverCount,
                sampledHonestDirectLabelKeyCount,
                inaccessibleHonestDirectLabelKeyCount:
                    sampledHonestDirectLabelKeyCount / 2,
                nonemptyDirectChallengeKeyCount:
                    honestReceiverCount *
                    (directLabelKeyCountPerParticipant / 2 -
                        zeroFanOutInactiveLabelCountPerParticipant),
                sampledHonestContinuationKeyCount,
                sampledHonestOperationKeyCount:
                    sampledHonestDirectLabelKeyCount +
                    sampledHonestContinuationKeyCount,
                directKmacTargetOutputCount:
                    honestReceiverCount *
                    unavailableLabelReplacementCountPerParticipant,
                alternativeKeyChallengeCount: honestReceiverTargetCount,
                knownKeySecondPreimageTargetCount: honestReceiverTargetCount,
                zeroContinuationDifferenceNumerator: honestReceiverTargetCount,
            };
        },
    );
    const maximumHonestReceiverChallengeCount =
        challengeCensusByCorruptParticipantCount[0]
            ?.alternativeKeyChallengeCount;
    if (maximumHonestReceiverChallengeCount !== continuationTargetCount) {
        throw new Error('The maximum honest-receiver census is inconsistent.');
    }
    const directSelectedEvaluationCallCount =
        operation.selectedEvaluationCallCount - continuationTargetCount;
    const localGenerationCallCount =
        participantCount *
        (280 * tally.conjunctionCount +
            32 * tally.linearCount +
            32 * tally.outputWires.length);
    const jointGenerationCallCount =
        participantCount * 80 * tally.conjunctionCount;
    if (
        localGenerationCallCount + jointGenerationCallCount !==
        operation.labelOutputCount
    ) {
        throw new Error('The direct-row call-family census is inconsistent.');
    }
    const localSelectedEvaluationCallCount =
        participantCount *
        (70 * tally.conjunctionCount +
            8 * tally.linearCount +
            8 * tally.outputWires.length);
    const jointSelectedEvaluationCallCount =
        participantCount * 40 * tally.conjunctionCount;
    if (
        localSelectedEvaluationCallCount + jointSelectedEvaluationCallCount !==
        directSelectedEvaluationCallCount
    ) {
        throw new Error(
            'The selected direct-row call-family census is inconsistent.',
        );
    }

    const operationGenerationKmacInputByteLength =
        operation.labelOutputCount * directRowPadInputByteLength +
        operation.continuationOutputCount * continuationRowPadInputByteLength;
    const operationGenerationKmacOutputByteLength =
        localGenerationCallCount * localRowPadOutputByteLength +
        jointGenerationCallCount * jointRowPadOutputByteLength +
        operation.continuationOutputCount * continuationRowPadOutputByteLength;
    const selectedEvaluationKmacInputByteLength =
        directSelectedEvaluationCallCount * directRowPadInputByteLength +
        continuationTargetCount * continuationRowPadInputByteLength;
    const selectedEvaluationKmacOutputByteLength =
        localSelectedEvaluationCallCount * localRowPadOutputByteLength +
        jointSelectedEvaluationCallCount * jointRowPadOutputByteLength +
        continuationTargetCount * continuationRowPadOutputByteLength;
    const operationKmacHistogram: readonly OperationKmacHistogramEntry[] = [
        {
            phase: 'generation',
            family: 'local-row',
            keyClass: 'independent-label',
            keyByteLength: operationKeyByteLength,
            messageByteLength: directRowPadInputByteLength,
            outputByteLength: localRowPadOutputByteLength,
            invocationCount: localGenerationCallCount,
        },
        {
            phase: 'generation',
            family: 'joint-row',
            keyClass: 'independent-label',
            keyByteLength: operationKeyByteLength,
            messageByteLength: directRowPadInputByteLength,
            outputByteLength: jointRowPadOutputByteLength,
            invocationCount: jointGenerationCallCount,
        },
        {
            phase: 'generation',
            family: 'continuation-row',
            keyClass: 'conditionally-derived-continuation',
            keyByteLength: operationKeyByteLength,
            messageByteLength: continuationRowPadInputByteLength,
            outputByteLength: continuationRowPadOutputByteLength,
            invocationCount: operation.continuationOutputCount,
        },
        {
            phase: 'selected-evaluation',
            family: 'local-row',
            keyClass: 'independent-label',
            keyByteLength: operationKeyByteLength,
            messageByteLength: directRowPadInputByteLength,
            outputByteLength: localRowPadOutputByteLength,
            invocationCount: localSelectedEvaluationCallCount,
        },
        {
            phase: 'selected-evaluation',
            family: 'joint-row',
            keyClass: 'independent-label',
            keyByteLength: operationKeyByteLength,
            messageByteLength: directRowPadInputByteLength,
            outputByteLength: jointRowPadOutputByteLength,
            invocationCount: jointSelectedEvaluationCallCount,
        },
        {
            phase: 'selected-evaluation',
            family: 'continuation-row',
            keyClass: 'conditionally-derived-continuation',
            keyByteLength: operationKeyByteLength,
            messageByteLength: continuationRowPadInputByteLength,
            outputByteLength: continuationRowPadOutputByteLength,
            invocationCount: continuationTargetCount,
        },
    ];

    const directLabelAllocationByteLength =
        tally.labelEntropyByteLength * participantCount;
    const directLabelByteLength =
        operation.labelKeyCount * operationKeyByteLength;
    const directPointBitAllocationByteLength =
        directLabelAllocationByteLength - directLabelByteLength;
    const signatureKeyGenerationSeedByteLength = participantCount * 32;
    const mailboxKeyGenerationSeedByteLength = participantCount * 64;
    const preparationContributionAndSaltByteLength =
        participantCount * 120 * (32 + 48);
    const directedPairwiseMasterByteLength =
        participantCount * participantCount * 32;
    const mailboxEncapsulationCoinByteLength = 90 * 32;
    const signatureCoinByteLength = 40 * 32;
    const checkpointKeyByteLength = participantCount * 2 * 32;
    const allocationNonceByteLength = participantCount * 32;
    const localRecordNonceByteLength =
        localRecord.distinctDerivationInputCount * 12;
    const explicitByteDrawLength =
        signatureKeyGenerationSeedByteLength +
        mailboxKeyGenerationSeedByteLength +
        preparationContributionAndSaltByteLength +
        directedPairwiseMasterByteLength +
        mailboxEncapsulationCoinByteLength +
        signatureCoinByteLength +
        checkpointKeyByteLength +
        allocationNonceByteLength +
        directLabelAllocationByteLength +
        localRecordNonceByteLength;
    const activationChunkCorpusByteLength =
        participantCount *
        tally.descriptors.reduce(
            (sum, descriptor) => sum + descriptor.chunkByteLength,
            0,
        );
    const maximumCoherentPrimitiveQueryCount =
        (1n << BigInt(adversarialCoherentQueryBudgetBitLength)) - 1n;

    return {
        topCount,
        circuit: {
            inputWireCount: tally.inputWireCount,
            constantCount: tally.constantCount,
            linearCount: tally.linearCount,
            conjunctionCount: tally.conjunctionCount,
            negationCount: tally.negationCount,
            outputCount: tally.outputWires.length,
        },
        adversaryWork: {
            coherentPrimitiveQueries: {
                symbol: 'q_A',
                configuredMaximum: maximumCoherentPrimitiveQueryCount,
                configuredMaximumBitLength:
                    adversarialCoherentQueryBudgetBitLength,
                countingRule:
                    'Count adversarial coherent evaluations in each invoked primitive game; never subtract honest protocol work.',
            },
            acceptedOnlineContinuationVerifierInvocations: {
                symbol: 'v_online',
                maximumHonestReceiverTargetsPerCompleteInventory:
                    maximumHonestReceiverChallengeCount,
                countingRule:
                    'For honest receivers only, count each distinct target-context-reconstructed-key candidate accepted for an online continuation-row check; corrupt receiver coordinates are adversarial confluence inputs.',
            },
            adversarialOfflineCandidateTests: {
                symbol: 'v_offline',
                countingRule:
                    'Count each completed offline target-context-reconstructed-key candidate test, including tests learned across sessions and losing forks.',
            },
            adversarialStorageStateCandidates: {
                symbol: 'v_state',
                countingRule:
                    'Count each distinct initialized root-and-seven-store snapshot presented to an honest restore, including losing-fork, replay, rollback, insertion, partial-deletion, and mutation candidates; post-initialization rootless empty state is excluded by A_STATE.',
            },
        },
        unionMultiplicities: {
            participantCount,
            maximumCorruptParticipantCount,
            actionCountPerTheorem: 1,
            directLabelKeyCount: operation.labelKeyCount,
            continuationKeyCount: operation.continuationKeyCount,
            emittedContinuationTargetCountPerCompleteInventory:
                continuationTargetCount,
            sessionAndForkAttempts:
                'counted individually in v_online or v_offline',
        },
        foundation: {
            signatureKeyCount: participantCount,
            signaturePurposeQueriesPerKey: 4,
            signatureCount: 40,
            mailboxKemKeyCount: participantCount,
            mailboxCiphertextCount: 90,
            maximumAuthenticatedCorruptSenderDecapsulationCount: 21,
            mailboxKmacDistinctOutputCount: 180,
            mailboxKmacImplementationInvocationCount,
            mailboxAeadKeyCount: 90,
            mailboxPlaintextByteLength: 608_940,
            mailboxAssociatedDataByteLength: 32_040,
        },
        preparation: {
            contributionCommitmentCount:
                preparation.preparation.commitmentCount,
            contributionOpeningOccurrenceCount:
                preparation.preparation.commitmentCount +
                preparation.preparation.remoteOpeningOccurrenceCount,
            remoteContributionOpeningOccurrenceCount:
                preparation.preparation.remoteOpeningOccurrenceCount,
            distinctDerivedSubkeyCount:
                preparation.streams.uniqueDerivedSubkeyCount,
            scalarDerivedSubkeyInvocationCount:
                preparation.streams.maximumDerivedSubkeyInvocationCount,
            distinctAesAddressBlockCount:
                preparation.streams.distinctAesBlockCount,
            scalarAesBlockInvocationCount:
                preparation.streams.scalarAesInvocationCount,
            privateSourceBitCount: participantCount * 40,
            hiddenHonestSourceBitCountAtMaximumCorruption:
                maximumCorruptProjection.hiddenHonestSourceBitCount,
            extractableCorruptSourceBitCountAtMaximumCorruption:
                maximumCorruptProjection.extractableCorruptSourceBitCount,
        },
        operation: {
            directRowHiding: {
                assumption: 'A_KMAC-DIRECT',
                sampledIndependentKeyCount: operation.labelKeyCount,
                maximumInaccessibleLabelCount: operation.labelKeyCount / 2,
                maximumNonemptyChallengeKeyCount:
                    operation.labelKeyCount / 2 -
                    zeroFanOutDirectLabelKeyCount / 2,
                generatedOutputCount: operation.labelOutputCount,
                selectedEvaluationCallCountPerCompleteInventory:
                    directSelectedEvaluationCallCount,
                maximumChallengeOutputCount:
                    operation.unavailableLabelReplacementCount,
                maximumKeyFanOut: operation.maximumLabelFanOut,
            },
            alternativeKeyHiding: {
                assumption: 'A_KMAC-ALT',
                maximumConditionallyFreshKeyCountPerSelectedTranscript:
                    maximumHonestReceiverChallengeCount,
                generatedContinuationOutputCount:
                    operation.continuationOutputCount,
                maximumChallengeOutputCount:
                    maximumHonestReceiverChallengeCount,
            },
            knownKeySecondPreimage: {
                assumption: 'A_KMAC-2P',
                authenticatorByteLength:
                    continuationRowPadOutputByteLength -
                    localRowPadOutputByteLength,
                maximumHonestReceiverTargetCountPerCompleteInventory:
                    maximumHonestReceiverChallengeCount,
                acceptedCandidateCountSymbol: 'v_online',
                offlineCandidateCountSymbol: 'v_offline',
            },
            challengeCensusByCorruptParticipantCount,
            selectedContinuationKeyCountPerCompleteInventory:
                continuationTargetCount,
            alternativeContinuationKeyCountPerCompleteInventory:
                continuationTargetCount,
            totalContinuationKeyCount: operation.continuationKeyCount,
            totalOperationKeyCount: operation.keyCount,
            generationKmacInvocationCount: operation.generationCallCount,
            selectedEvaluationKmacInvocationCountPerCompleteInventory:
                operation.selectedEvaluationCallCount,
        },
        honestWork: {
            symbol: 'sigma_honest',
            operationKmacHistogram,
            operationGenerationKmacInvocationCount:
                operation.generationCallCount,
            operationGenerationKmacInputByteLength,
            operationGenerationKmacOutputByteLength,
            selectedEvaluationKmacInvocationCountPerCompleteInventory:
                operation.selectedEvaluationCallCount,
            selectedEvaluationKmacInputByteLengthPerCompleteInventory:
                selectedEvaluationKmacInputByteLength,
            selectedEvaluationKmacOutputByteLengthPerCompleteInventory:
                selectedEvaluationKmacOutputByteLength,
            preparationKdfScalarInvocationCount:
                preparation.streams.maximumDerivedSubkeyInvocationCount,
            mailboxKdfScalarInvocationCount:
                mailboxKmacImplementationInvocationCount,
            preparationAesScalarInvocationCount:
                preparation.streams.scalarAesInvocationCount,
            activationChunkCorpusByteLength,
            directLabelAllocationByteLength,
            localRecordAssociatedDataByteLength:
                localRecord.storageVisibleSealCount *
                localRecordContextByteLength,
            accountingRule:
                'This is an honest emitted-work vector, not an adversarial-query allowance or a scalar security denominator.',
        },
        randomness: {
            signatureKeyGenerationSeedByteLength,
            mailboxKeyGenerationSeedByteLength,
            preparationContributionAndSaltByteLength,
            directedPairwiseMasterByteLength,
            mailboxEncapsulationCoinByteLength,
            signatureCoinByteLength,
            checkpointKeyByteLength,
            allocationNonceByteLength,
            directLabelByteLength,
            directPointBitAllocationByteLength,
            directLabelAllocationByteLength,
            localRecordNonceByteLength,
            explicitByteDrawLength,
            nonexportableLocalRootCount: participantCount,
            nonexportableLocalRootBitLength: 256,
        },
        localRecord: {
            storageVisibleSealCount: localRecord.storageVisibleSealCount,
            inMemoryProposalSealCount: localRecord.distinctDerivationInputCount,
            implementationEncryptionCallCount:
                localRecord.storageVisibleSealCount +
                localRecord.distinctDerivationInputCount,
            inventoryCommitCount: localRecord.inventoryCommitCount,
            retainedRecordCount: localRecord.retainedRecordCount,
            maximumSealsPerExactContext:
                localRecord.maximumSealsPerExactContext,
            distinctContextCount: localRecord.distinctDerivationInputCount,
            maximumEncryptionsPerExactContext:
                localRecord.maximumSealsPerExactContext,
            encryptionKeyDerivationInputCount:
                localRecord.distinctDerivationInputCount,
            noncePrefixDerivationInputCount:
                localRecord.distinctDerivationInputCount,
            inventoryAuthenticatorInputCount: localRecord.inventoryCommitCount,
            totalDistinctHmacInputCount:
                2 * localRecord.distinctDerivationInputCount +
                localRecord.inventoryCommitCount,
            inventoryAuthenticatorByteLength: 32,
            inventoryGenerationBitLength: 32,
            contextByteLength: localRecordContextByteLength,
            storageVisibleAssociatedDataByteLength:
                localRecord.storageVisibleSealCount *
                localRecordContextByteLength,
            implementationEncryptionAssociatedDataByteLength:
                (localRecord.storageVisibleSealCount +
                    localRecord.distinctDerivationInputCount) *
                localRecordContextByteLength,
        },
        computationalAdvantageTerms: [
            'A_CSPRNG',
            'A_LOCAL-HMAC',
            'A_LOCAL-AEAD',
            'A_BIND',
            'A_SIG',
            'A_KEM',
            'A_MAILBOX-KDF',
            'A_AEAD',
            'A_COM',
            'A_KMAC-KDF',
            'A_AES-PRF',
            'A_KMAC-DIRECT',
            'A_KMAC-ALT',
            'A_KMAC-2P',
        ],
        securityStatisticalTerms: [
            {
                event: 'operation-key collision',
                numerator: binomialTwo(BigInt(operation.keyCount)),
                denominatorBitLength: operationKeyBitLength,
                consequence: 'security',
            },
            {
                event: 'local-record derived-key-and-nonce-prefix collision',
                numerator: binomialTwo(
                    BigInt(localRecord.distinctDerivationInputCount),
                ),
                denominatorBitLength: localRecordDerivedKeyBitLength + 64,
                consequence: 'security',
            },
        ],
        correctnessFailures: [
            {
                event: 'zero continuation difference',
                numerator: BigInt(continuationTargetCount),
                denominatorBitLength: operationKeyBitLength,
                consequence: 'pending',
            },
            {
                event: 'allocation-nonce collision',
                numerator: binomialTwo(BigInt(participantCount)),
                denominatorBitLength: allocationNonceBitLength,
                consequence: 'pending',
            },
            {
                event: 'honest ML-KEM-768 encapsulation or decapsulation correctness failure',
                primitiveOwner: 'A_KEM correctness',
                consequence: 'pending',
            },
        ],
        deterministicTerms: [
            {
                event: 'nonzero degree-six codeword substitution with seven fixed honest coordinates',
                acceptedFailureCount: 0,
                consequence: 'security',
            },
            {
                event: 'nonzero degree-three refreshed-or-terminal codeword substitution with seven fixed honest coordinates',
                acceptedFailureCount: 0,
                consequence: 'security',
            },
        ],
        environmentalAssumptions: [
            'honest delivered application code executes the reviewed verifiers while secrets are live',
            'honest retained state, long-lived keys, and CSPRNG state remain outside the adversary view',
            'Web Locks and strict IndexedDB transactions serialize each honest participant',
            'the complete root-authenticated protected-record inventory is not rolled back as one coherent snapshot',
            'an initialized root and all seven protected stores are not erased together to the pristine empty state',
            "the storage adversary cannot synthesize, replace, or transplant an attacker-controlled usable CryptoKey into an honest profile's root record",
        ],
        randomFunctionQromHeuristic: {
            classification: 'heuristic only; not a fixed-KMAC theorem',
            expression: '((2*q_A+1)^2+v_online+v_offline)/2^320',
            coherentQueryContributionNumeratorAtConfiguredMaximum:
                (2n * maximumCoherentPrimitiveQueryCount + 1n) ** 2n,
            denominatorBitLength: 320,
            verifierCountsAreNotBoundedByHonestWork: true,
        },
    };
};
