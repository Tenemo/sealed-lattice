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
const localRecordNonceBitLength = 96;
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
            legitimateTargetsPerCompleteInventory: number;
            countingRule: string;
        }>;
        adversarialOfflineCandidateTests: Readonly<{
            symbol: 'v_offline';
            countingRule: string;
        }>;
    }>;
    unionMultiplicities: Readonly<{
        participantCount: number;
        maximumCorruptParticipantCount: number;
        actionCountPerTheorem: 1;
        directLabelKeyCount: number;
        continuationKeyCount: number;
        continuationTargetCountPerCompleteInventory: number;
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
            independentKeyCount: number;
            generatedOutputCount: number;
            selectedEvaluationCallCountPerCompleteInventory: number;
            hiddenReplacementCount: number;
            maximumKeyFanOut: number;
        }>;
        alternativeKeyHiding: Readonly<{
            assumption: 'A_KMAC-ALT';
            conditionallyFreshKeyCountPerSelectedTranscript: number;
            generatedContinuationOutputCount: number;
            hiddenReplacementCount: number;
        }>;
        knownKeySecondPreimage: Readonly<{
            assumption: 'A_KMAC-2P';
            authenticatorByteLength: number;
            legitimateTargetCountPerCompleteInventory: number;
            acceptedCandidateCountSymbol: 'v_online';
            offlineCandidateCountSymbol: 'v_offline';
        }>;
        selectedContinuationKeyCountPerCompleteInventory: number;
        alternativeContinuationKeyCountPerCompleteInventory: number;
        totalContinuationKeyCount: number;
        totalOperationKeyCount: number;
        generationKmacInvocationCount: number;
        selectedEvaluationKmacInvocationCountPerCompleteInventory: number;
    }>;
    honestWork: Readonly<{
        symbol: 'sigma_honest';
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
        successfulSealCount: number;
        retainedRecordCount: number;
        maximumSealsPerExactContext: number;
        successfulContextCount: number;
        maximumEncryptionsPerExactContext: number;
        contextByteLength: number;
        associatedDataByteLength: number;
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
    const localRecordNonceByteLength = localRecord.successfulSealCount * 12;
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
                legitimateTargetsPerCompleteInventory: continuationTargetCount,
                countingRule:
                    'Count each distinct target-context-reconstructed-key candidate accepted for an online continuation-row check.',
            },
            adversarialOfflineCandidateTests: {
                symbol: 'v_offline',
                countingRule:
                    'Count each completed offline target-context-reconstructed-key candidate test, including tests learned across sessions and losing forks.',
            },
        },
        unionMultiplicities: {
            participantCount,
            maximumCorruptParticipantCount,
            actionCountPerTheorem: 1,
            directLabelKeyCount: operation.labelKeyCount,
            continuationKeyCount: operation.continuationKeyCount,
            continuationTargetCountPerCompleteInventory:
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
                independentKeyCount: operation.labelKeyCount,
                generatedOutputCount: operation.labelOutputCount,
                selectedEvaluationCallCountPerCompleteInventory:
                    directSelectedEvaluationCallCount,
                hiddenReplacementCount:
                    operation.unavailableLabelReplacementCount,
                maximumKeyFanOut: operation.maximumLabelFanOut,
            },
            alternativeKeyHiding: {
                assumption: 'A_KMAC-ALT',
                conditionallyFreshKeyCountPerSelectedTranscript:
                    continuationTargetCount,
                generatedContinuationOutputCount:
                    operation.continuationOutputCount,
                hiddenReplacementCount:
                    operation.counterfactualContinuationReplacementCount,
            },
            knownKeySecondPreimage: {
                assumption: 'A_KMAC-2P',
                authenticatorByteLength:
                    continuationRowPadOutputByteLength -
                    localRowPadOutputByteLength,
                legitimateTargetCountPerCompleteInventory:
                    continuationTargetCount,
                acceptedCandidateCountSymbol: 'v_online',
                offlineCandidateCountSymbol: 'v_offline',
            },
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
                localRecord.successfulSealCount * localRecordContextByteLength,
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
            successfulSealCount: localRecord.successfulSealCount,
            retainedRecordCount: localRecord.retainedRecordCount,
            maximumSealsPerExactContext:
                localRecord.maximumSealsPerExactContext,
            successfulContextCount: localRecord.successfulSealCount,
            maximumEncryptionsPerExactContext: 1,
            contextByteLength: localRecordContextByteLength,
            associatedDataByteLength:
                localRecord.successfulSealCount * localRecordContextByteLength,
        },
        computationalAdvantageTerms: [
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
            'A_LOCAL-HMAC',
            'A_LOCAL-AEAD',
            'A_CSPRNG',
        ],
        securityStatisticalTerms: [
            {
                event: 'operation-key collision',
                numerator: binomialTwo(BigInt(operation.keyCount)),
                denominatorBitLength: operationKeyBitLength,
                consequence: 'security',
            },
            {
                event: 'local-record derived-key-and-nonce collision',
                numerator: binomialTwo(BigInt(localRecord.successfulSealCount)),
                denominatorBitLength:
                    localRecordDerivedKeyBitLength + localRecordNonceBitLength,
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
            'the nonexportable local root is not rolled back together with the complete protected-record database',
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
