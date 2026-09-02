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
const quantumQueryBudgetBitLength = 80;
const operationKeyBitLength = 320;
const allocationNonceBitLength = 256;
const localRecordDerivedKeyBitLength = 256;
const localRecordNonceBitLength = 96;
const mailboxKmacImplementationInvocationCount = 360;

type ExactStatisticalTerm = Readonly<{
    event: string;
    numerator: bigint;
    denominatorBitLength: number;
    securityBitLength: number;
    consequence: 'pending' | 'security';
}>;

type ExactDeterministicTerm = Readonly<{
    event: string;
    acceptedFailureCount: 0;
    consequence: 'pending' | 'security';
}>;

export type FullTallySecurityLedger = Readonly<{
    topCount: number;
    quantumQueryBudget: Readonly<{
        bitLength: number;
        maximumQueryCount: bigint;
        minimumHonestKmacInvocationCount: bigint;
        selectedEvaluationKmacInvocationCount: bigint;
        maximumCompleteVerificationInventoryCountBeforeOtherQueries: bigint;
        remainingQueryCountAtThatMaximum: bigint;
        maximumWrongKeyAuthenticationTargetCountBeforeOtherQueries: bigint;
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
        directLabelKeyCount: number;
        continuationKeyCount: number;
        totalKeyCount: number;
        directLabelOutputCount: number;
        continuationOutputCount: number;
        generationKmacInvocationCount: number;
        selectedEvaluationKmacInvocationCount: number;
        hiddenLabelReplacementCount: number;
        hiddenContinuationReplacementCount: number;
        hiddenReplacementCount: number;
        maximumDirectLabelFanOut: number;
        continuationTargetCount: number;
        wrongKeyAuthenticationTargetCountPerVerifiedInventory: number;
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
    statisticalTerms: readonly ExactStatisticalTerm[];
    aggregateFiniteFailureBound: Readonly<{
        numerator: bigint;
        denominatorBitLength: number;
        securityBitLength: number;
    }>;
    deterministicTerms: readonly ExactDeterministicTerm[];
}>;

const binomialTwo = (value: bigint): bigint =>
    value < 2n ? 0n : (value * (value - 1n)) / 2n;

const logarithmBaseTwoOfBigInt = (value: bigint): number => {
    if (value <= 0n) {
        throw new RangeError('A statistical numerator must be positive.');
    }
    const bitLength = value.toString(2).length;
    const shift = Math.max(0, bitLength - 53);
    return Math.log2(Number(value >> BigInt(shift))) + shift;
};

const exactStatisticalTerm = (
    event: string,
    numerator: bigint,
    denominatorBitLength: number,
    consequence: ExactStatisticalTerm['consequence'],
): ExactStatisticalTerm => ({
    event,
    numerator,
    denominatorBitLength,
    securityBitLength:
        denominatorBitLength - logarithmBaseTwoOfBigInt(numerator),
    consequence,
});

export const compileFullTallySecurityLedger = (
    topCount: number,
): FullTallySecurityLedger => {
    const tally = compileIndependentPaddedTallyModel(topCount);
    const preparation = compileCompletionPreparationModel(tally);
    const localRecord = compileIndependentLocalRecordCensus(
        enumerateFullTallyLocalRecordSeals(tally),
    );
    const operation = tally.kmacCensus;
    const maximumQueryCount = (1n << BigInt(quantumQueryBudgetBitLength)) - 1n;
    const minimumHonestKmacInvocationCount =
        BigInt(operation.generationCallCount) +
        BigInt(preparation.streams.maximumDerivedSubkeyInvocationCount) +
        BigInt(mailboxKmacImplementationInvocationCount);
    const selectedEvaluationKmacInvocationCount = BigInt(
        operation.selectedEvaluationCallCount,
    );
    const remainingAfterHonestCalls =
        maximumQueryCount - minimumHonestKmacInvocationCount;
    const maximumCompleteVerificationInventoryCountBeforeOtherQueries =
        remainingAfterHonestCalls / selectedEvaluationKmacInvocationCount;
    const remainingQueryCountAtThatMaximum =
        remainingAfterHonestCalls % selectedEvaluationKmacInvocationCount;
    const maximumCorruptProjection = enumerateCorruptProjectionCensuses(
        maximumCorruptParticipantCount,
    )[0];
    if (maximumCorruptProjection === undefined) {
        throw new Error('The maximum-corruption projection is absent.');
    }
    const continuationTargetCount = tally.conjunctionCount * participantCount;
    const maximumWrongKeyAuthenticationTargetCountBeforeOtherQueries =
        maximumCompleteVerificationInventoryCountBeforeOtherQueries *
        BigInt(continuationTargetCount);

    const statisticalTerms = [
        exactStatisticalTerm(
            'operation-key collision',
            binomialTwo(BigInt(operation.keyCount)),
            operationKeyBitLength,
            'security',
        ),
        exactStatisticalTerm(
            'zero continuation difference',
            BigInt(continuationTargetCount),
            operationKeyBitLength,
            'pending',
        ),
        exactStatisticalTerm(
            'wrong-key continuation acceptance before other queries',
            maximumWrongKeyAuthenticationTargetCountBeforeOtherQueries,
            operationKeyBitLength,
            'security',
        ),
        exactStatisticalTerm(
            'allocation-nonce collision',
            binomialTwo(BigInt(participantCount)),
            allocationNonceBitLength,
            'pending',
        ),
        exactStatisticalTerm(
            'local-record derived-key-and-nonce collision',
            binomialTwo(BigInt(localRecord.successfulSealCount)),
            localRecordDerivedKeyBitLength + localRecordNonceBitLength,
            'security',
        ),
    ] as const;
    const aggregateDenominatorBitLength = Math.max(
        ...statisticalTerms.map(({ denominatorBitLength }) =>
            Number(denominatorBitLength),
        ),
    );
    const aggregateNumerator = statisticalTerms.reduce(
        (sum, { numerator, denominatorBitLength }) =>
            sum +
            (numerator <<
                BigInt(aggregateDenominatorBitLength - denominatorBitLength)),
        0n,
    );

    return {
        topCount,
        quantumQueryBudget: {
            bitLength: quantumQueryBudgetBitLength,
            maximumQueryCount,
            minimumHonestKmacInvocationCount,
            selectedEvaluationKmacInvocationCount,
            maximumCompleteVerificationInventoryCountBeforeOtherQueries,
            remainingQueryCountAtThatMaximum,
            maximumWrongKeyAuthenticationTargetCountBeforeOtherQueries,
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
            directLabelKeyCount: operation.labelKeyCount,
            continuationKeyCount: operation.continuationKeyCount,
            totalKeyCount: operation.keyCount,
            directLabelOutputCount: operation.labelOutputCount,
            continuationOutputCount: operation.continuationOutputCount,
            generationKmacInvocationCount: operation.generationCallCount,
            selectedEvaluationKmacInvocationCount:
                operation.selectedEvaluationCallCount,
            hiddenLabelReplacementCount:
                operation.unavailableLabelReplacementCount,
            hiddenContinuationReplacementCount:
                operation.counterfactualContinuationReplacementCount,
            hiddenReplacementCount: operation.hiddenReplacementCount,
            maximumDirectLabelFanOut: operation.maximumLabelFanOut,
            continuationTargetCount,
            wrongKeyAuthenticationTargetCountPerVerifiedInventory:
                continuationTargetCount,
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
        statisticalTerms,
        aggregateFiniteFailureBound: {
            numerator: aggregateNumerator,
            denominatorBitLength: aggregateDenominatorBitLength,
            securityBitLength:
                aggregateDenominatorBitLength -
                logarithmBaseTwoOfBigInt(aggregateNumerator),
        },
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
    };
};
