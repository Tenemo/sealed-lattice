import { describe, expect, it } from 'vitest';

import { compileFullTallySecurityLedger } from '#tests/full-tally-security-ledger.js';

describe('independent full-tally security ledger', () => {
    it('keeps adversary work, honest work, and verifier attempts separate', () => {
        for (let topCount = 1; topCount <= 10; topCount += 1) {
            const ledger = compileFullTallySecurityLedger(topCount);
            expect(ledger.topCount).toBe(topCount);
            expect(ledger.circuit.outputCount).toBe(11 + 4 * topCount);
            expect(ledger.adversaryWork.coherentPrimitiveQueries).toEqual(
                expect.objectContaining({
                    symbol: 'q_A',
                    configuredMaximum: (1n << 80n) - 1n,
                }),
            );
            expect(
                ledger.adversaryWork
                    .acceptedOnlineContinuationVerifierInvocations.symbol,
            ).toBe('v_online');
            expect(
                ledger.adversaryWork.adversarialOfflineCandidateTests.symbol,
            ).toBe('v_offline');
            expect(
                ledger.adversaryWork.adversarialStorageStateCandidates.symbol,
            ).toBe('v_state');
            expect(
                ledger.operation.knownKeySecondPreimage
                    .maximumHonestReceiverTargetCountPerCompleteInventory,
            ).toBe(ledger.circuit.conjunctionCount * 10);
            for (
                let corruptParticipantCount = 0;
                corruptParticipantCount <= 3;
                corruptParticipantCount += 1
            ) {
                const census =
                    ledger.operation.challengeCensusByCorruptParticipantCount[
                        corruptParticipantCount
                    ];
                expect(census).toMatchObject({
                    corruptParticipantCount,
                    honestReceiverCount: 10 - corruptParticipantCount,
                    alternativeKeyChallengeCount:
                        (10 - corruptParticipantCount) *
                        ledger.circuit.conjunctionCount,
                    knownKeySecondPreimageTargetCount:
                        (10 - corruptParticipantCount) *
                        ledger.circuit.conjunctionCount,
                });
            }
            expect(
                ledger.operation
                    .selectedContinuationKeyCountPerCompleteInventory,
            ).toBe(
                ledger.operation
                    .alternativeContinuationKeyCountPerCompleteInventory,
            );
            expect(ledger.operation.totalContinuationKeyCount).toBe(
                2 *
                    ledger.operation
                        .selectedContinuationKeyCountPerCompleteInventory,
            );
            expect(
                ledger.localRecord.maximumSealsPerExactContext,
            ).toBeGreaterThan(1);
            expect(ledger.localRecord.maximumEncryptionsPerExactContext).toBe(
                ledger.localRecord.maximumSealsPerExactContext,
            );
            expect(
                ledger.securityStatisticalTerms.map(({ event }) => event),
            ).not.toContain(
                'wrong-key continuation acceptance before other queries',
            );
        }
    });

    it('regenerates the maximum-width emitted-interface ledger', () => {
        const ledger = compileFullTallySecurityLedger(10);
        expect(ledger.circuit).toEqual({
            inputWireCount: 410,
            constantCount: 2,
            linearCount: 3_803,
            conjunctionCount: 2_962,
            negationCount: 756,
            outputCount: 51,
        });
        expect(ledger.foundation).toEqual({
            signatureKeyCount: 10,
            signaturePurposeQueriesPerKey: 4,
            signatureCount: 40,
            mailboxKemKeyCount: 10,
            mailboxCiphertextCount: 90,
            maximumAuthenticatedCorruptSenderDecapsulationCount: 21,
            mailboxKmacDistinctOutputCount: 180,
            mailboxKmacImplementationInvocationCount: 360,
            mailboxAeadKeyCount: 90,
            mailboxPlaintextByteLength: 608_940,
            mailboxAssociatedDataByteLength: 32_040,
        });
        expect(ledger.preparation).toEqual({
            contributionCommitmentCount: 1_200,
            contributionOpeningOccurrenceCount: 8_760,
            remoteContributionOpeningOccurrenceCount: 7_560,
            distinctDerivedSubkeyCount: 2_065,
            scalarDerivedSubkeyInvocationCount: 534_520,
            distinctAesAddressBlockCount: 11_056_050,
            scalarAesBlockInvocationCount: 71_981_280,
            privateSourceBitCount: 400,
            hiddenHonestSourceBitCountAtMaximumCorruption: 280,
            extractableCorruptSourceBitCountAtMaximumCorruption: 120,
        });
        expect(ledger.operation).toEqual({
            directRowHiding: {
                assumption: 'A_KMAC-DIRECT',
                sampledIndependentKeyCount: 2_892_680,
                maximumInaccessibleLabelCount: 1_446_340,
                maximumNonemptyChallengeKeyCount: 1_439_220,
                generatedOutputCount: 11_896_480,
                selectedEvaluationCallCountPerCompleteInventory: 3_566_520,
                maximumChallengeOutputCount: 5_948_240,
                maximumKeyFanOut: 332,
            },
            alternativeKeyHiding: {
                assumption: 'A_KMAC-ALT',
                maximumConditionallyFreshKeyCountPerSelectedTranscript: 29_620,
                generatedContinuationOutputCount: 59_240,
                maximumChallengeOutputCount: 29_620,
            },
            knownKeySecondPreimage: {
                assumption: 'A_KMAC-2P',
                authenticatorByteLength: 40,
                maximumHonestReceiverTargetCountPerCompleteInventory: 29_620,
                acceptedCandidateCountSymbol: 'v_online',
                offlineCandidateCountSymbol: 'v_offline',
            },
            challengeCensusByCorruptParticipantCount: [
                {
                    corruptParticipantCount: 0,
                    honestReceiverCount: 10,
                    sampledHonestDirectLabelKeyCount: 2_892_680,
                    inaccessibleHonestDirectLabelKeyCount: 1_446_340,
                    nonemptyDirectChallengeKeyCount: 1_439_220,
                    sampledHonestContinuationKeyCount: 59_240,
                    sampledHonestOperationKeyCount: 2_951_920,
                    directKmacTargetOutputCount: 5_948_240,
                    alternativeKeyChallengeCount: 29_620,
                    knownKeySecondPreimageTargetCount: 29_620,
                    zeroContinuationDifferenceNumerator: 29_620,
                },
                {
                    corruptParticipantCount: 1,
                    honestReceiverCount: 9,
                    sampledHonestDirectLabelKeyCount: 2_603_412,
                    inaccessibleHonestDirectLabelKeyCount: 1_301_706,
                    nonemptyDirectChallengeKeyCount: 1_295_298,
                    sampledHonestContinuationKeyCount: 53_316,
                    sampledHonestOperationKeyCount: 2_656_728,
                    directKmacTargetOutputCount: 5_353_416,
                    alternativeKeyChallengeCount: 26_658,
                    knownKeySecondPreimageTargetCount: 26_658,
                    zeroContinuationDifferenceNumerator: 26_658,
                },
                {
                    corruptParticipantCount: 2,
                    honestReceiverCount: 8,
                    sampledHonestDirectLabelKeyCount: 2_314_144,
                    inaccessibleHonestDirectLabelKeyCount: 1_157_072,
                    nonemptyDirectChallengeKeyCount: 1_151_376,
                    sampledHonestContinuationKeyCount: 47_392,
                    sampledHonestOperationKeyCount: 2_361_536,
                    directKmacTargetOutputCount: 4_758_592,
                    alternativeKeyChallengeCount: 23_696,
                    knownKeySecondPreimageTargetCount: 23_696,
                    zeroContinuationDifferenceNumerator: 23_696,
                },
                {
                    corruptParticipantCount: 3,
                    honestReceiverCount: 7,
                    sampledHonestDirectLabelKeyCount: 2_024_876,
                    inaccessibleHonestDirectLabelKeyCount: 1_012_438,
                    nonemptyDirectChallengeKeyCount: 1_007_454,
                    sampledHonestContinuationKeyCount: 41_468,
                    sampledHonestOperationKeyCount: 2_066_344,
                    directKmacTargetOutputCount: 4_163_768,
                    alternativeKeyChallengeCount: 20_734,
                    knownKeySecondPreimageTargetCount: 20_734,
                    zeroContinuationDifferenceNumerator: 20_734,
                },
            ],
            selectedContinuationKeyCountPerCompleteInventory: 29_620,
            alternativeContinuationKeyCountPerCompleteInventory: 29_620,
            totalContinuationKeyCount: 59_240,
            totalOperationKeyCount: 2_951_920,
            generationKmacInvocationCount: 11_955_720,
            selectedEvaluationKmacInvocationCountPerCompleteInventory: 3_596_140,
        });
        expect(ledger.honestWork).toEqual({
            symbol: 'sigma_honest',
            operationKmacHistogram: [
                {
                    phase: 'generation',
                    family: 'local-row',
                    keyClass: 'independent-label',
                    keyByteLength: 40,
                    messageByteLength: 223,
                    outputByteLength: 41,
                    invocationCount: 9_526_880,
                },
                {
                    phase: 'generation',
                    family: 'joint-row',
                    keyClass: 'independent-label',
                    keyByteLength: 40,
                    messageByteLength: 223,
                    outputByteLength: 40,
                    invocationCount: 2_369_600,
                },
                {
                    phase: 'generation',
                    family: 'continuation-row',
                    keyClass: 'conditionally-derived-continuation',
                    keyByteLength: 40,
                    messageByteLength: 230,
                    outputByteLength: 81,
                    invocationCount: 59_240,
                },
                {
                    phase: 'selected-evaluation',
                    family: 'local-row',
                    keyClass: 'independent-label',
                    keyByteLength: 40,
                    messageByteLength: 223,
                    outputByteLength: 41,
                    invocationCount: 2_381_720,
                },
                {
                    phase: 'selected-evaluation',
                    family: 'joint-row',
                    keyClass: 'independent-label',
                    keyByteLength: 40,
                    messageByteLength: 223,
                    outputByteLength: 40,
                    invocationCount: 1_184_800,
                },
                {
                    phase: 'selected-evaluation',
                    family: 'continuation-row',
                    keyClass: 'conditionally-derived-continuation',
                    keyByteLength: 40,
                    messageByteLength: 230,
                    outputByteLength: 81,
                    invocationCount: 29_620,
                },
            ],
            operationGenerationKmacInvocationCount: 11_955_720,
            operationGenerationKmacInputByteLength: 2_666_540_240,
            operationGenerationKmacOutputByteLength: 490_184_520,
            selectedEvaluationKmacInvocationCountPerCompleteInventory: 3_596_140,
            selectedEvaluationKmacInputByteLengthPerCompleteInventory: 802_146_560,
            selectedEvaluationKmacOutputByteLengthPerCompleteInventory: 147_441_740,
            preparationKdfScalarInvocationCount: 534_520,
            mailboxKdfScalarInvocationCount: 360,
            preparationAesScalarInvocationCount: 71_981_280,
            activationChunkCorpusByteLength: 304_336_370,
            directLabelAllocationByteLength: 117_153_540,
            localRecordAssociatedDataByteLength: 9_176_100,
            accountingRule:
                'This is an honest emitted-work vector, not an adversarial-query allowance or a scalar security denominator.',
        });
        expect(ledger.randomness).toEqual({
            signatureKeyGenerationSeedByteLength: 320,
            mailboxKeyGenerationSeedByteLength: 640,
            preparationContributionAndSaltByteLength: 96_000,
            directedPairwiseMasterByteLength: 3_200,
            mailboxEncapsulationCoinByteLength: 2_880,
            signatureCoinByteLength: 1_280,
            checkpointKeyByteLength: 640,
            allocationNonceByteLength: 320,
            directLabelByteLength: 115_707_200,
            directPointBitAllocationByteLength: 1_446_340,
            directLabelAllocationByteLength: 117_153_540,
            localRecordNonceByteLength: 35_040,
            explicitByteDrawLength: 117_293_860,
            nonexportableLocalRootCount: 10,
            nonexportableLocalRootBitLength: 256,
        });
        expect(ledger.localRecord).toEqual({
            storageVisibleSealCount: 20_950,
            inMemoryProposalSealCount: 2_920,
            implementationEncryptionCallCount: 23_870,
            inventoryCommitCount: 1_570,
            retainedRecordCount: 150,
            maximumSealsPerExactContext: 155,
            distinctContextCount: 2_920,
            maximumEncryptionsPerExactContext: 155,
            encryptionKeyDerivationInputCount: 2_920,
            noncePrefixDerivationInputCount: 2_920,
            inventoryAuthenticatorInputCount: 1_570,
            totalDistinctHmacInputCount: 7_410,
            inventoryAuthenticatorByteLength: 32,
            inventoryGenerationBitLength: 32,
            contextByteLength: 438,
            storageVisibleAssociatedDataByteLength: 9_176_100,
            implementationEncryptionAssociatedDataByteLength: 10_455_060,
        });
    });

    it('separates security statistics from correctness failures', () => {
        const ledger = compileFullTallySecurityLedger(10);
        expect(ledger.securityStatisticalTerms).toEqual([
            {
                event: 'operation-key collision',
                numerator: 4_356_914_367_240n,
                denominatorBitLength: 320,
                consequence: 'security',
            },
            {
                event: 'local-record derived-key-and-nonce-prefix collision',
                numerator: 4_261_740n,
                denominatorBitLength: 320,
                consequence: 'security',
            },
        ]);
        expect(ledger.correctnessFailures).toEqual([
            {
                event: 'zero continuation difference',
                numerator: 29_620n,
                denominatorBitLength: 320,
                consequence: 'pending',
            },
            {
                event: 'allocation-nonce collision',
                numerator: 45n,
                denominatorBitLength: 256,
                consequence: 'pending',
            },
            {
                event: 'honest ML-KEM-768 encapsulation or decapsulation correctness failure',
                primitiveOwner: 'A_KEM correctness',
                consequence: 'pending',
            },
        ]);
        expect(ledger.computationalAdvantageTerms).toContain('A_KMAC-2P');
        expect(ledger.environmentalAssumptions).toHaveLength(6);
        expect(ledger.environmentalAssumptions).toContain(
            'an initialized root and all eight protected stores are not erased together to the pristine empty state',
        );
        expect(ledger.environmentalAssumptions).toContain(
            "the storage adversary cannot synthesize, replace, or transplant an attacker-controlled usable CryptoKey into an honest profile's root record",
        );
    });

    it('labels the random-function QROM calculation as a heuristic', () => {
        const ledger = compileFullTallySecurityLedger(10);
        expect(ledger.randomFunctionQromHeuristic).toEqual({
            classification: 'heuristic only; not a fixed-KMAC theorem',
            expression: '((2*q_A+1)^2+v_online+v_offline)/2^320',
            coherentQueryContributionNumeratorAtConfiguredMaximum:
                ((1n << 81n) - 1n) ** 2n,
            denominatorBitLength: 320,
            verifierCountsAreNotBoundedByHonestWork: true,
        });
        expect(ledger).not.toHaveProperty('aggregateFiniteFailureBound');
    });

    it('keeps exact codeword rejection out of every probability ledger', () => {
        expect(compileFullTallySecurityLedger(10).deterministicTerms).toEqual([
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
        ]);
    });
});
