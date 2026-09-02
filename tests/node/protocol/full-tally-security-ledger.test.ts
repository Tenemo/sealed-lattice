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
                ledger.operation.knownKeySecondPreimage
                    .legitimateTargetCountPerCompleteInventory,
            ).toBe(ledger.circuit.conjunctionCount * 10);
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
            expect(ledger.localRecord.maximumSealsPerExactContext).toBe(1);
            expect(ledger.localRecord.maximumEncryptionsPerExactContext).toBe(
                1,
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
                independentKeyCount: 2_892_680,
                generatedOutputCount: 11_896_480,
                selectedEvaluationCallCountPerCompleteInventory: 3_566_520,
                hiddenReplacementCount: 5_948_240,
                maximumKeyFanOut: 332,
            },
            alternativeKeyHiding: {
                assumption: 'A_KMAC-ALT',
                conditionallyFreshKeyCountPerSelectedTranscript: 29_620,
                generatedContinuationOutputCount: 59_240,
                hiddenReplacementCount: 29_620,
            },
            knownKeySecondPreimage: {
                assumption: 'A_KMAC-2P',
                authenticatorByteLength: 40,
                legitimateTargetCountPerCompleteInventory: 29_620,
                acceptedCandidateCountSymbol: 'v_online',
                offlineCandidateCountSymbol: 'v_offline',
            },
            selectedContinuationKeyCountPerCompleteInventory: 29_620,
            alternativeContinuationKeyCountPerCompleteInventory: 29_620,
            totalContinuationKeyCount: 59_240,
            totalOperationKeyCount: 2_951_920,
            generationKmacInvocationCount: 11_955_720,
            selectedEvaluationKmacInvocationCountPerCompleteInventory: 3_596_140,
        });
        expect(ledger.honestWork).toEqual({
            symbol: 'sigma_honest',
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
            localRecordAssociatedDataByteLength: 1_278_960,
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
            successfulSealCount: 2_920,
            retainedRecordCount: 150,
            maximumSealsPerExactContext: 1,
            successfulContextCount: 2_920,
            maximumEncryptionsPerExactContext: 1,
            contextByteLength: 438,
            associatedDataByteLength: 1_278_960,
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
                event: 'local-record derived-key-and-nonce collision',
                numerator: 4_261_740n,
                denominatorBitLength: 352,
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
        expect(ledger.environmentalAssumptions).toHaveLength(4);
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
