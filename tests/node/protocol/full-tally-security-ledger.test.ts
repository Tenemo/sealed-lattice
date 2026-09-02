import { describe, expect, it } from 'vitest';

import { compileFullTallySecurityLedger } from '#tests/full-tally-security-ledger.js';

describe('independent full-tally security ledger', () => {
    it('binds every admitted output width to a concrete query budget', () => {
        for (let topCount = 1; topCount <= 10; topCount += 1) {
            const ledger = compileFullTallySecurityLedger(topCount);
            expect(ledger.topCount).toBe(topCount);
            expect(ledger.operation.continuationTargetCount).toBe(
                ledger.operation.continuationKeyCount / 2,
            );
            expect(
                ledger.operation
                    .wrongKeyAuthenticationTargetCountPerVerifiedInventory,
            ).toBe(ledger.operation.continuationTargetCount);
            expect(ledger.operation.totalKeyCount).toBe(
                ledger.operation.directLabelKeyCount +
                    ledger.operation.continuationKeyCount,
            );
            expect(
                ledger.quantumQueryBudget.minimumHonestKmacInvocationCount,
            ).toBe(
                BigInt(ledger.operation.generationKmacInvocationCount) +
                    BigInt(
                        ledger.preparation.scalarDerivedSubkeyInvocationCount,
                    ) +
                    BigInt(
                        ledger.foundation
                            .mailboxKmacImplementationInvocationCount,
                    ),
            );
            expect(
                ledger.quantumQueryBudget
                    .maximumCompleteVerificationInventoryCountBeforeOtherQueries,
            ).toBeGreaterThan(0n);
            expect(ledger.localRecord.maximumSealsPerExactContext).toBe(1);
            expect(ledger.localRecord.maximumEncryptionsPerExactContext).toBe(
                1,
            );
        }
    });

    it('regenerates the maximum-width emitted-interface ledger', () => {
        const ledger = compileFullTallySecurityLedger(10);
        expect(ledger.quantumQueryBudget).toEqual({
            bitLength: 80,
            maximumQueryCount: (1n << 80n) - 1n,
            minimumHonestKmacInvocationCount: 12_490_600n,
            selectedEvaluationKmacInvocationCount: 3_596_140n,
            maximumCompleteVerificationInventoryCountBeforeOtherQueries:
                336_173_180_024_868_098n,
            remainingQueryCountAtThatMaximum: 273_855n,
            maximumWrongKeyAuthenticationTargetCountBeforeOtherQueries:
                9_957_449_592_336_593_062_760n,
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
            directLabelKeyCount: 2_892_680,
            continuationKeyCount: 59_240,
            totalKeyCount: 2_951_920,
            directLabelOutputCount: 11_896_480,
            continuationOutputCount: 59_240,
            generationKmacInvocationCount: 11_955_720,
            selectedEvaluationKmacInvocationCount: 3_596_140,
            hiddenLabelReplacementCount: 5_948_240,
            hiddenContinuationReplacementCount: 29_620,
            hiddenReplacementCount: 5_977_860,
            maximumDirectLabelFanOut: 332,
            continuationTargetCount: 29_620,
            wrongKeyAuthenticationTargetCountPerVerifiedInventory: 29_620,
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

    it('keeps statistical failures separate from direct primitive games', () => {
        const terms = compileFullTallySecurityLedger(10).statisticalTerms;
        expect(terms).toHaveLength(5);
        expect(terms).toEqual([
            expect.objectContaining({
                event: 'operation-key collision',
                numerator: 4_356_914_367_240n,
                denominatorBitLength: 320,
                consequence: 'security',
            }),
            expect.objectContaining({
                event: 'zero continuation difference',
                numerator: 29_620n,
                denominatorBitLength: 320,
                consequence: 'pending',
            }),
            expect.objectContaining({
                event: 'wrong-key continuation acceptance before other queries',
                numerator: 9_957_449_592_336_593_062_760n,
                denominatorBitLength: 320,
                consequence: 'security',
            }),
            expect.objectContaining({
                event: 'allocation-nonce collision',
                numerator: 45n,
                denominatorBitLength: 256,
                consequence: 'pending',
            }),
            expect.objectContaining({
                event: 'local-record derived-key-and-nonce collision',
                numerator: 4_261_740n,
                denominatorBitLength: 352,
                consequence: 'security',
            }),
        ]);
        expect(terms.map(({ securityBitLength }) => securityBitLength)).toEqual(
            [
                expect.closeTo(278.013_556, 6),
                expect.closeTo(305.145_716, 6),
                expect.closeTo(246.923_734, 6),
                expect.closeTo(250.508_147, 6),
                expect.closeTo(329.976_989, 6),
            ],
        );
    });

    it('keeps exact codeword rejection out of the probability ledger', () => {
        const ledger = compileFullTallySecurityLedger(10);
        expect(ledger.aggregateFiniteFailureBound.numerator).toBe(
            46_332_187_682_508_899_466_309_422_614_380n,
        );
        expect(ledger.aggregateFiniteFailureBound.denominatorBitLength).toBe(
            352,
        );
        expect(
            ledger.aggregateFiniteFailureBound.securityBitLength,
        ).toBeCloseTo(246.808_214, 6);
        expect(ledger.deterministicTerms).toEqual([
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
