import { describe, expect, it } from 'vitest';

import {
    compilePreparationFamilyInventory,
    compilePreparationLedger,
    compilePreparationPollPopulations,
} from '#tests/preparation-ledger-model.js';
import { reductionConstructorOrigins } from '#tests/security-margin/constructor-price.js';
import {
    deriveSupportedProfile,
    supportedProfileRanges,
} from '#tests/supported-profile-model.js';

describe('complete preparation populations', () => {
    it('counts original births and both ciphertext hops across losing rosters', () => {
        for (const participants of [3, 10, 20])
            for (const population of [0n, 1n, 20n, 83n]) {
                const row = compilePreparationLedger(
                    deriveSupportedProfile(participants, 20),
                    population,
                );
                expect(row.generatedSourceEntries).toBe(
                    row.sourceFamilies * population,
                );
                expect(row.maximumStartedPreparationRosters).toBe(population);
                expect(row.maximumHonestProofScopes).toBe(3n * population);
                expect(row.sourceCiphertextComparisons).toBe(
                    2n * row.generatedSourceEntries,
                );
                expect(row.recipientKeyComparisons).toBe(2n * population);
                expect(row.recipientCiphertextComparisons).toBe(
                    2n * BigInt(participants) * population,
                );
                expect(row.auxiliaryKeyComparisons).toBe(3n);
                expect(row.auxiliaryBallotComparisons).toBe(2n * population);
            }
    });
    it('refuses a poll maximum outside the supported rosters', () => {
        const profile = deriveSupportedProfile(10, 20);
        expect(() => compilePreparationLedger(profile, 1n, 9)).toThrow();
        expect(() => compilePreparationLedger(profile, 1n, 21)).toThrow();
        expect(() => compilePreparationLedger(profile, 1n, 10.5)).toThrow();
        expect(() => compilePreparationLedger(profile, -1n)).toThrow();
        expect(
            compilePreparationLedger(profile, 1n, 20)
                .recipientCiphertextComparisons,
        ).toBe(40n);
    });
    it('distinguishes actual source families from the pre-preprocessing catalogue guess', () => {
        const families = compilePreparationFamilyInventory();
        const smallest = compilePreparationLedger(
            deriveSupportedProfile(3, 2),
            1n,
        );
        expect(smallest.sourceFamilies).toBe(1n);
        expect(smallest.guessedFheFamilies).toBe(BigInt(families.length));
        expect(smallest.guessedFheFamilies).toBeGreaterThan(
            smallest.sourceFamilies,
        );
        expect(smallest.fheTupleComparisons).toBe(2n * BigInt(families.length));
        expect(smallest.fheBallotComparisons).toBe(
            2n *
                families.reduce(
                    (sum, family) =>
                        sum + family.maximumPositions * family.selectedSetRange,
                    0n,
                ),
        );
        for (const family of families)
            expect(
                family.selectedSetRange & (family.selectedSetRange - 1n),
            ).toBe(0n);
        expect(
            compilePreparationPollPopulations(20, 20, 37n).maximumSourceDecodes,
        ).toBe(740n);
    });
    it('stays within the constructor origin coefficients at every supported profile', () => {
        const origins = reductionConstructorOrigins;
        const { participants, options } = supportedProfileRanges();
        for (
            let rosterSize = participants.minimum;
            rosterSize <= participants.maximum;
            rosterSize++
        ) {
            for (
                let optionCount = options.minimum;
                optionCount <= options.maximum;
                optionCount++
            ) {
                const poll = compilePreparationPollPopulations(
                    rosterSize,
                    optionCount,
                    1n,
                );
                expect(poll.generatedSourceEntries).toBeLessThanOrEqual(
                    origins.sourceStatements,
                );
                expect(poll.maximumSourceDecodes).toBeLessThanOrEqual(
                    origins.earlySourceRecoveries,
                );
            }
            const row = compilePreparationLedger(
                deriveSupportedProfile(rosterSize, options.maximum),
                1n,
                participants.maximum,
            );
            expect(row.generatedSourceEntries).toBeLessThanOrEqual(
                origins.sourceStatements,
            );
            expect(row.maximumSourceDecodes).toBeLessThanOrEqual(
                origins.earlySourceRecoveries,
            );
            expect(row.recipientKeyComparisons).toBeLessThanOrEqual(
                2n * origins.recipientKeyStatements,
            );
            expect(row.maximumHonestProofScopes).toBeLessThanOrEqual(
                origins.proofScopes,
            );
            expect(row.maximumHonestReleases).toBeLessThanOrEqual(
                origins.firstPrescribedReleases,
            );
        }
    });
});
