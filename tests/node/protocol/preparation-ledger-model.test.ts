import { describe, expect, it } from 'vitest';

import {
    compilePreparationFamilyInventory,
    compilePreparationLedger,
    compilePreparationPollPopulations,
} from '#tests/preparation-ledger-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

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
});
