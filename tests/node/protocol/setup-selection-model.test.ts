import { describe, expect, it } from 'vitest';

import {
    SetupSelectionModel,
    closeOnlySelectionCounterexample,
    compileSetupSelectionCensus,
    countStagePath,
    preparationStagePath,
    selectedPublicCoordinateDistribution,
    uniformSelectedKeyEmbedding,
} from '#tests/setup-selection-model.js';

describe('clear contribution selection candidate', () => {
    it('preserves the complete uniform prefix for each fixed guess before adaptive selection', () => {
        for (const modulus of [5, 17, 31]) {
            const result = uniformSelectedKeyEmbedding(modulus);
            expect(result.reference.size).toBe(modulus * modulus);
            for (const guess of result.guesses)
                expect(guess.prefixes).toEqual(result.reference);
            expect(
                result.guesses.reduce(
                    (sum, guess) => sum + guess.selectedPrefixes,
                    0,
                ),
            ).toBe(modulus * modulus);
        }
    });
    it('does not treat an adaptively selected aggregate as a fresh uniform key', () => {
        for (const prime of [5, 17, 31]) {
            const distribution = selectedPublicCoordinateDistribution(prime, 3);
            expect(distribution.reduce((sum, count) => sum + count, 0)).toBe(
                prime ** 2,
            );
            expect(distribution[0]).toBe(2 * prime - 1);
            expect(distribution[prime - 1]).toBe(1);
            expect(distribution[0]).toBeGreaterThan(prime);
        }
    });

    it('has at most one certified choice through every small honest lock assignment despite corrupt double signing', () => {
        for (const participants of [4, 5, 6, 7]) {
            const profile = compileSetupSelectionCensus(participants);
            const corrupt = Array.from(
                { length: profile.faultBound },
                (_unused, index) => index,
            );
            const first = Array.from(
                { length: profile.selectedCount },
                (_unused, index) => index,
            );
            const second = first.map((value) => value + 1);
            const honestCount = participants - corrupt.length;
            for (
                let assignment = 0;
                assignment < 3 ** honestCount;
                assignment++
            ) {
                const model = new SetupSelectionModel(participants, corrupt);
                const firstSigners = [...corrupt],
                    secondSigners = [...corrupt];
                for (const signer of corrupt) {
                    expect(model.endorse(signer, first)).toBe(true);
                    expect(model.endorse(signer, second)).toBe(true);
                }
                let choices = assignment;
                for (let index = 0; index < honestCount; index++) {
                    const signer = corrupt.length + index;
                    const choice = choices % 3;
                    choices = Math.floor(choices / 3);
                    if (choice === 0) continue;
                    const selected = choice === 1 ? first : second;
                    expect(model.endorse(signer, selected)).toBe(true);
                    (choice === 1 ? firstSigners : secondSigners).push(signer);
                }
                expect(
                    Number(model.certificate(first, firstSigners)) +
                        Number(model.certificate(second, secondSigners)),
                ).toBeLessThanOrEqual(1);
            }
        }
    });
    it.each([4, 10, 20])(
        'cannot move a protected ballot to another setup at n=%i',
        (count) => {
            const result = closeOnlySelectionCounterexample(count);
            expect(result.originalPlaintext).toEqual(result.scores);
            expect(result.changedSetupPlaintext).not.toEqual(result.scores);
            expect(result.honestHolders).toHaveLength(
                result.profile.faultBound + 1,
            );
            expect(
                result.honestHolders.every(
                    (position) => position >= result.profile.faultBound,
                ),
            ).toBe(true);
            expect(result.firstTargetSigners).toHaveLength(
                result.profile.quorum,
            );
            expect(result.firstTargetSigners).not.toContain(result.author);
            expect(
                result.secondSelection[result.secondSelection.length - 1],
            ).toBeLessThan(result.profile.eligibleCount);
        },
    );

    it('requires a complete certificate before setup activation and accepts it after a losing endorsement', () => {
        const model = new SetupSelectionModel(4);
        expect(model.endorse(3, [1, 2])).toBe(true);
        expect(model.endorse(3, [0, 1])).toBe(false);
        expect(model.endorse(0, [0, 1])).toBe(true);
        expect(model.endorse(1, [0, 1])).toBe(true);
        expect(model.certificate([0, 1], [0, 1])).toBe(false);
        expect(model.certificate([0, 1], [0, 1, 1])).toBe(false);
        expect(model.endorse(2, [0, 1])).toBe(true);
        expect(model.certificate([0, 1], [0, 1, 2])).toBe(true);
        expect(model.certificate([1, 2], [0, 1, 2])).toBe(false);
        expect(model.endorse(3, [1, 2])).toBe(true);
    });

    it('ignores malformed choices before accepting a valid list', () => {
        const model = new SetupSelectionModel(4);
        for (const selection of [
            [0],
            [0, 0],
            [1, 0],
            [-1, 0],
            [0, 3],
            [0, 1.5],
        ])
            expect(model.endorse(1, selection)).toBe(false);
        expect(model.endorse(1, [0, 1])).toBe(true);
    });

    it.each(Array.from({ length: 18 }, (_unused, index) => index + 3))(
        'derives fixed-pool availability and honest quorum intersection at n=%i',
        (count) => {
            const census = compileSetupSelectionCensus(count);
            expect(census.remainingEligibleCount).toBe(census.selectedCount);
            expect(census.minimumHonestSelected).toBeGreaterThan(0);
            expect(census.minimumCertificateIntersection).toBeGreaterThan(
                census.faultBound,
            );
            const model = new SetupSelectionModel(count);
            const selected = Array.from(
                { length: census.selectedCount },
                (_unused, index) => index,
            );
            // Cooperative corrupt parties remain valid continuers while a
            // disjoint set of honest parties uses the departure allowance.
            const continuers = Array.from(
                { length: census.quorum },
                (_unused, index) => index,
            );
            for (const signer of continuers)
                expect(model.endorse(signer, selected)).toBe(true);
            expect(model.certificate(selected, continuers)).toBe(true);
        },
    );

    it('counts candidate stages without adding organizer collection sessions', () => {
        for (const organizer of [false, true]) {
            expect(
                countStagePath(
                    preparationStagePath('clear-close-only', organizer),
                ),
            ).toBe(7);
            expect(
                countStagePath(
                    preparationStagePath('clear-certified', organizer),
                ),
            ).toBe(8);
            expect(
                countStagePath(
                    preparationStagePath('recoverable-sealed', organizer),
                ),
            ).toBe(10);
        }
        const path = preparationStagePath('recoverable-sealed', true);
        const extra = {
            name: 'additional-approval',
            prerequisite: path[path.length - 1].name,
        };
        expect(countStagePath([...path, extra])).toBe(11);
        expect(() =>
            countStagePath([{ name: 'target', prerequisite: 'missing' }]),
        ).toThrow('predecessor');
    });

    it('counts selection guesses from the actual eligible set', () => {
        expect(compileSetupSelectionCensus(3).possibleSelectedSets).toBe(1n);
        expect(compileSetupSelectionCensus(10).possibleSelectedSets).toBe(35n);
        expect(compileSetupSelectionCensus(20).possibleSelectedSets).toBe(
            1716n,
        );
    });
});
