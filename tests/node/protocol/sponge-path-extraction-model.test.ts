import { describe, expect, it } from 'vitest';

import {
    compareInverseExtractionPredicates,
    compileSpongePathExtractionCensus,
    compressionComparisonSlack,
} from '#tests/sponge-path-extraction-model.js';

describe('complete-path extraction in a compressed permutation database', () => {
    it('checks every bounded small injective database in both query directions', () => {
        const census = compileSpongePathExtractionCensus();
        // Independently counted contexts: k-pair partial injections times
        // remaining query points times output-prefix values.
        const contexts =
            2 * (4 + 16 * 3 + 72 * 2) +
            2 * (8 + 64 * 7 + 1568 * 6) +
            6 * (16 + 256 * 15);
        expect(census.checkedForwardStars).toBe(contexts);
        expect(census.checkedInverseStars).toBe(contexts);
        expect(census.changedPaths).toBeGreaterThan(0);
    });

    it('exposes the inverse-query failure of extracting only a terminal edge', () => {
        expect(compareInverseExtractionPredicates(16, 2)).toEqual({
            terminalEdgeChanges: 16,
            completePathChanges: 4,
        });
        expect(compareInverseExtractionPredicates(64, 3)).toEqual({
            terminalEdgeChanges: 64,
            completePathChanges: 8,
        });
    });

    it('checks the exact algebra behind the compression comparison', () => {
        const cases: { available: bigint; changing: bigint }[] = [];
        for (let available = 1n; available <= 128n; available++)
            for (let changing = 0n; 3n * changing < 2n * available; changing++)
                cases.push({ available, changing });
        const slacks = cases.map(({ available, changing }) =>
            compressionComparisonSlack(available, changing),
        );
        expect(slacks).toEqual(
            cases.map(
                ({ available, changing }) =>
                    changing * (8n * available - 9n * changing),
            ),
        );
        expect(
            slacks.every((value) => value !== undefined && value >= 0n),
        ).toBe(true);
        expect(compressionComparisonSlack(16n, 12n)).toBeUndefined();
    });
});
