import { describe, expect, it } from 'vitest';

import {
    maximumSharedPathSiblings,
    merklePathSharingSchedule,
} from '#tests/merkle-path-sharing-model.js';

describe('canonical incremental Merkle multiproofs', () => {
    it('matches an independent union of internal ancestor paths for every small subset', () => {
        for (const length of [2, 4, 8]) {
            const maxima = Array.from({ length: length + 1 }, () => 0);
            for (let subset = 1; subset < 2 ** length; subset++) {
                const indices = Array.from(
                    { length },
                    (_unused, index) => index,
                ).filter((index) => Math.floor(subset / 2 ** index) % 2 === 1);
                const ancestors = new Set<number>();
                for (const index of indices)
                    for (
                        let node = Math.floor((length + index) / 2);
                        node > 0;
                        node = Math.floor(node / 2)
                    )
                        ancestors.add(node);
                const schedule = merklePathSharingSchedule(length, indices);
                expect(schedule.siblingCount).toBe(ancestors.size);
                expect(schedule.cachedNodeCount).toBe(2 * ancestors.size);
                maxima[indices.length] = Math.max(
                    maxima[indices.length],
                    schedule.siblingCount,
                );
            }
            for (let count = 1; count <= length; count++)
                expect(maximumSharedPathSiblings(length, count)).toBe(
                    maxima[count],
                );
        }
    });

    it('reuses already authenticated leaf hashes and stops at the first known subtree', () => {
        const result = merklePathSharingSchedule(8, [0, 1, 3, 4, 7]);
        expect(result.openings.map((opening) => opening.siblings)).toEqual([
            [9, 5, 3],
            [],
            [10],
            [13, 7],
            [14],
        ]);
        expect(
            result.openings.map((opening) => opening.authenticatedAncestor),
        ).toEqual([1, 9, 5, 3, 7]);
    });

    it('refuses ambiguous index orders and out-of-domain values', () => {
        for (const [length, indices] of [
            [1, [0]],
            [3, [0]],
            [8, []],
            [8, [-1]],
            [8, [8]],
            [8, [2, 2]],
            [8, [2, 1]],
            [8, [1.5]],
        ] as const)
            expect(() => merklePathSharingSchedule(length, indices)).toThrow(
                'Invalid canonical',
            );
        for (const [length, count] of [
            [1, 1],
            [3, 1],
            [8, 0],
            [8, 9],
            [8, 1.5],
        ])
            expect(() => maximumSharedPathSiblings(length, count)).toThrow(
                'Invalid Merkle',
            );
    });
});
