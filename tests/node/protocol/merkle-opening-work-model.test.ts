import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    maximumMerkleOpeningWork,
    merkleOpeningWork,
} from '#tests/merkle-opening-work-model.js';
import { merklePathSharingSchedule } from '#tests/merkle-path-sharing-model.js';

// Traverse the transmitted sibling schedule and the complete local cache
// trees, rather than multiplying the model's per-block formulas.
const reference = (
    length: number,
    indices: readonly number[],
    forgotten: boolean,
) => {
    const levels = Math.min(4, Math.log2(length) - 1);
    const span = 2 ** (levels + 1);
    let leaves = 0,
        nodes = 0,
        leafPrefixes = 0,
        nodePrefixes = 0;
    if (forgotten) {
        const visited = new Set<number>();
        for (const index of indices) {
            const first = index - (index % span);
            if (visited.has(first)) continue;
            visited.add(first);
            leafPrefixes++;
            for (let leaf = first; leaf < first + span; leaf++) leaves++;
            for (let parents = span / 2; parents >= 1; parents /= 2) {
                nodePrefixes++;
                for (let parent = 0; parent < parents; parent++) nodes++;
            }
        }
    }
    let cached = -1;
    const schedule =
        indices.length === 0
            ? []
            : merklePathSharingSchedule(length, indices).openings;
    for (const opening of schedule)
        for (const node of opening.siblings) {
            if (node >= length || node < length / 2 ** levels) continue;
            let left = node;
            while (left < length) left *= 2;
            const block = Math.floor((left - length) / span);
            if (block === cached) continue;
            cached = block;
            for (let level = 1; level <= levels; level++) nodePrefixes++;
            for (let local = span - 1; local >= 2; local--) nodes++;
        }
    return {
        leaves,
        nodes,
        leafPrefixes,
        nodePrefixes,
        salts: leaves + indices.length,
    };
};

describe('prover Merkle opening work', () => {
    it('counts full cache reconstruction rather than only transmitted path siblings', () => {
        for (const length of [2, 4, 8])
            for (let mask = 0; mask < 2 ** length; mask++) {
                const indices = Array.from(
                    { length },
                    (_, index) => index,
                ).filter((index) => mask & (1 << index));
                for (const forgotten of [false, true]) {
                    const actual = merkleOpeningWork(
                        length,
                        indices,
                        forgotten,
                    );
                    const expected = reference(length, indices, forgotten);
                    expect(actual.restoredLeaves).toBe(expected.leaves);
                    expect(actual.nodeHashes).toBe(expected.nodes);
                    expect(actual.leafPrefixInitializations).toBe(
                        expected.leafPrefixes,
                    );
                    expect(actual.nodePrefixInitializations).toBe(
                        expected.nodePrefixes,
                    );
                    expect(actual.saltExpansions).toBe(expected.salts);
                }
            }
    });

    it('covers adjacent, separated and complete block boundaries in both retention modes', () => {
        for (const length of [16, 32, 64, 1024, 262144]) {
            const choices = [
                [],
                [0],
                [0, 1],
                [0, length - 1],
                [0, length / 2],
                Array.from(
                    { length: Math.min(1406, length) },
                    (_, index) => index,
                ),
                Array.from(
                    { length: Math.min(1406, Math.ceil(length / 32)) },
                    (_, index) => index * 32,
                ),
            ];
            for (const indices of choices)
                for (const forgotten of [false, true]) {
                    const actual = merkleOpeningWork(
                        length,
                        indices,
                        forgotten,
                    );
                    const expected = reference(length, indices, forgotten);
                    const bound = maximumMerkleOpeningWork(
                        length,
                        indices.length,
                        forgotten,
                    );
                    expect(actual.nodeHashes).toBe(expected.nodes);
                    expect(actual.restoredLeaves).toBe(expected.leaves);
                    expect(actual.saltExpansions).toBe(expected.salts);
                    expect(actual.leafPrefixInitializations).toBe(
                        expected.leafPrefixes,
                    );
                    expect(actual.nodePrefixInitializations).toBe(
                        expected.nodePrefixes,
                    );
                    expect(actual.nodeHashes).toBeLessThanOrEqual(
                        bound.nodeHashes,
                    );
                    expect(actual.restoredLeaves).toBeLessThanOrEqual(
                        bound.restoredLeaves,
                    );
                }
        }
        const opened = merkleOpeningWork(1024, [0], true);
        expect(opened.nodeHashes).toBeGreaterThan(
            merklePathSharingSchedule(1024, [0]).siblingCount,
        );
        expect(opened.saltExpansions).toBe(opened.restoredLeaves + 1);
    });

    it('binds the omission and retention policy to the current producer', async () => {
        const [tree, oracles, linear, fri] = await Promise.all([
            readFile('crates/protocol-research/word-proof/src/tree.rs', 'utf8'),
            readFile(
                'crates/protocol-research/word-proof/src/oracles.rs',
                'utf8',
            ),
            readFile(
                'crates/protocol-research/word-proof/src/linear-oracle.rs',
                'utf8',
            ),
            readFile('crates/protocol-research/word-proof/src/fri.rs', 'utf8'),
        ]);
        expect(tree).toContain('const RECOMPUTED_LEVELS: usize = 4;');
        expect(tree).toContain('for local in (2..span).rev()');
        expect(oracles).toContain(
            'let tree = Tree::new(role, 0, DOMAIN, relation.first_width());',
        );
        expect(oracles).toContain(
            'let tree = Tree::new(role, 1, DOMAIN, relation.second_width());',
        );
        expect(tree).toContain('forgotten: false,');
        expect(linear).toContain('tree.forget_leaves();');
        expect(fri).toContain('tree.forget_leaves();');
        expect(() => merkleOpeningWork(3, [0], true)).toThrow();
        expect(() => merkleOpeningWork(8, [1, 0], false)).toThrow();
        expect(() => merkleOpeningWork(8, [1, 1], false)).toThrow();
        expect(() => maximumMerkleOpeningWork(8, 9, true)).toThrow();
    });
});
