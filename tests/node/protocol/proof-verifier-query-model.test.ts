import { describe, expect, it } from 'vitest';

import {
    compileProofVerifierQueryCensus,
    merkleVerificationQueries,
} from '#tests/proof-verifier-query-model.js';

describe('proof verifier query accounting', () => {
    it('counts each expanded parent exactly once for every small opening set', () => {
        for (const length of [2, 4, 8])
            for (let mask = 1; mask < 2 ** length; mask++) {
                const indices = Array.from(
                    { length },
                    (_, index) => index,
                ).filter((index) => mask & (1 << index));
                const parents = new Set<number>();
                for (const index of indices)
                    for (
                        let node = Math.floor((length + index) / 2);
                        node > 0;
                        node = Math.floor(node / 2)
                    )
                        parents.add(node);
                const queries = merkleVerificationQueries(length, indices);
                expect(queries.leafQueries).toBe(indices.length);
                expect(queries.nodeQueries).toBe(parents.size);
            }
    });

    it('includes every first-stage and FRI tree plus the full transcript chain', () => {
        const census = compileProofVerifierQueryCensus();
        expect(census.groups.map((group) => group.length)).toEqual([
            262144, 262144, 262144, 131072, 65536, 32768, 16384, 8192, 4096,
            2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4,
        ]);
        expect(census.maximumLeafQueries).toBe(16124);
        expect(census.maximumNodeQueries).toBe(81641);
        expect(census.verifierMessageQueries).toBe(21);
        expect(census.chainStateQueries).toBe(20);
        expect(census.messageRootQueries).toBe(20);
        expect(census.contextQueries).toBe(1);
        expect(census.maximumCoreQueries).toBe(97827);
    });
});
