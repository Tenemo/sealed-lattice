import { describe, expect, it } from 'vitest';

import { compileStatelessSignatureWork } from '#tests/stateless-signature-work-model.js';

describe('Stateless signature work screen', () => {
    it('derives the standard size and includes all authentication paths', () => {
        const work = compileStatelessSignatureWork();
        // Independently published FIPS 205 Table 2 size, not the formula output.
        expect(work.signatureBytes).toBe(49_856n);
        expect(work.publicKeyBytes).toBe(64n);
        expect(work.secretKeyBytes).toBe(128n);
        expect(work.chains).toBe(67n);
        expect(work.layerHeight).toBe(4n);
    });

    it('matches a recursive enumeration of sibling subtrees and root recovery', () => {
        const work = compileStatelessSignatureWork();
        type Nodes = { leaves: bigint; parents: bigint };
        const tree = (height: number): Nodes => {
            if (!height) return { leaves: 1n, parents: 0n };
            const left = tree(height - 1),
                right = tree(height - 1);
            return {
                leaves: left.leaves + right.leaves,
                parents: left.parents + right.parents + 1n,
            };
        };
        const siblings = (height: number) => {
            const nodes = { leaves: 0n, parents: 0n };
            for (let level = 0; level < height; level++) {
                const subtree = tree(level);
                nodes.leaves += subtree.leaves;
                nodes.parents += subtree.parents;
            }
            return nodes;
        };
        const completeLayer = tree(4),
            forestPath = siblings(9),
            layerPath = siblings(4);
        expect(work.keyGeneration.parentHash).toBe(completeLayer.parents);
        expect(work.keyGeneration.pseudorandomFunction).toBe(
            completeLayer.leaves * 67n,
        );
        let secretLeaves = 0n,
            leafHashes = 0n,
            parents = 0n,
            compressedChains = 0n;
        for (let forest = 0; forest < 35; forest++) {
            secretLeaves += forestPath.leaves + 1n;
            leafHashes += forestPath.leaves + 1n;
            parents += forestPath.parents + 9n;
        }
        for (let layer = 0; layer < 17; layer++) {
            secretLeaves += (layerPath.leaves + 1n) * 67n;
            leafHashes += (layerPath.leaves + 1n) * 67n * 15n;
            parents += layerPath.parents + (layer < 16 ? 4n : 0n);
            compressedChains += layerPath.leaves + (layer < 16 ? 1n : 0n);
        }
        expect(work.signing.pseudorandomFunction).toBe(secretLeaves);
        expect(work.signing.chainHashUpper).toBe(leafHashes);
        expect(work.signing.parentHash).toBe(parents);
        expect(work.signing.chainCompression).toBe(compressedChains);
        expect(work.verification.parentHash).toBe(35n * 9n + 17n * 4n);
    });
});
