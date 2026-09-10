import { describe, expect, it } from 'vitest';

import {
    compileStatelessSignatureProofWork,
    compileStatelessSignatureWork,
    encodeStatelessSignatureChainMessage,
} from '#tests/stateless-signature-work-model.js';

describe('Stateless signature work screen', () => {
    it('instantiates the hash-free message encoding with the checksum order', () => {
        const zero = new Uint8Array(32),
            maximum = new Uint8Array(32).fill(255);
        expect(encodeStatelessSignatureChainMessage(zero)).toEqual([
            ...Array<number>(64).fill(0),
            3,
            12,
            0,
        ]);
        expect(encodeStatelessSignatureChainMessage(maximum)).toEqual([
            ...Array<number>(64).fill(15),
            0,
            0,
            0,
        ]);
        const encodings = Array.from({ length: 256 }, (_, value) => {
            const message = new Uint8Array(32);
            message[31] = value;
            return encodeStatelessSignatureChainMessage(message);
        });
        for (let left = 0; left < 256; left++)
            for (let right = 0; right < 256; right++) {
                if (left === right) continue;
                expect(
                    encodings[left].some(
                        (value, index) => value < encodings[right][index],
                    ),
                ).toBe(true);
            }
        expect(() =>
            encodeStatelessSignatureChainMessage(new Uint8Array(31)),
        ).toThrow(RangeError);
    });
    it('keeps full-space reduction initialization separate from demanded keys', () => {
        const empty = compileStatelessSignatureProofWork(0n);
        const six = compileStatelessSignatureProofWork(6n);
        // All forest positions in the source reduction exist before A.forge,
        // including when A will never request a signature.
        expect(empty.secretElements).toBe(six.secretElements);
        expect(empty.forestSecretElements).toBe(35n * (1n << 77n));
        // Independent geometric-series count for the WOTS instance population.
        const chains = (67n * 16n * ((1n << 68n) - 1n)) / 15n;
        expect(empty.chainSecretElements).toBe(chains);
        expect(empty.secretPayloadBytes).toBe(
            (35n * (1n << 77n) + chains) * 32n,
        );
        // Independent count by tree levels, omitting the supplied leaves.
        let parentHashesPerForest = 0n;
        for (let width = 256n; width > 0n; width /= 2n)
            parentHashesPerForest += 35n * width;
        expect(empty.openPreimageParentHashes).toBe(
            parentHashesPerForest * (1n << 68n),
        );
        expect(empty.openPreimageForestCompressions).toBe(1n << 68n);
        expect(empty.openPreimagePublicHashCalls).toBe(
            (parentHashesPerForest + 1n) * (1n << 68n),
        );
        expect(empty.openPreimagePublicHashCalls).toBe(
            six.openPreimagePublicHashCalls,
        );
        expect(empty.openPreimagePublicHashCalls).toBeGreaterThan(1n << 80n);
        const work = compileStatelessSignatureWork();
        let demanded = work.keyGeneration.pseudorandomFunction;
        for (let signature = 0; signature < 6; signature++)
            demanded += work.signing.pseudorandomFunction;
        expect(six.demandSecretOracleCallsUpper).toBe(demanded);
        expect(empty.demandSecretOracleCallsUpper).toBe(1072n);
        expect(six.demandMessageOracleCallsUpper).toBe(6n);
        expect(() => compileStatelessSignatureProofWork(-1n)).toThrow(
            RangeError,
        );
    });
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
