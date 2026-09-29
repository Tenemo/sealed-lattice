import { describe, expect, it } from 'vitest';

import {
    byteAlignedSpongePermutations,
    compileProofHashWork,
    framedProofHashBytes,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('proof hash work', () => {
    it('matches explicit suffix padding and block-by-block squeezing', () => {
        for (const rate of [72, 136, 168])
            for (let input = 0; input <= 2 * rate + 1; input++)
                for (const output of [
                    0,
                    1,
                    rate - 1,
                    rate,
                    rate + 1,
                    2 * rate + 1,
                ]) {
                    const padded = Array<number>(input).fill(0);
                    padded.push(rate === 72 ? 0x06 : 0x1f);
                    while (padded.length % rate !== 0) padded.push(0);
                    padded[padded.length - 1] |= 0x80;
                    let expected = padded.length / rate;
                    for (
                        let produced = rate;
                        produced < output;
                        produced += rate
                    )
                        expected++;
                    expect(
                        byteAlignedSpongePermutations(
                            BigInt(input),
                            BigInt(output),
                            BigInt(rate),
                        ),
                    ).toBe(BigInt(expected));
                }
    });

    it('includes every part length, including empty parts', () => {
        expect(framedProofHashBytes('d', [3n, 0n, 5n])).toBe(25n);
        expect(() => framedProofHashBytes('d', [1n << 32n])).toThrow();
        expect(() => byteAlignedSpongePermutations(-1n, 64n, 72n)).toThrow();
    });

    it('matches the deployed per-role layouts while retaining the shared query bound', () => {
        const profiles = proofHashProfiles(completionProfile());
        expect(
            profiles.map((value) => [
                value.role,
                value.firstWidth,
                value.secondWidth,
                value.parameterBytes,
                value.statementBytes,
            ]),
        ).toEqual([
            ['registration', 144n, 288n, 180n, 2752540n],
            ['setup', 5808n, 18240n, 7740n, 342737041n],
            ['ballot', 576n, 1632n, 776n, 28672136n],
            ['release', 1040n, 3360n, 1540n, 8782022n],
        ]);
        expect(profiles.map((value) => value.roleBytes)).toEqual([
            282n,
            272n,
            266n,
            341n,
        ]);
        for (const profile of profiles) {
            const costs = compileProofHashWork(completionProfile(), profile);
            expect(costs.verifierCore.queries).toBe(97827n);
            expect(costs.proverCore.queries).toBe(2097187n);
            expect(costs.proverCore.permutations).toBeGreaterThan(
                costs.proverCore.queries,
            );
            expect(costs.verifierCore.permutations).toBeGreaterThan(
                costs.verifierCore.queries,
            );
            expect(
                compileProofHashWork(completionProfile(), profile, 1024n)
                    .proverCoreWithoutPrefixReuse.permutations,
            ).toBeGreaterThan(costs.proverCoreWithoutPrefixReuse.permutations);
        }
    });

    it('counts cached SHAKE blocks from explicit framed messages at different prefix alignments', () => {
        const frame = (bytes: Uint8Array) => {
            const size = Buffer.alloc(4);
            size.writeUInt32LE(bytes.length);
            return Buffer.concat([size, bytes]);
        };
        const blocks = (length: number) => {
            let position = 0,
                permutations = 0;
            for (let byte = 0; byte < length; byte++) {
                if (++position === 136) {
                    position = 0;
                    permutations++;
                }
            }
            return { position, permutations };
        };
        const finish = (position: number, bytes: Uint8Array) => {
            const padded = Array<number>(position + bytes.length).fill(0);
            padded.push(0x1f);
            while (padded.length % 136 !== 0) padded.push(0);
            padded[padded.length - 1] |= 0x80;
            return padded.length / 136;
        };
        const exponents = [
            18,
            18,
            18,
            ...Array.from({ length: 16 }, (_value, index) => 17 - index),
        ];
        const profile = proofHashProfiles(completionProfile())[0];
        for (const roleBytes of [64, 72, 136, 282, 341, 1024]) {
            const prefix = (domain: string, level: boolean) =>
                Buffer.concat([
                    Buffer.alloc(64),
                    frame(Buffer.from(domain)),
                    frame(Buffer.alloc(roleBytes)),
                    frame(Buffer.alloc(4)),
                    ...(level ? [frame(Buffer.alloc(4))] : []),
                ]);
            const leaf = blocks(prefix('bounded-proof/leaf', false).length);
            const node = blocks(prefix('bounded-proof/node', true).length);
            const measured = compileProofHashWork(
                completionProfile(),
                profile,
                BigInt(roleBytes),
            );
            for (const [index, exponent] of exponents.entries()) {
                const width = index === 0 ? 144 : index === 1 ? 288 : 48;
                const leafTail = Buffer.concat([
                    frame(Buffer.alloc(4)),
                    frame(Buffer.alloc(128)),
                    frame(Buffer.alloc(width)),
                ]);
                const nodeTail = Buffer.concat([
                    frame(Buffer.alloc(64)),
                    frame(Buffer.alloc(64)),
                ]);
                const length = 2 ** exponent;
                // Longer prefixes need not cost more after caching: their
                // remainder can save a block in every leaf or node.
                const expected =
                    leaf.permutations +
                    length * finish(leaf.position, leafTail) +
                    exponent * node.permutations +
                    (length - 1) * finish(node.position, nodeTail);
                expect(measured.groups[index].prover.permutations).toBe(
                    BigInt(expected),
                );
            }
        }
    });

    it('preserves distinct hash inputs even when only their common prefix grows', () => {
        const profile = proofHashProfiles(completionProfile())[0];
        const short = compileProofHashWork(completionProfile(), profile, 64n);
        const long = compileProofHashWork(completionProfile(), profile, 282n);
        expect(long.proverCore.queries).toBe(short.proverCore.queries);
        expect(long.proverCore.inputBytes).toBeGreaterThan(
            short.proverCore.inputBytes,
        );
        expect(long.proverCore.permutations).toBeGreaterThan(
            short.proverCore.permutations,
        );
        expect(() =>
            compileProofHashWork(completionProfile(), profile, 0n),
        ).toThrow();
        expect(() =>
            compileProofHashWork(completionProfile(), profile, 1025n),
        ).toThrow();
    });

    it('charges cached prefix initialization while preserving logical queries and inputs', () => {
        const values = proofHashProfiles(completionProfile()).map((profile) =>
            compileProofHashWork(completionProfile(), profile),
        );
        // First, second and linear trees, followed by the emitted FRI trees.
        // Each tree reuses a leaf prefix after the first leaf and a node
        // prefix after the first node of each level.
        const exponents = [
            18,
            18,
            18,
            ...Array.from({ length: 16 }, (_, index) => 17 - index),
        ];
        const reusedPrefixes = exponents.reduce(
            (sum, exponent) =>
                sum + 2n * ((1n << BigInt(exponent)) - 1n) - BigInt(exponent),
            0n,
        );
        expect(
            values.map(
                (value) =>
                    value.proverCoreWithoutPrefixReuse.permutations -
                    value.proverCore.permutations,
            ),
        ).toEqual(
            [2n, 2n, 2n, 3n].map(
                (prefixBlocks) => reusedPrefixes * prefixBlocks,
            ),
        );
        for (const value of values) {
            expect(value.proverCore.queries).toBe(
                value.proverCoreWithoutPrefixReuse.queries,
            );
            expect(value.proverCore.inputBytes).toBe(
                value.proverCoreWithoutPrefixReuse.inputBytes,
            );
            expect(value.proverCore.outputBytes).toBe(
                value.proverCoreWithoutPrefixReuse.outputBytes,
            );
            expect(
                value.groups.reduce(
                    (sum, group) => sum + group.prefixReuse.initializations,
                    0n,
                ),
            ).toBe(225n);
            expect(
                value.groups.reduce(
                    (sum, group) => sum + group.prefixReuse.stateClones,
                    0n,
                ),
            ).toBe(2097125n);
        }
    });

    it('charges the verifier one leaf and one node prefix per opened group', () => {
        const values = proofHashProfiles(completionProfile()).map((profile) =>
            compileProofHashWork(completionProfile(), profile),
        );
        // Every leaf and node hash of a group but the first of each reuses
        // the prefix blocks, including the fixed 64-byte digest domain: two blocks for
        // roles of 266, 272 and 282 bytes and three for 341 bytes at SHAKE256's rate.
        const reusedPrefixes = compileProofVerifierQueryCensus().groups.reduce(
            (sum, group) =>
                sum +
                BigInt(group.maximumLeafQueries - 1) +
                BigInt(group.maximumNodeQueries - 1),
            0n,
        );
        expect(
            values.map(
                (value) =>
                    value.verifierCoreWithoutPrefixReuse.permutations -
                    value.verifierCore.permutations,
            ),
        ).toEqual(
            [2n, 2n, 2n, 3n].map(
                (prefixBlocks) => reusedPrefixes * prefixBlocks,
            ),
        );
        for (const value of values) {
            expect(value.verifierCore.queries).toBe(
                value.verifierCoreWithoutPrefixReuse.queries,
            );
            expect(value.verifierCore.inputBytes).toBe(
                value.verifierCoreWithoutPrefixReuse.inputBytes,
            );
        }
    });
});
