import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    byteAlignedSpongePermutations,
    compileProofHashWork,
    framedProofHashBytes,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import {
    completionProfile,
    deriveSupportedProfile,
} from '#tests/supported-profile-model.js';

// Traverse the source's row jobs and subtree/upper-level jobs independently
// of the model's closed initialization formulas.
const prefixInitializations = (
    length: number,
    rowShards: boolean,
    helpers = 0,
) => {
    let leaf = 0,
        node = 0,
        subtrees = 0;
    for (let first = 0; first < length; first += 16384) {
        subtrees++;
        if (!rowShards) leaf++;
        for (let width = Math.min(16384, length - first); width > 1; width /= 2)
            node++;
    }
    for (let roots = subtrees; roots > 1; roots /= 2) node++;
    if (rowShards) {
        let classes = 1;
        while (8 * classes <= helpers) classes *= 2;
        for (let shard = 0; shard < 4 * classes; shard++)
            for (let first = 0; first < length / (4 * classes); first += 16384)
                leaf++;
    }
    return { leaf, node };
};

describe('proof hash work', () => {
    it('adds opening regeneration and every leaf-salt expansion without treating them as fresh seeds', () => {
        const profile = completionProfile();
        for (const role of proofHashProfiles(profile)) {
            const value = compileProofHashWork(profile, role);
            let saltCalls = 0n,
                leafHashes = 0n,
                nodeHashes = 0n;
            for (const [index, group] of value.groups.entries()) {
                const count = group.openingCounts;
                expect(count.restoredLeaves === 0).toBe(index < 2);
                saltCalls += BigInt(
                    group.length + count.restoredLeaves + count.openedLeaves,
                );
                leafHashes += BigInt(count.restoredLeaves);
                nodeHashes += BigInt(
                    count.restoredNodes + count.reconstructedNodes,
                );
            }
            // tree::salt uses three length-framed parts, without the fixed
            // ProtocolHash prefix. Re-expansion of an index reuses its seed.
            const saltInput = BigInt(
                3 * 4 + Buffer.byteLength('bounded-proof/salt') + 64 + 4,
            );
            expect(value.proverLeafSaltExpansion.queries).toBe(saltCalls);
            expect(value.proverLeafSaltExpansion.inputBytes).toBe(
                saltCalls * saltInput,
            );
            expect(value.proverLeafSaltExpansion.outputBytes).toBe(
                saltCalls * 128n,
            );
            expect(value.proverLeafSaltExpansion.permutations).toBe(saltCalls);
            expect(value.proverOpeningHashes.queries).toBe(
                leafHashes + nodeHashes,
            );
            expect(value.proverHashSubtotal.queries).toBe(
                value.proverCore.queries + saltCalls + leafHashes + nodeHashes,
            );
            expect(value.proverHashSubtotal.permutations).toBe(
                value.proverCore.permutations +
                    value.proverOpeningHashes.permutations +
                    saltCalls,
            );
        }
    });

    it('uses each actual Rust descriptor word width across small and large profiles', async () => {
        const source = await readFile(
            new URL(
                '../../../crates/protocol-research/supported-profile/src/relation.rs',
                import.meta.url,
            ),
            'utf8',
        );
        const fixed = BigInt(
            source
                .match(/const MESSAGE_BYTES: usize = ([\d_]+);/u)![1]
                .replace(/_/gu, ''),
        );
        expect(fixed).toBe(262144n);
        expect(source.match(/message_bytes: MESSAGE_BYTES/gu)).toHaveLength(2);
        expect(source).toContain(
            'relation.message_bytes = relation.minimum_message_bytes();',
        );
        for (const [participants, options, setupBytes] of [
            [3, 2, 131072n],
            [10, 10, 262144n],
            [20, 20, 524288n],
        ] as const) {
            const profile = deriveSupportedProfile(participants, options);
            const roles = proofHashProfiles(profile);
            expect(roles.map((role) => role.messageBytes)).toEqual([
                setupBytes,
                fixed,
                fixed,
            ]);
            const queries = compileProofVerifierQueryCensus();
            const wideCalls = BigInt(
                queries.verifierMessageQueries + queries.chainStateQueries,
            );
            for (const role of roles.filter(
                (value) => value.role !== 'setup',
            )) {
                const actual = compileProofHashWork(profile, role);
                const borrowedSetupWidth = compileProofHashWork(profile, {
                    ...role,
                    messageBytes: setupBytes,
                });
                expect(
                    actual.transcript.inputBytes -
                        borrowedSetupWidth.transcript.inputBytes,
                ).toBe(wideCalls * (fixed - setupBytes));
                expect(
                    actual.transcript.outputBytes -
                        borrowedSetupWidth.transcript.outputBytes,
                ).toBe(wideCalls * (fixed - setupBytes));
                expect(actual.groups).toEqual(borrowedSetupWidth.groups);
            }
        }
    });
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
            [
                'setup',
                356n * 16n + 48n,
                377n * 48n,
                4n * (18n + 1147n) + 8n * 375n,
                4n + 4n + 108n + 20n + 42n * 65536n * 109n + 31n * 65536n * 21n,
            ],
            ['ballot', 576n, 1632n, 776n, 28672136n],
            ['release', 1040n, 3360n, 1540n, 8782022n],
        ]);
        expect(profiles.map((value) => value.roleBytes)).toEqual([
            340n,
            334n,
            409n,
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
        const profile = proofHashProfiles(completionProfile()).find(
            (value) => value.role === 'ballot',
        )!;
        for (const roleBytes of [64, 72, 136, 282, 334, 340, 409, 1024]) {
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
                const width = index === 0 ? 576 : index === 1 ? 1632 : 48;
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
                const initializations = prefixInitializations(
                    length,
                    index < 3,
                );
                // Longer prefixes need not cost more after caching: their
                // remainder can save a block in every leaf or node.
                const expected =
                    initializations.leaf * leaf.permutations +
                    length * finish(leaf.position, leafTail) +
                    initializations.node * node.permutations +
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
        // Prefixes are local to row and subtree jobs, including an upper
        // node prefix for each level above the subtrees. Every role's leaf
        // and node prefix, with the fixed 64-byte digest domain, the framed
        // family name and role and its framed fields, covers three complete
        // 136-byte blocks.
        const exponents = [
            18,
            18,
            18,
            ...Array.from({ length: 16 }, (_, index) => 17 - index),
        ];
        let initializations = 0n;
        const reusedPrefixes = exponents.reduce((sum, exponent, index) => {
            const length = 2 ** exponent;
            const prefixes = prefixInitializations(length, index < 3);
            initializations += BigInt(prefixes.leaf + prefixes.node);
            return sum + BigInt(2 * length - 1 - prefixes.leaf - prefixes.node);
        }, 0n);
        expect(
            values.map(
                (value) =>
                    value.proverCoreWithoutPrefixReuse.permutations -
                    value.proverCore.permutations,
            ),
        ).toEqual(
            [3n, 3n, 3n].map((prefixBlocks) => reusedPrefixes * prefixBlocks),
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
            ).toBe(initializations);
            expect(
                value.groups.reduce(
                    (sum, group) => sum + group.prefixReuse.stateClones,
                    0n,
                ),
            ).toBe(2097125n);
        }
    });

    it('retains every subtree and row-job initialization under the supported helper bound', async () => {
        const [tree, rows, parallel, verifier, digest] = await Promise.all([
            readFile('crates/protocol-research/word-proof/src/tree.rs', 'utf8'),
            readFile('crates/protocol-research/word-proof/src/rows.rs', 'utf8'),
            readFile(
                'crates/protocol-research/parallel-work/src/lib.rs',
                'utf8',
            ),
            readFile(
                'crates/protocol-research/word-verifier/src/engine.rs',
                'utf8',
            ),
            readFile(
                'crates/protocol-research/parallel-work/src/protocol-hash.rs',
                'utf8',
            ),
        ]);
        expect(tree).toContain('const SUBTREE_LEAVES: usize = 1 << 14;');
        expect(tree).toContain('const SALT_BYTES: usize = 128;');
        expect(rows).toContain('const ROWS_PER_JOB: usize = 16_384;');
        expect(parallel).toContain('const MAXIMUM_HELPERS: usize = 8;');
        expect(verifier).toContain('role.is_empty() || role.len() > 1024');
        expect(digest).toContain('const RATE: usize = 136;');
        expect(digest).toContain('const PREFIX_BYTES: usize = 64;');
        const work = compileProofHashWork(
            completionProfile(),
            proofHashProfiles(completionProfile())[0],
        );
        for (const [index, group] of work.groups.entries()) {
            for (let helpers = 0; helpers <= 8; helpers++) {
                const counts = prefixInitializations(
                    group.length,
                    index < 3,
                    helpers,
                );
                expect(group.prefixReuse.leafInitializations).toBe(
                    BigInt(counts.leaf),
                );
                expect(group.prefixReuse.nodeInitializations).toBe(
                    BigInt(counts.node),
                );
            }
        }
        const first = work.groups[0];
        expect(first.prefixReuse.initializations).toBeGreaterThan(
            1n + BigInt(Math.log2(first.length)),
        );
    });

    it('bounds full-input Merkle hashes by their remaining uncached permutations', () => {
        const profile = completionProfile();
        for (const role of proofHashProfiles(profile)) {
            const actual = compileProofHashWork(profile, role);
            expect(
                actual.groups.every(
                    (group) => group.prefixReuse.completeInputFactor <= 3n,
                ),
            ).toBe(true);
            const maximum = compileProofHashWork(profile, role, 1024n);
            expect(
                maximum.groups.every(
                    (group) => group.prefixReuse.completeInputFactor <= 5n,
                ),
            ).toBe(true);
        }
        // A long arbitrary cached prefix would invalidate the same factor;
        // it is not covered just because its final digest is short.
        const longPrefix =
            64n + framedProofHashBytes('bounded-proof/node', [8192n, 4n, 4n]);
        const full = byteAlignedSpongePermutations(
            longPrefix + 136n,
            64n,
            136n,
        );
        const remaining = full - longPrefix / 136n;
        expect(full).toBeGreaterThan(5n * remaining);
        // Exhaust the accepted role-length range. Larger leaf payloads only
        // increase the uncached work, so the smallest emitted row suffices.
        for (let roleBytes = 1n; roleBytes <= 1024n; roleBytes++) {
            const leafPrefix =
                64n +
                framedProofHashBytes('bounded-proof/leaf', [roleBytes, 4n]);
            const nodePrefix =
                64n +
                framedProofHashBytes('bounded-proof/node', [roleBytes, 4n, 4n]);
            const verifierPrefix =
                64n +
                framedProofHashBytes('bounded-proof/node', [roleBytes, 4n]);
            for (const [prefix, tail] of [
                [leafPrefix, 8n + 132n + 4n + 48n],
                [nodePrefix, 136n],
                [verifierPrefix, 144n],
            ]) {
                const whole = (prefix + tail) / 136n + 1n;
                const suffix = ((prefix % 136n) + tail) / 136n + 1n;
                expect(whole).toBe(prefix / 136n + suffix);
                expect(whole).toBeLessThanOrEqual(5n * suffix);
            }
        }
    });

    it('charges the verifier one leaf and one node prefix per opened group', () => {
        const values = proofHashProfiles(completionProfile()).map((profile) =>
            compileProofHashWork(completionProfile(), profile),
        );
        // Every leaf and node hash of a group but the first of each reuses
        // the prefix blocks, including the fixed 64-byte digest domain: three
        // complete blocks for every role.
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
            [3n, 3n, 3n].map((prefixBlocks) => reusedPrefixes * prefixBlocks),
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

    it('charges the complete owner item in every contribution hash input', () => {
        const profile = completionProfile();
        const role = proofHashProfiles(profile).find(
            (value) => value.role === 'setup',
        )!;
        const previousRoleBytes = 8n + 4n * 6n + 4n + 36n + 2n * 64n + 2n;
        const ownerItemBytes = 6n + 4n + 2n * 64n;
        expect(role.roleBytes).toBe(previousRoleBytes + ownerItemBytes);
        const current = compileProofHashWork(profile, role);
        const previous = compileProofHashWork(profile, role, previousRoleBytes);
        for (const member of ['proverCore', 'verifierCore'] as const) {
            expect(current[member].queries).toBe(previous[member].queries);
            expect(current[member].outputBytes).toBe(
                previous[member].outputBytes,
            );
            expect(
                current[member].inputBytes - previous[member].inputBytes,
            ).toBe(ownerItemBytes * current[member].queries);
        }
        expect(current.statementDigestPass).toEqual(
            previous.statementDigestPass,
        );
    });
});
