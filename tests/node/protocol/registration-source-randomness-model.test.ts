import { describe, expect, it } from 'vitest';

import {
    ascii,
    item,
    itemType,
    tuple,
    unsigned,
    variable,
} from '#tests/node/protocol/reference/canonical-tuple.js';
import {
    shake256RateBytes,
    spongePermutations,
} from '#tests/node/protocol/reference/sponge-permutations.js';
import { operationSeedCount } from '#tests/operation-seed-model.js';
import {
    compileRegistrationSourceRandomness,
    compileRegistrationSourceExtractionWork,
} from '#tests/registration-source-randomness-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('original registration source randomness and hash work', () => {
    it('prices the full source cell and exact-length padding at every extraction', () => {
        const queries = 19n;
        const requests = 7n;
        const result = compileRegistrationSourceExtractionWork(
            10,
            10,
            queries,
            requests,
        );
        const inventory = compileRegistrationSourceRandomness(10, 10);
        let largest = 0n;
        let largestDecoded = 0n;
        for (const [index, family] of inventory.families.entries()) {
            // Recover the raw mask from its independent byte framing: only
            // salt, poll and the coordinate payload are unconstrained.
            const rawLength = 8n * family.commitmentInputBytes;
            const rawMask =
                8n *
                (family.commitmentInputBytes -
                    128n -
                    family.publicCoordinateBytes);
            let classWidth = 1n;
            while (classWidth < rawLength) classWidth *= 2n;
            const padding = classWidth + 1n - rawLength;
            const label = rawMask + padding;
            const input = classWidth + 1n;
            const expected =
                2n * queries * (14n + 5n * (label + 512n) + 3n * input) +
                input +
                1n +
                2n * (label + 512n);
            expect(result.families[index].preparedSelectionGates).toBe(
                expected,
            );
            expect(result.families[index].comparedInputBits).toBe(label);
            // The native source binder uses one sign byte followed by a
            // fixed-width little-endian magnitude, bounded by floor(q/2).
            // The extracted context is the 512-bit poll identity.
            const magnitudeBits = 8n * family.modulusBytes;
            const payloadBits = 512n + 65536n * (8n + magnitudeBits);
            const decoding =
                11n +
                10n * 512n +
                65536n * (24n * magnitudeBits + 94n) +
                3n * payloadBits;
            expect(result.families[index].coordinateDecodingGates).toBe(
                decoding,
            );
            expect(
                result.families[index].preparedSelectionAndDecodingGates,
            ).toBe(expected + decoding);
            largestDecoded =
                expected + decoding > largestDecoded
                    ? expected + decoding
                    : largestDecoded;
            const withoutPadding =
                2n * queries * (14n + 5n * (rawMask + 512n) + 3n * input) +
                input +
                1n +
                2n * (rawMask + 512n);
            expect(expected).toBeGreaterThan(withoutPadding);
            largest = expected > largest ? expected : largest;
        }
        expect(result.maximumPreparedSelectionGates).toBe(requests * largest);
        expect(result.maximumPreparedSelectionAndDecodingGates).toBe(
            requests * largestDecoded,
        );
        expect(
            compileRegistrationSourceExtractionWork(3, 2, 0n, 0n)
                .maximumPreparedSelectionGates,
        ).toBe(0n);
        expect(() =>
            compileRegistrationSourceExtractionWork(3, 2, -1n, 0n),
        ).toThrow();
    });
    it.each([
        [3, 2],
        [10, 10],
        [20, 20],
    ])(
        'frames every source for original poll maximum %i and %i options',
        (maximum, options) => {
            const value = compileRegistrationSourceRandomness(maximum, options);
            for (const family of value.families) {
                const source = tuple([
                    ascii('sealed-lattice/fhe-source-randomness/v2'),
                    item(itemType.rawBytes, Buffer.alloc(1952)),
                    item(itemType.hash512, Buffer.alloc(64)),
                    item(
                        itemType.rawBytes,
                        variable(Buffer.alloc(Number(family.modulusBytes))),
                    ),
                    item(itemType.unsigned64, unsigned(family.sampleBits, 8)),
                    item(itemType.rawBytes, Buffer.alloc(64)),
                ]);
                expect(family.sourceInputBytes).toBe(BigInt(source.length));
                // The source's seed is fixed bytes, unlike the operation
                // stream's variable-byte seed. No inner length is added.
                expect(family.minimumSourceOutputBytes).toBe(
                    4n * 1024n + 20n * 65536n,
                );
                expect(family.comparisonMaximumSourceOutputBytes).toBe(
                    8n * 1024n + 20n * 65536n,
                );
                expect(family.comparisonSourcePermutations).toBe(
                    spongePermutations(
                        source.length,
                        Number(family.comparisonMaximumSourceOutputBytes),
                        shake256RateBytes,
                    ),
                );
                const commitmentPrefix = tuple([
                    ascii('sealed-lattice/registered-fhe-key/v2'),
                    item(itemType.rawBytes, Buffer.alloc(1952)),
                    item(itemType.rawBytes, Buffer.alloc(64)),
                    item(itemType.hash512, Buffer.alloc(64)),
                    item(
                        itemType.rawBytes,
                        variable(Buffer.alloc(Number(family.modulusBytes))),
                    ),
                    item(itemType.unsigned64, unsigned(family.sampleBits, 8)),
                    item(itemType.rawBytes, variable(Buffer.alloc(0))),
                ]);
                const commitmentBytes =
                    BigInt(commitmentPrefix.length) +
                    family.publicCoordinateBytes;
                expect(family.commitmentInputBytes).toBe(commitmentBytes);
                expect(family.commitmentPermutations).toBe(
                    spongePermutations(
                        Number(commitmentBytes),
                        64,
                        shake256RateBytes,
                    ),
                );
                const commonInput = Buffer.concat([
                    Buffer.from('synthetic-full-setup-witness/1'),
                    unsigned(14, 4),
                    Buffer.from('common-fhe-a-0'),
                ]);
                expect(family.commonInputBytes).toBe(
                    BigInt(commonInput.length),
                );
                expect(family.commonOutputBytes).toBe(
                    65536n * BigInt(family.sampleBits / 8),
                );
                expect(family.commonPermutations).toBe(
                    spongePermutations(
                        commonInput.length,
                        Number(family.commonOutputBytes),
                        shake256RateBytes,
                    ),
                );
            }
            expect(value.sourceSeedCount).toBe(BigInt(value.families.length));
            expect(value.freshSeedAndSaltBytes).toBe(
                128n * value.sourceSeedCount,
            );
            expect(value.gaussianSamples).toBe(65536n * value.sourceSeedCount);
            expect(value.sparseCalls).toBe(value.sourceSeedCount);
        },
    );

    it('keeps registration family seeds separate from retained operation seeds', () => {
        const profile = completionProfile();
        const small = compileRegistrationSourceRandomness(10, 10);
        const large = compileRegistrationSourceRandomness(20, 10);
        expect(large.sourceSeedCount).toBeGreaterThanOrEqual(
            small.sourceSeedCount,
        );
        expect(operationSeedCount(profile)).toBe(2n * 7n + 2n * 10n);
        expect(large.comparisonHashPermutations).toBe(
            large.families.reduce(
                (sum, family) =>
                    sum +
                    family.comparisonSourcePermutations +
                    family.commitmentPermutations +
                    family.commonPermutations,
                0n,
            ),
        );
    });
});
