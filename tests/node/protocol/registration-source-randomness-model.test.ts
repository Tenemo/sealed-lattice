import { describe, expect, it } from 'vitest';

import { operationSeedCount } from '#tests/operation-seed-model.js';
import { compileRegistrationSourceRandomness } from '#tests/registration-source-randomness-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

const unsigned = (bytes: number, value: bigint) => {
    const result = Buffer.alloc(bytes);
    for (let index = 0; index < bytes; index++) {
        result[index] = Number(value & 255n);
        value >>= 8n;
    }
    return result;
};
const variable = (value: Buffer) =>
    Buffer.concat([unsigned(4, BigInt(value.length)), value]);
const item = (type: number, value: Buffer) =>
    Buffer.concat([
        unsigned(2, BigInt(type)),
        unsigned(4, BigInt(value.length)),
        value,
    ]);
const tuple = (items: Buffer[]) =>
    Buffer.concat([
        unsigned(2, 1n),
        unsigned(2, 1n),
        unsigned(4, BigInt(items.length)),
        ...items,
    ]);
const permutations = (input: number, output: number) => {
    // SHAKE padding always starts another absorption block, even at an
    // exact boundary; the first output block is already that permutation.
    let count = 1;
    for (let position = 136; position <= input; position += 136) count++;
    for (let position = 136; position < output; position += 136) count++;
    return BigInt(count);
};

describe('original registration source randomness and hash work', () => {
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
                    item(
                        2,
                        variable(
                            Buffer.from(
                                'sealed-lattice/fhe-source-randomness/v1',
                            ),
                        ),
                    ),
                    item(1, Buffer.alloc(1952)),
                    item(6, Buffer.alloc(64)),
                    item(6, Buffer.alloc(64)),
                    item(
                        1,
                        variable(Buffer.alloc(Number(family.modulusBytes))),
                    ),
                    item(4, unsigned(8, BigInt(family.sampleBits))),
                    item(1, Buffer.alloc(64)),
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
                    permutations(
                        source.length,
                        Number(family.comparisonMaximumSourceOutputBytes),
                    ),
                );
                const commitmentPrefix = tuple([
                    item(
                        2,
                        variable(
                            Buffer.from('sealed-lattice/registered-fhe-key/v1'),
                        ),
                    ),
                    item(1, Buffer.alloc(1952)),
                    item(1, Buffer.alloc(64)),
                    item(6, Buffer.alloc(64)),
                    item(6, Buffer.alloc(64)),
                    item(
                        1,
                        variable(Buffer.alloc(Number(family.modulusBytes))),
                    ),
                    item(4, unsigned(8, BigInt(family.sampleBits))),
                    item(1, variable(Buffer.alloc(0))),
                ]);
                const commitmentBytes =
                    BigInt(commitmentPrefix.length) +
                    family.publicCoordinateBytes;
                expect(family.commitmentInputBytes).toBe(commitmentBytes);
                expect(family.commitmentPermutations).toBe(
                    permutations(Number(commitmentBytes), 64),
                );
                const commonInput = Buffer.concat([
                    Buffer.from('synthetic-full-setup-witness/1'),
                    unsigned(4, 14n),
                    Buffer.from('common-fhe-a-0'),
                ]);
                expect(family.commonInputBytes).toBe(
                    BigInt(commonInput.length),
                );
                expect(family.commonOutputBytes).toBe(
                    65536n * BigInt(family.sampleBits / 8),
                );
                expect(family.commonPermutations).toBe(
                    permutations(
                        commonInput.length,
                        Number(family.commonOutputBytes),
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
        expect(operationSeedCount(profile)).toBe(2n * 4n + 2n * 10n);
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
