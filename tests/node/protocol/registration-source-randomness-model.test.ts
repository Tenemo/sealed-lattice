import { describe, expect, it } from 'vitest';

import {
    spongePermutations,
    shake256RateBytes,
} from '#tests/node/protocol/reference/sponge-permutations.js';
import { compileRegistrationSourceRandomness } from '#tests/registration-source-randomness-model.js';

describe('encrypted registration source randomness', () => {
    it.each([
        [3, 2],
        [10, 10],
        [20, 20],
    ])(
        'accounts both streams and every source ciphertext for %i/%i',
        (maximum, options) => {
            const value = compileRegistrationSourceRandomness(maximum, options);
            expect(value.freshSeedBytes).toBe(
                64n * BigInt(value.families.length),
            );
            expect(value.gaussianSamples).toBe(
                5n * 65536n * BigInt(value.families.length),
            );
            expect(value.sparseCalls).toBe(2n * BigInt(value.families.length));
            expect(value.sourceCiphertextSamples).toBe(64n);
            expect(value.sharedAuxiliaryKeySamples).toBe(33n);
            for (const family of value.families) {
                const privateFrame = Buffer.concat([
                    Buffer.from('sealed-lattice/source-private/v1'),
                    Buffer.alloc(1 + 64 + 64 + 64 + 4 + 2),
                    Buffer.alloc(Number(family.modulusBytes)),
                    Buffer.alloc(4),
                ]);
                expect(family.sourceInputBytes).toBe(
                    BigInt(privateFrame.length),
                );
                expect(family.minimumSourceOutputBytes).toBe(
                    4n * 1024n + 20n * 65536n,
                );
                expect(family.minimumEncryptionOutputBytes).toBe(
                    4n * 256n + 4n * 20n * 65536n,
                );
                expect(
                    family.comparisonMaximumSourceOutputBytes,
                ).toBeGreaterThan(family.minimumSourceOutputBytes);
                expect(
                    family.comparisonMaximumEncryptionOutputBytes,
                ).toBeGreaterThan(family.minimumEncryptionOutputBytes);
                expect(family.comparisonEncryptionPermutations).toBe(
                    spongePermutations(
                        BigInt(privateFrame.length),
                        family.comparisonMaximumEncryptionOutputBytes,
                        shake256RateBytes,
                    ),
                );
                expect(family.sourceCommonCalls).toBe(64n);
            }
        },
    );
    it('retains families admitted before a smaller eventual roster', () => {
        expect(
            compileRegistrationSourceRandomness(20, 20).sourceSeedCount,
        ).toBeGreaterThan(
            compileRegistrationSourceRandomness(3, 20).sourceSeedCount,
        );
        expect(() => compileRegistrationSourceRandomness(2, 2)).toThrow();
    });
});
