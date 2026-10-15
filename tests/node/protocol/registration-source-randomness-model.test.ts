import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    spongePermutations,
    shake256RateBytes,
} from '#tests/node/protocol/reference/sponge-permutations.js';
import { compilePreparationFamilyInventory } from '#tests/preparation-ledger-model.js';
import { compileRegistrationSourceRandomness } from '#tests/registration-source-randomness-model.js';
import { reductionConstructorOperands } from '#tests/security-margin/constructor-operands.js';
import {
    deriveSupportedProfile,
    supportedProfileRanges,
} from '#tests/supported-profile-model.js';

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
    it('reproduces the native source and encryption stream prefixes', () => {
        const profile = deriveSupportedProfile(3, 2);
        const modulus = profile.ciphertext.modulus;
        const modulusBytes = Buffer.alloc(
            Math.ceil(modulus.toString(2).length / 8),
        );
        for (let index = 0; index < modulusBytes.length; index++)
            modulusBytes[index] = Number((modulus >> BigInt(8 * index)) & 255n);
        const word = (value: number | bigint, bytes: 2 | 4) => {
            const encoded = Buffer.alloc(bytes);
            if (bytes === 2) encoded.writeUInt16LE(Number(value));
            else encoded.writeUInt32LE(Number(value));
            return encoded;
        };
        const prefix = (purpose: number) =>
            createHash('shake256', { outputLength: 32 })
                .update(
                    Buffer.concat([
                        Buffer.from('sealed-lattice/source-private/v1'),
                        Uint8Array.of(purpose),
                        Buffer.alloc(64, 3),
                        Buffer.alloc(64, 29),
                        Buffer.alloc(64, 23),
                        word(fixedModulusBfvInputs.polynomialDegree, 4),
                        word(modulusBytes.length, 2),
                        modulusBytes,
                        word(
                            compileCommonMatrixSamplingCensus(profile)
                                .fheBitsPerCoefficient,
                            4,
                        ),
                    ]),
                )
                .digest('hex');
        // The native encrypted-source tests pin the same prefixes for this
        // seed, poll and owner.
        expect(prefix(0)).toBe(
            'b98d123ff68d01b9e491483817f4730d59bfe7f4e0c3324457048ba86412b4db',
        );
        expect(prefix(1)).toBe(
            '1885cddfe0f23df93986e65b3db6b6c4daa5154ade55d3dcb5e278067d036853',
        );
    });
    it('covers the private-input length class of every catalogue family', () => {
        // The full-roster poll of each option count admits every profile of
        // that count, so together these polls admit the whole catalogue.
        const { participants, options } = supportedProfileRanges();
        const admitted = new Set<bigint>();
        for (
            let optionCount = options.minimum;
            optionCount <= options.maximum;
            optionCount++
        )
            for (const family of compileRegistrationSourceRandomness(
                participants.maximum,
                optionCount,
            ).families)
                admitted.add(family.sourceInputBytes);
        const catalogue = new Set<bigint>();
        for (const family of compilePreparationFamilyInventory()) {
            const modulusBytes = BigInt(
                Math.ceil(family.modulus.toString(2).length / 8),
            );
            // The frame carries the modulus length in a 16-bit word.
            expect(modulusBytes).toBeLessThan(1n << 16n);
            catalogue.add(
                BigInt(
                    Buffer.byteLength('sealed-lattice/source-private/v1') +
                        1 +
                        3 * 64 +
                        4 +
                        2 +
                        4,
                ) + modulusBytes,
            );
        }
        expect(admitted).toEqual(catalogue);
    });
    it('fits the stream coins of every family within the priced stream rows', () => {
        // The reduction never absorbs the private frame: its source and
        // source-encryption stream rows read only expanded coins, up to their
        // input widths.
        const row = (name: string) => {
            const statement = reductionConstructorOperands.statements.find(
                (entry) => entry.name === name,
            );
            expect(statement, name).toBeDefined();
            return statement!;
        };
        const source = row('source stream');
        const encryption = row('source encryption stream');
        const { participants, options } = supportedProfileRanges();
        let families = 0;
        for (
            let optionCount = options.minimum;
            optionCount <= options.maximum;
            optionCount++
        )
            for (const family of compileRegistrationSourceRandomness(
                participants.maximum,
                optionCount,
            ).families) {
                families++;
                expect(
                    8n * family.comparisonMaximumSourceOutputBytes,
                ).toBeLessThanOrEqual(source.inputBits);
                expect(
                    8n * family.comparisonMaximumEncryptionOutputBytes,
                ).toBeLessThanOrEqual(encryption.inputBits);
            }
        expect(families).toBeGreaterThan(0);
    });
    it('retains families admitted before a smaller eventual roster', () => {
        expect(
            compileRegistrationSourceRandomness(20, 20).sourceSeedCount,
        ).toBeGreaterThan(
            compileRegistrationSourceRandomness(3, 20).sourceSeedCount,
        );
        expect(() => compileRegistrationSourceRandomness(2, 2)).toThrow();
    });
});
