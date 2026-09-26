import { describe, expect, it } from 'vitest';

import {
    compileLinkedReleaseColumnLayout,
    compileLinkedReleaseRelationCensus,
    createLinkedReleaseRelationModel,
} from '#tests/linked-release-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    completionProfile,
    deriveSupportedProfile,
} from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

describe('release linked to the original encrypted aggregate share', () => {
    it('places every signed range in complete words and constrains each high word', () => {
        const layout = compileLinkedReleaseColumnLayout(completionProfile());
        expect(layout.wordColumns).toBe(59);
        expect(layout.positiveSecretColumn).toBe(59);
        expect(layout.negativeSecretColumn).toBe(60);
        expect(
            layout.columns.find((column) => column.name === 'aggregate-share'),
        ).toMatchObject({ firstColumn: 3, bits: 120, wordCount: 8 });
        expect(
            layout.columns.find((column) => column.name === 'release-noise'),
        ).toMatchObject({ firstColumn: 16, bits: 144, wordCount: 9 });
        // The 144-bit release noise and quotient fill their words; each
        // 72-bit carry leaves a high byte.
        expect(layout.lookups.slice(layout.wordColumns)).toEqual([
            { column: 2, factor: 512n },
            { column: 10, factor: 256n },
            { column: 12, factor: 256n },
            { column: 15, factor: 4n },
            { column: 38, factor: 256n },
            { column: 43, factor: 256n },
            { column: 48, factor: 256n },
            { column: 53, factor: 256n },
            { column: 58, factor: 256n },
        ]);
        for (const { factor } of layout.lookups) {
            const firstOutside = 65536n / factor;
            expect((firstOutside - 1n) * factor).toBeLessThan(65536n);
            expect(firstOutside * factor).toBe(65536n);
        }
    });
    it('rejects high-limb aliases in every public polynomial family', () => {
        const model = createLinkedReleaseRelationModel(completionProfile());
        for (const [coefficients, bits] of [
            [model.common, 192],
            [model.publicKey, 192],
            [model.encryptedConstant, 192],
            [model.encryptedLinear, 192],
            [model.targetLinear, 192],
            [model.partial, 288],
        ] as const) {
            const original = coefficients[0];
            coefficients[0] +=
                (original < 0n ? -1n : 1n) * (1n << BigInt(bits));
            expect(
                Object.values(model.rows())
                    .flat()
                    .every((value) => value === 0n),
            ).toBe(true);
            expect(model.verify()).toBe(false);
            coefficients[0] = original;
        }
        expect(model.verify()).toBe(true);
        model.encryptedLinear.pop();
        expect(model.verify()).toBe(false);
    });

    it('checks the key, aggregate decryption, and dense partial release in the same integer relation', () => {
        const sharing = shareEncryptionParameters;
        for (const seed of [0n, 1n, 17n, 987654321n]) {
            const model = createLinkedReleaseRelationModel(
                completionProfile(),
                seed,
            );
            expect(model.verify()).toBe(true);
            expect(Object.values(model.rows()).flat()).toHaveLength(10 * 16);
            expect(
                Object.values(model.rows())
                    .flat()
                    .every((value) => value === 0n),
            ).toBe(true);
            expect(
                model.decodedPhase.map((value) => {
                    const absolute = value < 0n ? -value : value;
                    const decoded =
                        (absolute + sharing.scale / 2n) / sharing.scale;
                    return value < 0n ? -decoded : decoded;
                }),
            ).toEqual(model.share);
        }
    });

    it('rejects a valid partial decryption of a different hidden share, including its attempted noise repair', () => {
        const model = createLinkedReleaseRelationModel(completionProfile());
        const sharing = shareEncryptionParameters;
        model.share[0] += 1n;
        model.derivePartial();
        expect(model.rows().partial.every((value) => value === 0n)).toBe(true);
        expect(model.verify()).toBe(false);
        model.decodingError[0] -= sharing.scale;
        expect(model.rows().decoding.every((value) => value === 0n)).toBe(true);
        expect(model.rangeValid()).toBe(false);
        expect(model.verify()).toBe(false);
    });

    it('rejects another bounded recipient key and a changed release target', () => {
        const model = createLinkedReleaseRelationModel(
            completionProfile(),
            31n,
        );
        model.recipientSecret[0] = 0n;
        model.recipientSecret[4] = 1n;
        expect(model.verify()).toBe(false);
        model.recipientSecret[4] = 0n;
        model.recipientSecret[0] = 1n;
        expect(model.verify()).toBe(true);
        model.targetLinear[0] += 1n;
        expect(model.verify()).toBe(false);
    });

    it('excludes an exact proof-field alias through the accepted carry bound', () => {
        const model = createLinkedReleaseRelationModel(completionProfile());
        const prime = compileSmallLimbProofFieldCensus().modulus;
        const radix = 1n << 96n;
        const highDigit = (value: bigint) => value / radix;
        const previous = model.encryptedConstant[0];
        model.encryptedConstant[0] += prime;
        model.decodingCarry[0] -=
            highDigit(model.encryptedConstant[0]) - highDigit(previous);
        expect(model.rows().decoding.some((value) => value !== 0n)).toBe(true);
        expect(
            model.rows().decoding.every((value) => value % prime === 0n),
        ).toBe(true);
        expect(model.rangeValid()).toBe(false);
        expect(model.verify()).toBe(false);
    });

    it('derives the full residual bound and word inventory', () => {
        const census = compileLinkedReleaseRelationCensus(completionProfile());
        const prime = compileSmallLimbProofFieldCensus().modulus;
        expect(census.trueDecodingQuotientBound).toBeLessThan(1n << 15n);
        expect(census.trueDecodingCarryBound).toBeLessThan(1n << 29n);
        expect(census.decodingResidualBound).toBeLessThan(prime);
        expect(census.releaseResidualBound).toBeLessThan(prime);
        expect(census.wordColumns).toBe(3 + 8 + 2 + 1 + 2 + 9 + 9 + 5 * 5);
        expect(census.narrowMemberships).toBe(9);
        expect(census.lookupEntries).toBe(59 + 9);
        expect(census.affineRows).toBe(655362n);
    });

    it('keeps the whole-word decoding bounds below the proof field for every roster size', () => {
        const prime = compileSmallLimbProofFieldCensus().modulus;
        for (
            let participantCount = 3;
            participantCount <= 20;
            participantCount++
        ) {
            const census = compileLinkedReleaseRelationCensus(
                deriveSupportedProfile(participantCount, 2),
            );
            expect(census.trueDecodingCarryBound).toBeLessThan(1n << 29n);
            expect(census.decodingResidualBound).toBeLessThan(prime);
        }
    });

    it('links the release at two shares, capped share widths and the largest profile', () => {
        for (const [participantCount, optionCount] of [
            [3, 2],
            [16, 2],
            [20, 20],
        ]) {
            const profile = deriveSupportedProfile(
                participantCount,
                optionCount,
            );
            for (const seed of [0n, 7n]) {
                const model = createLinkedReleaseRelationModel(profile, seed);
                expect(model.verify()).toBe(true);
                model.share[0] += 1n;
                model.derivePartial();
                expect(model.verify()).toBe(false);
            }
            const census = compileLinkedReleaseRelationCensus(profile);
            const prime = compileSmallLimbProofFieldCensus().modulus;
            expect(census.decodingResidualBound).toBeLessThan(prime);
            expect(census.releaseResidualBound).toBeLessThan(prime);
            expect(
                compileLinkedReleaseColumnLayout(profile).columns.find(
                    (column) => column.name === 'aggregate-share',
                ),
            ).toMatchObject({ bits: profile.releaseLifting.shareBits });
        }
    });
});
