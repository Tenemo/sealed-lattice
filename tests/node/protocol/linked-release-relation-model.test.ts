import { describe, expect, it } from 'vitest';

import {
    compileLinkedReleaseRelationCensus,
    createLinkedReleaseRelationModel,
} from '#tests/linked-release-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';

describe('release linked to the original encrypted aggregate share', () => {
    it('checks the key, aggregate decryption, and dense partial release in the same integer relation', () => {
        const sharing = compileWideShareLiftingCensus();
        for (const seed of [0n, 1n, 17n, 987654321n]) {
            const model = createLinkedReleaseRelationModel(seed);
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
        const model = createLinkedReleaseRelationModel();
        const sharing = compileWideShareLiftingCensus();
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
        const model = createLinkedReleaseRelationModel(31n);
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
        const model = createLinkedReleaseRelationModel();
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
        const census = compileLinkedReleaseRelationCensus();
        const prime = compileSmallLimbProofFieldCensus().modulus;
        expect(census.trueDecodingQuotientBound).toBeLessThan(1n << 15n);
        expect(census.trueDecodingCarryBound).toBeLessThan(1n << 29n);
        expect(census.decodingResidualBound).toBeLessThan(prime);
        expect(census.releaseResidualBound).toBeLessThan(prime);
        expect(census.wordColumns).toBe(3 + 8 + 2 + 1 + 2 + 11 + 9 + 5 * 5);
        expect(census.narrowMemberships).toBe(10);
        expect(census.lookupEntries).toBe(71);
        expect(census.affineRows).toBe(655362n);
    });
});
