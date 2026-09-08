import { describe, expect, it } from 'vitest';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import {
    compileBallotEncryptionColumnLayout,
    compileBallotEncryptionRelationCensus,
    createBallotEncryptionRelationModel,
} from '#tests/ballot-encryption-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';

describe('linked scored ballot encryption', () => {
    it('keeps the full plaintext interval and exact score range in the committed columns', () => {
        const layout = compileBallotEncryptionColumnLayout();
        expect(
            layout.columns.slice(20, 23).map((column) => column.name),
        ).toEqual([
            'plaintext-lower-word',
            'packing-quotient',
            'score-minus-one',
        ]);
        expect(layout.zeroProducts).toEqual([
            [27, 28],
            [29, 30],
            [20, 31],
        ]);
        const admitted = (column: number, value: number) =>
            layout.lookups
                .filter((lookup) => lookup.column === column)
                .every((lookup) => value >= 0 && value * lookup.scale <= 65535);
        for (const value of [-1, 0, 1, 9, 10, 127, 128, 65535, 65536]) {
            expect(admitted(22, value)).toBe(value >= 0 && value <= 9);
            expect(admitted(9, value)).toBe(value >= 0 && value <= 127);
            expect(admitted(20, value)).toBe(value >= 0 && value <= 65535);
        }
        const endpointValues = [];
        for (let high = 0; high <= 1; high++)
            for (let low = 0; low <= 65535; low++)
                if (low * high === 0)
                    endpointValues.push(low + 65536 * high - 32768);
        expect(new Set(endpointValues).size).toBe(65537);
        expect(Math.min(...endpointValues)).toBe(-32768);
        expect(Math.max(...endpointValues)).toBe(32768);
        expect(layout.maximumLiveProductColumns).toBe(2);
        expect(
            compileBallotEncryptionRelationCensus().zeroProductCacheBytes,
        ).toBe(4194304n);
    });

    it('rejects truncated FHE limbs and direct auxiliary proof-field aliases', () => {
        const model = createBallotEncryptionRelationModel([1n, 10n]);
        for (const coefficients of [
            model.fhe.common,
            model.fhe.publicKey,
            ...model.fhe.ciphertext,
        ]) {
            const original = coefficients[0];
            coefficients[0] += (original < 0n ? -1n : 1n) * (1n << 864n);
            expect(model.rows().fhe.every((value) => value === 0n)).toBe(true);
            expect(model.verify()).toBe(false);
            coefficients[0] = original;
        }
        const prime = compileSmallLimbProofFieldCensus().modulus;
        for (const coefficients of [
            model.auxiliaryCiphertext.common,
            model.auxiliaryCiphertext.publicKey,
            ...model.auxiliaryCiphertext.ciphertext,
        ]) {
            const original = coefficients[0];
            coefficients[0] += prime;
            expect(
                model.rows().auxiliary.every((value) => value % prime === 0n),
            ).toBe(true);
            expect(model.verify()).toBe(false);
            coefficients[0] = original;
        }
        expect(model.verify()).toBe(true);
        for (const ciphertext of [
            model.fhe.ciphertext,
            model.auxiliaryCiphertext.ciphertext,
        ]) {
            ciphertext.push([...ciphertext[0]]);
            expect(model.verify()).toBe(false);
            ciphertext.pop();
        }
        expect(model.verify()).toBe(true);
        model.auxiliaryCiphertext.ciphertext[0].pop();
        expect(model.verify()).toBe(false);
    });

    it('encrypts the same complete score vector in both ciphertexts and the exact comparison windows', () => {
        const reduce = (value: bigint) =>
            Number(((value % 65537n) + 65537n) % 65537n);
        for (const scores of [
            [1n, 1n],
            [1n, 10n],
            [10n, 1n],
            [10n, 10n],
            [5n, 9n],
        ]) {
            const model = createBallotEncryptionRelationModel(scores);
            expect(model.verify()).toBe(true);
            expect(
                Object.values(model.rows())
                    .flat()
                    .every((value) => value === 0n),
            ).toBe(true);
            expect(model.rows().fhe).toHaveLength(2 * 9 * 64);
            for (let option = 0; option < 2; option++)
                for (let rank = 0; rank < 2; rank++)
                    for (let opponent = 0; opponent < 2; opponent++)
                        expect(
                            model.decodedSlots[
                                (option * 2 + rank) * model.window + opponent
                            ],
                        ).toBe(
                            reduce(2n * (scores[opponent] - scores[option])),
                        );
            expect(
                model.decodedSlots.slice(
                    model.activeSlots,
                    model.activeSlots + 2,
                ),
            ).toEqual(scores.map(Number));
            expect(
                model.decodedSlots
                    .slice(model.activeSlots + 2)
                    .every((value) => value === 0),
            ).toBe(true);
            expect(model.auxiliaryCiphertext.decoded).toEqual([
                ...scores,
                0n,
                0n,
                0n,
                0n,
                0n,
                0n,
            ]);
        }
    });

    it('rejects individually valid encryptions of different scores and a forged error repair', () => {
        const model = createBallotEncryptionRelationModel([1n, 10n], [10n, 1n]);
        expect(model.rows().fhe.every((value) => value === 0n)).toBe(true);
        expect(model.rows().packing.every((value) => value === 0n)).toBe(true);
        expect(model.auxiliaryCiphertext.decoded.slice(0, 2)).toEqual([
            10n,
            1n,
        ]);
        expect(model.verify()).toBe(false);
        model.auxiliaryCiphertext.errors[0][0] +=
            9n * auxiliaryInputEncryptionParameters.scale;
        model.auxiliaryCiphertext.errors[0][1] -=
            9n * auxiliaryInputEncryptionParameters.scale;
        expect(model.rows().auxiliary.every((value) => value === 0n)).toBe(
            true,
        );
        expect(model.rangeValid()).toBe(false);
    });

    it('rejects out-of-domain scores even when every encryption equality holds', () => {
        for (const scores of [
            [0n, 1n],
            [1n, 11n],
            [-1n, 10n],
        ]) {
            const model = createBallotEncryptionRelationModel(scores);
            expect(
                Object.values(model.rows())
                    .flat()
                    .every((value) => value === 0n),
            ).toBe(true);
            expect(model.verify()).toBe(false);
        }
    });

    it('admits both centered plaintext endpoints and excludes a high-bit alias', () => {
        const model = createBallotEncryptionRelationModel([1n, 1n]);
        model.plaintextWords[0] = 0n;
        model.plaintextHighBits[0] = 0n;
        expect(model.rangeValid()).toBe(true);
        model.plaintextHighBits[0] = 1n;
        expect(model.rangeValid()).toBe(true);
        model.plaintextWords[0] = 1n;
        expect(model.rangeValid()).toBe(false);
    });

    it('fits the actual auxiliary decoding margin and full field residuals', () => {
        const census = compileBallotEncryptionRelationCensus();
        expect(census.auxiliaryNoiseBound).toBe((2n * 10n * 256n + 1n) * 64n);
        expect(2n * census.auxiliaryNoiseBound).toBeLessThan(
            auxiliaryInputEncryptionParameters.scale,
        );
        expect(census.residualBound).toBeLessThan(
            compileSmallLimbProofFieldCensus().modulus,
        );
        expect(census.trueQuotientBound).toBeLessThan(1n << 15n);
        expect(census.trueCarryBound).toBeLessThan(1n << 15n);
        expect(census.packingQuotientBound).toBe(50n);
        expect(census.wordColumns).toBe(27);
        expect(census.lookupEntries).toBe(32);
        expect(census.affineRows).toBe(19n * 65536n + 2n * 4096n + 4n);
    });
});
