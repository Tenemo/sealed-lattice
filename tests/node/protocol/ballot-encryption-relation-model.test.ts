import { describe, expect, it } from 'vitest';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import {
    ballotPackingMatrix,
    compileBallotEncryptionColumnLayout,
    compileBallotEncryptionRelationCensus,
    createBallotEncryptionRelationModel,
} from '#tests/ballot-encryption-relation-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    completionProfile,
    deriveSupportedProfile,
} from '#tests/supported-profile-model.js';

describe('linked scored ballot encryption', () => {
    it('keeps the full plaintext interval and exact score range in the committed columns', () => {
        const layout = compileBallotEncryptionColumnLayout(completionProfile());
        expect(
            layout.columns.slice(18, 22).map((column) => column.name),
        ).toEqual([
            'plaintext-lower-word',
            'plaintext-complement-word',
            'packing-quotient',
            'score-minus-one',
        ]);
        expect(layout.zeroProducts).toEqual([
            [26, 27],
            [28, 29],
        ]);
        const admitted = (column: number, value: number) =>
            layout.lookups
                .filter((lookup) => lookup.column === column)
                .every((lookup) => value >= 0 && value * lookup.scale <= 65535);
        for (const value of [-1, 0, 1, 9, 10, 127, 128, 65535, 65536]) {
            expect(admitted(21, value)).toBe(value >= 0 && value <= 9);
            expect(admitted(8, value)).toBe(value >= 0 && value <= 127);
            expect(admitted(18, value)).toBe(value >= 0 && value <= 65535);
        }
        const endpointValues = [];
        for (let lower = 0; lower <= 65535; lower++) {
            const complement = 12288 - lower;
            if (complement >= 0 && complement <= 65535)
                endpointValues.push(lower - 6144);
        }
        expect(new Set(endpointValues).size).toBe(12289);
        expect(Math.min(...endpointValues)).toBe(-6144);
        expect(Math.max(...endpointValues)).toBe(6144);
        expect(layout.maximumLiveProductColumns).toBe(1);
        expect(
            compileBallotEncryptionRelationCensus(completionProfile())
                .zeroProductCacheBytes,
        ).toBe(2097152n);
    });

    it('refuses truncated FHE limbs and direct auxiliary proof-field aliases', () => {
        const model = createBallotEncryptionRelationModel(completionProfile(), [
            1n,
            10n,
        ]);
        for (const coefficients of [
            model.fhe.common,
            model.fhe.publicKey,
            ...model.fhe.ciphertext,
        ]) {
            const original = coefficients[0];
            coefficients[0] += (original < 0n ? -1n : 1n) * (1n << 768n);
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
            Number(((value % 12289n) + 12289n) % 12289n);
        for (const scores of [
            [1n, 1n],
            [1n, 10n],
            [10n, 1n],
            [10n, 10n],
            [5n, 9n],
        ]) {
            const model = createBallotEncryptionRelationModel(
                completionProfile(),
                scores,
            );
            expect(model.verify()).toBe(true);
            expect(
                Object.values(model.rows())
                    .flat()
                    .every((value) => value === 0n),
            ).toBe(true);
            expect(model.rows().fhe).toHaveLength(2 * 8 * 64);
            for (let option = 0; option < 2; option++)
                for (let opponent = 0; opponent < 2; opponent++)
                    expect(
                        model.decodedSlots[option * model.window + opponent],
                    ).toBe(reduce(2n * (scores[opponent] - scores[option])));
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

    it('refuses individually valid encryptions of different scores and a forged error repair', () => {
        const model = createBallotEncryptionRelationModel(
            completionProfile(),
            [1n, 10n],
            [10n, 1n],
        );
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

    it('refuses out-of-domain scores even when every encryption equality holds', () => {
        for (const scores of [
            [0n, 1n],
            [1n, 11n],
            [-1n, 10n],
        ]) {
            const model = createBallotEncryptionRelationModel(
                completionProfile(),
                scores,
            );
            expect(
                Object.values(model.rows())
                    .flat()
                    .every((value) => value === 0n),
            ).toBe(true);
            expect(model.verify()).toBe(false);
        }
    });

    it('admits both centered plaintext endpoints and rejects interval aliases', () => {
        const model = createBallotEncryptionRelationModel(completionProfile(), [
            1n,
            1n,
        ]);
        for (const lower of [0n, 6144n, 12288n]) {
            model.plaintextWords[0] = lower;
            model.plaintextComplements[0] = 12288n - lower;
            expect(model.rangeValid()).toBe(true);
            expect(model.rows().interval[0]).toBe(0n);
        }
        model.plaintextWords[0] = 12289n;
        model.plaintextComplements[0] = 65535n;
        expect(model.rangeValid()).toBe(true);
        expect(model.rows().interval[0]).not.toBe(0n);
        expect(model.verify()).toBe(false);
        model.plaintextComplements[0] = -1n;
        expect(model.rangeValid()).toBe(false);
    });

    it('fits the actual auxiliary decoding margin and full field residuals', () => {
        const census =
            compileBallotEncryptionRelationCensus(completionProfile());
        // Only the proof game's single good key has a secret/noise bound.
        expect(census.auxiliaryGoodKeyNoiseBound).toBe((2n * 256n + 1n) * 64n);
        expect(2n * census.auxiliaryGoodKeyNoiseBound).toBeLessThan(
            auxiliaryInputEncryptionParameters.scale,
        );
        expect(census.residualBound).toBeLessThan(
            compileSmallLimbProofFieldCensus().modulus,
        );
        expect(census.trueQuotientBound).toBeLessThan(1n << 15n);
        expect(census.trueCarryBound).toBeLessThan(1n << 15n);
        expect(census.packingQuotientBound).toBe(50n);
        expect(census.wordColumns).toBe(26);
        expect(census.lookupEntries).toBe(31);
        expect(census.affineRows).toBe(18n * 65536n + 2n * 4096n + 4n);
    });

    it('encrypts in every public limb of the smallest and largest ciphertext moduli', () => {
        for (const [participantCount, optionCount] of [
            [3, 2],
            [20, 20],
        ]) {
            const profile = deriveSupportedProfile(
                participantCount,
                optionCount,
            );
            const limbs = Math.ceil(profile.ciphertext.bits / 96);
            const model = createBallotEncryptionRelationModel(profile, [
                1n,
                10n,
            ]);
            expect(model.verify()).toBe(true);
            expect(model.rows().fhe).toHaveLength(2 * limbs * 64);
            expect(model.carries[0].flat().some((value) => value !== 0n)).toBe(
                true,
            );
            const original = model.fhe.ciphertext[0][0];
            model.fhe.ciphertext[0][0] +=
                (original < 0n ? -1n : 1n) * (1n << BigInt(96 * limbs));
            expect(model.rows().fhe.every((value) => value === 0n)).toBe(true);
            expect(model.verify()).toBe(false);
            model.fhe.ciphertext[0][0] = original;
            expect(
                createBallotEncryptionRelationModel(profile, [
                    1n,
                    11n,
                ]).verify(),
            ).toBe(false);
            expect(
                compileBallotEncryptionColumnLayout(profile).wordColumns,
            ).toBe(compileBallotEncryptionRelationCensus(profile).wordColumns);
        }
    });
    it('embeds the full-size packing in the selected subring with its literal-score orbit', () => {
        const modulus = 12289n;
        const power = (value: bigint, exponent: number) => {
            let result = 1n;
            for (let remaining = exponent; remaining > 0; remaining >>= 1) {
                if (remaining % 2) result = (result * value) % modulus;
                value = (value * value) % modulus;
            }
            return result;
        };
        const packing = ballotPackingMatrix(65536, 3);
        expect(packing.activeSlots).toBe(1024);
        const evaluate = (coefficients: readonly bigint[], point: bigint) => {
            let result = 0n;
            for (let index = 2047; index >= 0; index--)
                result = (result * point + coefficients[32 * index]) % modulus;
            return (result + modulus) % modulus;
        };
        const root = power(11n, 3);
        for (const [selected, coefficients] of packing.columns.entries()) {
            expect(
                coefficients.every(
                    (value, index) => index % 32 === 0 || value === 0n,
                ),
            ).toBe(true);
            for (const slot of [
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 101, 1023,
            ]) {
                const exponent = Number(powerModulo4096(slot));
                const option = Math.floor(slot / 4),
                    opponent = slot % 4;
                const expected =
                    option < 3 && opponent < 3
                        ? 2n *
                          BigInt(
                              Number(opponent === selected) -
                                  Number(option === selected),
                          )
                        : 0n;
                expect(evaluate(coefficients, power(root, exponent))).toBe(
                    (expected + modulus) % modulus,
                );
                expect(
                    evaluate(coefficients, power(root, 4096 - exponent)),
                ).toBe(BigInt(slot === selected));
            }
        }
        function powerModulo4096(exponent: number) {
            let value = 1;
            for (let index = 0; index < exponent; index++)
                value = (value * 5) % 4096;
            return value;
        }
    });
});
