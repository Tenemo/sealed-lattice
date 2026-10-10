import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { reduceSignedDigitModel } from '#tests/setup-randomness-model.js';
import {
    boundSetupShareArithmetic,
    compileSetupShareArithmeticBounds,
} from '#tests/setup-share-arithmetic-model.js';
import { listSupportedProfiles } from '#tests/supported-profile-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

const absolute = (value: bigint) => (value < 0n ? -value : value);
const digit = (value: bigint, limb: number, radix: bigint) =>
    (value < 0n ? -1n : 1n) *
    ((absolute(value) / radix ** BigInt(limb)) % radix);
const product = (left: readonly bigint[], right: readonly bigint[]) => {
    const output = Array<bigint>(left.length).fill(0n);
    for (let first = 0; first < left.length; first++)
        for (let second = 0; second < right.length; second++)
            output[(first + second) % left.length] +=
                left[first] *
                right[second] *
                (first + second < left.length ? 1n : -1n);
    return output;
};
const floorDivide = (value: bigint, divisor: bigint) =>
    value / divisor - (value < 0n && value % divisor !== 0n ? 1n : 0n);

describe('generated share arithmetic bounds', () => {
    it('matches direct monomial evaluations, both ciphertext components and signed carry rows', () => {
        const secret = [1n, 0n, -1n, 0n];
        const ephemeral = [1n, -1n, 0n, 0n];
        const corrections = new Set<bigint>();
        const quotientSigns = new Set<number>();
        for (const [modulus, radix, coefficientBits] of [
            [47n, 8n, 5],
            [173n, 16n, 7],
        ] as const) {
            const scale = 3n;
            const radius = 1n << BigInt(coefficientBits - 1);
            const coefficientAlphabet = [-radius, -1n, 0n, 1n, radius - 1n];
            const half = modulus / 2n;
            const publicInputs = [
                [0n, 0n, 0n, 0n],
                [half, half, half, half],
                [-half, half, -half, half],
                [1n, 0n, 0n, 0n],
                [0n, 1n, -1n, half],
            ];
            for (const publicKey of publicInputs)
                for (const sharingDegree of [1, 2, 3])
                    for (const point of [0, 1, 3, 6])
                        for (
                            let pattern = 0;
                            pattern < coefficientAlphabet.length;
                            pattern++
                        ) {
                            const message = [...secret];
                            const low = Array<bigint>(secret.length).fill(0n);
                            const high = [...low];
                            const offset = [...low];
                            for (
                                let coefficient = 1;
                                coefficient <= sharingDegree;
                                coefficient++
                            )
                                for (
                                    let position = 0;
                                    position < secret.length;
                                    position++
                                ) {
                                    const value =
                                        coefficientAlphabet[
                                            (position + pattern + coefficient) %
                                                coefficientAlphabet.length
                                        ];
                                    const exponent =
                                        position + point * coefficient;
                                    const target = exponent % secret.length;
                                    const sign =
                                        Math.floor(exponent / secret.length) %
                                            2 ===
                                        0
                                            ? 1n
                                            : -1n;
                                    message[target] += sign * value;
                                    low[target] +=
                                        sign *
                                        ((((value % radix) + radix) % radix) -
                                            radix / 2n);
                                    high[target] +=
                                        sign * floorDivide(value, radix);
                                    offset[target] +=
                                        sign * scale * (radix / 2n);
                                }
                            const products = product(publicKey, ephemeral);
                            const limbProducts = [0, 1].map((limb) =>
                                product(
                                    publicKey.map((value) =>
                                        digit(value, limb, radix),
                                    ),
                                    ephemeral,
                                ),
                            );
                            for (const withMessage of [true, false]) {
                                const bound = boundSetupShareArithmetic(
                                    modulus,
                                    radix,
                                    2n,
                                    1n,
                                    scale,
                                    sharingDegree,
                                    coefficientBits,
                                    withMessage,
                                );
                                assert.ok(
                                    bound.maximumQuotientEstimate <
                                        bound.leadingModulusDigit,
                                );
                                for (
                                    let position = 0;
                                    position < secret.length;
                                    position++
                                ) {
                                    const error = BigInt(
                                        ((position + pattern) % 3) - 1,
                                    );
                                    assert.equal(
                                        scale * message[position],
                                        scale *
                                            (secret[position] +
                                                low[position] +
                                                radix * high[position]) +
                                            offset[position],
                                    );
                                    assert.ok(
                                        absolute(message[position]) <=
                                            bound.maximumMessage,
                                    );
                                    assert.ok(
                                        absolute(low[position]) <=
                                            bound.maximumLowSum,
                                    );
                                    assert.ok(
                                        absolute(high[position]) <=
                                            bound.maximumHighSum,
                                    );
                                    assert.ok(
                                        absolute(offset[position]) <=
                                            bound.maximumOffset,
                                    );
                                    const raw = [
                                        limbProducts[0][position] +
                                            error +
                                            (withMessage
                                                ? scale *
                                                  (message[position] % radix)
                                                : 0n),
                                        limbProducts[1][position] +
                                            (withMessage
                                                ? scale *
                                                  (message[position] / radix)
                                                : 0n),
                                    ];
                                    assert.ok(
                                        absolute(raw[0]) <= bound.maximumRawLow,
                                    );
                                    assert.ok(
                                        absolute(raw[1]) <=
                                            bound.maximumRawHigh,
                                    );
                                    const firstCarry = floorDivide(
                                        raw[0],
                                        radix,
                                    );
                                    const finalCarry = floorDivide(
                                        raw[1] + firstCarry,
                                        radix,
                                    );
                                    assert.ok(
                                        absolute(firstCarry) <=
                                            bound.maximumFirstNormalizationCarry,
                                    );
                                    assert.ok(
                                        absolute(finalCarry) <=
                                            bound.maximumFinalNormalizationCarry,
                                    );
                                    const value =
                                        products[position] +
                                        error +
                                        (withMessage
                                            ? scale * message[position]
                                            : 0n);
                                    assert.ok(
                                        absolute(value) <=
                                            bound.maximumRawInteger,
                                    );
                                    let expected =
                                        ((value % modulus) + modulus) % modulus;
                                    if (expected > half) expected -= modulus;
                                    const reduced = reduceSignedDigitModel(
                                        raw,
                                        radix,
                                        modulus,
                                    );
                                    assert.equal(reduced.remainder, expected);
                                    assert.ok(
                                        reduced.estimate <=
                                            bound.maximumQuotientEstimate,
                                    );
                                    assert.ok(
                                        absolute(reduced.quotient) <=
                                            bound.maximumQuotient,
                                    );
                                    corrections.add(reduced.correction);
                                    quotientSigns.add(
                                        reduced.quotient < 0n
                                            ? -1
                                            : reduced.quotient > 0n
                                              ? 1
                                              : 0,
                                    );
                                    let carry = 0n;
                                    for (const limb of [0, 1]) {
                                        const shared = withMessage
                                            ? digit(
                                                  offset[position],
                                                  limb,
                                                  radix,
                                              ) +
                                              scale *
                                                  (limb === 0
                                                      ? low[position] +
                                                        secret[position]
                                                      : high[position])
                                            : 0n;
                                        assert.ok(
                                            absolute(shared) <=
                                                (limb === 0
                                                    ? bound.maximumSharedLow
                                                    : bound.maximumSharedHigh),
                                        );
                                        const row =
                                            limbProducts[limb][position] -
                                            digit(expected, limb, radix) +
                                            shared +
                                            (limb === 0 ? error : 0n) -
                                            digit(modulus, limb, radix) *
                                                reduced.quotient +
                                            carry;
                                        assert.ok(
                                            absolute(row) <=
                                                (limb === 0
                                                    ? bound.maximumWitnessLowRow
                                                    : bound.maximumWitnessHighRow),
                                        );
                                        if (limb === 0) {
                                            assert.equal(row % radix, 0n);
                                            carry = row / radix;
                                            assert.ok(
                                                absolute(carry) <=
                                                    bound.maximumWitnessCarry,
                                            );
                                        } else assert.equal(row, 0n);
                                    }
                                }
                            }
                        }
        }
        expect(corrections).toEqual(new Set([0n, 1n]));
        expect(quotientSigns).toEqual(new Set([-1, 0, 1]));
    });

    it('checks machine and emitted witness widths for every supported profile against native operands', async () => {
        const native = await readFile(
            new URL(
                '../../../crates/protocol-research/supported-profile/src/lib.rs',
                import.meta.url,
            ),
            'utf8',
        );
        expect(native).toContain(
            'pub const SHARE_EPHEMERAL_SUPPORT: usize = 256;',
        );
        expect(native).toContain('pub const SHARE_SCALE: u32 = 998_244_353;');
        expect(native).toContain('pub const SETUP_QUOTIENT_BITS: usize = 16;');
        expect(native).toContain('pub const SETUP_FHE_CARRY_BITS: usize = 16;');
        expect(native).toContain('pub const SETUP_ERROR_BITS: usize = 7;');
        for (const profile of listSupportedProfiles()) {
            const [constant, linear] =
                compileSetupShareArithmeticBounds(profile);
            expect(constant.maximumRawInteger).toBeGreaterThan(
                linear.maximumRawInteger,
            );
            expect(constant.maximumWitnessCarry).toBeLessThan(
                1n << BigInt(profile.shareLifting.carryBits - 1),
            );
            expect(linear.maximumWitnessCarry).toBeLessThan(1n << 15n);
            expect(constant.maximumOffset).toBeLessThan(1n << 127n);
        }
    });

    it('does not erase the native signed-offset boundary for an unsupported wider limb', () => {
        const bound = boundSetupShareArithmetic(
            shareEncryptionParameters.modulus,
            1n << 96n,
            shareEncryptionParameters.encryptionSupportWeight,
            shareEncryptionParameters.errorBound,
            shareEncryptionParameters.scale,
            6,
            115,
            true,
        );
        expect(bound.maximumOffset).toBeGreaterThanOrEqual(1n << 127n);
        expect(() =>
            boundSetupShareArithmetic(47n, 8n, 2n, 1n, 3n, 1, 3, true),
        ).toThrow();
        expect(() =>
            boundSetupShareArithmetic(64n, 8n, 2n, 1n, 3n, 1, 5, true),
        ).toThrow();
    });
});
