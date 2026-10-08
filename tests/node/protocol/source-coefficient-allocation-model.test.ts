import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { reduceSignedDigitModel } from '#tests/setup-randomness-model.js';
import {
    boundSetupKeyArithmetic,
    compileFheGadgetArithmeticBounds,
    compileSourceArithmeticBounds,
    compileSourceCoefficientAllocation,
    normalizationShrinkResidues,
} from '#tests/source-coefficient-allocation-model.js';
import { listSupportedProfiles } from '#tests/supported-profile-model.js';

const logicalWords = (value: bigint, digitBits: number) => {
    let words = 0;
    for (
        let magnitude = value < 0n ? -value : value;
        magnitude !== 0n;
        magnitude >>= BigInt(digitBits)
    )
        words++;
    return words;
};

// Direct toy negacyclic multiplication, independent of the production limb
// transforms. This checks a marginal distribution, not an encryption scheme.
const coordinate = (
    common: number[],
    secret: number[],
    error: number[],
    modulus: number,
) => {
    const output = [...error];
    for (let left = 0; left < common.length; left++)
        for (let right = 0; right < secret.length; right++) {
            const index = left + right;
            output[index % output.length] -=
                common[left] * secret[right] * (index < output.length ? 1 : -1);
        }
    return output.map((value) => ((value % modulus) + modulus) % modulus);
};

const absolute = (value: bigint) => (value < 0n ? -value : value);
const digit = (value: bigint, limb: number, radix: bigint) =>
    (value < 0n ? -1n : 1n) *
    ((absolute(value) / radix ** BigInt(limb)) % radix);
const negacyclicProduct = (
    left: readonly bigint[],
    right: readonly bigint[],
) => {
    const output = Array<bigint>(left.length).fill(0n);
    for (let i = 0; i < left.length; i++)
        for (let j = 0; j < right.length; j++)
            output[(i + j) % left.length] +=
                left[i] * right[j] * (i + j < left.length ? 1n : -1n);
    return output;
};

describe('source coefficient allocation comparison', () => {
    it('bounds direct integer source equations and every signed carry in finite rings', () => {
        const corrections = new Set<bigint>();
        const quotientSigns = new Set<number>();
        for (const [modulus, radix, secret, exhaustive] of [
            [47n, 8n, [1n, -1n], true],
            [17n, 8n, [1n, 0n, -1n, 0n], true],
            [347n, 8n, [1n, -1n], false],
            [47n, 8n, [1n, -1n, 1n, -1n], false],
        ] as const) {
            const half = modulus / 2n;
            const alphabet = exhaustive
                ? Array.from(
                      { length: Number(modulus) },
                      (_, index) => BigInt(index) - half,
                  )
                : [-half, -1n, 0n, 1n, half];
            const support = secret.reduce<bigint>(
                (sum, value) => sum + absolute(value),
                0n,
            );
            const bounds = boundSetupKeyArithmetic(modulus, radix, support, 1n);
            assert.ok(
                bounds.maximumQuotientEstimate < bounds.leadingModulusDigit,
            );
            for (
                let encoded = 0;
                encoded < alphabet.length ** secret.length;
                encoded++
            ) {
                let rest = encoded;
                const common = Array.from({ length: secret.length }, () => {
                    const value = alphabet[rest % alphabet.length];
                    rest = Math.floor(rest / alphabet.length);
                    return value;
                });
                const product = negacyclicProduct(common, secret);
                const limbProducts = Array.from(
                    { length: bounds.limbs },
                    (_, limb) =>
                        negacyclicProduct(
                            common.map((value) => digit(value, limb, radix)),
                            [...secret],
                        ),
                );
                for (let position = 0; position < secret.length; position++) {
                    const error = position % 2 === 0 ? -1n : 1n;
                    const raw = limbProducts.map(
                        (values, limb) =>
                            -values[position] + (limb === 0 ? error : 0n),
                    );
                    const value = -product[position] + error;
                    assert.ok(absolute(value) <= bounds.maximumRawInteger);
                    assert.ok(
                        absolute(value) / radix ** BigInt(bounds.limbs - 1) <=
                            bounds.maximumPrefix,
                    );
                    for (const values of limbProducts)
                        assert.ok(
                            absolute(values[position]) <=
                                bounds.maximumLimbProduct,
                        );
                    let normalizationCarry = 0n;
                    for (const limb of raw) {
                        const sum = limb + normalizationCarry;
                        normalizationCarry =
                            sum / radix -
                            (sum < 0n && sum % radix !== 0n ? 1n : 0n);
                        assert.ok(absolute(limb) <= bounds.maximumRawLimb);
                        assert.ok(
                            absolute(normalizationCarry) <=
                                bounds.maximumNormalizationCarry,
                        );
                    }
                    const reduced = reduceSignedDigitModel(raw, radix, modulus);
                    let expected = ((value % modulus) + modulus) % modulus;
                    if (expected > half) expected -= modulus;
                    assert.equal(reduced.remainder, expected);
                    assert.ok(
                        reduced.estimate <= bounds.maximumQuotientEstimate,
                    );
                    assert.ok(
                        absolute(reduced.quotient) <= bounds.maximumQuotient,
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
                    for (let limb = 0; limb < bounds.limbs; limb++) {
                        // The source stores the negative of the reducer's
                        // quotient in its affine witness.
                        const row =
                            limbProducts[limb][position] +
                            digit(expected, limb, radix) +
                            digit(modulus, limb, radix) * reduced.quotient -
                            (limb === 0 ? error : 0n) +
                            carry;
                        assert.ok(absolute(row) <= bounds.maximumWitnessRow);
                        if (limb + 1 === bounds.limbs) assert.equal(row, 0n);
                        else {
                            assert.equal(row % radix, 0n);
                            carry = row / radix;
                            assert.ok(
                                absolute(carry) <= bounds.maximumWitnessCarry,
                            );
                        }
                    }
                }
            }
        }
        expect(corrections).toEqual(new Set([0n, 1n]));
        expect(quotientSigns).toEqual(new Set([-1, 0, 1]));
    });

    it('bounds both gadget signs and automorphism terms through reduction and witness carries', () => {
        let exceedsFirstCoordinateBound = false;
        let nontrivialAutomorphism = false;
        const corrections = new Set<bigint>();
        for (const [modulus, secret, other, directPowers] of [
            [47n, [1n, -1n], [0n, 1n], [1n, 8n]],
            [347n, [1n, -1n, 0n, 1n], [-1n, 0n, 1n, -1n], [1n, 8n, 64n]],
        ] as const) {
            const radix = 8n;
            const half = modulus / 2n;
            const support = secret.reduce<bigint>(
                (sum, value) => sum + absolute(value),
                0n,
            );
            const sourceBound = boundSetupKeyArithmetic(
                modulus,
                radix,
                support,
                1n,
            );
            const alphabet =
                secret.length === 2
                    ? Array.from(
                          { length: Number(modulus) },
                          (_, index) => BigInt(index) - half,
                      )
                    : [-half, -1n, 0n, 1n, half];
            const multipliers = [
                0n,
                ...directPowers.flatMap((power) => [-power, power]),
            ];
            for (
                let encoded = 0;
                encoded < alphabet.length ** secret.length;
                encoded++
            ) {
                let rest = encoded;
                const common = Array.from({ length: secret.length }, () => {
                    const value = alphabet[rest % alphabet.length];
                    rest = Math.floor(rest / alphabet.length);
                    return value;
                });
                const product = negacyclicProduct(common, secret);
                const limbProducts = Array.from(
                    { length: sourceBound.limbs },
                    (_, limb) =>
                        negacyclicProduct(
                            common.map((value) => digit(value, limb, radix)),
                            secret,
                        ),
                );
                for (const automorphism of [1, 5]) {
                    const transformed = Array<bigint>(other.length).fill(0n);
                    for (
                        let position = 0;
                        position < other.length;
                        position++
                    ) {
                        const exponent = position * automorphism;
                        transformed[exponent % other.length] =
                            other[position] *
                            (Math.floor(exponent / other.length) % 2 === 0
                                ? 1n
                                : -1n);
                    }
                    nontrivialAutomorphism ||= transformed.some(
                        (value, index) => value !== other[index],
                    );
                    for (const multiplier of multipliers) {
                        const bound = boundSetupKeyArithmetic(
                            modulus,
                            radix,
                            support,
                            1n,
                            absolute(multiplier),
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
                            const error = position % 2 === 0 ? -1n : 1n;
                            const value =
                                -product[position] +
                                multiplier * transformed[position] +
                                error;
                            exceedsFirstCoordinateBound ||=
                                absolute(value) > sourceBound.maximumRawInteger;
                            assert.ok(
                                absolute(value) <= bound.maximumRawInteger,
                            );
                            const raw = limbProducts.map(
                                (values, limb) =>
                                    -values[position] +
                                    digit(multiplier, limb, radix) *
                                        transformed[position] +
                                    (limb === 0 ? error : 0n),
                            );
                            let normalizationCarry = 0n;
                            for (const limb of raw) {
                                const sum = limb + normalizationCarry;
                                normalizationCarry =
                                    sum / radix -
                                    (sum < 0n && sum % radix !== 0n ? 1n : 0n);
                                assert.ok(
                                    absolute(limb) <= bound.maximumRawLimb,
                                );
                                assert.ok(
                                    absolute(normalizationCarry) <=
                                        bound.maximumNormalizationCarry,
                                );
                            }
                            const reduced = reduceSignedDigitModel(
                                raw,
                                radix,
                                modulus,
                            );
                            let expected =
                                ((value % modulus) + modulus) % modulus;
                            if (expected > half) expected -= modulus;
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
                            let carry = 0n;
                            for (let limb = 0; limb < bound.limbs; limb++) {
                                const row =
                                    limbProducts[limb][position] +
                                    digit(expected, limb, radix) -
                                    digit(multiplier, limb, radix) *
                                        transformed[position] -
                                    (limb === 0 ? error : 0n) +
                                    digit(modulus, limb, radix) *
                                        reduced.quotient +
                                    carry;
                                assert.ok(
                                    absolute(row) <= bound.maximumWitnessRow,
                                );
                                if (limb + 1 === bound.limbs)
                                    assert.equal(row, 0n);
                                else {
                                    assert.equal(row % radix, 0n);
                                    carry = row / radix;
                                    assert.ok(
                                        absolute(carry) <=
                                            bound.maximumWitnessCarry,
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
        expect(exceedsFirstCoordinateBound).toBe(true);
        expect(nontrivialAutomorphism).toBe(true);
        expect(corrections).toEqual(new Set([0n, 1n]));
    });

    it('counts the exact strict normalization predicate, including zero and limb boundaries', () => {
        for (const modulus of [3n, 5n, 17n, 97n, 257n])
            for (const digitBits of [1, 2, 3])
                for (const capacity of [2, 3, 4, 5, 6, 7]) {
                    let affected = 0n;
                    for (
                        let value = -(modulus / 2n);
                        value <= modulus / 2n;
                        value++
                    )
                        if (
                            logicalWords(value, digitBits) <
                            Math.floor(capacity / 2)
                        )
                            affected++;
                    expect(
                        normalizationShrinkResidues(
                            modulus,
                            digitBits,
                            capacity,
                        ).affectedResidues,
                    ).toBe(affected);
                }
    });

    it('has uniform first-key coefficient marginals and a valid union bound under a uniform common polynomial', () => {
        for (const [modulus, secret] of [
            [5, [1, 0, -1, 0]],
            [17, [1, -1, 1, -1]],
            [97, [1, -1]],
        ] as const) {
            const degree = secret.length;
            const error = Array.from(
                { length: degree },
                (_, index) => index - 2,
            );
            const marginals = Array.from({ length: degree }, () =>
                Array<number>(modulus).fill(0),
            );
            const tapes = modulus ** degree;
            let anyShrinks = 0;
            for (let tape = 0; tape < tapes; tape++) {
                let digits = tape;
                const common = Array.from({ length: degree }, () => {
                    const value = digits % modulus;
                    digits = Math.floor(digits / modulus);
                    return value;
                });
                const result = coordinate(common, [...secret], error, modulus);
                if (result.some((value) => value === 0)) anyShrinks++;
                result.forEach((value, index) => marginals[index][value]++);
            }
            for (const counts of marginals)
                expect(counts).toEqual(
                    Array<number>(modulus).fill(tapes / modulus),
                );
            const bound = normalizationShrinkResidues(BigInt(modulus), 2, 3);
            expect(BigInt(anyShrinks) * BigInt(modulus)).toBeLessThanOrEqual(
                BigInt(tapes * degree) * bound.affectedResidues,
            );
        }
    });

    it('does not turn the distributional statement into a bound for a fixed common polynomial', () => {
        const result = coordinate([0, 0], [1, -1], [0, 0], 97);
        expect(result).toEqual([0, 0]);
        const bound = normalizationShrinkResidues(97n, 2, 3);
        // For this fixed public input every output shrinks, whereas the
        // uniform-common-polynomial union bound is strictly below one.
        expect(BigInt(result.length) * bound.affectedResidues).toBeLessThan(
            97n,
        );
    });

    it('matches the pinned scalar constructor and all supported parameter widths', async () => {
        const read = (file: string) =>
            readFile(new URL('../../../' + file, import.meta.url), 'utf8');
        const [
            source,
            profile,
            workspaceManifest,
            manifest,
            builder,
            toolchain,
            reduction,
            gaussian,
            arithmetic,
        ] = await Promise.all([
            read('crates/protocol-research/setup-witness/src/lib.rs'),
            read('crates/protocol-research/supported-profile/src/lib.rs'),
            read('crates/protocol-research/Cargo.toml'),
            read('crates/protocol-research/setup-witness/Cargo.toml'),
            read('tools/ci/build-participant-module.ts'),
            read('tools/ci/rust-toolchain.ts'),
            read('crates/protocol-research/setup-witness/src/reduction.rs'),
            read('crates/protocol-research/setup-witness/src/gaussian.rs'),
            read(
                'crates/protocol-research/setup-stream-kernel/src/arithmetic.rs',
            ),
        ]);
        expect(source).toContain(
            'Vec::with_capacity((digits.len() * radix_bits).div_ceil(32) + 1)',
        );
        expect(source).toContain('BigUint::new(words)');
        expect(profile).toContain('pub const FHE_LIMB_BITS: usize = 96;');
        expect(workspaceManifest).toContain('num-bigint = "=0.5.1"');
        expect(manifest).toContain('num-bigint.workspace = true');
        expect(toolchain).toContain(
            "export const rustCompilerCommit = '59807616e1fa2540724bfbac14d7976d7e4a3860';",
        );
        expect(builder).toContain('commit-hash: ${rustCompilerCommit}');
        expect(builder).toContain("'wasm32-unknown-unknown'");
        expect(profile).toContain(
            'pub const FHE_SECRET_SUPPORT: usize = 1_024;',
        );
        for (const name of ['SETUP_QUOTIENT_BITS', 'SETUP_FHE_CARRY_BITS'])
            expect(profile).toContain(`pub const ${name}: usize = 16;`);
        expect(profile).toContain('pub const SETUP_ERROR_BITS: usize = 7;');
        expect(profile).toContain('const GADGET_BASE_BITS: usize = 144;');
        expect(reduction).toContain('pub const MAXIMUM_LIMBS: usize = 16;');
        expect(reduction).toContain('digits.last().copied().unwrap() <= 65536');
        expect(reduction).toContain('if top >= modulus_top << 16');
        expect(reduction).toContain('for bit in (0..16).rev()');
        expect(gaussian).toContain('const THRESHOLDS: &[u8; 127 * 20]');
        expect(gaussian).toContain('rank - 64');
        expect(arithmetic).toContain('const OFFSET: u128 = 133;');
        expect(arithmetic).toContain(
            'pub const MODULUS: u128 = u128::MAX - (OFFSET << 64) + 2;',
        );
        for (const supported of listSupportedProfiles()) {
            const row = compileSourceCoefficientAllocation(supported);
            const arithmeticBounds = compileSourceArithmeticBounds(supported);
            const gadgetBounds = compileFheGadgetArithmeticBounds(supported);
            let power = 1n;
            let gadget = 0;
            while (power < supported.ciphertext.modulus) {
                expect(gadgetBounds[gadget].directMultiplierMagnitude).toBe(
                    power,
                );
                expect(gadgetBounds[gadget].maximumRawInteger).toBe(
                    arithmeticBounds.maximumRawInteger + power,
                );
                power <<= 144n;
                gadget++;
            }
            expect(gadgetBounds).toHaveLength(gadget);
            let coveredBits = 0;
            let words = 1;
            while (1n << BigInt(coveredBits) < supported.ciphertext.modulus) {
                coveredBits += 96;
                words += 3;
            }
            expect(row.constructorWords).toBe(words);
            expect(arithmeticBounds.limbs).toBe((words - 1) / 3);
            expect(row.unionNumerator << row.exceptionBits).toBeLessThanOrEqual(
                row.modulus,
            );
            expect(
                row.unionNumerator << (row.exceptionBits + 1n),
            ).toBeGreaterThan(row.modulus);
        }
    });

    it('retains the quotient-correction premise instead of hiding an unsupported source profile', () => {
        const row = boundSetupKeyArithmetic(17n, 8n, 4n, 1n);
        expect(row.maximumQuotientEstimate).toBeGreaterThanOrEqual(
            row.leadingModulusDigit,
        );
        expect(() => reduceSignedDigitModel([1n, 4n], 8n, 17n)).toThrow(
            'single-correction',
        );
        for (const [modulus, radix, support, errorBound] of [
            [16n, 8n, 2n, 1n],
            [17n, 7n, 2n, 1n],
            [17n, 8n, 0n, 1n],
            [17n, 8n, 2n, 8n],
        ] as const)
            expect(() =>
                boundSetupKeyArithmetic(modulus, radix, support, errorBound),
            ).toThrow('Invalid setup-key arithmetic operands.');
        expect(() => boundSetupKeyArithmetic(17n, 8n, 2n, 1n, -1n)).toThrow();
        expect(() => boundSetupKeyArithmetic(17n, 8n, 2n, 1n, 17n)).toThrow();
    });

    it('refuses operands outside the centered normalization model', () => {
        for (const [modulus, digitBits, capacity] of [
            [2n, 2, 4],
            [1n, 2, 4],
            [17n, 0, 4],
            [17n, 65, 4],
            [17n, 2, 1],
            [17n, 2, 3.5],
        ] as const)
            expect(() =>
                normalizationShrinkResidues(modulus, digitBits, capacity),
            ).toThrow('Invalid centered-coefficient allocation operands.');
    });
});
