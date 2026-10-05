import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
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

describe('source coefficient allocation comparison', () => {
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
        const [source, profile, manifest, builder] = await Promise.all([
            read('crates/protocol-research/setup-witness/src/lib.rs'),
            read('crates/protocol-research/supported-profile/src/lib.rs'),
            read('crates/protocol-research/setup-witness/Cargo.toml'),
            read('tools/ci/build-participant-module.ts'),
        ]);
        expect(source).toContain(
            'Vec::with_capacity((digits.len() * radix_bits).div_ceil(32) + 1)',
        );
        expect(source).toContain('BigUint::new(words)');
        expect(profile).toContain('pub const FHE_LIMB_BITS: usize = 96;');
        expect(manifest).toContain('num-bigint = "=0.5.1"');
        expect(builder).toContain(
            "const compilerCommit = '59807616e1fa2540724bfbac14d7976d7e4a3860';",
        );
        expect(builder).toContain("'wasm32-unknown-unknown'");
        for (const supported of listSupportedProfiles()) {
            const row = compileSourceCoefficientAllocation(supported);
            let coveredBits = 0;
            let words = 1;
            while (1n << BigInt(coveredBits) < supported.ciphertext.modulus) {
                coveredBits += 96;
                words += 3;
            }
            expect(row.constructorWords).toBe(words);
            expect(row.unionNumerator << row.exceptionBits).toBeLessThanOrEqual(
                row.modulus,
            );
            expect(
                row.unionNumerator << (row.exceptionBits + 1n),
            ).toBeGreaterThan(row.modulus);
        }
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
