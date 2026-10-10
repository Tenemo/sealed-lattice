import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    compileRecipientKeyCensus,
    recipientKeyIntegerRows,
} from '#tests/recipient-key-model.js';
import { reduceSignedDigitModel } from '#tests/setup-randomness-model.js';
import { compileRecipientKeyArithmeticBounds } from '#tests/source-coefficient-allocation-model.js';

describe('recipient key relation', () => {
    it('checks generation and retained-key arithmetic against the native recipient parameters', async () => {
        const native = await readFile(
            new URL(
                '../../../crates/protocol-research/supported-profile/src/lib.rs',
                import.meta.url,
            ),
            'utf8',
        );
        expect(native).toContain(
            'pub const RECIPIENT_SECRET_SUPPORT: usize = 256;',
        );
        expect(native).toContain('pub const FHE_LIMB_BITS: usize = 96;');
        const parameters = compileRecipientKeyCensus();
        const { generated, restored } = compileRecipientKeyArithmeticBounds();
        expect(generated.maximumRawInteger).toBe(
            256n * (parameters.modulus / 2n) + 64n,
        );
        expect(restored.maximumRawInteger).toBe(
            257n * (parameters.modulus / 2n),
        );
        expect(generated.limbs).toBe(2);
        expect(restored.limbs).toBe(2);
        expect(restored.maximumRawLimb).toBe(257n * ((1n << 96n) - 1n));
        for (const row of [generated, restored]) {
            expect(row.maximumQuotientEstimate).toBeLessThan(
                row.leadingModulusDigit,
            );
            expect(row.maximumQuotientEstimate).toBeLessThan(1n << 16n);
            expect(
                row.maximumRawLimb + row.maximumNormalizationCarry,
            ).toBeLessThan(1n << 127n);
        }
    });

    it('recovers the original error through the retained-key reduction and distinguishes its signed endpoints', () => {
        const common = [31001n, -30117n, 12345n, -678n];
        const secret = [1n, 0n, -1n, 0n];
        const modulus = 65521n;
        const radix = 256n;
        const digit = (value: bigint, limb: number) =>
            (value < 0n ? -1n : 1n) *
            (((value < 0n ? -value : value) / radix ** BigInt(limb)) % radix);
        const product = (values: bigint[]) => {
            const result = Array<bigint>(values.length).fill(0n);
            for (let i = 0; i < values.length; i++)
                for (let j = 0; j < secret.length; j++)
                    result[(i + j) % values.length] +=
                        values[i] *
                        secret[j] *
                        (i + j < values.length ? 1n : -1n);
            return result;
        };
        const full = product(common);
        const limbs = [0, 1].map((limb) =>
            product(common.map((value) => digit(value, limb))),
        );
        for (const [error, accepted] of [
            [-65n, false],
            [-64n, true],
            [-63n, true],
            [0n, true],
            [63n, true],
            [64n, false],
            [65n, false],
        ] as const) {
            const key = full.map((value) => {
                let residue = (((error - value) % modulus) + modulus) % modulus;
                if (residue > modulus / 2n) residue -= modulus;
                return residue;
            });
            for (let position = 0; position < key.length; position++) {
                const result = reduceSignedDigitModel(
                    limbs.map(
                        (values, limb) =>
                            values[position] + digit(key[position], limb),
                    ),
                    radix,
                    modulus,
                );
                expect(result.remainder).toBe(error);
                const magnitude =
                    result.remainder < 0n
                        ? -result.remainder
                        : result.remainder;
                expect(
                    magnitude <= 64n &&
                        !(result.remainder >= 0n && magnitude === 64n),
                ).toBe(accepted);
            }
        }
    });

    it('derives the recipient encoding and bounded-key integer operands', () => {
        const value = compileRecipientKeyCensus();

        expect(value.publicKeyBytes).toBe(65_536n * 21n);
        expect(value.support).toBe(256n);
        expect(value.error).toBe(64n);
        expect(value.honestQuotient).toBe(128n);
        expect(value.honestCarry).toBe(384n);
    });
    it('checks both signed radix equations against an independently constructed key', () => {
        const degree = 8,
            radix = 256n,
            modulus = 65521n;
        const common = [
            31001n,
            -30117n,
            12345n,
            -678n,
            91n,
            24173n,
            -2111n,
            3n,
        ];
        const secret = [1n, 0n, -1n, 0n, 0n, 1n, 0n, -1n];
        const errors = [-3n, 0n, 7n, -8n, 1n, 4n, -1n, 0n];
        const convolution = Array.from({ length: degree }, () => 0n);
        for (let left = 0; left < degree; left++)
            for (let right = 0; right < degree; right++)
                convolution[(left + right) % degree] +=
                    common[left] *
                    secret[right] *
                    (left + right < degree ? 1n : -1n);
        const key = convolution.map((value, index) => {
            let residue =
                (((errors[index] - value) % modulus) + modulus) % modulus;
            if (residue > modulus / 2n) residue -= modulus;
            return residue;
        });
        const quotient = convolution.map(
            (value, index) => (value + key[index] - errors[index]) / modulus,
        );
        const zeroCarry = recipientKeyIntegerRows(
            common,
            key,
            secret,
            errors,
            quotient,
            Array<bigint>(degree).fill(0n),
            modulus,
            radix,
        );
        const carry = zeroCarry.slice(0, degree).map((value) => {
            expect(value % radix).toBe(0n);
            return value / radix;
        });
        expect(
            recipientKeyIntegerRows(
                common,
                key,
                secret,
                errors,
                quotient,
                carry,
                modulus,
                radix,
            ).every((value) => value === 0n),
        ).toBe(true);
        const changed = [...key];
        changed[degree - 1]++;
        expect(
            recipientKeyIntegerRows(
                common,
                changed,
                secret,
                errors,
                quotient,
                carry,
                modulus,
                radix,
            ).some((value) => value !== 0n),
        ).toBe(true);
    });
});
