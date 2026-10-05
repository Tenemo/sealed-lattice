import { describe, expect, it } from 'vitest';

import {
    compileRecipientKeyCensus,
    recipientKeyIntegerRows,
} from '#tests/recipient-key-model.js';

describe('recipient key relation', () => {
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
