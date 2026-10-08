import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { setupGaussianParameters } from '#tests/setup-randomness-model.js';
import {
    encodeSupportedProfileTable,
    supportedProfileRecordBytes,
} from '#tests/supported-profile-table-model.js';
import { shareEncryptionParameters } from '#tests/wide-share-lifting-model.js';

const unsigned = (value: bigint, bytes: number) => {
    const encoded = Buffer.alloc(bytes);
    for (let index = 0; index < bytes; index++) {
        encoded[index] = Number(value & 255n);
        value >>= 8n;
    }
    expect(value).toBe(0n);
    return encoded;
};
type Fraction = readonly [bigint, bigint];
const fraction = (numerator: bigint, denominator: bigint): Fraction => {
    let a = numerator,
        b = denominator;
    while (b !== 0n) [a, b] = [b, a % b];
    return [numerator / a, denominator / a];
};
const sum = ([a, b]: Fraction, [c, d]: Fraction): Fraction =>
    fraction(a * d + c * b, b * d);
const product = ([a, b]: Fraction, [c, d]: Fraction): Fraction =>
    fraction(a * c, b * d);

describe('tracked research parameter correspondence', () => {
    it('rebuilds the tracked profile table from the supported-profile owners', async () => {
        const stored = await readFile(
            'crates/protocol-research/supported-profile/profiles.bin',
        );
        expect(stored).toEqual(encodeSupportedProfileTable());
        // Header: magic, both length-prefixed moduli, their families' common
        // sample width and the count ranges.
        expect(stored.subarray(0, 4).toString()).toBe('SPT1');
        expect(stored.subarray(4, 25)).toEqual(
            Buffer.concat([
                Buffer.of(20),
                unsigned(shareEncryptionParameters.modulus, 20),
            ]),
        );
        expect(stored.subarray(25, 31)).toEqual(
            Buffer.concat([
                Buffer.of(5),
                unsigned(auxiliaryInputEncryptionParameters.modulus, 5),
            ]),
        );
        expect(stored.readUInt16LE(31)).toBe(320);
        expect([...stored.subarray(33, 37)]).toEqual([3, 20, 2, 20]);
        expect(stored.length).toBe(37 + 18 * 19 * supportedProfileRecordBytes);
        // The completion record, independently of the search: the FHE
        // modulus 65537*65319*2^832+1 and the release modulus
        // 65537*65445*2^160+1, both with Proth witness 7.
        const offset =
            37 + ((10 - 3) * 19 + (10 - 2)) * supportedProfileRecordBytes;
        const record = stored.subarray(
            offset,
            offset + supportedProfileRecordBytes,
        );
        expect(record.readUInt16LE(0)).toBe(832);
        expect(record.readUInt32LE(2)).toBe(65537 * 65319);
        expect(record.readUInt16LE(6)).toBe(7);
        expect(record.readUInt16LE(8)).toBe(160);
        expect(record.readUInt32LE(10)).toBe(65537 * 65445);
        expect(record.readUInt16LE(14)).toBe(7);
    });

    it('certifies every Gaussian CDF threshold using positive-series interval bounds', async () => {
        const {
            sigmaNumerator,
            sigmaDenominator,
            sampleBits,
            minimum,
            maximum,
        } = setupGaussianParameters;
        const precision = 640n,
            scale = 1n << precision;
        const weights = new Map<number, readonly [bigint, bigint]>();
        const weight = (index: number): readonly [bigint, bigint] => {
            const cached = weights.get(index);
            if (cached) return cached;
            // Bound exp(x), invert, then square the dyadic interval twelve
            // times. All rounding is outward; floating point is never used.
            const argument = fraction(
                sigmaDenominator ** 2n * BigInt(index) ** 2n,
                2n * sigmaNumerator ** 2n * 4096n,
            );
            let term: Fraction = [1n, 1n],
                lower: Fraction = [1n, 1n];
            for (let order = 1n; order <= 64n; order++) {
                term = product(term, [argument[0], argument[1] * order]);
                lower = sum(lower, term);
            }
            const next = product(term, [argument[0], argument[1] * 65n]);
            const ratio = fraction(argument[0], argument[1] * 66n);
            expect(ratio[0]).toBeLessThan(ratio[1]);
            const upper = sum(
                lower,
                product(next, [ratio[1], ratio[1] - ratio[0]]),
            );
            let low = (scale * upper[1]) / upper[0];
            let high = (scale * lower[1] + lower[0] - 1n) / lower[0];
            for (let step = 0; step < 12; step++) {
                low = (low * low) / scale;
                high = (high * high + scale - 1n) / scale;
            }
            const interval = [low, high] as const;
            weights.set(index, interval);
            return interval;
        };
        let totalLow = 0n,
            totalHigh = 0n;
        for (let value = minimum; value <= maximum; value++) {
            const [low, high] = weight(Math.abs(value));
            totalLow += low;
            totalHigh += high;
        }
        const thresholds: Buffer[] = [];
        let lower = 0n,
            upper = 0n;
        for (let value = minimum; value < maximum; value++) {
            const [low, high] = weight(Math.abs(value));
            lower += low;
            upper += high;
            const first = (lower << sampleBits) / totalHigh;
            const last = (upper << sampleBits) / totalLow;
            expect(first).toBe(last);
            thresholds.push(unsigned(first, Number(sampleBits / 8n)));
        }
        expect(
            await readFile(
                'crates/protocol-research/setup-witness/gaussian-thresholds.bin',
            ),
        ).toEqual(Buffer.concat(thresholds));
    });
});
