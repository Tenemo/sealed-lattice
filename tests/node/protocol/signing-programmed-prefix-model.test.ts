import { describe, expect, it } from 'vitest';

import {
    compileCurrentSignatureSamplingBounds,
    compileSignatureCounterBoundary,
} from '#tests/authentication-work-model.js';
import { mlDsa65Parameters } from '#tests/ml-dsa-theorem-screen-model.js';
import { compileProgrammedSignatureSamplerBounds } from '#tests/signing-programmed-prefix-model.js';

describe('sampling after fresh signature-prefix programming', () => {
    it('charges the full mask nonce family using only its newly sampled prefix', () => {
        const [mask] = compileProgrammedSignatureSamplerBounds();
        const bitsPerCoefficient = BigInt(
            (2n * mlDsa65Parameters.maskingBound - 1n).toString(2).length,
        );
        expect(mask.prefixBytes * 8n).toBe(
            mlDsa65Parameters.polynomialDegree * bitsPerCoefficient,
        );
        expect(mask.refreshedPoints).toBe(
            compileSignatureCounterBoundary().nonceCapacity,
        );
        expect(mask.candidatePositions - mask.requiredRejections).toBe(
            mlDsa65Parameters.polynomialDegree - 1n,
        );
        const original = compileCurrentSignatureSamplingBounds().find(
            (row) => row.purpose === 'Secret polynomial sampling',
        )!;
        expect(mask.prefixBytes).toBeLessThan(original.outputBytes);
        expect(mask.failureExponent).toBeGreaterThanOrEqual(256n);
    });

    it('separates one fresh challenge prefix from the base all-input event', () => {
        const [, programmed] = compileProgrammedSignatureSamplerBounds();
        const original = compileCurrentSignatureSamplingBounds().find(
            (row) => row.purpose === 'Challenge polynomial sampling',
        )!;
        expect(programmed.prefixBytes).toBe(original.outputBytes);
        expect(programmed.refreshedPoints).toBe(1n);
        expect(programmed.numerator * original.inputCount).toBe(
            original.numerator,
        );
        expect(programmed.denominatorBits).toBe(original.denominatorBits);
    });

    it('detects that replacing a good prefix can break an old sampler event', () => {
        const succeeds = (samples: readonly number[]) =>
            samples.filter((value) => value < 2).length >= 2;
        expect(succeeds([0, 1, 3, 3])).toBe(true);
        expect(succeeds([3, 3, 3, 3])).toBe(false);
        // A sufficient fresh prefix protects the read bound for every old tail,
        // including one deliberately correlated with that prefix.
        let checked = 0;
        for (let prefix = 0; prefix < 64; prefix++) {
            const values = [prefix & 3, (prefix >> 2) & 3, (prefix >> 4) & 3];
            if (!succeeds(values)) continue;
            for (let tail = 0; tail < 16; tail++) {
                expect(succeeds([...values, tail & 3, (tail >> 2) & 3])).toBe(
                    true,
                );
                checked++;
            }
        }
        expect(checked).toBe(512);
    });
});
