import { describe, expect, it } from 'vitest';

// Exhaustive two-coefficient distributions for the pointwise release lemma.
// Ciphertexts are chosen algebraically from the corrupt share, without an
// encryption algorithm or a history of honestly generated encryption coins.
type Ring = readonly [number, number];
const modulus = 257;
const floodingRadius = 3;
const modulo = (value: number): number =>
    ((value % modulus) + modulus) % modulus;
const add = (left: Ring, right: Ring): Ring => [
    left[0] + right[0],
    left[1] + right[1],
];
const subtract = (left: Ring, right: Ring): Ring => [
    left[0] - right[0],
    left[1] - right[1],
];
const scale = (value: Ring, scalar: number): Ring => [
    scalar * value[0],
    scalar * value[1],
];
const multiply = (left: Ring, right: Ring): Ring => [
    left[0] * right[0] - left[1] * right[1],
    left[0] * right[1] + left[1] * right[0],
];
const centered = (value: number): number => {
    const residue = modulo(value);
    return residue > modulus / 2 ? residue - modulus : residue;
};
const encoded = (...values: Ring[]): string =>
    values.flat().map(modulo).join(',');
const noiseCube: Ring[] = [];
for (let real = -floodingRadius; real <= floodingRadius; real += 1)
    for (
        let imaginary = -floodingRadius;
        imaginary <= floodingRadius;
        imaginary += 1
    )
        noiseCube.push([real, imaginary]);

describe('pointwise threshold-release simulation', () => {
    it('matches the exact translated-cube overlap for ciphertexts depending on a corrupt share', () => {
        const secret: Ring = [1, -1];
        const sharingSlope: Ring = [2, 1];
        const corruptShare = add(secret, sharingSlope); // Corrupt point 1.
        const honestPoints: Ring[] = [
            [0, 1],
            [-1, 0],
        ];
        const honestShares = honestPoints.map((point) =>
            add(secret, multiply(point, sharingSlope)),
        );
        const zeroWeights = honestPoints.map((point) =>
            subtract([1, 0], point),
        );
        const linear = add(multiply(corruptShare, corruptShare), [127, -121]);
        const plaintext: Ring = [1, 0];
        for (let firstError = -1; firstError <= 1; firstError += 1)
            for (let secondError = -1; secondError <= 1; secondError += 1) {
                const error: Ring = [firstError, secondError];
                const constant = subtract(
                    add(scale(plaintext, 15), error),
                    multiply(linear, secret),
                );
                const shifts = zeroWeights.map((weight) =>
                    multiply(weight, error),
                );
                const real = new Set<string>();
                const simulated = new Set<string>();
                for (const firstNoise of noiseCube)
                    for (const secondNoise of noiseCube) {
                        const noises = [firstNoise, secondNoise];
                        const realShares = honestShares.map((share, index) =>
                            add(
                                scale(multiply(linear, share), 2),
                                scale(noises[index], 2),
                            ),
                        );
                        const simulatedShares = honestPoints.map(
                            (point, index) =>
                                add(
                                    scale(
                                        add(
                                            multiply(
                                                zeroWeights[index],
                                                subtract(
                                                    scale(plaintext, 15),
                                                    constant,
                                                ),
                                            ),
                                            multiply(
                                                linear,
                                                multiply(point, corruptShare),
                                            ),
                                        ),
                                        2,
                                    ),
                                    scale(noises[index], 2),
                                ),
                        );
                        expect(encoded(...simulatedShares)).toBe(
                            encoded(
                                ...realShares.map((share, index) =>
                                    subtract(share, scale(shifts[index], 2)),
                                ),
                            ),
                        );
                        real.add(encoded(...realShares));
                        simulated.add(encoded(...simulatedShares));
                        // The shifted witness fits the expanded proof support.
                        noises.forEach((noise, index) => {
                            const shifted = subtract(noise, shifts[index]);
                            shifted.forEach((coefficient) =>
                                expect(
                                    Math.abs(coefficient),
                                ).toBeLessThanOrEqual(floodingRadius + 2),
                            );
                        });
                    }
                const sampleCount = noiseCube.length ** honestPoints.length;
                expect(real.size).toBe(sampleCount);
                expect(simulated.size).toBe(sampleCount);
                const actualOverlap = [...real].filter((transcript) =>
                    simulated.has(transcript),
                ).length;
                const width = 2 * floodingRadius + 1;
                const predictedOverlap = shifts
                    .flat()
                    .reduce(
                        (product, shift) =>
                            product * Math.max(0, width - Math.abs(shift)),
                        1,
                    );
                expect(actualOverlap).toBe(predictedOverlap);
                const shiftOneNorm = shifts
                    .flat()
                    .reduce(
                        (sum, coefficient) => sum + Math.abs(coefficient),
                        0,
                    );
                // Integer cross multiplication checks the joint TV bound.
                expect(
                    (sampleCount - actualOverlap) * width,
                ).toBeLessThanOrEqual(sampleCount * shiftOneNorm);
                expect(actualOverlap === sampleCount).toBe(
                    firstError === 0 && secondError === 0,
                );
            }
    });

    it('requires the actual target plaintext even when the apparent output can be changed', () => {
        const zeroWeight: Ring = [1, -1];
        const error: Ring = [1, 0];
        const changedPlaintext: Ring = [1, 0];
        const actualShift = multiply(zeroWeight, error);
        const changedShift = subtract(
            actualShift,
            multiply(zeroWeight, scale(changedPlaintext, 15)),
        );
        const realNoise = new Set(noiseCube.map((noise) => encoded(noise)));
        const changedNoise = new Set(
            noiseCube.map((noise) => encoded(subtract(noise, changedShift))),
        );
        expect(
            [...changedNoise].filter((noise) => realNoise.has(noise)),
        ).toHaveLength(0);
        expect(changedShift.map(centered)).toEqual([-14, 14]);
        expect(Math.max(...actualShift.map(Math.abs))).toBe(1);
    });
});
