import { describe, expect, it } from 'vitest';

import { candidateBgvParameterInputs } from '#tests/candidate-bgv-parameter-model.js';
import { verifyThresholdKeyAggregationModel } from '#tests/threshold-key-aggregation-model.js';

const participantCount = candidateBgvParameterInputs.participantCount;
// Release needs shares from at least f + 1 participants, for
// f = floor((n - 1) / 3), and never fewer than 2.
const releaseThreshold = Math.max(
    Math.floor((participantCount - 1) / 3) + 1,
    2,
);

// KLLPS26 Section 4.2 interpolates at the monomials x^0, ..., x^(n - 1) and
// assumes n <= 2N; this is the smallest power-of-two degree allowing that.
const smallestMonomialRingDegree = (pointCount: number): number => {
    let ringDegree = 1;
    while (2 * ringDegree < pointCount) ringDegree *= 2;
    return ringDegree;
};
const ringDegree = smallestMonomialRingDegree(participantCount);

// KLLPS26 Section 4.2 scales decryption and simulation by 2^ceil(log2 t).
const scaleForThreshold = (threshold: number): bigint => {
    let scale = 1n;
    while (scale < BigInt(threshold)) scale *= 2n;
    return scale;
};

// Exact integer arithmetic in Z[X]/(X^N + 1), where X^(2N) = 1.
const constant = (value: bigint): bigint[] =>
    Array.from({ length: ringDegree }, (_unused, index) =>
        index === 0 ? value : 0n,
    );
const monomial = (exponent: number): bigint[] => {
    const reduced =
        ((exponent % (2 * ringDegree)) + 2 * ringDegree) % (2 * ringDegree);
    const result = constant(0n);
    result[reduced % ringDegree] = reduced >= ringDegree ? -1n : 1n;
    return result;
};
const add = (left: readonly bigint[], right: readonly bigint[]): bigint[] =>
    left.map((value, index) => value + right[index]);
const multiply = (
    left: readonly bigint[],
    right: readonly bigint[],
): bigint[] => {
    const result = constant(0n);
    left.forEach((leftValue, leftIndex) => {
        right.forEach((rightValue, rightIndex) => {
            const exponent = leftIndex + rightIndex;
            result[exponent % ringDegree] +=
                (exponent >= ringDegree ? -1n : 1n) * leftValue * rightValue;
        });
    });
    return result;
};
const oneMinusMonomial = (exponent: number): bigint[] =>
    add(
        constant(1n),
        monomial(exponent).map((coefficient) => -coefficient),
    );
const oneNorm = (value: readonly bigint[]): bigint =>
    value.reduce(
        (sum, coefficient) =>
            sum + (coefficient < 0n ? -coefficient : coefficient),
        0n,
    );

// (1 - X^k) * (1 + X^k + ... + X^((m - 1)k)) = 1 - X^(mk) = 2 once X^(mk) =
// -1, which holds for m = N / gcd(k, N) whenever 2N does not divide k.
const doubledInverseOfOneMinusMonomial = (exponent: number): bigint[] => {
    let divisor = ringDegree;
    while (exponent % divisor !== 0) divisor /= 2;
    let result = constant(0n);
    for (let power = 0; power < ringDegree / divisor; power += 1) {
        result = add(result, monomial(power * exponent));
    }
    return result;
};

// Every release set, enumerated as roster bit masks.
const releaseSets = (): number[][] => {
    const sets: number[][] = [];
    for (let mask = 0; mask < 1 << participantCount; mask += 1) {
        const members = Array.from(
            { length: participantCount },
            (_unused, position) => position,
        ).filter((position) => ((mask >> position) & 1) === 1);
        if (members.length === releaseThreshold) sets.push(members);
    }
    return sets;
};

// For points x^i, the Lagrange coefficient at zero is
// lambda_i = prod_(j != i) 1 / (1 - x^(i - j)). Its inverse is the integral
// simulation coefficient prod_(j != i) (1 - x^(i - j)), and
// 2^(t - 1) * lambda_i is the integral product of the doubled inverses.
const integralLagrangeData = (releaseSet: readonly number[]) =>
    releaseSet.map((position) => {
        const others = releaseSet.filter((other) => other !== position);
        return {
            position,
            powerOfTwoTimesCoefficient: others.reduce(
                (product, other) =>
                    multiply(
                        product,
                        doubledInverseOfOneMinusMonomial(position - other),
                    ),
                constant(1n),
            ),
            simulationCoefficient: others.reduce(
                (product, other) =>
                    multiply(product, oneMinusMonomial(position - other)),
                constant(1n),
            ),
        };
    });

describe('threshold key aggregation model', () => {
    it('reconstructs every degree-f polynomial from every release set in exact integers', () => {
        const denominator = 1n << BigInt(releaseThreshold - 1);
        for (const releaseSet of releaseSets()) {
            const data = integralLagrangeData(releaseSet);
            // sum_i lambda_i * (x^i)^k is one for k = 0 and zero for the
            // other degrees, so these coefficients recover f(0).
            for (let degree = 0; degree < releaseThreshold; degree += 1) {
                const interpolated = data.reduce(
                    (sum, { position, powerOfTwoTimesCoefficient }) =>
                        add(
                            sum,
                            multiply(
                                powerOfTwoTimesCoefficient,
                                monomial(position * degree),
                            ),
                        ),
                    constant(0n),
                );
                expect(interpolated).toEqual(
                    constant(degree === 0 ? denominator : 0n),
                );
            }
            // Each coefficient times its simulation coefficient is one, so
            // every coefficient is a unit and any nonzero change to one
            // share moves the reconstructed secret.
            for (const {
                powerOfTwoTimesCoefficient,
                simulationCoefficient,
            } of data) {
                expect(
                    multiply(powerOfTwoTimesCoefficient, simulationCoefficient),
                ).toEqual(constant(denominator));
            }
        }
    });

    it('derives the coefficient norms and every structural count independently', () => {
        const scale = scaleForThreshold(releaseThreshold);
        const denominator = 1n << BigInt(releaseThreshold - 1);
        const sets = releaseSets();
        let maximumScaledReconstructionCoefficientOneNorm = 0n;
        let maximumSimulationCoefficientOneNorm = 0n;
        let maximumCoefficientMagnitude = 0n;
        for (const releaseSet of sets) {
            for (const {
                powerOfTwoTimesCoefficient,
                simulationCoefficient,
            } of integralLagrangeData(releaseSet)) {
                // KLLPS26 Section 4.2: the scale clears every denominator.
                const scaled = powerOfTwoTimesCoefficient.map(
                    (coefficient) => coefficient * scale,
                );
                expect(
                    scaled.every((value) => value % denominator === 0n),
                ).toBe(true);
                const scaledCoefficient = scaled.map(
                    (value) => value / denominator,
                );
                for (const value of [
                    ...scaledCoefficient,
                    ...simulationCoefficient,
                ]) {
                    const magnitude = value < 0n ? -value : value;
                    if (magnitude > maximumCoefficientMagnitude) {
                        maximumCoefficientMagnitude = magnitude;
                    }
                }
                const scaledOneNorm = oneNorm(scaledCoefficient);
                const simulationOneNorm = oneNorm(simulationCoefficient);
                if (
                    scaledOneNorm >
                    maximumScaledReconstructionCoefficientOneNorm
                ) {
                    maximumScaledReconstructionCoefficientOneNorm =
                        scaledOneNorm;
                }
                if (simulationOneNorm > maximumSimulationCoefficientOneNorm) {
                    maximumSimulationCoefficientOneNorm = simulationOneNorm;
                }
            }
        }
        // The participant points are distinct monomials.
        const pointKeys = new Set(
            Array.from({ length: participantCount }, (_unused, position) =>
                monomial(position).join(','),
            ),
        );

        const census = verifyThresholdKeyAggregationModel();
        // The coefficient modulus is a configuration choice. The model inverts
        // by Fermat's little theorem, so it must be prime, and its centered
        // norms equal the integral norms only if every coefficient stays
        // below half of it.
        const modulus = census.coefficientModulus;
        let smallestDivisor = 2n;
        while (smallestDivisor < modulus && modulus % smallestDivisor !== 0n) {
            smallestDivisor += 1n;
        }
        expect(smallestDivisor).toBe(modulus);
        expect(2n * maximumCoefficientMagnitude).toBeLessThan(modulus);
        // The gadget length is also a configuration choice; more than one
        // coordinate makes every aggregated key a vector equation.
        expect(census.gadgetLength).toBeGreaterThan(1);
        expect(census).toEqual({
            // KLSW24 Section 4.1 publishes b, d, v, and one h per automorphism,
            // and the model uses one automorphism.
            aggregatePublicKeyEquationCount: ['b', 'd', 'v', 'h1'].length,
            authorizedReleaseSetCount: sets.length,
            coefficientModulus: expect.any(BigInt) as bigint,
            gadgetLength: expect.any(Number) as number,
            maximumScaledReconstructionCoefficientOneNorm,
            maximumSimulationCoefficientOneNorm,
            monomialInterpolationPointCount: pointKeys.size,
            participantCount,
            releaseEquationCount: sets.length,
            releaseThreshold,
            ringDegree,
            // Every coefficient is a unit, so the tampered share must move
            // the reconstruction.
            tamperedShareChangedReconstruction: true,
            // A partial decryption must bind its target ciphertext.
            wrongTargetChangedPartialDecryption: true,
        });
    });
});
