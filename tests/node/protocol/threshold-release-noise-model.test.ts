import { describe, expect, it } from 'vitest';

import { compileThresholdReleaseNoiseCensus } from '#tests/threshold-release-noise-model.js';

type Rational = Readonly<{ numerator: bigint; denominator: bigint }>;

const rational = (numerator: bigint, denominator = 1n): Rational => ({
    numerator,
    denominator,
});
const multiply = (...factors: readonly Rational[]): Rational =>
    factors.reduce(
        (product, factor) =>
            rational(
                product.numerator * factor.numerator,
                product.denominator * factor.denominator,
            ),
        rational(1n),
    );
const subtract = (left: Rational, right: Rational): Rational =>
    rational(
        left.numerator * right.denominator - right.numerator * left.denominator,
        left.denominator * right.denominator,
    );
const reciprocal = (value: Rational): Rational =>
    rational(value.denominator, value.numerator);

// X^e in Z[X]/(X^8+1), where X^8 = -1 and exponents repeat modulo 16.
const monomial = (exponent: number): bigint[] => {
    const reduced = ((exponent % 16) + 16) % 16;
    const coefficients = Array<bigint>(8).fill(0n);
    coefficients[reduced % 8] = reduced < 8 ? 1n : -1n;
    return coefficients;
};
const oneMinusMonomial = (exponent: number): bigint[] =>
    monomial(exponent).map(
        (coefficient, index) => (index === 0 ? 1n : 0n) - coefficient,
    );
const multiplyReducedRing = (
    left: readonly bigint[],
    right: readonly bigint[],
): bigint[] => {
    const product = Array<bigint>(8).fill(0n);
    left.forEach((leftCoefficient, leftIndex) =>
        right.forEach((rightCoefficient, rightIndex) => {
            const exponent = leftIndex + rightIndex;
            product[exponent % 8] +=
                (exponent < 8 ? 1n : -1n) * leftCoefficient * rightCoefficient;
        }),
    );
    return product;
};
const oneNorm = (coefficients: readonly bigint[]): bigint =>
    coefficients.reduce(
        (total, coefficient) =>
            total + (coefficient < 0n ? -coefficient : coefficient),
        0n,
    );

// In the field Q[X]/(X^8+1), y = X^e with e not divisible by 16 has an order
// m > 1 and 1 + y + ... + y^(m-1) = 0. Hence
// (1 - y) * -(y + 2y^2 + ... + (m-1)y^(m-1)) = m.
const inverseOfOneMinusMonomial = (
    exponent: number,
): Readonly<{ numerator: bigint[]; denominator: bigint }> => {
    const reduced = ((exponent % 16) + 16) % 16;
    let order = 1;
    while ((order * reduced) % 16 !== 0) order += 1;
    let numerator = Array<bigint>(8).fill(0n);
    for (let power = 1; power < order; power += 1) {
        const term = monomial(power * reduced);
        numerator = numerator.map(
            (coefficient, index) => coefficient - BigInt(power) * term[index],
        );
    }
    return { numerator, denominator: BigInt(order) };
};

// Each four-member release subset is a corrupt triple C with one honest member
// i of the points X^0, ..., X^9. The simulation coefficient is
// lambda_0,i = product_(j in C) (1-X^(i-j)) and the reconstruction
// coefficient is its inverse, both without rational matrix inversion.
const interpolationOracle = () => {
    let maximumJointSimulationSum = 0n;
    let maximumSimulation = 0n;
    let maximumScaledReconstruction = 0n;
    let fractionalScaledReconstructionCount = 0;
    for (let first = 0; first < 8; first += 1)
        for (let second = first + 1; second < 9; second += 1)
            for (let third = second + 1; third < 10; third += 1) {
                const corrupt = [first, second, third];
                let jointSimulationSum = 0n;
                for (let honest = 0; honest < 10; honest += 1) {
                    if (corrupt.includes(honest)) continue;
                    let simulation = monomial(0);
                    let reconstructionNumerator = monomial(0);
                    let reconstructionDenominator = 1n;
                    for (const position of corrupt) {
                        simulation = multiplyReducedRing(
                            simulation,
                            oneMinusMonomial(honest - position),
                        );
                        const inverse = inverseOfOneMinusMonomial(
                            honest - position,
                        );
                        reconstructionNumerator = multiplyReducedRing(
                            reconstructionNumerator,
                            inverse.numerator,
                        );
                        reconstructionDenominator *= inverse.denominator;
                    }
                    const simulationNorm = oneNorm(simulation);
                    jointSimulationSum += simulationNorm;
                    if (simulationNorm > maximumSimulation)
                        maximumSimulation = simulationNorm;
                    // KLLPS26 clears reconstruction by 2^ceil(log2 t) = 4.
                    const scaled = reconstructionNumerator.map(
                        (coefficient) => 4n * coefficient,
                    );
                    if (
                        scaled.some(
                            (coefficient) =>
                                coefficient % reconstructionDenominator !== 0n,
                        )
                    )
                        fractionalScaledReconstructionCount += 1;
                    const scaledNorm =
                        oneNorm(scaled) / reconstructionDenominator;
                    if (scaledNorm > maximumScaledReconstruction)
                        maximumScaledReconstruction = scaledNorm;
                }
                if (jointSimulationSum > maximumJointSimulationSum)
                    maximumJointSimulationSum = jointSimulationSum;
            }
    return {
        maximumJointSimulationSum,
        maximumSimulation,
        maximumScaledReconstruction,
        fractionalScaledReconstructionCount,
    };
};

describe('threshold release noise model', () => {
    it('charges all honest shares using an independent integral interpolation oracle', () => {
        const oracle = interpolationOracle();
        expect(oracle.fractionalScaledReconstructionCount).toBe(0);
        const census = compileThresholdReleaseNoiseCensus();
        expect(census.exactMaximumJointSimulationCoefficientOneNormSum).toBe(
            oracle.maximumJointSimulationSum,
        );
        expect(census.exactMaximumSimulationCoefficientOneNorm).toBe(
            oracle.maximumSimulation,
        );
        expect(census.exactMaximumScaledReconstructionCoefficientOneNorm).toBe(
            oracle.maximumScaledReconstruction,
        );
        const interpolationProduct =
            oracle.maximumScaledReconstruction * oracle.maximumSimulation;
        expect(census.exactInterpolationProduct).toBe(interpolationProduct);
        // Four releases in ring degree 32768; the joint reserve uses
        // 2^(lambda-1) for the width 2*B_sm+1.
        for (const [exactDominantFactor, bitLength] of [
            [
                4n *
                    32_768n *
                    (1n << 79n) *
                    oracle.maximumScaledReconstruction *
                    oracle.maximumJointSimulationSum,
                census.jointTargetSecurityDominantNoiseReserveBitLength,
            ],
            [
                4n * 32_768n * (1n << 80n) * interpolationProduct,
                census.exactTargetSecurityDominantNoiseBudgetLowerBoundBitLength,
            ],
            [
                4n * 32_768n * (1n << 128n) * interpolationProduct,
                census.exactConservativeSecurityDominantNoiseBudgetLowerBoundBitLength,
            ],
        ] as const) {
            const bits = BigInt(bitLength);
            expect(exactDominantFactor).toBeLessThanOrEqual(1n << bits);
            expect(exactDominantFactor).toBeGreaterThan(1n << (bits - 1n));
        }
        expect(
            census.jointTargetSecurityDominantNoiseReserveBitLength,
        ).toBeGreaterThan(
            census.exactTargetSecurityDominantNoiseBudgetLowerBoundBitLength,
        );
    });

    it('inverts one minus each interpolation monomial in closed form', () => {
        for (let exponent = -9; exponent <= 9; exponent += 1) {
            if (exponent === 0) continue;
            const inverse = inverseOfOneMinusMonomial(exponent);
            expect(
                multiplyReducedRing(
                    oneMinusMonomial(exponent),
                    inverse.numerator,
                ),
            ).toEqual(
                monomial(0).map(
                    (coefficient) => coefficient * inverse.denominator,
                ),
            );
        }
    });

    it('derives the KLLPS dominant flooding reserve for four-of-ten release', () => {
        // KLLPS26 equation (1) with t = 4 and 2N = 16 gives
        // 2^2 * 8 * cot^2(pi/16) / sin^2(pi/8). Archimedes gives
        // 223/71 < pi < 22/7. For 0 < x < 1, x - x^3/6 <= sin(x) <= x and
        // 1 - x^2/2 <= cos(x) <= 1, and each bound is monotone in x.
        const smallerPi = rational(223n, 71n);
        const largerPi = rational(22n, 7n);
        const sineLowerBound = (angle: Rational): Rational =>
            subtract(angle, multiply(angle, angle, angle, rational(1n, 6n)));
        const upperEighth = multiply(largerPi, rational(1n, 8n));
        const upperSixteenth = multiply(largerPi, rational(1n, 16n));
        const cosineLowerBound = subtract(
            rational(1n),
            multiply(upperSixteenth, upperSixteenth, rational(1n, 2n)),
        );
        const productLowerBound = multiply(
            rational(32n),
            reciprocal(multiply(upperEighth, upperEighth)),
            cosineLowerBound,
            cosineLowerBound,
            reciprocal(multiply(upperSixteenth, upperSixteenth)),
        );
        const sineEighth = sineLowerBound(
            multiply(smallerPi, rational(1n, 8n)),
        );
        const sineSixteenth = sineLowerBound(
            multiply(smallerPi, rational(1n, 16n)),
        );
        const productUpperBound = multiply(
            rational(32n),
            reciprocal(multiply(sineEighth, sineEighth)),
            reciprocal(multiply(sineSixteenth, sineSixteenth)),
        );
        const census = compileThresholdReleaseNoiseCensus();
        for (const [statisticalBits, bitLength] of [
            [80n, census.targetSecurityDominantNoiseBudgetLowerBoundBitLength],
            [
                128n,
                census.conservativeSecurityDominantNoiseBudgetLowerBoundBitLength,
            ],
        ] as const) {
            // 2^(bits-1) < scale * lower <= scale * product
            // <= scale * upper <= 2^bits, so the ceiling cannot move.
            const scale = 4n * 32_768n * (1n << statisticalBits);
            const bits = BigInt(bitLength);
            expect(scale * productLowerBound.numerator).toBeGreaterThan(
                (1n << (bits - 1n)) * productLowerBound.denominator,
            );
            expect(scale * productUpperBound.numerator).toBeLessThanOrEqual(
                (1n << bits) * productUpperBound.denominator,
            );
        }
        // Half-angle identities give 1/sin^2(pi/8) = 4 + 2 sqrt(2) and
        // cot^2(pi/16) = (1 + c)/(1 - c) with c = cos(pi/8) = sqrt(2+sqrt(2))/2.
        const cosineEighth = Math.sqrt(2 + Math.SQRT2) / 2;
        expect(census.interpolationProductBound).toBeCloseTo(
            32 *
                (4 + 2 * Math.SQRT2) *
                ((1 + cosineEighth) / (1 - cosineEighth)),
            9,
        );
        expect(census).toMatchObject({
            authorizedSubsetCount: 210,
            boundedIntegerSharingReconstructionCount: 210,
            completionParticipantCount: 10,
            exactConservativeSecurityDominantNoiseBudgetLowerBoundBitLength: 154,
            exactInterpolationProduct: 352n,
            exactMaximumScaledReconstructionCoefficientOneNorm: 44n,
            exactMaximumSimulationCoefficientOneNorm: 8n,
            exactTargetSecurityDominantNoiseBudgetLowerBoundBitLength: 106,
            lagrangeCoefficientCount: 840,
            productionInterpolationPointExponentStride: 4_096,
            releaseThreshold: 4,
            spacedInterpolationSize: 16,
            targetSecurityDominantNoiseBudgetLowerBoundBitLength: 110,
            conservativeSecurityDominantNoiseBudgetLowerBoundBitLength: 158,
        });
    });
});
