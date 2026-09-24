const participantCount = 10;
const releaseThreshold = 4;
const polynomialModulusDegree = 32_768;
const spacedInterpolationSize = 16;
const reducedInterpolationRingDegree = 8;
const productionInterpolationPointExponentStride =
    polynomialModulusDegree / reducedInterpolationRingDegree;
// 2^ceil(log2 t) for t >= 2, without a floating-point logarithm.
const reconstructionClearingFactor =
    1n << BigInt((releaseThreshold - 1).toString(2).length);

type Fraction = Readonly<{ denominator: bigint; numerator: bigint }>;
type RationalRingElement = readonly Fraction[];

const absolute = (value: bigint): bigint => (value < 0n ? -value : value);

const greatestCommonDivisor = (left: bigint, right: bigint): bigint => {
    let first = absolute(left);
    let second = absolute(right);
    while (second !== 0n) {
        [first, second] = [second, first % second];
    }
    return first;
};

const fraction = (numerator: bigint, denominator = 1n): Fraction => {
    if (denominator === 0n) throw new RangeError('Division by zero.');
    const sign = denominator < 0n ? -1n : 1n;
    const divisor = greatestCommonDivisor(numerator, denominator);
    return {
        numerator: (sign * numerator) / divisor,
        denominator: absolute(denominator) / divisor,
    };
};

const addFraction = (left: Fraction, right: Fraction): Fraction =>
    fraction(
        left.numerator * right.denominator + right.numerator * left.denominator,
        left.denominator * right.denominator,
    );
const negateFraction = (value: Fraction): Fraction =>
    fraction(-value.numerator, value.denominator);
const subtractFraction = (left: Fraction, right: Fraction): Fraction =>
    addFraction(left, negateFraction(right));
const multiplyFraction = (left: Fraction, right: Fraction): Fraction =>
    fraction(
        left.numerator * right.numerator,
        left.denominator * right.denominator,
    );
const inverseFraction = (value: Fraction): Fraction => {
    if (value.numerator === 0n) throw new RangeError('Zero has no inverse.');
    return fraction(value.denominator, value.numerator);
};

const createRationalRing = (
    coefficient: (index: number) => Fraction,
): RationalRingElement =>
    Array.from({ length: reducedInterpolationRingDegree }, (_unused, index) =>
        coefficient(index),
    );
const rationalRingOne = (): RationalRingElement =>
    createRationalRing((index) => fraction(index === 0 ? 1n : 0n));
const rationalRingCoefficient = (
    value: RationalRingElement,
    index: number,
): Fraction => {
    const coefficient = value[index];
    if (coefficient === undefined) {
        throw new Error('A rational-ring coefficient is absent.');
    }
    return coefficient;
};
const addRationalRing = (
    left: RationalRingElement,
    right: RationalRingElement,
): RationalRingElement =>
    createRationalRing((index) =>
        addFraction(
            rationalRingCoefficient(left, index),
            rationalRingCoefficient(right, index),
        ),
    );
const negateRationalRing = (value: RationalRingElement): RationalRingElement =>
    createRationalRing((index) =>
        negateFraction(rationalRingCoefficient(value, index)),
    );
const subtractRationalRing = (
    left: RationalRingElement,
    right: RationalRingElement,
): RationalRingElement => addRationalRing(left, negateRationalRing(right));
const multiplyRationalRing = (
    left: RationalRingElement,
    right: RationalRingElement,
): RationalRingElement => {
    const coefficients = Array.from(
        { length: reducedInterpolationRingDegree },
        () => fraction(0n),
    );
    for (
        let leftIndex = 0;
        leftIndex < reducedInterpolationRingDegree;
        leftIndex += 1
    ) {
        for (
            let rightIndex = 0;
            rightIndex < reducedInterpolationRingDegree;
            rightIndex += 1
        ) {
            const exponent = leftIndex + rightIndex;
            const target = exponent % reducedInterpolationRingDegree;
            const sign = exponent >= reducedInterpolationRingDegree ? -1n : 1n;
            coefficients[target] = addFraction(
                rationalRingCoefficient(coefficients, target),
                multiplyFraction(
                    fraction(sign),
                    multiplyFraction(
                        rationalRingCoefficient(left, leftIndex),
                        rationalRingCoefficient(right, rightIndex),
                    ),
                ),
            );
        }
    }
    return coefficients;
};
const scaleRationalRing = (
    value: RationalRingElement,
    scalar: bigint,
): RationalRingElement =>
    createRationalRing((index) =>
        multiplyFraction(
            rationalRingCoefficient(value, index),
            fraction(scalar),
        ),
    );
const equalRationalRing = (
    left: RationalRingElement,
    right: RationalRingElement,
): boolean =>
    left.every((coefficient, index) => {
        const other = rationalRingCoefficient(right, index);
        return (
            coefficient.numerator === other.numerator &&
            coefficient.denominator === other.denominator
        );
    });

const invertRationalRing = (
    value: RationalRingElement,
): RationalRingElement => {
    const matrix = Array.from(
        { length: reducedInterpolationRingDegree },
        (_unused, row) => [
            ...Array.from(
                { length: reducedInterpolationRingDegree },
                (_unusedColumn, column) =>
                    rationalRingCoefficient(
                        multiplyRationalRing(
                            value,
                            createRationalRing((index) =>
                                fraction(index === column ? 1n : 0n),
                            ),
                        ),
                        row,
                    ),
            ),
            fraction(row === 0 ? 1n : 0n),
        ],
    );

    for (let column = 0; column < reducedInterpolationRingDegree; column += 1) {
        const pivot = matrix.findIndex(
            (row, rowIndex) =>
                rowIndex >= column && (row[column]?.numerator ?? 0n) !== 0n,
        );
        if (pivot < 0) {
            throw new RangeError(
                'The rational-ring element is not invertible.',
            );
        }
        [matrix[column], matrix[pivot]] = [matrix[pivot], matrix[column]];
        const pivotInverse = inverseFraction(matrix[column][column]);
        matrix[column] = matrix[column].map((entry) =>
            multiplyFraction(entry, pivotInverse),
        );
        for (let row = 0; row < reducedInterpolationRingDegree; row += 1) {
            if (row === column) continue;
            const factor = matrix[row][column];
            if (factor.numerator === 0n) continue;
            matrix[row] = matrix[row].map((entry, index) =>
                subtractFraction(
                    entry,
                    multiplyFraction(factor, matrix[column][index]),
                ),
            );
        }
    }

    const result = createRationalRing(
        (index) => matrix[index][reducedInterpolationRingDegree],
    );
    if (
        !equalRationalRing(
            multiplyRationalRing(value, result),
            rationalRingOne(),
        )
    ) {
        throw new Error('The rational-ring inverse is incorrect.');
    }
    return result;
};

const monomialPoint = (exponent: number): RationalRingElement => {
    const reducedExponent = exponent % (2 * reducedInterpolationRingDegree);
    const coefficientIndex = reducedExponent % reducedInterpolationRingDegree;
    const sign = reducedExponent >= reducedInterpolationRingDegree ? -1n : 1n;
    return createRationalRing((index) =>
        fraction(index === coefficientIndex ? sign : 0n),
    );
};

const combinations = (size: number, choose: number): readonly number[][] => {
    const result: number[][] = [];
    const visit = (start: number, selected: number[]): void => {
        if (selected.length === choose) {
            result.push([...selected]);
            return;
        }
        for (
            let index = start;
            index <= size - (choose - selected.length);
            index += 1
        ) {
            selected.push(index);
            visit(index + 1, selected);
            selected.pop();
        }
    };
    visit(0, []);
    return result;
};

const lagrangeCoefficientAtZero = (
    points: readonly RationalRingElement[],
    selectedIndex: number,
): RationalRingElement => {
    const selectedPoint = points[selectedIndex];
    if (selectedPoint === undefined) {
        throw new Error('The selected interpolation point is absent.');
    }
    let numerator = rationalRingOne();
    let denominator = rationalRingOne();
    for (let index = 0; index < points.length; index += 1) {
        if (index === selectedIndex) continue;
        const point = points[index];
        if (point === undefined) {
            throw new Error('An interpolation point is absent.');
        }
        numerator = multiplyRationalRing(numerator, negateRationalRing(point));
        denominator = multiplyRationalRing(
            denominator,
            subtractRationalRing(selectedPoint, point),
        );
    }
    return multiplyRationalRing(numerator, invertRationalRing(denominator));
};

const integerOneNorm = (value: RationalRingElement): bigint =>
    value.reduce((sum, coefficient) => {
        if (coefficient.denominator !== 1n) {
            throw new Error(
                'A cleared interpolation coefficient is fractional.',
            );
        }
        return sum + absolute(coefficient.numerator);
    }, 0n);

const exactInterpolationCensus = (): Readonly<{
    authorizedSubsetCount: number;
    boundedIntegerSharingReconstructionCount: number;
    exactMaximumScaledReconstructionCoefficientOneNorm: bigint;
    exactMaximumSimulationCoefficientOneNorm: bigint;
    exactMaximumJointSimulationCoefficientOneNormSum: bigint;
    lagrangeCoefficientCount: number;
}> => {
    const participantPoints = Array.from(
        { length: participantCount },
        (_unused, index) => monomialPoint(index),
    );
    const authorizedSubsets = combinations(participantCount, releaseThreshold);
    const integerSharingPolynomial = Array.from(
        { length: releaseThreshold },
        (_unused, degree) =>
            createRationalRing((index) =>
                fraction(BigInt((degree + 1) * (index + 3) - 2 * index)),
            ),
    );
    const integerShares = participantPoints.map((point) => {
        let value = createRationalRing(() => fraction(0n));
        for (
            let degree = integerSharingPolynomial.length - 1;
            degree >= 0;
            degree -= 1
        ) {
            value = addRationalRing(
                multiplyRationalRing(value, point),
                integerSharingPolynomial[degree] ?? rationalRingOne(),
            );
        }
        return value;
    });
    let exactMaximumScaledReconstructionCoefficientOneNorm = 0n;
    let exactMaximumSimulationCoefficientOneNorm = 0n;
    let boundedIntegerSharingReconstructionCount = 0;
    let lagrangeCoefficientCount = 0;
    const simulationNormSums = new Map<string, bigint>();

    for (const authorizedSubset of authorizedSubsets) {
        const points = authorizedSubset.map((index) => {
            const point = participantPoints[index];
            if (point === undefined) {
                throw new Error('A participant interpolation point is absent.');
            }
            return point;
        });
        for (let index = 0; index < points.length; index += 1) {
            const coefficient = lagrangeCoefficientAtZero(points, index);
            const scaledCoefficientOneNorm = integerOneNorm(
                scaleRationalRing(coefficient, reconstructionClearingFactor),
            );
            exactMaximumScaledReconstructionCoefficientOneNorm =
                exactMaximumScaledReconstructionCoefficientOneNorm >
                scaledCoefficientOneNorm
                    ? exactMaximumScaledReconstructionCoefficientOneNorm
                    : scaledCoefficientOneNorm;
            const inverseCoefficientOneNorm = integerOneNorm(
                invertRationalRing(coefficient),
            );
            const corruptPositions = authorizedSubset
                .filter((_position, selectedIndex) => selectedIndex !== index)
                .join(',');
            simulationNormSums.set(
                corruptPositions,
                (simulationNormSums.get(corruptPositions) ?? 0n) +
                    inverseCoefficientOneNorm,
            );
            exactMaximumSimulationCoefficientOneNorm =
                exactMaximumSimulationCoefficientOneNorm >
                inverseCoefficientOneNorm
                    ? exactMaximumSimulationCoefficientOneNorm
                    : inverseCoefficientOneNorm;
            lagrangeCoefficientCount += 1;
        }
        const reconstructed = authorizedSubset.reduce(
            (sum, participant, index) =>
                addRationalRing(
                    sum,
                    multiplyRationalRing(
                        scaleRationalRing(
                            lagrangeCoefficientAtZero(points, index),
                            reconstructionClearingFactor,
                        ),
                        integerShares[participant] ?? rationalRingOne(),
                    ),
                ),
            createRationalRing(() => fraction(0n)),
        );
        if (
            !equalRationalRing(
                reconstructed,
                scaleRationalRing(
                    integerSharingPolynomial[0] ?? rationalRingOne(),
                    reconstructionClearingFactor,
                ),
            )
        ) {
            throw new Error(
                'A bounded-integer sharing subset failed reconstruction.',
            );
        }
        boundedIntegerSharingReconstructionCount += 1;
    }

    return {
        authorizedSubsetCount: authorizedSubsets.length,
        boundedIntegerSharingReconstructionCount,
        exactMaximumScaledReconstructionCoefficientOneNorm,
        exactMaximumSimulationCoefficientOneNorm,
        exactMaximumJointSimulationCoefficientOneNormSum: [
            ...simulationNormSums.values(),
        ].reduce((maximum, value) => (value > maximum ? value : maximum), 0n),
        lagrangeCoefficientCount,
    };
};

// KLLPS26 equation (1), with its 2N replaced by the spaced interpolation
// size. This floating-point value is displayed only; bit lengths use the
// certified rational upper bound below.
const optimizedInterpolationProductBound = (): number => {
    const halfThreshold = Math.floor(releaseThreshold / 2);
    let product =
        1 / Math.sin((Math.PI * halfThreshold) / spacedInterpolationSize) ** 2;
    for (let index = 1; index < halfThreshold; index += 1) {
        product *=
            1 / Math.tan((Math.PI * index) / spacedInterpolationSize) ** 2;
    }
    return (
        Number(reconstructionClearingFactor) *
        (spacedInterpolationSize / 2) *
        product
    );
};

// pi = 3.14159265358979323..., so this fraction is below pi.
const piLowerBound = fraction(314_159_265_358_979n, 100_000_000_000_000n);

// For 0 < x <= pi/4, sin(x) >= x - x^3/6 and tan(x) >= x + x^3/3, and both
// lower bounds increase with x. Evaluating them at angles computed from a
// lower bound on pi gives a rational upper bound on the same product.
const certifiedInterpolationProductUpperBound = (): Fraction => {
    const halfThreshold = Math.floor(releaseThreshold / 2);
    if (4 * halfThreshold > spacedInterpolationSize) {
        throw new RangeError('A certified interpolation angle exceeds pi/4.');
    }
    const angleLowerBound = (multiple: number): Fraction =>
        multiplyFraction(
            piLowerBound,
            fraction(BigInt(multiple), BigInt(spacedInterpolationSize)),
        );
    const cubeOverDivisor = (angle: Fraction, divisor: bigint): Fraction =>
        multiplyFraction(
            multiplyFraction(angle, multiplyFraction(angle, angle)),
            fraction(1n, divisor),
        );
    const inverseSquare = (value: Fraction): Fraction =>
        inverseFraction(multiplyFraction(value, value));
    const sineAngle = angleLowerBound(halfThreshold);
    let product = inverseSquare(
        subtractFraction(sineAngle, cubeOverDivisor(sineAngle, 6n)),
    );
    for (let index = 1; index < halfThreshold; index += 1) {
        const tangentAngle = angleLowerBound(index);
        product = multiplyFraction(
            product,
            inverseSquare(
                addFraction(tangentAngle, cubeOverDivisor(tangentAngle, 3n)),
            ),
        );
    }
    return multiplyFraction(
        fraction(
            reconstructionClearingFactor * BigInt(spacedInterpolationSize / 2),
        ),
        product,
    );
};

// Exact ceil(log2(t * 2^lambda * N * B)) for a positive rational bound B.
// A power of two bounds a rational value exactly when it bounds its ceiling.
const requiredDominantNoiseBudgetBitLength = (
    statisticalSecurityBitLength: number,
    interpolationProductBound: Fraction,
): number => {
    const dominantFactor = multiplyFraction(
        fraction(
            BigInt(releaseThreshold * polynomialModulusDegree) <<
                BigInt(statisticalSecurityBitLength),
        ),
        interpolationProductBound,
    );
    const dominantFactorCeiling =
        (dominantFactor.numerator + dominantFactor.denominator - 1n) /
        dominantFactor.denominator;
    return (dominantFactorCeiling - 1n).toString(2).length;
};

export type ThresholdReleaseNoiseCensus = Readonly<{
    authorizedSubsetCount: number;
    boundedIntegerSharingReconstructionCount: number;
    completionParticipantCount: number;
    exactInterpolationProduct: bigint;
    exactConservativeSecurityDominantNoiseBudgetLowerBoundBitLength: number;
    exactMaximumScaledReconstructionCoefficientOneNorm: bigint;
    exactMaximumSimulationCoefficientOneNorm: bigint;
    exactMaximumJointSimulationCoefficientOneNormSum: bigint;
    jointTargetSecurityDominantNoiseReserveBitLength: number;
    exactTargetSecurityDominantNoiseBudgetLowerBoundBitLength: number;
    lagrangeCoefficientCount: number;
    productionInterpolationPointExponentStride: number;
    releaseThreshold: number;
    spacedInterpolationSize: number;
    interpolationProductBound: number;
    targetSecurityDominantNoiseBudgetLowerBoundBitLength: number;
    conservativeSecurityDominantNoiseBudgetLowerBoundBitLength: number;
}>;

export const compileThresholdReleaseNoiseCensus =
    (): ThresholdReleaseNoiseCensus => {
        const exactInterpolation = exactInterpolationCensus();
        const interpolationProductUpperBound =
            certifiedInterpolationProductUpperBound();
        const exactInterpolationProduct =
            exactInterpolation.exactMaximumScaledReconstructionCoefficientOneNorm *
            exactInterpolation.exactMaximumSimulationCoefficientOneNorm;
        // Joint cube coupling charges every honest release for a fixed corrupt
        // set. Width 2*B_sm+1 gives B_sm = 2^(lambda-1)*N*sum_i ||lambda_0,i||_1*E.
        // This remains a dominant-term floor; the entire accepted support and
        // every non-dominant BFV correctness term must also be included.
        const jointDominantFactor =
            BigInt(releaseThreshold * polynomialModulusDegree) *
            (1n << 79n) *
            exactInterpolation.exactMaximumScaledReconstructionCoefficientOneNorm *
            exactInterpolation.exactMaximumJointSimulationCoefficientOneNormSum;
        return {
            authorizedSubsetCount: exactInterpolation.authorizedSubsetCount,
            boundedIntegerSharingReconstructionCount:
                exactInterpolation.boundedIntegerSharingReconstructionCount,
            completionParticipantCount: participantCount,
            exactInterpolationProduct,
            exactConservativeSecurityDominantNoiseBudgetLowerBoundBitLength:
                requiredDominantNoiseBudgetBitLength(
                    128,
                    fraction(exactInterpolationProduct),
                ),
            exactMaximumScaledReconstructionCoefficientOneNorm:
                exactInterpolation.exactMaximumScaledReconstructionCoefficientOneNorm,
            exactMaximumSimulationCoefficientOneNorm:
                exactInterpolation.exactMaximumSimulationCoefficientOneNorm,
            exactMaximumJointSimulationCoefficientOneNormSum:
                exactInterpolation.exactMaximumJointSimulationCoefficientOneNormSum,
            jointTargetSecurityDominantNoiseReserveBitLength: (
                jointDominantFactor - 1n
            ).toString(2).length,
            exactTargetSecurityDominantNoiseBudgetLowerBoundBitLength:
                requiredDominantNoiseBudgetBitLength(
                    80,
                    fraction(exactInterpolationProduct),
                ),
            lagrangeCoefficientCount:
                exactInterpolation.lagrangeCoefficientCount,
            productionInterpolationPointExponentStride,
            releaseThreshold,
            spacedInterpolationSize,
            interpolationProductBound: optimizedInterpolationProductBound(),
            targetSecurityDominantNoiseBudgetLowerBoundBitLength:
                requiredDominantNoiseBudgetBitLength(
                    80,
                    interpolationProductUpperBound,
                ),
            conservativeSecurityDominantNoiseBudgetLowerBoundBitLength:
                requiredDominantNoiseBudgetBitLength(
                    128,
                    interpolationProductUpperBound,
                ),
        };
    };
