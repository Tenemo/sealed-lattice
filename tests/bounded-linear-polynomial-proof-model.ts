import assert from 'node:assert/strict';

// A finite RS-encoded experiment with an exhaustive degree oracle. There is
// no Merkle/Fiat-Shamir compiler or production acceptance path in this file.
const prime = 97;
const systematicSize = 4;
const maskDimension = 2;
const witnessDegree = systematicSize + maskDimension - 1;
const sumDegree = 2 * systematicSize + maskDimension - 2;
const mod = (value: number): number => ((value % prime) + prime) % prime;
const pow = (base: number, exponent: number): number => {
    let value = 1;
    for (let bit = exponent; bit > 0; bit = Math.floor(bit / 2)) {
        if (bit % 2 === 1) value = mod(value * base);
        base = mod(base * base);
    }
    return value;
};
const inverse = (value: number): number => {
    assert.notEqual(mod(value), 0);
    return pow(mod(value), prime - 2);
};
type Polynomial = readonly number[];
const trim = (value: number[]): number[] => {
    while (value.length > 1 && value[value.length - 1] === 0) value.pop();
    return value;
};
const add = (left: Polynomial, right: Polynomial): number[] =>
    trim(
        Array.from(
            { length: Math.max(left.length, right.length) },
            (_, index) => mod((left[index] ?? 0) + (right[index] ?? 0)),
        ),
    );
const scale = (value: Polynomial, factor: number): number[] =>
    trim(value.map((coefficient) => mod(coefficient * factor)));
const subtract = (left: Polynomial, right: Polynomial): number[] =>
    add(left, scale(right, -1));
const multiply = (left: Polynomial, right: Polynomial): number[] => {
    const result = Array.from(
        { length: left.length + right.length - 1 },
        () => 0,
    );
    left.forEach((coefficient, index) =>
        right.forEach(
            (other, offset) =>
                (result[index + offset] = mod(
                    result[index + offset] + coefficient * other,
                )),
        ),
    );
    return trim(result);
};
const evaluate = (value: Polynomial, point: number): number =>
    value.reduceRight(
        (accumulator, coefficient) => mod(accumulator * point + coefficient),
        0,
    );
const systematic = Array.from({ length: systematicSize }, (_, index) =>
    pow(22, index),
);
const domain = Array.from({ length: 32 }, (_, index) =>
    mod(5 * pow(28, index)),
);
assert.equal(new Set(domain).size, 32);
assert.ok(domain.every((point) => !systematic.includes(point)));
const vanishing = [96, 0, 0, 0, 1];
assert.ok(systematic.every((point) => evaluate(vanishing, point) === 0));
const interpolate = (
    points: readonly number[],
    values: readonly number[],
): number[] =>
    points.reduce(
        (sum, point, index) => {
            let basis = [1];
            let divisor = 1;
            points.forEach((other, offset) => {
                if (offset === index) return;
                basis = multiply(basis, [mod(-other), 1]);
                divisor = mod(divisor * (point - other));
            });
            return add(
                sum,
                scale(basis, mod(values[index] * inverse(divisor))),
            );
        },
        [0],
    );
const inverseTransform = Array.from({ length: 32 }, (_, degree) =>
    domain.map((_point, index) =>
        mod(
            inverse(32) *
                pow(inverse(5), degree) *
                pow(inverse(28), degree * index),
        ),
    ),
);
const degreeOfTable = (values: readonly number[]): number => {
    const coefficients = inverseTransform.map((row) =>
        mod(
            row.reduce(
                (sum, coefficient, index) => sum + coefficient * values[index],
                0,
            ),
        ),
    );
    return trim(coefficients).length - 1;
};
const quotientByVanishing = (value: Polynomial): number[] => {
    const remainder = [...value];
    const quotient = Array.from(
        { length: Math.max(1, value.length - systematicSize) },
        () => 0,
    );
    for (
        let index = remainder.length - 1;
        index >= systematicSize;
        index -= 1
    ) {
        quotient[index - systematicSize] = remainder[index];
        remainder[index - systematicSize] = mod(
            remainder[index - systematicSize] + remainder[index],
        );
    }
    return trim(quotient);
};
const sumOnSystematic = (polynomial: Polynomial): number =>
    mod(
        systematic.reduce((sum, point) => sum + evaluate(polynomial, point), 0),
    );
const matrix = [
    [
        [1, 2, 3, 4],
        [4, 3, 2, 1],
    ],
    [
        [1, 2, 3, 4],
        [4, 3, 2, 1],
    ],
];
const assignment = [
    [1, 0, 1, 0],
    [96, 0, 1, 96],
];
const publicTarget = matrix.map((row) =>
    mod(
        row.reduce(
            (sum, coefficients, column) =>
                sum +
                coefficients.reduce(
                    (subtotal, coefficient, index) =>
                        subtotal + coefficient * assignment[column][index],
                    0,
                ),
            0,
        ),
    ),
);
const falseTarget = [mod(publicTarget[0] + 1), mod(publicTarget[1] - 1)];
// Identical left-hand sides and different right-hand sides make this instance
// unsatisfiable for every assignment, independently of the bounded witness.
assert.deepEqual(matrix[0], matrix[1]);
assert.notEqual(falseTarget[0], falseTarget[1]);
const witness = assignment.map((values, index) =>
    add(
        interpolate(systematic, values),
        multiply(vanishing, [index + 3, index + 7]),
    ),
);
const zeroWitness = assignment.map((_values, index) =>
    multiply(vanishing, [index + 4, index + 8]),
);
const firstMask = [4, 1, 9, 7, 2, 3, 8, 5, 6];
const maskSum = sumOnSystematic(firstMask);
const linearCombination = (
    oracles: readonly Polynomial[],
    challenge: number,
): number[] => {
    let result = [0];
    for (let column = 0; column < oracles.length; column += 1) {
        const weights = matrix[0][column].map((coefficient, index) =>
            mod(coefficient + challenge * matrix[1][column][index]),
        );
        result = add(
            result,
            multiply(interpolate(systematic, weights), oracles[column]),
        );
    }
    return result;
};
const normDegrees = (oracles: readonly Polynomial[]): number[] =>
    oracles.map((oracle, index) =>
        degreeOfTable(
            domain.map((point) => {
                const value = evaluate(oracle, point);
                const residual =
                    index === 0
                        ? mod(value * (value - 1))
                        : mod(value * (value - 1) * (value + 1));
                return mod(residual * inverse(evaluate(vanishing, point)));
            }),
        ),
    );
const sumcheckDegree = (masked: Polynomial, claimedSum: number): number => {
    const quotient = quotientByVanishing(masked);
    assert.ok(quotient.length - 1 <= sumDegree - systematicSize);
    return degreeOfTable(
        domain.map((point) =>
            mod(
                (evaluate(masked, point) -
                    evaluate(vanishing, point) * evaluate(quotient, point) -
                    claimedSum * inverse(systematicSize)) *
                    inverse(point),
            ),
        ),
    );
};

export const compileBoundedLinearPolynomialProofCensus = () => {
    assert.ok(witness.every((oracle) => oracle.length - 1 <= witnessDegree));
    const degrees = normDegrees(witness);
    assert.ok(degrees[0] <= 2 * witnessDegree - systematicSize);
    assert.ok(degrees[1] <= 3 * witnessDegree - systematicSize);
    let trueAcceptanceCount = 0,
        falseAcceptanceCount = 0,
        simulatedFalseAcceptanceCount = 0;
    for (let challenge = 0; challenge < prime; challenge += 1) {
        const combination = linearCombination(witness, challenge);
        const simulatedCombination = linearCombination(zeroWitness, challenge);
        for (let maskChallenge = 0; maskChallenge < prime; maskChallenge += 1) {
            const masked = add(scale(combination, maskChallenge), firstMask);
            const trueSum = mod(
                maskChallenge *
                    (publicTarget[0] + challenge * publicTarget[1]) +
                    maskSum,
            );
            const falseSum = mod(
                maskChallenge * (falseTarget[0] + challenge * falseTarget[1]) +
                    maskSum,
            );
            if (sumcheckDegree(masked, trueSum) <= systematicSize - 2)
                trueAcceptanceCount += 1;
            if (sumcheckDegree(masked, falseSum) <= systematicSize - 2)
                falseAcceptanceCount += 1;
            // Accepting simulator: choose the challenge first, then a random
            // polynomial with the claimed sum, and derive the mask backwards.
            const simulatedMasked = [...firstMask];
            simulatedMasked[0] = mod(
                simulatedMasked[0] +
                    (falseSum - sumOnSystematic(simulatedMasked)) *
                        inverse(systematicSize),
            );
            const simulatedMask = subtract(
                simulatedMasked,
                scale(simulatedCombination, maskChallenge),
            );
            assert.ok(simulatedMask.length - 1 <= sumDegree);
            assert.deepEqual(
                add(scale(simulatedCombination, maskChallenge), simulatedMask),
                trim(simulatedMasked),
            );
            if (sumcheckDegree(simulatedMasked, falseSum) <= systematicSize - 2)
                simulatedFalseAcceptanceCount += 1;
        }
    }
    assert.equal(trueAcceptanceCount, prime ** 2);
    assert.equal(falseAcceptanceCount, 2 * prime - 1);
    assert.equal(simulatedFalseAcceptanceCount, prime ** 2);
    const invalidNorm = normDegrees([[2], witness[1]])[0];
    assert.ok(invalidNorm > 2 * witnessDegree - systematicSize);
    const tamperedTable = domain.map((point) => evaluate(witness[0], point));
    tamperedTable[0] = mod(tamperedTable[0] + 1);
    assert.ok(degreeOfTable(tamperedTable) > witnessDegree);
    return {
        prime,
        systematicSize,
        maskDimension,
        domainSize: domain.length,
        witnessDegree,
        sumDegree,
        normDegrees: degrees,
        trueAcceptanceCount,
        falseAcceptanceCount,
        simulatedFalseAcceptanceCount,
        invalidNormTableDegree: invalidNorm,
        tamperedWitnessTableDegree: degreeOfTable(tamperedTable),
    };
};
