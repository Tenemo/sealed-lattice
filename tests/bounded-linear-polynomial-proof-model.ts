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
const sumMaskDegree = witnessDegree;
const firstMask = [4, 1, 9, 7, 2, 3];
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

const matrixRank = (input: readonly (readonly number[])[]): number => {
    const rows = input.map((row) => [...row]);
    let pivot = 0;
    for (
        let column = 0;
        column < rows[0].length && pivot < rows.length;
        column++
    ) {
        const selected = rows.findIndex(
            (row, index) => index >= pivot && row[column] !== 0,
        );
        if (selected < 0) continue;
        [rows[pivot], rows[selected]] = [rows[selected], rows[pivot]];
        const divisor = inverse(rows[pivot][column]);
        rows[pivot] = rows[pivot].map((value) => mod(value * divisor));
        for (let row = 0; row < rows.length; row++) {
            if (row === pivot) continue;
            const factor = rows[row][column];
            rows[row] = rows[row].map((value, index) =>
                mod(value - factor * rows[pivot][index]),
            );
        }
        pivot++;
    }
    return pivot;
};

const shortMaskViewCensus = () => {
    const columnCount = assignment.length;
    const observationCount = 2 * (columnCount + 2) + 1;
    const randomCoefficientCount =
        (columnCount + 1) * maskDimension + systematicSize;
    let checkedViews = 0;
    let minimumRank = observationCount;
    let maximumRankWithoutQuotientMask = 0;
    for (const pair of [
        [0, 1],
        [0, 16],
        [7, 9],
        [12, 31],
    ]) {
        const points = pair.map((index) => domain[index]);
        for (let alpha = 0; alpha < prime; alpha++) {
            const weights = matrix[0].map((column, index) =>
                interpolate(
                    systematic,
                    column.map((value, position) =>
                        mod(value + alpha * matrix[1][index][position]),
                    ),
                ),
            );
            for (const challenge of [0, 1, 2, 48, 96]) {
                const observe = (coins: readonly number[]): number[] => {
                    const masks = Array.from(
                        { length: columnCount },
                        (_, index) =>
                            coins.slice(
                                index * maskDimension,
                                (index + 1) * maskDimension,
                            ),
                    );
                    const low = coins.slice(
                        columnCount * maskDimension,
                        columnCount * maskDimension + systematicSize,
                    );
                    const high = coins.slice(
                        columnCount * maskDimension + systematicSize,
                    );
                    const values = masks.flatMap((mask) =>
                        points.map((point) =>
                            mod(
                                evaluate(vanishing, point) *
                                    evaluate(mask, point),
                            ),
                        ),
                    );
                    values.push(
                        ...points.map((point) =>
                            mod(
                                evaluate(low, point) +
                                    evaluate(vanishing, point) *
                                        evaluate(high, point),
                            ),
                        ),
                    );
                    values.push(
                        ...points.map((point) =>
                            mod(
                                evaluate(high, point) +
                                    challenge *
                                        masks.reduce(
                                            (sum, mask, index) =>
                                                mod(
                                                    sum +
                                                        evaluate(
                                                            weights[index],
                                                            point,
                                                        ) *
                                                            evaluate(
                                                                mask,
                                                                point,
                                                            ),
                                                ),
                                            0,
                                        ),
                            ),
                        ),
                    );
                    values.push(mod(systematicSize * low[0]));
                    return values;
                };
                const columns = Array.from(
                    { length: randomCoefficientCount },
                    (_, index) =>
                        observe(
                            Array.from(
                                { length: randomCoefficientCount },
                                (_unused, position) =>
                                    position === index ? 1 : 0,
                            ),
                        ),
                );
                const observationMatrix = Array.from(
                    { length: observationCount },
                    (_, row) => columns.map((column) => column[row]),
                );
                minimumRank = Math.min(
                    minimumRank,
                    matrixRank(observationMatrix),
                );
                maximumRankWithoutQuotientMask = Math.max(
                    maximumRankWithoutQuotientMask,
                    matrixRank(
                        observationMatrix.map((row) =>
                            row.slice(0, -maskDimension),
                        ),
                    ),
                );
                checkedViews++;
            }
        }
    }
    return {
        checkedViews,
        observationCount,
        minimumRank,
        maximumRankWithoutQuotientMask,
    };
};

export const compileBoundedLinearPolynomialProofCensus = () => {
    assert.ok(firstMask.length - 1 <= sumMaskDegree);
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
            // A short mask changes only its low constant to establish the
            // claimed sum. Its independent high part masks quotient queries.
            const simulatedMask = [...firstMask];
            simulatedMask[0] = mod(
                simulatedMask[0] +
                    (falseSum -
                        sumOnSystematic(
                            add(
                                scale(simulatedCombination, maskChallenge),
                                simulatedMask,
                            ),
                        )) *
                        inverse(systematicSize),
            );
            const simulatedMasked = add(
                scale(simulatedCombination, maskChallenge),
                simulatedMask,
            );
            assert.ok(simulatedMask.length - 1 <= sumMaskDegree);
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
    const shortMaskViews = shortMaskViewCensus();
    assert.equal(shortMaskViews.minimumRank, shortMaskViews.observationCount);
    assert.ok(
        shortMaskViews.maximumRankWithoutQuotientMask <
            shortMaskViews.observationCount,
    );
    return {
        prime,
        systematicSize,
        maskDimension,
        domainSize: domain.length,
        witnessDegree,
        sumDegree,
        sumMaskDegree,
        shortMaskViews,
        normDegrees: degrees,
        trueAcceptanceCount,
        falseAcceptanceCount,
        simulatedFalseAcceptanceCount,
        invalidNormTableDegree: invalidNorm,
        tamperedWitnessTableDegree: degreeOfTable(tamperedTable),
    };
};
