import assert from 'node:assert/strict';

// Exact rational-identity experiment in F_13[Z]/(Z^3-2). This is not a
// polynomial commitment or a complete lookup-proof implementation.
const prime = 13;
type Extension = readonly [number, number, number];
const mod = (value: number): number => ((value % prime) + prime) % prime;
const zero: Extension = [0, 0, 0];
const one: Extension = [1, 0, 0];
const add = (left: Extension, right: Extension): Extension => [
    mod(left[0] + right[0]),
    mod(left[1] + right[1]),
    mod(left[2] + right[2]),
];
const scale = (value: Extension, factor: number): Extension => [
    mod(value[0] * factor),
    mod(value[1] * factor),
    mod(value[2] * factor),
];
const multiply = (left: Extension, right: Extension): Extension => {
    const coefficients = [0, 0, 0, 0, 0];
    for (let i = 0; i < 3; i++)
        for (let j = 0; j < 3; j++) coefficients[i + j] += left[i] * right[j];
    for (let i = 4; i >= 3; i--) coefficients[i - 3] += 2 * coefficients[i];
    return [mod(coefficients[0]), mod(coefficients[1]), mod(coefficients[2])];
};
const pow = (value: Extension, exponent: number): Extension => {
    let result = one;
    for (
        let remaining = exponent;
        remaining > 0;
        remaining = Math.floor(remaining / 2)
    ) {
        if (remaining % 2 === 1) result = multiply(result, value);
        value = multiply(value, value);
    }
    return result;
};
const inverse = (value: Extension): Extension => {
    assert.notDeepEqual(value, zero);
    return pow(value, prime ** 3 - 2);
};
const sum = (values: readonly Extension[]): Extension =>
    values.reduce(add, zero);
const reciprocal = (challenge: Extension, value: number): Extension =>
    inverse(add(challenge, [mod(-value), 0, 0]));
const table = [0, 1, 2, 3];
const validWitness = [0, 0, 1, 1, 2, 2, 3, 3];
const invalidWitness = [0, 0, 1, 1, 2, 2, 3, 4];
const targetedChallenge: Extension = [1, 0, 1];
const targetedValue = sum(
    invalidWitness.map((value) => reciprocal(targetedChallenge, value)),
);
const columns = table.map((value) => reciprocal(targetedChallenge, value));
const matrix = Array.from({ length: 4 }, (_, row) => [
    ...columns.map((column) => (row === 3 ? 1 : column[row])),
    row === 3 ? invalidWitness.length : targetedValue[row],
]);
for (let column = 0; column < 4; column++) {
    const pivot = matrix.findIndex(
        (row, index) => index >= column && mod(row[column]) !== 0,
    );
    assert.ok(pivot >= column);
    [matrix[column], matrix[pivot]] = [matrix[pivot], matrix[column]];
    const factor = inverse([mod(matrix[column][column]), 0, 0])[0];
    matrix[column] = matrix[column].map((value) => mod(value * factor));
    for (let row = 0; row < 4; row++)
        if (row !== column) {
            const multiplier = matrix[row][column];
            matrix[row] = matrix[row].map((value, index) =>
                mod(value - multiplier * matrix[column][index]),
            );
        }
}
const forgedMultiplicities = matrix.map((row) => row[4]);
assert.equal(
    mod(forgedMultiplicities.reduce((total, value) => total + value, 0)),
    invalidWitness.length,
);
assert.deepEqual(
    sum(
        columns.map((column, index) =>
            scale(column, forgedMultiplicities[index]),
        ),
    ),
    targetedValue,
);
const accepts = (
    challenge: Extension,
    witness: readonly number[],
    multiplicities: readonly number[],
): boolean => {
    const left = sum(witness.map((value) => reciprocal(challenge, value)));
    const right = sum(
        table.map((value, index) =>
            scale(reciprocal(challenge, value), multiplicities[index]),
        ),
    );
    return left.every((value, index) => value === right[index]);
};

export const compileBoundedLookupCensus = () => {
    assert.equal(mod(2 ** ((prime - 1) / 3)), 3); // Noncube, so Z^3-2 is irreducible.
    assert.deepEqual(pow([0, 1, 0], prime ** 3), [0, 1, 0]);
    const roots: string[] = [];
    let challenges = 0,
        validAcceptances = 0,
        characteristicWrapAcceptances = 0;
    for (let first = 0; first < prime; first++)
        for (let second = 0; second < prime; second++)
            for (let third = 1; third < prime; third++) {
                const challenge: Extension = [first, second, third];
                challenges++;
                if (accepts(challenge, validWitness, [2, 2, 2, 2]))
                    validAcceptances++;
                if (accepts(challenge, invalidWitness, forgedMultiplicities))
                    roots.push(challenge.join(','));
                // Omitting the occurrence-count bound makes thirteen invalid values
                // disappear in the characteristic, despite the much larger extension.
                if (
                    accepts(
                        challenge,
                        Array.from({ length: prime }, () => 4),
                        [0, 0, 0, 0],
                    )
                )
                    characteristicWrapAcceptances++;
            }
    const conjugateRoots = [
        targetedChallenge,
        pow(targetedChallenge, prime),
        pow(targetedChallenge, prime ** 2),
    ]
        .map((value) => value.join(','))
        .sort();
    assert.deepEqual(roots.sort(), conjugateRoots);
    assert.equal(validAcceptances, challenges);
    assert.equal(characteristicWrapAcceptances, challenges);
    return {
        basePrime: prime,
        extensionDegree: 3,
        challengeCount: challenges,
        validAcceptances,
        invalidAcceptances: roots.length,
        forgedMultiplicities,
        roots,
        characteristicWrapAcceptances,
    };
};
