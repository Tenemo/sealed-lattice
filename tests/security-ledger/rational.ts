import assert from 'node:assert/strict';

// Exact nonnegative rationals for probabilities and cost ratios.
export type Rational = Readonly<{ numerator: bigint; denominator: bigint }>;

export const rational = (numerator: bigint, denominator = 1n): Rational => {
    assert.ok(numerator >= 0n && denominator > 0n);
    return { numerator, denominator };
};

export const addRationals = (...values: readonly Rational[]): Rational =>
    values.reduce(
        (sum, value) =>
            rational(
                sum.numerator * value.denominator +
                    value.numerator * sum.denominator,
                sum.denominator * value.denominator,
            ),
        rational(0n),
    );

export const atMost = (left: Rational, right: Rational) =>
    left.numerator * right.denominator <= right.numerator * left.denominator;

// Smallest integer r with value <= r^2. Newton's iteration from above
// descends to the integer square root's floor.
export const ceilingSquareRoot = (value: bigint) => {
    assert.ok(value >= 0n);
    if (value < 2n) return value;
    let root = value;
    let next = (value + 1n) / 2n;
    while (next < root) {
        root = next;
        next = (root + value / root) / 2n;
    }
    return root * root < value ? root + 1n : root;
};

// Smallest integer k with value <= 2^k, for a positive value.
export const rationalCeilingLog2 = (value: Rational) => {
    assert.ok(value.numerator > 0n);
    const fits = (exponent: bigint) =>
        exponent >= 0n
            ? value.numerator <= value.denominator << exponent
            : value.numerator << -exponent <= value.denominator;
    let exponent =
        BigInt(value.numerator.toString(2).length) -
        BigInt(value.denominator.toString(2).length);
    while (!fits(exponent)) exponent += 1n;
    while (fits(exponent - 1n)) exponent -= 1n;
    return exponent;
};
