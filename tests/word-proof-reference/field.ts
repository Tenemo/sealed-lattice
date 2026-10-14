import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { type WordProofDomain } from '#tests/word-proof-reference/transcript.js';

const field = compileSmallLimbProofFieldCensus();

export const modulus = field.modulus;

const nonresidue = field.cubicNonresidue;

export const shift = field.prothWitness;

export type Extension = readonly [bigint, bigint, bigint];

export const reduce = (value: bigint) => {
    const result = value % modulus;
    return result < 0n ? result + modulus : result;
};

export const power = (base: bigint, exponent: bigint) => {
    let result = 1n;
    let current = reduce(base);
    for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
        if ((remaining & 1n) === 1n) result = (result * current) % modulus;
        current = (current * current) % modulus;
    }
    return result;
};

export const inverse = (value: bigint) => {
    if (reduce(value) === 0n) throw new RangeError('Zero has no inverse.');
    return power(value, modulus - 2n);
};

// The inverses of nonzero values with one exponentiation.
export const inverses = (values: readonly bigint[]) => {
    const prefixes: bigint[] = [];
    let product = 1n;
    for (const value of values) {
        prefixes.push(product);
        product = (product * value) % modulus;
    }
    let suffix = inverse(product);
    const output = new Array<bigint>(values.length);
    for (let index = values.length - 1; index >= 0; index--) {
        output[index] = (prefixes[index] * suffix) % modulus;
        suffix = (suffix * values[index]) % modulus;
    }
    return output;
};

export const zero: Extension = [0n, 0n, 0n];

export const one: Extension = [1n, 0n, 0n];

export const base = (value: bigint): Extension => [reduce(value), 0n, 0n];

export const add = (left: Extension, right: Extension): Extension => [
    reduce(left[0] + right[0]),
    reduce(left[1] + right[1]),
    reduce(left[2] + right[2]),
];

export const subtract = (left: Extension, right: Extension): Extension => [
    reduce(left[0] - right[0]),
    reduce(left[1] - right[1]),
    reduce(left[2] - right[2]),
];

export const scale = (value: Extension, factor: bigint): Extension => [
    reduce(value[0] * factor),
    reduce(value[1] * factor),
    reduce(value[2] * factor),
];

// The cubic extension by a root of X^3 minus the census nonresidue.
export const multiply = (left: Extension, right: Extension): Extension => {
    const [a0, a1, a2] = left;
    const [b0, b1, b2] = right;
    return [
        reduce(a0 * b0 + nonresidue * (a1 * b2 + a2 * b1)),
        reduce(a0 * b1 + a1 * b0 + nonresidue * a2 * b2),
        reduce(a0 * b2 + a1 * b1 + a2 * b0),
    ];
};

// The norm map gives an extension element's inverse through the base field.
export const invertExtension = (value: Extension): Extension => {
    const [a0, a1, a2] = value;
    const c0 = reduce(a0 * a0 - nonresidue * a1 * a2);
    const c1 = reduce(nonresidue * a2 * a2 - a0 * a1);
    const c2 = reduce(a1 * a1 - a0 * a2);
    const norm = reduce(a0 * c0 + nonresidue * (a1 * c2 + a2 * c1));
    return scale([c0, c1, c2], inverse(norm));
};

export const equal = (left: Extension, right: Extension) =>
    left[0] === right[0] && left[1] === right[1] && left[2] === right[2];

export const wordFieldArithmetic = {
    modulus,
    zero,
    one,
    base,
    add,
    subtract,
    multiply,
    scale,
    equal,
};

const domainRoot = (length: number) =>
    power(shift, (modulus - 1n) / BigInt(length));

export const point = (domain: WordProofDomain, position: number) =>
    reduce(shift * power(domainRoot(domain.domain), BigInt(position)));

// A radix-two transform of a power-of-two vector at the powers of a root of
// that order, in natural order.
const transform = (values: readonly bigint[], root: bigint) => {
    const size = values.length;
    const output = [...values];
    for (let index = 1, reversed = 0; index < size; index++) {
        let bit = size >> 1;
        for (; (reversed & bit) !== 0; bit >>= 1) reversed ^= bit;
        reversed ^= bit;
        if (index < reversed)
            [output[index], output[reversed]] = [
                output[reversed],
                output[index],
            ];
    }
    for (let length = 2; length <= size; length <<= 1) {
        const step = power(root, BigInt(size / length));
        const twiddles = [1n];
        for (let offset = 1; offset < length / 2; offset++)
            twiddles.push((twiddles[offset - 1] * step) % modulus);
        for (let start = 0; start < size; start += length)
            for (let offset = 0; offset < length / 2; offset++) {
                const even = output[start + offset];
                const odd =
                    (output[start + offset + length / 2] * twiddles[offset]) %
                    modulus;
                output[start + offset] = (even + odd) % modulus;
                output[start + offset + length / 2] = reduce(even - odd);
            }
    }
    return output;
};

// Coefficients from values on the subgroup of the vector's size.
export const interpolate = (values: readonly bigint[]) => {
    const size = values.length;
    const scaleBack = inverse(BigInt(size));
    return transform(values, inverse(domainRoot(size))).map(
        (value) => (value * scaleBack) % modulus,
    );
};

// Values at every point of the evaluation coset.
export const evaluateOnCoset = (
    coefficients: readonly bigint[],
    domain: WordProofDomain,
) => {
    if (coefficients.length > domain.domain)
        throw new RangeError('The polynomial exceeds its evaluation domain.');
    const twisted = new Array<bigint>(domain.domain).fill(0n);
    let twist = 1n;
    coefficients.forEach((coefficient, degree) => {
        twisted[degree] = (coefficient * twist) % modulus;
        twist = (twist * shift) % modulus;
    });
    return transform(twisted, domainRoot(domain.domain));
};

// Extension-valued vectors by coordinate.
const extensionCoordinates = (values: readonly Extension[]) =>
    [0, 1, 2].map((index) => values.map((value) => value[index]));

const fromCoordinates = (coordinates: readonly (readonly bigint[])[]) =>
    coordinates[0].map((value, index): Extension => [
        value,
        coordinates[1][index],
        coordinates[2][index],
    ]);

export const interpolateExtension = (values: readonly Extension[]) =>
    fromCoordinates(extensionCoordinates(values).map(interpolate));

export const evaluateExtensionOnCoset = (
    coefficients: readonly Extension[],
    domain: WordProofDomain,
) =>
    fromCoordinates(
        extensionCoordinates(coefficients).map((coordinate) =>
            evaluateOnCoset(coordinate, domain),
        ),
    );

// Each column's interpolant over the systematic subgroup, whose element of
// index h carries the column's value h, at the given evaluation positions.
export const evaluateSystematicColumns = (
    domain: WordProofDomain,
    columns: readonly (readonly Extension[])[],
    positions: readonly number[],
) =>
    columns.map((column) => {
        if (column.length !== domain.systematic)
            throw new RangeError('A column does not cover the subgroup.');
        const values = fromCoordinates(
            extensionCoordinates(column).map((coordinate) =>
                evaluateOnCoset(interpolate(coordinate), domain),
            ),
        );
        return positions.map((position) => values[position]);
    });

// The lookup table polynomial takes the systematic subgroup's element of
// each index to that index. Its coefficients are (H-1)/2 at degree zero and
// 1/(omega^-k - 1) at each degree k, for the subgroup's root omega.
export const lookupTableCoefficients = (domain: WordProofDomain) => {
    const inverseOmega = inverse(domainRoot(domain.systematic));
    const denominators: bigint[] = [];
    for (
        let degree = 1, current = inverseOmega;
        degree < domain.systematic;
        degree++, current = (current * inverseOmega) % modulus
    )
        denominators.push(reduce(current - 1n));
    return [
        reduce(BigInt(domain.systematic - 1) * inverse(2n)),
        ...inverses(denominators),
    ];
};

const tables = new Map<number, readonly bigint[]>();

export const tableOnDomain = (domain: WordProofDomain) => {
    let table = tables.get(domain.domain);
    if (table === undefined) {
        table = evaluateOnCoset(lookupTableCoefficients(domain), domain);
        tables.set(domain.domain, table);
    }
    return table;
};
