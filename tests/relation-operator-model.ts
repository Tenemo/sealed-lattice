import assert from 'node:assert/strict';

import { byteLength } from '#tests/exact-integer.js';
import {
    evaluateSystematicColumns,
    wordFieldArithmetic,
    type Extension,
} from '#tests/word-proof-reference/field.js';
import { type WordProofDomain } from '#tests/word-proof-reference/transcript.js';

// The affine operator of the setup, ballot and release relations, built
// from a canonical public statement at the affine challenge alpha. Row r of
// a relation has weight alpha^r, so a witness column's coefficient at a row
// is the alpha-weighted sum of its factors in every relation row, and the
// target is the alpha-weighted sum of the rows' public constants. The limb
// rows of one equation lie one ring degree apart, so a public operand
// enters through its fingerprint: its signed limbs weighted by the powers
// of alpha^degree. A product of a public polynomial with a secret ring
// element gives that element the polynomial's negacyclic adjoint. The
// operator keeps each public column with the weight it gives every witness
// column, which is how a verifier evaluates it at queried points.

const { modulus, zero, one, add, subtract, multiply, scale, equal } =
    wordFieldArithmetic;

export const negate = (value: Extension) => subtract(zero, value);

export const power = (value: Extension, exponent: number): Extension => {
    let result = one;
    let current = value;
    for (let remaining = exponent; remaining > 0; remaining >>= 1) {
        if ((remaining & 1) === 1) result = multiply(result, current);
        current = multiply(current, current);
    }
    return result;
};

export const powers = (alpha: Extension, count: number) => {
    const values: Extension[] = [];
    for (let index = 0, current = one; index < count; index++) {
        values.push(current);
        current = multiply(current, alpha);
    }
    return values;
};

const residue = (value: bigint) => ((value % modulus) + modulus) % modulus;

// A public column places its values at every (systematic / degree)-th row:
// the powers of alpha at each position's automorphism image and negacyclic
// shift, negated past the degree; ones; or public values.
export type PublicColumn =
    | Readonly<{
          kind: 'geometric';
          degree: number;
          automorphism: number;
          shift: number;
      }>
    | Readonly<{ kind: 'ones'; degree: number }>
    | Readonly<{ kind: 'values'; values: readonly Extension[] }>;

type OperatorTerm = Readonly<{
    key: string;
    public: PublicColumn;
    weights: ReadonlyMap<number, Extension>;
}>;

export type RelationOperator = Readonly<{
    alpha: Extension;
    columns: number;
    terms: readonly OperatorTerm[];
    target: Extension;
    lookupWeight: Extension;
}>;

const publicColumnValues = (
    column: PublicColumn,
    alpha: Extension,
): readonly Extension[] => {
    switch (column.kind) {
        case 'values':
            return column.values;
        case 'ones':
            return Array.from({ length: column.degree }, () => one);
        case 'geometric': {
            const { degree, automorphism, shift } = column;
            const table = powers(alpha, degree);
            return Array.from({ length: degree }, (_unused, position) => {
                const exponent =
                    (position * automorphism + shift) % (2 * degree);
                const value = table[exponent % degree];
                return exponent < degree ? value : negate(value);
            });
        }
    }
};

// A signed variable: its columns with their factors, and the offset by
// which its value lies below their weighted sum.
export type Variable = Readonly<{
    terms: readonly (readonly [number, bigint])[];
    offset: bigint;
}>;

export const column = (index: number): Variable => ({
    terms: [[index, 1n]],
    offset: 0n,
});

// A sparse ternary element: its positive minus its negative Boolean column.
export const sparse = (positive: number): Variable => ({
    terms: [
        [positive, 1n],
        [positive + 1, -1n],
    ],
    offset: 0n,
});

// A signed variable of one word offset by half its range.
export const signedWord = (index: number, bits: number): Variable => ({
    terms: [[index, 1n]],
    offset: -(1n << BigInt(bits - 1)),
});

export const createOperatorBuilder = (alpha: Extension, columns: number) => {
    const terms = new Map<
        string,
        { public: PublicColumn; weights: Map<number, Extension> }
    >();
    const sums = new Map<string, Extension>();
    let target = zero;
    // Adds weight times the variable at the public column: each of its
    // columns takes the weight times its factor, and the target takes the
    // offset's share of the column's sum.
    const put = (
        variable: Variable,
        key: string,
        publicColumn: PublicColumn,
        weight: Extension,
    ) => {
        let term = terms.get(key);
        if (term === undefined) {
            term = { public: publicColumn, weights: new Map() };
            terms.set(key, term);
            sums.set(
                key,
                publicColumnValues(publicColumn, alpha).reduce(add, zero),
            );
        }
        assert.equal(term.public, publicColumn, key);
        for (const [index, factor] of variable.terms) {
            assert.ok(Number.isInteger(index) && index >= 0 && index < columns);
            term.weights.set(
                index,
                add(term.weights.get(index) ?? zero, scale(weight, factor)),
            );
        }
        if (variable.offset !== 0n)
            target = add(
                target,
                scale(multiply(weight, sums.get(key)!), -variable.offset),
            );
    };
    const publicColumns = new Map<string, PublicColumn>();
    const shared = (key: string, create: () => PublicColumn) => {
        let publicColumn = publicColumns.get(key);
        if (publicColumn === undefined) {
            publicColumn = create();
            publicColumns.set(key, publicColumn);
        }
        return publicColumn;
    };
    return {
        put,
        putGeometric: (
            variable: Variable,
            degree: number,
            weight: Extension,
            automorphism = 1,
            shift = 0,
        ) => {
            const key = `geometric:${degree}:${automorphism}:${shift}`;
            put(
                variable,
                key,
                shared(key, () => ({
                    kind: 'geometric',
                    degree,
                    automorphism,
                    shift,
                })),
                weight,
            );
        },
        putOnes: (variable: Variable, degree: number, weight: Extension) => {
            const key = `ones:${degree}`;
            put(
                variable,
                key,
                shared(key, () => ({ kind: 'ones', degree })),
                weight,
            );
        },
        addTarget: (value: Extension) => {
            target = add(target, value);
        },
        finish: (lookupWeight: Extension): RelationOperator => ({
            alpha,
            columns,
            terms: [...terms].map(([key, term]) => ({ key, ...term })),
            target,
            lookupWeight,
        }),
    };
};

// One canonical polynomial: each coefficient's fingerprint and their sum
// weighted by the powers of alpha.
type ParsedPolynomial = Readonly<{
    fingerprints: readonly Extension[];
    total: Extension;
}>;

// Reads a statement's polynomials in order. Each coefficient is a sign byte
// and a little-endian magnitude of the modulus's byte length, at most half
// the modulus and never a negative zero. Its fingerprint sums the
// magnitude's limbs at the powers of alpha^degree, negated for a negative
// sign.
export const createStatementReader = (
    statement: Uint8Array,
    offset: number,
    alpha: Extension,
) => {
    const bytes = Buffer.from(
        statement.buffer,
        statement.byteOffset,
        statement.byteLength,
    );
    let position = offset;
    return {
        next: (
            degree: number,
            polynomialModulus: bigint,
            limbBits: number,
        ): ParsedPolynomial => {
            const magnitudeBytes = byteLength(polynomialModulus);
            const half = (polynomialModulus - 1n) / 2n;
            const limbPowers = powers(
                power(alpha, degree),
                Math.ceil((8 * magnitudeBytes) / limbBits),
            );
            const width = BigInt(limbBits);
            const mask = (1n << width) - 1n;
            if (position + degree * (1 + magnitudeBytes) > bytes.length)
                throw new RangeError('The statement ends inside a polynomial.');
            const fingerprints: Extension[] = [];
            let total = zero;
            let weight = one;
            for (let index = 0; index < degree; index++) {
                const sign = bytes[position];
                const magnitude = BigInt(
                    `0x${Buffer.from(
                        bytes.subarray(
                            position + 1,
                            position + 1 + magnitudeBytes,
                        ),
                    )
                        .reverse()
                        .toString('hex')}`,
                );
                position += 1 + magnitudeBytes;
                if (
                    sign > 1 ||
                    magnitude > half ||
                    (sign === 1 && magnitude === 0n)
                )
                    throw new RangeError(
                        'A statement coefficient is not canonical.',
                    );
                let first = 0n,
                    second = 0n,
                    third = 0n;
                for (
                    let limb = 0, rest = magnitude;
                    rest > 0n;
                    limb++, rest >>= width
                ) {
                    const value = rest & mask;
                    first += value * limbPowers[limb][0];
                    second += value * limbPowers[limb][1];
                    third += value * limbPowers[limb][2];
                }
                const fingerprint: Extension =
                    sign === 1
                        ? [residue(-first), residue(-second), residue(-third)]
                        : [residue(first), residue(second), residue(third)];
                fingerprints.push(fingerprint);
                total = add(total, multiply(weight, fingerprint));
                weight = multiply(weight, alpha);
            }
            return { fingerprints, total };
        },
        finish: () => assert.equal(position, bytes.length),
    };
};

// The fingerprint of a public integer: its signed limbs at the powers of
// the limb weight.
export const fingerprint = (
    value: bigint,
    limbBits: number,
    limbWeight: Extension,
): Extension => {
    const width = BigInt(limbBits);
    const mask = (1n << width) - 1n;
    let result = zero;
    for (
        let rest = value < 0n ? -value : value, weight = one;
        rest > 0n;
        rest >>= width, weight = multiply(weight, limbWeight)
    )
        result = add(result, scale(weight, rest & mask));
    return value < 0n ? negate(result) : result;
};

// Row i of a negacyclic product P*s has weight alpha^i, so s at position j
// takes adjoint[j] = sum_i alpha^i * sign * P[i - j], negative where the
// index wraps. Then adjoint[0] is the polynomial's total and adjoint[j + 1]
// = alpha * adjoint[j] - (alpha^n + 1) * P[n - 1 - j]; after n steps the
// recurrence returns to minus the total.
export const negacyclicAdjoint = (
    polynomial: ParsedPolynomial,
    alpha: Extension,
): Extension[] => {
    const { fingerprints, total } = polynomial;
    const degree = fingerprints.length;
    const wrap = add(power(alpha, degree), one);
    const result: Extension[] = [];
    let current = total;
    for (let index = 0; index < degree; index++) {
        result.push(current);
        current = subtract(
            multiply(alpha, current),
            multiply(wrap, fingerprints[degree - 1 - index]),
        );
    }
    assert.ok(equal(current, negate(total)));
    return result;
};

export const addWeighted = (
    accumulator: Extension[],
    weight: Extension,
    values: readonly Extension[],
) => {
    assert.equal(values.length, accumulator.length);
    values.forEach(
        (value, index) =>
            (accumulator[index] = add(
                accumulator[index],
                multiply(weight, value),
            )),
    );
};

export const zeros = (length: number) => Array.from({ length }, () => zero);

// Each column's coefficient at every row of a systematic subgroup.
export const relationOperatorColumns = (
    operator: RelationOperator,
    systematic: number,
) => {
    const output = Array.from({ length: operator.columns }, () =>
        zeros(systematic),
    );
    for (const term of operator.terms) {
        const values = publicColumnValues(term.public, operator.alpha);
        const stride = systematic / values.length;
        assert.ok(Number.isInteger(stride) && stride >= 1);
        for (const [index, weight] of term.weights)
            values.forEach(
                (value, position) =>
                    (output[index][stride * position] = add(
                        output[index][stride * position],
                        multiply(weight, value),
                    )),
            );
    }
    return output;
};

// Each column's interpolated coefficient at the domain positions: the
// weighted sum of its public columns' interpolants there, where ones on
// every row interpolate to one. Operators at one challenge and positions
// share the evaluations of the challenge's powers and of ones through the
// cache.
export const evaluateRelationOperator = (
    operator: RelationOperator,
    domain: WordProofDomain,
    positions: readonly number[],
    cache = new Map<string, readonly Extension[]>(),
) => {
    const prefix = `${operator.alpha.join(',')}/${domain.systematic}/${positions.join(',')}/`;
    const coefficients = Array.from({ length: operator.columns }, () =>
        positions.map(() => zero),
    );
    for (const term of operator.terms) {
        let values: readonly Extension[] | undefined;
        if (
            term.public.kind === 'ones' &&
            term.public.degree === domain.systematic
        )
            values = positions.map(() => one);
        const cacheKey =
            term.public.kind === 'values' ? undefined : prefix + term.key;
        if (cacheKey !== undefined) values ??= cache.get(cacheKey);
        if (values === undefined) {
            const placed = publicColumnValues(term.public, operator.alpha);
            const stride = domain.systematic / placed.length;
            assert.ok(Number.isInteger(stride) && stride >= 1);
            const dense = zeros(domain.systematic);
            placed.forEach((value, index) => (dense[stride * index] = value));
            values = evaluateSystematicColumns(domain, [dense], positions)[0];
            if (cacheKey !== undefined) cache.set(cacheKey, values);
        }
        for (const [index, weight] of term.weights)
            values.forEach(
                (value, position) =>
                    (coefficients[index][position] = add(
                        coefficients[index][position],
                        multiply(weight, value),
                    )),
            );
    }
    return {
        positions,
        coefficients,
        target: operator.target,
        lookupWeight: operator.lookupWeight,
    };
};

// The operator applied to integer witness columns over the systematic
// subgroup: the alpha-weighted sum of every row's left side.
export const applyRelationOperator = (
    operator: RelationOperator,
    witness: readonly (readonly bigint[])[],
) => {
    assert.equal(witness.length, operator.columns);
    let total = zero;
    for (const term of operator.terms) {
        const values = publicColumnValues(term.public, operator.alpha);
        for (const [index, weight] of term.weights) {
            const stride = witness[index].length / values.length;
            assert.ok(Number.isInteger(stride) && stride >= 1);
            let dot = zero;
            values.forEach(
                (value, position) =>
                    (dot = add(
                        dot,
                        scale(value, witness[index][stride * position]),
                    )),
            );
            total = add(total, multiply(weight, dot));
        }
    }
    return total;
};
