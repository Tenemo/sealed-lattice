import {
    modulus,
    type Extension,
    reduce,
    power,
    inverse,
    zero,
    one,
    base,
    add,
    subtract,
    scale,
    multiply,
} from '#tests/word-proof-reference/field.js';
import {
    type WordProofDomain,
    type WordRelation,
    wordRelationShape,
} from '#tests/word-proof-reference/transcript.js';

// The degree-combination weight of an oracle at a point: its own weight
// plus its shifted weight times the point raised to the gap between the
// largest degree and the oracle's degree.
const combinationWeights = (
    combination: readonly Extension[],
    degrees: readonly number[],
    maximumDegree: number,
    x: bigint,
) => {
    const corrections = new Map<number, bigint>();
    return (oracle: number): Extension => {
        const degree = degrees[oracle];
        let correction = corrections.get(degree);
        if (correction === undefined) {
            correction = power(x, BigInt(maximumDegree - degree));
            corrections.set(degree, correction);
        }
        return add(
            combination[2 * oracle],
            scale(combination[2 * oracle + 1], correction),
        );
    };
};

// One point's committed values: the column values, multiplicity, degree
// mask, every lookup reciprocal, the table reciprocal, the sum mask and the
// affine quotient.
type PointValues = Readonly<{
    words: readonly bigint[];
    multiplicity: bigint;
    degreeMask: Extension;
    reciprocals: readonly Extension[];
    tableReciprocal: Extension;
    sumMask: Extension;
    quotient: Extension;
}>;

type PointContext = Readonly<{
    relation: WordRelation;
    shape: ReturnType<typeof wordRelationShape>;
    domain: WordProofDomain;
    challenges: Readonly<{
        lookup: Extension;
        mask: Extension;
        combination: readonly Extension[];
    }>;
    coefficients: readonly Extension[];
    target: Extension;
    lookupWeight: Extension;
    maskSum: Extension;
    // The point, its inverse, its vanishing value's inverse and the table.
    x: bigint;
    inverseX: bigint;
    inverseVanishing: bigint;
    table: bigint;
    // The affine remainder's numerator constant: the claimed sum over H for
    // the verifier, the prover's own remainder constant for the prover.
    remainderConstant?: Extension;
}>;

// The combined rational word at one point.
export const combinedValue = (at: PointContext, values: PointValues) => {
    const { relation, shape, domain, challenges } = at;
    const weight = combinationWeights(
        challenges.combination,
        shape.degrees,
        domain.maximumDegree,
        at.x,
    );
    let combined = values.degreeMask;
    let linear = zero;
    values.words.forEach((value, column) => {
        linear = add(linear, scale(at.coefficients[column], value));
        combined = add(combined, scale(weight(column), value));
    });
    combined = add(combined, scale(weight(shape.columns), values.multiplicity));
    for (let index = 0; index < relation.booleans; index++) {
        const value = values.words[relation.words + index];
        combined = add(
            combined,
            scale(
                weight(shape.original + index),
                reduce(value * (value - 1n) * at.inverseVanishing),
            ),
        );
    }
    relation.zeroProducts.forEach(([left, right], pair) => {
        combined = add(
            combined,
            scale(
                weight(shape.original + relation.booleans + pair),
                reduce(
                    values.words[left] *
                        values.words[right] *
                        at.inverseVanishing,
                ),
            ),
        );
    });
    let reciprocalSum = zero;
    relation.lookups.forEach(({ column, factor }, index) => {
        const reciprocal = values.reciprocals[index];
        reciprocalSum = add(reciprocalSum, reciprocal);
        combined = add(
            combined,
            multiply(weight(shape.columns + 1 + index), reciprocal),
        );
        // The reciprocal times (beta - scaled word) is one on H.
        const residual = scale(
            subtract(
                multiply(
                    reciprocal,
                    subtract(
                        challenges.lookup,
                        base(values.words[column] * factor),
                    ),
                ),
                one,
            ),
            at.inverseVanishing,
        );
        combined = add(
            combined,
            multiply(
                weight(
                    shape.original +
                        relation.booleans +
                        relation.zeroProducts.length +
                        index,
                ),
                residual,
            ),
        );
    });
    combined = add(
        combined,
        multiply(
            weight(shape.columns + 1 + shape.lookups),
            values.tableReciprocal,
        ),
    );
    combined = add(
        combined,
        multiply(weight(shape.columns + 2 + shape.lookups), values.sumMask),
    );
    // The table reciprocal times (beta - T) is the multiplicity on H.
    const tableResidual = scale(
        subtract(
            multiply(
                subtract(challenges.lookup, base(at.table)),
                values.tableReciprocal,
            ),
            base(values.multiplicity),
        ),
        at.inverseVanishing,
    );
    combined = add(
        combined,
        multiply(weight(shape.oracles - 2), tableResidual),
    );
    // The affine remainder (c*(F + lookup sum) + G - claimed/H - Z_H*h)/X,
    // with the quotient h opened in the third tree.
    linear = add(
        linear,
        multiply(
            at.lookupWeight,
            subtract(reciprocalSum, values.tableReciprocal),
        ),
    );
    const constant =
        at.remainderConstant ??
        scale(
            add(multiply(challenges.mask, at.target), at.maskSum),
            inverse(BigInt(domain.systematic)),
        );
    const vanishing = reduce(power(at.x, BigInt(domain.systematic)) - 1n);
    const numerator = subtract(
        subtract(
            add(multiply(challenges.mask, linear), values.sumMask),
            constant,
        ),
        scale(values.quotient, vanishing),
    );
    combined = add(
        combined,
        multiply(weight(shape.oracles - 1), scale(numerator, at.inverseX)),
    );
    return add(combined, multiply(weight(shape.original - 1), values.quotient));
};

// A fold of the pair at x and -x: (f(x)+f(-x))/2 + z*(f(x)-f(-x))/(2x).
export const fold = (
    left: Extension,
    right: Extension,
    challenge: Extension,
    inverseX: bigint,
) => {
    const half = inverse(2n);
    return add(
        scale(add(left, right), half),
        multiply(
            challenge,
            scale(subtract(left, right), (half * inverseX) % modulus),
        ),
    );
};
