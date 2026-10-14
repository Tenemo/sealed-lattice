import { createHash } from 'node:crypto';

import {
    merkleTree,
    encodeBase,
} from '#tests/word-proof-reference/commitments.js';
import {
    modulus,
    type Extension,
    reduce,
    power,
    inverse,
    inverses,
    zero,
    base,
    add,
    subtract,
    scale,
    multiply,
    invertExtension,
    equal,
    point,
    interpolate,
    evaluateOnCoset,
    interpolateExtension,
    evaluateExtensionOnCoset,
    tableOnDomain,
} from '#tests/word-proof-reference/field.js';
import {
    combinedValue,
    fold,
} from '#tests/word-proof-reference/relation-evaluation.js';
import {
    type WordProofDomain,
    type WordRelation,
    wordRelationShape,
    word32,
    readLittleEndian,
    framed,
    statementContext,
    sample,
    encodeExtension,
    transcript,
    requestedPositions,
} from '#tests/word-proof-reference/transcript.js';

// A small-domain reference prover. The statement supplies the affine
// operator's coefficient of every column at every systematic position, its
// target and its lookup weight, as functions of the affine challenge. Its
// hostile modes keep the honest procedure except for one change: a false
// statement proves a witness that misses the affine target, and an excess
// degree raises the degree mask one degree above the largest code degree.
type WordProofStatement = Readonly<{
    bytes: readonly Uint8Array[];
    operator: (affine: Extension) => Readonly<{
        coefficients: readonly (readonly Extension[])[];
        target: Extension;
        lookupWeight: Extension;
    }>;
}>;

export type WordProverMode = 'honest' | 'false-statement' | 'excess-degree';

// A deterministic stream of field elements and salts from a seed.
const seededStream = (seed: Uint8Array) => {
    let counter = 0;
    const draw = (length: number) =>
        createHash('shake256', { outputLength: length })
            .update(framed([seed, word32(counter++)]))
            .digest();
    const element = () => {
        for (;;) {
            const value = readLittleEndian(draw(16));
            if (value < modulus) return value;
        }
    };
    return {
        bytes: draw,
        element,
        extension: (): Extension => [element(), element(), element()],
    };
};

// A systematic interpolation plus the vanishing polynomial times a mask.
const masked = <Value>(
    interpolated: readonly Value[],
    mask: readonly Value[],
    negate: (value: Value) => Value,
    sum: (left: Value, right: Value) => Value,
): Value[] => {
    const result = [...interpolated, ...mask];
    mask.forEach((value, index) => {
        result[index] = sum(result[index], negate(value));
    });
    return result;
};

const multiplyPolynomials = (
    left: readonly Extension[],
    right: readonly Extension[],
) => {
    const result = Array.from(
        { length: left.length + right.length - 1 },
        () => zero,
    );
    left.forEach((value, first) => {
        if (equal(value, zero)) return;
        right.forEach((other, second) => {
            result[first + second] = add(
                result[first + second],
                multiply(value, other),
            );
        });
    });
    return result;
};

export const proveWordRelation = (
    input: Readonly<{
        relation: WordRelation;
        domain: WordProofDomain;
        role: Uint8Array;
        statement: WordProofStatement;
        statementDigest: Uint8Array;
        // Every column's values on the systematic subgroup.
        columns: readonly (readonly bigint[])[];
        seed: Uint8Array;
        mode: WordProverMode;
    }>,
) => {
    const { relation, domain, role, statement, columns, mode } = input;
    const shape = wordRelationShape(relation, domain);
    const random = seededStream(input.seed);
    const systematic = domain.systematic;
    if (
        columns.length !== shape.columns ||
        columns.some((column) => column.length !== systematic)
    )
        throw new RangeError('The witness does not match its relation.');
    // A false statement may hold an entry outside its table, which no
    // multiplicity counts.
    const counts = new Array<bigint>(systematic).fill(0n);
    for (const { column, factor } of relation.lookups)
        for (const value of columns[column]) {
            const entry = value * factor;
            if (entry < BigInt(systematic)) counts[Number(entry)]++;
            else if (mode !== 'false-statement')
                throw new RangeError('A lookup entry is outside its table.');
        }
    const context = statementContext(
        relation,
        domain,
        role,
        input.statementDigest,
    );
    const chain = transcript(role, context, relation.messageBytes);
    const salts = Array.from({ length: domain.folds + 3 }, () =>
        random.bytes(128),
    );
    const leafSalts = (count: number) =>
        Array.from({ length: count }, () => random.bytes(128));
    const points = Array.from({ length: domain.domain }, (_, position) =>
        point(domain, position),
    );

    // First oracle: masked columns and multiplicities, and the degree mask.
    const baseMask = () =>
        Array.from({ length: domain.masks }, () => random.element());
    const negateBase = (value: bigint) => reduce(-value);
    const sumBase = (left: bigint, right: bigint) => reduce(left + right);
    const committedBase = [...columns, counts].map((values) =>
        masked(interpolate(values), baseMask(), negateBase, sumBase),
    );
    const baseValues = committedBase.map((coefficients) =>
        evaluateOnCoset(coefficients, domain),
    );
    const degreeMask = Array.from(
        { length: domain.maximumDegree + (mode === 'excess-degree' ? 2 : 1) },
        () => random.extension(),
    );
    const degreeMaskValues = evaluateExtensionOnCoset(degreeMask, domain);
    const first = merkleTree(
        role,
        0,
        points.map((_, position) =>
            Buffer.concat([
                ...baseValues.map((values) => encodeBase(values[position])),
                encodeExtension(degreeMaskValues[position]),
            ]),
        ),
        leafSalts(domain.domain),
    );
    chain.respond(1, salts[0], [first.root]);

    // Second oracle: every lookup reciprocal, the table reciprocal and the
    // sum mask, whose sum over H the header carries.
    const lookup = sample(chain.message(2), 0, true);
    const extensionMask = () =>
        Array.from({ length: domain.masks }, () => random.extension());
    const negateExtension = (value: Extension) => subtract(zero, value);
    const maskedReciprocal = (values: readonly Extension[]) =>
        masked(
            interpolateExtension(values),
            extensionMask(),
            negateExtension,
            add,
        );
    const reciprocalCoefficients = [
        ...relation.lookups.map(({ column, factor }) =>
            maskedReciprocal(
                columns[column].map((value) =>
                    invertExtension(subtract(lookup, base(value * factor))),
                ),
            ),
        ),
        maskedReciprocal(
            counts.map((count, index) =>
                scale(
                    invertExtension(subtract(lookup, base(BigInt(index)))),
                    count,
                ),
            ),
        ),
    ];
    const reciprocalValues = reciprocalCoefficients.map((coefficients) =>
        evaluateExtensionOnCoset(coefficients, domain),
    );
    const reciprocals = reciprocalValues.slice(0, -1);
    const tableReciprocal = reciprocalValues[reciprocalValues.length - 1];
    const sumMask = Array.from({ length: domain.witnessDegree + 1 }, () =>
        random.extension(),
    );
    const maskSum = scale(
        sumMask
            .filter((_, degree) => degree % systematic === 0)
            .reduce(add, zero),
        BigInt(systematic),
    );
    const sumMaskValues = evaluateExtensionOnCoset(sumMask, domain);
    const second = merkleTree(
        role,
        1,
        points.map((_, position) =>
            Buffer.concat(
                [
                    ...reciprocals.map((values) => values[position]),
                    tableReciprocal[position],
                    sumMaskValues[position],
                ].map(encodeExtension),
            ),
        ),
        leafSalts(domain.domain),
    );
    chain.respond(2, salts[1], [second.root, encodeExtension(maskSum)]);

    // Affine quotient: c*(F + lookup weight * lookup sum) + G divided by the
    // vanishing polynomial; the remainder's constant must be the claimed sum
    // over H.
    const third = chain.message(3);
    const affine = sample(third, 0, false);
    const maskChallenge = sample(third, 1, false);
    const operator = statement.operator(affine);
    const combinedAffine: Extension[] = Array.from(
        { length: systematic + domain.witnessDegree },
        (_, degree) => sumMask[degree] ?? zero,
    );
    const accumulate = (coefficients: readonly Extension[]) =>
        coefficients.forEach((value, degree) => {
            combinedAffine[degree] = add(
                combinedAffine[degree],
                multiply(maskChallenge, value),
            );
        });
    columns.forEach((_, column) =>
        accumulate(
            multiplyPolynomials(
                interpolateExtension(operator.coefficients[column]),
                committedBase[column].map((value) => base(value)),
            ),
        ),
    );
    // The lookup sum: every lookup's reciprocals minus the table's.
    const tableCoefficients =
        reciprocalCoefficients[reciprocalCoefficients.length - 1];
    accumulate(
        tableCoefficients.map((tableValue, degree) =>
            multiply(
                operator.lookupWeight,
                subtract(
                    reciprocalCoefficients
                        .slice(0, -1)
                        .reduce(
                            (sum, values) => add(sum, values[degree]),
                            zero,
                        ),
                    tableValue,
                ),
            ),
        ),
    );
    // Division by X^H - 1: the quotient's coefficient of degree i sums the
    // coefficients of degrees i+H, i+2H, ..., and the remainder's coefficient
    // of degree j < H adds the quotient's coefficient of degree j.
    const remainder = combinedAffine.slice(0, systematic);
    const quotient = combinedAffine.slice(systematic);
    for (let index = quotient.length - 1; index >= systematic; index--)
        quotient[index - systematic] = add(
            quotient[index - systematic],
            quotient[index],
        );
    for (let index = 0; index < Math.min(systematic, quotient.length); index++)
        remainder[index] = add(remainder[index], quotient[index]);
    const claimed = scale(
        add(multiply(maskChallenge, operator.target), maskSum),
        inverse(BigInt(systematic)),
    );
    if (mode !== 'false-statement' && !equal(remainder[0], claimed))
        throw new RangeError('The witness misses the affine target.');
    if (mode === 'false-statement' && equal(remainder[0], claimed))
        throw new RangeError('A false statement meets the affine target.');
    const quotientValues = evaluateExtensionOnCoset(quotient, domain);
    const linear = merkleTree(
        role,
        2,
        quotientValues.map(encodeExtension),
        leafSalts(domain.domain),
    );
    chain.respond(3, salts[2], [linear.root]);

    // The combined word at every point, with the remainder constant the
    // prover's own quotient leaves, then the folds and the terminal.
    const table = tableOnDomain(domain);
    const fourth = chain.message(4);
    const combination = Array.from({ length: 2 * shape.oracles }, (_, index) =>
        sample(fourth, index, false),
    );
    const pointInverses = inverses(points);
    const vanishingInverses = inverses(
        points.map((x) => reduce(power(x, BigInt(systematic)) - 1n)),
    );
    const challenges = { lookup, mask: maskChallenge, combination };
    const coefficientValues = operator.coefficients.map((column) =>
        evaluateExtensionOnCoset(interpolateExtension(column), domain),
    );
    let layer = points.map((x, position) =>
        combinedValue(
            {
                relation,
                shape,
                domain,
                challenges,
                coefficients: coefficientValues.map(
                    (column) => column[position],
                ),
                target: operator.target,
                lookupWeight: operator.lookupWeight,
                maskSum,
                x,
                inverseX: pointInverses[position],
                inverseVanishing: vanishingInverses[position],
                table: table[position],
                remainderConstant: remainder[0],
            },
            {
                words: columns.map((_, column) => baseValues[column][position]),
                multiplicity: baseValues[shape.columns][position],
                degreeMask: degreeMaskValues[position],
                reciprocals: reciprocals.map((values) => values[position]),
                tableReciprocal: tableReciprocal[position],
                sumMask: sumMaskValues[position],
                quotient: quotientValues[position],
            },
        ),
    );
    const foldTrees: ReturnType<typeof merkleTree>[] = [];
    let terminal = zero;
    for (let round = 0; round < domain.folds; round++) {
        const challenge = sample(
            chain.message(4 + round),
            round === 0 ? 2 * shape.oracles : 0,
            false,
        );
        const half = layer.length / 2;
        const foldInverses = inverses(
            Array.from({ length: half }, (_, position) =>
                power(point(domain, position), 1n << BigInt(round)),
            ),
        );
        layer = Array.from({ length: half }, (_, position) =>
            fold(
                layer[position],
                layer[position + half],
                challenge,
                foldInverses[position],
            ),
        );
        if (round === domain.folds - 1) {
            terminal = layer[0];
            chain.respond(4 + round, salts[3 + round], [
                encodeExtension(terminal),
            ]);
        } else {
            const tree = merkleTree(
                role,
                3 + round,
                layer.map(encodeExtension),
                leafSalts(layer.length),
            );
            foldTrees.push(tree);
            chain.respond(4 + round, salts[3 + round], [tree.root]);
        }
    }
    const final = chain.message(domain.folds + 4);
    const queries = Array.from(
        { length: domain.queries },
        (_, index) => final.readUInt32LE(4 * index) % (domain.domain / 2),
    );
    const header = Buffer.concat([
        input.statementDigest,
        first.root,
        second.root,
        linear.root,
        encodeExtension(maskSum),
        ...salts,
        ...foldTrees.map((tree) => tree.root),
        encodeExtension(terminal),
    ]);
    const openings = [first, second, linear].map((tree) =>
        tree.open(requestedPositions(queries, domain.domain)),
    );
    foldTrees.forEach((tree, index) =>
        openings.push(
            tree.open(
                requestedPositions(queries, domain.domain >> (index + 1)),
            ),
        ),
    );
    // Each stage's openings begin at its offset in the proof.
    let start = 0;
    const stages = openings.map((opening) => {
        const offset = start;
        start += opening.length;
        return offset;
    });
    return { header, proof: Buffer.concat(openings), stages };
};
