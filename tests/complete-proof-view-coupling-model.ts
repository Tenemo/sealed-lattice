import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

// Finite algebra and disclosure model, not cryptographic implementation.
// F_97[Y]/(Y^3-2), an eight-point systematic subgroup, three mask
// coefficients, the full 32-point evaluation domain, and every FRI fold.
type ExtensionElement = readonly [number, number, number];
type Polynomial = ExtensionElement[];
const prime = 97,
    size = 8,
    masks = 3,
    domain = 32,
    maximumDegree = 15;
const zero: ExtensionElement = [0, 0, 0],
    one: ExtensionElement = [1, 0, 0];
const mod = (value: number) => ((value % prime) + prime) % prime;
const base = (value: number): ExtensionElement => [mod(value), 0, 0];
const add = (a: ExtensionElement, b: ExtensionElement): ExtensionElement => [
    mod(a[0] + b[0]),
    mod(a[1] + b[1]),
    mod(a[2] + b[2]),
];
const sub = (a: ExtensionElement, b: ExtensionElement): ExtensionElement => [
    mod(a[0] - b[0]),
    mod(a[1] - b[1]),
    mod(a[2] - b[2]),
];
const mul = (a: ExtensionElement, b: ExtensionElement): ExtensionElement => {
    const result = [0, 0, 0];
    for (let i = 0; i < 3; i++)
        for (let j = 0; j < 3; j++)
            result[(i + j) % 3] += a[i] * b[j] * (i + j >= 3 ? 2 : 1);
    return result.map(mod) as unknown as ExtensionElement;
};
const pow = (a: ExtensionElement, exponent: number): ExtensionElement => {
    let value = one;
    for (; exponent > 0; exponent = Math.floor(exponent / 2), a = mul(a, a))
        if (exponent % 2) value = mul(value, a);
    return value;
};
const equal = (a: ExtensionElement, b: ExtensionElement) =>
    a.every((v, i) => v === b[i]);
const inverse = (a: ExtensionElement): ExtensionElement => {
    assert.ok(!equal(a, zero));
    return pow(a, prime ** 3 - 2);
};
const trim = (a: Polynomial) => {
    while (a.length > 1 && equal(a[a.length - 1], zero)) a.pop();
    return a;
};
const plus = (a: Polynomial, b: Polynomial): Polynomial =>
    trim(
        Array.from({ length: Math.max(a.length, b.length) }, (_, i) =>
            add(a[i] ?? zero, b[i] ?? zero),
        ),
    );
const minus = (a: Polynomial, b: Polynomial): Polynomial =>
    plus(
        a,
        b.map((value) => sub(zero, value)),
    );
const scale = (a: Polynomial, c: ExtensionElement): Polynomial =>
    trim(a.map((value) => mul(value, c)));
const product = (a: Polynomial, b: Polynomial): Polynomial => {
    const result = Array<ExtensionElement>(a.length + b.length - 1).fill(zero);
    for (let i = 0; i < a.length; i++)
        for (let j = 0; j < b.length; j++)
            result[i + j] = add(result[i + j], mul(a[i], b[j]));
    return trim(result);
};
const at = (a: Polynomial, x: ExtensionElement): ExtensionElement =>
    a.reduceRight(
        (value, coefficient) => add(mul(value, x), coefficient),
        zero,
    );
const vanishing: Polynomial = [
    base(-1),
    ...Array<ExtensionElement>(size - 1).fill(zero),
    one,
];
const division = (a: Polynomial) => {
    const remainder = [...a],
        quotient = Array<ExtensionElement>(Math.max(1, a.length - size)).fill(
            zero,
        );
    for (let i = remainder.length - 1; i >= size; i--) {
        quotient[i - size] = remainder[i];
        remainder[i - size] = add(remainder[i - size], remainder[i]);
        remainder[i] = zero;
    }
    return {
        quotient: trim(quotient),
        remainder: trim(remainder.slice(0, size)),
    };
};
const exactQuotient = (a: Polynomial): Polynomial => {
    const result = division(a);
    assert.ok(
        result.remainder.every((value) => equal(value, zero)),
        'An unproved relation cannot supply a polynomial quotient.',
    );
    return result.quotient;
};
const interpolate = (
    points: ExtensionElement[],
    values: ExtensionElement[],
): Polynomial => {
    assert.equal(points.length, values.length);
    let result: Polynomial = [zero];
    for (let i = 0; i < points.length; i++) {
        let basis: Polynomial = [one],
            divisor = one;
        for (let j = 0; j < points.length; j++)
            if (i !== j) {
                basis = product(basis, [sub(zero, points[j]), one]);
                divisor = mul(divisor, sub(points[i], points[j]));
            }
        result = plus(result, scale(basis, mul(values[i], inverse(divisor))));
    }
    return result;
};
const points = (length: number, coset: ExtensionElement) =>
    Array.from({ length }, (_, i) =>
        mul(coset, pow(base(5), (96 / length) * i)),
    );
const systematic = points(size, one),
    evaluation = points(domain, base(7));
assert.ok(!equal(pow(base(2), 32), one));
assert.equal(new Set(evaluation.map(String)).size, domain);
assert.ok(
    evaluation.every((x) => !equal(at(vanishing, x), zero) && !equal(x, zero)),
);

type WitnessColumns = number[][];
type ProofMasks = {
    values: WitnessColumns;
    originalMasks: Polynomial[];
    inverseMasks: Polynomial[];
    sumMask: Polynomial;
    degreeMask: Polynomial;
    publicMaskSum: ExtensionElement;
};
type ProofChallenges = {
    lookup: ExtensionElement;
    affine: Polynomial[];
    target: ExtensionElement;
    mask: ExtensionElement;
    lookupWeight: ExtensionElement;
    weights: ExtensionElement[][];
    foldWeights: ExtensionElement[];
};
const multiplicities = (values: WitnessColumns) => {
    const result = Array<number>(size).fill(0);
    for (const value of values[0]) {
        assert.ok(value >= 0 && value < size);
        result[value]++;
    }
    return result;
};
const raw = (values: WitnessColumns): ExtensionElement[][] =>
    [...values, multiplicities(values)].map((column) => column.map(base));
const inverseRaw = (
    values: WitnessColumns,
    lookup: ExtensionElement,
): ExtensionElement[][] => [
    values[0].map((value) => inverse(sub(lookup, base(value)))),
    multiplicities(values).map((count, value) =>
        mul(base(count), inverse(sub(lookup, base(value)))),
    ),
];
const masked = (values: ExtensionElement[], mask: Polynomial) =>
    plus(interpolate(systematic, values), product(vanishing, mask));
const columns = (state: ProofMasks, context: ProofChallenges) => {
    const original = raw(state.values).map((values, i) =>
        masked(values, state.originalMasks[i]),
    );
    const reciprocals = inverseRaw(state.values, context.lookup).map(
        (values, i) => masked(values, state.inverseMasks[i]),
    );
    const affine = context.affine.reduce(
        (value, coefficient, i) =>
            plus(value, product(coefficient, original[i])),
        [zero] as Polynomial,
    );
    return {
        original,
        reciprocals,
        affine: plus(
            affine,
            scale(minus(reciprocals[0], reciprocals[1]), context.lookupWeight),
        ),
    };
};
const allOracles = (state: ProofMasks, context: ProofChallenges) => {
    const values = columns(state, context);
    const combined = plus(scale(values.affine, context.mask), state.sumMask);
    const { quotient, remainder } = division(combined);
    const claimed = add(mul(context.mask, context.target), state.publicMaskSum);
    assert.ok(
        equal(remainder[0], mul(claimed, inverse(base(size)))),
        'The affine remainder has the wrong constant.',
    );
    const table = interpolate(
        systematic,
        Array.from({ length: size }, (_, i) => base(i)),
    );
    const word = values.original[0],
        positive = values.original[1],
        negative = values.original[2],
        counts = values.original[3];
    const list: { value: Polynomial; degree: number }[] = [
        ...values.original.map((value) => ({
            value,
            degree: size + masks - 1,
        })),
        ...values.reciprocals.map((value) => ({
            value,
            degree: size + masks - 1,
        })),
        { value: state.sumMask, degree: size + masks - 1 },
        { value: quotient, degree: size + masks - 2 },
        ...[positive, negative].map((value) => ({
            value: exactQuotient(product(value, minus(value, [one]))),
            degree: size + 2 * masks - 2,
        })),
        {
            value: exactQuotient(product(positive, negative)),
            degree: size + 2 * masks - 2,
        },
        {
            value: exactQuotient(
                minus(
                    product(
                        minus([context.lookup], word),
                        values.reciprocals[0],
                    ),
                    [one],
                ),
            ),
            degree: size + 2 * masks - 2,
        },
        {
            value: exactQuotient(
                minus(
                    product(
                        minus([context.lookup], table),
                        values.reciprocals[1],
                    ),
                    counts,
                ),
            ),
            degree: size + masks - 2,
        },
        { value: trim(remainder.slice(1)), degree: size - 2 },
    ];
    assert.ok(
        list.every(
            ({ value, degree }) =>
                value.length <= degree + 1 && degree <= maximumDegree,
        ),
    );
    return { list, affine: values.affine };
};
const withoutDegreeMask = (
    oracles: ReturnType<typeof allOracles>,
    context: ProofChallenges,
) =>
    oracles.list.reduce(
        (sum, entry, i) =>
            plus(
                sum,
                product(
                    entry.value,
                    plus(
                        [context.weights[i][0]],
                        [
                            ...Array<ExtensionElement>(
                                maximumDegree - entry.degree,
                            ).fill(zero),
                            context.weights[i][1],
                        ],
                    ),
                ),
            ),
        [zero] as Polynomial,
    );
const combined = (state: ProofMasks, context: ProofChallenges) =>
    plus(
        state.degreeMask,
        withoutDegreeMask(allOracles(state, context), context),
    );
const folding = (polynomial: Polynomial, context: ProofChallenges) => {
    let coefficients = [
            ...polynomial,
            ...Array<ExtensionElement>(
                maximumDegree + 1 - polynomial.length,
            ).fill(zero),
        ],
        coset = base(7),
        length = domain;
    const layers: ExtensionElement[][] = [];
    for (const challenge of context.foldWeights) {
        coefficients = Array.from({ length: coefficients.length / 2 }, (_, i) =>
            add(coefficients[2 * i], mul(challenge, coefficients[2 * i + 1])),
        );
        length /= 2;
        coset = mul(coset, coset);
        layers.push(
            points(length, coset).map((point) => at(coefficients, point)),
        );
    }
    assert.equal(coefficients.length, 1);
    return { layers, terminal: coefficients[0] };
};

const couple = (
    state: ProofMasks,
    replacement: WitnessColumns,
    context: ProofChallenges,
    queryPoints: ExtensionElement[],
): ProofMasks => {
    assert.ok(queryPoints.length <= masks && queryPoints.length + 1 <= size);
    const oldColumns = columns(state, context);
    const adjust = (
        polynomial: Polynomial,
        rawValues: ExtensionElement[],
        mask: Polynomial,
    ) => {
        const unmasked = interpolate(systematic, rawValues);
        const correction = interpolate(
            queryPoints,
            queryPoints.map((x) =>
                mul(
                    sub(at(polynomial, x), at(masked(rawValues, mask), x)),
                    inverse(at(vanishing, x)),
                ),
            ),
        );
        assert.ok(unmasked.length <= size);
        return plus(mask, correction);
    };
    const next: ProofMasks = {
        ...state,
        values: replacement,
        originalMasks: raw(replacement).map((values, i) =>
            adjust(oldColumns.original[i], values, state.originalMasks[i]),
        ),
        inverseMasks: inverseRaw(replacement, context.lookup).map((values, i) =>
            adjust(oldColumns.reciprocals[i], values, state.inverseMasks[i]),
        ),
        sumMask: [...state.sumMask],
        degreeMask: [...state.degreeMask],
    };
    const difference = division(
        minus(oldColumns.affine, columns(next, context).affine),
    );
    const highCorrection = interpolate(
        queryPoints,
        queryPoints.map((x) => mul(context.mask, at(difference.quotient, x))),
    );
    const lowCorrection = interpolate(
        [zero, ...queryPoints],
        [
            mul(context.mask, difference.remainder[0]),
            ...queryPoints.map((x) =>
                sub(zero, mul(at(vanishing, x), at(highCorrection, x))),
            ),
        ],
    );
    next.sumMask = plus(
        next.sumMask,
        plus(product(vanishing, highCorrection), lowCorrection),
    );
    next.degreeMask = plus(
        state.degreeMask,
        minus(
            withoutDegreeMask(allOracles(state, context), context),
            withoutDegreeMask(allOracles(next, context), context),
        ),
    );
    assert.ok(next.originalMasks.every((value) => value.length <= masks));
    assert.ok(next.inverseMasks.every((value) => value.length <= masks));
    assert.ok(
        next.sumMask.length <= size + masks &&
            next.degreeMask.length <= maximumDegree + 1,
    );
    return next;
};

const fingerprint = (value: unknown) =>
    createHash('sha512').update(JSON.stringify(value)).digest('hex');
const disclosure = (
    state: ProofMasks,
    context: ProofChallenges,
    query: number,
    labels: number[][],
) => {
    const all = allOracles(state, context),
        fold = folding(combined(state, context), context);
    const rows = evaluation.map((x) => [
        ...all.list.slice(0, 4).map(({ value }) => at(value, x)),
        at(state.degreeMask, x),
    ]);
    const second = evaluation.map((x) =>
        all.list.slice(4, 7).map(({ value }) => at(value, x)),
    );
    const third = evaluation.map((x) => [at(all.list[7].value, x)]);
    const groups = [
        rows,
        second,
        third,
        ...fold.layers
            .slice(0, -1)
            .map((values) => values.map((value) => [value])),
    ];
    const trees = groups.map((payloads, group) => {
        const leaves = labels[group].map((value) =>
            fingerprint(['leaf-label', value]),
        );
        const nodes = [...Array<string>(payloads.length).fill(''), ...leaves];
        for (let i = payloads.length - 1; i > 0; i--)
            nodes[i] = fingerprint(['inner', nodes[2 * i], nodes[2 * i + 1]]);
        const selected = [
            query % (payloads.length / 2),
            (query % (payloads.length / 2)) + payloads.length / 2,
        ];
        return {
            root: nodes[1],
            openings: selected.map((index) => {
                const payload = payloads[index];
                // A deliberately nonbinding, perfectly balanced toy salted leaf.
                // The conditional salt is identical whenever the payload and
                // chosen label coincide. It tests disclosure coupling only.
                const messageValue =
                    Number.parseInt(
                        fingerprint([group, index, payload]).slice(0, 6),
                        16,
                    ) % prime;
                const salt = mod(labels[group][index] - messageValue);
                const path: string[] = [];
                for (
                    let node = payloads.length + index;
                    node > 1;
                    node = Math.floor(node / 2)
                )
                    path.push(nodes[node ^ 1]);
                return { index, payload, salt, path };
            }),
        };
    });
    return {
        publicMaskSum: state.publicMaskSum,
        terminal: fold.terminal,
        query,
        trees,
    };
};

export const completeProofViewCoupling = (seed: number, maskZero = false) => {
    let randomState = seed >>> 0;
    const random = () =>
        (randomState = (Math.imul(randomState, 1664525) + 1013904223) >>> 0) %
        prime;
    const randomElement = (): ExtensionElement => [
        random(),
        random(),
        random(),
    ];
    const polynomial = (count: number, baseOnly = false): Polynomial =>
        trim(
            Array.from({ length: count }, () =>
                baseOnly ? base(random()) : randomElement(),
            ),
        );
    const values = [
        Array.from({ length: size }, (_, i) => (i + seed) % size),
        [1, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 0, 0, 0, 0, 0, 0],
    ];
    const replacement = [
        Array<number>(size).fill(0),
        [0, 0, 1, 0, 0, 0, 0, 0],
        [0, 0, 0, 1, 0, 0, 0, 0],
    ];
    const affine = Array.from({ length: 3 }, () => polynomial(size));
    const target = systematic.reduce(
        (sum, x, index) =>
            affine.reduce(
                (columnSum, coefficient, column) =>
                    add(
                        columnSum,
                        mul(at(coefficient, x), base(values[column][index])),
                    ),
                sum,
            ),
        zero,
    );
    const context: ProofChallenges = {
        lookup: [random(), 1, 0],
        affine,
        target,
        mask: maskZero ? zero : randomElement(),
        lookupWeight: randomElement(),
        weights: Array.from({ length: 14 }, () => [
            randomElement(),
            randomElement(),
        ]),
        foldWeights: Array.from({ length: 4 }, randomElement),
    };
    const sumMask = polynomial(size + masks);
    const original: ProofMasks = {
        values,
        originalMasks: Array.from({ length: 4 }, () => polynomial(masks, true)),
        inverseMasks: Array.from({ length: 2 }, () => polynomial(masks)),
        sumMask,
        degreeMask: polynomial(maximumDegree + 1),
        publicMaskSum: mul(base(size), division(sumMask).remainder[0]),
    };
    const firstFold = folding(combined(original, context), context);
    // The final query depends on the exposed terminal, not just an independent
    // challenge fixed before all private masks. Preserve that dependency.
    const query =
        (firstFold.terminal[0] +
            2 * firstFold.terminal[1] +
            3 * firstFold.terminal[2] +
            seed) %
        (domain / 2);
    const queryPoints = [evaluation[query], evaluation[query + domain / 2]];
    const changed = couple(original, replacement, context, queryPoints);
    assert.deepEqual(combined(original, context), combined(changed, context));
    assert.deepEqual(firstFold, folding(combined(changed, context), context));
    assert.deepEqual(
        couple(changed, values, context, queryPoints),
        original,
        'The mask map must be invertible.',
    );
    const oldOracles = allOracles(original, context),
        newOracles = allOracles(changed, context);
    for (const x of queryPoints) {
        assert.deepEqual(
            oldOracles.list.map(({ value }) => at(value, x)),
            newOracles.list.map(({ value }) => at(value, x)),
        );
        assert.deepEqual(at(original.degreeMask, x), at(changed.degreeMask, x));
    }
    const labels = [32, 32, 32, 16, 8, 4].map((length) =>
        Array.from({ length }, random),
    );
    const realView = disclosure(original, context, query, labels),
        simulatedView = disclosure(changed, context, query, labels);
    assert.deepEqual(realView, simulatedView);
    const withoutSumRepair = { ...changed, sumMask: original.sumMask };
    const withoutDegreeRepair = { ...changed, degreeMask: original.degreeMask };
    let affineControlRejected = false;
    try {
        allOracles(withoutSumRepair, context);
    } catch {
        affineControlRejected = true;
    }
    const requiresSumRepair = !equal(
        division(minus(changed.sumMask, original.sumMask)).remainder[0],
        zero,
    );
    assert.equal(affineControlRejected, requiresSumRepair);
    assert.notDeepEqual(
        combined(withoutDegreeRepair, context),
        combined(original, context),
    );
    return {
        seed,
        maskZero,
        query,
        affineControlRejected,
        realView,
        simulatedView,
        realCombinedPolynomial: combined(original, context),
        simulatedCombinedPolynomial: combined(changed, context),
        realFolding: firstFold,
        simulatedFolding: folding(combined(changed, context), context),
        originalMasks: original,
        recoveredMasks: couple(changed, values, context, queryPoints),
        oracleCount: oldOracles.list.length,
    };
};
