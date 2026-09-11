// Exact finite quantum controls for a hidden point revealed after the query.
// This is a counterexample to a distinguishing-bound premise, not a forgery.
type Fraction = Readonly<{ numerator: bigint; denominator: bigint }>;
const fraction = (numerator: bigint, denominator: bigint): Fraction => {
    let left = numerator < 0n ? -numerator : numerator;
    let right = denominator;
    while (right) [left, right] = [right, left % right];
    return { numerator: numerator / left, denominator: denominator / left };
};
const subtract = (left: Fraction, right: Fraction) =>
    fraction(
        left.numerator * right.denominator - right.numerator * left.denominator,
        left.denominator * right.denominator,
    );

const uniformQuery = (squareRoot: number) => {
    if (
        !Number.isSafeInteger(squareRoot) ||
        squareRoot < 2 ||
        squareRoot > 64 ||
        (squareRoot & (squareRoot - 1)) !== 0
    )
        throw new RangeError('Unsupported exact quantum control size.');
    // |uniform> tensor |minus>, represented by integer amplitudes with
    // squared normalization 2N. The hidden point does not enter this state.
    return Array.from({ length: 2 * squareRoot * squareRoot }, (_, index) =>
        index % 2 ? -1n : 1n,
    );
};
const query = (state: readonly bigint[], value: (index: number) => number) => {
    const output = Array<bigint>(state.length).fill(0n);
    for (let index = 0; index < state.length / 2; index++) {
        const bit = value(index);
        for (let answer = 0; answer < 2; answer++)
            output[2 * index + (answer ^ bit)] = state[2 * index + answer];
    }
    return output;
};
const measureAfterDisclosure = (
    state: readonly bigint[],
    squareRoot: number,
    point: number,
) => {
    const size = state.length / 2;
    if (!Number.isSafeInteger(point) || point < 0 || point >= size)
        throw new RangeError('Invalid revealed point.');
    // Add |0>, apply H to that ancilla, then H^n on branch zero and
    // X^point on branch one, then Z and H to the ancilla. Accept ancilla
    // and query register all zero; retain every other outcome as rejection.
    // This realizes (|uniform>-|point>)(<uniform|-<point|)/4 without
    // postselection or a dense, inefficient measurement. It needs O(log N)
    // controlled gates and no further oracle call.
    const left = [...state];
    for (let stride = 1; stride < size; stride *= 2)
        for (let lower = 0; lower < size; lower++) {
            if ((lower & stride) !== 0) continue;
            for (let answer = 0; answer < 2; answer++) {
                const first = 2 * lower + answer,
                    second = 2 * (lower + stride) + answer;
                const a = left[first],
                    b = left[second];
                left[first] = a + b;
                left[second] = a - b;
            }
        }
    const root = BigInt(squareRoot);
    let numerator = 0n,
        finalNorm = 0n;
    for (let index = 0; index < size; index++)
        for (let answer = 0; answer < 2; answer++) {
            const first = left[2 * index + answer],
                second = root * state[2 * (index ^ point) + answer];
            const acceptedAncilla = first - second,
                rejectedAncilla = first + second;
            finalNorm += acceptedAncilla ** 2n + rejectedAncilla ** 2n;
            if (index === 0) numerator += acceptedAncilla ** 2n;
        }
    const stateNorm = state.reduce((sum, value) => sum + value * value, 0n);
    const denominator = 4n * BigInt(size) * stateNorm;
    if (finalNorm !== denominator)
        throw new Error('Disclosure measurement lost normalization.');
    return fraction(numerator, denominator);
};

export const delayedPointDisclosure = (squareRoot: number, point: number) => {
    const state = uniformQuery(squareRoot),
        size = squareRoot * squareRoot;
    const zero = query(state, () => 0),
        marked = query(state, (index) => Number(index === point));
    const zeroProbability = measureAfterDisclosure(zero, squareRoot, point);
    const markedProbability = measureAfterDisclosure(marked, squareRoot, point);
    return {
        size,
        zeroProbability,
        markedProbability,
        advantage: subtract(markedProbability, zeroProbability),
        proposedQuadraticBound: fraction(4n, BigInt(size)),
    };
};

export const delayedSliceReprogramming = (
    squareRoot: number,
    point: number,
    pattern: number,
) => {
    const state = uniformQuery(squareRoot),
        size = squareRoot * squareRoot;
    if (!Number.isSafeInteger(pattern) || pattern < 0 || pattern > 3)
        throw new RangeError('Invalid hash background.');
    const background = (index: number) =>
        pattern === 0
            ? 0
            : pattern === 1
              ? 1
              : pattern === 2
                ? index % 2
                : ((index * 13 + (index >> 2)) % 7) % 2;
    let numerator = 0n,
        denominator = 1n;
    const unchanged = measureAfterDisclosure(state, squareRoot, point);
    // All other hash bits cancel pointwise. Averaging the old and fresh bits
    // therefore gives the same result for a uniform random hash of any size.
    for (let old = 0; old < 2; old++)
        for (let fresh = 0; fresh < 2; fresh++) {
            const before = query(state, (index) =>
                index === point ? old : background(index),
            );
            const after = query(before, (index) =>
                index === point ? fresh : background(index),
            );
            const probability = measureAfterDisclosure(
                after,
                squareRoot,
                point,
            );
            numerator =
                numerator * probability.denominator +
                probability.numerator * denominator;
            denominator *= probability.denominator;
        }
    const reprogrammed = fraction(numerator, 4n * denominator);
    return {
        size,
        unchanged,
        reprogrammed,
        advantage: subtract(reprogrammed, unchanged),
        publicHashQueries: 2,
        proposedQuadraticBound: fraction(16n, BigInt(size)),
    };
};

export const compileDelayedDisclosureBounds = (
    totalHashQueries: bigint,
    precedingHashQueries: bigint,
    outputBits: number,
    parameterBits: number,
) => {
    if (
        totalHashQueries < 0n ||
        precedingHashQueries < 0n ||
        precedingHashQueries > totalHashQueries ||
        [outputBits, parameterBits].some(
            (bits) => !Number.isSafeInteger(bits) || bits < 1 || bits > 512,
        )
    )
        throw new RangeError('Invalid ideal-oracle bound operands.');
    const outputSpace = 1n << BigInt(outputBits),
        parameterSpace = 1n << BigInt(parameterBits);
    // One public hash query is routed through two point-oracle queries.
    // The average Euclidean distance is at most 4*q_before/sqrt(|P|).
    const squaredDistance = fraction(
        16n * precedingHashQueries ** 2n,
        parameterSpace,
    );
    // HK22's average-search bound for a 2*q-query reduction. This operand
    // remains conditional on the exact ideal game and its query simulation.
    const idealSearch = fraction(
        8n * (2n * totalHashQueries + 1n) ** 2n,
        outputSpace,
    );
    // A common final success projector gives p_real <= 2*p_ideal + 2*D^2.
    // Adding D^2 once would omit the interference cross term.
    // With no public query before disclosure the two ideal games coincide;
    // the general two-term inequality need not lose its factor two there.
    const upper =
        precedingHashQueries === 0n
            ? idealSearch
            : fraction(
                  2n * idealSearch.numerator * squaredDistance.denominator +
                      2n * squaredDistance.numerator * idealSearch.denominator,
                  idealSearch.denominator * squaredDistance.denominator,
              );
    return {
        totalHashQueries,
        precedingHashQueries,
        outputBits,
        parameterBits,
        squaredDistance,
        idealSearch,
        correctedSuccessUpper:
            upper.numerator < upper.denominator
                ? upper
                : { numerator: 1n, denominator: 1n },
    };
};

// Complete finite view, including the entire post-disclosure oracle table.
// Two public parameters, two tweaks, two messages and one output bit. There
// are no earlier public-oracle queries or oracle-correlated auxiliary state.
export const noPublicQuerySliceCoupling = () => {
    const views = new Map<string, { original: bigint; replaced: bigint }>();
    const record = (
        table: number,
        parameter: number,
        first: number,
        second: number,
        world: 'original' | 'replaced',
    ) => {
        const message = first;
        const view = JSON.stringify([first, message, second, parameter, table]);
        const count = views.get(view) ?? { original: 0n, replaced: 0n };
        count[world]++;
        views.set(view, count);
    };
    for (let parameter = 0; parameter < 2; parameter++)
        for (let table = 0; table < 256; table++) {
            const first = (table >> (4 * parameter)) & 1;
            const second = (table >> (4 * parameter + 2 + first)) & 1;
            record(table, parameter, first, second, 'original');
            for (let slice = 0; slice < 16; slice++) {
                // Obtain the adaptive preprocessing replies from the separate
                // keyed slice before constructing the final public oracle.
                const keyedFirst = slice & 1;
                const keyedSecond = (slice >> (2 + keyedFirst)) & 1;
                const shift = 4 * parameter;
                const replaced = (table & ~(15 << shift)) | (slice << shift);
                record(
                    replaced,
                    parameter,
                    keyedFirst,
                    keyedSecond,
                    'replaced',
                );
            }
        }
    return {
        originalSamples: 512n,
        replacedSamples: 8192n,
        views: [...views].map(([view, counts]) => ({ view, ...counts })),
    };
};
