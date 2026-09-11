import assert from 'node:assert/strict';

type Fraction = Readonly<{ numerator: bigint; denominator: bigint }>;
const fraction = (numerator: bigint, denominator: bigint): Fraction => {
    let a = numerator,
        b = denominator;
    while (b !== 0n) [a, b] = [b, a % b];
    return { numerator: numerator / a, denominator: denominator / a };
};

// Worst-case coverage by s target digests: sum_I product_j c[I,j] is at
// most sum_I m[I]^k <= s^k. This counts output coverage, not adaptive security.
export const interleavedCoverageBound = (
    targets: bigint,
    instances: bigint,
    leaves: bigint,
    trees: bigint,
) => {
    if (targets < 0n || instances < 1n || leaves < 1n || trees < 1n)
        throw new RangeError('Invalid interleaved coverage operands.');
    const numerator = targets ** trees,
        denominator = instances * leaves ** trees;
    return fraction(
        numerator < denominator ? numerator : denominator,
        denominator,
    );
};

// Conditional ideal-query argument: independent initial state, fresh random
// target keys selected after each classical message, and a fixed final oracle
// in the common success predicate. This is not a fixed-hash or time bound.
export const interleavedTargetQueryBound = (
    publicQueries: bigint,
    targets: bigint,
    keySpace: bigint,
    instances: bigint,
    leaves: bigint,
    trees: bigint,
) => {
    if (publicQueries < 0n || keySpace < 1n)
        throw new RangeError('Invalid interleaved query operands.');
    const coverage = interleavedCoverageBound(
        targets,
        instances,
        leaves,
        trees,
    );
    const repeatedKey = fraction(targets * (targets - 1n), 2n * keySpace);
    const stateError = fraction(8n * publicQueries ** 2n * targets, keySpace);
    const search = fraction(
        16n * (2n * publicQueries + 1n) ** 2n * coverage.numerator,
        coverage.denominator,
    );
    const total = [repeatedKey, stateError, search].reduce(
        (sum, value) =>
            fraction(
                sum.numerator * value.denominator +
                    value.numerator * sum.denominator,
                sum.denominator * value.denominator,
            ),
        fraction(0n, 1n),
    );
    return {
        coverage,
        repeatedKey,
        stateError,
        search,
        bound: total.numerator < total.denominator ? total : fraction(1n, 1n),
    };
};

// These controls enumerate oracle coins and complete views. They do not give
// the adversary free function tables in the query-bounded experiment.

const hadamard = (values: number[]) => {
    for (let width = 1; width < values.length; width *= 2)
        for (let base = 0; base < values.length; base += 2 * width)
            for (let index = 0; index < width; index++) {
                const left = values[base + index],
                    right = values[base + width + index];
                values[base + index] = left + right;
                values[base + width + index] = left - right;
            }
};
export const stagedRowStateControl = (keys: 16 | 64) => {
    const size = 2 * keys,
        denominator = size ** 3;
    let difference = 0,
        realSuccess = 0,
        stagedSuccess = 0,
        samples = 0,
        positiveGaps = 0,
        negativeGaps = 0;
    for (const pattern of [0, 1])
        for (const [firstRow, secondRow] of [
            [0, 3],
            [1, 2],
        ])
            for (let firstKey = 0; firstKey < keys; firstKey++)
                for (let secondKey = 0; secondKey < keys; secondKey++) {
                    if (firstKey === secondKey) continue;
                    const base = Array.from({ length: size }, (_, index) =>
                        pattern === 0
                            ? 0
                            : ((index * 7) ^ (index >> 2) ^ (index >> 4)) & 1,
                    );
                    const final = base.map((value, index) =>
                        index >> 1 === firstKey
                            ? (firstRow >> (index & 1)) & 1
                            : index >> 1 === secondKey
                              ? (secondRow >> (index & 1)) & 1
                              : value,
                    );
                    const installed = base.map((value, index) =>
                        index >> 1 === firstKey
                            ? (firstRow >> (index & 1)) & 1
                            : value,
                    );
                    const worlds = [final, base].map((table) => {
                        const vector = table.map((bit) => (bit ? -1 : 1));
                        hadamard(vector);
                        return vector;
                    });
                    let norm = 0,
                        real = 0,
                        staged = 0,
                        realNorm = 0,
                        stagedNorm = 0;
                    for (
                        let firstMessage = 0;
                        firstMessage < 2;
                        firstMessage++
                    ) {
                        const firstDigest = (firstRow >> firstMessage) & 1,
                            secondMessage = firstMessage ^ firstDigest,
                            secondDigest = (secondRow >> secondMessage) & 1;
                        const branches = worlds.map((world, which) => {
                            const vector = Array<number>(size).fill(0);
                            for (let index = 0; index < size; index++)
                                if ((index & 1) === firstMessage) {
                                    const routed =
                                        index ^ (2 * firstKey + firstDigest);
                                    vector[routed] = world[index];
                                }
                            const table = which === 0 ? final : installed;
                            for (let index = 0; index < size; index++)
                                if (table[index])
                                    vector[index] = -vector[index];
                            hadamard(vector);
                            return vector;
                        });
                        for (let index = 0; index < size; index++) {
                            const left = branches[0][index],
                                right = branches[1][index];
                            norm += (left - right) ** 2;
                            realNorm += left ** 2;
                            stagedNorm += right ** 2;
                            const target =
                                index === 2 * firstKey + firstMessage ||
                                index === 2 * secondKey + secondMessage;
                            if (
                                !target &&
                                (final[index] === firstDigest ||
                                    final[index] === secondDigest)
                            ) {
                                real += left ** 2;
                                staged += right ** 2;
                            }
                        }
                    }
                    assert.equal(realNorm, denominator);
                    assert.equal(stagedNorm, denominator);
                    assert.ok(real <= 2 * staged + 2 * norm);
                    difference += norm;
                    realSuccess += real;
                    stagedSuccess += staged;
                    samples++;
                    if (real > staged) positiveGaps++;
                    if (staged > real) negativeGaps++;
                }
    assert.ok(Number.isSafeInteger(difference));
    assert.ok(
        BigInt(difference) * BigInt(keys) <=
            32n * BigInt(samples) * BigInt(denominator),
    );
    assert.ok(positiveGaps > 0 && negativeGaps > 0);
    return {
        keys,
        changeableQueries: 2,
        knownRowReads: 1,
        samples,
        denominator,
        difference,
        realSuccess,
        stagedSuccess,
        positiveGaps,
        negativeGaps,
    };
};

const bit = (table: number, input: number) => (table >> input) & 1;
const replace = (table: number, input: number, value: number) =>
    (table & ~(1 << input)) | (value << input);
const execute = (
    base: number,
    rows: number[],
    keys: number[],
    targets?: number[],
) => {
    let current = base,
        between: number | null = null;
    const transcript: number[][] = [];
    const firstReply = bit(base, 0);
    let message = firstReply;
    for (let stage = 0; stage < 2; stage++) {
        const key = keys[stage],
            digest = targets ? targets[stage] : bit(rows[stage], message);
        if (targets) rows[stage] = replace(rows[stage], message, digest);
        for (let input = 0; input < 2; input++)
            current = replace(
                current,
                2 * key + input,
                bit(rows[stage], input),
            );
        transcript.push([key, message, digest]);
        if (stage === 0) {
            if (digest === 0) break;
            between = bit(current, 2 * keys[1] + 1);
            message = between ^ firstReply;
        }
    }
    let final = base;
    for (let stage = 0; stage < 2; stage++)
        for (let input = 0; input < 2; input++)
            final = replace(
                final,
                2 * keys[stage] + input,
                bit(rows[stage], input),
            );
    const candidate = [firstReply ^ keys[0], message ^ 1];
    const digest = bit(final, 2 * candidate[0] + candidate[1]);
    const forbidden = transcript.some(
        ([key, input]) => key === candidate[0] && input === candidate[1],
    );
    const success =
        !forbidden && transcript.some(([, , value]) => value === digest);
    return {
        key: JSON.stringify([
            base,
            keys,
            final,
            firstReply,
            between,
            transcript,
            candidate,
            digest,
        ]),
        success,
        candidate,
        transcript,
    };
};
export const interleavedTargetViews = () => {
    const views = new Map<
        string,
        { staged: bigint; deferred: bigint; search: bigint }
    >();
    const record = (key: string, world: 'staged' | 'deferred' | 'search') => {
        const counts = views.get(key) ?? {
            staged: 0n,
            deferred: 0n,
            search: 0n,
        };
        counts[world]++;
        views.set(key, counts);
    };
    let successes = 0,
        early = 0,
        forcedWithoutSearch = 0;
    for (let firstKey = 0; firstKey < 2; firstKey++)
        for (let functions = 0; functions < 256; functions++) {
            const keys = [firstKey, 1 - firstKey],
                base = functions & 15,
                rows = [(functions >> 4) & 3, (functions >> 6) & 3];
            const staged = execute(base, [...rows], keys);
            record(staged.key, 'staged');
            for (let digestBits = 0; digestBits < 4; digestBits++) {
                const targets = [digestBits & 1, digestBits >> 1];
                record(execute(base, [...rows], keys, targets).key, 'deferred');
                // If the covered output set has one bit, the independent membership coin
                // determines the output. If it has both, membership is one and a fresh
                // output bit is used. Both constructions give an independent uniform bit.
                const all = targets[0] !== targets[1];
                let simulatedFunctions = 0;
                for (let input = 0; input < 8; input++)
                    simulatedFunctions |=
                        (all
                            ? bit(functions, input)
                            : bit(functions, input)
                              ? targets[0]
                              : 1 - targets[0]) << input;
                const simulated = execute(
                    simulatedFunctions & 15,
                    [
                        (simulatedFunctions >> 4) & 3,
                        (simulatedFunctions >> 6) & 3,
                    ],
                    keys,
                    targets,
                );
                record(simulated.key, 'search');
                if (simulated.transcript.length === 1) early++;
                if (simulated.success) {
                    successes++;
                    const stage = keys.indexOf(simulated.candidate[0]),
                        searchIndex = 4 + 2 * stage + simulated.candidate[1];
                    assert.ok(
                        all || bit(functions, searchIndex) === 1,
                        'A successful new pair must solve the search predicate.',
                    );
                }
                for (
                    let stage = 0;
                    stage < simulated.transcript.length;
                    stage++
                ) {
                    const [, message] = simulated.transcript[stage];
                    if (!all && bit(functions, 4 + 2 * stage + message) === 0)
                        forcedWithoutSearch++;
                }
            }
        }
    for (const counts of views.values()) {
        assert.equal(counts.deferred, 4n * counts.staged);
        assert.equal(counts.search, counts.deferred);
    }
    assert.ok(successes > 0 && early > 0 && forcedWithoutSearch > 0);
    return {
        stagedSamples: 512n,
        deferredSamples: 2048n,
        successes,
        early,
        forcedWithoutSearch,
        views: [...views].map(([view, counts]) => ({ view, ...counts })),
    };
};
