import assert from 'node:assert/strict';

import { interleavedCoverageBound } from '#tests/interleaved-target-model.js';

type Fraction = Readonly<{ numerator: bigint; denominator: bigint }>;
const fraction = (numerator: bigint, denominator: bigint): Fraction => {
    let a = numerator,
        b = denominator;
    while (b !== 0n) [a, b] = [b, a % b];
    return { numerator: numerator / a, denominator: denominator / a };
};
const sum = (values: readonly Fraction[]) =>
    values.reduce(
        (total, value) =>
            fraction(
                total.numerator * value.denominator +
                    value.numerator * total.denominator,
                total.denominator * value.denominator,
            ),
        fraction(0n, 1n),
    );
const clamp = (value: Fraction) =>
    value.numerator < value.denominator ? value : fraction(1n, 1n);

// Distinct publicly routed credential domains. Fresh-intent private coins
// and the ideal message randomizers have separate repetition events. Neither
// the final roster nor a completed prefix supplies these population caps.
export const multiKeyTargetBound = (
    input: Readonly<{
        publicQueries: bigint;
        credentials: bigint;
        requestsPerCredential: bigint;
        randomizerDomain: bigint;
        coinDomain: bigint;
        instances: bigint;
        leavesPerTree: bigint;
        trees: bigint;
    }>,
) => {
    const { publicQueries, credentials, randomizerDomain, coinDomain } = input;
    if (
        publicQueries < 0n ||
        credentials < 0n ||
        input.requestsPerCredential < 0n ||
        randomizerDomain < 1n ||
        coinDomain < 1n
    )
        throw new RangeError('Invalid multi-key target operands.');
    const requests = credentials === 0n ? 0n : input.requestsPerCredential;
    const coverage = interleavedCoverageBound(
        requests,
        input.instances,
        input.leavesPerTree,
        input.trees,
    );
    const pairs = (credentials * requests * (requests - 1n)) / 2n;
    const coinInputRepetition = fraction(pairs, coinDomain),
        randomizerRepetition = fraction(pairs, randomizerDomain);
    const stateError = fraction(
        8n * publicQueries ** 2n * requests,
        randomizerDomain,
    );
    const search = fraction(
        16n * (2n * publicQueries + 1n) ** 2n * coverage.numerator,
        coverage.denominator,
    );
    const core = sum([randomizerRepetition, stateError, search]);
    return {
        coverage,
        coinInputRepetition,
        randomizerRepetition,
        stateError,
        search,
        coreBound: clamp(core),
        hedgedBound: clamp(sum([core, coinInputRepetition])),
    };
};

// One independent Bernoulli oracle at the maximum covered-output density
// can be thinned by independent bits to each credential's smaller density.
export const coverageThinningControl = () =>
    [0, 1].map((key) => {
        const covered = key === 0 ? [0] : [1, 3],
            counts = [0, 0, 0, 0];
        let falseSearchSolutions = 0;
        for (let search = 0; search < 2; search++)
            for (let selector = 0; selector < 2; selector++)
                for (let auxiliary = 0; auxiliary < 6; auxiliary++) {
                    const marked =
                            search === 1 && (key === 1 || selector === 1),
                        choices = [0, 1, 2, 3].filter(
                            (value) => covered.includes(value) === marked,
                        ),
                        output = choices[auxiliary % choices.length];
                    counts[output]++;
                    if (covered.includes(output) && search === 0)
                        falseSearchSolutions++;
                }
        return { key, counts, falseSearchSolutions };
    });
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

export const multiKeyTargetStateControl = (randomizers: 16 | 64) => {
    const perKey = 2 * randomizers,
        size = 2 * perKey,
        denominator = 2 * size ** 3;
    let distance = 0,
        realSuccess = 0,
        stagedSuccess = 0,
        samples = 0,
        crossKeyOnly = 0,
        equalRandomizerCases = 0;
    for (const pattern of [0, 1])
        for (const replacements of [
            [0, 3],
            [1, 2],
        ])
            for (let r0 = 0; r0 < randomizers; r0++)
                for (let r1 = 0; r1 < randomizers; r1++) {
                    const salts = [r0, r1];
                    const base = Array.from({ length: size }, (_, index) =>
                        pattern === 0
                            ? 0
                            : ((index * 7) ^
                                  (index >> 2) ^
                                  (index >> 4) ^
                                  Math.floor(index / perKey)) &
                              1,
                    );
                    const final = base.map((value, index) => {
                        const key = Math.floor(index / perKey),
                            salt = Math.floor(index / 2) % randomizers;
                        return salt === salts[key]
                            ? (replacements[key] >> (index & 1)) & 1
                            : value;
                    });
                    const worlds = [final, base].map((table) => {
                        const vector = table.map((value) => (value ? -1 : 1));
                        hadamard(vector);
                        return vector;
                    });
                    let norm = 0,
                        real = 0,
                        staged = 0,
                        realNorm = 0,
                        stagedNorm = 0;
                    for (let firstKey = 0; firstKey < 2; firstKey++)
                        for (
                            let firstMessage = 0;
                            firstMessage < 2;
                            firstMessage++
                        ) {
                            const firstDigest =
                                    (replacements[firstKey] >> firstMessage) &
                                    1,
                                other = 1 - firstKey;
                            const messages = [] as number[];
                            messages[firstKey] = firstMessage;
                            messages[other] = firstMessage ^ firstDigest;
                            const digests = messages.map(
                                (message, key) =>
                                    (replacements[key] >> message) & 1,
                            );
                            const installed = base.map((value, index) =>
                                Math.floor(index / perKey) === firstKey &&
                                Math.floor(index / 2) % randomizers ===
                                    salts[firstKey]
                                    ? (replacements[firstKey] >> (index & 1)) &
                                      1
                                    : value,
                            );
                            const branches = worlds.map((world, which) => {
                                const vector = Array<number>(size).fill(0);
                                for (let index = 0; index < size; index++)
                                    if (
                                        Math.floor(index / perKey) ===
                                            firstKey &&
                                        (index & 1) === firstMessage
                                    )
                                        vector[
                                            index ^
                                                (2 * salts[firstKey] +
                                                    firstDigest)
                                        ] = world[index];
                                for (let index = 0; index < perKey; index++) {
                                    const left = vector[index],
                                        right = vector[index + perKey];
                                    vector[index] = left + right;
                                    vector[index + perKey] = left - right;
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
                                const key = Math.floor(index / perKey),
                                    salt = Math.floor(index / 2) % randomizers,
                                    message = index & 1;
                                if (
                                    salt === salts[key] &&
                                    message === messages[key]
                                )
                                    continue;
                                if (final[index] === digests[key]) {
                                    real += left ** 2;
                                    staged += right ** 2;
                                } else if (
                                    final[index] === digests[1 - key] &&
                                    left !== 0
                                )
                                    crossKeyOnly++;
                            }
                        }
                    assert.equal(realNorm, denominator);
                    assert.equal(stagedNorm, denominator);
                    assert.ok(real <= 2 * staged + 2 * norm);
                    distance += norm;
                    realSuccess += real;
                    stagedSuccess += staged;
                    samples++;
                    if (r0 === r1) equalRandomizerCases++;
                }
    assert.ok(
        Number.isSafeInteger(distance) && Number.isSafeInteger(realSuccess),
    );
    assert.ok(
        BigInt(distance) * BigInt(randomizers) <=
            16n * BigInt(samples) * BigInt(denominator),
    );
    assert.ok(crossKeyOnly > 0 && equalRandomizerCases > 0);

    return {
        randomizers,
        samples,
        denominator,
        distance,
        realSuccess,
        stagedSuccess,
        crossKeyOnly,
        equalRandomizerCases,
    };
};
const bit = (table: number, index: number) => (table >> index) & 1;
const replace = (table: number, index: number, value: number) =>
    (table & ~(1 << index)) | (value << index);
const execute = (
    base: number,
    rows: number[],
    salts: number[],
    targets?: number[],
) => {
    let current = base;
    const records: number[][] = [],
        queries: number[][] = [];
    const query = (key: number, salt: number, message: number) => {
        const result = bit(current, 4 * key + 2 * salt + message);
        queries.push([key, salt, message, result]);
        return result;
    };
    const request = (key: number, message: number) => {
        const digest = targets ? targets[key] : bit(rows[key], message);
        if (targets) rows[key] = replace(rows[key], message, digest);
        for (let input = 0; input < 2; input++)
            current = replace(
                current,
                4 * key + 2 * salts[key] + input,
                bit(rows[key], input),
            );
        records.push([key, salts[key], message, digest]);
        return digest;
    };
    const firstKey = query(0, 0, 0),
        firstMessage = query(1, 1, firstKey),
        firstDigest = request(firstKey, firstMessage);
    if (firstDigest !== 0) {
        const next = 1 - firstKey,
            message = query(next, salts[firstKey], firstMessage) ^ firstMessage;
        request(next, message);
    }
    const candidateKey = query(firstKey, salts[firstKey], 1 - firstMessage),
        candidateSalt = salts[firstKey] ^ firstMessage,
        candidateMessage = firstMessage ^ firstDigest;
    let final = base;
    for (let key = 0; key < 2; key++)
        for (let message = 0; message < 2; message++)
            final = replace(
                final,
                4 * key + 2 * salts[key] + message,
                bit(rows[key], message),
            );
    const output = bit(
        final,
        4 * candidateKey + 2 * candidateSalt + candidateMessage,
    );
    const own = records.filter(([key]) => key === candidateKey),
        fresh = !own.some(
            ([, salt, message]) =>
                salt === candidateSalt && message === candidateMessage,
        );
    const success = fresh && own.some(([, , , digest]) => digest === output),
        otherOnly =
            fresh &&
            !success &&
            records.some(
                ([key, , , digest]) =>
                    key !== candidateKey && digest === output,
            );
    return {
        view: JSON.stringify([
            base,
            current,
            final,
            records,
            queries,
            [candidateKey, candidateSalt, candidateMessage],
            output,
        ]),
        records,
        success,
        otherOnly,
        candidateKey,
        candidateSalt,
        candidateMessage,
    };
};

export const multiKeyTargetViews = () => {
    const views = new Map<
        string,
        { staged: bigint; deferred: bigint; search: bigint }
    >();
    const record = (view: string, world: 'staged' | 'deferred' | 'search') => {
        const counts = views.get(view) ?? {
            staged: 0n,
            deferred: 0n,
            search: 0n,
        };
        counts[world]++;
        views.set(view, counts);
    };
    let early = 0,
        equalSalts = 0,
        successes = 0,
        crossKeyOnly = 0;
    for (let functions = 0; functions < 4096; functions++)
        for (let saltBits = 0; saltBits < 4; saltBits++) {
            const base = functions & 255,
                rows = [(functions >> 8) & 3, (functions >> 10) & 3],
                salts = [saltBits & 1, saltBits >> 1];
            record(execute(base, [...rows], salts).view, 'staged');
            for (let targetBits = 0; targetBits < 4; targetBits++) {
                const targets = [targetBits & 1, targetBits >> 1],
                    deferred = execute(base, [...rows], salts, targets);
                record(deferred.view, 'deferred');
                // Both bounding coverage sets contain one bit. Independent membership
                // bits therefore map to uniform function outputs, with each credential
                // using its own target output and independent base/replacement domains.
                let simulated = 0;
                for (let index = 0; index < 12; index++) {
                    const key =
                        index < 8
                            ? Math.floor(index / 4)
                            : Math.floor((index - 8) / 2);
                    simulated |=
                        (bit(functions, index)
                            ? targets[key]
                            : 1 - targets[key]) << index;
                }
                const search = execute(
                    simulated & 255,
                    [(simulated >> 8) & 3, (simulated >> 10) & 3],
                    salts,
                    targets,
                );
                record(search.view, 'search');
                if (search.records.length === 1) early++;
                if (salts[0] === salts[1]) equalSalts++;
                if (search.otherOnly) crossKeyOnly++;
                if (search.success) {
                    successes++;
                    const input =
                        search.candidateSalt === salts[search.candidateKey]
                            ? 8 +
                              2 * search.candidateKey +
                              search.candidateMessage
                            : 4 * search.candidateKey +
                              2 * search.candidateSalt +
                              search.candidateMessage;
                    assert.equal(bit(functions, input), 1);
                }
            }
        }
    for (const counts of views.values()) {
        assert.equal(counts.deferred, 4n * counts.staged);
        assert.equal(counts.search, counts.deferred);
    }
    assert.ok(early > 0 && equalSalts > 0 && successes > 0 && crossKeyOnly > 0);

    return {
        originalSamples: 16384n,
        simulatedSamples: 65536n,
        views: [...views].map(([view, counts]) => ({ view, ...counts })),
        early,
        equalSalts,
        successes,
        crossKeyOnly,
    };
};

export const randomizerInputCoupling = () => {
    const views = new Map<string, { real: bigint; fresh: bigint }>();
    const record = (key: string, world: 'real' | 'fresh') => {
        const counts = views.get(key) ?? { real: 0n, fresh: 0n };
        counts[world]++;
        views.set(key, counts);
    };
    let realBad = 0,
        freshBad = 0;
    const goodFirst = [0, 0],
        allFirst = [0, 0];
    for (let table = 0; table < 16; table++)
        for (let coins = 0; coins < 4; coins++) {
            const firstCoin = coins & 1,
                first = (table >> (2 * firstCoin)) & 1,
                secondMessage = first,
                secondCoin = coins >> 1;
            if (secondMessage === 0 && secondCoin === firstCoin) {
                realBad++;
                continue;
            }
            const second = (table >> (2 * secondCoin + secondMessage)) & 1;
            record(
                JSON.stringify([
                    firstCoin,
                    first,
                    secondMessage,
                    secondCoin,
                    second,
                ]),
                'real',
            );
        }
    for (let replies = 0; replies < 4; replies++)
        for (let coins = 0; coins < 4; coins++) {
            const firstCoin = coins & 1,
                first = replies & 1,
                secondMessage = first,
                secondCoin = coins >> 1;
            allFirst[first]++;
            if (secondMessage === 0 && secondCoin === firstCoin) {
                freshBad++;
                continue;
            }
            goodFirst[first]++;
            record(
                JSON.stringify([
                    firstCoin,
                    first,
                    secondMessage,
                    secondCoin,
                    replies >> 1,
                ]),
                'fresh',
            );
        }
    for (const counts of views.values())
        assert.equal(counts.real, 4n * counts.fresh);
    assert.equal(realBad, 4 * freshBad);
    assert.deepEqual(allFirst, [8, 8]);
    assert.deepEqual(goodFirst, [4, 8]);
    let crossKeyCoinMatches = 0;
    for (let first = 0; first < 4; first++)
        for (let second = 0; second < 4; second++)
            if (first === second) crossKeyCoinMatches++;
    assert.equal(crossKeyCoinMatches, 4);

    return {
        realSamples: 64n,
        freshSamples: 16n,
        realBad,
        freshBad,
        allFirst,
        goodFirst,
        crossKeyCoinMatches,
        views: [...views].map(([view, counts]) => ({ view, ...counts })),
    };
};
