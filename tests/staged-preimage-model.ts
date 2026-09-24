import assert from 'node:assert/strict';

type Fraction = Readonly<{ numerator: bigint; denominator: bigint }>;
const fraction = (numerator: bigint, denominator: bigint): Fraction => {
    let a = numerator,
        b = denominator;
    while (b !== 0n) [a, b] = [b, a % b];
    return { numerator: numerator / a, denominator: denominator / a };
};

// Independent uniform target preimages, registered before public queries.
// The same final function is used in both success predicates, and an opened
// target cannot win. Opening work is real work even though this query bound
// has no multiplicative opening-count loss.
export const stagedPreimageBound = (
    queries: bigint,
    inputDomain: bigint,
    outputDomain: bigint,
) => {
    if (queries < 0n || inputDomain < 1n || outputDomain < 1n)
        throw new RangeError('Invalid staged-preimage operands.');
    const search = fraction(16n * (2n * queries + 1n) ** 2n, outputDomain);
    const stateError = fraction(8n * queries ** 2n, inputDomain);
    const finalPointGuess = fraction(2n, inputDomain);
    const total = [search, stateError, finalPointGuess].reduce(
        (sum, value) =>
            fraction(
                sum.numerator * value.denominator +
                    value.numerator * sum.denominator,
                sum.denominator * value.denominator,
            ),
        fraction(0n, 1n),
    );
    return {
        search,
        stateError,
        finalPointGuess,
        bound: total.numerator < total.denominator ? total : fraction(1n, 1n),
    };
};

// Integer quantum controls and complete function/view enumerations below are
// evidence for the stated comparison, not a protocol acceptance mechanism.
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

export const stagedPreimageStateControl = (inputs: 16 | 64) => {
    const size = 2 * inputs,
        denominator = size ** 3;
    let difference = 0,
        realSuccess = 0,
        stagedSuccess = 0,
        baseSuccess = 0,
        guessSuccess = 0,
        eligible = 0,
        samples = 0,
        positiveGaps = 0,
        negativeGaps = 0;
    for (const pattern of [0, 1])
        for (let targets = 0; targets < 4; targets++)
            for (let firstInput = 0; firstInput < inputs; firstInput++)
                for (let secondInput = 0; secondInput < inputs; secondInput++) {
                    const originals = [firstInput, secondInput],
                        digests = [targets & 1, targets >> 1];
                    const base = Array.from({ length: size }, (_, index) =>
                        pattern === 0
                            ? 0
                            : ((index * 7) ^ (index >> 2) ^ (index >> 4)) & 1,
                    );
                    const final = base.slice();
                    for (let target = 0; target < 2; target++)
                        final[target * inputs + originals[target]] =
                            digests[target];
                    const worlds = [final, base].map((table) => {
                        const vector = table.map((bit, index) =>
                            bit ^ digests[Math.floor(index / inputs)] ? -1 : 1,
                        );
                        hadamard(vector);
                        return vector;
                    });
                    let norm = 0,
                        real = 0,
                        staged = 0,
                        baseMatch = 0,
                        guess = 0,
                        unopened = 0,
                        realNorm = 0,
                        stagedNorm = 0;
                    for (let branch = 0; branch < 2; branch++) {
                        const opened = branch ^ digests[0],
                            knownInput = originals[opened];
                        const installed = base.slice();
                        installed[opened * inputs + knownInput] =
                            digests[opened];
                        const branches = worlds.map((world, which) => {
                            const vector = Array<number>(size).fill(0);
                            for (let index = 0; index < size; index++)
                                if (Math.floor(index / inputs) === branch)
                                    vector[index ^ knownInput] = world[index];
                            const table = which === 0 ? final : installed;
                            for (let index = 0; index < size; index++)
                                if (
                                    table[index] ^
                                    digests[Math.floor(index / inputs)]
                                )
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
                            const target = Math.floor(index / inputs),
                                input = index % inputs;
                            if (target === opened) continue;
                            unopened += right ** 2;
                            if (final[index] === digests[target]) {
                                real += left ** 2;
                                staged += right ** 2;
                            }
                            if (base[index] === digests[target])
                                baseMatch += right ** 2;
                            if (input === originals[target])
                                guess += right ** 2;
                        }
                    }
                    assert.equal(realNorm, denominator);
                    assert.equal(stagedNorm, denominator);
                    assert.ok(real <= 2 * staged + 2 * norm);
                    assert.ok(staged <= baseMatch + guess);
                    difference += norm;
                    realSuccess += real;
                    stagedSuccess += staged;
                    baseSuccess += baseMatch;
                    guessSuccess += guess;
                    eligible += unopened;
                    samples++;
                    if (real > staged) positiveGaps++;
                    if (staged > real) negativeGaps++;
                }
    assert.ok(
        Number.isSafeInteger(difference) && Number.isSafeInteger(eligible),
    );
    assert.ok(
        BigInt(difference) * BigInt(inputs) <=
            16n * BigInt(samples) * BigInt(denominator),
    );
    assert.equal(BigInt(guessSuccess) * BigInt(inputs), BigInt(eligible));
    assert.ok(positiveGaps > 0 && negativeGaps > 0);

    return {
        inputs,
        samples,
        denominator,
        difference,
        realSuccess,
        stagedSuccess,
        baseSuccess,
        guessSuccess,
        eligible,
        positiveGaps,
        negativeGaps,
    };
};
const cell = (table: number, target: number, input: number) =>
    (table >> (2 * (2 * target + input))) & 3;
const replace = (
    table: number,
    target: number,
    input: number,
    value: number,
) => {
    const position = 2 * (2 * target + input);
    return (table & ~(1 << position)) | (value << position);
};
const execute = (
    base: number,
    inputs: number[],
    targets: number[],
    mode: number,
) => {
    let current = base;
    const opened = new Set<number>(),
        requests: number[][] = [],
        queries: number[][] = [];
    const query = (target: number, input: number) => {
        const value = cell(current, target, input);
        queries.push([target, input, value]);
        return value;
    };
    const open = (target: number) => {
        const value = inputs[target] ?? 0;
        requests.push([target, value]);
        if (target >= 0 && target < 2) {
            opened.add(target);
            current = replace(current, target, value, targets[target]);
        }
        return value;
    };
    const first = query(0, 0);
    let target = (first >> 1) ^ targets[1],
        input = (first & 1) ^ targets[0];
    if (mode === 1 || mode === 2) {
        const selected = (first & 1) ^ targets[0],
            value = open(selected);
        assert.equal(open(selected), value);
        target = 1 - selected;
        input = (query(target, value) >> 1) ^ value;
        if (mode === 2) open(target);
    }
    if (mode === 3) {
        assert.equal(open(2), 0);
        input ^= query(target, input) & 1;
    }
    let final = base;
    for (let index = 0; index < 2; index++)
        final = replace(final, index, inputs[index], targets[index]);
    const eligible = !opened.has(target),
        baseMatch =
            eligible && (cell(base, target, input) & 1) === targets[target],
        guess = eligible && input === inputs[target],
        success =
            eligible && (cell(final, target, input) & 1) === targets[target];
    const accessible = JSON.stringify([
        base,
        current,
        targets,
        mode,
        requests,
        queries,
        [target, input],
    ]);
    return {
        accessible,
        view: JSON.stringify([accessible, final]),
        target,
        input,
        opened,
        eligible,
        baseMatch,
        guess,
        success,
    };
};

export const stagedPreimageViews = () => {
    const imageViews = new Map<string, { real: bigint; programmed: bigint }>(),
        stageViews = new Map<string, { staged: bigint; search: bigint }>();
    const conditional = new Map<string, Map<number, bigint>>(),
        correlated = new Map<string, Map<number, bigint>>();
    const controls = Array.from({ length: 4 }, (_, mode) => ({
        mode,
        samples: 0,
        eligible: 0,
        success: 0,
        baseMatch: 0,
        guess: 0,
        guessOnly: 0,
    }));
    const image = (key: string, world: 'real' | 'programmed') => {
        const counts = imageViews.get(key) ?? { real: 0n, programmed: 0n };
        counts[world]++;
        imageViews.set(key, counts);
    };
    const stage = (key: string, world: 'staged' | 'search') => {
        const counts = stageViews.get(key) ?? { staged: 0n, search: 0n };
        counts[world]++;
        stageViews.set(key, counts);
    };
    const group = (
        groups: typeof conditional,
        value: ReturnType<typeof execute>,
        inputs: number[],
    ) => {
        const remaining = [0, 1].filter((target) => !value.opened.has(target));
        const hidden = remaining.reduce(
            (word, target, index) => word | (inputs[target] << index),
            0,
        );
        const counts =
            groups.get(value.accessible) ?? new Map<number, bigint>();
        counts.set(hidden, (counts.get(hidden) ?? 0n) + 1n);
        groups.set(value.accessible, counts);
        return remaining.length;
    };
    const expectedGroupSizes = new Map<string, number>();
    for (let base = 0; base < 256; base++)
        for (let inputBits = 0; inputBits < 4; inputBits++) {
            const inputs = [inputBits & 1, inputBits >> 1],
                derived = inputs.map(
                    (input, target) => cell(base, target, input) & 1,
                );
            image(JSON.stringify([base, inputs, derived]), 'real');
            for (let targetBits = 0; targetBits < 4; targetBits++) {
                const targets = [targetBits & 1, targetBits >> 1];
                let final = base;
                for (let target = 0; target < 2; target++)
                    final = replace(
                        final,
                        target,
                        inputs[target],
                        targets[target],
                    );
                image(JSON.stringify([final, inputs, targets]), 'programmed');
                // Independent membership coins occupy the low stream bits; high bits are
                // independent XOF suffixes. This constructs full uniform base streams.
                let simulated = 0;
                for (let target = 0; target < 2; target++)
                    for (let input = 0; input < 2; input++) {
                        const coin = cell(base, target, input),
                            prefix =
                                coin & 1
                                    ? targets[target]
                                    : 1 - targets[target];
                        simulated |=
                            (prefix | (coin & 2)) << (2 * (2 * target + input));
                    }
                for (let mode = 0; mode < 4; mode++) {
                    const value = execute(base, inputs, targets, mode),
                        search = execute(simulated, inputs, targets, mode);
                    stage(value.view, 'staged');
                    stage(search.view, 'search');
                    assert.ok(
                        !search.baseMatch ||
                            !!(cell(base, search.target, search.input) & 1),
                    );
                    assert.ok(!value.success || value.baseMatch || value.guess);
                    const count = controls[mode];
                    count.samples++;
                    if (value.eligible) count.eligible++;
                    if (value.success) count.success++;
                    if (value.baseMatch) count.baseMatch++;
                    if (value.guess) count.guess++;
                    if (value.success && !value.baseMatch) count.guessOnly++;
                    const remaining = group(conditional, value, inputs);
                    expectedGroupSizes.set(value.accessible, 2 ** remaining);
                }
            }
        }
    for (let base = 0; base < 256; base++)
        for (let shared = 0; shared < 2; shared++)
            for (let targetBits = 0; targetBits < 4; targetBits++) {
                const inputs = [shared, shared],
                    targets = [targetBits & 1, targetBits >> 1],
                    value = execute(base, inputs, targets, 1);
                group(correlated, value, inputs);
            }
    for (const counts of imageViews.values())
        assert.equal(counts.programmed, 4n * counts.real);
    for (const counts of stageViews.values())
        assert.equal(counts.staged, counts.search);
    for (const [key, counts] of conditional) {
        assert.equal(counts.size, expectedGroupSizes.get(key));
        assert.equal(new Set(counts.values()).size, 1);
    }
    for (const control of controls)
        assert.equal(control.guess * 2, control.eligible);
    const correlatedSingletons = [...correlated.values()].filter(
        (counts) => counts.size === 1,
    ).length;
    assert.ok(correlatedSingletons > 0);
    assert.ok(controls.some((value) => value.guessOnly > 0));
    assert.equal(controls[2].success, 0);

    return {
        controls,
        imageViews: [...imageViews].map(([view, counts]) => ({
            view,
            ...counts,
        })),
        stageViews: [...stageViews].map(([view, counts]) => ({
            view,
            ...counts,
        })),
        conditionalGroups: conditional.size,
        correlatedGroups: correlated.size,
        correlatedSingletons,
    };
};
