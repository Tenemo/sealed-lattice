import assert from 'node:assert/strict';

import {
    compileStatelessSignatureWork,
    encodeStatelessSignatureChainMessage,
} from '#tests/stateless-signature-work-model.js';

type Fraction = Readonly<{ numerator: bigint; denominator: bigint }>;
const fraction = (numerator: bigint, denominator: bigint): Fraction => {
    let a = numerator,
        b = denominator;
    while (b !== 0n) [a, b] = [b, a % b];
    return { numerator: numerator / a, denominator: denominator / a };
};

// Raw endpoint-vector game. One distinct signed message per WOTS instance,
// independently tweaked chain steps, and independent initial chain seeds.
// Only the first coordinate requiring an earlier position needs verification
// for the reduction; its full hash path is included in the query operand.
export const adaptiveWotsBound = (
    publicQueries: bigint,
    chainSteps: bigint,
    domain: bigint,
) => {
    if (publicQueries < 0n || chainSteps < 1n || domain < 1n)
        throw new RangeError('Invalid adaptive WOTS operands.');
    const queries = publicQueries + chainSteps;
    const stateError = fraction(8n * queries ** 2n, domain),
        search = fraction(16n * (2n * queries + 1n) ** 2n, domain);
    const total = fraction(
        stateError.numerator * search.denominator +
            search.numerator * stateError.denominator,
        stateError.denominator * search.denominator,
    );
    return {
        verificationQueries: chainSteps,
        queries,
        stateError,
        search,
        bound: total.numerator < total.denominator ? total : fraction(1n, 1n),
    };
};

// An address fixes its signed child object independently of which external
// message selected this path. Equality of the actual roots also requires the
// standard deterministic tree/authentication-path correctness equations.
export const wotsMessageSource = (index: bigint, layer: bigint) => {
    const work = compileStatelessSignatureWork();
    if (
        index < 0n ||
        index >= 1n << work.totalHeight ||
        layer < 0n ||
        layer >= work.layers
    )
        throw new RangeError('Invalid WOTS path.');
    const tree = index >> ((layer + 1n) * work.layerHeight),
        leaf = (index >> (layer * work.layerHeight)) & (work.layerLeaves - 1n);
    const message =
        layer === 0n
            ? { kind: 'forest' as const, tree, leaf }
            : {
                  kind: 'subtree' as const,
                  layer: layer - 1n,
                  tree: tree * work.layerLeaves + leaf,
              };
    return { address: { layer, tree, leaf }, message };
};
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

export const adaptiveChainStateControl = (domain: 16 | 64) => {
    const denominator = domain ** 2;
    let distance = 0,
        realSuccess = 0,
        stagedSuccess = 0,
        samples = 0,
        realHigher = 0,
        stagedHigher = 0;
    for (const pattern of [0, 1])
        for (let secret = 0; secret < domain; secret++)
            for (let endpoint = 0; endpoint < domain; endpoint++) {
                const base = Array.from({ length: domain }, (_, input) =>
                        pattern === 0 ? 0 : (13 * input + 7) % domain,
                    ),
                    final = base.slice();
                final[secret] = endpoint;
                const vectors = [final, base].map((table) => {
                    const values = table.map((value) => (value & 1 ? -1 : 1));
                    hadamard(values);
                    const routed = Array<number>(domain).fill(0);
                    for (let input = 0; input < domain; input++)
                        routed[input ^ endpoint] = values[input];
                    return routed;
                });
                let norm = 0,
                    real = 0,
                    staged = 0,
                    realNorm = 0,
                    stagedNorm = 0;
                for (let candidate = 0; candidate < domain; candidate++) {
                    const left = vectors[0][candidate],
                        right = vectors[1][candidate];
                    realNorm += left ** 2;
                    stagedNorm += right ** 2;
                    // The classical verifier writes its full oracle result. Different result
                    // registers are orthogonal; using only a shared Boolean check would omit
                    // this part of the state distance.
                    norm +=
                        left ** 2 +
                        right ** 2 -
                        (final[candidate] === base[candidate]
                            ? 2 * left * right
                            : 0);
                    if (final[candidate] === endpoint) real += left ** 2;
                    if (base[candidate] === endpoint) staged += right ** 2;
                }
                assert.equal(realNorm, denominator);
                assert.equal(stagedNorm, denominator);
                assert.ok(real <= 2 * staged + 2 * norm);
                distance += norm;
                realSuccess += real;
                stagedSuccess += staged;
                samples++;
                if (real > staged) realHigher++;
                if (staged > real) stagedHigher++;
            }
    assert.ok(
        BigInt(distance) * BigInt(domain) <=
            16n * BigInt(samples) * BigInt(denominator),
    );
    // These particular oracle families favor the real experiment. A change in
    // both directions is not a premise of the common-success norm inequality.
    assert.ok(realHigher > 0 && distance > 0);
    assert.notEqual(realSuccess, stagedSuccess);

    return {
        domain,
        denominator,
        samples,
        distance,
        realSuccess,
        stagedSuccess,
        realHigher,
        stagedHigher,
    };
};
const hash = (table: number, step: number, input: number) =>
    (table >> (2 * step + input)) & 1;
const replace = (table: number, step: number, input: number, value: number) => {
    const position = 2 * step + input;
    return (table & ~(1 << position)) | (value << position);
};
const verify = (
    base: number,
    nodes: number[],
    boundary: number,
    start: number,
    input: number,
) => {
    const trace: number[][] = [];
    let value = input;
    for (let step = start; step < 2; step++) {
        const forced = step >= boundary && value === nodes[step],
            output = forced ? nodes[step + 1] : hash(base, step, value);
        trace.push([
            step,
            value,
            output,
            Number(forced),
            Number(!forced && output === nodes[step + 1]),
        ]);
        value = output;
    }
    return { trace, success: start < boundary && value === nodes[2] };
};
const execute = (base: number, nodes: number[], mode: number) => {
    const publicKey = nodes[2],
        first = hash(base, publicKey, publicKey);
    let boundary = 2;
    const signing: number[][] = [];
    if (mode !== 0) {
        boundary = (first + publicKey) % 3;
        signing.push([boundary, ...nodes.slice(boundary)]);
        if (mode === 2) {
            signing.push([boundary, ...nodes.slice(boundary)]);
            signing.push([(boundary + 1) % 3, -1]);
        }
    }
    const input = nodes[boundary] ^ first,
        start = boundary === 0 ? 0 : (publicKey ^ first) % boundary;
    const accessible = JSON.stringify([
        base,
        publicKey,
        mode,
        first,
        signing,
        boundary,
        start,
        input,
    ]);
    return {
        accessible,
        view: JSON.stringify([
            accessible,
            verify(base, nodes, boundary, start, input),
        ]),
        boundary,
        start,
        input,
    };
};

export const adaptiveChainViews = () => {
    const image = new Map<string, { real: bigint; programmed: bigint }>(),
        views = new Map<string, { staged: bigint; search: bigint }>(),
        hidden = new Map<string, Map<number, bigint>>(),
        expected = new Map<string, number>();
    const recordImage = (key: string, world: 'real' | 'programmed') => {
        const counts = image.get(key) ?? { real: 0n, programmed: 0n };
        counts[world]++;
        image.set(key, counts);
    };
    const recordView = (key: string, world: 'staged' | 'search') => {
        const counts = views.get(key) ?? { staged: 0n, search: 0n };
        counts[world]++;
        views.set(key, counts);
    };
    let validStaged = 0,
        unjustifiedRealVerifier = 0;
    for (let base = 0; base < 16; base++) {
        for (let secret = 0; secret < 2; secret++) {
            const middle = hash(base, 0, secret),
                end = hash(base, 1, middle);
            recordImage(JSON.stringify([base, [secret, middle, end]]), 'real');
        }
        for (let values = 0; values < 8; values++) {
            const nodes = [values & 1, (values >> 1) & 1, values >> 2],
                final = replace(
                    replace(base, 0, nodes[0], nodes[1]),
                    1,
                    nodes[1],
                    nodes[2],
                );
            recordImage(JSON.stringify([final, nodes]), 'programmed');
            let searchTable = 0;
            for (let step = 0; step < 2; step++)
                for (let input = 0; input < 2; input++)
                    searchTable |=
                        (hash(base, step, input)
                            ? nodes[step + 1]
                            : 1 - nodes[step + 1]) <<
                        (2 * step + input);
            for (let mode = 0; mode < 3; mode++) {
                const staged = execute(base, nodes, mode),
                    search = execute(searchTable, nodes, mode);
                recordView(staged.view, 'staged');
                recordView(search.view, 'search');
                const key = nodes
                        .slice(0, staged.boundary)
                        .reduce(
                            (value, bit, index) => value | (bit << index),
                            0,
                        ),
                    counts =
                        hidden.get(staged.accessible) ??
                        new Map<number, bigint>();
                counts.set(key, (counts.get(key) ?? 0n) + 1n);
                hidden.set(staged.accessible, counts);
                expected.set(staged.accessible, 2 ** staged.boundary);
                const checked = verify(
                    searchTable,
                    nodes,
                    search.boundary,
                    search.start,
                    search.input,
                );
                if (checked.success)
                    assert.ok(
                        checked.trace.some(
                            ([step, input, , , marked]) =>
                                marked === 1 && hash(base, step, input) === 1,
                        ),
                    );
            }
            for (let boundary = 0; boundary < 3; boundary++)
                for (let start = 0; start < 2; start++)
                    for (let input = 0; input < 2; input++) {
                        const staged = verify(
                            base,
                            nodes,
                            boundary,
                            start,
                            input,
                        );
                        if (staged.success) {
                            validStaged++;
                            assert.ok(
                                staged.trace.some((value) => value[4] === 1),
                            );
                        }
                        let value = input;
                        for (let step = start; step < 2; step++)
                            value = hash(final, step, value);
                        if (
                            start < boundary &&
                            value === nodes[2] &&
                            !staged.trace.some((entry) => entry[4] === 1)
                        )
                            unjustifiedRealVerifier++;
                    }
        }
    }
    for (const counts of image.values())
        assert.equal(counts.programmed, 4n * counts.real);
    for (const counts of views.values())
        assert.equal(counts.staged, counts.search);
    for (const [key, counts] of hidden) {
        assert.equal(counts.size, expected.get(key));
        assert.equal(new Set(counts.values()).size, 1);
    }
    assert.ok(validStaged > 0 && unjustifiedRealVerifier > 0);
    const low = encodeStatelessSignatureChainMessage(new Uint8Array(32)),
        high = encodeStatelessSignatureChainMessage(
            new Uint8Array(32).fill(255),
        ),
        forged = encodeStatelessSignatureChainMessage(
            new Uint8Array(32).fill(0xa5),
        );
    const exposed = low.map((value, index) => Math.min(value, high[index]));
    assert.ok(exposed.every((value) => value === 0));
    assert.notDeepEqual(forged, low);
    assert.notDeepEqual(forged, high);
    assert.ok(forged.every((value, index) => value >= exposed[index]));

    return {
        image: [...image].map(([view, counts]) => ({ view, ...counts })),
        views: [...views].map(([view, counts]) => ({ view, ...counts })),
        hiddenGroups: hidden.size,
        validStaged,
        unjustifiedRealVerifier,
        twoMessageExposure: { low, high, forged, exposed },
    };
};
