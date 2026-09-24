import assert from 'node:assert/strict';

import { unrevealedPointQueryBound } from '#tests/unrevealed-point-query-model.js';

type Fraction = Readonly<{ numerator: bigint; denominator: bigint }>;
const fraction = (numerator: bigint, denominator: bigint): Fraction => {
    let a = numerator,
        b = denominator;
    while (b !== 0n) [a, b] = [b, a % b];
    return { numerator: numerator / a, denominator: denominator / a };
};

// Uniform independent public labels and hidden keys; an injective byte domain
// identifies one key and secret role before the Boolean oracle is queried.
// This does not model key serialization or fix the complete wrapper runtime.
export const labelledKeyedXofBound = (
    publicQueries: bigint,
    keys: bigint,
    secretDomain: bigint,
    labelDomain: bigint,
) => {
    if (
        publicQueries < 0n ||
        keys < 0n ||
        secretDomain < 1n ||
        labelDomain < 1n
    )
        throw new RangeError('Invalid labelled-key operands.');
    const labelCollision = fraction(keys * (keys - 1n), 2n * labelDomain);
    const hiddenPoint = unrevealedPointQueryBound(
        keys === 0n ? 0n : 2n * publicQueries,
        secretDomain,
    );
    const total = fraction(
        labelCollision.numerator * hiddenPoint.bound.denominator +
            hiddenPoint.bound.numerator * labelCollision.denominator,
        labelCollision.denominator * hiddenPoint.bound.denominator,
    );
    return {
        labelCollision,
        hiddenPoint,
        bound: total.numerator < total.denominator ? total : fraction(1n, 1n),
    };
};

// Complete finite functions are enumerated for distribution checking only.
// Two public labels and two separate hidden secret roles are represented.
const cell = (table: number, role: number, label: number, secret: number) =>
    (table >> (2 * (2 * role + label) + secret)) & 1;
const view = (
    table: number,
    oracle: (role: number, label: number) => number,
) => {
    const first = oracle(0, 0),
        beforeSecondCreation = cell(table, 1, first, 0),
        createSecond = beforeSecondCreation === 1;
    const second = createSecond ? oracle(first, 1) : -1;
    const later = cell(
        table,
        first,
        createSecond ? 1 : 0,
        second < 0 ? first : second,
    );
    const keyed = [0, 1].flatMap((role) =>
        [0, 1].map((label) => oracle(role, label)),
    );
    return JSON.stringify([
        table,
        keyed,
        first,
        beforeSecondCreation,
        createSecond,
        second,
        later,
        oracle(0, 0),
    ]);
};

export const labelledKeyedXofViews = () => {
    const views = new Map<
        string,
        { real: bigint; random: bigint; one: bigint; zero: bigint }
    >();
    const record = (key: string, world: 'real' | 'random' | 'one' | 'zero') => {
        const counts = views.get(key) ?? {
            real: 0n,
            random: 0n,
            one: 0n,
            zero: 0n,
        };
        counts[world]++;
        views.set(key, counts);
    };
    for (let table = 0; table < 256; table++) {
        for (let secrets = 0; secrets < 16; secrets++)
            record(
                view(table, (role, label) =>
                    cell(
                        table,
                        role,
                        label,
                        (secrets >> (2 * role + label)) & 1,
                    ),
                ),
                'real',
            );
        for (let outputs = 0; outputs < 16; outputs++) {
            const oracle = (role: number, label: number) =>
                (outputs >> (2 * role + label)) & 1;
            record(view(table, oracle), 'random');
            for (let offsets = 0; offsets < 16; offsets++)
                for (let mark = 0; mark < 2; mark++) {
                    let programmed = table;
                    for (let role = 0; role < 2; role++)
                        for (let label = 0; label < 2; label++) {
                            const component = 2 * role + label,
                                secret = mark ^ ((offsets >> component) & 1),
                                position = 2 * component + secret;
                            programmed =
                                (programmed & ~(1 << position)) |
                                (oracle(role, label) << position);
                        }
                    record(view(table, oracle), 'zero');
                    record(view(programmed, oracle), 'one');
                }
        }
    }
    for (const counts of views.values()) {
        assert.equal(counts.one, 32n * counts.real);
        assert.equal(counts.zero, 32n * counts.random);
    }
    // A shared label can ask one function input to carry two independent values.
    // Unique public labels prevent this conflict even if secret values coincide.
    let collisions = 0;
    for (let left = 0; left < 2; left++)
        for (let right = 0; right < 2; right++)
            for (let a = 0; a < 2; a++)
                for (let b = 0; b < 2; b++)
                    if (left === right && a !== b) collisions++;
    assert.equal(collisions, 4);

    return {
        originalSamples: 4096n,
        simulatedSamples: 131072n,
        views: [...views].map(([key, counts]) => ({ view: key, ...counts })),
        collisions,
    };
};
