import assert from 'node:assert/strict';

// A fixed acyclic graph uses one canonical input at each distinct hash row.
// This query-only bound permits arbitrary advice independent of the search
// oracle. It does not give a finite implementation of that advice or oracle.
export const hashGraphCollisionBound = (queries: bigint, domain: bigint) => {
    if (queries < 0n || domain < 1n)
        throw new RangeError('Invalid hash graph operands.');
    let numerator = 8n * (2n * queries + 1n) ** 2n;
    if (numerator >= domain) return { numerator: 1n, denominator: 1n };
    let divisor = numerator,
        remainder = domain;
    while (remainder !== 0n)
        [divisor, remainder] = [remainder, divisor % remainder];
    numerator /= divisor;
    return { numerator, denominator: domain / divisor };
};

const hash = (table: number, row: number, input: number) =>
    (table >> (4 * row + input)) & 1;
const replace = (table: number, row: number, input: number, output: number) => {
    const bit = 4 * row + input;
    return (table & ~(1 << bit)) | (output << bit);
};
const graph = (leaf: number, outputs: number[]) => [
    leaf,
    2 * outputs[0] + (leaf & 1),
];

// Independent finite joint-law control: the second target input depends on
// the first target output. All graph values and the complete function are
// retained, including off-path entries and repeated output values.
export const hashGraphViews = () => {
    type Counts = { real: bigint; programmed: bigint; search: bigint };
    const views = new Map<string, Counts>();
    const record = (
        world: keyof Counts,
        table: number,
        leaf: number,
        outputs: number[],
    ) => {
        const inputs = graph(leaf, outputs),
            key = JSON.stringify({ table, leaf, inputs, outputs });
        const value = views.get(key) ?? {
            real: 0n,
            programmed: 0n,
            search: 0n,
        };
        value[world]++;
        views.set(key, value);
    };
    let collisions = 0,
        cyclesFail = 0,
        reusedRowsFail = 0;
    for (let table = 0; table < 256; table++)
        for (let leaf = 0; leaf < 4; leaf++) {
            const left = hash(table, 0, leaf),
                right = hash(table, 1, 2 * left + (leaf & 1));
            record('real', table, leaf, [left, right]);
            for (let encoded = 0; encoded < 4; encoded++) {
                const outputs = [encoded & 1, encoded >> 1],
                    inputs = graph(leaf, outputs);
                const programmed = replace(
                    replace(table, 0, inputs[0], outputs[0]),
                    1,
                    inputs[1],
                    outputs[1],
                );
                record('programmed', programmed, leaf, outputs);
                let search = 0;
                for (let row = 0; row < 2; row++)
                    for (let input = 0; input < 4; input++) {
                        const forced = input === inputs[row],
                            marked = hash(table, row, input) === 1;
                        search |=
                            (forced || marked
                                ? outputs[row]
                                : 1 - outputs[row]) <<
                            (4 * row + input);
                    }
                record('search', search, leaf, outputs);
                // Every candidate is checked, including choices based on
                // complete graph/function disclosure. The original input
                // must be excluded from target-collision success.
                for (let row = 0; row < 2; row++)
                    for (let input = 0; input < 4; input++)
                        if (
                            input !== inputs[row] &&
                            hash(search, row, input) === outputs[row]
                        ) {
                            collisions++;
                            assert.equal(hash(table, row, input), 1);
                        }
                assert.equal(hash(search, 0, inputs[0]), outputs[0]);
                const selfCycle = replace(table, 0, outputs[0], outputs[1]);
                if (
                    outputs[0] !== outputs[1] &&
                    hash(selfCycle, 0, outputs[0]) !== outputs[0]
                )
                    cyclesFail++;
                const reused = replace(
                    replace(table, 0, leaf, outputs[0]),
                    0,
                    leaf,
                    outputs[1],
                );
                if (hash(reused, 0, leaf) !== outputs[0]) reusedRowsFail++;
            }
        }
    for (const value of views.values()) {
        assert.equal(value.programmed, 4n * value.real);
        assert.equal(value.search, value.programmed);
    }
    assert.ok(collisions > 0 && cyclesFail > 0 && reusedRowsFail > 0);
    return {
        views: [...views].map(([view, count]) => ({ view, ...count })),
        collisions,
        cyclesFail,
        reusedRowsFail,
    };
};
