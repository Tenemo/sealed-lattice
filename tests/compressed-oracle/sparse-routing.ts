import assert from 'node:assert/strict';

import {
    type Circuit,
    Builder,
    applyClean,
    integerBits,
    fromBits,
} from '#tests/compressed-oracle/reversible-circuit.js';

export function compileSparseRouting(
    previousCapacity: number,
    inputBits: number,
    outputBits: number,
) {
    assert.ok(
        [previousCapacity, inputBits, outputBits].every(Number.isSafeInteger),
    );
    assert.ok(previousCapacity >= 0 && inputBits >= 1 && outputBits >= 1);
    const width = inputBits + outputBits + 1,
        databaseBits = (previousCapacity + 1) * width;
    const query = Array.from({ length: inputBits }, (_, index) => index);
    const tuple = (index: number) =>
        Array.from(
            { length: width },
            (_, bit) => inputBits + index * width + bit,
        );
    const buildRemove = () => {
        const builder = new Builder(inputBits + databaseBits),
            matches = [];
        for (let index = 0; index <= previousCapacity; index++) {
            const entry = tuple(index);
            matches.push(
                builder.and(
                    entry[width - 1],
                    builder.equal(query, entry.slice(0, inputBits)),
                ),
            );
        }
        let seen = builder.zero;
        const output: number[] = [];
        for (let index = 0; index < previousCapacity; index++) {
            seen = builder.or(seen, matches[index]);
            const current = tuple(index),
                next = tuple(index + 1);
            for (let bit = 0; bit < width; bit++)
                output.push(builder.select(seen, next[bit], current[bit]));
        }
        for (let bit = 0; bit < outputBits; bit++) {
            let value = builder.zero;
            // Visit this output column directly. Materializing tuple(index)
            // here would allocate a whole row for every selected output bit.
            let entryBit = 2 * inputBits + bit;
            for (let index = 0; index <= previousCapacity; index++) {
                value = builder.xor(
                    value,
                    builder.and(matches[index], entryBit),
                );
                entryBit += width;
            }
            output.push(value);
        }
        let present = builder.zero;
        for (const match of matches) present = builder.or(present, match);
        output.push(present);
        output.push(...Array<number>(inputBits).fill(builder.zero));
        return builder.finish(output);
    };
    const buildInsert = () => {
        const builder = new Builder(inputBits + databaseBits),
            selected = Array.from(
                { length: outputBits + 1 },
                (_, bit) => inputBits + previousCapacity * width + bit,
            ),
            target = [...query, ...selected],
            zero = Array<number>(width).fill(builder.zero);
        let inserted = builder.zero;
        const output: number[] = [];
        for (let index = 0; index < previousCapacity; index++) {
            const current = tuple(index),
                prior = index === 0 ? zero : tuple(index - 1),
                before = builder.or(
                    builder.not(current[width - 1]),
                    builder.less(query, current.slice(0, inputBits)),
                ),
                here = builder.and(
                    selected[outputBits],
                    builder.and(builder.not(inserted), before),
                );
            for (let bit = 0; bit < width; bit++)
                output.push(
                    builder.select(
                        here,
                        target[bit],
                        builder.select(inserted, prior[bit], current[bit]),
                    ),
                );
            inserted = builder.or(inserted, here);
        }
        const prior =
            previousCapacity === 0 ? zero : tuple(previousCapacity - 1);
        for (let bit = 0; bit < width; bit++)
            output.push(
                builder.select(
                    inserted,
                    prior[bit],
                    builder.select(
                        selected[outputBits],
                        target[bit],
                        zero[bit],
                    ),
                ),
            );
        return builder.finish(output);
    };
    const remove = buildRemove(),
        insert = buildInsert();
    assert.equal(remove.output.length, databaseBits);
    assert.equal(insert.output.length, databaseBits);
    const cleanQueryGates = (circuit: Circuit) =>
        2 * circuit.gates.length + circuit.output.length;
    const routingGates =
        cleanQueryGates(remove) + cleanQueryGates(insert) + 3 * databaseBits;
    return {
        previousCapacity,
        inputBits,
        outputBits,
        width,
        databaseBits,
        remove,
        insert,
        routingGates,
        roundTripRoutingGates: 2 * routingGates,
    };
}

function runSparseRouting(
    compiled: ReturnType<typeof compileSparseRouting>,
    query: Uint8Array,
    database: Uint8Array,
    reverse = false,
) {
    const left = database.slice(),
        right = new Uint8Array(compiled.databaseBits);
    assert.equal(left.length, right.length);
    if (!reverse) {
        applyClean(compiled.remove, query, left, right);
        applyClean(compiled.insert, query, right, left);
    } else {
        applyClean(compiled.insert, query, left, right);
        applyClean(compiled.remove, query, right, left);
    }
    assert.ok(
        left.every((value) => value === 0),
        'Routing inverse failed to erase the original register.',
    );
    // Three CNOTs per bit restore the database to its original register.
    for (let bit = 0; bit < left.length; bit++) {
        left[bit] ^= right[bit];
        right[bit] ^= left[bit];
        left[bit] ^= right[bit];
    }
    assert.ok(right.every((value) => value === 0));
    return left;
}

export type Entry = { input: number; output: number };

export function encodeDatabase(
    entries: readonly Entry[],
    capacity: number,
    inputBits: number,
    outputBits: number,
) {
    const result = new Uint8Array(capacity * (inputBits + outputBits + 1));
    assert.ok(entries.length <= capacity);
    entries.forEach((entry, index) => {
        assert.ok(index === 0 || entries[index - 1].input < entry.input);
        assert.ok(
            entry.input >= 0 &&
                entry.input < 2 ** inputBits &&
                entry.output >= 0 &&
                entry.output < 2 ** outputBits,
        );
        const offset = index * (inputBits + outputBits + 1);
        result.set(integerBits(entry.input, inputBits), offset);
        result.set(integerBits(entry.output, outputBits), offset + inputBits);
        result[offset + inputBits + outputBits] = 1;
    });
    return result;
}

export function verifySparseRouting(
    previousCapacity: number,
    inputBits: number,
    outputBits: number,
) {
    const compiled = compileSparseRouting(
        previousCapacity,
        inputBits,
        outputBits,
    );
    let cases = 0,
        updates = 0;
    const exercise = (entries: Entry[]) => {
        for (let query = 0; query < 2 ** inputBits; query++) {
            const found = entries.find((value) => value.input === query);
            if (entries.length > previousCapacity && !found) continue;
            const bits = integerBits(query, inputBits),
                database = encodeDatabase(
                    entries,
                    previousCapacity + 1,
                    inputBits,
                    outputBits,
                ),
                routed = runSparseRouting(compiled, bits, database),
                others = entries.filter((value) => value.input !== query);
            const expected = new Uint8Array(compiled.databaseBits);
            expected.set(
                encodeDatabase(others, previousCapacity, inputBits, outputBits),
            );
            if (found) {
                expected.set(
                    integerBits(found.output, outputBits),
                    previousCapacity * compiled.width,
                );
                expected[previousCapacity * compiled.width + outputBits] = 1;
            }
            assert.deepEqual(routed, expected);
            assert.deepEqual(
                runSparseRouting(compiled, bits, routed, true),
                database,
            );
            cases++;
            for (
                let replacement = -1;
                replacement < 2 ** outputBits;
                replacement++
            ) {
                const changed = routed.slice();
                changed.fill(0, previousCapacity * compiled.width);
                if (replacement >= 0) {
                    changed.set(
                        integerBits(replacement, outputBits),
                        previousCapacity * compiled.width,
                    );
                    changed[previousCapacity * compiled.width + outputBits] = 1;
                }
                const expanded = [
                    ...others,
                    ...(replacement < 0
                        ? []
                        : [{ input: query, output: replacement }]),
                ].sort((a, b) => a.input - b.input);
                const restored = runSparseRouting(
                    compiled,
                    bits,
                    changed,
                    true,
                );
                assert.deepEqual(
                    restored,
                    encodeDatabase(
                        expanded,
                        previousCapacity + 1,
                        inputBits,
                        outputBits,
                    ),
                );
                assert.deepEqual(
                    runSparseRouting(compiled, bits, restored),
                    changed,
                );
                updates++;
            }
        }
    };
    const enumerate = (entries: Entry[], next: number) => {
        exercise(entries);
        if (entries.length === previousCapacity + 1) return;
        for (let input = next; input < 2 ** inputBits; input++)
            for (let output = 0; output < 2 ** outputBits; output++)
                enumerate([...entries, { input, output }], input + 1);
    };
    enumerate([], 0);
    return {
        previousCapacity,
        inputBits,
        outputBits,
        cases,
        updates,
        removeGates: compiled.remove.gates.length,
        insertGates: compiled.insert.gates.length,
        routingGates: compiled.routingGates,
        roundTripRoutingGates: compiled.roundTripRoutingGates,
        routingQubits:
            inputBits +
            2 * compiled.databaseBits +
            Math.max(
                compiled.remove.wires - compiled.remove.inputs,
                compiled.insert.wires - compiled.insert.inputs,
            ),
    };
}

// Independently derived from the linear scan and mux construction above.
// These are gates in {X, CNOT, Toffoli, controlled-H}, each of arity at most 3.
export function sparseRoutingWork(
    priorQueries: bigint,
    inputBits: bigint,
    outputBits: bigint,
) {
    assert.ok(priorQueries >= 0n && inputBits >= 1n && outputBits >= 1n);
    const width = inputBits + outputBits + 1n,
        databaseBits = (priorQueries + 1n) * width;
    const removeGates =
        priorQueries * (18n + 10n * inputBits + 8n * outputBits) +
        8n +
        5n * inputBits +
        3n * outputBits;
    const insertGates =
        priorQueries * (26n + 17n * inputBits + 10n * outputBits) + 10n * width;
    const routingGates =
        priorQueries * (93n + 59n * inputBits + 41n * outputBits) +
        41n +
        35n * inputBits +
        31n * outputBits;
    const maximumCleanWorkBits =
        7n +
        6n * inputBits +
        6n * outputBits +
        priorQueries * (16n + 10n * inputBits + 6n * outputBits);
    const localUpdate = {
        controlledHadamard: 4n * outputBits,
        not: 4n * outputBits,
        cnot: 2n,
        toffoli: 5n * outputBits - 4n,
    };
    return {
        priorQueries,
        inputBits,
        outputBits,
        databaseBits,
        removeGates,
        insertGates,
        routingGates,
        roundTripRoutingGates: 2n * routingGates,
        routingQubits: inputBits + 2n * databaseBits + maximumCleanWorkBits,
        // Wire-index entries materialized in row tuples while constructing
        // both circuits, not bit gates or a complete constructor-time bound.
        // Remove uses C+1 comparison rows and 2C shift rows; insert uses 2C.
        constructorTupleIndexWords: (5n * priorQueries + 1n) * width,
        localUpdate,
        localUpdateGates: 13n * outputBits - 2n,
    };
}

export function sparseOracleQuerySchedule(
    queries: bigint,
    inputBits: bigint,
    outputBits: bigint,
) {
    assert.ok(queries >= 0n && inputBits >= 1n && outputBits >= 1n);
    const slope = 2n * (93n + 59n * inputBits + 41n * outputBits),
        constant =
            2n * (41n + 35n * inputBits + 31n * outputBits) +
            13n * outputBits -
            2n;
    return {
        queries,
        inputBits,
        outputBits,
        queryGates:
            (slope * queries * (queries - 1n)) / 2n + constant * queries,
        maximumQubits:
            queries === 0n
                ? 0n
                : sparseRoutingWork(queries - 1n, inputBits, outputBits)
                      .routingQubits + outputBits,
    };
}

export function firstMatchingEntry(
    builder: Builder,
    rows: readonly number[][],
    matches: readonly number[],
    inputBits: number,
) {
    const output = Array<number>(inputBits).fill(builder.zero);
    let found = builder.zero;
    for (let index = 0; index < rows.length; index++) {
        const row = rows[index],
            take = builder.and(
                builder.and(matches[index], row[row.length - 1]),
                builder.not(found),
            );
        for (let bit = 0; bit < inputBits; bit++)
            output[bit] = builder.xor(output[bit], builder.and(take, row[bit]));
        found = builder.or(found, take);
    }
    return [...output, found];
}

// Selection consumes coherently computed relation bits, never public claims.
function compileSparseSelection(
    capacity: number,
    inputBits: number,
    outputBits: number,
) {
    assert.ok([capacity, inputBits, outputBits].every(Number.isSafeInteger));
    assert.ok(capacity >= 0 && inputBits >= 1 && outputBits >= 1);
    const width = inputBits + outputBits + 1,
        builder = new Builder(capacity + capacity * width),
        rows = Array.from({ length: capacity }, (_, index) =>
            Array.from(
                { length: width },
                (_item, bit) => capacity + index * width + bit,
            ),
        );
    const circuit = builder.finish(
        firstMatchingEntry(
            builder,
            rows,
            Array.from({ length: capacity }, (_, index) => index),
            inputBits,
        ),
    );
    assert.equal(circuit.gates.length, capacity * (9 + 3 * inputBits));
    return circuit;
}

export function verifySparseSelection(
    capacity: number,
    inputBits: number,
    outputBits: number,
) {
    const circuit = compileSparseSelection(capacity, inputBits, outputBits);
    let cases = 0;
    const enumerate = (entries: Entry[], next: number) => {
        const database = encodeDatabase(
            entries,
            capacity,
            inputBits,
            outputBits,
        );
        for (let mask = 0; mask < 2 ** capacity; mask++) {
            const matches = integerBits(mask, capacity),
                out = new Uint8Array(inputBits + 1);
            applyClean(circuit, matches, database, out);
            const expected = entries.find(
                (_entry, index) => matches[index] === 1,
            );
            assert.equal(out[inputBits], expected ? 1 : 0);
            assert.equal(
                fromBits(out.subarray(0, inputBits)),
                expected?.input ?? 0,
            );
            cases++;
        }
        if (entries.length === capacity) return;
        for (let input = next; input < 2 ** inputBits; input++)
            for (let output = 0; output < 2 ** outputBits; output++)
                enumerate([...entries, { input, output }], input + 1);
    };
    enumerate([], 0);
    return {
        capacity,
        inputBits,
        outputBits,
        cases,
        computeGates: circuit.gates.length,
        cleanSelectionGates: 2 * circuit.gates.length + inputBits + 1,
    };
}
