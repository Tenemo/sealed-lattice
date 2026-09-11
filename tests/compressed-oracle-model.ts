import assert from 'node:assert/strict';

type Gate = { target: number; controls: number[] };
type Circuit = {
    inputs: number;
    wires: number;
    gates: Gate[];
    output: number[];
};

class Builder {
    readonly gates: Gate[] = [];
    wires: number;
    readonly zero: number;
    constructor(readonly inputs: number) {
        this.wires = inputs;
        this.zero = this.wires++;
    }
    gate(controls: number[]) {
        const target = this.wires++;
        this.gates.push({ target, controls });
        return target;
    }
    not(value: number) {
        const target = this.gate([]);
        this.gates.push({ target, controls: [value] });
        return target;
    }
    and(left: number, right: number) {
        return this.gate(left === right ? [left] : [left, right]);
    }
    xor(left: number, right: number) {
        const target = this.gate([left]);
        this.gates.push({ target, controls: [right] });
        return target;
    }
    or(left: number, right: number) {
        return this.xor(this.xor(left, right), this.and(left, right));
    }
    select(control: number, yes: number, no: number) {
        return this.xor(no, this.and(control, this.xor(yes, no)));
    }
    equal(left: readonly number[], right: readonly number[]) {
        let value = this.not(this.zero);
        for (let index = 0; index < left.length; index++)
            value = this.and(
                value,
                this.not(this.xor(left[index], right[index])),
            );
        return value;
    }
    less(left: readonly number[], right: readonly number[]) {
        let value = this.zero;
        for (let index = 0; index < left.length; index++) {
            const different = this.xor(left[index], right[index]);
            value = this.select(different, right[index], value);
        }
        return value;
    }
    finish(output: number[]): Circuit {
        for (const gate of this.gates) {
            assert.equal(new Set(gate.controls).size, gate.controls.length);
            assert.ok(!gate.controls.includes(gate.target));
        }
        return {
            inputs: this.inputs,
            wires: this.wires,
            gates: this.gates,
            output,
        };
    }
}

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
            for (let index = 0; index <= previousCapacity; index++)
                value = builder.xor(
                    value,
                    builder.and(matches[index], tuple(index)[inputBits + bit]),
                );
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

function applyGate(bits: Uint8Array, gate: Gate) {
    if (gate.controls.every((control) => bits[control] === 1))
        bits[gate.target] ^= 1;
}

// Compute, XOR-copy, then uncompute every work bit. Outputs may be nonzero.
function applyClean(
    circuit: Circuit,
    query: Uint8Array,
    input: Uint8Array,
    output: Uint8Array,
) {
    assert.equal(query.length + input.length, circuit.inputs);
    assert.equal(output.length, circuit.output.length);
    const bits = new Uint8Array(circuit.wires);
    bits.set(query);
    bits.set(input, query.length);
    // The clean XOR oracle is its own inverse, including nonzero output.
    for (const gate of circuit.gates) applyGate(bits, gate);
    for (let index = 0; index < output.length; index++)
        output[index] ^= bits[circuit.output[index]];
    for (let index = circuit.gates.length - 1; index >= 0; index--)
        applyGate(bits, circuit.gates[index]);
    assert.ok(
        bits.subarray(circuit.inputs).every((value) => value === 0),
        'Circuit left private routing garbage.',
    );
    assert.deepEqual(bits.subarray(0, query.length), query);
    assert.deepEqual(bits.subarray(query.length, circuit.inputs), input);
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

const integerBits = (value: number, width: number) => {
    assert.ok(
        Number.isSafeInteger(value) &&
            value >= 0 &&
            Number.isSafeInteger(width) &&
            width >= 0 &&
            value < 2 ** width,
    );
    return Uint8Array.from(
        { length: width },
        (_, bit) => Math.floor(value / 2 ** bit) % 2,
    );
};
const fromBits = (bits: Uint8Array) => {
    const value = bits.reduce((sum, bit, index) => sum + bit * 2 ** index, 0);
    assert.ok(Number.isSafeInteger(value));
    return value;
};
type Entry = { input: number; output: number };
function encodeDatabase(
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

function firstMatchingEntry(
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

// Complete predicate computation for f(x,y)=(low_label_bits(x),y), followed
// by the exact first-match output. Its relation bits are part of clean work.
export function compileLabelledHashExtraction(
    capacity: number,
    inputBits: number,
    outputBits: number,
    labelBits: number,
    hashPrefixBits = outputBits,
) {
    assert.ok(
        [capacity, inputBits, outputBits, labelBits, hashPrefixBits].every(
            Number.isSafeInteger,
        ),
    );
    assert.ok(
        capacity >= 0 &&
            inputBits >= 1 &&
            outputBits >= 1 &&
            labelBits >= 0 &&
            labelBits <= inputBits &&
            hashPrefixBits >= 1 &&
            hashPrefixBits <= outputBits,
    );
    const targetBits = labelBits + hashPrefixBits,
        width = inputBits + outputBits + 1,
        builder = new Builder(targetBits + capacity * width),
        target = Array.from({ length: targetBits }, (_, index) => index),
        rows = Array.from({ length: capacity }, (_, index) =>
            Array.from(
                { length: width },
                (_item, bit) => targetBits + index * width + bit,
            ),
        );
    const matches = rows.map((row) =>
        builder.and(
            builder.equal(row.slice(0, labelBits), target.slice(0, labelBits)),
            builder.equal(
                row.slice(inputBits, inputBits + hashPrefixBits),
                target.slice(labelBits),
            ),
        ),
    );
    const circuit = builder.finish(
        firstMatchingEntry(builder, rows, matches, inputBits),
    );
    assert.equal(
        circuit.gates.length,
        capacity * (14 + 5 * (labelBits + hashPrefixBits) + 3 * inputBits),
    );
    return circuit;
}

export function labelledHashExtractionWork(
    capacity: bigint,
    inputBits: bigint,
    outputBits: bigint,
    labelBits: bigint,
    hashPrefixBits = outputBits,
) {
    assert.ok(
        capacity >= 0n &&
            inputBits >= 1n &&
            outputBits >= 1n &&
            labelBits >= 0n &&
            labelBits <= inputBits &&
            hashPrefixBits >= 1n &&
            hashPrefixBits <= outputBits,
    );
    return {
        capacity,
        inputBits,
        outputBits,
        labelBits,
        hashPrefixBits,
        extractionGates:
            2n *
                capacity *
                (14n + 5n * (labelBits + hashPrefixBits) + 3n * inputBits) +
            inputBits +
            1n,
        measuredQubits: inputBits + 1n,
        extractionQubits:
            labelBits +
            hashPrefixBits +
            inputBits +
            2n +
            capacity *
                (10n +
                    3n * labelBits +
                    3n * hashPrefixBits +
                    outputBits +
                    3n * inputBits),
    };
}

export function verifyLabelledHashExtraction(
    capacity: number,
    inputBits: number,
    outputBits: number,
    labelBits: number,
    hashPrefixBits = outputBits,
) {
    const circuit = compileLabelledHashExtraction(
        capacity,
        inputBits,
        outputBits,
        labelBits,
        hashPrefixBits,
    );
    let cases = 0;
    const enumerate = (entries: Entry[], next: number) => {
        const database = encodeDatabase(
            entries,
            capacity,
            inputBits,
            outputBits,
        );
        for (let label = 0; label < 2 ** labelBits; label++)
            for (let hash = 0; hash < 2 ** hashPrefixBits; hash++) {
                const target = Uint8Array.from([
                        ...integerBits(label, labelBits),
                        ...integerBits(hash, hashPrefixBits),
                    ]),
                    out = new Uint8Array(inputBits + 1);
                applyClean(circuit, target, database, out);
                const expected = entries.find(
                    (entry) =>
                        entry.input % 2 ** labelBits === label &&
                        entry.output % 2 ** hashPrefixBits === hash,
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
        labelBits,
        cases,
        extractionGates: 2 * circuit.gates.length + inputBits + 1,
    };
}

export function sparseExtractionWork(
    capacity: bigint,
    inputBits: bigint,
    relationCleanQueryGates: bigint,
) {
    assert.ok(
        capacity >= 0n && inputBits >= 1n && relationCleanQueryGates >= 0n,
    );
    const selectionGates =
        2n * capacity * (9n + 3n * inputBits) + inputBits + 1n;
    return {
        capacity,
        inputBits,
        relationCleanQueryGates,
        selectionGates,
        extractionGates:
            2n * capacity * relationCleanQueryGates + selectionGates,
    };
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

export function compileLocalOracleUpdate(outputBits: number) {
    assert.ok(Number.isSafeInteger(outputBits) && outputBits >= 1);
    const valid = outputBits,
        accumulator = outputBits + 1,
        ancilla = 2 * outputBits + 1,
        qubits = 3 * outputBits;
    type QuantumGate = {
        kind: 'x' | 'cnot' | 'toffoli' | 'controlledHadamard';
        target: number;
        controls: number[];
    };
    const gates: QuantumGate[] = [];
    const x = (target: number) =>
        gates.push({ kind: 'x', target, controls: [] });
    const cx = (control: number, target: number) =>
        gates.push({ kind: 'cnot', target, controls: [control] });
    const ccx = (first: number, second: number, target: number) =>
        gates.push({ kind: 'toffoli', target, controls: [first, second] });
    const transform = () => {
        for (let bit = 0; bit < outputBits; bit++)
            gates.push({
                kind: 'controlledHadamard',
                target: bit,
                controls: [valid],
            });
        for (let bit = 0; bit < outputBits; bit++) x(bit);
        if (outputBits === 1) cx(0, valid);
        else {
            ccx(0, 1, ancilla);
            for (let bit = 2; bit < outputBits; bit++)
                ccx(ancilla + bit - 2, bit, ancilla + bit - 1);
            cx(ancilla + outputBits - 2, valid);
            for (let bit = outputBits - 1; bit >= 2; bit--)
                ccx(ancilla + bit - 2, bit, ancilla + bit - 1);
            ccx(0, 1, ancilla);
        }
        for (let bit = 0; bit < outputBits; bit++) x(bit);
        for (let bit = 0; bit < outputBits; bit++)
            gates.push({
                kind: 'controlledHadamard',
                target: bit,
                controls: [valid],
            });
    };
    transform();
    for (let bit = 0; bit < outputBits; bit++)
        ccx(valid, bit, accumulator + bit);
    transform();
    return { gates, valid, accumulator, qubits };
}

export function compilePrefixCopy(outputBits: number) {
    assert.ok(Number.isSafeInteger(outputBits) && outputBits >= 1);
    const lengthBits = Math.ceil(Math.log2(outputBits + 1)),
        builder = new Builder(outputBits + lengthBits),
        one = builder.not(builder.zero),
        length = Array.from(
            { length: lengthBits },
            (_, bit) => outputBits + bit,
        ),
        out = [];
    for (let bit = 0; bit < outputBits; bit++) {
        const ordinal = Array.from({ length: lengthBits }, (_item, index) =>
            Math.floor(bit / 2 ** index) % 2 ? one : builder.zero,
        );
        out.push(builder.and(bit, builder.less(ordinal, length)));
    }
    return { circuit: builder.finish(out), lengthBits };
}

export const prefixOracleQueriesPerAccess = 2n;

const integerWidth = (value: bigint) => {
    let width = 1n;
    while (1n << width <= value) width++;
    return width;
};

export function oracleCellControllerWork(
    inputCapacity: bigint,
    outputCapacity: bigint,
    inputClassUpper: bigint,
    outputStart: bigint,
    outputSize: bigint,
) {
    assert.ok(
        inputCapacity >= 0n &&
            outputCapacity >= 0n &&
            inputClassUpper >= 1n &&
            (inputClassUpper & (inputClassUpper - 1n)) === 0n &&
            outputStart >= 0n &&
            outputSize >= 1n,
    );
    const maximum = (a: bigint, b: bigint) => (a > b ? a : b),
        inputLengthBits = integerWidth(inputCapacity),
        outputLengthBits = integerWidth(outputCapacity),
        inputComparisonBits = maximum(
            integerWidth(inputCapacity + 1n),
            integerWidth(inputClassUpper + 1n),
        ),
        outputComparisonBits = maximum(
            integerWidth(outputCapacity + 1n),
            integerWidth(outputStart + outputSize),
        ),
        prefixLengthBits = integerWidth(outputSize);
    const dataBits =
            inputCapacity < inputClassUpper + 1n
                ? inputCapacity
                : inputClassUpper + 1n,
        markerBits = inputCapacity <= inputClassUpper ? 1n : 0n;
    const computeGates =
        12n +
        21n * inputComparisonBits +
        32n * outputComparisonBits +
        6n * prefixLengthBits +
        dataBits * (9n + 12n * inputComparisonBits) +
        markerBits * (3n + 5n * inputComparisonBits);
    const cleanWorkQubits =
        9n +
        12n * inputComparisonBits +
        19n * outputComparisonBits +
        4n * prefixLengthBits +
        dataBits * (6n + 7n * inputComparisonBits) +
        markerBits * (2n + 3n * inputComparisonBits);
    const outputBits = inputClassUpper + 1n + prefixLengthBits,
        inputBits = inputCapacity + inputLengthBits + outputLengthBits;
    return {
        inputCapacity,
        outputCapacity,
        inputClassUpper,
        outputStart,
        outputSize,
        inputLengthBits,
        outputLengthBits,
        inputComparisonBits,
        outputComparisonBits,
        prefixLengthBits,
        computeGates,
        cleanWorkQubits,
        inputBits,
        outputBits,
        computeAndUncomputeGates: 4n * computeGates + 2n * outputBits,
        controllerQubits: inputBits + outputBits + cleanWorkQubits,
    };
}

export function compileOracleCellController(
    inputCapacity: number,
    outputCapacity: number,
    inputClassUpper: number,
    outputStart: number,
    outputSize: number,
) {
    assert.ok(
        [
            inputCapacity,
            outputCapacity,
            inputClassUpper,
            outputStart,
            outputSize,
            outputStart + outputSize,
        ].every(Number.isSafeInteger),
    );
    const work = oracleCellControllerWork(
        BigInt(inputCapacity),
        BigInt(outputCapacity),
        BigInt(inputClassUpper),
        BigInt(outputStart),
        BigInt(outputSize),
    );
    const inputLengthBits = Number(work.inputLengthBits),
        outputLengthBits = Number(work.outputLengthBits),
        cx = Number(work.inputComparisonBits),
        cy = Number(work.outputComparisonBits),
        prefixLengthBits = Number(work.prefixLengthBits),
        builder = new Builder(Number(work.inputBits)),
        one = builder.not(builder.zero);
    const constant = (value: number, width: number) =>
        Array.from({ length: width }, (_, bit) =>
            Math.floor(value / 2 ** bit) % 2 ? one : builder.zero,
        );
    const inputLength = Array.from({ length: cx }, (_, bit) =>
            bit < inputLengthBits ? inputCapacity + bit : builder.zero,
        ),
        outputLength = Array.from({ length: cy }, (_, bit) =>
            bit < outputLengthBits
                ? inputCapacity + inputLengthBits + bit
                : builder.zero,
        );
    const lower = inputClassUpper === 1 ? 0 : inputClassUpper / 2 + 1;
    const validInput = builder.less(
            inputLength,
            constant(inputCapacity + 1, cx),
        ),
        aboveLower = builder.not(
            builder.less(inputLength, constant(lower, cx)),
        ),
        belowUpper = builder.less(
            inputLength,
            constant(inputClassUpper + 1, cx),
        ),
        inside = builder.and(builder.and(validInput, aboveLower), belowUpper);
    const key = [];
    for (let bit = 0; bit <= inputClassUpper; bit++) {
        if (bit < inputCapacity) {
            const atEnd = builder.equal(inputLength, constant(bit, cx)),
                beforeEnd = builder.less(constant(bit, cx), inputLength);
            key.push(
                builder.and(
                    inside,
                    builder.or(atEnd, builder.and(bit, beforeEnd)),
                ),
            );
        } else if (bit === inputCapacity)
            key.push(
                builder.and(
                    inside,
                    builder.equal(inputLength, constant(bit, cx)),
                ),
            );
        else key.push(builder.zero);
    }
    const validOutput = builder.less(
            outputLength,
            constant(outputCapacity + 1, cy),
        ),
        pastEnd = builder.not(
            builder.less(outputLength, constant(outputStart + outputSize, cy)),
        ),
        start = constant(outputStart, cy),
        difference: number[] = [];
    let borrow = builder.zero;
    for (let bit = 0; bit < cy; bit++) {
        difference.push(
            builder.xor(builder.xor(outputLength[bit], start[bit]), borrow),
        );
        borrow = builder.or(
            builder.and(
                builder.not(outputLength[bit]),
                builder.or(start[bit], borrow),
            ),
            builder.and(start[bit], borrow),
        );
    }
    const active = builder.and(
            builder.and(inside, validOutput),
            builder.not(borrow),
        ),
        size = constant(outputSize, prefixLengthBits),
        length = Array.from({ length: prefixLengthBits }, (_, bit) =>
            builder.and(
                active,
                builder.select(pastEnd, size[bit], difference[bit]),
            ),
        );
    const circuit = builder.finish([...key, ...length]);
    assert.equal(BigInt(circuit.gates.length), work.computeGates);
    assert.equal(BigInt(circuit.wires - circuit.inputs), work.cleanWorkQubits);
    return { circuit, work };
}

export function runOracleCellController(
    compiled: ReturnType<typeof compileOracleCellController>,
    data: Uint8Array,
    inputLength: number,
    outputLength: number,
) {
    const { work, circuit } = compiled,
        controls = Uint8Array.from([
            ...integerBits(inputLength, Number(work.inputLengthBits)),
            ...integerBits(outputLength, Number(work.outputLengthBits)),
        ]),
        out = new Uint8Array(circuit.output.length);
    applyClean(circuit, data, controls, out);
    const result = {
        encodedInput: out.slice(0, Number(work.inputClassUpper) + 1),
        prefixLength: fromBits(out.subarray(Number(work.inputClassUpper) + 1)),
    };
    applyClean(circuit, data, controls, out);
    assert.ok(out.every((value) => value === 0));
    return result;
}

export function prefixOracleWork(
    logicalQueries: bigint,
    inputBits: bigint,
    outputBits: bigint,
) {
    assert.ok(logicalQueries >= 0n && inputBits >= 1n && outputBits >= 1n);
    let lengthBits = 0n;
    while (1n << lengthBits < outputBits + 1n) lengthBits++;
    const copyGates = 4n + outputBits * (14n * lengthBits + 3n),
        copyWorkQubits = 2n + outputBits * (4n * lengthBits + 1n),
        fullValueQueries = prefixOracleQueriesPerAccess * logicalQueries;
    const full = sparseOracleQuerySchedule(
            fullValueQueries,
            inputBits,
            outputBits,
        ),
        databaseQubits = fullValueQueries * (inputBits + outputBits + 1n);
    const duringQuery = full.maximumQubits + outputBits + lengthBits,
        duringCopy =
            inputBits +
            databaseQubits +
            2n * outputBits +
            lengthBits +
            copyWorkQubits;
    return {
        logicalQueries,
        inputBits,
        outputBits,
        lengthBits,
        fullValueQueries,
        copyGates,
        copyWorkQubits,
        queryGates: full.queryGates + logicalQueries * copyGates,
        maximumQubits:
            logicalQueries === 0n
                ? 0n
                : duringQuery > duringCopy
                  ? duringQuery
                  : duringCopy,
    };
}

export function verifyPrefixOracleWrapper(outputBits: number) {
    assert.ok(
        Number.isSafeInteger(outputBits) && outputBits >= 1 && outputBits <= 2,
    );
    const full = compileLocalOracleUpdate(outputBits),
        copy = compilePrefixCopy(outputBits),
        size = 2 ** outputBits,
        resultStart = full.qubits,
        lengthStart = resultStart + outputBits,
        dimension = 2 ** (lengthStart + copy.lengthBits);
    let copyCases = 0;
    for (let value = 0; value < size; value++)
        for (let length = 0; length <= outputBits; length++)
            for (let result = 0; result < size; result++) {
                const out = integerBits(result, outputBits);
                applyClean(
                    copy.circuit,
                    integerBits(value, outputBits),
                    integerBits(length, copy.lengthBits),
                    out,
                );
                assert.equal(
                    fromBits(out),
                    result ^ (value & (2 ** length - 1)),
                );
                copyCases++;
            }
    const index = (entry: number, result: number, length: number) =>
        (entry < 0 ? 0 : 2 ** full.valid + entry) +
        result * 2 ** resultStart +
        length * 2 ** lengthStart;
    const coefficient = (out: number, input: number) =>
        out < 0
            ? input < 0
                ? 0
                : 1 / Math.sqrt(size)
            : input < 0
              ? 1 / Math.sqrt(size)
              : (out === input ? 1 : 0) - 1 / size;
    let cases = 0,
        maximumError = 0,
        fullValueQueries = 0;
    const oracle = (state: Float64Array) => {
        fullValueQueries++;
        applyLocalGates(full.gates, state);
    };
    for (let entry = -1; entry < size; entry++)
        for (let result = 0; result < size; result++)
            for (let length = 0; length <= outputBits; length++) {
                const actual = new Float64Array(dimension),
                    expected = new Float64Array(dimension);
                actual[index(entry, result, length)] = 1;
                oracle(actual);
                // The independently checked clean copy circuit has this phase-free
                // action on its logical registers; all its work qubits are zero.
                for (let bit = 0; bit < outputBits; bit++)
                    for (let basis = 0; basis < dimension; basis++)
                        if (
                            (basis & (2 ** (resultStart + bit))) === 0 &&
                            ((basis >> lengthStart) &
                                (2 ** copy.lengthBits - 1)) >
                                bit &&
                            (basis & (2 ** (full.accumulator + bit))) !== 0
                        ) {
                            const other = basis | (2 ** (resultStart + bit)),
                                value = actual[basis];
                            actual[basis] = actual[other];
                            actual[other] = value;
                        }
                oracle(actual);
                for (let intermediate = -1; intermediate < size; intermediate++)
                    for (let out = -1; out < size; out++)
                        expected[
                            index(
                                out,
                                result ^
                                    (intermediate < 0
                                        ? 0
                                        : intermediate & (2 ** length - 1)),
                                length,
                            )
                        ] +=
                            coefficient(intermediate, entry) *
                            coefficient(out, intermediate);
                for (let basis = 0; basis < dimension; basis++)
                    maximumError = Math.max(
                        maximumError,
                        Math.abs(actual[basis] - expected[basis]),
                    );
                assert.ok(maximumError < 1e-12);
                cases++;
            }
    const work = prefixOracleWork(1n, 1n, BigInt(outputBits));
    assert.equal(
        work.copyGates,
        BigInt(2 * copy.circuit.gates.length + outputBits),
    );
    assert.equal(
        work.copyWorkQubits,
        BigInt(copy.circuit.wires - copy.circuit.inputs),
    );
    const discardedTail = [];
    for (let requested = 0; requested < outputBits; requested++) {
        let unequalTails = 0;
        for (let first = 0; first < size; first++)
            for (let second = 0; second < size; second++)
                if (
                    Math.floor(first / 2 ** requested) !==
                    Math.floor(second / 2 ** requested)
                )
                    unequalTails++;
        const badMinusProbability = unequalTails / (2 * size * size);
        assert.equal(
            badMinusProbability,
            (1 - 2 ** -(outputBits - requested)) / 2,
        );
        discardedTail.push({ requested, badMinusProbability });
    }
    return {
        outputBits,
        copyCases,
        cases,
        maximumError,
        fullValueQueriesPerLogicalQuery: fullValueQueries / cases,
        copyGates: 2 * copy.circuit.gates.length + outputBits,
        discardedTail,
    };
}

function applyLocalGates(
    gates: ReturnType<typeof compileLocalOracleUpdate>['gates'],
    actual: Float64Array,
) {
    for (const gate of gates) {
        const target = 2 ** gate.target;
        for (let basis = 0; basis < actual.length; basis++)
            if (
                (basis & target) === 0 &&
                gate.controls.every((control) => (basis & (2 ** control)) !== 0)
            ) {
                const other = basis | target,
                    left = actual[basis],
                    right = actual[other];
                if (gate.kind === 'controlledHadamard') {
                    actual[basis] = (left + right) / Math.sqrt(2);
                    actual[other] = (left - right) / Math.sqrt(2);
                } else {
                    actual[basis] = right;
                    actual[other] = left;
                }
            }
    }
}

export function verifyLocalOracleUpdate(outputBits: number) {
    assert.ok(
        Number.isSafeInteger(outputBits) && outputBits >= 1 && outputBits <= 3,
    );
    const { gates, valid, accumulator, qubits } =
            compileLocalOracleUpdate(outputBits),
        size = 2 ** outputBits,
        dimension = 2 ** qubits;
    const index = (entry: number, value: number) =>
        (entry < 0 ? 0 : 2 ** valid + entry) + value * 2 ** accumulator;
    const coefficient = (out: number, input: number) =>
        out < 0
            ? input < 0
                ? 0
                : 1 / Math.sqrt(size)
            : input < 0
              ? 1 / Math.sqrt(size)
              : (out === input ? 1 : 0) - 1 / size;
    const apply = (actual: Float64Array) => applyLocalGates(gates, actual);
    let cases = 0,
        maximumError = 0;
    for (let entry = -1; entry < size; entry++)
        for (let value = 0; value < size; value++) {
            const actual = new Float64Array(dimension),
                expected = new Float64Array(dimension);
            actual[index(entry, value)] = 1;
            apply(actual);
            for (let intermediate = -1; intermediate < size; intermediate++)
                for (let out = -1; out < size; out++)
                    expected[
                        index(
                            out,
                            intermediate < 0 ? value : value ^ intermediate,
                        )
                    ] +=
                        coefficient(intermediate, entry) *
                        coefficient(out, intermediate);
            for (let basis = 0; basis < dimension; basis++)
                maximumError = Math.max(
                    maximumError,
                    Math.abs(actual[basis] - expected[basis]),
                );
            assert.ok(maximumError < 1e-12);
            cases++;
        }
    const counts = { not: 0, cnot: 0, toffoli: 0, controlledHadamard: 0 };
    for (const gate of gates) counts[gate.kind === 'x' ? 'not' : gate.kind]++;
    assert.deepEqual(
        counts,
        Object.fromEntries(
            Object.entries(
                sparseRoutingWork(0n, 1n, BigInt(outputBits)).localUpdate,
            ).map(([key, value]) => [key, Number(value)]),
        ),
    );
    const first = new Float64Array(dimension);
    first[index(-1, 0)] = 1;
    apply(first);
    const clean = first.slice();
    apply(clean);
    const nonzero = (state: Float64Array) =>
        state.reduce(
            (sum, value, basis) =>
                sum +
                (((basis >> accumulator) & (size - 1)) === 0
                    ? 0
                    : value * value),
            0,
        );
    assert.ok(nonzero(clean) < 1e-24);
    // Copying the old presence flag to private garbage before the next query
    // dephases these branches even if the adversary never reads that flag.
    let retainedPresenceError = 0;
    for (const present of [false, true]) {
        const branch = first.slice();
        for (let basis = 0; basis < dimension; basis++)
            if (((basis & (2 ** valid)) !== 0) !== present) branch[basis] = 0;
        apply(branch);
        retainedPresenceError += nonzero(branch);
    }
    const expectedPresenceError = (2 * (size - 1)) / (size * size);
    assert.ok(Math.abs(retainedPresenceError - expectedPresenceError) < 1e-12);
    return {
        outputBits,
        cases,
        gates: gates.length,
        counts,
        maximumError,
        qubits,
        cleanTwoQueryError: nonzero(clean),
        retainedPresenceError,
        expectedPresenceError,
    };
}
