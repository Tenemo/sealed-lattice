import assert from 'node:assert/strict';

import {
    compileOraclePrefixReplacement,
    runOraclePrefixReplacement,
    prefixOracleWork,
} from '#tests/compressed-oracle/oracle-access.js';
import {
    Builder,
    applyClean,
    integerBits,
    fromBits,
} from '#tests/compressed-oracle/reversible-circuit.js';
import { sparseRoutingWork } from '#tests/compressed-oracle/sparse-routing.js';

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

export function verifyProgrammedLocalOracle(outputBits: number) {
    assert.ok(
        Number.isSafeInteger(outputBits) && outputBits >= 1 && outputBits <= 2,
    );
    const full = compileLocalOracleUpdate(outputBits),
        size = 2 ** outputBits,
        resultStart = full.qubits,
        dimension = 2 ** (resultStart + outputBits),
        index = (entry: number, result: number) =>
            (entry < 0 ? 0 : 2 ** full.valid + entry) +
            result * 2 ** resultStart,
        coefficient = (out: number, input: number) =>
            out < 0
                ? input < 0
                    ? 0
                    : 1 / Math.sqrt(size)
                : input < 0
                  ? 1 / Math.sqrt(size)
                  : (out === input ? 1 : 0) - 1 / size;
    let cases = 0,
        maximumError = 0;
    for (let prefixBits = 0; prefixBits <= outputBits; prefixBits++)
        for (
            let replacement = 0;
            replacement < 2 ** prefixBits;
            replacement++
        ) {
            const copy = compileOraclePrefixReplacement(0, outputBits, [
                {
                    input: new Uint8Array(),
                    prefix: integerBits(replacement, prefixBits),
                },
            ]);
            for (let length = 0; length <= outputBits; length++) {
                const masks = Array.from({ length: size }, (_, base) =>
                    fromBits(
                        runOraclePrefixReplacement(
                            copy,
                            new Uint8Array(),
                            0,
                            length,
                            integerBits(base, outputBits),
                            new Uint8Array(outputBits),
                        ),
                    ),
                );
                for (let entry = -1; entry < size; entry++)
                    for (let response = 0; response < size; response++) {
                        const actual = new Float64Array(dimension),
                            expected = new Float64Array(dimension);
                        actual[index(entry, response)] = 1;
                        applyLocalGates(full.gates, actual);
                        const copied = new Float64Array(dimension);
                        for (let basis = 0; basis < dimension; basis++) {
                            const base =
                                Math.floor(basis / 2 ** full.accumulator) %
                                size;
                            copied[basis ^ (masks[base] * 2 ** resultStart)] =
                                actual[basis];
                        }
                        applyLocalGates(full.gates, copied);
                        for (
                            let intermediate = -1;
                            intermediate < size;
                            intermediate++
                        )
                            for (let out = -1; out < size; out++) {
                                const value =
                                        intermediate < 0 ? 0 : intermediate,
                                    patched =
                                        (Math.floor(value / 2 ** prefixBits) *
                                            2 ** prefixBits +
                                            replacement) %
                                        2 ** length;
                                expected[index(out, response ^ patched)] +=
                                    coefficient(intermediate, entry) *
                                    coefficient(out, intermediate);
                            }
                        for (let basis = 0; basis < dimension; basis++)
                            maximumError = Math.max(
                                maximumError,
                                Math.abs(copied[basis] - expected[basis]),
                            );
                        assert.ok(maximumError < 1e-12);
                        cases++;
                    }
            }
        }
    return { outputBits, cases, maximumError };
}
