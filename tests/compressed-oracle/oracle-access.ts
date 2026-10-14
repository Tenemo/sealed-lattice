import assert from 'node:assert/strict';

import {
    Builder,
    applyClean,
    integerBits,
    fromBits,
    integerWidth,
} from '#tests/compressed-oracle/reversible-circuit.js';
import { sparseOracleQuerySchedule } from '#tests/compressed-oracle/sparse-routing.js';

export const prefixOracleQueriesPerAccess = 2n;

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
        inputComparisonBits = Number(work.inputComparisonBits),
        outputComparisonBits = Number(work.outputComparisonBits),
        prefixLengthBits = Number(work.prefixLengthBits),
        builder = new Builder(Number(work.inputBits)),
        one = builder.not(builder.zero);
    const constant = (value: number, width: number) =>
        Array.from({ length: width }, (_, bit) =>
            Math.floor(value / 2 ** bit) % 2 ? one : builder.zero,
        );
    const inputLength = Array.from({ length: inputComparisonBits }, (_, bit) =>
            bit < inputLengthBits ? inputCapacity + bit : builder.zero,
        ),
        outputLength = Array.from({ length: outputComparisonBits }, (_, bit) =>
            bit < outputLengthBits
                ? inputCapacity + inputLengthBits + bit
                : builder.zero,
        );
    const lower = inputClassUpper === 1 ? 0 : inputClassUpper / 2 + 1;
    const validInput = builder.less(
            inputLength,
            constant(inputCapacity + 1, inputComparisonBits),
        ),
        aboveLower = builder.not(
            builder.less(inputLength, constant(lower, inputComparisonBits)),
        ),
        belowUpper = builder.less(
            inputLength,
            constant(inputClassUpper + 1, inputComparisonBits),
        ),
        inside = builder.and(builder.and(validInput, aboveLower), belowUpper);
    const key = [];
    for (let bit = 0; bit <= inputClassUpper; bit++) {
        if (bit < inputCapacity) {
            const atEnd = builder.equal(
                    inputLength,
                    constant(bit, inputComparisonBits),
                ),
                beforeEnd = builder.less(
                    constant(bit, inputComparisonBits),
                    inputLength,
                );
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
                    builder.equal(
                        inputLength,
                        constant(bit, inputComparisonBits),
                    ),
                ),
            );
        else key.push(builder.zero);
    }
    const validOutput = builder.less(
            outputLength,
            constant(outputCapacity + 1, outputComparisonBits),
        ),
        pastEnd = builder.not(
            builder.less(
                outputLength,
                constant(outputStart + outputSize, outputComparisonBits),
            ),
        ),
        start = constant(outputStart, outputComparisonBits),
        difference: number[] = [];
    let borrow = builder.zero;
    for (let bit = 0; bit < outputComparisonBits; bit++) {
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

type OraclePrefixReplacement = {
    readonly input: Uint8Array;
    readonly prefix: Uint8Array;
};

export function oracleSliceRoutingWork(
    inputCapacity: bigint,
    outputCapacity: bigint,
    prefixLengths: readonly bigint[],
) {
    assert.ok(
        inputCapacity >= 0n &&
            outputCapacity >= 0n &&
            prefixLengths.every((length) => length >= 0n),
    );
    const inputLengthBits = integerWidth(inputCapacity),
        outputLengthBits = integerWidth(outputCapacity),
        inputComparisonBits = integerWidth(inputCapacity + 1n),
        outputComparisonBits = integerWidth(outputCapacity + 1n);
    let computeGates =
            6n +
            7n * inputComparisonBits +
            7n * outputComparisonBits +
            outputLengthBits,
        cleanWorkQubits =
            5n +
            4n * inputComparisonBits +
            4n * outputComparisonBits +
            outputLengthBits;
    for (const length of prefixLengths)
        if (length <= inputCapacity) {
            computeGates +=
                11n + 5n * length + 7n * inputComparisonBits + outputLengthBits;
            cleanWorkQubits +=
                7n + 3n * length + 4n * inputComparisonBits + outputLengthBits;
        }
    const inputBits = inputCapacity + inputLengthBits + outputLengthBits,
        outputBits = BigInt(prefixLengths.length + 1) * outputLengthBits;
    return {
        inputCapacity,
        outputCapacity,
        inputLengthBits,
        outputLengthBits,
        inputBits,
        outputBits,
        computeGates,
        cleanWorkQubits,
        computeAndUncomputeGates: 4n * computeGates + 2n * outputBits,
        routingQubits: inputBits + outputBits + cleanWorkQubits,
    };
}

export function compileOracleSliceRouting(
    inputCapacity: number,
    outputCapacity: number,
    prefixes: readonly Uint8Array[],
) {
    assert.ok(
        Number.isSafeInteger(inputCapacity) &&
            Number.isSafeInteger(outputCapacity),
    );
    for (let index = 0; index < prefixes.length; index++) {
        assert.ok(prefixes[index].every((bit) => bit <= 1));
        for (let other = 0; other < index; other++) {
            const length = Math.min(
                prefixes[index].length,
                prefixes[other].length,
            );
            assert.ok(
                !prefixes[index]
                    .subarray(0, length)
                    .every(
                        (bit, position) => bit === prefixes[other][position],
                    ),
                'Oracle slices overlap.',
            );
        }
    }
    const work = oracleSliceRoutingWork(
            BigInt(inputCapacity),
            BigInt(outputCapacity),
            prefixes.map((value) => BigInt(value.length)),
        ),
        builder = new Builder(Number(work.inputBits)),
        one = builder.not(builder.zero),
        inputComparisonBits = Number(integerWidth(BigInt(inputCapacity + 1))),
        outputComparisonBits = Number(integerWidth(BigInt(outputCapacity + 1))),
        a = Number(work.inputLengthBits),
        b = Number(work.outputLengthBits),
        constant = (value: number, width: number) =>
            Array.from({ length: width }, (_, bit) =>
                Math.floor(value / 2 ** bit) % 2 ? one : builder.zero,
            ),
        inputLength = Array.from({ length: inputComparisonBits }, (_, bit) =>
            bit < a ? inputCapacity + bit : builder.zero,
        ),
        outputLength = Array.from({ length: outputComparisonBits }, (_, bit) =>
            bit < b ? inputCapacity + a + bit : builder.zero,
        ),
        valid = builder.and(
            builder.less(
                inputLength,
                constant(inputCapacity + 1, inputComparisonBits),
            ),
            builder.less(
                outputLength,
                constant(outputCapacity + 1, outputComparisonBits),
            ),
        );
    const outputs: number[][] = [];
    let seen = builder.zero;
    for (const prefix of prefixes) {
        if (prefix.length > inputCapacity) {
            outputs.push(Array<number>(b).fill(builder.zero));
            continue;
        }
        const match = builder.and(
            builder.equal(
                Array.from({ length: prefix.length }, (_, bit) => bit),
                Array.from(prefix, (bit) => (bit ? one : builder.zero)),
            ),
            builder.not(
                builder.less(
                    inputLength,
                    constant(prefix.length, inputComparisonBits),
                ),
            ),
        );
        seen = builder.or(seen, match);
        const selected = builder.and(valid, match);
        outputs.push(
            outputLength.slice(0, b).map((bit) => builder.and(selected, bit)),
        );
    }
    const background = builder.and(valid, builder.not(seen));
    const circuit = builder.finish([
        ...outputLength.slice(0, b).map((bit) => builder.and(background, bit)),
        ...outputs.flat(),
    ]);
    assert.equal(BigInt(circuit.gates.length), work.computeGates);
    assert.equal(BigInt(circuit.wires - circuit.inputs), work.cleanWorkQubits);
    return { work, circuit };
}

export function runOracleSliceRouting(
    compiled: ReturnType<typeof compileOracleSliceRouting>,
    data: Uint8Array,
    inputLength: number,
    outputLength: number,
) {
    const { work, circuit } = compiled,
        controls = Uint8Array.from([
            ...integerBits(inputLength, Number(work.inputLengthBits)),
            ...integerBits(outputLength, Number(work.outputLengthBits)),
        ]),
        output = new Uint8Array(circuit.output.length);
    applyClean(circuit, data, controls, output);
    const values = Array.from(
        { length: output.length / Number(work.outputLengthBits) },
        (_, index) =>
            fromBits(
                output.subarray(
                    index * Number(work.outputLengthBits),
                    (index + 1) * Number(work.outputLengthBits),
                ),
            ),
    );
    applyClean(circuit, data, controls, output);
    assert.ok(output.every((bit) => bit === 0));
    return values;
}

export type OracleInputMask = {
    readonly inputLength: number;
    readonly positions: readonly number[];
    readonly values: Uint8Array;
};

export function oracleMaskRoutingWork(
    inputCapacity: bigint,
    outputCapacity: bigint,
    masks: readonly { inputLength: bigint; comparedBits: bigint }[],
) {
    assert.ok(inputCapacity >= 0n && outputCapacity >= 0n);
    const inputLengthBits = integerWidth(inputCapacity);
    const outputLengthBits = integerWidth(outputCapacity);
    const inputComparisonBits = integerWidth(inputCapacity + 1n);
    const outputComparisonBits = integerWidth(outputCapacity + 1n);
    let computeGates =
        6n +
        7n * inputComparisonBits +
        7n * outputComparisonBits +
        outputLengthBits;
    let cleanWorkQubits =
        5n +
        4n * inputComparisonBits +
        4n * outputComparisonBits +
        outputLengthBits;
    for (const mask of masks) {
        assert.ok(
            mask.inputLength >= 0n &&
                mask.comparedBits >= 0n &&
                mask.comparedBits <= mask.inputLength,
        );
        if (mask.inputLength <= inputCapacity) {
            computeGates +=
                11n +
                5n * mask.comparedBits +
                5n * inputComparisonBits +
                outputLengthBits;
            cleanWorkQubits +=
                7n +
                3n * mask.comparedBits +
                3n * inputComparisonBits +
                outputLengthBits;
        }
    }
    const inputBits = inputCapacity + inputLengthBits + outputLengthBits;
    const outputBits = BigInt(masks.length + 1) * outputLengthBits;
    return {
        inputCapacity,
        outputCapacity,
        inputLengthBits,
        outputLengthBits,
        inputBits,
        outputBits,
        computeGates,
        cleanWorkQubits,
        computeAndUncomputeGates: 4n * computeGates + 2n * outputBits,
        routingQubits: inputBits + outputBits + cleanWorkQubits,
    };
}

// Exact-length masks act on selected original input wires. They neither
// relabel raw inputs nor make two calls to the same bytes independent.
export function compileOracleMaskRouting(
    inputCapacity: number,
    outputCapacity: number,
    masks: readonly OracleInputMask[],
) {
    assert.ok(
        Number.isSafeInteger(inputCapacity) &&
            Number.isSafeInteger(outputCapacity),
    );
    for (const [index, mask] of masks.entries()) {
        assert.ok(
            Number.isSafeInteger(mask.inputLength) && mask.inputLength >= 0,
        );
        assert.equal(mask.positions.length, mask.values.length);
        assert.equal(new Set(mask.positions).size, mask.positions.length);
        assert.ok(
            mask.positions.every(
                (position) =>
                    Number.isSafeInteger(position) &&
                    position >= 0 &&
                    position < mask.inputLength,
            ),
        );
        assert.ok(mask.values.every((bit) => bit <= 1));
        const fixed = new Map(
            mask.positions.map((position, bit) => [position, mask.values[bit]]),
        );
        for (const other of masks.slice(0, index))
            assert.ok(
                other.inputLength !== mask.inputLength ||
                    other.positions.some(
                        (position, bit) =>
                            fixed.has(position) &&
                            fixed.get(position) !== other.values[bit],
                    ),
                'Oracle slices overlap.',
            );
    }
    const work = oracleMaskRoutingWork(
        BigInt(inputCapacity),
        BigInt(outputCapacity),
        masks.map((mask) => ({
            inputLength: BigInt(mask.inputLength),
            comparedBits: BigInt(mask.positions.length),
        })),
    );
    const builder = new Builder(Number(work.inputBits));
    const one = builder.not(builder.zero);
    const inputComparisonBits = Number(integerWidth(BigInt(inputCapacity + 1)));
    const outputComparisonBits = Number(
        integerWidth(BigInt(outputCapacity + 1)),
    );
    const a = Number(work.inputLengthBits);
    const b = Number(work.outputLengthBits);
    const constant = (value: number, width: number) =>
        Array.from({ length: width }, (_, bit) =>
            Math.floor(value / 2 ** bit) % 2 ? one : builder.zero,
        );
    const inputLength = Array.from({ length: inputComparisonBits }, (_, bit) =>
        bit < a ? inputCapacity + bit : builder.zero,
    );
    const outputLength = Array.from(
        { length: outputComparisonBits },
        (_, bit) => (bit < b ? inputCapacity + a + bit : builder.zero),
    );
    const valid = builder.and(
        builder.less(
            inputLength,
            constant(inputCapacity + 1, inputComparisonBits),
        ),
        builder.less(
            outputLength,
            constant(outputCapacity + 1, outputComparisonBits),
        ),
    );
    const outputs: number[][] = [];
    let seen = builder.zero;
    for (const mask of masks) {
        if (mask.inputLength > inputCapacity) {
            outputs.push(Array<number>(b).fill(builder.zero));
            continue;
        }
        const match = builder.and(
            builder.equal(
                mask.positions,
                Array.from(mask.values, (bit) => (bit ? one : builder.zero)),
            ),
            builder.equal(
                inputLength,
                constant(mask.inputLength, inputComparisonBits),
            ),
        );
        seen = builder.or(seen, match);
        const selected = builder.and(valid, match);
        outputs.push(
            outputLength.slice(0, b).map((bit) => builder.and(selected, bit)),
        );
    }
    const background = builder.and(valid, builder.not(seen));
    const circuit = builder.finish([
        ...outputLength.slice(0, b).map((bit) => builder.and(background, bit)),
        ...outputs.flat(),
    ]);
    assert.equal(BigInt(circuit.gates.length), work.computeGates);
    assert.equal(BigInt(circuit.wires - circuit.inputs), work.cleanWorkQubits);
    return { work, circuit };
}

export function oraclePrefixReplacementWork(
    inputCapacity: bigint,
    outputCapacity: bigint,
    replacements: readonly {
        readonly inputBits: bigint;
        readonly prefixBits: bigint;
    }[],
) {
    assert.ok(inputCapacity >= 0n && outputCapacity >= 0n);
    const inputLengthBits = integerWidth(inputCapacity),
        outputLengthBits = integerWidth(outputCapacity),
        inputComparisonBits = integerWidth(inputCapacity + 1n),
        outputComparisonBits = integerWidth(outputCapacity + 1n);
    let computeGates =
            3n +
            7n * inputComparisonBits +
            7n * outputComparisonBits +
            outputCapacity * (7n * outputComparisonBits + 2n),
        cleanWorkQubits =
            3n +
            4n * inputComparisonBits +
            4n * outputComparisonBits +
            outputCapacity * (4n * outputComparisonBits + 2n);
    for (const replacement of replacements) {
        assert.ok(replacement.inputBits >= 0n && replacement.prefixBits >= 0n);
        if (replacement.inputBits > inputCapacity) continue;
        const used =
            replacement.prefixBits < outputCapacity
                ? replacement.prefixBits
                : outputCapacity;
        computeGates +=
            5n + 5n * (inputComparisonBits + replacement.inputBits) + 5n * used;
        cleanWorkQubits +=
            3n + 3n * (inputComparisonBits + replacement.inputBits) + 3n * used;
    }
    const inputBits =
        inputCapacity + inputLengthBits + outputLengthBits + outputCapacity;
    return {
        inputCapacity,
        outputCapacity,
        inputLengthBits,
        outputLengthBits,
        inputComparisonBits,
        outputComparisonBits,
        inputBits,
        computeGates,
        cleanWorkQubits,
        cleanCopyGates: 2n * computeGates + outputCapacity,
        copyQubits: inputBits + outputCapacity + cleanWorkQubits,
    };
}

export function compileOraclePrefixReplacement(
    inputCapacity: number,
    outputCapacity: number,
    replacements: readonly OraclePrefixReplacement[],
) {
    assert.ok(
        Number.isSafeInteger(inputCapacity) &&
            Number.isSafeInteger(outputCapacity),
    );
    for (const replacement of replacements)
        assert.ok(
            replacement.input.every((bit) => bit <= 1) &&
                replacement.prefix.every((bit) => bit <= 1),
        );
    const work = oraclePrefixReplacementWork(
            BigInt(inputCapacity),
            BigInt(outputCapacity),
            replacements.map((replacement) => ({
                inputBits: BigInt(replacement.input.length),
                prefixBits: BigInt(replacement.prefix.length),
            })),
        ),
        builder = new Builder(Number(work.inputBits)),
        one = builder.not(builder.zero),
        constant = (value: number, width: number) =>
            Array.from({ length: width }, (_, bit) =>
                Math.floor(value / 2 ** bit) % 2 ? one : builder.zero,
            ),
        inputComparisonBits = Number(work.inputComparisonBits),
        outputComparisonBits = Number(work.outputComparisonBits),
        inputLength = Array.from({ length: inputComparisonBits }, (_, bit) =>
            bit < Number(work.inputLengthBits)
                ? inputCapacity + bit
                : builder.zero,
        ),
        outputLength = Array.from({ length: outputComparisonBits }, (_, bit) =>
            bit < Number(work.outputLengthBits)
                ? inputCapacity + Number(work.inputLengthBits) + bit
                : builder.zero,
        ),
        valid = builder.and(
            builder.less(
                inputLength,
                constant(inputCapacity + 1, inputComparisonBits),
            ),
            builder.less(
                outputLength,
                constant(outputCapacity + 1, outputComparisonBits),
            ),
        ),
        sourceStart =
            inputCapacity +
            Number(work.inputLengthBits + work.outputLengthBits),
        values = Array.from(
            { length: outputCapacity },
            (_, bit) => sourceStart + bit,
        );
    for (const replacement of replacements) {
        if (replacement.input.length > inputCapacity) continue;
        const match = builder.and(
            builder.equal(
                inputLength,
                constant(replacement.input.length, inputComparisonBits),
            ),
            builder.equal(
                Array.from(
                    { length: replacement.input.length },
                    (_, bit) => bit,
                ),
                Array.from(replacement.input, (bit) =>
                    bit ? one : builder.zero,
                ),
            ),
        );
        for (
            let bit = 0;
            bit < Math.min(outputCapacity, replacement.prefix.length);
            bit++
        )
            values[bit] = builder.select(
                match,
                replacement.prefix[bit] ? one : builder.zero,
                values[bit],
            );
    }
    const output = values.map((value, bit) =>
            builder.and(
                valid,
                builder.and(
                    builder.less(
                        constant(bit, outputComparisonBits),
                        outputLength,
                    ),
                    value,
                ),
            ),
        ),
        circuit = builder.finish(output);
    assert.equal(BigInt(circuit.gates.length), work.computeGates);
    assert.equal(BigInt(circuit.wires - circuit.inputs), work.cleanWorkQubits);
    return { circuit, work };
}

export function runOraclePrefixReplacement(
    compiled: ReturnType<typeof compileOraclePrefixReplacement>,
    data: Uint8Array,
    inputLength: number,
    outputLength: number,
    base: Uint8Array,
    response: Uint8Array,
) {
    const { work, circuit } = compiled;
    assert.equal(base.length, Number(work.outputCapacity));
    const controls = Uint8Array.from([
            ...integerBits(inputLength, Number(work.inputLengthBits)),
            ...integerBits(outputLength, Number(work.outputLengthBits)),
            ...base,
        ]),
        output = response.slice();
    applyClean(circuit, data, controls, output);
    const answer = output.slice();
    applyClean(circuit, data, controls, output);
    assert.deepEqual(output, response);
    return answer;
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
