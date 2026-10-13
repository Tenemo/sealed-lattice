import assert from 'node:assert/strict';

type Gate = { target: number; controls: number[] };

export type Circuit = {
    inputs: number;
    wires: number;
    gates: Gate[];
    output: number[];
};

export class Builder {
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

function applyGate(bits: Uint8Array, gate: Gate) {
    if (gate.controls.every((control) => bits[control] === 1))
        bits[gate.target] ^= 1;
}

// Compute, XOR-copy, then uncompute every work bit. Outputs may be nonzero.
export function applyClean(
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

export function runCleanCircuit(
    circuit: Circuit,
    input: Uint8Array,
    output = new Uint8Array(circuit.output.length),
) {
    applyClean(circuit, new Uint8Array(0), input, output);
    return output;
}

export const integerBits = (value: number, width: number) => {
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

export const fromBits = (bits: Uint8Array) => {
    const value = bits.reduce((sum, bit, index) => sum + bit * 2 ** index, 0);
    assert.ok(Number.isSafeInteger(value));
    return value;
};

export const integerWidth = (value: bigint) => {
    let width = 1n;
    while (1n << width <= value) width++;
    return width;
};
