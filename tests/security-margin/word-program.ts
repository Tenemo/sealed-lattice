import assert from 'node:assert/strict';

export type Word = number | bigint;
type BinaryOperation =
    | 'add'
    | 'subtract'
    | 'multiply'
    | 'bit-and'
    | 'shift-right'
    | 'equal'
    | 'less';
type Operation =
    | BinaryOperation
    | 'copy'
    | 'half'
    | 'low'
    | 'require'
    | 'read-span'
    | 'write-span'
    | 'jump-if-zero'
    | 'jump'
    | 'halt';
type Instruction = {
    operation: Operation;
    destination?: number;
    left?: Word;
    right?: Word;
    value?: Word;
    branch?: number;
};
export type WordProgram = {
    instructions: Instruction[];
    registers: number;
    inputs: Record<string, number>;
    results: Record<string, number>;
};

// This assembler writes a finite literal table before the reduction runs.
// The table uses only the classical instructions priced by the word-machine
// lowering lemma; assembly closures are not instructions in that machine.
export class WordProgramBuilder {
    readonly instructions: Instruction[] = [];
    readonly inputs: Record<string, number> = {};
    registers = 0;
    input(name: string) {
        assert(!(name in this.inputs));
        const register = this.registers++;
        this.inputs[name] = register;
        return register;
    }
    assign(destination: number, left: Word) {
        this.instructions.push({ operation: 'copy', destination, left });
    }
    copy(left: Word) {
        const destination = this.registers++;
        this.assign(destination, left);
        return destination;
    }
    binary(operation: BinaryOperation, left: Word, right: Word) {
        const destination = this.registers++;
        this.instructions.push({ operation, destination, left, right });
        return destination;
    }
    half(left: Word) {
        const destination = this.registers++;
        this.instructions.push({ operation: 'half', destination, left });
        return destination;
    }
    low(left: Word) {
        const destination = this.registers++;
        this.instructions.push({ operation: 'low', destination, left });
        return destination;
    }
    add(left: Word, right: Word) {
        return this.binary('add', left, right);
    }
    subtract(left: Word, right: Word) {
        return this.binary('subtract', left, right);
    }
    multiply(left: Word, right: Word) {
        return this.binary('multiply', left, right);
    }
    equal(left: Word, right: Word) {
        return this.binary('equal', left, right);
    }
    less(left: Word, right: Word) {
        return this.binary('less', left, right);
    }
    require(left: Word) {
        this.instructions.push({ operation: 'require', left });
    }
    readSpan(left: Word, right: Word) {
        const destination = this.registers++;
        this.instructions.push({
            operation: 'read-span',
            destination,
            left,
            right,
        });
        return destination;
    }
    writeSpan(left: Word, right: Word, value: Word) {
        this.instructions.push({ operation: 'write-span', left, right, value });
    }
    when(condition: Word, yes: () => void, no?: () => void) {
        const branch = this.instructions.length;
        this.instructions.push({
            operation: 'jump-if-zero',
            left: condition,
            branch: -1,
        });
        yes();
        if (no) {
            const finish = this.instructions.length;
            this.instructions.push({ operation: 'jump', branch: -1 });
            this.instructions[branch].branch = this.instructions.length;
            no();
            this.instructions[finish].branch = this.instructions.length;
        } else this.instructions[branch].branch = this.instructions.length;
    }
    loop(condition: () => Word, body: () => void) {
        const start = this.instructions.length;
        const left = condition();
        const branch = this.instructions.length;
        this.instructions.push({ operation: 'jump-if-zero', left, branch: -1 });
        body();
        this.instructions.push({ operation: 'jump', branch: start });
        this.instructions[branch].branch = this.instructions.length;
    }
    range(limit: Word, body: (index: number) => void) {
        const index = this.copy(0n);
        this.loop(
            () => this.less(index, limit),
            () => {
                body(index);
                this.assign(index, this.add(index, 1n));
            },
        );
    }
    finish(results: Record<string, number>): WordProgram {
        this.instructions.push({ operation: 'halt' });
        return {
            instructions: this.instructions,
            registers: this.registers,
            inputs: this.inputs,
            results,
        };
    }
}

const isEvent = (instruction: Instruction) =>
    instruction.operation === 'half' ||
    instruction.operation === 'read-span' ||
    instruction.operation === 'write-span' ||
    (instruction.operation === 'multiply' && instruction.right === 2n) ||
    (instruction.operation === 'add' && instruction.right === 1n);

export const auditWordProgram = (program: WordProgram) => {
    const { instructions } = program;
    for (const instruction of instructions) {
        if (
            instruction.operation === 'jump' ||
            instruction.operation === 'jump-if-zero'
        )
            assert(
                Number.isInteger(instruction.branch) &&
                    instruction.branch! >= 0 &&
                    instruction.branch! < instructions.length,
                'Invalid branch destination.',
            );
    }
    const memo = new Map<number, number>();
    const active = new Set<number>();
    const longest = (position: number): number => {
        assert(position >= 0 && position < instructions.length);
        const instruction = instructions[position];
        if (isEvent(instruction) || instruction.operation === 'halt') return 1;
        const known = memo.get(position);
        if (known !== undefined) return known;
        assert(!active.has(position), 'An event-free cycle has no finite gap.');
        active.add(position);
        const next =
            instruction.operation === 'jump'
                ? [instruction.branch!]
                : instruction.operation === 'jump-if-zero'
                  ? [position + 1, instruction.branch!]
                  : [position + 1];
        const result = 1 + Math.max(...next.map(longest));
        active.delete(position);
        memo.set(position, result);
        return result;
    };
    return {
        instructions: BigInt(instructions.length),
        registers: BigInt(program.registers),
        maximumEventGap: BigInt(
            Math.max(...instructions.map((_, position) => longest(position))),
        ),
    };
};

export const runWordProgram = (
    program: WordProgram,
    supplied: Record<string, bigint>,
    memory: Uint8Array,
    wordBits: number,
) => {
    assert(Number.isSafeInteger(wordBits) && wordBits > 0);
    const limit = 1n << BigInt(wordBits);
    const registers = Array<bigint>(program.registers).fill(0n);
    const bounded = (value: bigint) => {
        assert(
            value >= 0n && value < limit,
            'Metadata word overflow or negative value.',
        );
        return value;
    };
    for (const [name, register] of Object.entries(program.inputs)) {
        assert(name in supplied);
        registers[register] = bounded(supplied[name]);
    }
    const read = (word: Word | undefined) => {
        assert(word !== undefined);
        if (typeof word === 'bigint') return bounded(word);
        assert(Number.isInteger(word) && word >= 0 && word < registers.length);
        return registers[word];
    };
    let position = 0,
        steps = 0n,
        events = 0n,
        spanBitTraffic = 0n;
    for (;;) {
        assert(position >= 0 && position < program.instructions.length);
        const instruction = program.instructions[position];
        steps++;
        if (isEvent(instruction)) events++;
        const left =
            instruction.left === undefined ? 0n : read(instruction.left);
        const right =
            instruction.right === undefined ? 0n : read(instruction.right);
        let value: bigint | undefined;
        let next = position + 1;
        switch (instruction.operation) {
            case 'copy':
                value = left;
                break;
            case 'add':
                value = left + right;
                break;
            case 'subtract':
                value = left - right;
                break;
            case 'multiply':
                value = left * right;
                break;
            case 'half':
                value = left >> 1n;
                break;
            case 'low':
                value = left & 1n;
                break;
            case 'bit-and':
                value = left & right;
                break;
            case 'shift-right':
                value = right >= BigInt(wordBits) ? 0n : left >> right;
                break;
            case 'equal':
                value = BigInt(left === right);
                break;
            case 'less':
                value = BigInt(left < right);
                break;
            case 'require':
                assert.equal(left, 1n, 'Source recovery requirement failed.');
                break;
            case 'read-span':
            case 'write-span': {
                assert(
                    right > 0n &&
                        right <= BigInt(wordBits) &&
                        left + right <= BigInt(memory.length),
                    'Span exceeds its declared extent.',
                );
                spanBitTraffic += right;
                if (instruction.operation === 'read-span') {
                    value = 0n;
                    for (let bit = 0n; bit < right; bit++) {
                        const digit = memory[Number(left + bit)];
                        assert(digit <= 1);
                        value |= BigInt(digit) << bit;
                    }
                } else {
                    const output = read(instruction.value);
                    assert(output < 1n << right, 'Span write would truncate.');
                    for (let bit = 0n; bit < right; bit++)
                        memory[Number(left + bit)] = Number(
                            (output >> bit) & 1n,
                        );
                }
                break;
            }
            case 'jump-if-zero':
                if (left === 0n) next = instruction.branch!;
                break;
            case 'jump':
                next = instruction.branch!;
                break;
            case 'halt':
                return {
                    steps,
                    events,
                    spanBitTraffic,
                    results: Object.fromEntries(
                        Object.entries(program.results).map(
                            ([name, register]) => [name, registers[register]],
                        ),
                    ),
                };
        }
        if (value !== undefined) {
            assert(
                instruction.destination !== undefined &&
                    instruction.destination >= 0 &&
                    instruction.destination < registers.length,
            );
            registers[instruction.destination] = bounded(value);
        }
        position = next;
    }
};
