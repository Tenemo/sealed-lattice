import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { createFoundationCeremonyRuntimeLoader } from '../../src/foundation-ceremony-runtime.js';
import { instantiateFoundationKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';

type SyntheticAllocator = 'bump' | 'past-end' | 'null';

const unsignedLeb128 = (value: number): number[] => {
    const bytes: number[] = [];
    let remaining = value;
    do {
        const byte = remaining & 0x7f;
        remaining >>>= 7;
        bytes.push(remaining === 0 ? byte : byte | 0x80);
    } while (remaining !== 0);
    return bytes;
};

const signedLeb128 = (value: number): number[] => {
    const bytes: number[] = [];
    let remaining = value;
    for (;;) {
        const byte = remaining & 0x7f;
        remaining >>= 7;
        const signBitSet = (byte & 0x40) !== 0;
        if (
            (remaining === 0 && !signBitSet) ||
            (remaining === -1 && signBitSet)
        ) {
            bytes.push(byte);
            return bytes;
        }
        bytes.push(byte | 0x80);
    }
};

const vector = (items: readonly (readonly number[])[]): number[] => [
    ...unsignedLeb128(items.length),
    ...items.flat(),
];
const byteVector = (bytes: Uint8Array): number[] =>
    vector(Array.from(bytes, (byte) => [byte]));
const encodedName = (name: string): number[] =>
    byteVector(new TextEncoder().encode(name));
const section = (identifier: number, contents: readonly number[]): number[] => [
    identifier,
    ...unsignedLeb128(contents.length),
    ...contents,
];
const functionBody = (
    localTypes: readonly number[],
    instructions: readonly number[],
): number[] => {
    const body = [
        ...vector(localTypes.map((localType) => [1, localType])),
        ...instructions,
    ];
    return [...unsignedLeb128(body.length), ...body];
};

const i32 = 0x7f;
const instruction = {
    unreachable: 0x00,
    if: 0x04,
    else: 0x05,
    end: 0x0b,
    localGet: 0x20,
    localSet: 0x21,
    globalGet: 0x23,
    globalSet: 0x24,
    i32Load8Unsigned: 0x2d,
    i32Store: 0x36,
    memorySize: 0x3f,
    i32Const: 0x41,
    i32Equal: 0x46,
    i32Add: 0x6a,
    i32Subtract: 0x6b,
    i32ShiftLeft: 0x74,
} as const;
const emptyBlockType = 0x40;
const heapPointerGlobal = 0;
const deallocationCountGlobal = 1;
const responsePointer = 1024;
const heapStart = 2048;
const trapMarker = 0xff;
const outOfBoundsResponseMarker = 0xfe;

const refusalReason = new TextEncoder().encode('malformedEncoding');
// A successful manifest-verification command carrying one refusal.
const refusalResponse = Uint8Array.from([
    0,
    0,
    refusalReason.length,
    0,
    0,
    0,
    ...refusalReason,
]);

const allocatorInstructions = (allocator: SyntheticAllocator): number[] => {
    switch (allocator) {
        case 'bump':
            return [
                instruction.globalGet,
                heapPointerGlobal,
                instruction.globalGet,
                heapPointerGlobal,
                instruction.localGet,
                0,
                instruction.i32Add,
                instruction.globalSet,
                heapPointerGlobal,
                instruction.end,
            ];
        case 'past-end':
            return [
                instruction.memorySize,
                0,
                instruction.i32Const,
                ...signedLeb128(16),
                instruction.i32ShiftLeft,
                instruction.end,
            ];
        case 'null':
            return [instruction.i32Const, 0, instruction.end];
    }
};

// The command reads the final request byte. A trap marker executes
// unreachable, an out-of-bounds marker reports a response past the memory end,
// and every other request receives the fixed refusal response.
const commandInstructions = [
    instruction.localGet,
    0,
    instruction.localGet,
    1,
    instruction.i32Add,
    instruction.i32Const,
    1,
    instruction.i32Subtract,
    instruction.i32Load8Unsigned,
    0,
    0,
    instruction.localSet,
    3,
    instruction.localGet,
    3,
    instruction.i32Const,
    ...signedLeb128(trapMarker),
    instruction.i32Equal,
    instruction.if,
    emptyBlockType,
    instruction.unreachable,
    instruction.end,
    instruction.localGet,
    2,
    instruction.localGet,
    3,
    instruction.i32Const,
    ...signedLeb128(outOfBoundsResponseMarker),
    instruction.i32Equal,
    instruction.if,
    i32,
    instruction.i32Const,
    ...signedLeb128(65_536),
    instruction.else,
    instruction.i32Const,
    ...signedLeb128(refusalResponse.length),
    instruction.end,
    instruction.i32Store,
    2,
    0,
    instruction.i32Const,
    ...signedLeb128(responsePointer),
    instruction.end,
];

const syntheticKernelUrl = (allocator: SyntheticAllocator): URL => {
    const mutableI32Global = (initialValue: number): number[] => [
        i32,
        1,
        instruction.i32Const,
        ...signedLeb128(initialValue),
        instruction.end,
    ];
    const module = Uint8Array.from([
        ...[0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00],
        ...section(
            1,
            vector([
                [0x60, ...vector([[i32]]), ...vector([[i32]])],
                [0x60, ...vector([[i32], [i32]]), ...vector([])],
                [0x60, ...vector([[i32], [i32], [i32]]), ...vector([[i32]])],
            ]),
        ),
        ...section(3, vector([[0], [1], [2]])),
        ...section(5, vector([[0x00, 1]])),
        ...section(
            6,
            vector([mutableI32Global(heapStart), mutableI32Global(0)]),
        ),
        ...section(
            7,
            vector([
                [...encodedName('memory'), 0x02, 0],
                [...encodedName('sealed_lattice_allocate'), 0x00, 0],
                [...encodedName('sealed_lattice_deallocate'), 0x00, 1],
                [
                    ...encodedName(
                        'sealed_lattice_foundation_command_with_length',
                    ),
                    0x00,
                    2,
                ],
                [...encodedName('heap_pointer'), 0x03, heapPointerGlobal],
                [
                    ...encodedName('deallocation_count'),
                    0x03,
                    deallocationCountGlobal,
                ],
            ]),
        ),
        ...section(
            10,
            vector([
                functionBody([], allocatorInstructions(allocator)),
                functionBody(
                    [],
                    [
                        instruction.globalGet,
                        deallocationCountGlobal,
                        instruction.i32Const,
                        1,
                        instruction.i32Add,
                        instruction.globalSet,
                        deallocationCountGlobal,
                        instruction.end,
                    ],
                ),
                functionBody([i32], commandInstructions),
            ]),
        ),
        ...section(
            11,
            vector([
                [
                    0x00,
                    instruction.i32Const,
                    ...signedLeb128(responsePointer),
                    instruction.end,
                    ...byteVector(refusalResponse),
                ],
            ]),
        ),
    ]);
    return new URL(
        `data:application/wasm;base64,${Buffer.from(module).toString('base64')}`,
    );
};

const request = (...bytes: number[]): Uint8Array => Uint8Array.from(bytes);

const observedInstances: WebAssembly.Instance[] = [];
const instantiateWebAssembly = WebAssembly.instantiate.bind(WebAssembly);
const globalValue = (instance: WebAssembly.Instance, name: string): number =>
    (instance.exports[name] as WebAssembly.Global).value as number;
const onlyInstance = (): WebAssembly.Instance => {
    expect(observedInstances).toHaveLength(1);
    return observedInstances[0];
};

beforeEach(() => {
    vi.spyOn(WebAssembly, 'instantiate').mockImplementation((async (
        bytes: BufferSource,
    ) => {
        const source = await instantiateWebAssembly(bytes);
        observedInstances.push(source.instance);
        return source;
    }) as typeof WebAssembly.instantiate);
});

afterEach(() => {
    vi.restoreAllMocks();
    observedInstances.length = 0;
});

describe('foundation kernel instance faults', () => {
    it('returns kernel responses and releases every allocation after each command', async () => {
        const kernel = await instantiateFoundationKernelCommandRuntime(
            syntheticKernelUrl('bump'),
            { allowUnpinnedKernel: true },
        );
        const instance = onlyInstance();

        expect(kernel.executeCommand(request(1, 2, 3))).toEqual(
            refusalResponse,
        );
        expect(kernel.executeCommand(request(4))).toEqual(refusalResponse);
        expect(globalValue(instance, 'deallocation_count')).toBe(6);
        expect(kernel.isFaulted()).toBe(false);
        expect(kernel.measureResources()).toEqual({
            wasmMemoryByteLength: 65_536,
            maximumRequestByteLength: 3,
            maximumResponseByteLength: refusalResponse.length,
        });
    });

    it('refuses an oversized request before the kernel call without faulting the instance', async () => {
        const kernel = await instantiateFoundationKernelCommandRuntime(
            syntheticKernelUrl('bump'),
            { allowUnpinnedKernel: true },
        );
        const instance = onlyInstance();

        expect(() => kernel.executeCommand(new Uint8Array(8_388_609))).toThrow(
            'exceeds the copied-buffer limit',
        );
        expect(kernel.isFaulted()).toBe(false);
        expect(globalValue(instance, 'heap_pointer')).toBe(heapStart);
        expect(kernel.executeCommand(request(1))).toEqual(refusalResponse);
    });

    it('faults on a trap and never calls into the trapped instance again', async () => {
        const kernel = await instantiateFoundationKernelCommandRuntime(
            syntheticKernelUrl('bump'),
            { allowUnpinnedKernel: true },
        );
        const instance = onlyInstance();
        kernel.executeCommand(request(1));

        expect(() => kernel.executeCommand(request(2, trapMarker))).toThrow(
            WebAssembly.RuntimeError,
        );
        expect(kernel.isFaulted()).toBe(true);
        // The trapped command's input and output-length allocations are
        // abandoned with the instance instead of being deallocated.
        expect(globalValue(instance, 'deallocation_count')).toBe(3);
        const heapPointer = globalValue(instance, 'heap_pointer');

        expect(() => kernel.executeCommand(request(1))).toThrow(
            'faulted and must be replaced',
        );
        expect(globalValue(instance, 'heap_pointer')).toBe(heapPointer);
        expect(globalValue(instance, 'deallocation_count')).toBe(3);
    });

    it('faults when the kernel reports a response past the end of memory', async () => {
        const kernel = await instantiateFoundationKernelCommandRuntime(
            syntheticKernelUrl('bump'),
            { allowUnpinnedKernel: true },
        );

        expect(() =>
            kernel.executeCommand(request(outOfBoundsResponseMarker)),
        ).toThrow('out-of-bounds foundation command memory range');
        expect(kernel.isFaulted()).toBe(true);
        expect(globalValue(onlyInstance(), 'deallocation_count')).toBe(0);
    });

    it.each(['past-end', 'null'] as const)(
        'faults on a %s allocation without growing kernel memory',
        async (allocator) => {
            const kernel = await instantiateFoundationKernelCommandRuntime(
                syntheticKernelUrl(allocator),
                { allowUnpinnedKernel: true },
            );

            expect(() => kernel.executeCommand(request(1, 2))).toThrow(
                'out-of-bounds input allocation memory range',
            );
            expect(kernel.isFaulted()).toBe(true);
            expect(kernel.measureResources().wasmMemoryByteLength).toBe(65_536);
            expect(() => kernel.executeCommand(request(1, 2))).toThrow(
                'faulted and must be replaced',
            );
        },
    );
});

describe('foundation ceremony runtime loader', () => {
    it('reuses a healthy instance and replaces a faulted one', async () => {
        const load = createFoundationCeremonyRuntimeLoader(
            syntheticKernelUrl('bump'),
            { allowUnpinnedKernel: true },
        );
        const refused = { isValid: false, refusalReason: 'malformedEncoding' };
        const first = await load();
        expect(first.verifyManifest(request(1))).toEqual(refused);
        expect(await load()).toBe(first);
        expect(observedInstances).toHaveLength(1);

        expect(() => first.verifyManifest(request(trapMarker))).toThrow(
            WebAssembly.RuntimeError,
        );
        expect(() => first.verifyManifest(request(1))).toThrow(
            'faulted and must be replaced',
        );

        const [second, concurrent] = await Promise.all([load(), load()]);
        expect(second).not.toBe(first);
        expect(concurrent).toBe(second);
        expect(observedInstances).toHaveLength(2);
        expect(second.verifyManifest(request(1))).toEqual(refused);
        expect(await load()).toBe(second);
    });
});
