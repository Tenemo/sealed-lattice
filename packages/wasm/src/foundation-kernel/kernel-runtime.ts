import {
    maximumFoundationCopiedBufferByteLength,
    maximumFoundationWasmMemoryByteLength,
} from '../foundation-contract.js';

type KernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
    sealed_lattice_foundation_command_with_length?: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number;
};
type NodeFileSystemPromises = {
    readonly open: (
        fileUrl: URL,
        flags: 'r',
    ) => Promise<{
        readonly readableWebStream: () => ReadableStream<Uint8Array>;
        readonly close: () => Promise<void>;
    }>;
};

const wasmPageByteLength = 65_536;
const wasm32UsizeByteLength = 4;
const nodeFileSystemPromisesModuleSpecifier = 'node:fs/promises';
const sha256HexPattern = /^[a-f0-9]{64}$/u;
const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const sha256Hex = async (bytes: ArrayBuffer): Promise<string> => {
    const subtleCrypto = globalThis.crypto?.subtle;
    /* v8 ignore next 5 */
    if (subtleCrypto === undefined) {
        throw new Error(
            'The foundation kernel loader requires Web Crypto SHA-256 support.',
        );
    }

    return bytesToHex(
        new Uint8Array(await subtleCrypto.digest('SHA-256', bytes)),
    );
};

const verifyKernelIntegrity = async (
    bytes: ArrayBuffer,
    expectedSha256Hex: string,
): Promise<void> => {
    const actualSha256Hex = await sha256Hex(bytes);
    if (actualSha256Hex !== expectedSha256Hex) {
        throw new Error(
            `The foundation kernel failed integrity verification: expected ${expectedSha256Hex}, received ${actualSha256Hex}.`,
        );
    }
};

export type FoundationKernelLoaderOptions = {
    readonly allowUnpinnedKernel?: boolean;
    readonly expectedKernelSha256Hex?: string;
};

export type FoundationKernelCommandRuntime = Readonly<{
    readonly executeCommand: (request: Uint8Array) => Uint8Array;
    readonly measureResources: () => KernelResourceMeasurement;
}>;

type KernelResourceMeasurement = Readonly<{
    wasmMemoryByteLength: number;
    maximumRequestByteLength: number;
    maximumResponseByteLength: number;
}>;

const requireKernelIntegrityExpectation = (
    options: FoundationKernelLoaderOptions,
): string | undefined => {
    const { expectedKernelSha256Hex } = options;
    if (expectedKernelSha256Hex !== undefined) {
        if (!sha256HexPattern.test(expectedKernelSha256Hex)) {
            throw new Error(
                `The foundation kernel expected integrity hash is invalid: ${expectedKernelSha256Hex}.`,
            );
        }
        return expectedKernelSha256Hex;
    }
    if (options.allowUnpinnedKernel === true) {
        return undefined;
    }
    throw new Error(
        'The foundation kernel loader requires expectedKernelSha256Hex unless allowUnpinnedKernel is explicitly enabled.',
    );
};

const readBoundedKernelStream = async (
    stream: ReadableStream<Uint8Array>,
): Promise<ArrayBuffer> => {
    const reader = stream.getReader();
    let bytes = new Uint8Array(0);
    let length = 0;
    try {
        for (;;) {
            const chunk = await reader.read();
            if (chunk.done) break;
            if (
                chunk.value.byteLength >
                maximumFoundationCopiedBufferByteLength - length
            ) {
                await reader.cancel();
                throw new RangeError(
                    'The foundation kernel exceeds the copied-buffer bound.',
                );
            }
            const required = length + chunk.value.byteLength;
            if (required > bytes.length) {
                const capacity = Math.min(
                    maximumFoundationCopiedBufferByteLength,
                    Math.max(wasmPageByteLength, bytes.length * 2, required),
                );
                const grown = new Uint8Array(capacity);
                grown.set(bytes.subarray(0, length));
                bytes = grown;
            }
            bytes.set(chunk.value, length);
            length = required;
        }
    } finally {
        reader.releaseLock();
    }
    return length === bytes.length
        ? bytes.buffer
        : bytes.buffer.slice(0, length);
};

const readWasmFile = async (fileUrl: URL): Promise<ArrayBuffer> => {
    const fileSystem = (await import(
        /* @vite-ignore */ nodeFileSystemPromisesModuleSpecifier
    )) as NodeFileSystemPromises;
    const file = await fileSystem.open(fileUrl, 'r');
    try {
        return await readBoundedKernelStream(file.readableWebStream());
    } finally {
        await file.close();
    }
};

const resolveKernelBytes = async (
    foundationKernelUrl: URL,
): Promise<ArrayBuffer> => {
    /* v8 ignore next */
    if (foundationKernelUrl.protocol === 'file:') {
        return readWasmFile(foundationKernelUrl);
    }

    /* v8 ignore start */
    const response = await fetch(foundationKernelUrl);
    if (!response.ok) {
        throw new Error(
            `Failed to fetch the foundation kernel from ${foundationKernelUrl.toString()}.`,
        );
    }
    if (response.body === null) {
        throw new Error('The foundation kernel response has no readable body.');
    }
    return readBoundedKernelStream(response.body);
    /* v8 ignore stop */
};

const assertKernelMemoryWithinProfile = (memory: WebAssembly.Memory): void => {
    if (memory.buffer.byteLength > maximumFoundationWasmMemoryByteLength) {
        throw new RangeError(
            'The foundation kernel exceeded the absolute linear-memory safety bound.',
        );
    }
};

const resolveMemory = (exports: KernelExports): WebAssembly.Memory => {
    const { memory } = exports;
    /* v8 ignore next 3 */
    if (!(memory instanceof WebAssembly.Memory)) {
        throw new Error('The foundation kernel did not expose linear memory.');
    }
    assertKernelMemoryWithinProfile(memory);
    return memory;
};

const requireKernelMemoryRange = (
    memory: WebAssembly.Memory,
    pointer: number,
    length: number,
    operationName: string,
): number => {
    assertKernelMemoryWithinProfile(memory);
    if (!Number.isSafeInteger(length) || length < 0) {
        throw new Error(
            `The foundation kernel returned an invalid ${operationName} byte length.`,
        );
    }
    const unsignedPointer = pointer >>> 0;
    const endOffset = unsignedPointer + length;
    if (
        (length > 0 && unsignedPointer === 0) ||
        endOffset > memory.buffer.byteLength
    ) {
        throw new Error(
            `The foundation kernel returned an out-of-bounds ${operationName} memory range.`,
        );
    }
    return unsignedPointer;
};

type NumberExportName =
    | 'sealed_lattice_allocate'
    | 'sealed_lattice_deallocate'
    | 'sealed_lattice_foundation_command_with_length';

const resolveNumberExport = <ExportName extends NumberExportName>(
    exports: KernelExports,
    exportName: ExportName,
): NonNullable<KernelExports[ExportName]> => {
    const exportValue = exports[exportName];
    /* v8 ignore next 3 */
    if (typeof exportValue !== 'function') {
        throw new Error(`The foundation kernel did not expose ${exportName}.`);
    }
    return exportValue;
};

const copyIntoKernelMemory = (
    memory: WebAssembly.Memory,
    allocate: (length: number) => number,
    deallocate: (pointer: number, length: number) => void,
    input: Uint8Array,
): number => {
    if (input.length === 0) {
        return 0;
    }

    const pointer = allocate(input.length) >>> 0;
    try {
        assertKernelMemoryWithinProfile(memory);
        if (pointer === 0) {
            throw new Error(
                'The foundation kernel returned a null pointer for a non-empty allocation.',
            );
        }
        const requiredByteLength = pointer + input.length;
        if (requiredByteLength > maximumFoundationWasmMemoryByteLength) {
            throw new RangeError(
                'The foundation command allocation exceeds the absolute linear-memory safety bound.',
            );
        }
        if (requiredByteLength > memory.buffer.byteLength) {
            memory.grow(
                Math.ceil(
                    (requiredByteLength - memory.buffer.byteLength) /
                        wasmPageByteLength,
                ),
            );
            assertKernelMemoryWithinProfile(memory);
        }
        new Uint8Array(memory.buffer).set(input, pointer);
        return pointer;
    } catch (error) {
        if (pointer !== 0) {
            deallocate(pointer, input.length);
        }
        throw error;
    }
};

const copyFromKernelMemory = (
    memory: WebAssembly.Memory,
    pointer: number,
    length: number,
    operationName: string,
): Uint8Array => {
    if (length === 0) {
        return new Uint8Array();
    }
    const unsignedPointer = requireKernelMemoryRange(
        memory,
        pointer,
        length,
        operationName,
    );
    return Uint8Array.from(
        new Uint8Array(memory.buffer, unsignedPointer, length),
    );
};

const readKernelOutputLength = (
    memory: WebAssembly.Memory,
    pointer: number,
): number =>
    new DataView(
        memory.buffer,
        requireKernelMemoryRange(
            memory,
            pointer,
            wasm32UsizeByteLength,
            'output-length',
        ),
        wasm32UsizeByteLength,
    ).getUint32(0, true);

const runKernelCommand = (
    memory: WebAssembly.Memory,
    allocate: (length: number) => number,
    deallocate: (pointer: number, length: number) => void,
    commandWithLength: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number,
    request: Uint8Array,
): Uint8Array => {
    if (request.byteLength > maximumFoundationCopiedBufferByteLength) {
        throw new RangeError(
            'The foundation command exceeds the copied-buffer limit.',
        );
    }

    let inputPointer = 0;
    let outputPointer = 0;
    let outputLengthPointer = 0;
    let outputLength = 0;
    try {
        inputPointer = copyIntoKernelMemory(
            memory,
            allocate,
            deallocate,
            request,
        );
        outputLengthPointer = allocate(wasm32UsizeByteLength) >>> 0;
        assertKernelMemoryWithinProfile(memory);
        if (outputLengthPointer === 0) {
            throw new Error(
                'The foundation kernel returned a null pointer for the output-length allocation.',
            );
        }
        outputPointer =
            commandWithLength(
                inputPointer,
                request.byteLength,
                outputLengthPointer,
            ) >>> 0;
        outputLength = readKernelOutputLength(memory, outputLengthPointer);
        if (outputLength > maximumFoundationCopiedBufferByteLength) {
            throw new RangeError(
                'The foundation command response exceeds the copied-buffer limit.',
            );
        }
        return copyFromKernelMemory(
            memory,
            outputPointer,
            outputLength,
            'foundation command',
        );
    } finally {
        if (outputPointer !== 0) {
            deallocate(outputPointer, outputLength);
        }
        if (inputPointer !== 0) {
            deallocate(inputPointer, request.byteLength);
        }
        if (outputLengthPointer !== 0) {
            deallocate(outputLengthPointer, wasm32UsizeByteLength);
        }
    }
};

const instantiateKernelCommandRuntime = async (
    foundationKernelUrl: URL,
    options: FoundationKernelLoaderOptions,
): Promise<FoundationKernelCommandRuntime> => {
    const expectedKernelSha256Hex = requireKernelIntegrityExpectation(options);
    const bytes = await resolveKernelBytes(foundationKernelUrl);
    if (expectedKernelSha256Hex !== undefined) {
        await verifyKernelIntegrity(bytes, expectedKernelSha256Hex);
    }
    const instantiatedSource = await WebAssembly.instantiate(bytes);
    const wasmExports = instantiatedSource.instance.exports as KernelExports;
    const memory = resolveMemory(wasmExports);
    const allocate = resolveNumberExport(
        wasmExports,
        'sealed_lattice_allocate',
    );
    const deallocate = resolveNumberExport(
        wasmExports,
        'sealed_lattice_deallocate',
    );
    const commandWithLength = resolveNumberExport(
        wasmExports,
        'sealed_lattice_foundation_command_with_length',
    );
    let maximumRequestByteLength = 0;
    let maximumResponseByteLength = 0;
    return {
        executeCommand: (request): Uint8Array => {
            maximumRequestByteLength = Math.max(
                maximumRequestByteLength,
                request.byteLength,
            );
            const response = runKernelCommand(
                memory,
                allocate,
                deallocate,
                commandWithLength,
                request,
            );
            maximumResponseByteLength = Math.max(
                maximumResponseByteLength,
                response.byteLength,
            );
            return response;
        },
        measureResources: () => ({
            wasmMemoryByteLength: memory.buffer.byteLength,
            maximumRequestByteLength,
            maximumResponseByteLength,
        }),
    };
};

export const instantiateFoundationKernelCommandRuntime = (
    foundationKernelUrl: URL,
    options: FoundationKernelLoaderOptions = {},
): Promise<FoundationKernelCommandRuntime> =>
    instantiateKernelCommandRuntime(foundationKernelUrl, options);
