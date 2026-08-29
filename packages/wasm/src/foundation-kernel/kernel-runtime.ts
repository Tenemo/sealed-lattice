import {
    maximumFoundationCopiedBufferByteLength,
    maximumFoundationWasmMemoryByteLength,
} from '../foundation-contract.js';

type FoundationKernelExports = WebAssembly.Exports & {
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
    readonly readFile: (fileUrl: URL) => Promise<Uint8Array>;
};

const wasmPageByteLength = 65_536;
const wasm32UsizeByteLength = 4;
const maximumCopiedBufferByteLength = maximumFoundationCopiedBufferByteLength;
const maximumFoundationKernelMemoryByteLength =
    maximumFoundationWasmMemoryByteLength;
const nodeFileSystemPromisesModuleSpecifier = 'node:fs/promises';
const sha256HexPattern = /^[a-f0-9]{64}$/u;
const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const sha256Hex = async (bytes: Uint8Array): Promise<string> => {
    const subtleCrypto = globalThis.crypto?.subtle;
    /* v8 ignore next 5 */
    if (subtleCrypto === undefined) {
        throw new Error(
            'The foundation kernel loader requires Web Crypto SHA-256 support.',
        );
    }

    const hashInput = Uint8Array.from(bytes);
    return bytesToHex(
        new Uint8Array(await subtleCrypto.digest('SHA-256', hashInput.buffer)),
    );
};

const verifyKernelIntegrity = async (
    bytes: ArrayBuffer,
    expectedSha256Hex: string,
): Promise<void> => {
    if (!sha256HexPattern.test(expectedSha256Hex)) {
        throw new Error(
            `The foundation kernel expected integrity hash is invalid: ${expectedSha256Hex}.`,
        );
    }

    const actualSha256Hex = await sha256Hex(new Uint8Array(bytes));
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

const readWasmFile = async (fileUrl: URL): Promise<ArrayBuffer> => {
    const fileSystem = (await import(
        /* @vite-ignore */ nodeFileSystemPromisesModuleSpecifier
    )) as NodeFileSystemPromises;
    return Uint8Array.from(await fileSystem.readFile(fileUrl)).buffer;
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
    return response.arrayBuffer();
    /* v8 ignore stop */
};

const assertKernelMemoryWithinProfile = (
    memory: WebAssembly.Memory,
    maximumByteLength: number = maximumFoundationKernelMemoryByteLength,
): void => {
    if (
        !Number.isSafeInteger(maximumByteLength) ||
        maximumByteLength < wasmPageByteLength ||
        maximumByteLength % wasmPageByteLength !== 0
    ) {
        throw new RangeError(
            'The foundation kernel memory limit must be a positive whole number of WASM pages.',
        );
    }
    if (memory.buffer.byteLength > maximumByteLength) {
        throw new RangeError(
            'The foundation kernel exceeded the absolute linear-memory safety bound.',
        );
    }
};

const resolveMemory = (
    exports: FoundationKernelExports,
): WebAssembly.Memory => {
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
        endOffset > memory.buffer.byteLength ||
        endOffset > maximumFoundationKernelMemoryByteLength
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
    exports: FoundationKernelExports,
    exportName: ExportName,
): NonNullable<FoundationKernelExports[ExportName]> => {
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
    assertKernelMemoryWithinProfile(memory);
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
        if (requiredByteLength > maximumFoundationKernelMemoryByteLength) {
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
    if (request.byteLength > maximumCopiedBufferByteLength) {
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
        assertKernelMemoryWithinProfile(memory);
        outputLength = readKernelOutputLength(memory, outputLengthPointer);
        if (outputLength > maximumCopiedBufferByteLength) {
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
        if (inputPointer !== 0 && inputPointer !== outputPointer) {
            deallocate(inputPointer, request.byteLength);
        }
        if (
            outputLengthPointer !== 0 &&
            outputLengthPointer !== inputPointer &&
            outputLengthPointer !== outputPointer
        ) {
            deallocate(outputLengthPointer, wasm32UsizeByteLength);
        }
    }
};

export const instantiateFoundationKernelCommandRuntime = async (
    foundationKernelUrl: URL,
    options: FoundationKernelLoaderOptions = {},
): Promise<FoundationKernelCommandRuntime> => {
    const expectedKernelSha256Hex = requireKernelIntegrityExpectation(options);
    const bytes = await resolveKernelBytes(foundationKernelUrl);
    if (expectedKernelSha256Hex !== undefined) {
        await verifyKernelIntegrity(bytes, expectedKernelSha256Hex);
    }
    const instantiatedSource = await WebAssembly.instantiate(bytes);
    const wasmExports = instantiatedSource.instance
        .exports as FoundationKernelExports;
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
    let commandInProgress = false;

    return {
        executeCommand: (request): Uint8Array => {
            if (commandInProgress) {
                throw new Error(
                    'The foundation kernel cannot run overlapping commands on one instance.',
                );
            }
            commandInProgress = true;
            try {
                return runKernelCommand(
                    memory,
                    allocate,
                    deallocate,
                    commandWithLength,
                    request,
                );
            } finally {
                commandInProgress = false;
            }
        },
    };
};
