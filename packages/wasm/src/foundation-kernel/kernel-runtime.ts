import {
    foundationProfile,
    type CanonicalError,
    type CanonicalErrorCode,
} from '../foundation-contract.js';

import type {
    KernelFailureResponse,
    KernelSuccessResponse,
    FoundationKernelCommand,
    FoundationKernelExports,
} from './kernel-contracts.js';
import {
    bytesToHex,
    sha256HexPattern,
    textDecoder,
    textEncoder,
    wasm32UsizeByteLength,
} from './kernel-contracts.js';
import { canonicalErrorCodes } from './kernel-errors.js';

export class FoundationKernelCommandError extends Error {
    readonly code: CanonicalErrorCode;

    constructor(error: CanonicalError) {
        super(`${error.code}: ${error.message}`);
        this.name = 'FoundationKernelCommandError';
        this.code = error.code;
    }
}

const wasmPageByteLength = 65_536;
const maximumFoundationCommandByteLength = 64 * 1024 * 1024;
const maximumFoundationCommandResponseByteLength = 256 * 1024 * 1024;
const maximumFoundationCommandJsonContainerDepth = 64;
const maximumFoundationKernelMemoryByteLength =
    foundationProfile.maximumWasmMemoryByteLength;

const commandBoundaryError = (
    code: CanonicalErrorCode,
    message: string,
): FoundationKernelCommandError =>
    new FoundationKernelCommandError({ code, message });

const jsonStringByteLength = (value: string): number => {
    let byteLength = 2;
    for (let index = 0; index < value.length; index += 1) {
        const codeUnit = value.charCodeAt(index);
        if (codeUnit === 0x22 || codeUnit === 0x5c) {
            byteLength += 2;
        } else if (codeUnit <= 0x1f) {
            byteLength += [0x08, 0x09, 0x0a, 0x0c, 0x0d].includes(codeUnit)
                ? 2
                : 6;
        } else if (codeUnit <= 0x7f) {
            byteLength += 1;
        } else if (codeUnit <= 0x7ff) {
            byteLength += 2;
        } else if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
            const followingCodeUnit = value.charCodeAt(index + 1);
            if (followingCodeUnit >= 0xdc00 && followingCodeUnit <= 0xdfff) {
                byteLength += 4;
                index += 1;
            } else {
                byteLength += 6;
            }
        } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
            byteLength += 6;
        } else {
            byteLength += 3;
        }
    }

    return byteLength;
};

const serializeBoundedKernelCommandRequest = (
    request: unknown,
    maximumByteLength = maximumFoundationCommandByteLength,
): Uint8Array => {
    if (!Number.isSafeInteger(maximumByteLength) || maximumByteLength < 0) {
        throw new RangeError(
            'The foundation command byte limit must be a non-negative safe integer.',
        );
    }
    if (
        typeof request !== 'object' ||
        request === null ||
        Array.isArray(request)
    ) {
        throw commandBoundaryError(
            'InvalidProtocolObject',
            'The foundation command must be a JSON object.',
        );
    }

    let measuredByteLength = 0;
    const activeContainers = new WeakSet<object>();
    const charge = (additionalByteLength: number): void => {
        if (additionalByteLength > maximumByteLength - measuredByteLength) {
            throw commandBoundaryError(
                'MalformedLength',
                'The foundation command exceeds the accepted byte length.',
            );
        }
        measuredByteLength += additionalByteLength;
    };
    const omittedObjectValue = Symbol('omitted-object-value');
    const serializeValue = (
        value: unknown,
        arrayElement: boolean,
        containerDepth: number,
    ): string | typeof omittedObjectValue => {
        if (value === null) {
            charge(4);
            return 'null';
        }

        switch (typeof value) {
            case 'string': {
                charge(jsonStringByteLength(value));
                return JSON.stringify(value);
            }
            case 'boolean':
                charge(value ? 4 : 5);
                return value ? 'true' : 'false';
            case 'number': {
                if (!Number.isFinite(value)) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The foundation command contains a non-finite number.',
                    );
                }
                if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The foundation command contains an integer outside the interoperable safe range.',
                    );
                }
                const serializedNumber = String(
                    Object.is(value, -0) ? 0 : value,
                );
                charge(serializedNumber.length);
                return serializedNumber;
            }
            case 'undefined':
            case 'function':
            case 'symbol':
                if (arrayElement) {
                    charge(4);
                    return 'null';
                }
                return omittedObjectValue;
            case 'bigint':
                throw commandBoundaryError(
                    'InvalidProtocolObject',
                    'The foundation command cannot contain a bigint.',
                );
            case 'object':
                break;
            default:
                return omittedObjectValue;
        }

        const container = value;
        if (containerDepth >= maximumFoundationCommandJsonContainerDepth) {
            throw commandBoundaryError(
                'MalformedLength',
                'The foundation command exceeds the accepted JSON nesting depth.',
            );
        }
        if (activeContainers.has(container)) {
            throw commandBoundaryError(
                'InvalidProtocolObject',
                'The foundation command contains a cyclic value.',
            );
        }
        activeContainers.add(container);
        try {
            const toJsonDescriptor = Object.getOwnPropertyDescriptor(
                container,
                'toJSON',
            );
            if (
                toJsonDescriptor !== undefined &&
                ('get' in toJsonDescriptor ||
                    'set' in toJsonDescriptor ||
                    ('value' in toJsonDescriptor &&
                        typeof toJsonDescriptor.value === 'function'))
            ) {
                throw commandBoundaryError(
                    'InvalidProtocolObject',
                    'The foundation command cannot contain custom JSON serialization.',
                );
            }

            if (Array.isArray(container)) {
                const prototype = Reflect.getPrototypeOf(container);
                if (prototype !== Array.prototype && prototype !== null) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The foundation command must contain only plain objects and arrays.',
                    );
                }
                const lengthDescriptor = Object.getOwnPropertyDescriptor(
                    container,
                    'length',
                );
                if (
                    lengthDescriptor === undefined ||
                    !('value' in lengthDescriptor) ||
                    !Number.isSafeInteger(lengthDescriptor.value) ||
                    lengthDescriptor.value < 0
                ) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The foundation command contains an invalid array length.',
                    );
                }
                const arrayLength = lengthDescriptor.value as number;
                charge(2 + Math.max(0, arrayLength - 1));
                const serializedItems: string[] = [];
                for (let index = 0; index < arrayLength; index += 1) {
                    const descriptor = Object.getOwnPropertyDescriptor(
                        container,
                        String(index),
                    );
                    if (descriptor === undefined) {
                        charge(4);
                        serializedItems.push('null');
                    } else if ('get' in descriptor || 'set' in descriptor) {
                        throw commandBoundaryError(
                            'InvalidProtocolObject',
                            'The foundation command cannot contain accessor properties.',
                        );
                    } else {
                        const serializedItem = serializeValue(
                            descriptor.value,
                            true,
                            containerDepth + 1,
                        );
                        if (serializedItem === omittedObjectValue) {
                            throw new Error(
                                'Array-element JSON serialization unexpectedly omitted a value.',
                            );
                        }
                        serializedItems.push(serializedItem);
                    }
                }
                return `[${serializedItems.join(',')}]`;
            }

            const prototype = Reflect.getPrototypeOf(container);
            if (prototype !== Object.prototype && prototype !== null) {
                throw commandBoundaryError(
                    'InvalidProtocolObject',
                    'The foundation command must contain only plain objects and arrays.',
                );
            }

            const descriptors = Object.getOwnPropertyDescriptors(container);
            const serializedEntries: string[] = [];
            for (const [fieldName, descriptor] of Object.entries(descriptors)) {
                if (descriptor.enumerable !== true) {
                    continue;
                }
                if ('get' in descriptor || 'set' in descriptor) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The foundation command cannot contain accessor properties.',
                    );
                }
                const serializedValue = serializeValue(
                    descriptor.value,
                    false,
                    containerDepth + 1,
                );
                if (serializedValue === omittedObjectValue) {
                    continue;
                }
                charge(jsonStringByteLength(fieldName) + 1);
                serializedEntries.push(
                    `${JSON.stringify(fieldName)}:${serializedValue}`,
                );
            }
            charge(2 + Math.max(0, serializedEntries.length - 1));
            return `{${serializedEntries.join(',')}}`;
        } finally {
            activeContainers.delete(container);
        }
    };

    const serializedRequest = serializeValue(request, false, 0);
    if (serializedRequest === omittedObjectValue) {
        throw commandBoundaryError(
            'InvalidProtocolObject',
            'The foundation command is not a JSON object.',
        );
    }
    const requestBytes = textEncoder.encode(serializedRequest);
    if (requestBytes.byteLength > maximumByteLength) {
        throw commandBoundaryError(
            'MalformedLength',
            'The foundation command exceeds the accepted byte length.',
        );
    }
    return requestBytes;
};

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
    readonly allocate: (length: number) => number;
    readonly deallocate: (pointer: number, length: number) => void;
    readonly executeCommand: <Result>(
        request: FoundationKernelCommand,
    ) => Result;
    readonly memory: WebAssembly.Memory;
    readonly runExclusive: <Result>(
        operationName: string,
        operation: () => Result,
    ) => Result;
    readonly wasmExports: FoundationKernelExports;
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
    const { readNodeFileAsArrayBuffer } =
        await import('./kernel-node-file-loader.js');

    return readNodeFileAsArrayBuffer(fileUrl);
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const isCanonicalErrorCode = (value: unknown): value is CanonicalErrorCode =>
    typeof value === 'string' &&
    canonicalErrorCodes.has(value as CanonicalErrorCode);

const isCanonicalError = (value: unknown): value is CanonicalError =>
    isRecord(value) &&
    isCanonicalErrorCode(value.code) &&
    typeof value.message === 'string';

const isKernelFailureResponse = (
    value: unknown,
): value is KernelFailureResponse =>
    isRecord(value) && value.success === false && isCanonicalError(value.error);

const isKernelSuccessResponse = <T>(
    value: unknown,
): value is KernelSuccessResponse<T> =>
    isRecord(value) && value.success === true && 'value' in value;

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
        throw commandBoundaryError(
            'MalformedLength',
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
    releaseAfterCopyFailure: (pointer: number, length: number) => void,
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
            throw commandBoundaryError(
                'MalformedLength',
                'The foundation command allocation exceeds the absolute linear-memory safety bound.',
            );
        }
        if (requiredByteLength > memory.buffer.byteLength) {
            const missingByteLength =
                requiredByteLength - memory.buffer.byteLength;
            const missingPageCount = Math.ceil(
                missingByteLength / wasmPageByteLength,
            );
            memory.grow(missingPageCount);
            assertKernelMemoryWithinProfile(memory);
        }
        new Uint8Array(memory.buffer).set(input, pointer);

        return pointer;
    } catch (error) {
        if (pointer !== 0) {
            releaseAfterCopyFailure(pointer, input.length);
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
    assertKernelMemoryWithinProfile(memory);
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

// The kernel writes the response byte length as a little-endian u32 into this
// caller-allocated 4-byte cell (separate from the returned data pointer); read it back.
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

const parseKernelResponse = <T>(bytes: Uint8Array): T => {
    const decodedResponse = JSON.parse(textDecoder.decode(bytes)) as unknown;

    if (isKernelFailureResponse(decodedResponse)) {
        throw new FoundationKernelCommandError(decodedResponse.error);
    }
    if (isKernelSuccessResponse<T>(decodedResponse)) {
        return decodedResponse.value;
    }

    throw new Error(
        'The foundation kernel returned an invalid command response.',
    );
};

const runKernelCommand = <T>(
    memory: WebAssembly.Memory,
    allocate: (length: number) => number,
    deallocate: (pointer: number, length: number) => void,
    commandWithLength: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number,
    request: FoundationKernelCommand,
): T => {
    const requestBytes = serializeBoundedKernelCommandRequest(request);
    let inputPointer = 0;
    let outputPointer = 0;
    let outputLengthPointer = 0;
    let outputLength = 0;

    try {
        inputPointer = copyIntoKernelMemory(
            memory,
            allocate,
            deallocate,
            requestBytes,
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
                requestBytes.length,
                outputLengthPointer,
            ) >>> 0;
        assertKernelMemoryWithinProfile(memory);
        outputLength = readKernelOutputLength(memory, outputLengthPointer);
        if (outputLength > maximumFoundationCommandResponseByteLength) {
            throw commandBoundaryError(
                'MalformedLength',
                'The foundation command response exceeds the accepted byte length.',
            );
        }
        const outputBytes = copyFromKernelMemory(
            memory,
            outputPointer,
            outputLength,
            'foundation command',
        );

        return parseKernelResponse<T>(outputBytes);
    } finally {
        // The kernel may alias the input buffer as the output or otherwise reuse
        // pointers, so each distinct region is freed exactly once: the equality
        // guards below skip a dealloc whose pointer coincides with an already-freed
        // region, preventing a double free.
        if (outputPointer !== 0) {
            deallocate(outputPointer, outputLength);
        }
        if (inputPointer !== 0 && inputPointer !== outputPointer) {
            deallocate(inputPointer, requestBytes.length);
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
    let kernelOperationInProgress = false;
    const runExclusive = <Result>(
        operationName: string,
        operation: () => Result,
    ): Result => {
        if (kernelOperationInProgress) {
            throw new Error(
                `The foundation kernel cannot run overlapping ${operationName} operations on one instance.`,
            );
        }
        kernelOperationInProgress = true;
        try {
            return operation();
        } finally {
            kernelOperationInProgress = false;
        }
    };
    const executeCommand = <Result>(request: FoundationKernelCommand): Result =>
        runExclusive('command', () =>
            runKernelCommand<Result>(
                memory,
                allocate,
                deallocate,
                commandWithLength,
                request,
            ),
        );
    return {
        allocate,
        deallocate,
        executeCommand,
        memory,
        runExclusive,
        wasmExports,
    };
};
