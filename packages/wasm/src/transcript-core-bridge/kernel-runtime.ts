import {
    foundationProfile,
    type CanonicalError,
    type CanonicalErrorCode,
} from '@sealed-lattice/types';

import type {
    KernelFailureResponse,
    KernelSuccessResponse,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
} from './kernel-contracts.js';
import {
    bytesToHex,
    concatenateByteChunks,
    hasWasmHeader,
    normalizeRustSourcePathsForHash,
    readWasmVarUint32,
    sha256HexPattern,
    textDecoder,
    textEncoder,
    wasm32UsizeByteLength,
    wasmCustomSectionId,
    wasmHeaderByteLength,
} from './kernel-contracts.js';
import { canonicalErrorCodes } from './kernel-errors.js';

export class TranscriptCoreKernelCommandError extends Error {
    readonly code: CanonicalErrorCode;

    constructor(error: CanonicalError) {
        super(`${error.code}: ${error.message}`);
        this.name = 'TranscriptCoreKernelCommandError';
        this.code = error.code;
    }
}

const wasmPageByteLength = 65_536;
const maximumTranscriptCoreCommandByteLength = 64 * 1024 * 1024;
const maximumTranscriptCoreCommandResponseByteLength = 256 * 1024 * 1024;
const maximumTranscriptCoreCommandJsonContainerDepth = 64;
const maximumTranscriptCoreKernelMemoryByteLength =
    foundationProfile.maximumWasmMemoryByteLength;

const commandBoundaryError = (
    code: CanonicalErrorCode,
    message: string,
): TranscriptCoreKernelCommandError =>
    new TranscriptCoreKernelCommandError({ code, message });

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
    maximumByteLength = maximumTranscriptCoreCommandByteLength,
): Uint8Array => {
    if (!Number.isSafeInteger(maximumByteLength) || maximumByteLength < 0) {
        throw new RangeError(
            'The transcript-core command byte limit must be a non-negative safe integer.',
        );
    }
    if (
        typeof request !== 'object' ||
        request === null ||
        Array.isArray(request)
    ) {
        throw commandBoundaryError(
            'InvalidProtocolObject',
            'The transcript-core command must be a JSON object.',
        );
    }

    let measuredByteLength = 0;
    const activeContainers = new WeakSet<object>();
    const charge = (additionalByteLength: number): void => {
        if (additionalByteLength > maximumByteLength - measuredByteLength) {
            throw commandBoundaryError(
                'MalformedLength',
                'The transcript-core command exceeds the accepted byte length.',
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
                        'The transcript-core command contains a non-finite number.',
                    );
                }
                if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The transcript-core command contains an integer outside the interoperable safe range.',
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
                    'The transcript-core command cannot contain a bigint.',
                );
            case 'object':
                break;
            default:
                return omittedObjectValue;
        }

        const container = value;
        if (containerDepth >= maximumTranscriptCoreCommandJsonContainerDepth) {
            throw commandBoundaryError(
                'MalformedLength',
                'The transcript-core command exceeds the accepted JSON nesting depth.',
            );
        }
        if (activeContainers.has(container)) {
            throw commandBoundaryError(
                'InvalidProtocolObject',
                'The transcript-core command contains a cyclic value.',
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
                    'The transcript-core command cannot contain custom JSON serialization.',
                );
            }

            if (Array.isArray(container)) {
                const prototype = Reflect.getPrototypeOf(container);
                if (prototype !== Array.prototype && prototype !== null) {
                    throw commandBoundaryError(
                        'InvalidProtocolObject',
                        'The transcript-core command must contain only plain objects and arrays.',
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
                        'The transcript-core command contains an invalid array length.',
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
                            'The transcript-core command cannot contain accessor properties.',
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
                    'The transcript-core command must contain only plain objects and arrays.',
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
                        'The transcript-core command cannot contain accessor properties.',
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
            'The transcript-core command is not a JSON object.',
        );
    }
    const requestBytes = textEncoder.encode(serializedRequest);
    if (requestBytes.byteLength > maximumByteLength) {
        throw commandBoundaryError(
            'MalformedLength',
            'The transcript-core command exceeds the accepted byte length.',
        );
    }
    return requestBytes;
};

// Excludes WASM custom sections (debug / producers / name) from the integrity hash:
// they vary by toolchain but do not affect execution, so dropping them keeps the
// hash reproducible across build environments.
const stripWasmCustomSectionsForHash = (bytes: Uint8Array): Uint8Array => {
    if (!hasWasmHeader(bytes)) {
        return bytes;
    }

    const chunks: Uint8Array[] = [bytes.subarray(0, wasmHeaderByteLength)];
    let totalByteLength = wasmHeaderByteLength;
    let sectionOffset = wasmHeaderByteLength;

    while (sectionOffset < bytes.length) {
        const sectionId = bytes[sectionOffset];
        const sectionSize = readWasmVarUint32(bytes, sectionOffset + 1);
        const sectionPayloadOffset = sectionSize.nextOffset;
        const nextSectionOffset = sectionPayloadOffset + sectionSize.value;
        if (nextSectionOffset > bytes.length) {
            throw new Error(
                'The transcript-core kernel contains a truncated WASM section.',
            );
        }

        if (sectionId !== wasmCustomSectionId) {
            const sectionBytes = bytes.subarray(
                sectionOffset,
                nextSectionOffset,
            );
            chunks.push(sectionBytes);
            totalByteLength += sectionBytes.length;
        }

        sectionOffset = nextSectionOffset;
    }

    return concatenateByteChunks(chunks, totalByteLength);
};

export const normalizeTranscriptCoreKernelBytesForHash = (
    bytes: Uint8Array,
): Uint8Array =>
    stripWasmCustomSectionsForHash(normalizeRustSourcePathsForHash(bytes));

const sha256Hex = async (bytes: Uint8Array): Promise<string> => {
    const subtleCrypto = globalThis.crypto?.subtle;
    /* v8 ignore next 5 */
    if (subtleCrypto === undefined) {
        throw new Error(
            'The transcript-core kernel loader requires Web Crypto SHA-256 support.',
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
            `The transcript-core kernel expected integrity hash is invalid: ${expectedSha256Hex}.`,
        );
    }

    const actualSha256Hex = await sha256Hex(
        normalizeTranscriptCoreKernelBytesForHash(new Uint8Array(bytes)),
    );
    if (actualSha256Hex !== expectedSha256Hex) {
        throw new Error(
            `The transcript-core kernel failed integrity verification: expected ${expectedSha256Hex}, received ${actualSha256Hex}.`,
        );
    }
};

export type TranscriptCoreKernelLoaderOptions = {
    readonly allowUnpinnedKernel?: boolean;
    readonly expectedKernelSha256Hex?: string;
};

export type TranscriptCoreKernelCommandRuntime = Readonly<{
    readonly allocate: (length: number) => number;
    readonly deallocate: (pointer: number, length: number) => void;
    readonly executeCommand: <Result>(
        request: TranscriptCoreKernelCommand,
    ) => Result;
    readonly exportedFunctionNames: readonly string[];
    readonly memory: WebAssembly.Memory;
    readonly runExclusive: <Result>(
        operationName: string,
        operation: () => Result,
    ) => Result;
    readonly wasmExports: TranscriptCoreKernelExports;
}>;

const requireKernelIntegrityExpectation = (
    options: TranscriptCoreKernelLoaderOptions,
): string | undefined => {
    const { expectedKernelSha256Hex } = options;
    if (expectedKernelSha256Hex !== undefined) {
        if (!sha256HexPattern.test(expectedKernelSha256Hex)) {
            throw new Error(
                `The transcript-core kernel expected integrity hash is invalid: ${expectedKernelSha256Hex}.`,
            );
        }

        return expectedKernelSha256Hex;
    }
    if (options.allowUnpinnedKernel === true) {
        return undefined;
    }

    throw new Error(
        'The transcript-core kernel loader requires expectedKernelSha256Hex unless allowUnpinnedKernel is explicitly enabled.',
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
    transcriptCoreKernelUrl: URL,
): Promise<ArrayBuffer> => {
    /* v8 ignore next */
    if (transcriptCoreKernelUrl.protocol === 'file:') {
        return readWasmFile(transcriptCoreKernelUrl);
    }

    /* v8 ignore start */
    const response = await fetch(transcriptCoreKernelUrl);
    if (!response.ok) {
        throw new Error(
            `Failed to fetch the transcript-core kernel from ${transcriptCoreKernelUrl.toString()}.`,
        );
    }

    return response.arrayBuffer();
    /* v8 ignore stop */
};

const assertKernelMemoryWithinProfile = (
    memory: WebAssembly.Memory,
    maximumByteLength: number = maximumTranscriptCoreKernelMemoryByteLength,
): void => {
    if (
        !Number.isSafeInteger(maximumByteLength) ||
        maximumByteLength < wasmPageByteLength ||
        maximumByteLength % wasmPageByteLength !== 0
    ) {
        throw new RangeError(
            'The transcript-core kernel memory limit must be a positive whole number of WASM pages.',
        );
    }
    if (memory.buffer.byteLength > maximumByteLength) {
        throw commandBoundaryError(
            'MalformedLength',
            'The transcript-core kernel exceeded the accepted linear-memory profile.',
        );
    }
};

const resolveMemory = (
    exports: TranscriptCoreKernelExports,
): WebAssembly.Memory => {
    const { memory } = exports;
    /* v8 ignore next 3 */
    if (!(memory instanceof WebAssembly.Memory)) {
        throw new Error(
            'The transcript-core kernel did not expose linear memory.',
        );
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
            `The transcript-core kernel returned an invalid ${operationName} byte length.`,
        );
    }
    const unsignedPointer = pointer >>> 0;
    const endOffset = unsignedPointer + length;
    if (
        (length > 0 && unsignedPointer === 0) ||
        endOffset > memory.buffer.byteLength ||
        endOffset > maximumTranscriptCoreKernelMemoryByteLength
    ) {
        throw new Error(
            `The transcript-core kernel returned an out-of-bounds ${operationName} memory range.`,
        );
    }

    return unsignedPointer;
};

type NumberExportName =
    | 'sealed_lattice_allocate'
    | 'sealed_lattice_accepted_setup_canonical_stream_begin'
    | 'sealed_lattice_accepted_setup_command_with_length'
    | 'sealed_lattice_accepted_setup_session_begin'
    | 'sealed_lattice_accepted_setup_session_cancel'
    | 'sealed_lattice_bgv_canonical_stream_absorb_chunk'
    | 'sealed_lattice_bgv_canonical_stream_begin'
    | 'sealed_lattice_bgv_canonical_stream_cancel'
    | 'sealed_lattice_bgv_canonical_stream_finish'
    | 'sealed_lattice_bgv_canonical_material_reader_begin'
    | 'sealed_lattice_bgv_canonical_material_reader_cancel'
    | 'sealed_lattice_bgv_canonical_material_reader_finish'
    | 'sealed_lattice_bgv_canonical_material_reader_read_chunk'
    | 'sealed_lattice_canonical_stream_absorb_chunk'
    | 'sealed_lattice_canonical_stream_begin_verifier'
    | 'sealed_lattice_canonical_stream_begin_writer'
    | 'sealed_lattice_canonical_stream_cancel'
    | 'sealed_lattice_canonical_stream_finish_verifier'
    | 'sealed_lattice_canonical_stream_finish_writer'
    | 'sealed_lattice_deallocate'
    | 'sealed_lattice_local_storage_root_command'
    | 'sealed_lattice_state_verifier_begin'
    | 'sealed_lattice_state_verifier_cancel'
    | 'sealed_lattice_state_verifier_certify_intent'
    | 'sealed_lattice_state_verifier_describe'
    | 'sealed_lattice_state_verifier_release'
    | 'sealed_lattice_state_verifier_finish_output'
    | 'sealed_lattice_state_verifier_prepare_output'
    | 'sealed_lattice_state_verifier_prepare_recovery'
    | 'sealed_lattice_state_verifier_prepare_reservation'
    | 'sealed_lattice_state_verifier_verify_recovery'
    | 'sealed_lattice_state_verifier_verify_reservation'
    | 'sealed_lattice_transcript_core_command_with_length';

const resolveNumberExport = <ExportName extends NumberExportName>(
    exports: TranscriptCoreKernelExports,
    exportName: ExportName,
): NonNullable<TranscriptCoreKernelExports[ExportName]> => {
    const exportValue = exports[exportName];
    /* v8 ignore next 3 */
    if (typeof exportValue !== 'function') {
        throw new Error(
            `The transcript-core kernel did not expose ${exportName}.`,
        );
    }

    return exportValue;
};

const resolveOptionalNumberExport = <ExportName extends NumberExportName>(
    exports: TranscriptCoreKernelExports,
    exportName: ExportName,
): NonNullable<TranscriptCoreKernelExports[ExportName]> | undefined =>
    typeof exports[exportName] === 'function'
        ? resolveNumberExport(exports, exportName)
        : undefined;

const copyIntoKernelMemory = (
    memory: WebAssembly.Memory,
    allocate: (length: number) => number,
    input: Uint8Array,
): number => {
    assertKernelMemoryWithinProfile(memory);
    if (input.length === 0) {
        return 0;
    }

    const pointer = allocate(input.length) >>> 0;
    assertKernelMemoryWithinProfile(memory);
    if (pointer === 0) {
        throw new Error(
            'The transcript-core kernel returned a null pointer for a non-empty allocation.',
        );
    }

    const requiredByteLength = pointer + input.length;
    if (requiredByteLength > maximumTranscriptCoreKernelMemoryByteLength) {
        throw commandBoundaryError(
            'MalformedLength',
            'The transcript-core command allocation exceeds the accepted linear-memory profile.',
        );
    }
    if (requiredByteLength > memory.buffer.byteLength) {
        const missingByteLength = requiredByteLength - memory.buffer.byteLength;
        const missingPageCount = Math.ceil(
            missingByteLength / wasmPageByteLength,
        );
        memory.grow(missingPageCount);
        assertKernelMemoryWithinProfile(memory);
    }
    new Uint8Array(memory.buffer).set(input, pointer);

    return pointer;
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
        throw new TranscriptCoreKernelCommandError(decodedResponse.error);
    }
    if (isKernelSuccessResponse<T>(decodedResponse)) {
        return decodedResponse.value;
    }

    throw new Error(
        'The transcript-core kernel returned an invalid command response.',
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
    request: TranscriptCoreKernelCommand,
): T => {
    const requestBytes = serializeBoundedKernelCommandRequest(request);
    let inputPointer = 0;
    let outputPointer = 0;
    let outputLengthPointer = 0;
    let outputLength = 0;

    try {
        inputPointer = copyIntoKernelMemory(memory, allocate, requestBytes);
        outputLengthPointer = allocate(wasm32UsizeByteLength) >>> 0;
        assertKernelMemoryWithinProfile(memory);
        if (outputLengthPointer === 0) {
            throw new Error(
                'The transcript-core kernel returned a null pointer for the output-length allocation.',
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
        if (outputLength > maximumTranscriptCoreCommandResponseByteLength) {
            throw commandBoundaryError(
                'MalformedLength',
                'The transcript-core command response exceeds the accepted byte length.',
            );
        }
        const outputBytes = copyFromKernelMemory(
            memory,
            outputPointer,
            outputLength,
            'transcript-core command',
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

export const instantiateTranscriptCoreKernelCommandRuntime = async (
    transcriptCoreKernelUrl: URL,
    options: TranscriptCoreKernelLoaderOptions = {},
): Promise<TranscriptCoreKernelCommandRuntime> => {
    const expectedKernelSha256Hex = requireKernelIntegrityExpectation(options);
    const bytes = await resolveKernelBytes(transcriptCoreKernelUrl);
    if (expectedKernelSha256Hex !== undefined) {
        await verifyKernelIntegrity(bytes, expectedKernelSha256Hex);
    }
    const instantiatedSource = await WebAssembly.instantiate(bytes, {});
    const wasmExports = instantiatedSource.instance
        .exports as TranscriptCoreKernelExports;
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
        'sealed_lattice_transcript_core_command_with_length',
    );
    const exportedFunctionNames = WebAssembly.Module.exports(
        instantiatedSource.module,
    )
        .map((entry) => entry.name)
        .sort();
    let kernelOperationInProgress = false;
    const runExclusive = <Result>(
        operationName: string,
        operation: () => Result,
    ): Result => {
        if (kernelOperationInProgress) {
            throw new Error(
                `The transcript-core kernel cannot run overlapping ${operationName} operations on one instance.`,
            );
        }
        kernelOperationInProgress = true;
        try {
            return operation();
        } finally {
            kernelOperationInProgress = false;
        }
    };
    const executeCommand = <Result>(
        request: TranscriptCoreKernelCommand,
    ): Result =>
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
        exportedFunctionNames,
        memory,
        runExclusive,
        wasmExports,
    };
};

export {
    resolveKernelBytes,
    resolveMemory,
    resolveNumberExport,
    resolveOptionalNumberExport,
    copyIntoKernelMemory,
    copyFromKernelMemory,
    assertKernelMemoryWithinProfile,
    serializeBoundedKernelCommandRequest,
    runKernelCommand,
};
