import type { CanonicalError, CanonicalErrorCode } from '@sealed-lattice/types';

import type {
    KernelFailureResponse,
    KernelSuccessResponse,
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
} from './kernel-contracts.js';
import {
    bytesToHex,
    canonicalErrorCodes,
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

const wasmPageByteLength = 65_536;

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

type TranscriptCoreKernelCommandRuntimeEvidence = Readonly<{
    readonly commandWallTimeMilliseconds: string;
    readonly requestByteLength: number;
    readonly responseByteLength: number;
    readonly jsWasmCopyCount: number;
    readonly largestJsWasmCopiedBufferBytes: number;
    readonly wasmMemoryByteLengthBefore: number;
    readonly wasmMemoryByteLengthAfter: number;
    readonly wasmMemoryByteLengthPeak: number;
    readonly measurementBoundary: string;
}>;

type TranscriptCoreKernelMeasuredCommandResult<T> = Readonly<{
    readonly value: T;
    readonly runtimeEvidence: TranscriptCoreKernelCommandRuntimeEvidence;
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

export class TranscriptCoreKernelCommandError extends Error {
    readonly code: CanonicalErrorCode;

    constructor(error: CanonicalError) {
        super(`${error.code}: ${error.message}`);
        this.name = 'TranscriptCoreKernelCommandError';
        this.code = error.code;
    }
}

const toArrayBuffer = (bytes: Uint8Array): ArrayBuffer =>
    Uint8Array.from(bytes).buffer;

const readWasmFile = async (fileUrl: URL): Promise<ArrayBuffer> => {
    const [{ readFile }, { fileURLToPath }] = await Promise.all([
        import('node:fs/promises'),
        import('node:url'),
    ]);
    const bytes = await readFile(fileURLToPath(fileUrl));

    return toArrayBuffer(bytes);
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

    return memory;
};

const resolveNumberExport = (
    exports: TranscriptCoreKernelExports,
    exportName:
        | 'sealed_lattice_allocate'
        | 'sealed_lattice_deallocate'
        | 'sealed_lattice_transcript_core_command_with_length'
        | 'sealed_lattice_roundtrip',
): ((...values: number[]) => number | void) => {
    const exportValue = exports[exportName];
    /* v8 ignore next 3 */
    if (typeof exportValue !== 'function') {
        throw new Error(
            `The transcript-core kernel did not expose ${exportName}.`,
        );
    }

    return exportValue;
};

const copyIntoKernelMemory = (
    memory: WebAssembly.Memory,
    allocate: (length: number) => number,
    input: Uint8Array,
): number => {
    if (input.length === 0) {
        return 0;
    }

    const pointer = allocate(input.length) >>> 0;
    if (pointer === 0) {
        throw new Error(
            'The transcript-core kernel returned a null pointer for a non-empty allocation.',
        );
    }

    const requiredByteLength = pointer + input.length;
    if (requiredByteLength > memory.buffer.byteLength) {
        const missingByteLength = requiredByteLength - memory.buffer.byteLength;
        const missingPageCount = Math.ceil(
            missingByteLength / wasmPageByteLength,
        );
        memory.grow(missingPageCount);
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
    if (length === 0) {
        return new Uint8Array();
    }
    const unsignedPointer = pointer >>> 0;
    if (unsignedPointer === 0) {
        throw new Error(
            `The transcript-core kernel returned a null pointer for a non-empty ${operationName} result.`,
        );
    }

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
    new DataView(memory.buffer, pointer >>> 0, wasm32UsizeByteLength).getUint32(
        0,
        true,
    );

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

const currentMilliseconds = (): number => {
    const performance = globalThis.performance;

    return typeof performance?.now === 'function'
        ? performance.now()
        : Date.now();
};

const runMeasuredKernelCommand = <T>(
    memory: WebAssembly.Memory,
    allocate: (length: number) => number,
    deallocate: (pointer: number, length: number) => void,
    commandWithLength: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
    ) => number,
    request: TranscriptCoreKernelCommand,
): TranscriptCoreKernelMeasuredCommandResult<T> => {
    const requestBytes = textEncoder.encode(JSON.stringify(request));
    const wasmMemoryByteLengthBefore = memory.buffer.byteLength;
    const startedMilliseconds = currentMilliseconds();
    let inputPointer = 0;
    let outputPointer = 0;
    let outputLengthPointer = 0;
    let outputLength = 0;

    try {
        inputPointer = copyIntoKernelMemory(memory, allocate, requestBytes);
        outputLengthPointer = allocate(wasm32UsizeByteLength) >>> 0;
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
        outputLength = readKernelOutputLength(memory, outputLengthPointer);
        const outputBytes = copyFromKernelMemory(
            memory,
            outputPointer,
            outputLength,
            'transcript-core command',
        );

        const finishedMilliseconds = currentMilliseconds();
        const commandWallTimeMilliseconds = Math.max(
            0,
            finishedMilliseconds - startedMilliseconds,
        );
        const responseByteLength = outputBytes.length;

        return {
            value: parseKernelResponse<T>(outputBytes),
            runtimeEvidence: {
                commandWallTimeMilliseconds:
                    commandWallTimeMilliseconds.toFixed(3),
                requestByteLength: requestBytes.length,
                responseByteLength,
                jsWasmCopyCount:
                    (requestBytes.length > 0 ? 1 : 0) +
                    (responseByteLength > 0 ? 1 : 0),
                largestJsWasmCopiedBufferBytes: Math.max(
                    requestBytes.length,
                    responseByteLength,
                ),
                wasmMemoryByteLengthBefore,
                wasmMemoryByteLengthAfter: memory.buffer.byteLength,
                wasmMemoryByteLengthPeak: memory.buffer.byteLength,
                measurementBoundary:
                    'Measured by the JavaScript WASM loader around one synchronous transcript-core command. It covers request copy into linear memory, kernel execution, response copy out of linear memory, JSON parse, and the peak linear-memory length after the command; WASM internal prove/verify phase timing remains unavailable on wasm32-unknown-unknown.',
            },
        };
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
): T =>
    runMeasuredKernelCommand<T>(
        memory,
        allocate,
        deallocate,
        commandWithLength,
        request,
    ).value;

export {
    verifyKernelIntegrity,
    requireKernelIntegrityExpectation,
    resolveKernelBytes,
    resolveMemory,
    resolveNumberExport,
    copyIntoKernelMemory,
    copyFromKernelMemory,
    runMeasuredKernelCommand,
    runKernelCommand,
};
