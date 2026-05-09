import type {
    CanonicalError,
    CanonicalErrorCode,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from './types.js';

type TranscriptCoreKernelCommand = {
    readonly command: 'VerifyFixture';
    readonly fixture: TranscriptCoreFixture;
};

type TranscriptCoreKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
    sealed_lattice_last_output_length?: () => number;
    sealed_lattice_transcript_core_command?: (
        pointer: number,
        length: number,
    ) => number;
};

type KernelSuccessResponse<T> = {
    readonly success: true;
    readonly value: T;
};

type KernelFailureResponse = {
    readonly success: false;
    readonly error: CanonicalError;
};

type TranscriptCoreKernel = {
    verifyFixture(
        fixture: TranscriptCoreFixture,
    ): TranscriptCoreFixtureVerification;
};

const canonicalErrorCodes = new Set<string>([
    'DuplicateField',
    'FieldOrder',
    'FixtureMismatch',
    'InvalidChunkSize',
    'InvalidEnum',
    'InvalidFixture',
    'InvalidHex',
    'InvalidUtf8',
    'MalformedLength',
    'MalformedMagic',
    'MalformedVarUint',
    'MissingField',
    'NonCanonicalVarUint',
    'ProofProfileMismatch',
    'TrailingBytes',
    'UnknownField',
    'UnknownProofProfile',
    'UnknownSecurityProfile',
    'UnsupportedEnvelopeVersion',
    'UnsupportedObjectType',
    'UnsupportedObjectVersion',
]);

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

const transcriptCoreKernelUrl = new URL(
    './sealed-lattice-kernel.wasm',
    import.meta.url,
);

class TranscriptCoreKernelCommandError extends Error {
    readonly code: CanonicalErrorCode;

    constructor(error: CanonicalError) {
        super(`${error.code}: ${error.message}`);
        this.name = 'TranscriptCoreKernelCommandError';
        this.code = error.code;
    }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null;

const isCanonicalErrorCode = (value: unknown): value is CanonicalErrorCode =>
    typeof value === 'string' && canonicalErrorCodes.has(value);

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

const resolveKernelBytes = async (): Promise<ArrayBuffer> => {
    /* v8 ignore next */
    if (transcriptCoreKernelUrl.protocol === 'file:') {
        const { readWasmFile } = await import('./node-wasm-file.js');

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
        | 'sealed_lattice_last_output_length'
        | 'sealed_lattice_transcript_core_command',
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

    const pointer = allocate(input.length);
    if (pointer === 0) {
        throw new Error(
            'The transcript-core kernel returned a null pointer for a non-empty allocation.',
        );
    }

    new Uint8Array(memory.buffer).set(input, pointer);

    return pointer;
};

const copyFromKernelMemory = (
    memory: WebAssembly.Memory,
    pointer: number,
    length: number,
): Uint8Array => {
    if (length === 0) {
        return new Uint8Array();
    }
    if (pointer === 0) {
        throw new Error(
            'The transcript-core kernel returned a null pointer for a non-empty transcript-core command result.',
        );
    }

    return Uint8Array.from(new Uint8Array(memory.buffer, pointer, length));
};

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
    command: (pointer: number, length: number) => number,
    lastOutputLength: () => number,
    request: TranscriptCoreKernelCommand,
): T => {
    const requestBytes = textEncoder.encode(JSON.stringify(request));
    let inputPointer = 0;
    let outputPointer = 0;
    let outputLength = 0;

    try {
        inputPointer = copyIntoKernelMemory(memory, allocate, requestBytes);
        outputPointer = command(inputPointer, requestBytes.length);
        outputLength = lastOutputLength();
        const outputBytes = copyFromKernelMemory(
            memory,
            outputPointer,
            outputLength,
        );

        return parseKernelResponse<T>(outputBytes);
    } finally {
        if (outputPointer !== 0) {
            deallocate(outputPointer, outputLength);
        }
        if (inputPointer !== 0 && inputPointer !== outputPointer) {
            deallocate(inputPointer, requestBytes.length);
        }
    }
};

export const loadTranscriptCoreKernel =
    async (): Promise<TranscriptCoreKernel> => {
        const bytes = await resolveKernelBytes();
        const instantiatedSource = await WebAssembly.instantiate(bytes, {});
        const exports = instantiatedSource.instance
            .exports as TranscriptCoreKernelExports;
        const memory = resolveMemory(exports);
        const allocate = resolveNumberExport(
            exports,
            'sealed_lattice_allocate',
        ) as (length: number) => number;
        const deallocate = resolveNumberExport(
            exports,
            'sealed_lattice_deallocate',
        ) as (pointer: number, length: number) => void;
        const lastOutputLength = resolveNumberExport(
            exports,
            'sealed_lattice_last_output_length',
        ) as () => number;
        const transcriptCoreCommand = resolveNumberExport(
            exports,
            'sealed_lattice_transcript_core_command',
        ) as (pointer: number, length: number) => number;
        const executeCommand = <T>(request: TranscriptCoreKernelCommand): T =>
            runKernelCommand<T>(
                memory,
                allocate,
                deallocate,
                transcriptCoreCommand,
                lastOutputLength,
                request,
            );

        return {
            verifyFixture: (fixture): TranscriptCoreFixtureVerification =>
                executeCommand<TranscriptCoreFixtureVerification>({
                    command: 'VerifyFixture',
                    fixture,
                }),
        };
    };
