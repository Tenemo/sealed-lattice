import type {
    CanonicalError,
    CanonicalErrorCode,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

export type TranscriptCoreKernel = {
    readonly exportedFunctionNames: readonly string[];
    analyzeCanonicalObject(input: {
        readonly canonicalBytesHex: string;
        readonly chunkSize: number;
    }): TranscriptCoreAnalysis;
    computeChunkRoot(input: {
        readonly inputHex: string;
        readonly chunkSize: number;
    }): string;
    hashRaw(inputHex: string): string;
    listCanonicalErrorCodes(): readonly string[];
    roundTripBytes(input: Uint8Array): Uint8Array;
    verifyFixture(
        fixture: TranscriptCoreFixture,
    ): TranscriptCoreFixtureVerification;
};

type TranscriptCoreKernelCommand =
    | {
          readonly command: 'AnalyzeCanonicalObject';
          readonly canonicalBytesHex: string;
          readonly chunkSize: number;
      }
    | {
          readonly command: 'ComputeChunkRoot';
          readonly inputHex: string;
          readonly chunkSize: number;
      }
    | {
          readonly command: 'HashRaw';
          readonly inputHex: string;
      }
    | {
          readonly command: 'ListCanonicalErrorCodes';
      }
    | {
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
    sealed_lattice_roundtrip?: (pointer: number, length: number) => number;
};

type KernelSuccessResponse<T> = {
    readonly success: true;
    readonly value: T;
};

type KernelFailureResponse = {
    readonly success: false;
    readonly error: CanonicalError;
};

const bridgeCanonicalErrorCodeValues = [
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
    'ProfileComponentMismatch',
    'TrailingBytes',
    'UnknownBaseClaimProfile',
    'UnknownField',
    'UnknownMheSecurityStage',
    'UnknownProofProfile',
    'UnsupportedCanonicalEnvelopeVersion',
    'UnsupportedObjectType',
    'UnsupportedObjectVersion',
] as const satisfies readonly CanonicalErrorCode[];

export const canonicalErrorCodes: ReadonlySet<CanonicalErrorCode> = new Set(
    bridgeCanonicalErrorCodeValues,
);

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

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
        | 'sealed_lattice_last_output_length'
        | 'sealed_lattice_transcript_core_command'
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
    operationName: string,
): Uint8Array => {
    if (length === 0) {
        return new Uint8Array();
    }
    if (pointer === 0) {
        throw new Error(
            `The transcript-core kernel returned a null pointer for a non-empty ${operationName} result.`,
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
            'transcript-core command',
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

export const createTranscriptCoreKernelLoader = (
    transcriptCoreKernelUrl: URL,
): (() => Promise<TranscriptCoreKernel>) => {
    let kernelPromise: Promise<TranscriptCoreKernel> | undefined;

    return async (): Promise<TranscriptCoreKernel> => {
        kernelPromise ??= (async (): Promise<TranscriptCoreKernel> => {
            const bytes = await resolveKernelBytes(transcriptCoreKernelUrl);
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
            const roundtrip = resolveNumberExport(
                exports,
                'sealed_lattice_roundtrip',
            ) as (pointer: number, length: number) => number;
            const exportedFunctionNames = WebAssembly.Module.exports(
                instantiatedSource.module,
            )
                .map((entry) => entry.name)
                .sort();
            const executeCommand = <T>(
                request: TranscriptCoreKernelCommand,
            ): T =>
                runKernelCommand<T>(
                    memory,
                    allocate,
                    deallocate,
                    transcriptCoreCommand,
                    lastOutputLength,
                    request,
                );

            return {
                exportedFunctionNames,
                analyzeCanonicalObject: (input): TranscriptCoreAnalysis =>
                    executeCommand<TranscriptCoreAnalysis>({
                        command: 'AnalyzeCanonicalObject',
                        canonicalBytesHex: input.canonicalBytesHex,
                        chunkSize: input.chunkSize,
                    }),
                computeChunkRoot: (input): string =>
                    executeCommand<{ readonly chunkRoot: string }>({
                        command: 'ComputeChunkRoot',
                        inputHex: input.inputHex,
                        chunkSize: input.chunkSize,
                    }).chunkRoot,
                hashRaw: (inputHex): string =>
                    executeCommand<{ readonly hash512: string }>({
                        command: 'HashRaw',
                        inputHex,
                    }).hash512,
                listCanonicalErrorCodes: (): readonly string[] =>
                    executeCommand<readonly string[]>({
                        command: 'ListCanonicalErrorCodes',
                    }),
                roundTripBytes: (input: Uint8Array): Uint8Array => {
                    const normalizedInput = Uint8Array.from(input);
                    let inputPointer = 0;
                    let outputPointer = 0;

                    try {
                        inputPointer = copyIntoKernelMemory(
                            memory,
                            allocate,
                            normalizedInput,
                        );
                        outputPointer = roundtrip(
                            inputPointer,
                            normalizedInput.length,
                        );

                        return copyFromKernelMemory(
                            memory,
                            outputPointer,
                            normalizedInput.length,
                            'round-trip',
                        );
                    } finally {
                        if (outputPointer !== 0) {
                            deallocate(outputPointer, normalizedInput.length);
                        }
                        if (
                            inputPointer !== 0 &&
                            inputPointer !== outputPointer
                        ) {
                            deallocate(inputPointer, normalizedInput.length);
                        }
                    }
                },
                verifyFixture: (fixture): TranscriptCoreFixtureVerification =>
                    executeCommand<TranscriptCoreFixtureVerification>({
                        command: 'VerifyFixture',
                        fixture,
                    }),
            };
        })().catch((error: unknown) => {
            kernelPromise = undefined;
            throw error;
        });

        return kernelPromise;
    };
};
