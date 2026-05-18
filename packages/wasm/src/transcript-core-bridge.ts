import type {
    CanonicalError,
    CanonicalErrorCode,
    FieldElement,
    ProtocolDigest,
    TranscriptCoreAnalysis,
    TranscriptCoreFixture,
    TranscriptCoreFixtureVerification,
} from '@sealed-lattice/types';

export type TranscriptCoreKernelSharePoint = {
    readonly rosterPosition: number;
    readonly value: FieldElement;
};

export type TranscriptCorePlaintextComparison = {
    readonly greaterThan: FieldElement;
    readonly equal: FieldElement;
    readonly scoreDifference: number;
};

export type BallotPrivacyProofBackendStatus = {
    readonly backendName: string;
    readonly backendAvailable: false;
    readonly portableRustWasmPortRequired: true;
    readonly requiredComponents: readonly string[];
    readonly blockedReason: string;
};

export type BallotPrivacyKernelVerification = {
    readonly ok: boolean;
    readonly backendAvailable: false;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly operation: string;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
        readonly objectDigest?: string;
    }[];
    readonly unresolvedReason: string | null;
};

export type BallotPrivacyLinearProofVectorVerification = {
    readonly ok: boolean;
    readonly backendAvailable: false;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
    readonly unresolvedReason: string | null;
    readonly caseName?: string;
    readonly vectorAvailable?: boolean;
    readonly expectedOutcome?: string;
};

export type BallotPrivacyEncodedRelationVectorVerification = {
    readonly ok: boolean;
    readonly backendAvailable: false;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
    readonly unresolvedReason: string | null;
    readonly caseName?: string;
    readonly vectorAvailable?: boolean;
    readonly expectedOutcome?: string;
};

export type BallotPrivacyReceiverKeyVectorVerification = {
    readonly ok: boolean;
    readonly backendAvailable: false;
    readonly backendStatus: BallotPrivacyProofBackendStatus;
    readonly statusLabels: readonly string[];
    readonly acceptedDigests: readonly string[];
    readonly refusedObjects: readonly {
        readonly code: string;
        readonly message: string;
    }[];
    readonly unresolvedReason: string | null;
    readonly caseName?: string;
    readonly vectorAvailable?: boolean;
    readonly expectedOutcome?: string;
};

export type BallotPrivacyReceiverKeyProofGenerationPreparation =
    BallotPrivacyKernelVerification & {
        readonly generatedProofBytes?: false;
        readonly summary?: {
            readonly relationWitnessPolynomialCount: number;
            readonly shortWitnessPolynomialCount: number;
            readonly preparedShortWitnessPolynomialCount: number;
            readonly witnessL2Squared: string;
            readonly witnessL2BoundSquared: string;
            readonly normSlack: string;
            readonly abdlopCommitment?: {
                readonly compressedCommitmentPolynomialCount: number;
                readonly openingRandomnessPolynomialCount: number;
                readonly openingRemainderPolynomialCount: number;
                readonly proverRandomnessSeedBytes: number;
                readonly subprotocolSeedBytes: number;
                readonly abdlopCommitmentHash: string;
            } | null;
        };
    };

export type BallotPrivacyReceiverKeyProofGeneration =
    BallotPrivacyKernelVerification & {
        readonly generatedProofBytes?: true;
        readonly proofBytesHex?: string;
        readonly proofSizeBytes?: number;
        readonly summary?: {
            readonly abdlopCommitmentHash: string;
            readonly z34ChallengeHash: string;
            readonly generatorChallengeHash: string;
            readonly quadraticChallengeHash: string;
        };
    };

export type BallotPrivacyProofGeneration =
    BallotPrivacyReceiverKeyProofGeneration & {
        readonly ballotProof?: unknown;
        readonly componentProofBundle?: unknown;
        readonly componentProofInputs?: readonly unknown[];
        readonly parameterSet?: unknown;
        readonly proofEncoding?: unknown;
        readonly verification?: BallotPrivacyKernelVerification;
    };

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
    deriveProtocolDigest(input: {
        readonly namespace: string;
        readonly value: unknown;
    }): ProtocolDigest;
    evaluatePlaintextComparison(input: {
        readonly leftTotalScore: number;
        readonly rightTotalScore: number;
        readonly rosterSize: number;
    }): TranscriptCorePlaintextComparison;
    hashRaw(inputHex: string): string;
    interpolateShamirConstantTerm(input: {
        readonly sharePoints: readonly TranscriptCoreKernelSharePoint[];
    }): FieldElement;
    listCanonicalErrorCodes(): readonly string[];
    listReservedRootNamespaces(): readonly string[];
    roundTripBytes(input: Uint8Array): Uint8Array;
    verifyFixture(
        fixture: TranscriptCoreFixture,
    ): TranscriptCoreFixtureVerification;
    describeBallotPrivacyProofBackend(): BallotPrivacyProofBackendStatus;
    verifyBallotPrivacyLinearProofVector(input: {
        readonly vectorCase: unknown;
    }): BallotPrivacyLinearProofVectorVerification;
    verifyBallotPrivacyEncodedRelationVector(input: {
        readonly vectorCase: unknown;
    }): BallotPrivacyEncodedRelationVectorVerification;
    verifyBallotPrivacyReceiverKeyVector(input: {
        readonly vectorCase: unknown;
    }): BallotPrivacyReceiverKeyVectorVerification;
    verifyReceiverKeyProof(input: {
        readonly linearStatement?: unknown;
        readonly parameterSet?: unknown;
        readonly proofBytesHex?: string;
        readonly proofEncoding?: unknown;
        readonly publicRandomnessHex?: string;
        readonly receiverKeyProof: unknown;
    }): BallotPrivacyKernelVerification;
    prepareReceiverKeyProofGeneration(input: {
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex: string;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyReceiverKeyProofGenerationPreparation;
    generateReceiverKeyProof(input: {
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex: string;
        readonly secretState: unknown;
        readonly proverRandomnessHex: string;
    }): BallotPrivacyReceiverKeyProofGeneration;
    generateBallotProof(input: {
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex: string;
        readonly secretState: unknown;
        readonly proverRandomnessHex: string;
    }): BallotPrivacyProofGeneration;
    generateBallotComponentProof(input: {
        readonly componentId: string;
        readonly proofInput: unknown;
        readonly secretState: unknown;
        readonly proverRandomnessHex: string;
    }): BallotPrivacyProofGeneration;
    generateBallotProofRecord(input: {
        readonly statement: unknown;
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex: string;
        readonly componentBundleStatement: unknown;
        readonly componentProofInputs: readonly unknown[];
        readonly secretState: unknown;
        readonly proverRandomnessHex: string;
        readonly componentProverRandomnessHexes: Readonly<
            Record<string, string>
        >;
        readonly componentSecretStates?: Readonly<Record<string, unknown>>;
    }): BallotPrivacyProofGeneration;
    verifyBallotProof(input: {
        readonly ballotProof: unknown;
        readonly componentBundleStatement?: unknown;
        readonly componentProofBundle?: unknown;
        readonly componentProofInputs?: readonly unknown[];
        readonly linearStatement?: unknown;
        readonly parameterSet?: unknown;
        readonly proofBytesHex?: string;
        readonly proofEncoding?: unknown;
        readonly publicRandomnessHex?: string;
        readonly statement: unknown;
    }): BallotPrivacyKernelVerification;
    verifyClaimBearingBallotPackage(input: {
        readonly ballotPackage: unknown;
    }): BallotPrivacyKernelVerification;
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
          readonly command: 'DeriveProtocolDigest';
          readonly namespace: string;
          readonly value: unknown;
      }
    | {
          readonly command: 'EvaluatePlaintextComparison';
          readonly leftTotalScore: number;
          readonly rightTotalScore: number;
          readonly rosterSize: number;
      }
    | {
          readonly command: 'HashRaw';
          readonly inputHex: string;
      }
    | {
          readonly command: 'InterpolateShamirConstantTerm';
          readonly sharePoints: readonly TranscriptCoreKernelSharePoint[];
      }
    | {
          readonly command: 'ListCanonicalErrorCodes';
      }
    | {
          readonly command: 'ListReservedRootNamespaces';
      }
    | {
          readonly command: 'VerifyFixture';
          readonly fixture: TranscriptCoreFixture;
      }
    | {
          readonly command: 'DescribeBallotPrivacyProofBackend';
      }
    | {
          readonly command: 'VerifyBallotPrivacyLinearProofVector';
          readonly vectorCase: unknown;
      }
    | {
          readonly command: 'VerifyBallotPrivacyEncodedRelationVector';
          readonly vectorCase: unknown;
      }
    | {
          readonly command: 'VerifyBallotPrivacyReceiverKeyVector';
          readonly vectorCase: unknown;
      }
    | {
          readonly command: 'VerifyReceiverKeyProof';
          readonly linearStatement?: unknown;
          readonly parameterSet?: unknown;
          readonly proofBytesHex?: string;
          readonly proofEncoding?: unknown;
          readonly publicRandomnessHex?: string;
          readonly receiverKeyProof: unknown;
      }
    | {
          readonly command: 'PrepareReceiverKeyProofGeneration';
          readonly linearStatement: unknown;
          readonly parameterSet: unknown;
          readonly proofEncoding: unknown;
          readonly publicRandomnessHex: string;
          readonly secretState: unknown;
          readonly proverRandomnessHex?: string;
      }
    | {
          readonly command: 'GenerateReceiverKeyProof';
          readonly linearStatement: unknown;
          readonly parameterSet: unknown;
          readonly proofEncoding: unknown;
          readonly publicRandomnessHex: string;
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
      }
    | {
          readonly command: 'GenerateBallotProof';
          readonly linearStatement: unknown;
          readonly parameterSet: unknown;
          readonly proofEncoding: unknown;
          readonly publicRandomnessHex: string;
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
      }
    | {
          readonly command: 'GenerateBallotComponentProof';
          readonly componentId: string;
          readonly proofInput: unknown;
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
      }
    | {
          readonly command: 'GenerateBallotProofRecord';
          readonly statement: unknown;
          readonly linearStatement: unknown;
          readonly parameterSet: unknown;
          readonly proofEncoding: unknown;
          readonly publicRandomnessHex: string;
          readonly componentBundleStatement: unknown;
          readonly componentProofInputs: readonly unknown[];
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
          readonly componentProverRandomnessHexes: Readonly<
              Record<string, string>
          >;
          readonly componentSecretStates?: Readonly<Record<string, unknown>>;
      }
    | {
          readonly command: 'VerifyBallotProof';
          readonly ballotProof: unknown;
          readonly componentBundleStatement?: unknown;
          readonly componentProofBundle?: unknown;
          readonly componentProofInputs?: readonly unknown[];
          readonly linearStatement?: unknown;
          readonly parameterSet?: unknown;
          readonly proofBytesHex?: string;
          readonly proofEncoding?: unknown;
          readonly publicRandomnessHex?: string;
          readonly statement: unknown;
      }
    | {
          readonly command: 'VerifyClaimBearingBallotPackage';
          readonly ballotPackage: unknown;
      };

type TranscriptCoreKernelExports = WebAssembly.Exports & {
    memory?: WebAssembly.Memory;
    sealed_lattice_allocate?: (length: number) => number;
    sealed_lattice_deallocate?: (pointer: number, length: number) => void;
    sealed_lattice_transcript_core_command_with_length?: (
        pointer: number,
        length: number,
        outputLengthPointer: number,
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

export type TranscriptCoreKernelBuildRunner =
    | 'githubActionsMacosLatest'
    | 'githubActionsUbuntuLatest'
    | 'windowsDeveloperBuild';

type TranscriptCoreKernelDigestManifest = Readonly<
    Record<TranscriptCoreKernelBuildRunner, string>
>;

// These are reviewed current-kernel build outputs from tools/ci/build-wasm-kernel.ts.
// Add a digest only after confirming the Rust/WASM kernel change is expected.
export const currentTranscriptCoreKernelNormalizedSha256HexByBuildRunner: TranscriptCoreKernelDigestManifest =
    {
        windowsDeveloperBuild:
            'e6555df1fb9ccaa775840092f79e2a60017fe9760bae0b4f1da8e1d235162076',
        githubActionsUbuntuLatest:
            '73691262c72912cb7cf5a9a85644acc39b8b81d7927269c95f52a37eecd11db9',
        githubActionsMacosLatest:
            'fd77c6ac8e8ad766ba5e0262181e2c54dfa5c992752400bc36a64ddc9056451c',
    };
const currentTranscriptCoreKernelNormalizedSha256HexValues = new Set<string>(
    Object.values(currentTranscriptCoreKernelNormalizedSha256HexByBuildRunner),
);

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
    'UnknownMheSecurityClosure',
    'UnknownProofProfile',
    'UnsupportedCanonicalEnvelopeVersion',
    'UnsupportedObjectType',
    'UnsupportedObjectVersion',
] as const satisfies readonly CanonicalErrorCode[];

export const canonicalErrorCodes: ReadonlySet<CanonicalErrorCode> = new Set(
    bridgeCanonicalErrorCodeValues,
);

const wasm32UsizeByteLength = 4;
const wasmHeaderByteLength = 8;
const wasmCustomSectionId = 0;
const textDecoder = new TextDecoder('utf-8', { fatal: true });
const textEncoder = new TextEncoder();

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const isPrintableAscii = (byte: number): boolean =>
    byte >= 0x20 && byte <= 0x7e;

const normalizeRustSourcePathForDigest = (sourcePath: string): string => {
    const forwardSlashSourcePath = sourcePath.replace(/\\/gu, '/');
    const cargoRegistrySourcePath = forwardSlashSourcePath.replace(
        /^(?:[A-Za-z]:)?\/.*?\/\.cargo\/registry\/src\//u,
        '/cargo/registry/src/',
    );

    return cargoRegistrySourcePath.replace(
        /^.*?\/crates\/sealed-lattice-kernel\//u,
        'crates/sealed-lattice-kernel/',
    );
};

const normalizeDigestChunk = (chunk: Uint8Array): Uint8Array => {
    if (chunk.length === 0) {
        return chunk;
    }
    if (!chunk.includes(0x2e)) {
        return chunk;
    }
    for (const byte of chunk) {
        if (!isPrintableAscii(byte)) {
            return chunk;
        }
    }

    const text = textDecoder.decode(chunk);
    if (!text.includes('.rs')) {
        return chunk;
    }

    const normalizedText = normalizeRustSourcePathForDigest(text);
    if (normalizedText === text) {
        return chunk;
    }

    return textEncoder.encode(normalizedText);
};

const normalizeRustSourcePathsForDigest = (bytes: Uint8Array): Uint8Array => {
    const normalizedChunks: Uint8Array[] = [];
    let totalByteLength = 0;
    let chunkStart = 0;

    for (let byteIndex = 0; byteIndex <= bytes.length; byteIndex += 1) {
        if (byteIndex !== bytes.length && bytes[byteIndex] !== 0) {
            continue;
        }

        const normalizedChunk = normalizeDigestChunk(
            bytes.subarray(chunkStart, byteIndex),
        );
        normalizedChunks.push(normalizedChunk);
        totalByteLength += normalizedChunk.length;

        if (byteIndex !== bytes.length) {
            normalizedChunks.push(Uint8Array.of(0));
            totalByteLength += 1;
        }
        chunkStart = byteIndex + 1;
    }

    const normalizedBytes = new Uint8Array(totalByteLength);
    let writeOffset = 0;
    for (const chunk of normalizedChunks) {
        normalizedBytes.set(chunk, writeOffset);
        writeOffset += chunk.length;
    }

    return normalizedBytes;
};

const hasWasmHeader = (bytes: Uint8Array): boolean =>
    bytes.length >= wasmHeaderByteLength &&
    bytes[0] === 0x00 &&
    bytes[1] === 0x61 &&
    bytes[2] === 0x73 &&
    bytes[3] === 0x6d &&
    bytes[4] === 0x01 &&
    bytes[5] === 0x00 &&
    bytes[6] === 0x00 &&
    bytes[7] === 0x00;

const readWasmVarUint32 = (
    bytes: Uint8Array,
    startOffset: number,
): { readonly nextOffset: number; readonly value: number } => {
    let value = 0;
    let multiplier = 1;

    for (
        let byteOffset = startOffset;
        byteOffset < bytes.length;
        byteOffset += 1
    ) {
        const byte = bytes[byteOffset];
        value += (byte & 0x7f) * multiplier;
        if (byte < 0x80) {
            return {
                nextOffset: byteOffset + 1,
                value,
            };
        }
        multiplier *= 0x80;
        if (multiplier > 0x1_0000_0000) {
            throw new Error(
                'The transcript-core kernel contains an invalid WASM section length.',
            );
        }
    }

    throw new Error(
        'The transcript-core kernel contains a truncated WASM section length.',
    );
};

const concatenateByteChunks = (
    chunks: readonly Uint8Array[],
    totalByteLength: number,
): Uint8Array => {
    const output = new Uint8Array(totalByteLength);
    let writeOffset = 0;

    for (const chunk of chunks) {
        output.set(chunk, writeOffset);
        writeOffset += chunk.length;
    }

    return output;
};

const stripWasmCustomSectionsForDigest = (bytes: Uint8Array): Uint8Array => {
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

export const normalizeTranscriptCoreKernelBytesForDigest = (
    bytes: Uint8Array,
): Uint8Array =>
    stripWasmCustomSectionsForDigest(normalizeRustSourcePathsForDigest(bytes));

const hashSha256Hex = async (bytes: Uint8Array): Promise<string> => {
    const subtleCrypto = globalThis.crypto?.subtle;
    /* v8 ignore next 5 */
    if (subtleCrypto === undefined) {
        throw new Error(
            'The transcript-core kernel loader requires Web Crypto SHA-256 support.',
        );
    }

    const digestInput = Uint8Array.from(bytes);

    return bytesToHex(
        new Uint8Array(
            await subtleCrypto.digest('SHA-256', digestInput.buffer),
        ),
    );
};

const verifyKernelIntegrity = async (
    bytes: ArrayBuffer,
    expectedSha256HexValues: ReadonlySet<string>,
): Promise<void> => {
    const actualSha256Hex = await hashSha256Hex(
        normalizeTranscriptCoreKernelBytesForDigest(new Uint8Array(bytes)),
    );
    if (!expectedSha256HexValues.has(actualSha256Hex)) {
        throw new Error(
            `The transcript-core kernel failed integrity verification: expected one of ${Array.from(expectedSha256HexValues).join(', ')}, received ${actualSha256Hex}.`,
        );
    }
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

const readKernelOutputLength = (
    memory: WebAssembly.Memory,
    pointer: number,
): number =>
    new DataView(memory.buffer, pointer, wasm32UsizeByteLength).getUint32(
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
    const requestBytes = textEncoder.encode(JSON.stringify(request));
    let inputPointer = 0;
    let outputPointer = 0;
    let outputLengthPointer = 0;
    let outputLength = 0;

    try {
        inputPointer = copyIntoKernelMemory(memory, allocate, requestBytes);
        outputLengthPointer = allocate(wasm32UsizeByteLength);
        if (outputLengthPointer === 0) {
            throw new Error(
                'The transcript-core kernel returned a null pointer for the output-length allocation.',
            );
        }
        outputPointer = commandWithLength(
            inputPointer,
            requestBytes.length,
            outputLengthPointer,
        );
        outputLength = readKernelOutputLength(memory, outputLengthPointer);
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
        if (
            outputLengthPointer !== 0 &&
            outputLengthPointer !== inputPointer &&
            outputLengthPointer !== outputPointer
        ) {
            deallocate(outputLengthPointer, wasm32UsizeByteLength);
        }
    }
};

export const createTranscriptCoreKernelLoader = (
    transcriptCoreKernelUrl: URL,
    options: {
        readonly expectedKernelSha256Hex?: string;
    } = {},
): (() => Promise<TranscriptCoreKernel>) => {
    let kernelPromise: Promise<TranscriptCoreKernel> | undefined;

    return async (): Promise<TranscriptCoreKernel> => {
        kernelPromise ??= (async (): Promise<TranscriptCoreKernel> => {
            const bytes = await resolveKernelBytes(transcriptCoreKernelUrl);
            const expectedSha256HexValues =
                options.expectedKernelSha256Hex === undefined
                    ? currentTranscriptCoreKernelNormalizedSha256HexValues
                    : new Set([options.expectedKernelSha256Hex]);
            await verifyKernelIntegrity(bytes, expectedSha256HexValues);
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
            const transcriptCoreCommandWithLength = resolveNumberExport(
                exports,
                'sealed_lattice_transcript_core_command_with_length',
            ) as (
                pointer: number,
                length: number,
                outputLengthPointer: number,
            ) => number;
            const roundtrip = resolveNumberExport(
                exports,
                'sealed_lattice_roundtrip',
            ) as (pointer: number, length: number) => number;
            const exportedFunctionNames = WebAssembly.Module.exports(
                instantiatedSource.module,
            )
                .map((entry) => entry.name)
                .sort();
            let kernelOperationInProgress = false;
            const runExclusiveKernelOperation = <Result>(
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
            const executeCommand = <T>(
                request: TranscriptCoreKernelCommand,
            ): T =>
                runExclusiveKernelOperation('command', () =>
                    runKernelCommand<T>(
                        memory,
                        allocate,
                        deallocate,
                        transcriptCoreCommandWithLength,
                        request,
                    ),
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
                deriveProtocolDigest: (input): ProtocolDigest =>
                    executeCommand<{ readonly protocolDigest: ProtocolDigest }>(
                        {
                            command: 'DeriveProtocolDigest',
                            namespace: input.namespace,
                            value: input.value,
                        },
                    ).protocolDigest,
                evaluatePlaintextComparison: (
                    input,
                ): TranscriptCorePlaintextComparison =>
                    executeCommand<TranscriptCorePlaintextComparison>({
                        command: 'EvaluatePlaintextComparison',
                        leftTotalScore: input.leftTotalScore,
                        rightTotalScore: input.rightTotalScore,
                        rosterSize: input.rosterSize,
                    }),
                hashRaw: (inputHex): string =>
                    executeCommand<{ readonly hash512: string }>({
                        command: 'HashRaw',
                        inputHex,
                    }).hash512,
                interpolateShamirConstantTerm: (input): FieldElement =>
                    executeCommand<{ readonly fieldElement: FieldElement }>({
                        command: 'InterpolateShamirConstantTerm',
                        sharePoints: input.sharePoints,
                    }).fieldElement,
                listCanonicalErrorCodes: (): readonly string[] =>
                    executeCommand<readonly string[]>({
                        command: 'ListCanonicalErrorCodes',
                    }),
                listReservedRootNamespaces: (): readonly string[] =>
                    executeCommand<readonly string[]>({
                        command: 'ListReservedRootNamespaces',
                    }),
                roundTripBytes: (input: Uint8Array): Uint8Array =>
                    runExclusiveKernelOperation('round-trip', () => {
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
                                deallocate(
                                    outputPointer,
                                    normalizedInput.length,
                                );
                            }
                            if (
                                inputPointer !== 0 &&
                                inputPointer !== outputPointer
                            ) {
                                deallocate(
                                    inputPointer,
                                    normalizedInput.length,
                                );
                            }
                        }
                    }),
                verifyFixture: (fixture): TranscriptCoreFixtureVerification =>
                    executeCommand<TranscriptCoreFixtureVerification>({
                        command: 'VerifyFixture',
                        fixture,
                    }),
                describeBallotPrivacyProofBackend:
                    (): BallotPrivacyProofBackendStatus =>
                        executeCommand<BallotPrivacyProofBackendStatus>({
                            command: 'DescribeBallotPrivacyProofBackend',
                        }),
                verifyBallotPrivacyLinearProofVector: (
                    input,
                ): BallotPrivacyLinearProofVectorVerification =>
                    executeCommand<BallotPrivacyLinearProofVectorVerification>({
                        command: 'VerifyBallotPrivacyLinearProofVector',
                        vectorCase: input.vectorCase,
                    }),
                verifyBallotPrivacyEncodedRelationVector: (
                    input,
                ): BallotPrivacyEncodedRelationVectorVerification =>
                    executeCommand<BallotPrivacyEncodedRelationVectorVerification>(
                        {
                            command: 'VerifyBallotPrivacyEncodedRelationVector',
                            vectorCase: input.vectorCase,
                        },
                    ),
                verifyBallotPrivacyReceiverKeyVector: (
                    input,
                ): BallotPrivacyReceiverKeyVectorVerification =>
                    executeCommand<BallotPrivacyReceiverKeyVectorVerification>({
                        command: 'VerifyBallotPrivacyReceiverKeyVector',
                        vectorCase: input.vectorCase,
                    }),
                verifyReceiverKeyProof: (
                    input,
                ): BallotPrivacyKernelVerification =>
                    executeCommand<BallotPrivacyKernelVerification>({
                        command: 'VerifyReceiverKeyProof',
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofBytesHex: input.proofBytesHex,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: input.publicRandomnessHex,
                        receiverKeyProof: input.receiverKeyProof,
                    }),
                prepareReceiverKeyProofGeneration: (
                    input,
                ): BallotPrivacyReceiverKeyProofGenerationPreparation =>
                    executeCommand<BallotPrivacyReceiverKeyProofGenerationPreparation>(
                        {
                            command: 'PrepareReceiverKeyProofGeneration',
                            linearStatement: input.linearStatement,
                            parameterSet: input.parameterSet,
                            proofEncoding: input.proofEncoding,
                            publicRandomnessHex: input.publicRandomnessHex,
                            secretState: input.secretState,
                            proverRandomnessHex: input.proverRandomnessHex,
                        },
                    ),
                generateReceiverKeyProof: (
                    input,
                ): BallotPrivacyReceiverKeyProofGeneration =>
                    executeCommand<BallotPrivacyReceiverKeyProofGeneration>({
                        command: 'GenerateReceiverKeyProof',
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: input.publicRandomnessHex,
                        secretState: input.secretState,
                        proverRandomnessHex: input.proverRandomnessHex,
                    }),
                generateBallotProof: (input): BallotPrivacyProofGeneration =>
                    executeCommand<BallotPrivacyProofGeneration>({
                        command: 'GenerateBallotProof',
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: input.publicRandomnessHex,
                        secretState: input.secretState,
                        proverRandomnessHex: input.proverRandomnessHex,
                    }),
                generateBallotComponentProof: (
                    input,
                ): BallotPrivacyProofGeneration =>
                    executeCommand<BallotPrivacyProofGeneration>({
                        command: 'GenerateBallotComponentProof',
                        componentId: input.componentId,
                        proofInput: input.proofInput,
                        secretState: input.secretState,
                        proverRandomnessHex: input.proverRandomnessHex,
                    }),
                generateBallotProofRecord: (
                    input,
                ): BallotPrivacyProofGeneration =>
                    executeCommand<BallotPrivacyProofGeneration>({
                        command: 'GenerateBallotProofRecord',
                        statement: input.statement,
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: input.publicRandomnessHex,
                        componentBundleStatement:
                            input.componentBundleStatement,
                        componentProofInputs: input.componentProofInputs,
                        secretState: input.secretState,
                        proverRandomnessHex: input.proverRandomnessHex,
                        componentProverRandomnessHexes:
                            input.componentProverRandomnessHexes,
                        componentSecretStates: input.componentSecretStates,
                    }),
                verifyBallotProof: (input): BallotPrivacyKernelVerification =>
                    executeCommand<BallotPrivacyKernelVerification>({
                        command: 'VerifyBallotProof',
                        ballotProof: input.ballotProof,
                        componentBundleStatement:
                            input.componentBundleStatement,
                        componentProofBundle: input.componentProofBundle,
                        componentProofInputs: input.componentProofInputs,
                        linearStatement: input.linearStatement,
                        parameterSet: input.parameterSet,
                        proofBytesHex: input.proofBytesHex,
                        proofEncoding: input.proofEncoding,
                        publicRandomnessHex: input.publicRandomnessHex,
                        statement: input.statement,
                    }),
                verifyClaimBearingBallotPackage: (
                    input,
                ): BallotPrivacyKernelVerification =>
                    executeCommand<BallotPrivacyKernelVerification>({
                        command: 'VerifyClaimBearingBallotPackage',
                        ballotPackage: input.ballotPackage,
                    }),
            };
        })().catch((error: unknown) => {
            kernelPromise = undefined;
            throw error;
        });

        return kernelPromise;
    };
};
