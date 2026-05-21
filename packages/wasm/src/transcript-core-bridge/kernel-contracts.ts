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

/** Runtime status reported by the ballot privacy proof backend. */
export type BallotPrivacyProofBackendStatus = {
    readonly backendName: string;
    readonly backendAvailable: boolean;
    readonly portableRustWasmPortRequired: boolean;
    readonly requiredComponents: readonly string[];
    readonly blockedReason: string | null;
};

/** Structured result returned by WASM ballot privacy proof verification commands. */
export type BallotPrivacyKernelVerification = {
    readonly ok: boolean;
    readonly backendAvailable: boolean;
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
    readonly backendAvailable: boolean;
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
    readonly backendAvailable: boolean;
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
    readonly backendAvailable: boolean;
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

const createFreshRandomnessHex = (): string => {
    const cryptoProvider = globalThis.crypto;
    if (cryptoProvider === undefined) {
        throw new Error(
            'Proof generation requires Web Crypto getRandomValues for fresh prover randomness.',
        );
    }
    const randomBytes = new Uint8Array(32);
    cryptoProvider.getRandomValues(randomBytes);

    return Array.from(randomBytes, (byte) =>
        byte.toString(16).padStart(2, '0'),
    ).join('');
};

const suppliedOrFreshRandomnessHex = (value: string | undefined): string =>
    value ?? createFreshRandomnessHex();

const componentProverRandomnessHexes = (
    componentProofInputs: readonly unknown[],
    suppliedRandomnessHexes: Readonly<Record<string, string>> | undefined,
): Readonly<Record<string, string>> => {
    const randomnessHexes: Record<string, string> = {
        ...(suppliedRandomnessHexes ?? {}),
    };

    for (const componentProofInput of componentProofInputs) {
        if (
            typeof componentProofInput === 'object' &&
            componentProofInput !== null &&
            'componentId' in componentProofInput
        ) {
            const componentId = (
                componentProofInput as { readonly componentId: unknown }
            ).componentId;
            if (
                typeof componentId === 'string' &&
                randomnessHexes[componentId] === undefined
            ) {
                randomnessHexes[componentId] = createFreshRandomnessHex();
            }
        }
    }

    return randomnessHexes;
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
        readonly publicRandomnessHex?: string;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyReceiverKeyProofGeneration;
    generateBallotProof(input: {
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex?: string;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyProofGeneration;
    generateBallotComponentProof(input: {
        readonly componentId: string;
        readonly proofInput: unknown;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyProofGeneration;
    generateBallotProofRecord(input: {
        readonly statement: unknown;
        readonly linearStatement: unknown;
        readonly parameterSet: unknown;
        readonly proofEncoding: unknown;
        readonly publicRandomnessHex?: string;
        readonly componentBundleStatement: unknown;
        readonly componentProofInputs: readonly unknown[];
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
        readonly componentProverRandomnessHexes?: Readonly<
            Record<string, string>
        >;
        readonly componentSecretStates?: Readonly<Record<string, unknown>>;
        readonly casualMicroRosterAcknowledged?: boolean;
        readonly unsafeSmallRosterAcknowledged?: boolean;
    }): BallotPrivacyProofGeneration;
    verifyBallotProof(input: {
        readonly ballotProof: unknown;
        readonly componentBundleStatement?: unknown;
        readonly componentProofBundle?: unknown;
        readonly componentProofInputs?: readonly unknown[];
        readonly dynamicRosterProfileEvidence?: unknown;
        readonly linearStatement?: unknown;
        readonly parameterSet?: unknown;
        readonly proofBytesHex?: string;
        readonly proofEncoding?: unknown;
        readonly publicRandomnessHex?: string;
        readonly statement: unknown;
        readonly casualMicroRosterAcknowledged?: boolean;
        readonly unsafeSmallRosterAcknowledged?: boolean;
    }): BallotPrivacyKernelVerification;
    verifyClaimBearingBallotPackage(input: {
        readonly ballotPackage: unknown;
        readonly dynamicRosterProfileEvidence?: unknown;
        readonly casualMicroRosterAcknowledged?: boolean;
        readonly unsafeSmallRosterAcknowledged?: boolean;
    }): BallotPrivacyKernelVerification;
    generateAggregateDerivationProof(input: {
        readonly proofInput: unknown;
        readonly secretState: unknown;
        readonly proverRandomnessHex?: string;
    }): BallotPrivacyProofGeneration;
    verifyAggregateDerivationProof(input: {
        readonly component?: unknown;
        readonly proofInput?: unknown;
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
          readonly casualMicroRosterAcknowledged?: boolean;
          readonly unsafeSmallRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'VerifyBallotProof';
          readonly ballotProof: unknown;
          readonly componentBundleStatement?: unknown;
          readonly componentProofBundle?: unknown;
          readonly componentProofInputs?: readonly unknown[];
          readonly dynamicRosterProfileEvidence?: unknown;
          readonly linearStatement?: unknown;
          readonly parameterSet?: unknown;
          readonly proofBytesHex?: string;
          readonly proofEncoding?: unknown;
          readonly publicRandomnessHex?: string;
          readonly statement: unknown;
          readonly casualMicroRosterAcknowledged?: boolean;
          readonly unsafeSmallRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'VerifyClaimBearingBallotPackage';
          readonly ballotPackage: unknown;
          readonly dynamicRosterProfileEvidence?: unknown;
          readonly casualMicroRosterAcknowledged?: boolean;
          readonly unsafeSmallRosterAcknowledged?: boolean;
      }
    | {
          readonly command: 'GenerateAggregateDerivationProof';
          readonly proofInput: unknown;
          readonly secretState: unknown;
          readonly proverRandomnessHex: string;
      }
    | {
          readonly command: 'VerifyAggregateDerivationProof';
          readonly component?: unknown;
          readonly proofInput?: unknown;
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

const sha256HexPattern = /^[a-f0-9]{64}$/u;

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

export {
    suppliedOrFreshRandomnessHex,
    componentProverRandomnessHexes,
    wasm32UsizeByteLength,
    wasmHeaderByteLength,
    wasmCustomSectionId,
    sha256HexPattern,
    textDecoder,
    textEncoder,
    bytesToHex,
    normalizeRustSourcePathsForDigest,
    hasWasmHeader,
    readWasmVarUint32,
    concatenateByteChunks,
};
export type {
    TranscriptCoreKernelCommand,
    TranscriptCoreKernelExports,
    KernelSuccessResponse,
    KernelFailureResponse,
};
