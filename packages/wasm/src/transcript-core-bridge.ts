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
    readonly upstreamReference: string;
    readonly upstreamDirectDependencyUsableInBrowser: false;
    readonly portableRustWasmPortRequired: true;
    readonly requiredComponents: readonly string[];
    readonly upstreamReferenceFiles: readonly string[];
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

const transcriptCoreKernelNormalizedSha256HexValues = [
    '7fb272f285f98a378ee53fc3f857a922415897da7abd93ff12bd42395629db84',
    'e68ad9a15a76ecff354d4f14ecf0554f5e8e556665b12041f9de4159f43e967f',
    'e2640736eb4b7985fe20760cb6de0061dc4aa49690c47a05e3bb172670d1c1f2',
    '203e2ace56c4f4b55d477fcaf15bda338fb8a9ca2a25097a469c1dd06d358146',
    '390b1d16a23c50225995a49427fb2db54ebe87bec4f9835c9706722fd22aebf3',
    'd70e11274e11dffc3c500ab3a8acd2df817909edc85a6c3e266674dfdf071a8c',
    '637c519e4fe1648cc7c366c86e159d3f9b04d08fcebb38bac380690fc31aa995',
    'eb8e34683e6d6ceb778628e253a8067128a90f95f8351357c6b84f45c7ca33bc',
    '9b0600143d67d29c44784d99e993972585d588da6eff718917d433947b842ab2',
    '6e356bbf395c00dbf2a4e468e63f82116f9f4b48e1ea8ac62d3b4ca9ec2507f0',
    'e99f4c32cf7572473b1fbb1117d052fd1d60627f8f2fc71285a211a4b1693ae4',
    '8f0fa37a3e8f571be5d788c6666c6d24ae6ba0ecf7ebae5387e6cee2e854e5ad',
    'aa02821ad2f6e7f01933f48704aea76a128876df2afbd447d36e3faf474b509d',
    '567d2df11d7941e0b0cf33d5a6ebfb81e04b977c3d1ccfe3d4c6caa6244b142b',
    '8ca4a23a74fff0cd38691d2d210f72a5a861dfdf67a17b7e73678dc1b85b6367',
    'ca9c7df4bc0f5730654e9dfa6b233ad533c3dafa0d90ded75dda78f28617d57b',
    '15112b7920ead0a440a61f76f45042660dfe215a2045e44363a4d844b7241401',
    '5d1f6a92e4c8e982a2ac12b016db46e131b2aa3beca01b00319b262153f52d25',
    'ed70c522d98f95dbc30d2c83c4a31c8e8f70925803f1bb050107be708fc1aad1',
    '6d4fa5f041072fdd39b2d041b804f7b3c907acd92375971a2e9d38eba860eedf',
    '2141ed25a0aa2e7ddc5a0d6b8c72f6dc07c9208923cc36fb3a0c562a70511182',
    '287413585146cbe73e28b6932ebe9f3ac66a97723997a6d64a76f68b23e73f7a',
    '6c75458c6615d7f2d3b6675b01892ea4d186e5e142e320112865600a347ae5f3',
    '572f2fda7bc64bb7a1061f1bfa097c76cca52f100e921e82f8d30b7be2408ce8',
    '804ab12b4bfdcacc5cf567f39db9be05e9167a304fee3ff4c8ce032f6cd8c451',
    '77c9bf2b763c2c77235e62c6ec977eee031d3400b6081b3d18e900de44bc3efc',
    'b484acc4843eba890eda530e8c451267cbe24fce28022e4d8c190d42f1d9d354',
    '835cdd96bd6ffab881a53d176261acac59a35d6b5a24173962542be529299b9e',
    'f898de6a6cd6993467df009656d50af5df86ae8212324385e94721622c0a27cd',
    'd6912ccce0b059461a265ce080a0bc29b9feb68e1385c69fe011994c1a653fb7',
    'fab065601bd3bbf54d65dc0065791699a26114f7898798d1af5a0533230226bc',
    '3e76c9ecda96950a942f6315ea88f1be0a7209b0ce6a2eaaeea68ac6f3b0107c',
    'd55186a40312c9a08dfebf9ef96b9b54a6934cec47c31fe31c7a5572b4a482b3',
    'e5974f806c54a4765afeb4d9c5a28959e8187032d0b5a674bde23b5a4be74071',
    'ad3ce283a108fa0fb2dba16ffd2948d3dd2ac415f543d45ecc7706d1fdfbca45',
    'e32e1a5b1e4f3710cab62d16946927bb4d26a5b1f2297e7b178fd278a469ec5a',
    '9d79b58a9ec23c9345eb4ce08d8e277b72208db5ffe940102c5c1e2a94f4ab71',
    '15ec6fcde404afc33c42173f5d64b51db739d4f5a70497a646b197b77db1e5ce',
    'd3b2085a01eb670b4d836f5411babdd595b24b59ba8d8bc33ff157b9fe3dd02d',
    'c334fa5e3818f4c0a0a4a8f595e971c1c73109007d7c4ebd6b50c7a4cfcaf2a4',
    'e5e554773bf462baaae47c4b66e3df8204742f7752e6b148d1f30f7c02b30340',
    '5ab92007b6a4c31a9538396aa4a475fb2bf7dd50804309197b87f5cc5f6cd1c9',
    '6c7879298bc0a76e35a5d6d2fcb7c5039795f26457d235f7b65f6140a9689405',
    '3fd22ecfe4f39391ea77e4a94e65988909b7baf7fe29cbeefdf8b7a4f7ab7809',
    'e69214b4a428a34d4f73ab767d50e013401b6ba58132bf60eea17ee52078c355',
    'd77ccc2cb505e384040b20d2f69a3a7178059daeb7ba06385a9782aa0a5201f1',
    'e6801dcf533d59fed729d6f02bbce746d4932293476236a75413b50f5124c7ec',
    '00b6a63fcdb812f93e2074361adf6098e2148bc4075a946f34afdf98f2794e4f',
    'e3f6b47734f3ab107f6a4d01e44415d9ba8033600f9fbc00331e5078a0a43bc4',
    '813e3258b6c7d14366b8bb9cc5aefdc1223956acafff9ae49ddfa06c2f3de7d6',
    '9e61680946c1cd9627a768d8321cfb2dc5409cc5d3f6dc664be2c48b7dccdf1f',
    '67b6b4f8a9f01d042feffa9e05157124bb725fcf951b6f4a594f477903f41f73',
    '0589a1ad67171e06bbfe3bb8edc32eb03c255a151f0172b4c447a024e8ccb13f',
    'e5b1158dbb4cf28456a5a3b068f3a8973eb70585cbcff5afaa551202937919b7',
    '50f3bd5adc915e43e1b58df62165f3b6cc8d68c84785e3925769e41dc5b35f37',
    'ee9e015bcc384985070758bb4292fc1ed0e3fc780b7a25cae996d83e96ea80f9',
    'feb22829dd3c208b9c9cb3adaca77ee25307b9c894850d6923ef832b465b2610',
    '4c711dc81c70b0ac82b1e5ea89d7d2e49d42cd20f38af79590a3b6c83a78807f',
    '9562457e0424fd40d90b9a7493acaf351ec397b10e967e83e68f0bd9f128a88d',
    '5b000f2fdd7f7ccf6db9d91c64ca427a85f905202cbc4c3e2521d3c2d62008f6',
    '7d68c10468efb9f60361567e0087ed4821988670f503648e60cfdb28ec11b119',
    'd807255202275e58385160d64a266073cba216ff3e1d863ea55c776f74a158f7',
    '5a7ad4a4d7ded9894ce36dc46352f5f815cfca04d7f7629b434544194b6a51b2',
    '0820267a833515aadba4fc21186965b9fd6bfb11f71ee87f5c3168f34c326153',
    '04751166b468d32fb541b5c0ec8b91250ad4abd3517cb5ca8ed494b07ce2041c',
] as const;
const defaultTranscriptCoreKernelNormalizedSha256HexValues = new Set<string>(
    transcriptCoreKernelNormalizedSha256HexValues,
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
                    ? defaultTranscriptCoreKernelNormalizedSha256HexValues
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
