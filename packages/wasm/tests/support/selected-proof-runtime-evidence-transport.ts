import { sha512 } from '@noble/hashes/sha2.js';

import {
    desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole,
    desktopBrowserProofTransportGenerationCaseIdentifiers,
    resolveDesktopBrowserProofTransportVerificationCaseIdentifier,
    type DesktopBrowserProofEvidenceCaseIdentifier,
    type DesktopBrowserProofTransportGenerationCaseIdentifier,
    type DesktopBrowserProofTransportVerificationCaseIdentifier,
} from '../../../../tests/support/desktop-browser-proof-evidence-catalog.js';

const transportManifestSchemaIdentifier =
    'sealed-lattice/desktop-browser-proof-evidence-transport/v1';
const sha256HexPattern = /^[0-9a-f]{64}$/u;
const sha512HexPattern = /^[0-9a-f]{128}$/u;
const safeFileNamePattern = /^[a-z0-9]+(?:[a-z0-9.-]*[a-z0-9])?$/u;

export const desktopBrowserProofGenerationSessionIdentifiers = Object.freeze([
    'chromium-generation',
] as const);

export const desktopBrowserProofVerificationSessionIdentifiers = Object.freeze([
    'chromium-verification',
] as const);

export type DesktopBrowserProofGenerationSessionIdentifier =
    (typeof desktopBrowserProofGenerationSessionIdentifiers)[number];

export type DesktopBrowserProofVerificationSessionIdentifier =
    (typeof desktopBrowserProofVerificationSessionIdentifiers)[number];

type DesktopBrowserProofGenerationBrowserEngine = 'chromium';

type DesktopBrowserProofDeterministicParityBinding = Readonly<{
    deterministicCoinBindingSha512Hex: string;
    nativeProofByteLength: number;
    nativeProofSha512Hex: string;
    wasmProofByteLength: number;
    wasmProofSha512Hex: string;
}>;

export type DesktopBrowserProofTransportArtifact = Readonly<{
    canonicalProofByteLength: number;
    canonicalProofSha512Hex: string;
    fileName: string;
    generationCaseIdentifier: DesktopBrowserProofTransportGenerationCaseIdentifier;
    runOrdinal: number;
}>;

type DesktopBrowserProofTransportManifest = Readonly<{
    artifacts: readonly DesktopBrowserProofTransportArtifact[];
    generationBrowserEngine: DesktopBrowserProofGenerationBrowserEngine;
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
    schemaIdentifier: typeof transportManifestSchemaIdentifier;
    suiteId: string;
    wasmSha256Hex: string;
}>;

type DesktopBrowserProofTransportManifestAuthenticationBindings = Readonly<
    Record<DesktopBrowserProofGenerationSessionIdentifier, string>
>;

export type DesktopBrowserProofEvidenceGenerationWorkerStartMessage = Readonly<{
    caseIdentifiers: readonly DesktopBrowserProofEvidenceCaseIdentifier[];
    command: 'generate-selected-proof-runtime-evidence';
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
    ownershipRole: 'generation';
    wasmSha256Hex: string;
}>;

export type DesktopBrowserProofEvidenceVerificationWorkerStartMessage =
    Readonly<{
        canonicalProofByteLength: number;
        canonicalProofSha512Hex: string;
        command: 'verify-selected-proof-runtime-evidence';
        generationCaseIdentifier: DesktopBrowserProofTransportGenerationCaseIdentifier;
        generationRunOrdinal: number;
        generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
        ownershipRole: 'verification';
        proofBytes: Uint8Array<ArrayBuffer>;
        suiteId: string;
        verificationCaseIdentifier: DesktopBrowserProofTransportVerificationCaseIdentifier;
        verificationRunOrdinal: number;
        verificationSessionIdentifier: DesktopBrowserProofVerificationSessionIdentifier;
        wasmSha256Hex: string;
    }>;

export type DesktopBrowserProofEvidenceWorkerStartMessage =
    | DesktopBrowserProofEvidenceGenerationWorkerStartMessage
    | DesktopBrowserProofEvidenceVerificationWorkerStartMessage;

type EncodedFileReader = (
    absoluteFilePath: string,
    encoding: 'base64' | 'utf8',
) => Promise<string>;

const isRecord = (value: unknown): value is Readonly<Record<string, unknown>> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const hasExactKeys = (
    record: Readonly<Record<string, unknown>>,
    expectedKeys: readonly string[],
): boolean => {
    const actualKeys = Object.keys(record).sort();
    const sortedExpectedKeys = [...expectedKeys].sort();
    return (
        actualKeys.length === sortedExpectedKeys.length &&
        actualKeys.every(
            (actualKey, keyIndex) => actualKey === sortedExpectedKeys[keyIndex],
        )
    );
};

const requireSha256Hex = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !sha256HexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a lowercase SHA-256 digest.`);
    }
    return value;
};

const requireSha512Hex = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string' || !sha512HexPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a lowercase SHA-512 digest.`);
    }
    return value;
};

const requirePositiveSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (!Number.isSafeInteger(value) || Number(value) <= 0) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }
    return Number(value);
};

const includesString = <Value extends string>(
    values: readonly Value[],
    value: unknown,
): value is Value =>
    typeof value === 'string' && values.includes(value as Value);

export const parseDesktopBrowserProofDeterministicParityBinding = (
    value: unknown,
): DesktopBrowserProofDeterministicParityBinding => {
    if (
        !isRecord(value) ||
        !hasExactKeys(value, [
            'deterministicCoinBindingSha512Hex',
            'nativeProofByteLength',
            'nativeProofSha512Hex',
            'wasmProofByteLength',
            'wasmProofSha512Hex',
        ])
    ) {
        throw new TypeError(
            'The native and WebAssembly deterministic-parity binding is malformed.',
        );
    }
    const binding = Object.freeze({
        deterministicCoinBindingSha512Hex: requireSha512Hex(
            value.deterministicCoinBindingSha512Hex,
            'deterministicCoinBindingSha512Hex',
        ),
        nativeProofByteLength: requirePositiveSafeInteger(
            value.nativeProofByteLength,
            'nativeProofByteLength',
        ),
        nativeProofSha512Hex: requireSha512Hex(
            value.nativeProofSha512Hex,
            'nativeProofSha512Hex',
        ),
        wasmProofByteLength: requirePositiveSafeInteger(
            value.wasmProofByteLength,
            'wasmProofByteLength',
        ),
        wasmProofSha512Hex: requireSha512Hex(
            value.wasmProofSha512Hex,
            'wasmProofSha512Hex',
        ),
    });
    if (
        binding.nativeProofByteLength !== binding.wasmProofByteLength ||
        binding.nativeProofSha512Hex !== binding.wasmProofSha512Hex
    ) {
        throw new TypeError(
            'Native and WebAssembly deterministic proof bytes are not identical.',
        );
    }
    return binding;
};

export const requireDesktopBrowserProofGenerationSessionIdentifier = (
    value: unknown,
): DesktopBrowserProofGenerationSessionIdentifier => {
    if (
        !includesString(desktopBrowserProofGenerationSessionIdentifiers, value)
    ) {
        throw new TypeError(
            'generationSessionIdentifier must name a registered proof-generation session.',
        );
    }
    return value;
};

export const requireDesktopBrowserProofVerificationSessionIdentifier = (
    value: unknown,
): DesktopBrowserProofVerificationSessionIdentifier => {
    if (
        !includesString(
            desktopBrowserProofVerificationSessionIdentifiers,
            value,
        )
    ) {
        throw new TypeError(
            'verificationSessionIdentifier must name a registered proof-verification session.',
        );
    }
    return value;
};

const requireTransportGenerationCaseIdentifier = (
    value: unknown,
): DesktopBrowserProofTransportGenerationCaseIdentifier => {
    if (
        !includesString(
            desktopBrowserProofTransportGenerationCaseIdentifiers,
            value,
        )
    ) {
        throw new TypeError(
            'generationCaseIdentifier must name a transported proof-generation case.',
        );
    }
    return value;
};

const requireTransportVerificationCaseIdentifier = (
    value: unknown,
): DesktopBrowserProofTransportVerificationCaseIdentifier => {
    const generationCaseIdentifier =
        desktopBrowserProofTransportGenerationCaseIdentifiers.find(
            (candidateGenerationCaseIdentifier) =>
                resolveDesktopBrowserProofTransportVerificationCaseIdentifier(
                    candidateGenerationCaseIdentifier,
                ) === value,
        );
    if (generationCaseIdentifier === undefined) {
        throw new TypeError(
            'verificationCaseIdentifier must name a transported proof-verification case.',
        );
    }
    const verificationCaseIdentifier =
        resolveDesktopBrowserProofTransportVerificationCaseIdentifier(
            generationCaseIdentifier,
        );
    if (verificationCaseIdentifier === undefined) {
        throw new Error(
            `The transported proof catalog omitted ${generationCaseIdentifier}.`,
        );
    }
    return verificationCaseIdentifier;
};

const requireGenerationCaseCatalog = (
    value: unknown,
): readonly DesktopBrowserProofEvidenceCaseIdentifier[] => {
    const expectedCaseIdentifiers =
        desktopBrowserProofEvidenceCaseIdentifiersByOwnershipRole.generation;
    if (
        !Array.isArray(value) ||
        value.length !== expectedCaseIdentifiers.length ||
        value.some(
            (caseIdentifier, caseIndex) =>
                caseIdentifier !== expectedCaseIdentifiers[caseIndex],
        )
    ) {
        throw new TypeError(
            'The desktop proof-evidence generation worker received a noncanonical generation case catalog.',
        );
    }
    return Object.freeze([...expectedCaseIdentifiers]);
};

const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const summarizeDesktopBrowserProofTransportBytes = (
    bytes: Uint8Array,
): Readonly<{ byteLength: number; sha512Hex: string }> =>
    Object.freeze({
        byteLength: bytes.byteLength,
        sha512Hex: bytesToHex(sha512(bytes)),
    });

const createTransportArtifactFileName = (input: {
    generationCaseIdentifier: DesktopBrowserProofTransportGenerationCaseIdentifier;
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
    runOrdinal: number;
}): string =>
    `${input.generationSessionIdentifier}-${input.generationCaseIdentifier}-run-${String(input.runOrdinal)}.proof`;

const parseTransportArtifact = (
    value: unknown,
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier,
): DesktopBrowserProofTransportArtifact => {
    if (
        !isRecord(value) ||
        !hasExactKeys(value, [
            'canonicalProofByteLength',
            'canonicalProofSha512Hex',
            'fileName',
            'generationCaseIdentifier',
            'runOrdinal',
        ])
    ) {
        throw new TypeError(
            'The desktop proof transport manifest contains a malformed artifact record.',
        );
    }
    const generationCaseIdentifier = requireTransportGenerationCaseIdentifier(
        value.generationCaseIdentifier,
    );
    const runOrdinal = requirePositiveSafeInteger(
        value.runOrdinal,
        'runOrdinal',
    );
    const expectedFileName = createTransportArtifactFileName({
        generationCaseIdentifier,
        generationSessionIdentifier,
        runOrdinal,
    });
    if (value.fileName !== expectedFileName) {
        throw new TypeError(
            'The desktop proof transport artifact file name is not canonical.',
        );
    }
    return Object.freeze({
        canonicalProofByteLength: requirePositiveSafeInteger(
            value.canonicalProofByteLength,
            'canonicalProofByteLength',
        ),
        canonicalProofSha512Hex: requireSha512Hex(
            value.canonicalProofSha512Hex,
            'canonicalProofSha512Hex',
        ),
        fileName: expectedFileName,
        generationCaseIdentifier,
        runOrdinal,
    });
};

export const createDesktopBrowserProofTransportArtifact = (input: {
    generationCaseIdentifier: DesktopBrowserProofTransportGenerationCaseIdentifier;
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
    proofBytes: Uint8Array;
    runOrdinal: number;
}): DesktopBrowserProofTransportArtifact => {
    const runOrdinal = requirePositiveSafeInteger(
        input.runOrdinal,
        'runOrdinal',
    );
    const proofSummary = summarizeDesktopBrowserProofTransportBytes(
        input.proofBytes,
    );
    if (proofSummary.byteLength === 0) {
        throw new TypeError('A transported canonical proof must not be empty.');
    }
    return parseTransportArtifact(
        {
            canonicalProofByteLength: proofSummary.byteLength,
            canonicalProofSha512Hex: proofSummary.sha512Hex,
            fileName: createTransportArtifactFileName({
                generationCaseIdentifier: input.generationCaseIdentifier,
                generationSessionIdentifier: input.generationSessionIdentifier,
                runOrdinal,
            }),
            generationCaseIdentifier: input.generationCaseIdentifier,
            runOrdinal,
        },
        input.generationSessionIdentifier,
    );
};

const transportCaseOrder = new Map(
    desktopBrowserProofTransportGenerationCaseIdentifiers.map(
        (caseIdentifier, caseIndex) => [caseIdentifier, caseIndex],
    ),
);

const sortTransportArtifacts = (
    artifacts: readonly DesktopBrowserProofTransportArtifact[],
): readonly DesktopBrowserProofTransportArtifact[] =>
    [...artifacts].sort((left, right) => {
        const caseOrderDifference =
            Number(transportCaseOrder.get(left.generationCaseIdentifier)) -
            Number(transportCaseOrder.get(right.generationCaseIdentifier));
        return caseOrderDifference === 0
            ? left.runOrdinal - right.runOrdinal
            : caseOrderDifference;
    });

const parseTransportManifestValue = (
    value: unknown,
): DesktopBrowserProofTransportManifest => {
    if (
        !isRecord(value) ||
        !hasExactKeys(value, [
            'artifacts',
            'generationBrowserEngine',
            'generationSessionIdentifier',
            'schemaIdentifier',
            'suiteId',
            'wasmSha256Hex',
        ]) ||
        value.schemaIdentifier !== transportManifestSchemaIdentifier ||
        !Array.isArray(value.artifacts)
    ) {
        throw new TypeError(
            'The desktop proof transport manifest is malformed or has an unsupported schema.',
        );
    }
    const generationSessionIdentifier =
        requireDesktopBrowserProofGenerationSessionIdentifier(
            value.generationSessionIdentifier,
        );
    const generationBrowserEngine: DesktopBrowserProofGenerationBrowserEngine =
        'chromium';
    if (value.generationBrowserEngine !== generationBrowserEngine) {
        throw new TypeError(
            'The desktop proof transport manifest browser does not own its generation session.',
        );
    }
    const artifacts = value.artifacts.map((artifact) =>
        parseTransportArtifact(artifact, generationSessionIdentifier),
    );
    const sortedArtifacts = sortTransportArtifacts(artifacts);
    if (
        artifacts.some(
            (artifact, artifactIndex) =>
                artifact.fileName !== sortedArtifacts[artifactIndex]?.fileName,
        )
    ) {
        throw new TypeError(
            'The desktop proof transport manifest artifacts are not in canonical order.',
        );
    }
    if (
        new Set(artifacts.map(({ fileName }) => fileName)).size !==
        artifacts.length
    ) {
        throw new TypeError(
            'The desktop proof transport manifest repeats an artifact file.',
        );
    }
    for (const generationCaseIdentifier of desktopBrowserProofTransportGenerationCaseIdentifiers) {
        const runOrdinals = artifacts
            .filter(
                (artifact) =>
                    artifact.generationCaseIdentifier ===
                    generationCaseIdentifier,
            )
            .map(({ runOrdinal }) => runOrdinal);
        if (
            runOrdinals.length === 0 ||
            runOrdinals.some(
                (runOrdinal, runIndex) => runOrdinal !== runIndex + 1,
            )
        ) {
            throw new TypeError(
                `The desktop proof transport manifest must contain contiguous runs for ${generationCaseIdentifier}.`,
            );
        }
    }
    return Object.freeze({
        artifacts: Object.freeze(artifacts),
        generationBrowserEngine,
        generationSessionIdentifier,
        schemaIdentifier: transportManifestSchemaIdentifier,
        suiteId: requireSha512Hex(value.suiteId, 'suiteId'),
        wasmSha256Hex: requireSha256Hex(value.wasmSha256Hex, 'wasmSha256Hex'),
    });
};

export const createDesktopBrowserProofTransportManifest = (input: {
    artifacts: readonly DesktopBrowserProofTransportArtifact[];
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
    suiteId: string;
    wasmSha256Hex: string;
}): DesktopBrowserProofTransportManifest =>
    parseTransportManifestValue({
        artifacts: sortTransportArtifacts(input.artifacts),
        generationBrowserEngine: 'chromium',
        generationSessionIdentifier: input.generationSessionIdentifier,
        schemaIdentifier: transportManifestSchemaIdentifier,
        suiteId: input.suiteId,
        wasmSha256Hex: input.wasmSha256Hex,
    });

export const encodeDesktopBrowserProofTransportManifest = (
    manifest: DesktopBrowserProofTransportManifest,
): string => {
    const validatedManifest = parseTransportManifestValue(manifest);
    return `${JSON.stringify(validatedManifest)}\n`;
};

export const parseDesktopBrowserProofTransportManifest = (
    manifestText: string,
): DesktopBrowserProofTransportManifest => {
    let value: unknown;
    try {
        value = JSON.parse(manifestText) as unknown;
    } catch (error) {
        throw Object.assign(
            new TypeError('The desktop proof transport manifest is not JSON.'),
            { failureCause: error },
        );
    }
    const manifest = parseTransportManifestValue(value);
    if (encodeDesktopBrowserProofTransportManifest(manifest) !== manifestText) {
        throw new TypeError(
            'The desktop proof transport manifest is not canonically encoded.',
        );
    }
    return manifest;
};

const normalizeAbsoluteTransportDirectory = (
    transportDirectoryPath: string,
): Readonly<{ path: string; separator: '\\' | '/' }> => {
    if (/^[A-Za-z]:[\\/]/u.test(transportDirectoryPath)) {
        const normalizedPath = transportDirectoryPath.replace(/\//gu, '\\');
        const pathSegments = normalizedPath.slice(3).split('\\');
        if (
            pathSegments.some(
                (pathSegment) =>
                    pathSegment.length === 0 ||
                    pathSegment === '.' ||
                    pathSegment === '..',
            )
        ) {
            throw new TypeError(
                'The desktop proof transport directory must be a normalized absolute path.',
            );
        }
        return Object.freeze({
            path: normalizedPath.endsWith('\\')
                ? normalizedPath.slice(0, -1)
                : normalizedPath,
            separator: '\\',
        });
    }
    if (transportDirectoryPath.startsWith('/')) {
        const pathSegments = transportDirectoryPath.slice(1).split('/');
        if (
            pathSegments.some(
                (pathSegment) =>
                    pathSegment.length === 0 ||
                    pathSegment === '.' ||
                    pathSegment === '..' ||
                    pathSegment.includes('\\'),
            )
        ) {
            throw new TypeError(
                'The desktop proof transport directory must be a normalized absolute path.',
            );
        }
        return Object.freeze({
            path: transportDirectoryPath.endsWith('/')
                ? transportDirectoryPath.slice(0, -1)
                : transportDirectoryPath,
            separator: '/',
        });
    }
    throw new TypeError(
        'The desktop proof transport directory must be absolute.',
    );
};

const resolveConfinedTransportFilePath = (
    transportDirectoryPath: string,
    fileName: string,
): string => {
    if (!safeFileNamePattern.test(fileName)) {
        throw new TypeError(
            'The desktop proof transport file name is not a confined canonical file name.',
        );
    }
    const normalizedDirectory = normalizeAbsoluteTransportDirectory(
        transportDirectoryPath,
    );
    return `${normalizedDirectory.path}${normalizedDirectory.separator}${fileName}`;
};

export const resolveDesktopBrowserProofTransportManifestPath = (
    transportDirectoryPath: string,
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier,
): string =>
    resolveConfinedTransportFilePath(
        transportDirectoryPath,
        `${generationSessionIdentifier}-manifest.json`,
    );

export const resolveDesktopBrowserProofTransportArtifactPath = (
    transportDirectoryPath: string,
    artifact: DesktopBrowserProofTransportArtifact,
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier,
): string => {
    const validatedArtifact = parseTransportArtifact(
        artifact,
        generationSessionIdentifier,
    );
    return resolveConfinedTransportFilePath(
        transportDirectoryPath,
        validatedArtifact.fileName,
    );
};

const base64ChunkByteLength = 32_768;

export const encodeDesktopBrowserProofTransportBytesAsBase64 = (
    bytes: Uint8Array,
): string => {
    const binaryChunks: string[] = [];
    for (
        let chunkOffset = 0;
        chunkOffset < bytes.byteLength;
        chunkOffset += base64ChunkByteLength
    ) {
        const chunk = bytes.subarray(
            chunkOffset,
            Math.min(bytes.byteLength, chunkOffset + base64ChunkByteLength),
        );
        binaryChunks.push(String.fromCharCode(...chunk));
    }
    return btoa(binaryChunks.join(''));
};

const decodeDesktopBrowserProofTransportBytesFromBase64 = (
    encodedBytes: string,
): Uint8Array<ArrayBuffer> => {
    let binaryString: string;
    try {
        binaryString = atob(encodedBytes);
    } catch (error) {
        throw Object.assign(
            new TypeError(
                'The desktop proof transport artifact is not valid base64.',
            ),
            { failureCause: error },
        );
    }
    const bytes = new Uint8Array(binaryString.length);
    for (let byteIndex = 0; byteIndex < binaryString.length; byteIndex += 1) {
        bytes[byteIndex] = binaryString.charCodeAt(byteIndex);
    }
    if (
        encodeDesktopBrowserProofTransportBytesAsBase64(bytes) !== encodedBytes
    ) {
        throw new TypeError(
            'The desktop proof transport artifact is not canonically base64 encoded.',
        );
    }
    return bytes;
};

export const validateDesktopBrowserProofTransportArtifactBytes = (
    artifact: DesktopBrowserProofTransportArtifact,
    proofBytes: Uint8Array,
): void => {
    const proofSummary = summarizeDesktopBrowserProofTransportBytes(proofBytes);
    if (
        proofSummary.byteLength !== artifact.canonicalProofByteLength ||
        proofSummary.sha512Hex !== artifact.canonicalProofSha512Hex
    ) {
        throw new Error(
            `The desktop proof transport artifact failed its length or SHA-512 binding: ${artifact.fileName}.`,
        );
    }
};

export const readDesktopBrowserProofTransportManifest = async (input: {
    expectedManifestSha512Hex?: string;
    expectedSuiteId?: string;
    expectedWasmSha256Hex?: string;
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
    readFile: EncodedFileReader;
    transportDirectoryPath: string;
}): Promise<
    Readonly<{
        manifest: DesktopBrowserProofTransportManifest;
        manifestSha512Hex: string;
    }>
> => {
    const manifestPath = resolveDesktopBrowserProofTransportManifestPath(
        input.transportDirectoryPath,
        input.generationSessionIdentifier,
    );
    let manifestText: string;
    try {
        manifestText = await input.readFile(manifestPath, 'utf8');
    } catch (error) {
        throw Object.assign(
            new Error(
                `The desktop proof transport manifest is missing or unreadable: ${input.generationSessionIdentifier}.`,
            ),
            { failureCause: error },
        );
    }
    const manifest = parseDesktopBrowserProofTransportManifest(manifestText);
    if (
        manifest.generationSessionIdentifier !==
        input.generationSessionIdentifier
    ) {
        throw new Error(
            'The desktop proof transport manifest belongs to a different generation session.',
        );
    }
    if (
        input.expectedSuiteId !== undefined &&
        manifest.suiteId !== input.expectedSuiteId
    ) {
        throw new Error(
            'The desktop proof transport manifest is bound to a different suite.',
        );
    }
    if (
        input.expectedWasmSha256Hex !== undefined &&
        manifest.wasmSha256Hex !== input.expectedWasmSha256Hex
    ) {
        throw new Error(
            'The desktop proof transport manifest is bound to a different WebAssembly module.',
        );
    }
    const manifestSha512Hex = summarizeDesktopBrowserProofTransportBytes(
        new TextEncoder().encode(manifestText),
    ).sha512Hex;
    if (
        input.expectedManifestSha512Hex !== undefined &&
        manifestSha512Hex !==
            requireSha512Hex(
                input.expectedManifestSha512Hex,
                'expectedManifestSha512Hex',
            )
    ) {
        throw new Error(
            'The desktop proof transport manifest failed its authenticated SHA-512 binding.',
        );
    }
    return Object.freeze({ manifest, manifestSha512Hex });
};

export const readDesktopBrowserProofTransportArtifact = async (input: {
    artifact: DesktopBrowserProofTransportArtifact;
    generationSessionIdentifier: DesktopBrowserProofGenerationSessionIdentifier;
    readFile: EncodedFileReader;
    transportDirectoryPath: string;
}): Promise<Uint8Array<ArrayBuffer>> => {
    const artifactPath = resolveDesktopBrowserProofTransportArtifactPath(
        input.transportDirectoryPath,
        input.artifact,
        input.generationSessionIdentifier,
    );
    let encodedBytes: string;
    try {
        encodedBytes = await input.readFile(artifactPath, 'base64');
    } catch (error) {
        throw Object.assign(
            new Error(
                `The desktop proof transport artifact is missing or unreadable: ${input.artifact.fileName}.`,
            ),
            { failureCause: error },
        );
    }
    const proofBytes =
        decodeDesktopBrowserProofTransportBytesFromBase64(encodedBytes);
    validateDesktopBrowserProofTransportArtifactBytes(
        input.artifact,
        proofBytes,
    );
    return proofBytes;
};

export const serializeDesktopBrowserProofTransportManifestAuthenticationBindings =
    (
        bindings: DesktopBrowserProofTransportManifestAuthenticationBindings,
    ): string =>
        JSON.stringify({
            'chromium-generation': requireSha512Hex(
                bindings['chromium-generation'],
                'chromium-generation manifest digest',
            ),
        });

export const parseDesktopBrowserProofTransportManifestAuthenticationBindings = (
    value: string,
): DesktopBrowserProofTransportManifestAuthenticationBindings => {
    let parsedValue: unknown;
    try {
        parsedValue = JSON.parse(value) as unknown;
    } catch (error) {
        throw Object.assign(
            new TypeError(
                'The desktop proof transport manifest authentication binding is not JSON.',
            ),
            { failureCause: error },
        );
    }
    if (
        !isRecord(parsedValue) ||
        !hasExactKeys(parsedValue, ['chromium-generation'])
    ) {
        throw new TypeError(
            'The desktop proof transport manifest authentication binding is malformed.',
        );
    }
    const bindings = Object.freeze({
        'chromium-generation': requireSha512Hex(
            parsedValue['chromium-generation'],
            'chromium-generation manifest digest',
        ),
    });
    if (
        serializeDesktopBrowserProofTransportManifestAuthenticationBindings(
            bindings,
        ) !== value
    ) {
        throw new TypeError(
            'The desktop proof transport manifest authentication binding is not canonical.',
        );
    }
    return bindings;
};

const requireOwnedProofBytes = (value: unknown): Uint8Array<ArrayBuffer> => {
    if (
        !(value instanceof Uint8Array) ||
        !(value.buffer instanceof ArrayBuffer) ||
        value.byteOffset !== 0 ||
        value.byteLength !== value.buffer.byteLength ||
        value.byteLength === 0
    ) {
        throw new TypeError(
            'proofBytes must be one nonempty owned Uint8Array buffer.',
        );
    }
    return value as Uint8Array<ArrayBuffer>;
};

export const parseDesktopBrowserProofEvidenceWorkerStartMessage = (
    value: unknown,
): DesktopBrowserProofEvidenceWorkerStartMessage => {
    if (!isRecord(value)) {
        throw new TypeError(
            'The desktop proof-evidence worker received a non-object start message.',
        );
    }
    if (value.command === 'generate-selected-proof-runtime-evidence') {
        if (
            !hasExactKeys(value, [
                'caseIdentifiers',
                'command',
                'generationSessionIdentifier',
                'ownershipRole',
                'wasmSha256Hex',
            ]) ||
            value.ownershipRole !== 'generation'
        ) {
            throw new TypeError(
                'The desktop proof-evidence generation worker received a malformed or role-mixed start message.',
            );
        }
        return Object.freeze({
            caseIdentifiers: requireGenerationCaseCatalog(
                value.caseIdentifiers,
            ),
            command: value.command,
            generationSessionIdentifier:
                requireDesktopBrowserProofGenerationSessionIdentifier(
                    value.generationSessionIdentifier,
                ),
            ownershipRole: 'generation',
            wasmSha256Hex: requireSha256Hex(
                value.wasmSha256Hex,
                'wasmSha256Hex',
            ),
        });
    }
    if (value.command === 'verify-selected-proof-runtime-evidence') {
        if (
            !hasExactKeys(value, [
                'canonicalProofByteLength',
                'canonicalProofSha512Hex',
                'command',
                'generationCaseIdentifier',
                'generationRunOrdinal',
                'generationSessionIdentifier',
                'ownershipRole',
                'proofBytes',
                'suiteId',
                'verificationCaseIdentifier',
                'verificationRunOrdinal',
                'verificationSessionIdentifier',
                'wasmSha256Hex',
            ]) ||
            value.ownershipRole !== 'verification'
        ) {
            throw new TypeError(
                'The desktop proof-evidence verification worker received a malformed or role-mixed start message.',
            );
        }
        const generationCaseIdentifier =
            requireTransportGenerationCaseIdentifier(
                value.generationCaseIdentifier,
            );
        const verificationCaseIdentifier =
            requireTransportVerificationCaseIdentifier(
                value.verificationCaseIdentifier,
            );
        if (
            resolveDesktopBrowserProofTransportVerificationCaseIdentifier(
                generationCaseIdentifier,
            ) !== verificationCaseIdentifier
        ) {
            throw new TypeError(
                'The desktop proof-evidence verification case does not own the transported generation case.',
            );
        }
        const proofBytes = requireOwnedProofBytes(value.proofBytes);
        const canonicalProofByteLength = requirePositiveSafeInteger(
            value.canonicalProofByteLength,
            'canonicalProofByteLength',
        );
        const canonicalProofSha512Hex = requireSha512Hex(
            value.canonicalProofSha512Hex,
            'canonicalProofSha512Hex',
        );
        const proofSummary =
            summarizeDesktopBrowserProofTransportBytes(proofBytes);
        if (
            proofSummary.byteLength !== canonicalProofByteLength ||
            proofSummary.sha512Hex !== canonicalProofSha512Hex
        ) {
            throw new TypeError(
                'The desktop proof-evidence verification worker received proof bytes that do not match their transport binding.',
            );
        }
        return Object.freeze({
            canonicalProofByteLength,
            canonicalProofSha512Hex,
            command: value.command,
            generationCaseIdentifier,
            generationRunOrdinal: requirePositiveSafeInteger(
                value.generationRunOrdinal,
                'generationRunOrdinal',
            ),
            generationSessionIdentifier:
                requireDesktopBrowserProofGenerationSessionIdentifier(
                    value.generationSessionIdentifier,
                ),
            ownershipRole: 'verification',
            proofBytes,
            suiteId: requireSha512Hex(value.suiteId, 'suiteId'),
            verificationCaseIdentifier,
            verificationRunOrdinal: requirePositiveSafeInteger(
                value.verificationRunOrdinal,
                'verificationRunOrdinal',
            ),
            verificationSessionIdentifier:
                requireDesktopBrowserProofVerificationSessionIdentifier(
                    value.verificationSessionIdentifier,
                ),
            wasmSha256Hex: requireSha256Hex(
                value.wasmSha256Hex,
                'wasmSha256Hex',
            ),
        });
    }
    throw new TypeError(
        'The desktop proof-evidence worker received an unknown role-specific command.',
    );
};
