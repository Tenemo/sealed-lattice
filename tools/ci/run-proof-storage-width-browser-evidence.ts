import { createHash, randomUUID } from 'node:crypto';
import {
    lstat,
    mkdir,
    open,
    readFile,
    readdir,
    realpath,
} from 'node:fs/promises';
import path from 'node:path';

import { normalizeTranscriptCoreKernelBytesForHash } from '../../packages/wasm/src/transcript-core-bridge.js';
import {
    parseProofStorageWidthBrowserMeasurement,
    parseProofStorageWidthBrowserNativeBinding,
    proofStorageWidthBrowserEvidenceProfile,
    requireProofStorageWidthBrowserNativeMatch,
    type ProofStorageWidthBrowserMeasurement,
    type ProofStorageWidthBrowserNativeBinding,
} from '../../tests/support/proof-storage-width-browser-evidence.js';

import {
    proofStorageWidthBrowserEvidenceProjectName,
    proofStorageWidthBrowserEvidenceTestGlobs,
} from './browser-test-project-selection.js';
import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    extractProofStorageWidthOperationMemory,
    type ValidatedProofStorageWidthResult,
    type ValidatedProofStorageWidthStaticPreflightPoint,
} from './proof-storage-width-evidence.js';
import {
    appendProofStorageWidthOfficialReservationOutcome,
    buildProofStorageWidthBrowserReservationIdentity,
    createProofStorageWidthBrowserSampleReservation,
    defaultProofStorageWidthOfficialReservationRootPath,
} from './proof-storage-width-official-reservation.js';
import {
    createPackageManagerCommand,
    runCommandAndCaptureOutput,
    type CapturedCommandResult,
    type CommandInvocation,
} from './run-command.js';
import { validateProofStorageWidthEvidenceArtifacts } from './run-proof-storage-width-evidence.js';

const laneLabel = 'Proof-storage width release WebAssembly evidence';
const scriptName = 'test:browser:proof-storage-width-evidence';
const browserOfficialSampleOwner = scriptName;
const testProjectLabel = 'proof-storage-width-browser-evidence';
const testProjectName = proofStorageWidthBrowserEvidenceProjectName;
const browserTestFile = proofStorageWidthBrowserEvidenceTestGlobs[0];
const browserEvidenceCargoFeature = 'proof-storage-width-browser-evidence';
const wasmEvidenceFeatureEnvironmentVariable =
    'SEALED_LATTICE_WASM_CARGO_FEATURES';
const expectedWasmHashEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_EXPECTED_WASM_SHA256_HEX';
const nativeBindingEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_NATIVE_BINDING';
const databaseNameEnvironmentVariable =
    'VITE_SEALED_LATTICE_PROOF_STORAGE_WIDTH_BROWSER_DATABASE_NAME';
const resourceSampleIntervalMilliseconds = 100;
const maximumOperationWindowGapMilliseconds = 500;
const plausibleBrowserProjectionNanoseconds = 120n * 60n * 1_000_000_000n;
const setupContributionPlanningTargetNanoseconds = 20n * 60n * 1_000_000_000n;
const terabyteScaleByteLength = 1_099_511_627_776n;
const billionTransactions = 1_000_000_000n;
const exactCommitHashPattern = /^[0-9a-f]{40}$/u;
const exactSha256HexPattern = /^[0-9a-f]{64}$/u;
const recoveryOrdinal = 1;
const recoveryRepairFilePaths = Object.freeze([
    'tests/node/tools/browser-test-project-selection.test.ts',
    'tests/node/tools/proof-storage-width-browser-evidence-runner.test.ts',
    'tools/ci/browser-test-project-selection.ts',
    'tools/ci/run-proof-storage-width-browser-evidence.ts',
    'vitest.config.ts',
] as const);
const processedWasmKernelPath = path.resolve(
    'packages',
    'wasm',
    'dist',
    'sealed-lattice-kernel.wasm',
);
const publicSdkWasmKernelPath = path.resolve(
    'packages',
    'sdk',
    'dist',
    'sealed-lattice-kernel.wasm',
);

export const proofStorageWidthBrowserEvidenceVitestArguments = Object.freeze([
    'exec',
    'vitest',
    '--project',
    testProjectName,
    '--run',
    browserTestFile,
    '--retry=0',
] as const);

export const proofStorageWidthBrowserEvidenceStaticPreflightArguments =
    Object.freeze([
        'exec',
        'vitest',
        'list',
        '--staticParse',
        '--filesOnly',
        '--project',
        testProjectName,
        browserTestFile,
    ] as const);

type JsonObject = Readonly<Record<string, unknown>>;

type RepositoryState = Readonly<{
    commitHash: string;
    treeDirty: boolean;
}>;

type RepositoryCheckpoint =
    | 'after'
    | 'before'
    | 'closure-after'
    | 'initial'
    | 'pre-operation';

type RecoveryArtifactProfile = Readonly<{
    relativePath: string;
    sha256Hex: string;
}>;

export type ProofStorageWidthBrowserPreOperationRecoveryProfile = Readonly<{
    failedArtifacts: Readonly<{
        diagnostics: RecoveryArtifactProfile;
        events: RecoveryArtifactProfile;
        metadata: RecoveryArtifactProfile;
        output: RecoveryArtifactProfile;
        processGuard: RecoveryArtifactProfile;
        resources: RecoveryArtifactProfile;
        summary: RecoveryArtifactProfile;
    }>;
    failedReservation: RecoveryArtifactProfile &
        Readonly<{ identitySha256Hex: string }>;
    failedRunDirectoryPath: string;
    nativeAggregateSha256Hex: string;
    nativeSourceCommitHash: string;
    rawWasmSha256Hex: string;
    recoveryOrdinal: 1;
}>;

export const proofStorageWidthBrowserPreOperationRecoveryProfile =
    Object.freeze({
        failedArtifacts: {
            diagnostics: {
                relativePath: 'diagnostics.txt',
                sha256Hex:
                    'ab2b76edc2e8efa7aa6d2c8f9ba78d01718fac19ae11f641f0565f866106e057',
            },
            events: {
                relativePath: 'events.jsonl',
                sha256Hex:
                    '3cc4141c42995ac25bd11165b00edfc2f30237c43f01cab65fc9ed3505492260',
            },
            metadata: {
                relativePath: 'metadata.json',
                sha256Hex:
                    'e236051d3784117eb59d3c6718a51484f3d69afb843fd18e8d8682d692b63481',
            },
            output: {
                relativePath: 'output.log',
                sha256Hex:
                    'accb98c77d60690742b8b10e1020f3e024f7b98b0636b7fca9bb3efa52dc3b7a',
            },
            processGuard: {
                relativePath:
                    'resources/process-memory-guard-proof-storage-width-browser.jsonl',
                sha256Hex:
                    '9018fdfded68ab6d4f91414bab499c82bae4f91b561189d5b696f292ea03efbb',
            },
            resources: {
                relativePath: 'resources.jsonl',
                sha256Hex:
                    'd4725b19a80acd48268767c7decc58419e30c43c2184a0ba7301bf3ca1962c81',
            },
            summary: {
                relativePath: 'summary.json',
                sha256Hex:
                    'f06bd97401c304a093126304f32b1c358a86ac0688dc63d34cdc68a851522292',
            },
        },
        failedReservation: {
            identitySha256Hex:
                '914a141e244d690c1bb53ab24cb4cab3a614698bc0118a648dcaa1a4d15cb317',
            relativePath:
                'browser/914a141e244d690c1bb53ab24cb4cab3a614698bc0118a648dcaa1a4d15cb317/browser-started.json',
            sha256Hex:
                'cd3d2ff2996aed5e29bc3556a1155dc52d1041d95333903c6cc777e81cbdb3a3',
        },
        failedRunDirectoryPath: path.resolve(
            'logs',
            '2026-07-23',
            '2026-07-23T08-38-46.141Z-test-browser-proof-storage-width-evidence',
        ),
        nativeAggregateSha256Hex:
            '79fabd816379edb7acd2999cf2bab3a1ca2a24864264616846d536600275da99',
        nativeSourceCommitHash: '604fffe55bede85cda2135d9293eb9f638a51d56',
        rawWasmSha256Hex:
            'daaefecebbe585b8c16c2456ae9aee8076114fdd633ab1540b92cbf22fa6c57d',
        recoveryOrdinal,
    } satisfies ProofStorageWidthBrowserPreOperationRecoveryProfile);

type CommandExecutor = (
    invocation: CommandInvocation,
    runLog: ActiveLocalRunLog,
) => Promise<CapturedCommandResult>;

type ProcessedWasmBinding = Readonly<{
    byteLength: bigint;
    normalizedSha256Hex: string;
    rawSha256Hex: string;
}>;

type NativeWidthEvidenceLoader = (
    evidencePath: string,
    options?: Readonly<{ officialReservationRootPath?: string }>,
) => Promise<NativeWidthEvidence>;

export type NativeWidthEvidence = Readonly<{
    evidencePath: string;
    evidenceSha256Hex: string;
    fullWidthResult: ValidatedProofStorageWidthResult;
    fullWidthStaticPoint: ValidatedProofStorageWidthStaticPreflightPoint;
    nativeBinding: ProofStorageWidthBrowserNativeBinding;
    nativeBindingRecord: JsonObject;
    officialSampleReservationIdentitySha256Hex: string;
    repositoryCommitHash: string;
    representativeResult: ValidatedProofStorageWidthResult;
    representativeStaticPoint: ValidatedProofStorageWidthStaticPreflightPoint;
}>;

export type ProofStorageWidthBrowserProjection = Readonly<{
    arithmeticNanoseconds: bigint;
    coordinatorNanoseconds: bigint;
    externalStorageWaitNanoseconds: bigint;
    operationNanoseconds: bigint;
    planningTargetNanoseconds: bigint;
    planningTargetRatio: Readonly<{
        denominator: bigint;
        numerator: bigint;
    }>;
    projectedCopiedBufferPeakByteLength: bigint;
    projectedWasmLinearMemoryPeakByteLength: bigint;
    representativeCopiedBufferPeakByteLength: bigint;
    representativeWasmLinearMemoryEndByteLength: bigint;
    representativeWasmLinearMemoryPeakByteLength: bigint;
    representativeWasmLinearMemoryStartByteLength: bigint;
    staticWasmMemoryCeilingGrowth: Readonly<{
        deltaByteLength: bigint;
        fullWidthByteLength: bigint;
        representativeByteLength: bigint;
    }>;
    workerYieldNanoseconds: bigint;
}>;

export type ProofStorageWidthBrowserProjectionViolation =
    | 'billion-scale-external-transaction-count'
    | 'copied-buffer-byte-length'
    | 'operation-time-projection'
    | 'terabyte-scale-external-io'
    | 'wasm-linear-memory-byte-length';

export type ProofStorageWidthBrowserProjectionDecision = Readonly<{
    outcome: 'eligible' | 'ineligible';
    violations: readonly ProofStorageWidthBrowserProjectionViolation[];
}>;

export type ProofStorageWidthBrowserProjectionPoint = Pick<
    ValidatedProofStorageWidthResult,
    | 'elapsedNanoseconds'
    | 'externalCommittedTransactionCount'
    | 'externalIoByteLength'
    | 'ldeTransformCount'
    | 'publicBaseLeafColumnCount'
>;

export type ProofStorageWidthBrowserStaticProjectionPoint = Pick<
    ValidatedProofStorageWidthStaticPreflightPoint,
    'publicBaseLeafColumnCount' | 'wasmMemoryByteLengthCeiling'
>;

export type ProofStorageWidthBrowserEvidenceDependencies = Readonly<{
    deriveProcessedWasmBinding?: () => Promise<ProcessedWasmBinding>;
    executeCommand?: CommandExecutor;
    loadNativeWidthEvidence?: NativeWidthEvidenceLoader;
    officialReservationRootPath?: string;
    processMemoryGuard?: ProcessMemoryGuard;
    processedWasmKernelPath?: string;
    preOperationRecoveryProfile?: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    publicSdkWasmKernelPath?: string;
    readRepositoryState?: (
        checkpoint: RepositoryCheckpoint,
        runLog: ActiveLocalRunLog,
    ) => Promise<RepositoryState>;
}>;

type ValidatedPreOperationRecovery = Readonly<{
    failedArtifacts: ProofStorageWidthBrowserPreOperationRecoveryProfile['failedArtifacts'];
    failedReservation: ProofStorageWidthBrowserPreOperationRecoveryProfile['failedReservation'];
    failedRunDirectoryPath: string;
    recoveryOrdinal: 1;
}>;

type ValidatedHarnessRepairTransition = Readonly<{
    changedFilePaths: readonly string[];
    harnessCommitHash: string;
    nativeSourceCommitHash: string;
}>;

const requireJsonObject = (value: unknown, fieldName: string): JsonObject => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} must be a JSON object.`);
    }
    return value as JsonObject;
};

const parseJson = (serialized: string, fieldName: string): unknown => {
    try {
        return JSON.parse(serialized) as unknown;
    } catch (error) {
        throw Object.assign(new Error(`${fieldName} is not valid JSON.`), {
            cause: error,
        });
    }
};

const requireString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string') {
        throw new Error(`${fieldName} must be a string.`);
    }
    return value;
};

const requireSha256Hex = (value: unknown, fieldName: string): string => {
    const digest = requireString(value, fieldName);
    if (!exactSha256HexPattern.test(digest)) {
        throw new Error(`${fieldName} must be a lowercase SHA-256 digest.`);
    }
    return digest;
};

const normalizeJsonValue = (value: unknown): unknown => {
    if (typeof value === 'bigint') {
        return value.toString();
    }
    if (Array.isArray(value)) {
        return value.map(normalizeJsonValue);
    }
    if (typeof value === 'object' && value !== null) {
        return Object.fromEntries(
            Object.entries(value)
                .sort(([leftFieldName], [rightFieldName]) =>
                    leftFieldName.localeCompare(rightFieldName),
                )
                .map(([fieldName, nestedValue]) => [
                    fieldName,
                    normalizeJsonValue(nestedValue),
                ]),
        );
    }
    return value;
};

const normalizedJsonEquals = (left: unknown, right: unknown): boolean =>
    JSON.stringify(normalizeJsonValue(left)) ===
    JSON.stringify(normalizeJsonValue(right));

const sha256Hex = (value: string | Uint8Array): string =>
    createHash('sha256').update(value).digest('hex');

const canonicalRelativePath = (rootPath: string, filePath: string): string =>
    path.relative(rootPath, filePath).split(path.sep).join('/');

const isPathWithinRoot = (rootPath: string, targetPath: string): boolean => {
    const relativePath = path.relative(rootPath, targetPath);
    return (
        relativePath.length === 0 ||
        (!relativePath.startsWith(`..${path.sep}`) &&
            relativePath !== '..' &&
            !path.isAbsolute(relativePath))
    );
};

const requireExistingPathWithoutLinks = async (input: {
    readonly expectedType: 'directory' | 'file';
    readonly fieldName: string;
    readonly path: string;
}): Promise<string> => {
    const resolvedPath = path.resolve(input.path);
    const parsedPath = path.parse(resolvedPath);
    const relativeSegments = path
        .relative(parsedPath.root, resolvedPath)
        .split(path.sep)
        .filter((segment) => segment.length !== 0);
    let currentPath = parsedPath.root;
    const pathsToInspect = [currentPath];
    for (const segment of relativeSegments) {
        currentPath = path.join(currentPath, segment);
        pathsToInspect.push(currentPath);
    }
    for (const inspectedPath of pathsToInspect) {
        const statistics = await lstat(inspectedPath);
        if (statistics.isSymbolicLink()) {
            throw new Error(
                `${input.fieldName} crosses a symbolic link or junction.`,
            );
        }
    }
    const targetStatistics = await lstat(resolvedPath);
    if (
        (input.expectedType === 'directory' &&
            !targetStatistics.isDirectory()) ||
        (input.expectedType === 'file' && !targetStatistics.isFile())
    ) {
        throw new Error(
            `${input.fieldName} is not the required ${input.expectedType}.`,
        );
    }
    return path.resolve(await realpath(resolvedPath));
};

const requireCanonicalCustodyRoot = (
    rootPath: string,
    fieldName: string,
): Promise<string> =>
    requireExistingPathWithoutLinks({
        expectedType: 'directory',
        fieldName,
        path: rootPath,
    });

const resolveCanonicalAbsoluteCustodyFile = async (
    filePath: string,
    fieldName: string,
): Promise<string> => {
    if (!path.isAbsolute(filePath)) {
        throw new Error(`${fieldName} path must be absolute.`);
    }
    const resolvedFilePath = path.resolve(filePath);
    const canonicalFilePath = await requireExistingPathWithoutLinks({
        expectedType: 'file',
        fieldName,
        path: resolvedFilePath,
    });
    if (path.relative(resolvedFilePath, canonicalFilePath).length !== 0) {
        throw new Error(`${fieldName} changed its canonical custody path.`);
    }
    return canonicalFilePath;
};

const resolveExistingCustodyFile = async (input: {
    readonly fieldName: string;
    readonly relativePath: string;
    readonly rootPath: string;
}): Promise<string> => {
    if (path.isAbsolute(input.relativePath)) {
        throw new Error(`${input.fieldName} must be relative to its root.`);
    }
    const canonicalRootPath = await requireCanonicalCustodyRoot(
        input.rootPath,
        `${input.fieldName} root`,
    );
    const resolvedFilePath = path.resolve(
        canonicalRootPath,
        input.relativePath,
    );
    if (!isPathWithinRoot(canonicalRootPath, resolvedFilePath)) {
        throw new Error(`${input.fieldName} escapes its custody root.`);
    }
    const canonicalFilePath = await requireExistingPathWithoutLinks({
        expectedType: 'file',
        fieldName: input.fieldName,
        path: resolvedFilePath,
    });
    if (!isPathWithinRoot(canonicalRootPath, canonicalFilePath)) {
        throw new Error(
            `${input.fieldName} resolves outside its custody root.`,
        );
    }
    return canonicalFilePath;
};

const prepareExclusiveCustodyFile = async (input: {
    readonly fieldName: string;
    readonly relativePath: string;
    readonly rootPath: string;
}): Promise<string> => {
    if (path.isAbsolute(input.relativePath)) {
        throw new Error(`${input.fieldName} must be relative to its root.`);
    }
    const canonicalRootPath = await requireCanonicalCustodyRoot(
        input.rootPath,
        `${input.fieldName} root`,
    );
    const normalizedSegments = input.relativePath
        .split(/[\\/]/u)
        .filter((segment) => segment.length !== 0);
    if (
        normalizedSegments.length === 0 ||
        normalizedSegments.some(
            (segment) => segment === '.' || segment === '..',
        )
    ) {
        throw new Error(`${input.fieldName} has a non-canonical path.`);
    }
    const fileName = normalizedSegments[normalizedSegments.length - 1] ?? '';
    let currentDirectoryPath = canonicalRootPath;
    for (const directoryName of normalizedSegments.slice(0, -1)) {
        currentDirectoryPath = path.join(currentDirectoryPath, directoryName);
        await mkdir(currentDirectoryPath).catch((error: unknown) => {
            if (
                typeof error !== 'object' ||
                error === null ||
                !('code' in error) ||
                error.code !== 'EEXIST'
            ) {
                throw error;
            }
        });
        const canonicalDirectoryPath = await requireExistingPathWithoutLinks({
            expectedType: 'directory',
            fieldName: `${input.fieldName} parent`,
            path: currentDirectoryPath,
        });
        if (!isPathWithinRoot(canonicalRootPath, canonicalDirectoryPath)) {
            throw new Error(
                `${input.fieldName} parent resolves outside its custody root.`,
            );
        }
        currentDirectoryPath = canonicalDirectoryPath;
    }
    const filePath = path.join(currentDirectoryPath, fileName);
    try {
        const canonicalExistingFilePath = await requireExistingPathWithoutLinks(
            {
                expectedType: 'file',
                fieldName: input.fieldName,
                path: filePath,
            },
        );
        if (!isPathWithinRoot(canonicalRootPath, canonicalExistingFilePath)) {
            throw new Error(
                `${input.fieldName} resolves outside its custody root.`,
            );
        }
    } catch (error) {
        if (
            typeof error !== 'object' ||
            error === null ||
            !('code' in error) ||
            error.code !== 'ENOENT'
        ) {
            throw error;
        }
    }
    return filePath;
};

const requireExactRelativeArtifactPath = (input: {
    readonly actual: unknown;
    readonly expected: string;
    readonly fieldName: string;
    readonly rootPath: string;
}): string => {
    const actual = requireString(input.actual, input.fieldName);
    if (actual !== input.expected || path.isAbsolute(actual)) {
        throw new Error(
            `${input.fieldName} must be the exact artifact path ${input.expected}.`,
        );
    }
    const resolvedPath = path.resolve(input.rootPath, actual);
    const relativePath = path.relative(input.rootPath, resolvedPath);
    if (
        relativePath.startsWith(`..${path.sep}`) ||
        relativePath === '..' ||
        path.isAbsolute(relativePath)
    ) {
        throw new Error(`${input.fieldName} escapes its artifact root.`);
    }
    return resolvedPath;
};

const requireArtifactDigest = (input: {
    readonly expectedSha256Hex: unknown;
    readonly fieldName: string;
    readonly value: string | Uint8Array;
}): string => {
    const expectedSha256Hex = requireSha256Hex(
        input.expectedSha256Hex,
        `${input.fieldName} digest`,
    );
    if (sha256Hex(input.value) !== expectedSha256Hex) {
        throw new Error(`${input.fieldName} does not match its bound digest.`);
    }
    return expectedSha256Hex;
};

const requireDirectoryAbsentOrEmpty = async (
    directoryPath: string,
    fieldName: string,
): Promise<void> => {
    let entries: string[];
    try {
        entries = await readdir(directoryPath);
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'ENOENT'
        ) {
            return;
        }
        throw error;
    }
    if (entries.length !== 0) {
        throw new Error(
            `${fieldName} must contain no prior operation artifact.`,
        );
    }
};

const listRecursiveRegularFilePaths = async (
    rootDirectoryPath: string,
): Promise<string[]> => {
    const filePaths: string[] = [];
    const visitDirectory = async (directoryPath: string): Promise<void> => {
        const entries = await readdir(directoryPath, { withFileTypes: true });
        for (const entry of entries) {
            const entryPath = path.join(directoryPath, entry.name);
            if (entry.isDirectory()) {
                await visitDirectory(entryPath);
            } else if (entry.isFile()) {
                filePaths.push(
                    path
                        .relative(rootDirectoryPath, entryPath)
                        .split(path.sep)
                        .join('/'),
                );
            } else {
                throw new Error(
                    'The predecessor run inventory contains an unsupported non-file entry.',
                );
            }
        }
    };
    await visitDirectory(rootDirectoryPath);
    return filePaths.sort((left, right) => left.localeCompare(right));
};

const parseJsonLines = (serialized: string, fieldName: string): JsonObject[] =>
    serialized
        .split(/\r?\n/u)
        .filter((line) => line.length !== 0)
        .map((line, lineIndex) =>
            requireJsonObject(
                parseJson(line, `${fieldName} line ${String(lineIndex + 1)}`),
                `${fieldName} line ${String(lineIndex + 1)}`,
            ),
        );

export const validateProofStorageWidthBrowserPreOperationRecovery = async (
    input: Readonly<{
        failedRunDirectoryPath: string;
        nativeEvidence: NativeWidthEvidence;
        officialReservationRootPath: string;
        profile?: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    }>,
): Promise<ValidatedPreOperationRecovery> => {
    const profile =
        input.profile ?? proofStorageWidthBrowserPreOperationRecoveryProfile;
    if (!path.isAbsolute(input.failedRunDirectoryPath)) {
        throw new Error(
            'The pre-operation recovery path must be an absolute failed run directory.',
        );
    }
    const declaredFailedRunDirectoryPath = path.resolve(
        input.failedRunDirectoryPath,
    );
    if (
        declaredFailedRunDirectoryPath !==
        path.resolve(profile.failedRunDirectoryPath)
    ) {
        throw new Error(
            'The pre-operation recovery path is not the one authorized failed run.',
        );
    }
    const failedRunDirectoryPath = await requireCanonicalCustodyRoot(
        declaredFailedRunDirectoryPath,
        'Predecessor failed-run custody root',
    );
    if (
        profile.recoveryOrdinal !== recoveryOrdinal ||
        input.nativeEvidence.repositoryCommitHash !==
            profile.nativeSourceCommitHash ||
        input.nativeEvidence.evidenceSha256Hex !==
            profile.nativeAggregateSha256Hex
    ) {
        throw new Error(
            'The pre-operation recovery does not bind the exact native source and aggregate.',
        );
    }
    const artifactEntries = Object.entries(profile.failedArtifacts) as Array<
        [
            keyof ProofStorageWidthBrowserPreOperationRecoveryProfile['failedArtifacts'],
            RecoveryArtifactProfile,
        ]
    >;
    const artifactBytes = new Map<string, Buffer>();
    for (const [artifactName, artifactProfile] of artifactEntries) {
        const artifactPath = path.resolve(
            failedRunDirectoryPath,
            artifactProfile.relativePath,
        );
        const relativePath = path.relative(
            failedRunDirectoryPath,
            artifactPath,
        );
        if (
            path.isAbsolute(artifactProfile.relativePath) ||
            relativePath.startsWith(`..${path.sep}`) ||
            relativePath === '..' ||
            path.isAbsolute(relativePath)
        ) {
            throw new Error(
                `The failed ${artifactName} artifact path escapes its run directory.`,
            );
        }
        const custodyArtifactPath = await resolveExistingCustodyFile({
            fieldName: `Failed ${artifactName} artifact`,
            relativePath: artifactProfile.relativePath,
            rootPath: failedRunDirectoryPath,
        });
        const bytes = await readFile(custodyArtifactPath);
        if (sha256Hex(bytes) !== artifactProfile.sha256Hex) {
            throw new Error(
                `The failed ${artifactName} artifact changed after the pre-operation failure.`,
            );
        }
        artifactBytes.set(artifactName, bytes);
    }
    const expectedFailedRunFilePaths = artifactEntries
        .map(([, artifactProfile]) =>
            artifactProfile.relativePath.split(path.sep).join('/'),
        )
        .sort((left, right) => left.localeCompare(right));
    const actualFailedRunFilePaths = await listRecursiveRegularFilePaths(
        failedRunDirectoryPath,
    );
    if (
        !normalizedJsonEquals(
            actualFailedRunFilePaths,
            expectedFailedRunFilePaths,
        )
    ) {
        throw new Error(
            'The predecessor run recursive file inventory changed after the pre-operation failure.',
        );
    }
    const summary = requireJsonObject(
        parseJson(
            artifactBytes.get('summary')?.toString('utf8') ?? '',
            'Failed browser run summary',
        ),
        'Failed browser run summary',
    );
    if (
        summary.exitCode !== 1 ||
        summary.failedCommandId !==
            'vitest-proof-storage-width-browser-evidence' ||
        summary.repositoryCommitHash !== profile.nativeSourceCommitHash ||
        summary.repositoryTreeDirty !== false ||
        summary.resultClassification !== 'runner-failure'
    ) {
        throw new Error(
            'The predecessor summary is not the authorized clean pre-operation runner failure.',
        );
    }
    const output = artifactBytes.get('output')?.toString('utf8') ?? '';
    const duplicateProjectError =
        'The project name "chromium-proof-storage-width-evidence" was already defined.';
    if (
        !output.includes(duplicateProjectError) ||
        output.includes('"event":"proof-storage-width-browser-evidence"')
    ) {
        throw new Error(
            'The predecessor output is not the authorized project-resolution failure.',
        );
    }
    const events = parseJsonLines(
        artifactBytes.get('events')?.toString('utf8') ?? '',
        'Failed browser run events',
    );
    const permittedRunEventTypes = new Set([
        'command-finished',
        'command-prepared',
        'command-started',
        'heavy-lane-lease-acquired',
        'heavy-lane-lease-released',
        'run-finished',
        'run-heartbeat',
        'run-started',
    ]);
    if (
        events.length === 0 ||
        events.some(
            (event) =>
                typeof event.eventType !== 'string' ||
                !permittedRunEventTypes.has(event.eventType),
        )
    ) {
        throw new Error(
            'The predecessor run contains a browser, test, worker, or measurement event.',
        );
    }
    const guardedCommandFinished = events.filter(
        (event) =>
            event.eventType === 'command-finished' &&
            event.commandId === 'vitest-proof-storage-width-browser-evidence',
    );
    if (guardedCommandFinished.length !== 1) {
        throw new Error(
            'The predecessor run must contain exactly one failed configuration launch.',
        );
    }
    const processGuardRecords = parseJsonLines(
        artifactBytes.get('processGuard')?.toString('utf8') ?? '',
        'Failed browser process guard',
    );
    const childExitRecords = processGuardRecords.filter(
        (record) => record.eventType === 'child-exited',
    );
    const resourceSamples = processGuardRecords.filter(
        (record) => record.eventType === 'resource-sample',
    );
    if (
        childExitRecords.length !== 1 ||
        childExitRecords[0]?.exitCode !== 1 ||
        childExitRecords[0]?.durationMilliseconds !== 608 ||
        resourceSamples.length === 0 ||
        resourceSamples.some(
            (sample) => sample.ioReadBytes !== 0 || sample.ioWriteBytes !== 0,
        )
    ) {
        throw new Error(
            'The predecessor process guard does not prove one zero-I/O configuration failure.',
        );
    }
    await Promise.all(
        ['attachments', 'diagnostic-reports', 'tests', 'vitest-results'].map(
            (directoryName) =>
                requireDirectoryAbsentOrEmpty(
                    path.join(failedRunDirectoryPath, directoryName),
                    `Failed browser ${directoryName} directory`,
                ),
        ),
    );
    const failedReservationPath = await resolveExistingCustodyFile({
        fieldName: 'Predecessor browser reservation',
        relativePath: profile.failedReservation.relativePath,
        rootPath: input.officialReservationRootPath,
    });
    const failedReservationBytes = await readFile(failedReservationPath);
    if (
        sha256Hex(failedReservationBytes) !==
        profile.failedReservation.sha256Hex
    ) {
        throw new Error(
            'The predecessor browser reservation changed after the failed launch.',
        );
    }
    const failedReservationRecords = parseJsonLines(
        failedReservationBytes.toString('utf8'),
        'Failed browser reservation',
    );
    if (
        failedReservationRecords.length !== 2 ||
        failedReservationRecords[0]?.eventType !==
            'official-browser-width-sample-started' ||
        failedReservationRecords[0]?.identitySha256Hex !==
            profile.failedReservation.identitySha256Hex ||
        failedReservationRecords[0]?.nativeAggregateSha256Hex !==
            profile.nativeAggregateSha256Hex ||
        failedReservationRecords[0]?.rawWasmSha256Hex !==
            profile.rawWasmSha256Hex ||
        failedReservationRecords[0]?.sourceCommitHash !==
            profile.nativeSourceCommitHash ||
        failedReservationRecords[0]?.width !== 512 ||
        failedReservationRecords[1]?.eventType !== 'official-sample-outcome' ||
        failedReservationRecords[1]?.outcome !== 'failed'
    ) {
        throw new Error(
            'The predecessor browser reservation is not the exact failed pre-operation marker.',
        );
    }
    return Object.freeze({
        failedArtifacts: profile.failedArtifacts,
        failedReservation: profile.failedReservation,
        failedRunDirectoryPath,
        recoveryOrdinal,
    });
};

export const parseProofStorageWidthBrowserStaticPreflightOutput = (
    stdout: string,
): string => {
    const listedFiles = stdout
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => line.length !== 0);
    const projectPrefix = `[${testProjectName}] `;
    const listedFile = listedFiles[0];
    if (
        listedFiles.length !== 1 ||
        listedFile === undefined ||
        !listedFile.startsWith(projectPrefix) ||
        path.resolve(listedFile.slice(projectPrefix.length)) !==
            path.resolve(browserTestFile)
    ) {
        throw new Error(
            'The browser static preflight must resolve exactly the fixed evidence test file.',
        );
    }
    return browserTestFile;
};

export const loadNativeWidthEvidence = async (
    evidencePath: string,
    options: Readonly<{ officialReservationRootPath?: string }> = {},
): Promise<NativeWidthEvidence> => {
    const canonicalEvidencePath = await resolveCanonicalAbsoluteCustodyFile(
        evidencePath,
        'Native width-evidence aggregate',
    );
    const serializedEvidenceBeforeValidation = await readFile(
        canonicalEvidencePath,
    );
    const evidence = await validateProofStorageWidthEvidenceArtifacts(
        canonicalEvidencePath,
        options,
    );
    const serializedEvidenceAfterValidation = await readFile(
        await resolveCanonicalAbsoluteCustodyFile(
            canonicalEvidencePath,
            'Reopened native width-evidence aggregate',
        ),
    );
    if (
        !serializedEvidenceBeforeValidation.equals(
            serializedEvidenceAfterValidation,
        )
    ) {
        throw new Error(
            'The native width evidence changed while its artifacts were being validated.',
        );
    }
    const representativeStaticPoint = evidence.staticPreflight.points.find(
        (point) =>
            point.publicBaseLeafColumnCount ===
            proofStorageWidthBrowserEvidenceProfile.representativeWidth,
    );
    const fullWidthStaticPoint = evidence.staticPreflight.points.find(
        (point) => point.publicBaseLeafColumnCount === 3_451,
    );
    if (
        representativeStaticPoint === undefined ||
        fullWidthStaticPoint === undefined
    ) {
        throw new Error(
            'Validated native width evidence omitted a required static projection point.',
        );
    }
    return Object.freeze({
        evidencePath: canonicalEvidencePath,
        evidenceSha256Hex: createHash('sha256')
            .update(serializedEvidenceAfterValidation)
            .digest('hex'),
        fullWidthResult: evidence.fullWidthPoint.result,
        fullWidthStaticPoint,
        nativeBinding: parseProofStorageWidthBrowserNativeBinding(
            evidence.representativePoint.resultRecord,
        ),
        nativeBindingRecord: evidence.representativePoint.resultRecord,
        officialSampleReservationIdentitySha256Hex:
            evidence.officialSampleReservationIdentitySha256Hex,
        repositoryCommitHash: evidence.repositoryCommitHash,
        representativeResult: evidence.representativePoint.result,
        representativeStaticPoint,
    });
};

const scaledCeiling = (
    value: bigint,
    numerator: bigint,
    denominator: bigint,
    fieldName: string,
): bigint => {
    if (denominator === 0n) {
        throw new Error(`${fieldName} has a zero scaling denominator.`);
    }
    return (value * numerator + denominator - 1n) / denominator;
};

const maximumBigInt = (values: readonly bigint[]): bigint => {
    const first = values[0];
    if (first === undefined) {
        throw new Error('Cannot derive a maximum from an empty collection.');
    }
    return values
        .slice(1)
        .reduce((maximum, value) => (value > maximum ? value : maximum), first);
};

const maximumUnsigned64 = (1n << 64n) - 1n;

const checkedNonnegativeDifference = (input: {
    readonly fieldName: string;
    readonly minuend: bigint;
    readonly subtrahend: bigint;
}): bigint => {
    if (input.minuend < 0n || input.subtrahend < 0n) {
        throw new Error(`${input.fieldName} requires nonnegative operands.`);
    }
    if (input.minuend < input.subtrahend) {
        throw new Error(`${input.fieldName} would be negative.`);
    }
    return input.minuend - input.subtrahend;
};

const checkedNonnegativeUnsigned64Sum = (input: {
    readonly fieldName: string;
    readonly left: bigint;
    readonly right: bigint;
}): bigint => {
    if (input.left < 0n || input.right < 0n) {
        throw new Error(`${input.fieldName} requires nonnegative operands.`);
    }
    const sum = input.left + input.right;
    if (sum > maximumUnsigned64) {
        throw new Error(`${input.fieldName} exceeds u64.`);
    }
    return sum;
};

export const deriveProofStorageWidthBrowserProjection = (input: {
    readonly fullWidthResult: ProofStorageWidthBrowserProjectionPoint;
    readonly fullWidthStaticPoint: ProofStorageWidthBrowserStaticProjectionPoint;
    readonly measurement: ProofStorageWidthBrowserMeasurement;
    readonly representativeResult: ProofStorageWidthBrowserProjectionPoint;
    readonly representativeStaticPoint: ProofStorageWidthBrowserStaticProjectionPoint;
}): ProofStorageWidthBrowserProjection => {
    if (
        input.representativeResult.publicBaseLeafColumnCount !==
            proofStorageWidthBrowserEvidenceProfile.representativeWidth ||
        input.fullWidthResult.publicBaseLeafColumnCount !== 3_451 ||
        input.representativeStaticPoint.publicBaseLeafColumnCount !==
            proofStorageWidthBrowserEvidenceProfile.representativeWidth ||
        input.fullWidthStaticPoint.publicBaseLeafColumnCount !== 3_451
    ) {
        throw new Error(
            'The browser projection requires the fixed width-512 and width-3451 points.',
        );
    }
    const staticWasmMemoryCeilingDeltaByteLength = checkedNonnegativeDifference(
        {
            fieldName: 'Static WebAssembly memory ceiling growth',
            minuend: input.fullWidthStaticPoint.wasmMemoryByteLengthCeiling,
            subtrahend:
                input.representativeStaticPoint.wasmMemoryByteLengthCeiling,
        },
    );
    const staticWasmMemoryCeilingGrowth = Object.freeze({
        deltaByteLength: staticWasmMemoryCeilingDeltaByteLength,
        fullWidthByteLength:
            input.fullWidthStaticPoint.wasmMemoryByteLengthCeiling,
        representativeByteLength:
            input.representativeStaticPoint.wasmMemoryByteLengthCeiling,
    });
    const representativeExternalIo =
        input.representativeResult.externalIoByteLength;
    const fullExternalIo = input.fullWidthResult.externalIoByteLength;
    const arithmeticNanoseconds = scaledCeiling(
        input.measurement.arithmeticNanoseconds,
        input.fullWidthResult.elapsedNanoseconds,
        input.representativeResult.elapsedNanoseconds,
        'arithmetic projection',
    );
    const storageScaleNumerators = [
        scaledCeiling(
            fullExternalIo,
            1_000_000_000n,
            representativeExternalIo,
            'external-I/O projection ratio',
        ),
        scaledCeiling(
            input.fullWidthResult.externalCommittedTransactionCount,
            1_000_000_000n,
            input.representativeResult.externalCommittedTransactionCount,
            'transaction projection ratio',
        ),
    ];
    const storageScaleNumerator = maximumBigInt(storageScaleNumerators);
    const externalStorageWaitNanoseconds = scaledCeiling(
        input.measurement.externalStorageWaitNanoseconds,
        storageScaleNumerator,
        1_000_000_000n,
        'external-storage wait projection',
    );
    const yieldScaleNumerator = maximumBigInt([
        storageScaleNumerator,
        scaledCeiling(
            input.fullWidthResult.ldeTransformCount,
            1_000_000_000n,
            input.representativeResult.ldeTransformCount,
            'worker-yield transform ratio',
        ),
    ]);
    const workerYieldNanoseconds = scaledCeiling(
        input.measurement.workerYieldNanoseconds,
        yieldScaleNumerator,
        1_000_000_000n,
        'worker-yield projection',
    );
    const coordinatorNanoseconds = scaledCeiling(
        input.measurement.coordinatorNanoseconds,
        maximumBigInt([
            yieldScaleNumerator,
            scaledCeiling(
                BigInt(input.fullWidthResult.publicBaseLeafColumnCount),
                1_000_000_000n,
                BigInt(input.representativeResult.publicBaseLeafColumnCount),
                'coordinator width ratio',
            ),
        ]),
        1_000_000_000n,
        'coordinator projection',
    );
    const operationNanoseconds =
        arithmeticNanoseconds +
        externalStorageWaitNanoseconds +
        workerYieldNanoseconds +
        coordinatorNanoseconds;
    return Object.freeze({
        arithmeticNanoseconds,
        coordinatorNanoseconds,
        externalStorageWaitNanoseconds,
        operationNanoseconds,
        planningTargetNanoseconds: setupContributionPlanningTargetNanoseconds,
        planningTargetRatio: Object.freeze({
            denominator: setupContributionPlanningTargetNanoseconds,
            numerator: operationNanoseconds,
        }),
        projectedCopiedBufferPeakByteLength:
            input.measurement.copiedBufferPeakByteLength,
        projectedWasmLinearMemoryPeakByteLength:
            checkedNonnegativeUnsigned64Sum({
                fieldName:
                    'Projected full-width WebAssembly linear-memory peak',
                left: input.measurement.wasmLinearMemoryPeakByteLength,
                right: staticWasmMemoryCeilingDeltaByteLength,
            }),
        representativeCopiedBufferPeakByteLength:
            input.measurement.copiedBufferPeakByteLength,
        representativeWasmLinearMemoryEndByteLength:
            input.measurement.wasmLinearMemoryEndByteLength,
        representativeWasmLinearMemoryPeakByteLength:
            input.measurement.wasmLinearMemoryPeakByteLength,
        representativeWasmLinearMemoryStartByteLength:
            input.measurement.wasmLinearMemoryStartByteLength,
        staticWasmMemoryCeilingGrowth,
        workerYieldNanoseconds,
    });
};

export const evaluateProofStorageWidthBrowserProjectionEligibility = (input: {
    readonly fullWidthResult: ProofStorageWidthBrowserProjectionPoint;
    readonly projection: ProofStorageWidthBrowserProjection;
}): ProofStorageWidthBrowserProjectionDecision => {
    const violations: ProofStorageWidthBrowserProjectionViolation[] = [];
    if (
        input.projection.projectedCopiedBufferPeakByteLength >
        proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
    ) {
        violations.push('copied-buffer-byte-length');
    }
    if (
        input.projection.projectedWasmLinearMemoryPeakByteLength >
        proofStorageWidthBrowserEvidenceProfile.maximumWasmLinearMemoryByteLength
    ) {
        violations.push('wasm-linear-memory-byte-length');
    }
    if (input.fullWidthResult.externalIoByteLength >= terabyteScaleByteLength) {
        violations.push('terabyte-scale-external-io');
    }
    if (
        input.fullWidthResult.externalCommittedTransactionCount >=
        billionTransactions
    ) {
        violations.push('billion-scale-external-transaction-count');
    }
    if (
        input.projection.operationNanoseconds >
        plausibleBrowserProjectionNanoseconds
    ) {
        violations.push('operation-time-projection');
    }
    return Object.freeze({
        outcome: violations.length === 0 ? 'eligible' : 'ineligible',
        violations: Object.freeze(violations),
    });
};

export const requireProofStorageWidthBrowserProjectionEligibility = (input: {
    readonly fullWidthResult: ProofStorageWidthBrowserProjectionPoint;
    readonly projection: ProofStorageWidthBrowserProjection;
}): void => {
    const firstViolation =
        evaluateProofStorageWidthBrowserProjectionEligibility(input)
            .violations[0];
    switch (firstViolation) {
        case undefined:
            return;
        case 'copied-buffer-byte-length':
            throw new Error(
                'The full-width browser projection exceeds the copied-buffer cap.',
            );
        case 'wasm-linear-memory-byte-length':
            throw new Error(
                'The full-width browser projection exceeds the WebAssembly linear-memory cap.',
            );
        case 'terabyte-scale-external-io':
            throw new Error(
                'The full-width browser projection requires terabyte-scale external I/O.',
            );
        case 'billion-scale-external-transaction-count':
            throw new Error(
                'The full-width browser projection requires at least one billion transactions.',
            );
        case 'operation-time-projection':
            throw new Error(
                'The full-width release-browser projection exceeds 120 minutes.',
            );
    }
};

const executeRequiredCommand = async (input: {
    readonly command: CommandInvocation;
    readonly executeCommand: CommandExecutor;
    readonly runLog: ActiveLocalRunLog;
}): Promise<CapturedCommandResult> => {
    const result = await input.executeCommand(input.command, input.runLog);
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `${input.command.description} failed with exit code ${String(result.exitCode)}${
                result.terminationSignal === null
                    ? ''
                    : ` and signal ${result.terminationSignal}`
            }. The browser evidence run is not retried.`,
        );
    }
    return result;
};

const defaultCommandExecutor: CommandExecutor = (invocation, runLog) =>
    runCommandAndCaptureOutput(invocation, {
        echoOutput: true,
        runLog,
    });

const readRepositoryStateWithCommands = async (input: {
    readonly checkpoint: RepositoryCheckpoint;
    readonly executeCommand: CommandExecutor;
    readonly runLog: ActiveLocalRunLog;
}): Promise<RepositoryState> => {
    const commitResult = await executeRequiredCommand({
        command: {
            args: ['rev-parse', '--verify', 'HEAD^{commit}'],
            command: 'git',
            description: `read the ${input.checkpoint} browser width-evidence commit`,
            logFileSlug: `git-browser-width-${input.checkpoint}-commit`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    const commitHash = commitResult.stdout.trim();
    if (!exactCommitHashPattern.test(commitHash)) {
        throw new Error(
            `The ${input.checkpoint} browser width-evidence commit is malformed.`,
        );
    }
    const statusResult = await executeRequiredCommand({
        command: {
            args: [
                'status',
                '--porcelain=v1',
                '--untracked-files=all',
                '--ignore-submodules=none',
            ],
            command: 'git',
            description: `read the ${input.checkpoint} browser width-evidence status`,
            logFileSlug: `git-browser-width-${input.checkpoint}-status`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    return Object.freeze({
        commitHash,
        treeDirty: statusResult.stdout.length !== 0,
    });
};

const requireCleanPinnedRepository = (
    actual: RepositoryState,
    expectedCommitHash: string,
    checkpoint: string,
): void => {
    if (actual.treeDirty || actual.commitHash !== expectedCommitHash) {
        throw new Error(
            `The browser width-evidence ${checkpoint} checkpoint is not the exact clean native-evidence commit.`,
        );
    }
};

const validateHarnessRepairCommitTransition = async (input: {
    readonly executeCommand: CommandExecutor;
    readonly harnessCommitHash: string;
    readonly nativeSourceCommitHash: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<ValidatedHarnessRepairTransition> => {
    const parentResult = await executeRequiredCommand({
        command: {
            args: ['rev-list', '--parents', '-n', '1', input.harnessCommitHash],
            command: 'git',
            description: 'validate the browser recovery direct-child commit',
            logFileSlug: 'git-browser-width-recovery-parent',
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    if (
        parentResult.stdout.trim() !==
        `${input.harnessCommitHash} ${input.nativeSourceCommitHash}`
    ) {
        throw new Error(
            'The browser recovery harness commit is not the sole direct child of the native source commit.',
        );
    }
    const diffResult = await executeRequiredCommand({
        command: {
            args: [
                'diff',
                '--name-only',
                '--no-renames',
                input.nativeSourceCommitHash,
                input.harnessCommitHash,
            ],
            command: 'git',
            description: 'validate the browser recovery repair file set',
            logFileSlug: 'git-browser-width-recovery-diff',
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    const changedFilePaths = diffResult.stdout
        .split(/\r?\n/u)
        .map((filePath) => filePath.trim().replace(/\\/gu, '/'))
        .filter((filePath) => filePath.length !== 0)
        .sort((left, right) => left.localeCompare(right));
    if (!normalizedJsonEquals(changedFilePaths, recoveryRepairFilePaths)) {
        throw new Error(
            'The browser recovery commit diff is not exactly the five authorized harness files.',
        );
    }
    return Object.freeze({
        changedFilePaths,
        harnessCommitHash: input.harnessCommitHash,
        nativeSourceCommitHash: input.nativeSourceCommitHash,
    });
};

type RecoveryReservationIdentity = Readonly<{
    identityRecord: JsonObject;
    identitySha256Hex: string;
}>;

const buildBrowserRecoveryAuthorizationKey = (
    profile: ProofStorageWidthBrowserPreOperationRecoveryProfile,
): string =>
    sha256Hex(
        JSON.stringify({
            failedReservationIdentitySha256Hex:
                profile.failedReservation.identitySha256Hex,
            formatVersion: 1,
            nativeAggregateSha256Hex: profile.nativeAggregateSha256Hex,
            nativeSourceCommitHash: profile.nativeSourceCommitHash,
            recoveryOrdinal: profile.recoveryOrdinal,
        }),
    );

const buildBrowserRecoveryReservationIdentity = (input: {
    readonly harnessTransition: ValidatedHarnessRepairTransition;
    readonly nativeEvidence: NativeWidthEvidence;
    readonly preOperationRecovery: ValidatedPreOperationRecovery;
    readonly rawWasmSha256Hex: string;
}): RecoveryReservationIdentity => {
    const identityRecord = Object.freeze({
        changedFilePaths: input.harnessTransition.changedFilePaths,
        failedArtifacts: input.preOperationRecovery.failedArtifacts,
        failedReservationIdentitySha256Hex:
            input.preOperationRecovery.failedReservation.identitySha256Hex,
        failedReservationSha256Hex:
            input.preOperationRecovery.failedReservation.sha256Hex,
        formatVersion: 1,
        harnessCommitHash: input.harnessTransition.harnessCommitHash,
        nativeAggregateSha256Hex: input.nativeEvidence.evidenceSha256Hex,
        nativeReservationIdentitySha256Hex:
            input.nativeEvidence.officialSampleReservationIdentitySha256Hex,
        nativeSourceCommitHash: input.harnessTransition.nativeSourceCommitHash,
        officialOwner: browserOfficialSampleOwner,
        rawWasmSha256Hex: input.rawWasmSha256Hex,
        recoveryOrdinal,
        width: proofStorageWidthBrowserEvidenceProfile.representativeWidth,
    });
    return Object.freeze({
        identityRecord,
        identitySha256Hex: sha256Hex(JSON.stringify(identityRecord)),
    });
};

const createBrowserRecoveryPreflightAttempt = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly profile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    readonly reservationRootPath: string;
}): Promise<string> => {
    const attemptRelativePath = path.join(
        'browser-recovery-preflight',
        input.authorizationKeySha256Hex,
        'preflight-attempted.json',
    );
    const attemptPath = await prepareExclusiveCustodyFile({
        fieldName: 'Browser recovery singleton marker',
        relativePath: attemptRelativePath,
        rootPath: input.reservationRootPath,
    });
    const file = await open(attemptPath, 'wx').catch((error: unknown) => {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'EEXIST'
        ) {
            throw Object.assign(
                new Error(
                    'The one authorized browser recovery already attempted its static preflight; no second recovery is permitted.',
                ),
                { cause: error },
            );
        }
        throw error;
    });
    try {
        await resolveExistingCustodyFile({
            fieldName: 'Opened browser recovery singleton marker',
            relativePath: attemptRelativePath,
            rootPath: input.reservationRootPath,
        });
        await file.writeFile(
            `${JSON.stringify({
                authorizationKeySha256Hex: input.authorizationKeySha256Hex,
                eventType:
                    'official-browser-width-recovery-preflight-attempted',
                failedReservationIdentitySha256Hex:
                    input.profile.failedReservation.identitySha256Hex,
                recordedAtUnixMilliseconds: Date.now(),
                recoveryOrdinal: input.profile.recoveryOrdinal,
            })}\n`,
            'utf8',
        );
        await file.sync();
    } finally {
        await file.close();
    }
    return attemptPath;
};

type ValidatedBrowserRecoveryPreflightAttempt = Readonly<{
    outputSha256Hex: string;
    testFile: string;
}>;

type BrowserRecoveryAuthorization = Readonly<{
    authorizationKeySha256Hex: string;
    preflightAttemptPath: string;
    profile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    reservationRootPath: string;
}>;

const appendBrowserRecoveryStaticPreflightObservation = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly identity: RecoveryReservationIdentity;
    readonly reservationPath: string;
    readonly reservationRootPath: string;
    readonly result: CapturedCommandResult;
}): Promise<void> => {
    if (!path.isAbsolute(input.reservationPath)) {
        throw new Error(
            'The browser recovery static preflight marker path must be absolute.',
        );
    }
    if (input.result.stderr !== '') {
        throw new Error(
            'The browser static preflight must produce no standard-error diagnostics.',
        );
    }
    const custodyReservationPath = await resolveExistingCustodyFile({
        fieldName: 'Browser recovery static preflight marker',
        relativePath: path.join(
            'browser-recovery-preflight',
            input.authorizationKeySha256Hex,
            'preflight-attempted.json',
        ),
        rootPath: input.reservationRootPath,
    });
    if (custodyReservationPath !== path.resolve(input.reservationPath)) {
        throw new Error(
            'The browser recovery static preflight marker changed custody paths.',
        );
    }
    const serializedRecord = `${JSON.stringify({
        eventType: 'official-browser-width-recovery-static-preflight-observed',
        identitySha256Hex: input.identity.identitySha256Hex,
        recordedAtUnixMilliseconds: Date.now(),
        ...input.identity.identityRecord,
        staticListStderr: input.result.stderr,
        staticListStderrSha256Hex: sha256Hex(input.result.stderr),
        staticListStdout: input.result.stdout,
        staticListStdoutSha256Hex: sha256Hex(input.result.stdout),
    })}\n`;
    const file = await open(input.reservationPath, 'r+');
    try {
        const openedCustodyReservationPath = await resolveExistingCustodyFile({
            fieldName: 'Opened browser recovery static preflight marker',
            relativePath: path.join(
                'browser-recovery-preflight',
                input.authorizationKeySha256Hex,
                'preflight-attempted.json',
            ),
            rootPath: input.reservationRootPath,
        });
        if (
            openedCustodyReservationPath !== path.resolve(input.reservationPath)
        ) {
            throw new Error(
                'The opened browser recovery static preflight marker changed custody paths.',
            );
        }
        const statistics = await file.stat();
        const { bytesWritten } = await file.write(
            serializedRecord,
            statistics.size,
            'utf8',
        );
        if (bytesWritten !== Buffer.byteLength(serializedRecord, 'utf8')) {
            throw new Error(
                'The browser recovery static preflight observation was only partially appended.',
            );
        }
        await file.sync();
    } finally {
        await file.close();
    }
};

const validateBrowserRecoveryPreflightAttempt = (input: {
    readonly authorizationKeySha256Hex: string;
    readonly identity: RecoveryReservationIdentity;
    readonly profile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    readonly serialized: string;
    readonly terminalOutcomeRequired: boolean;
}): ValidatedBrowserRecoveryPreflightAttempt => {
    const records = parseJsonLines(
        input.serialized,
        'Browser recovery static preflight attempt',
    );
    if (
        records.length !== (input.terminalOutcomeRequired ? 3 : 2) ||
        records[0]?.authorizationKeySha256Hex !==
            input.authorizationKeySha256Hex ||
        records[0]?.eventType !==
            'official-browser-width-recovery-preflight-attempted' ||
        records[0]?.failedReservationIdentitySha256Hex !==
            input.profile.failedReservation.identitySha256Hex ||
        records[0]?.recoveryOrdinal !== input.profile.recoveryOrdinal ||
        typeof records[0]?.recordedAtUnixMilliseconds !== 'number' ||
        records[1]?.eventType !==
            'official-browser-width-recovery-static-preflight-observed' ||
        records[1]?.identitySha256Hex !== input.identity.identitySha256Hex ||
        !normalizedJsonEquals(
            Object.fromEntries(
                Object.keys(input.identity.identityRecord).map((fieldName) => [
                    fieldName,
                    records[1]?.[fieldName],
                ]),
            ),
            input.identity.identityRecord,
        ) ||
        typeof records[1]?.recordedAtUnixMilliseconds !== 'number'
    ) {
        throw new Error(
            'The browser recovery static preflight marker changed or did not validate exactly once.',
        );
    }
    if (
        input.terminalOutcomeRequired &&
        (records[2]?.eventType !== 'official-sample-outcome' ||
            records[2]?.outcome !== 'validated' ||
            typeof records[2]?.recordedAtUnixMilliseconds !== 'number')
    ) {
        throw new Error(
            'The browser recovery static preflight marker lacks its one validated terminal outcome.',
        );
    }
    const staticListStdout = requireString(
        records[1]?.staticListStdout,
        'Browser recovery static preflight stdout',
    );
    const staticListStderr = requireString(
        records[1]?.staticListStderr,
        'Browser recovery static preflight stderr',
    );
    const staticListStdoutSha256Hex = requireSha256Hex(
        records[1]?.staticListStdoutSha256Hex,
        'Browser recovery static preflight stdout digest',
    );
    const staticListStderrSha256Hex = requireSha256Hex(
        records[1]?.staticListStderrSha256Hex,
        'Browser recovery static preflight stderr digest',
    );
    if (
        staticListStderr !== '' ||
        sha256Hex(staticListStdout) !== staticListStdoutSha256Hex ||
        sha256Hex(staticListStderr) !== staticListStderrSha256Hex
    ) {
        throw new Error(
            'The browser recovery static preflight output or diagnostics changed.',
        );
    }
    return Object.freeze({
        outputSha256Hex: staticListStdoutSha256Hex,
        testFile:
            parseProofStorageWidthBrowserStaticPreflightOutput(
                staticListStdout,
            ),
    });
};

const appendBrowserRecoveryPreflightFailedOutcomeIfPending = async (input: {
    readonly authorization: BrowserRecoveryAuthorization;
    readonly failure: unknown;
}): Promise<void> => {
    const serialized = await readFile(
        await resolveExistingCustodyFile({
            fieldName: 'Browser recovery static preflight marker',
            relativePath: path.join(
                'browser-recovery-preflight',
                input.authorization.authorizationKeySha256Hex,
                'preflight-attempted.json',
            ),
            rootPath: input.authorization.reservationRootPath,
        }),
        'utf8',
    );
    const records = parseJsonLines(
        serialized,
        'Browser recovery static preflight attempt',
    );
    const finalRecord = records[records.length - 1];
    if (finalRecord?.eventType === 'official-sample-outcome') {
        if (
            ![2, 3].includes(records.length) ||
            (finalRecord.outcome !== 'failed' &&
                finalRecord.outcome !== 'validated') ||
            typeof finalRecord.recordedAtUnixMilliseconds !== 'number'
        ) {
            throw new Error(
                'The browser recovery singleton marker has a malformed terminal outcome.',
            );
        }
        return;
    }
    if (
        (records.length !== 1 && records.length !== 2) ||
        records[0]?.authorizationKeySha256Hex !==
            input.authorization.authorizationKeySha256Hex ||
        records[0]?.eventType !==
            'official-browser-width-recovery-preflight-attempted' ||
        records[0]?.failedReservationIdentitySha256Hex !==
            input.authorization.profile.failedReservation.identitySha256Hex ||
        records[0]?.recoveryOrdinal !==
            input.authorization.profile.recoveryOrdinal ||
        typeof records[0]?.recordedAtUnixMilliseconds !== 'number'
    ) {
        throw new Error(
            'The browser recovery singleton marker changed before its terminal failure could be recorded.',
        );
    }
    if (records.length === 2) {
        const staticListStdout = requireString(
            records[1]?.staticListStdout,
            'Browser recovery pending static preflight stdout',
        );
        const staticListStderr = requireString(
            records[1]?.staticListStderr,
            'Browser recovery pending static preflight stderr',
        );
        if (
            records[1]?.eventType !==
                'official-browser-width-recovery-static-preflight-observed' ||
            staticListStderr !== '' ||
            sha256Hex(staticListStdout) !==
                requireSha256Hex(
                    records[1]?.staticListStdoutSha256Hex,
                    'Browser recovery pending static preflight stdout digest',
                ) ||
            sha256Hex(staticListStderr) !==
                requireSha256Hex(
                    records[1]?.staticListStderrSha256Hex,
                    'Browser recovery pending static preflight stderr digest',
                )
        ) {
            throw new Error(
                'The browser recovery pending static preflight observation changed.',
            );
        }
        parseProofStorageWidthBrowserStaticPreflightOutput(staticListStdout);
    }
    const serializedFailureRecord = `${JSON.stringify({
        eventType: 'official-sample-outcome',
        failureName: errorName(input.failure),
        outcome: 'failed',
        recordedAtUnixMilliseconds: Date.now(),
    })}\n`;
    const file = await open(input.authorization.preflightAttemptPath, 'r+');
    try {
        const custodyMarkerPath = await resolveExistingCustodyFile({
            fieldName: 'Opened browser recovery static preflight marker',
            relativePath: path.join(
                'browser-recovery-preflight',
                input.authorization.authorizationKeySha256Hex,
                'preflight-attempted.json',
            ),
            rootPath: input.authorization.reservationRootPath,
        });
        if (
            custodyMarkerPath !==
            path.resolve(input.authorization.preflightAttemptPath)
        ) {
            throw new Error(
                'The opened browser recovery static preflight marker changed custody paths.',
            );
        }
        const statistics = await file.stat();
        const { bytesWritten } = await file.write(
            serializedFailureRecord,
            statistics.size,
            'utf8',
        );
        if (
            bytesWritten !== Buffer.byteLength(serializedFailureRecord, 'utf8')
        ) {
            throw new Error(
                'The browser recovery singleton failure was only partially appended.',
            );
        }
        await file.sync();
    } finally {
        await file.close();
    }
};

const createBrowserRecoveryReservation = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly identity: RecoveryReservationIdentity;
    readonly reservationRootPath: string;
    readonly runDirectoryPath: string;
}): Promise<string> => {
    const reservationRootPath = await requireCanonicalCustodyRoot(
        input.reservationRootPath,
        'Browser recovery reservation root',
    );
    const runDirectoryPath = await requireCanonicalCustodyRoot(
        input.runDirectoryPath,
        'Browser recovery run root',
    );
    if (isPathWithinRoot(runDirectoryPath, reservationRootPath)) {
        throw new Error(
            'The browser recovery reservation root must stay outside the run directory.',
        );
    }
    const reservationRelativePath = path.join(
        'browser-recovery',
        input.authorizationKeySha256Hex,
        'browser-recovery-started.json',
    );
    const reservationPath = await prepareExclusiveCustodyFile({
        fieldName: 'Browser recovery operation reservation',
        relativePath: reservationRelativePath,
        rootPath: reservationRootPath,
    });
    const file = await open(reservationPath, 'wx').catch((error: unknown) => {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'EEXIST'
        ) {
            throw Object.assign(
                new Error(
                    'The one authorized browser recovery already has a durable started reservation; no replacement operation is permitted.',
                ),
                { cause: error },
            );
        }
        throw error;
    });
    try {
        await resolveExistingCustodyFile({
            fieldName: 'Opened browser recovery operation reservation',
            relativePath: reservationRelativePath,
            rootPath: reservationRootPath,
        });
        await file.writeFile(
            `${JSON.stringify({
                authorizationKeySha256Hex: input.authorizationKeySha256Hex,
                eventType: 'official-browser-width-recovery-started',
                identitySha256Hex: input.identity.identitySha256Hex,
                ...input.identity.identityRecord,
                recordedAtUnixMilliseconds: Date.now(),
            })}\n`,
            'utf8',
        );
        await file.sync();
    } finally {
        await file.close();
    }
    return reservationPath;
};

const validateBrowserRecoveryReservationArtifact = (input: {
    readonly authorizationKeySha256Hex: string;
    readonly identity: RecoveryReservationIdentity;
    readonly serialized: string;
}): void => {
    const records = parseJsonLines(
        input.serialized,
        'Browser recovery reservation',
    );
    const start = records[0];
    const outcome = records[1];
    if (
        records.length !== 2 ||
        start?.authorizationKeySha256Hex !== input.authorizationKeySha256Hex ||
        start?.eventType !== 'official-browser-width-recovery-started' ||
        start.identitySha256Hex !== input.identity.identitySha256Hex ||
        !normalizedJsonEquals(
            Object.fromEntries(
                Object.keys(input.identity.identityRecord).map((fieldName) => [
                    fieldName,
                    start[fieldName],
                ]),
            ),
            input.identity.identityRecord,
        ) ||
        typeof start.recordedAtUnixMilliseconds !== 'number' ||
        !Number.isSafeInteger(start.recordedAtUnixMilliseconds) ||
        outcome?.eventType !== 'official-sample-outcome' ||
        outcome.outcome !== 'validated' ||
        typeof outcome.recordedAtUnixMilliseconds !== 'number' ||
        !Number.isSafeInteger(outcome.recordedAtUnixMilliseconds) ||
        outcome.recordedAtUnixMilliseconds < start.recordedAtUnixMilliseconds
    ) {
        throw new Error(
            'The browser recovery reservation changed or lacks one validated terminal outcome.',
        );
    }
};

const deriveProcessedWasmBinding = async (input: {
    readonly processedWasmKernelPath: string;
    readonly publicSdkWasmKernelPath: string;
}): Promise<ProcessedWasmBinding> => {
    const [canonicalProcessedWasmKernelPath, canonicalPublicSdkWasmKernelPath] =
        await Promise.all([
            resolveCanonicalAbsoluteCustodyFile(
                input.processedWasmKernelPath,
                'Processed producer WebAssembly artifact',
            ),
            resolveCanonicalAbsoluteCustodyFile(
                input.publicSdkWasmKernelPath,
                'Public SDK WebAssembly artifact',
            ),
        ]);
    const [producerBytes, publicSdkBytes] = await Promise.all([
        readFile(canonicalProcessedWasmKernelPath),
        readFile(canonicalPublicSdkWasmKernelPath),
    ]);
    if (!producerBytes.equals(publicSdkBytes)) {
        throw new Error(
            'The public SDK WebAssembly bytes differ from the processed producer artifact.',
        );
    }
    const byteLength = BigInt(producerBytes.byteLength);
    if (
        byteLength >
        proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
    ) {
        throw new Error(
            'The processed release WebAssembly module exceeds the absolute copied-buffer bound.',
        );
    }
    return Object.freeze({
        byteLength,
        normalizedSha256Hex: createHash('sha256')
            .update(normalizeTranscriptCoreKernelBytesForHash(producerBytes))
            .digest('hex'),
        rawSha256Hex: createHash('sha256').update(producerBytes).digest('hex'),
    });
};

export const parseProofStorageWidthBrowserMeasurementEvents = (input: {
    readonly expectedWasmSha256Hex: string;
    readonly serializedEvents: string;
}): ProofStorageWidthBrowserMeasurement => {
    const records = input.serializedEvents
        .split(/\r?\n/u)
        .filter((line) => line.length !== 0)
        .map((line, lineIndex) =>
            requireJsonObject(
                parseJson(
                    line,
                    `Browser test event line ${String(lineIndex + 1)}`,
                ),
                `Browser test event line ${String(lineIndex + 1)}`,
            ),
        );
    if (
        records.length !== 1 ||
        records[0]?.event !== 'proof-storage-width-browser-evidence'
    ) {
        throw new Error(
            'The browser width-evidence JSONL must contain exactly one measurement record and no unrelated records.',
        );
    }
    const event = records[0];
    if (event?.browser !== true) {
        throw new Error(
            'The proof-storage width measurement was not emitted by a browser.',
        );
    }
    const measurement = parseProofStorageWidthBrowserMeasurement(event);
    if (measurement.wasmSha256Hex !== input.expectedWasmSha256Hex) {
        throw new Error(
            'The browser width-evidence measurement used the wrong release WebAssembly module.',
        );
    }
    return measurement;
};

const requireArtifactAbsent = async (
    filePath: string,
    fieldName: string,
): Promise<void> => {
    try {
        await readFile(filePath);
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'ENOENT'
        ) {
            return;
        }
        throw error;
    }
    throw new Error(`${fieldName} already exists before the one-shot sample.`);
};

const errorName = (error: unknown): string =>
    error instanceof Error ? error.name : 'NonErrorFailure';

const combineAttemptAndRepositoryFailure = (input: {
    readonly attemptError: unknown;
    readonly repositoryError: unknown;
}): Error =>
    Object.assign(
        new Error(
            'The browser width-evidence repository changed or could not be checked after the attempted one-shot sample.',
        ),
        {
            attemptCause: input.attemptError,
            cause: input.repositoryError,
        },
    );

const validateBrowserOfficialReservationArtifact = (input: {
    readonly identitySha256Hex: string;
    readonly nativeAggregateSha256Hex: string;
    readonly officialOwner: string;
    readonly rawWasmSha256Hex: string;
    readonly serialized: string;
    readonly sourceCommitHash: string;
}): void => {
    const records = input.serialized
        .split(/\r?\n/u)
        .filter((line) => line.length !== 0)
        .map((line, lineIndex) =>
            requireJsonObject(
                parseJson(
                    line,
                    `Browser reservation line ${String(lineIndex + 1)}`,
                ),
                `Browser reservation line ${String(lineIndex + 1)}`,
            ),
        );
    if (records.length !== 2) {
        throw new Error(
            'The browser official reservation must contain exactly one start and one outcome record.',
        );
    }
    const start = records[0];
    const outcome = records[1];
    const startTimestamp = start?.recordedAtUnixMilliseconds;
    const outcomeTimestamp = outcome?.recordedAtUnixMilliseconds;
    if (
        start?.eventType !== 'official-browser-width-sample-started' ||
        start.identitySha256Hex !== input.identitySha256Hex ||
        start.nativeAggregateSha256Hex !== input.nativeAggregateSha256Hex ||
        start.officialOwner !== input.officialOwner ||
        start.rawWasmSha256Hex !== input.rawWasmSha256Hex ||
        start.sourceCommitHash !== input.sourceCommitHash ||
        typeof startTimestamp !== 'number' ||
        !Number.isSafeInteger(startTimestamp) ||
        startTimestamp < 0 ||
        start.width !==
            proofStorageWidthBrowserEvidenceProfile.representativeWidth
    ) {
        throw new Error(
            'The browser official reservation start record changed its canonical binding.',
        );
    }
    if (
        outcome?.eventType !== 'official-sample-outcome' ||
        outcome.outcome !== 'validated' ||
        typeof outcomeTimestamp !== 'number' ||
        !Number.isSafeInteger(outcomeTimestamp) ||
        outcomeTimestamp < startTimestamp
    ) {
        throw new Error(
            'The browser official reservation lacks one validated terminal outcome.',
        );
    }
};

const requireGuardMemoryLimitBinding = (input: {
    readonly expectedMemoryLimitBytes: number;
    readonly serializedGuard: string;
}): void => {
    if (
        !Number.isSafeInteger(input.expectedMemoryLimitBytes) ||
        input.expectedMemoryLimitBytes <= 0
    ) {
        throw new Error(
            'The browser process-memory limit must be a positive safe integer.',
        );
    }
    const firstLine = input.serializedGuard
        .split(/\r?\n/u)
        .find((line) => line.length !== 0);
    if (firstLine === undefined) {
        throw new Error('The browser process-memory guard artifact is empty.');
    }
    const guardStarted = requireJsonObject(
        parseJson(firstLine, 'Browser process-memory guard start record'),
        'Browser process-memory guard start record',
    );
    if (
        guardStarted.eventType !== 'guard-started' ||
        guardStarted.memoryLimitBytes !== input.expectedMemoryLimitBytes
    ) {
        throw new Error(
            'The browser process-memory guard does not bind the exact enforced memory limit.',
        );
    }
};

const writeJsonExclusively = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    await mkdir(path.dirname(filePath), { recursive: true });
    const file = await open(filePath, 'wx');
    try {
        await file.writeFile(
            `${JSON.stringify(normalizeJsonValue(value), null, 2)}\n`,
            'utf8',
        );
        await file.sync();
    } finally {
        await file.close();
    }
};

const requirePinnedRepositoryRecord = (input: {
    readonly expectedCommitHash: string;
    readonly fieldName: string;
    readonly value: unknown;
}): void => {
    const record = requireJsonObject(input.value, input.fieldName);
    if (
        record.commitHash !== input.expectedCommitHash ||
        record.treeDirty !== false
    ) {
        throw new Error(
            `${input.fieldName} must bind the exact clean evidence commit.`,
        );
    }
};

export const validateProofStorageWidthBrowserEvidenceArtifacts = async (
    attachmentPath: string,
    options: Readonly<{
        loadNativeWidthEvidence?: NativeWidthEvidenceLoader;
        officialReservationRootPath?: string;
        preOperationRecoveryProfile?: ProofStorageWidthBrowserPreOperationRecoveryProfile;
        processedWasmKernelPath?: string;
        publicSdkWasmKernelPath?: string;
    }> = {},
): Promise<void> => {
    if (!path.isAbsolute(attachmentPath)) {
        throw new Error(
            'The proof-storage width browser evidence path must be absolute.',
        );
    }
    const resolvedAttachmentPath = path.resolve(attachmentPath);
    const declaredRunDirectoryPath = path.resolve(
        path.dirname(resolvedAttachmentPath),
        '..',
    );
    const expectedAttachmentPath = path.resolve(
        declaredRunDirectoryPath,
        'attachments',
        'proof-storage-width-browser-evidence.json',
    );
    if (resolvedAttachmentPath !== expectedAttachmentPath) {
        throw new Error(
            'The browser evidence file is outside its exact run attachment location.',
        );
    }
    const runDirectoryPath = await requireCanonicalCustodyRoot(
        declaredRunDirectoryPath,
        'Browser evidence run custody root',
    );
    const custodyAttachmentPath = await resolveExistingCustodyFile({
        fieldName: 'Browser evidence attachment',
        relativePath: 'attachments/proof-storage-width-browser-evidence.json',
        rootPath: runDirectoryPath,
    });
    if (
        path.relative(custodyAttachmentPath, resolvedAttachmentPath).length !==
        0
    ) {
        throw new Error(
            'The browser evidence attachment changed its canonical custody path.',
        );
    }
    const configuredReservationRootPath =
        options.officialReservationRootPath ??
        defaultProofStorageWidthOfficialReservationRootPath;
    if (!path.isAbsolute(configuredReservationRootPath)) {
        throw new Error(
            'The official browser reservation root path must be absolute.',
        );
    }
    const reservationRootPath = await requireCanonicalCustodyRoot(
        configuredReservationRootPath,
        'Browser official reservation custody root',
    );
    const reservationRelativeToRun = path.relative(
        runDirectoryPath,
        reservationRootPath,
    );
    if (
        reservationRelativeToRun.length === 0 ||
        (!reservationRelativeToRun.startsWith(`..${path.sep}`) &&
            reservationRelativeToRun !== '..' &&
            !path.isAbsolute(reservationRelativeToRun))
    ) {
        throw new Error(
            'The official browser reservation root must stay outside the run directory.',
        );
    }
    const evidence = requireJsonObject(
        parseJson(
            await readFile(custodyAttachmentPath, 'utf8'),
            'Proof-storage width browser evidence',
        ),
        'Proof-storage width browser evidence',
    );
    if (evidence.formatVersion !== 4 && evidence.formatVersion !== 5) {
        throw new Error(
            'Proof-storage width browser evidence must use integrity format version four or recovery version five.',
        );
    }
    const isRecoveryEvidence = evidence.formatVersion === 5;
    const repository = requireJsonObject(evidence.repository, 'repository');
    const initialRepository = requireJsonObject(
        repository.initial,
        'repository.initial',
    );
    const repositoryCommitHash = requireString(
        initialRepository.commitHash,
        'repository.initial.commitHash',
    );
    if (!exactCommitHashPattern.test(repositoryCommitHash)) {
        throw new Error(
            'repository.initial.commitHash must be an exact lowercase commit hash.',
        );
    }
    for (const checkpoint of [
        'initial',
        'before',
        'preOperation',
        'after',
    ] as const) {
        requirePinnedRepositoryRecord({
            expectedCommitHash: repositoryCommitHash,
            fieldName: `repository.${checkpoint}`,
            value: repository[checkpoint],
        });
    }
    const recovery = isRecoveryEvidence
        ? requireJsonObject(evidence.recovery, 'recovery')
        : undefined;
    const nativeSourceCommitHash =
        recovery === undefined
            ? repositoryCommitHash
            : requireString(
                  recovery.nativeSourceCommitHash,
                  'recovery.nativeSourceCommitHash',
              );
    if (!exactCommitHashPattern.test(nativeSourceCommitHash)) {
        throw new Error(
            'The recovery native source commit must be an exact lowercase commit hash.',
        );
    }

    const artifacts = requireJsonObject(evidence.artifacts, 'artifacts');
    const nativeAggregate = requireJsonObject(
        artifacts.nativeAggregate,
        'artifacts.nativeAggregate',
    );
    const nativeAggregatePath = requireString(
        nativeAggregate.path,
        'artifacts.nativeAggregate.path',
    );
    if (
        !path.isAbsolute(nativeAggregatePath) ||
        nativeAggregatePath !== path.resolve(nativeAggregatePath)
    ) {
        throw new Error(
            'The bound native aggregate path must be absolute and canonical.',
        );
    }
    const custodyNativeAggregatePath =
        await resolveCanonicalAbsoluteCustodyFile(
            nativeAggregatePath,
            'Bound native aggregate artifact',
        );
    const serializedNativeAggregate = await readFile(
        custodyNativeAggregatePath,
    );
    const nativeAggregateSha256Hex = requireArtifactDigest({
        expectedSha256Hex: nativeAggregate.sha256Hex,
        fieldName: 'Native aggregate artifact',
        value: serializedNativeAggregate,
    });
    const nativeEvidence = await (
        options.loadNativeWidthEvidence ?? loadNativeWidthEvidence
    )(custodyNativeAggregatePath, {
        officialReservationRootPath: reservationRootPath,
    });
    if (
        nativeEvidence.evidenceSha256Hex !== nativeAggregateSha256Hex ||
        nativeEvidence.evidencePath !== custodyNativeAggregatePath ||
        nativeEvidence.repositoryCommitHash !== nativeSourceCommitHash
    ) {
        throw new Error(
            'The reopened native aggregate does not match its browser closure binding.',
        );
    }
    const embeddedNativeEvidence = requireJsonObject(
        evidence.nativeEvidence,
        'nativeEvidence',
    );
    const expectedEmbeddedNativeEvidence = {
        fullWidthResult: nativeEvidence.fullWidthResult,
        fullWidthStaticPoint: nativeEvidence.fullWidthStaticPoint,
        officialSampleReservationIdentitySha256Hex:
            nativeEvidence.officialSampleReservationIdentitySha256Hex,
        repositoryCommitHash: nativeEvidence.repositoryCommitHash,
        representativeResult: nativeEvidence.representativeResult,
        representativeStaticPoint: nativeEvidence.representativeStaticPoint,
    };
    if (
        !normalizedJsonEquals(
            embeddedNativeEvidence,
            expectedEmbeddedNativeEvidence,
        )
    ) {
        throw new Error(
            'The browser closure native summary does not match the reopened native aggregate.',
        );
    }
    let validatedRecovery: ValidatedPreOperationRecovery | undefined;
    if (recovery !== undefined) {
        validatedRecovery =
            await validateProofStorageWidthBrowserPreOperationRecovery({
                failedRunDirectoryPath: requireString(
                    recovery.failedRunDirectoryPath,
                    'recovery.failedRunDirectoryPath',
                ),
                nativeEvidence,
                officialReservationRootPath: reservationRootPath,
                profile: options.preOperationRecoveryProfile,
            });
        const staticPreflight = requireJsonObject(
            recovery.staticPreflight,
            'recovery.staticPreflight',
        );
        if (
            recovery.recoveryOrdinal !== recoveryOrdinal ||
            recovery.harnessCommitHash !== repositoryCommitHash ||
            !normalizedJsonEquals(
                recovery.changedFilePaths,
                recoveryRepairFilePaths,
            ) ||
            !normalizedJsonEquals(
                recovery.failedArtifacts,
                validatedRecovery.failedArtifacts,
            ) ||
            !normalizedJsonEquals(
                recovery.failedReservation,
                validatedRecovery.failedReservation,
            ) ||
            staticPreflight.testFile !== browserTestFile ||
            staticPreflight.testProjectName !== testProjectName ||
            !normalizedJsonEquals(
                staticPreflight.semanticArguments,
                proofStorageWidthBrowserEvidenceStaticPreflightArguments,
            ) ||
            !exactSha256HexPattern.test(
                requireString(
                    staticPreflight.outputSha256Hex,
                    'recovery.staticPreflight.outputSha256Hex',
                ),
            )
        ) {
            throw new Error(
                'The browser recovery closure changed its predecessor, commits, repair diff, ordinal, or static preflight binding.',
            );
        }
    }

    const guardArtifact = requireJsonObject(artifacts.guard, 'artifacts.guard');
    requireExactRelativeArtifactPath({
        actual: guardArtifact.path,
        expected:
            'resources/process-memory-guard-proof-storage-width-browser.jsonl',
        fieldName: 'artifacts.guard.path',
        rootPath: runDirectoryPath,
    });
    const guardPath = await resolveExistingCustodyFile({
        fieldName: 'Browser process-memory guard artifact',
        relativePath:
            'resources/process-memory-guard-proof-storage-width-browser.jsonl',
        rootPath: runDirectoryPath,
    });
    const browserEventsArtifact = requireJsonObject(
        artifacts.browserEvents,
        'artifacts.browserEvents',
    );
    requireExactRelativeArtifactPath({
        actual: browserEventsArtifact.path,
        expected: `tests/${testProjectLabel}.jsonl`,
        fieldName: 'artifacts.browserEvents.path',
        rootPath: runDirectoryPath,
    });
    const browserEventsPath = await resolveExistingCustodyFile({
        fieldName: 'Raw browser event artifact',
        relativePath: `tests/${testProjectLabel}.jsonl`,
        rootPath: runDirectoryPath,
    });
    const [serializedGuard, serializedEvents] = await Promise.all([
        readFile(guardPath, 'utf8'),
        readFile(browserEventsPath, 'utf8'),
    ]);
    requireArtifactDigest({
        expectedSha256Hex: guardArtifact.sha256Hex,
        fieldName: 'Browser process-memory guard artifact',
        value: serializedGuard,
    });
    requireArtifactDigest({
        expectedSha256Hex: browserEventsArtifact.sha256Hex,
        fieldName: 'Raw browser event artifact',
        value: serializedEvents,
    });

    const wasm = requireJsonObject(evidence.wasm, 'wasm');
    const expectedProcessedWasmKernelPath =
        await resolveCanonicalAbsoluteCustodyFile(
            path.resolve(
                options.processedWasmKernelPath ?? processedWasmKernelPath,
            ),
            'Reopened processed producer WebAssembly artifact',
        );
    const expectedPublicSdkWasmKernelPath =
        await resolveCanonicalAbsoluteCustodyFile(
            path.resolve(
                options.publicSdkWasmKernelPath ?? publicSdkWasmKernelPath,
            ),
            'Reopened public SDK WebAssembly artifact',
        );
    if (
        wasm.cargoFeature !== browserEvidenceCargoFeature ||
        wasm.producerPath !== expectedProcessedWasmKernelPath ||
        wasm.publicSdkPath !== expectedPublicSdkWasmKernelPath
    ) {
        throw new Error(
            'The browser closure changed its release WebAssembly feature or artifact paths.',
        );
    }
    const rawWasmSha256Hex = requireSha256Hex(
        wasm.rawSha256Hex,
        'wasm.rawSha256Hex',
    );
    const normalizedWasmSha256Hex = requireSha256Hex(
        wasm.normalizedSha256Hex,
        'wasm.normalizedSha256Hex',
    );
    if (
        recovery !== undefined &&
        rawWasmSha256Hex !==
            (
                options.preOperationRecoveryProfile ??
                proofStorageWidthBrowserPreOperationRecoveryProfile
            ).rawWasmSha256Hex
    ) {
        throw new Error(
            'The browser recovery closure changed the pinned raw WebAssembly bytes.',
        );
    }
    const [reopenedProcessedWasmKernelPath, reopenedPublicSdkWasmKernelPath] =
        await Promise.all([
            resolveCanonicalAbsoluteCustodyFile(
                expectedProcessedWasmKernelPath,
                'Reopened processed producer WebAssembly artifact',
            ),
            resolveCanonicalAbsoluteCustodyFile(
                expectedPublicSdkWasmKernelPath,
                'Reopened public SDK WebAssembly artifact',
            ),
        ]);
    const [producerBytes, publicSdkBytes] = await Promise.all([
        readFile(reopenedProcessedWasmKernelPath),
        readFile(reopenedPublicSdkWasmKernelPath),
    ]);
    if (!producerBytes.equals(publicSdkBytes)) {
        throw new Error(
            'The reopened producer and public SDK WebAssembly artifacts differ.',
        );
    }
    if (
        sha256Hex(producerBytes) !== rawWasmSha256Hex ||
        sha256Hex(normalizeTranscriptCoreKernelBytesForHash(producerBytes)) !==
            normalizedWasmSha256Hex ||
        wasm.processedByteLength !== String(producerBytes.byteLength)
    ) {
        throw new Error(
            'The reopened release WebAssembly bytes do not match the raw, normalized, or length binding.',
        );
    }
    if (
        BigInt(producerBytes.byteLength) >
        proofStorageWidthBrowserEvidenceProfile.maximumCopiedBufferByteLength
    ) {
        throw new Error(
            'The reopened release WebAssembly module exceeds the absolute copied-buffer bound.',
        );
    }

    const measurement = parseProofStorageWidthBrowserMeasurementEvents({
        expectedWasmSha256Hex: normalizedWasmSha256Hex,
        serializedEvents,
    });
    requireProofStorageWidthBrowserNativeMatch(
        measurement,
        nativeEvidence.nativeBinding,
    );
    if (!normalizedJsonEquals(evidence.measurement, measurement)) {
        throw new Error(
            'The browser closure measurement does not match its raw event artifact.',
        );
    }
    const operationMemory = extractProofStorageWidthOperationMemory({
        guardJsonLines: serializedGuard,
        operationFinishedAtUnixMilliseconds:
            measurement.operationFinishedAtUnixMilliseconds,
        operationStartedAtUnixMilliseconds:
            measurement.operationStartedAtUnixMilliseconds,
    });
    const guard = requireJsonObject(evidence.guard, 'guard');
    if (
        typeof guard.memoryLimitBytes !== 'number' ||
        !Number.isSafeInteger(guard.memoryLimitBytes) ||
        guard.memoryLimitBytes <= 0
    ) {
        throw new Error(
            'guard.memoryLimitBytes must be a positive safe integer.',
        );
    }
    requireGuardMemoryLimitBinding({
        expectedMemoryLimitBytes: guard.memoryLimitBytes,
        serializedGuard,
    });
    if (
        guard.maximumOperationWindowGapMilliseconds !==
            maximumOperationWindowGapMilliseconds ||
        guard.resourceSampleIntervalMilliseconds !==
            resourceSampleIntervalMilliseconds ||
        !normalizedJsonEquals(guard.operationMemory, operationMemory)
    ) {
        throw new Error(
            'The browser closure guard summary does not match its raw telemetry.',
        );
    }
    const projection = deriveProofStorageWidthBrowserProjection({
        fullWidthResult: nativeEvidence.fullWidthResult,
        fullWidthStaticPoint: nativeEvidence.fullWidthStaticPoint,
        measurement,
        representativeResult: nativeEvidence.representativeResult,
        representativeStaticPoint: nativeEvidence.representativeStaticPoint,
    });
    const decision = evaluateProofStorageWidthBrowserProjectionEligibility({
        fullWidthResult: nativeEvidence.fullWidthResult,
        projection,
    });
    if (!normalizedJsonEquals(evidence.projection, projection)) {
        throw new Error(
            'The browser closure projection does not match the reopened native and browser artifacts.',
        );
    }
    if (!normalizedJsonEquals(evidence.decision, decision)) {
        throw new Error(
            'The browser closure decision does not match the recomputed projection eligibility.',
        );
    }

    const invocation = requireJsonObject(evidence.invocation, 'invocation');
    const expectedInvocation = {
        retryCount: 0,
        semanticArguments: proofStorageWidthBrowserEvidenceVitestArguments,
        testFile: browserTestFile,
        testProjectName,
    };
    if (!normalizedJsonEquals(invocation, expectedInvocation)) {
        throw new Error(
            'The browser closure must bind the exact project, test file, and zero-retry invocation.',
        );
    }

    const officialReservation = requireJsonObject(
        evidence.officialSampleReservation,
        'officialSampleReservation',
    );
    const ordinaryReservationIdentity =
        recovery === undefined
            ? buildProofStorageWidthBrowserReservationIdentity({
                  nativeAggregateSha256Hex,
                  nativeReservationIdentitySha256Hex:
                      nativeEvidence.officialSampleReservationIdentitySha256Hex,
                  officialOwner: browserOfficialSampleOwner,
                  rawWasmSha256Hex,
                  sourceCommitHash: repositoryCommitHash,
              })
            : undefined;
    const recoveryReservationIdentity =
        recovery === undefined || validatedRecovery === undefined
            ? undefined
            : buildBrowserRecoveryReservationIdentity({
                  harnessTransition: {
                      changedFilePaths: recoveryRepairFilePaths,
                      harnessCommitHash: repositoryCommitHash,
                      nativeSourceCommitHash,
                  },
                  nativeEvidence,
                  preOperationRecovery: validatedRecovery,
                  rawWasmSha256Hex,
              });
    const expectedReservationIdentitySha256Hex =
        recoveryReservationIdentity?.identitySha256Hex ??
        ordinaryReservationIdentity?.identitySha256Hex;
    if (expectedReservationIdentitySha256Hex === undefined) {
        throw new Error(
            'The browser closure omitted its recomputed reservation identity.',
        );
    }
    const recoveryAuthorizationKeySha256Hex =
        validatedRecovery === undefined
            ? undefined
            : buildBrowserRecoveryAuthorizationKey(
                  options.preOperationRecoveryProfile ??
                      proofStorageWidthBrowserPreOperationRecoveryProfile,
              );
    if (recovery !== undefined) {
        const staticPreflight = requireJsonObject(
            recovery.staticPreflight,
            'recovery.staticPreflight',
        );
        const preflightAttempt = requireJsonObject(
            staticPreflight.attempt,
            'recovery.staticPreflight.attempt',
        );
        const preflightAttemptRelativePath = `browser-recovery-preflight/${recoveryAuthorizationKeySha256Hex ?? ''}/preflight-attempted.json`;
        requireExactRelativeArtifactPath({
            actual: preflightAttempt.path,
            expected: preflightAttemptRelativePath,
            fieldName: 'recovery.staticPreflight.attempt.path',
            rootPath: reservationRootPath,
        });
        const preflightAttemptPath = await resolveExistingCustodyFile({
            fieldName: 'Browser recovery static preflight marker',
            relativePath: preflightAttemptRelativePath,
            rootPath: reservationRootPath,
        });
        const serializedPreflightAttempt = await readFile(
            preflightAttemptPath,
            'utf8',
        );
        requireArtifactDigest({
            expectedSha256Hex: preflightAttempt.sha256Hex,
            fieldName: 'Browser recovery static preflight marker',
            value: serializedPreflightAttempt,
        });
        if (
            preflightAttempt.identitySha256Hex !==
                expectedReservationIdentitySha256Hex ||
            preflightAttempt.authorizationKeySha256Hex !==
                recoveryAuthorizationKeySha256Hex
        ) {
            throw new Error(
                'The browser recovery static preflight marker changed its identity.',
            );
        }
        const validatedPreflightAttempt =
            validateBrowserRecoveryPreflightAttempt({
                authorizationKeySha256Hex:
                    recoveryAuthorizationKeySha256Hex ?? '',
                identity:
                    recoveryReservationIdentity as RecoveryReservationIdentity,
                profile:
                    options.preOperationRecoveryProfile ??
                    proofStorageWidthBrowserPreOperationRecoveryProfile,
                serialized: serializedPreflightAttempt,
                terminalOutcomeRequired: true,
            });
        if (
            staticPreflight.outputSha256Hex !==
                validatedPreflightAttempt.outputSha256Hex ||
            staticPreflight.testFile !== validatedPreflightAttempt.testFile
        ) {
            throw new Error(
                'The browser recovery closure does not match the retained static preflight output.',
            );
        }
    }
    const officialReservationIdentitySha256Hex = requireSha256Hex(
        officialReservation.identitySha256Hex,
        'officialSampleReservation.identitySha256Hex',
    );
    if (
        officialReservationIdentitySha256Hex !==
            expectedReservationIdentitySha256Hex ||
        officialReservation.officialOwner !== browserOfficialSampleOwner ||
        (recovery !== undefined &&
            officialReservation.authorizationKeySha256Hex !==
                recoveryAuthorizationKeySha256Hex) ||
        officialReservation.schemaVersion !==
            (recovery === undefined ? 1 : 'browser-recovery-1')
    ) {
        throw new Error(
            'The browser official reservation identity, owner, or schema changed.',
        );
    }
    const reservationRelativePath =
        recovery === undefined
            ? `browser/${officialReservationIdentitySha256Hex}/browser-started.json`
            : `browser-recovery/${recoveryAuthorizationKeySha256Hex ?? ''}/browser-recovery-started.json`;
    requireExactRelativeArtifactPath({
        actual: officialReservation.path,
        expected: reservationRelativePath,
        fieldName: 'officialSampleReservation.path',
        rootPath: reservationRootPath,
    });
    const reservationPath = await resolveExistingCustodyFile({
        fieldName: 'Browser official reservation artifact',
        relativePath: reservationRelativePath,
        rootPath: reservationRootPath,
    });
    const serializedReservation = await readFile(reservationPath, 'utf8');
    requireArtifactDigest({
        expectedSha256Hex: officialReservation.sha256Hex,
        fieldName: 'Browser official reservation artifact',
        value: serializedReservation,
    });
    if (recoveryReservationIdentity === undefined) {
        validateBrowserOfficialReservationArtifact({
            identitySha256Hex: officialReservationIdentitySha256Hex,
            nativeAggregateSha256Hex,
            officialOwner: browserOfficialSampleOwner,
            rawWasmSha256Hex,
            serialized: serializedReservation,
            sourceCommitHash: repositoryCommitHash,
        });
    } else {
        validateBrowserRecoveryReservationArtifact({
            authorizationKeySha256Hex: recoveryAuthorizationKeySha256Hex ?? '',
            identity: recoveryReservationIdentity,
            serialized: serializedReservation,
        });
    }
};

const createBrowserRecoveryAuthorizationIfSelected = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly preOperationRecoveryRunDirectoryPath?: string;
}): Promise<BrowserRecoveryAuthorization | undefined> => {
    if (input.preOperationRecoveryRunDirectoryPath === undefined) {
        return undefined;
    }
    const profile =
        input.dependencies?.preOperationRecoveryProfile ??
        proofStorageWidthBrowserPreOperationRecoveryProfile;
    if (
        !path.isAbsolute(input.preOperationRecoveryRunDirectoryPath) ||
        path.resolve(input.preOperationRecoveryRunDirectoryPath) !==
            path.resolve(profile.failedRunDirectoryPath) ||
        profile.recoveryOrdinal !== recoveryOrdinal
    ) {
        throw new Error(
            'The pre-operation recovery path is not the exact authorized failed run.',
        );
    }
    const configuredReservationRootPath =
        input.dependencies?.officialReservationRootPath ??
        defaultProofStorageWidthOfficialReservationRootPath;
    if (!path.isAbsolute(configuredReservationRootPath)) {
        throw new Error(
            'The official browser reservation root path must be absolute.',
        );
    }
    const reservationRootPath = await requireCanonicalCustodyRoot(
        configuredReservationRootPath,
        'Browser recovery reservation root',
    );
    const authorizationKeySha256Hex =
        buildBrowserRecoveryAuthorizationKey(profile);
    const preflightAttemptPath = await createBrowserRecoveryPreflightAttempt({
        authorizationKeySha256Hex,
        profile,
        reservationRootPath,
    });
    return Object.freeze({
        authorizationKeySha256Hex,
        preflightAttemptPath,
        profile,
        reservationRootPath,
    });
};

const executeProofStorageWidthBrowserEvidenceAttempt = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly nativeEvidencePath: string;
    readonly preOperationRecoveryRunDirectoryPath?: string;
    readonly recoveryAuthorization?: BrowserRecoveryAuthorization;
    readonly runLog: ActiveLocalRunLog;
}) => {
    if (!path.isAbsolute(input.nativeEvidencePath)) {
        throw new Error('The native width-evidence path must be absolute.');
    }
    const executeCommand =
        input.dependencies?.executeCommand ?? defaultCommandExecutor;
    const processMemoryGuard =
        input.dependencies?.processMemoryGuard ??
        createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription:
                'Proof-storage width release WebAssembly evidence',
        });
    const readRepositoryState =
        input.dependencies?.readRepositoryState ??
        ((checkpoint, runLog) =>
            readRepositoryStateWithCommands({
                checkpoint,
                executeCommand,
                runLog,
            }));
    const configuredOfficialReservationRootPath =
        input.dependencies?.officialReservationRootPath ??
        defaultProofStorageWidthOfficialReservationRootPath;
    if (!path.isAbsolute(configuredOfficialReservationRootPath)) {
        throw new Error(
            'The official browser reservation root path must be absolute.',
        );
    }
    const officialReservationRootPath = path.resolve(
        configuredOfficialReservationRootPath,
    );
    const recoveryProfile =
        input.recoveryAuthorization?.profile ??
        input.dependencies?.preOperationRecoveryProfile ??
        proofStorageWidthBrowserPreOperationRecoveryProfile;
    if (
        (input.preOperationRecoveryRunDirectoryPath === undefined) !==
        (input.recoveryAuthorization === undefined)
    ) {
        throw new Error(
            'The browser recovery did not carry its earliest singleton authorization.',
        );
    }
    const loadNativeEvidence =
        input.dependencies?.loadNativeWidthEvidence ?? loadNativeWidthEvidence;
    const canonicalNativeEvidencePath =
        await resolveCanonicalAbsoluteCustodyFile(
            input.nativeEvidencePath,
            'Native width-evidence aggregate',
        );
    const nativeEvidence = await loadNativeEvidence(
        canonicalNativeEvidencePath,
        {
            officialReservationRootPath,
        },
    );
    const preOperationRecovery =
        input.preOperationRecoveryRunDirectoryPath === undefined
            ? undefined
            : await validateProofStorageWidthBrowserPreOperationRecovery({
                  failedRunDirectoryPath:
                      input.preOperationRecoveryRunDirectoryPath,
                  nativeEvidence,
                  officialReservationRootPath,
                  profile: recoveryProfile,
              });
    const initialRepositoryState = await readRepositoryState(
        'initial',
        input.runLog,
    );
    const expectedHarnessCommitHash =
        preOperationRecovery === undefined
            ? nativeEvidence.repositoryCommitHash
            : initialRepositoryState.commitHash;
    requireCleanPinnedRepository(
        initialRepositoryState,
        expectedHarnessCommitHash,
        'initial',
    );
    const harnessTransition =
        preOperationRecovery === undefined
            ? undefined
            : await validateHarnessRepairCommitTransition({
                  executeCommand,
                  harnessCommitHash: expectedHarnessCommitHash,
                  nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
                  runLog: input.runLog,
              });
    const packageManagerRunner = resolvePackageManagerRunner();
    const commandEnvironment: NodeJS.ProcessEnv = {
        ...process.env,
        SEALED_LATTICE_TEST_PROJECT_LABEL: testProjectLabel,
        [wasmEvidenceFeatureEnvironmentVariable]: browserEvidenceCargoFeature,
    };
    await executeRequiredCommand({
        command: createPackageManagerCommand(
            'build the release WebAssembly width-evidence feature',
            ['run', 'build'],
            {
                env: commandEnvironment,
                logFileSlug: 'build-proof-storage-width-browser-evidence',
                packageManagerRunner,
            },
        ),
        executeCommand,
        runLog: input.runLog,
    });
    const evidenceProcessedWasmKernelPath =
        await resolveCanonicalAbsoluteCustodyFile(
            path.resolve(
                input.dependencies?.processedWasmKernelPath ??
                    processedWasmKernelPath,
            ),
            'Processed producer WebAssembly artifact',
        );
    const evidencePublicSdkWasmKernelPath =
        await resolveCanonicalAbsoluteCustodyFile(
            path.resolve(
                input.dependencies?.publicSdkWasmKernelPath ??
                    publicSdkWasmKernelPath,
            ),
            'Public SDK WebAssembly artifact',
        );
    const wasmBinding = await (
        input.dependencies?.deriveProcessedWasmBinding ??
        (() =>
            deriveProcessedWasmBinding({
                processedWasmKernelPath: evidenceProcessedWasmKernelPath,
                publicSdkWasmKernelPath: evidencePublicSdkWasmKernelPath,
            }))
    )();
    if (
        preOperationRecovery !== undefined &&
        wasmBinding.rawSha256Hex !== recoveryProfile.rawWasmSha256Hex
    ) {
        throw new Error(
            'The rebuilt release WebAssembly bytes drifted from the authorized pre-operation predecessor.',
        );
    }
    const beforeRepositoryState = await readRepositoryState(
        'before',
        input.runLog,
    );
    requireCleanPinnedRepository(
        beforeRepositoryState,
        expectedHarnessCommitHash,
        'before',
    );
    commandEnvironment[expectedWasmHashEnvironmentVariable] =
        wasmBinding.normalizedSha256Hex;
    commandEnvironment[nativeBindingEnvironmentVariable] = JSON.stringify(
        nativeEvidence.nativeBindingRecord,
    );
    commandEnvironment[databaseNameEnvironmentVariable] = [
        'sealed-lattice-proof-storage-width',
        nativeEvidence.repositoryCommitHash.slice(0, 12),
        randomUUID(),
    ].join('-');
    await executeRequiredCommand({
        command: processMemoryGuard.buildVerificationCommand(),
        executeCommand,
        runLog: input.runLog,
    });
    if (preOperationRecovery !== undefined && harnessTransition === undefined) {
        throw new Error(
            'The browser recovery omitted its validated commit transition.',
        );
    }
    const recoveryReservationIdentity =
        preOperationRecovery === undefined || harnessTransition === undefined
            ? undefined
            : buildBrowserRecoveryReservationIdentity({
                  harnessTransition,
                  nativeEvidence,
                  preOperationRecovery,
                  rawWasmSha256Hex: wasmBinding.rawSha256Hex,
              });
    const recoveryAuthorizationKeySha256Hex =
        preOperationRecovery === undefined
            ? undefined
            : input.recoveryAuthorization?.authorizationKeySha256Hex;
    const recoveryPreflightAttemptPath =
        recoveryReservationIdentity === undefined
            ? undefined
            : input.recoveryAuthorization?.preflightAttemptPath;
    if (
        recoveryReservationIdentity !== undefined &&
        (recoveryAuthorizationKeySha256Hex === undefined ||
            recoveryPreflightAttemptPath === undefined)
    ) {
        throw new Error(
            'The browser recovery omitted its earliest singleton marker.',
        );
    }
    const staticPreflightResult = await executeRequiredCommand({
        command: createPackageManagerCommand(
            'statically resolve the fixed browser evidence file',
            proofStorageWidthBrowserEvidenceStaticPreflightArguments,
            {
                env: {
                    ...process.env,
                    SEALED_LATTICE_TEST_PROJECT_LABEL: testProjectLabel,
                    [wasmEvidenceFeatureEnvironmentVariable]:
                        browserEvidenceCargoFeature,
                },
                logFileSlug: 'vitest-list-proof-storage-width-browser-evidence',
                packageManagerRunner,
            },
        ),
        executeCommand,
        runLog: input.runLog,
    });
    if (staticPreflightResult.stderr !== '') {
        throw new Error(
            'The browser static preflight must produce no standard-error diagnostics.',
        );
    }
    const staticPreflightTestFile =
        parseProofStorageWidthBrowserStaticPreflightOutput(
            staticPreflightResult.stdout,
        );
    let serializedRecoveryPreflightAttempt: string | undefined;
    if (
        recoveryPreflightAttemptPath !== undefined &&
        recoveryReservationIdentity !== undefined
    ) {
        await appendBrowserRecoveryStaticPreflightObservation({
            authorizationKeySha256Hex: recoveryAuthorizationKeySha256Hex ?? '',
            identity: recoveryReservationIdentity,
            reservationPath: recoveryPreflightAttemptPath,
            reservationRootPath: officialReservationRootPath,
            result: staticPreflightResult,
        });
        serializedRecoveryPreflightAttempt = await readFile(
            await resolveExistingCustodyFile({
                fieldName: 'Browser recovery static preflight marker',
                relativePath: path.join(
                    'browser-recovery-preflight',
                    recoveryAuthorizationKeySha256Hex ?? '',
                    'preflight-attempted.json',
                ),
                rootPath: officialReservationRootPath,
            }),
            'utf8',
        );
        validateBrowserRecoveryPreflightAttempt({
            authorizationKeySha256Hex: recoveryAuthorizationKeySha256Hex ?? '',
            identity: recoveryReservationIdentity,
            profile: recoveryProfile,
            serialized: serializedRecoveryPreflightAttempt,
            terminalOutcomeRequired: false,
        });
    }
    const preOperationRepositoryState = await readRepositoryState(
        'pre-operation',
        input.runLog,
    );
    requireCleanPinnedRepository(
        preOperationRepositoryState,
        expectedHarnessCommitHash,
        'pre-operation',
    );
    if (harnessTransition !== undefined) {
        await validateHarnessRepairCommitTransition({
            executeCommand,
            harnessCommitHash: harnessTransition.harnessCommitHash,
            nativeSourceCommitHash: harnessTransition.nativeSourceCommitHash,
            runLog: input.runLog,
        });
    }
    const runCustodyRootPath = await requireCanonicalCustodyRoot(
        input.runLog.runDirectoryPath,
        'Browser evidence run custody root',
    );
    const guardPath = await prepareExclusiveCustodyFile({
        fieldName: 'Browser process-memory guard artifact',
        relativePath:
            'resources/process-memory-guard-proof-storage-width-browser.jsonl',
        rootPath: runCustodyRootPath,
    });
    const eventPath = await prepareExclusiveCustodyFile({
        fieldName: 'Raw browser event artifact',
        relativePath: `tests/${testProjectLabel}.jsonl`,
        rootPath: runCustodyRootPath,
    });
    await Promise.all([
        requireArtifactAbsent(guardPath, 'Browser guard artifact'),
        requireArtifactAbsent(eventPath, 'Browser event artifact'),
    ]);
    const browserCommand = createPackageManagerCommand(
        'run the fixed width-512 release WebAssembly evidence',
        proofStorageWidthBrowserEvidenceVitestArguments,
        {
            env: commandEnvironment,
            logFileSlug: 'vitest-proof-storage-width-browser-evidence',
            packageManagerRunner,
        },
    );
    const ordinaryReservationIdentity =
        preOperationRecovery === undefined
            ? buildProofStorageWidthBrowserReservationIdentity({
                  nativeAggregateSha256Hex: nativeEvidence.evidenceSha256Hex,
                  nativeReservationIdentitySha256Hex:
                      nativeEvidence.officialSampleReservationIdentitySha256Hex,
                  officialOwner: browserOfficialSampleOwner,
                  rawWasmSha256Hex: wasmBinding.rawSha256Hex,
                  sourceCommitHash: nativeEvidence.repositoryCommitHash,
              })
            : undefined;
    const reservationPath =
        recoveryReservationIdentity === undefined
            ? await createProofStorageWidthBrowserSampleReservation({
                  identitySha256Hex:
                      ordinaryReservationIdentity?.identitySha256Hex ?? '',
                  nativeAggregateSha256Hex: nativeEvidence.evidenceSha256Hex,
                  officialOwner: browserOfficialSampleOwner,
                  rawWasmSha256Hex: wasmBinding.rawSha256Hex,
                  reservationRootPath: officialReservationRootPath,
                  runDirectoryPath: input.runLog.runDirectoryPath,
                  sourceCommitHash: nativeEvidence.repositoryCommitHash,
              })
            : await createBrowserRecoveryReservation({
                  authorizationKeySha256Hex:
                      recoveryAuthorizationKeySha256Hex ?? '',
                  identity: recoveryReservationIdentity,
                  reservationRootPath: officialReservationRootPath,
                  runDirectoryPath: input.runLog.runDirectoryPath,
              });
    let attemptError: unknown;
    try {
        if (
            recoveryPreflightAttemptPath !== undefined &&
            recoveryReservationIdentity !== undefined
        ) {
            await appendProofStorageWidthOfficialReservationOutcome({
                outcome: 'validated',
                reservationPath: recoveryPreflightAttemptPath,
            });
            serializedRecoveryPreflightAttempt = await readFile(
                await resolveExistingCustodyFile({
                    fieldName: 'Browser recovery static preflight marker',
                    relativePath: path.join(
                        'browser-recovery-preflight',
                        recoveryAuthorizationKeySha256Hex ?? '',
                        'preflight-attempted.json',
                    ),
                    rootPath: officialReservationRootPath,
                }),
                'utf8',
            );
            validateBrowserRecoveryPreflightAttempt({
                authorizationKeySha256Hex:
                    recoveryAuthorizationKeySha256Hex ?? '',
                identity: recoveryReservationIdentity,
                profile: recoveryProfile,
                serialized: serializedRecoveryPreflightAttempt,
                terminalOutcomeRequired: true,
            });
        }
        await executeRequiredCommand({
            command: processMemoryGuard.guardCommand(browserCommand, {
                diagnosticsPath: guardPath,
                resourceSampleIntervalMilliseconds,
            }),
            executeCommand,
            runLog: input.runLog,
        });
    } catch (error) {
        attemptError = error;
    }
    let afterRepositoryState: RepositoryState | undefined;
    try {
        afterRepositoryState = await readRepositoryState('after', input.runLog);
        requireCleanPinnedRepository(
            afterRepositoryState,
            expectedHarnessCommitHash,
            'after',
        );
    } catch (repositoryError) {
        attemptError =
            attemptError === undefined
                ? repositoryError
                : combineAttemptAndRepositoryFailure({
                      attemptError,
                      repositoryError,
                  });
    }
    let serializedEvents: string | undefined;
    let guardJsonLines: string | undefined;
    let measurement: ProofStorageWidthBrowserMeasurement | undefined;
    let operationMemory:
        | ReturnType<typeof extractProofStorageWidthOperationMemory>
        | undefined;
    let projection: ProofStorageWidthBrowserProjection | undefined;
    let decision: ProofStorageWidthBrowserProjectionDecision | undefined;
    if (attemptError === undefined) {
        try {
            [serializedEvents, guardJsonLines] = await Promise.all([
                readFile(eventPath, 'utf8'),
                readFile(guardPath, 'utf8'),
            ]);
            measurement = parseProofStorageWidthBrowserMeasurementEvents({
                expectedWasmSha256Hex: wasmBinding.normalizedSha256Hex,
                serializedEvents,
            });
            requireProofStorageWidthBrowserNativeMatch(
                measurement,
                nativeEvidence.nativeBinding,
            );
            operationMemory = extractProofStorageWidthOperationMemory({
                guardJsonLines,
                operationFinishedAtUnixMilliseconds:
                    measurement.operationFinishedAtUnixMilliseconds,
                operationStartedAtUnixMilliseconds:
                    measurement.operationStartedAtUnixMilliseconds,
            });
            requireGuardMemoryLimitBinding({
                expectedMemoryLimitBytes: processMemoryGuard.memoryLimitBytes,
                serializedGuard: guardJsonLines,
            });
            if (
                operationMemory.resourceSampleIntervalMilliseconds !==
                    BigInt(resourceSampleIntervalMilliseconds) ||
                operationMemory.inWindowSampleCount === 0
            ) {
                throw new Error(
                    'The browser width-evidence operation lacks guarded in-window samples.',
                );
            }
            projection = deriveProofStorageWidthBrowserProjection({
                fullWidthResult: nativeEvidence.fullWidthResult,
                fullWidthStaticPoint: nativeEvidence.fullWidthStaticPoint,
                measurement,
                representativeResult: nativeEvidence.representativeResult,
                representativeStaticPoint:
                    nativeEvidence.representativeStaticPoint,
            });
            decision = evaluateProofStorageWidthBrowserProjectionEligibility({
                fullWidthResult: nativeEvidence.fullWidthResult,
                projection,
            });
        } catch (error) {
            attemptError = error;
        }
    }
    try {
        if (recoveryAuthorizationKeySha256Hex !== undefined) {
            const custodyReservationPath = await resolveExistingCustodyFile({
                fieldName: 'Browser recovery operation reservation',
                relativePath: path.join(
                    'browser-recovery',
                    recoveryAuthorizationKeySha256Hex,
                    'browser-recovery-started.json',
                ),
                rootPath: officialReservationRootPath,
            });
            if (custodyReservationPath !== path.resolve(reservationPath)) {
                throw new Error(
                    'The browser recovery operation reservation changed custody paths.',
                );
            }
        }
        await appendProofStorageWidthOfficialReservationOutcome({
            ...(attemptError === undefined
                ? {}
                : { failureName: errorName(attemptError) }),
            outcome: attemptError === undefined ? 'validated' : 'failed',
            reservationPath,
        });
    } catch (outcomeError) {
        throw Object.assign(
            new Error(
                'The durable browser reservation outcome could not be appended; the started marker still prohibits a replacement sample.',
            ),
            { attemptCause: attemptError, cause: outcomeError },
        );
    }
    if (attemptError !== undefined) {
        throw attemptError instanceof Error
            ? attemptError
            : Object.assign(new Error('The browser sample failed.'), {
                  cause: attemptError,
              });
    }
    if (
        serializedEvents === undefined ||
        guardJsonLines === undefined ||
        measurement === undefined ||
        operationMemory === undefined ||
        projection === undefined ||
        decision === undefined ||
        afterRepositoryState === undefined
    ) {
        throw new Error(
            'The validated browser sample omitted a required closure artifact.',
        );
    }
    const serializedReservation = await readFile(reservationPath, 'utf8');
    if (recoveryReservationIdentity === undefined) {
        if (ordinaryReservationIdentity === undefined) {
            throw new Error(
                'The ordinary browser operation omitted its reservation identity.',
            );
        }
        validateBrowserOfficialReservationArtifact({
            identitySha256Hex: ordinaryReservationIdentity.identitySha256Hex,
            nativeAggregateSha256Hex: nativeEvidence.evidenceSha256Hex,
            officialOwner: browserOfficialSampleOwner,
            rawWasmSha256Hex: wasmBinding.rawSha256Hex,
            serialized: serializedReservation,
            sourceCommitHash: nativeEvidence.repositoryCommitHash,
        });
    } else {
        validateBrowserRecoveryReservationArtifact({
            authorizationKeySha256Hex: recoveryAuthorizationKeySha256Hex ?? '',
            identity: recoveryReservationIdentity,
            serialized: serializedReservation,
        });
    }
    const attachmentPath = await prepareExclusiveCustodyFile({
        fieldName: 'Browser evidence attachment',
        relativePath: 'attachments/proof-storage-width-browser-evidence.json',
        rootPath: runCustodyRootPath,
    });
    await writeJsonExclusively(attachmentPath, {
        artifacts: {
            browserEvents: {
                path: canonicalRelativePath(
                    input.runLog.runDirectoryPath,
                    eventPath,
                ),
                sha256Hex: sha256Hex(serializedEvents),
            },
            guard: {
                path: canonicalRelativePath(
                    input.runLog.runDirectoryPath,
                    guardPath,
                ),
                sha256Hex: sha256Hex(guardJsonLines),
            },
            nativeAggregate: {
                path: nativeEvidence.evidencePath,
                sha256Hex: nativeEvidence.evidenceSha256Hex,
            },
        },
        decision,
        formatVersion: preOperationRecovery === undefined ? 4 : 5,
        guard: {
            memoryLimitBytes: processMemoryGuard.memoryLimitBytes,
            maximumOperationWindowGapMilliseconds,
            operationMemory,
            resourceSampleIntervalMilliseconds,
        },
        measurement,
        invocation: {
            retryCount: 0,
            semanticArguments: proofStorageWidthBrowserEvidenceVitestArguments,
            testFile: browserTestFile,
            testProjectName,
        },
        nativeEvidence: {
            officialSampleReservationIdentitySha256Hex:
                nativeEvidence.officialSampleReservationIdentitySha256Hex,
            repositoryCommitHash: nativeEvidence.repositoryCommitHash,
            representativeResult: nativeEvidence.representativeResult,
            representativeStaticPoint: nativeEvidence.representativeStaticPoint,
            fullWidthResult: nativeEvidence.fullWidthResult,
            fullWidthStaticPoint: nativeEvidence.fullWidthStaticPoint,
        },
        officialSampleReservation: {
            ...(recoveryAuthorizationKeySha256Hex === undefined
                ? {}
                : {
                      authorizationKeySha256Hex:
                          recoveryAuthorizationKeySha256Hex,
                  }),
            identitySha256Hex:
                recoveryReservationIdentity?.identitySha256Hex ??
                ordinaryReservationIdentity?.identitySha256Hex,
            officialOwner: browserOfficialSampleOwner,
            path: canonicalRelativePath(
                officialReservationRootPath,
                reservationPath,
            ),
            schemaVersion:
                recoveryReservationIdentity === undefined
                    ? 1
                    : 'browser-recovery-1',
            sha256Hex: sha256Hex(serializedReservation),
        },
        projection,
        ...(preOperationRecovery === undefined ||
        harnessTransition === undefined
            ? {}
            : {
                  recovery: {
                      changedFilePaths: harnessTransition.changedFilePaths,
                      failedArtifacts: preOperationRecovery.failedArtifacts,
                      failedReservation: preOperationRecovery.failedReservation,
                      failedRunDirectoryPath:
                          preOperationRecovery.failedRunDirectoryPath,
                      harnessCommitHash: harnessTransition.harnessCommitHash,
                      nativeSourceCommitHash:
                          harnessTransition.nativeSourceCommitHash,
                      recoveryOrdinal,
                      staticPreflight: {
                          attempt:
                              recoveryPreflightAttemptPath === undefined ||
                              serializedRecoveryPreflightAttempt === undefined
                                  ? undefined
                                  : {
                                        authorizationKeySha256Hex:
                                            recoveryAuthorizationKeySha256Hex,
                                        identitySha256Hex:
                                            recoveryReservationIdentity?.identitySha256Hex,
                                        path: canonicalRelativePath(
                                            officialReservationRootPath,
                                            recoveryPreflightAttemptPath,
                                        ),
                                        sha256Hex: sha256Hex(
                                            serializedRecoveryPreflightAttempt,
                                        ),
                                    },
                          outputSha256Hex: sha256Hex(
                              staticPreflightResult.stdout,
                          ),
                          semanticArguments:
                              proofStorageWidthBrowserEvidenceStaticPreflightArguments,
                          testFile: staticPreflightTestFile,
                          testProjectName,
                      },
                  },
              }),
        repository: {
            after: afterRepositoryState,
            before: beforeRepositoryState,
            initial: initialRepositoryState,
            preOperation: preOperationRepositoryState,
        },
        wasm: {
            cargoFeature: browserEvidenceCargoFeature,
            processedByteLength: wasmBinding.byteLength,
            normalizedSha256Hex: wasmBinding.normalizedSha256Hex,
            producerPath: evidenceProcessedWasmKernelPath,
            publicSdkPath: evidencePublicSdkWasmKernelPath,
            rawSha256Hex: wasmBinding.rawSha256Hex,
        },
    });
    const attachmentBytesBeforeValidation = await readFile(attachmentPath);
    const attachmentSha256Hex = sha256Hex(attachmentBytesBeforeValidation);
    await validateProofStorageWidthBrowserEvidenceArtifacts(attachmentPath, {
        loadNativeWidthEvidence: loadNativeEvidence,
        officialReservationRootPath,
        preOperationRecoveryProfile:
            input.dependencies?.preOperationRecoveryProfile,
        processedWasmKernelPath: evidenceProcessedWasmKernelPath,
        publicSdkWasmKernelPath: evidencePublicSdkWasmKernelPath,
    });
    if (harnessTransition !== undefined) {
        await validateHarnessRepairCommitTransition({
            executeCommand,
            harnessCommitHash: harnessTransition.harnessCommitHash,
            nativeSourceCommitHash: harnessTransition.nativeSourceCommitHash,
            runLog: input.runLog,
        });
    }
    const attachmentBytesAfterValidation = await readFile(attachmentPath);
    if (
        !attachmentBytesBeforeValidation.equals(attachmentBytesAfterValidation)
    ) {
        throw new Error(
            'The browser width-evidence aggregate changed while its artifacts were being reopened and validated.',
        );
    }
    return {
        attachmentPath,
        decision,
        completionEventDetails: {
            attachmentPath,
            attachmentSha256Hex,
            decisionOutcome: decision.outcome,
            decisionViolations: decision.violations,
            projectedFullWidthNanoseconds:
                projection.operationNanoseconds.toString(),
            projectedWasmLinearMemoryPeakByteLength:
                projection.projectedWasmLinearMemoryPeakByteLength.toString(),
            repositoryCommitHash: nativeEvidence.repositoryCommitHash,
            harnessCommitHash: expectedHarnessCommitHash,
            staticWasmMemoryCeilingDeltaByteLength:
                projection.staticWasmMemoryCeilingGrowth.deltaByteLength.toString(),
            rawWasmSha256Hex: wasmBinding.rawSha256Hex,
            wasmSha256Hex: wasmBinding.normalizedSha256Hex,
        },
    };
};

export const executeProofStorageWidthBrowserEvidence = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly nativeEvidencePath: string;
    readonly preOperationRecoveryRunDirectoryPath?: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<void> => {
    const recoveryAuthorization =
        await createBrowserRecoveryAuthorizationIfSelected({
            dependencies: input.dependencies,
            preOperationRecoveryRunDirectoryPath:
                input.preOperationRecoveryRunDirectoryPath,
        });
    const executeCommand =
        input.dependencies?.executeCommand ?? defaultCommandExecutor;
    const processMemoryGuard =
        input.dependencies?.processMemoryGuard ??
        createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription:
                'Proof-storage width release WebAssembly evidence',
        });
    const readRepositoryState =
        input.dependencies?.readRepositoryState ??
        ((checkpoint: RepositoryCheckpoint, runLog: ActiveLocalRunLog) =>
            readRepositoryStateWithCommands({
                checkpoint,
                executeCommand,
                runLog,
            }));
    let initialCommitHash: string | undefined;
    const readTrackedRepositoryState = async (
        checkpoint: RepositoryCheckpoint,
        runLog: ActiveLocalRunLog,
    ): Promise<RepositoryState> => {
        const repositoryState = await readRepositoryState(checkpoint, runLog);
        if (checkpoint === 'initial') {
            initialCommitHash = repositoryState.commitHash;
        }
        return repositoryState;
    };

    let attemptError: unknown;
    let result:
        | Awaited<
              ReturnType<typeof executeProofStorageWidthBrowserEvidenceAttempt>
          >
        | undefined;
    try {
        result = await executeProofStorageWidthBrowserEvidenceAttempt({
            dependencies: {
                ...(input.dependencies ?? {}),
                executeCommand,
                processMemoryGuard,
                readRepositoryState: readTrackedRepositoryState,
            },
            nativeEvidencePath: input.nativeEvidencePath,
            ...(input.preOperationRecoveryRunDirectoryPath === undefined
                ? {}
                : {
                      preOperationRecoveryRunDirectoryPath:
                          input.preOperationRecoveryRunDirectoryPath,
                  }),
            ...(recoveryAuthorization === undefined
                ? {}
                : { recoveryAuthorization }),
            runLog: input.runLog,
        });
    } catch (error) {
        attemptError = error;
        if (recoveryAuthorization !== undefined) {
            try {
                await appendBrowserRecoveryPreflightFailedOutcomeIfPending({
                    authorization: recoveryAuthorization,
                    failure: error,
                });
            } catch (outcomeError) {
                attemptError = Object.assign(
                    new Error(
                        'The browser recovery attempt failed and its singleton terminal outcome could not be recorded.',
                    ),
                    { attemptCause: error, cause: outcomeError },
                );
            }
        }
    }

    let closureRepositoryError: unknown;
    if (initialCommitHash !== undefined) {
        try {
            const closureRepositoryState = await readRepositoryState(
                'closure-after',
                input.runLog,
            );
            requireCleanPinnedRepository(
                closureRepositoryState,
                initialCommitHash,
                'closure-after',
            );
        } catch (error) {
            closureRepositoryError = error;
        }
    }

    if (attemptError !== undefined && closureRepositoryError !== undefined) {
        throw Object.assign(
            new Error(
                'The browser width-evidence attempt failed and its final repository closure check also failed.',
            ),
            {
                attemptCause: attemptError,
                cause: closureRepositoryError,
            },
        );
    }
    if (attemptError !== undefined) {
        if (attemptError instanceof Error) {
            throw attemptError;
        }
        throw Object.assign(
            new Error(
                'The browser width-evidence attempt failed with a non-Error rejection value.',
            ),
            { cause: attemptError },
        );
    }
    if (closureRepositoryError !== undefined) {
        if (closureRepositoryError instanceof Error) {
            throw closureRepositoryError;
        }
        throw Object.assign(
            new Error(
                'The browser width-evidence final repository closure check failed with a non-Error rejection value.',
            ),
            { cause: closureRepositoryError },
        );
    }
    if (result === undefined) {
        throw new Error(
            'The browser width-evidence attempt completed without a result.',
        );
    }

    const message = `Proof-storage width browser evidence: ${result.attachmentPath}\n`;
    process.stdout.write(message);
    input.runLog.writeCombinedOutput(message);
    input.runLog.writeEvent({
        details: result.completionEventDetails,
        eventType:
            result.decision.outcome === 'eligible'
                ? 'proof-storage-width-browser-evidence-complete'
                : 'proof-storage-width-browser-evidence-decisive-negative',
    });
    if (result.decision.outcome === 'ineligible') {
        throw new Error(
            `The release-browser width evidence produced the decisive negative ${result.decision.violations.join(', ')} after canonical evidence closure at ${result.attachmentPath}.`,
        );
    }
};

export const parseProofStorageWidthBrowserEvidenceArguments = (
    rawArguments: readonly string[],
): Readonly<{
    nativeEvidencePath: string;
    preOperationRecoveryRunDirectoryPath?: string;
}> => {
    const effectiveArguments = rawArguments.filter(
        (argument) => argument !== '--',
    );
    const nativeEvidenceFlagIndex =
        effectiveArguments.indexOf('--native-evidence');
    const recoveryFlagIndex = effectiveArguments.indexOf(
        '--pre-operation-recovery',
    );
    const nativeEvidencePath = effectiveArguments[nativeEvidenceFlagIndex + 1];
    const preOperationRecoveryRunDirectoryPath =
        recoveryFlagIndex === -1
            ? undefined
            : effectiveArguments[recoveryFlagIndex + 1];
    const expectedArgumentLength =
        preOperationRecoveryRunDirectoryPath === undefined ? 2 : 4;
    if (
        effectiveArguments.length !== expectedArgumentLength ||
        nativeEvidenceFlagIndex !== 0 ||
        nativeEvidencePath === undefined ||
        !path.isAbsolute(nativeEvidencePath) ||
        (recoveryFlagIndex !== -1 &&
            (recoveryFlagIndex !== 2 ||
                preOperationRecoveryRunDirectoryPath === undefined ||
                !path.isAbsolute(preOperationRecoveryRunDirectoryPath)))
    ) {
        throw new Error(
            'The browser width-evidence runner requires --native-evidence followed by one absolute evidence path and optionally --pre-operation-recovery followed by one absolute failed run directory.',
        );
    }
    return Object.freeze({
        nativeEvidencePath,
        ...(preOperationRecoveryRunDirectoryPath === undefined
            ? {}
            : { preOperationRecoveryRunDirectoryPath }),
    });
};

export const runProofStorageWidthBrowserEvidence = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const parsedArguments =
        parseProofStorageWidthBrowserEvidenceArguments(rawArguments);
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: [laneLabel],
            resourceSampleIntervalMilliseconds,
            scriptName,
        },
        async (runLog) => {
            await withLocalHeavyLaneLease({
                action: () =>
                    executeProofStorageWidthBrowserEvidence({
                        nativeEvidencePath: parsedArguments.nativeEvidencePath,
                        ...(parsedArguments.preOperationRecoveryRunDirectoryPath ===
                        undefined
                            ? {}
                            : {
                                  preOperationRecoveryRunDirectoryPath:
                                      parsedArguments.preOperationRecoveryRunDirectoryPath,
                              }),
                        runLog,
                    }),
                laneLabel,
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runProofStorageWidthBrowserEvidence();
}
