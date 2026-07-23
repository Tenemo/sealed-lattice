import { createHash, randomUUID } from 'node:crypto';
import {
    access,
    link,
    mkdir,
    open,
    readFile,
    rm,
    unlink,
} from 'node:fs/promises';
import path from 'node:path';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    deriveProofStorageWidthGeometry,
    evaluateProofStorageWidthCurve,
    proofStorageWidthProfile,
    proofStorageWidthSchedule,
    validateProofStorageWidthPoint,
    validateProofStorageWidthPointAgainstStaticPreflight,
    validateProofStorageWidthStaticPreflightResult,
    type ProofStorageWidth,
    type ProofStorageWidthCurveDecision,
    type ValidatedProofStorageWidthPoint,
    type ValidatedProofStorageWidthStaticPreflight,
} from './proof-storage-width-evidence.js';
import {
    appendProofStorageWidthOfficialReservationOutcome,
    buildProofStorageWidthNativeReservationIdentity,
    createProofStorageWidthNativeSampleReservation,
    defaultProofStorageWidthOfficialReservationRootPath,
} from './proof-storage-width-official-reservation.js';
import {
    runCommandAndCaptureOutput,
    type CapturedCommandResult,
    type CommandInvocation,
} from './run-command.js';
import {
    executeProofBackendBakeoffPreflightSequence,
    readAndValidateCompletedProcessMemoryGuardArtifact,
    validateProofBackendBakeoffPreflightEvidenceArtifacts,
} from './run-proof-backend-bakeoff-preflight.js';

const laneLabel = 'Proof-storage width evidence';
const scriptName = 'test:rust:kernel:proof-storage-width-evidence';
const cargoFeatureName = 'proof-storage-width-evidence';
const cargoPackageName = 'sealed-lattice-kernel';
export const proofStorageWidthEvidenceTestFilter =
    'proof_storage_width_evidence_records_incumbent_curve';
const proofStorageWidthModuleFilter =
    'bgv::proof_suite::proof_storage_width_evidence';
export const proofStorageWidthStaticPreflightTestName = `${proofStorageWidthModuleFilter}::tests::proof_storage_width_evidence_static_preflight_checks_every_scheduled_width`;
export const proofStorageWidthMeasurementTestName = `${proofStorageWidthModuleFilter}::tests::${proofStorageWidthEvidenceTestFilter}`;
export const proofStorageWidthFeatureTestNames = [
    proofStorageWidthStaticPreflightTestName,
    proofStorageWidthMeasurementTestName,
] as const;
const widthEnvironmentVariable = 'SEALED_LATTICE_PROOF_STORAGE_WIDTH';
const resultPathEnvironmentVariable =
    'SEALED_LATTICE_PROOF_STORAGE_WIDTH_RESULT_PATH';
const staticPreflightResultPathEnvironmentVariable =
    'SEALED_LATTICE_PROOF_STORAGE_WIDTH_STATIC_PREFLIGHT_RESULT_PATH';
const manifestIdentityEnvironmentVariable =
    'SEALED_LATTICE_PROOF_STORAGE_WIDTH_MANIFEST_IDENTITY_SHAKE256_HEX';
export const proofStorageWidthCustodyDirectoryEnvironmentVariable =
    'SEALED_LATTICE_PROOF_STORAGE_WIDTH_CUSTODY_DIRECTORY_PATH';
const resourceSampleIntervalMilliseconds = 100;
const exactCommitHashPattern = /^[0-9a-f]{40}$/u;
const sha256HexPattern = /^[0-9a-f]{64}$/u;

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
    | `width-${ProofStorageWidth}-after`
    | `width-${ProofStorageWidth}-before`;

type CommandExecutor = (
    invocation: CommandInvocation,
    runLog: ActiveLocalRunLog,
) => Promise<CapturedCommandResult>;

export type ProofStorageWidthEvidenceRunnerDependencies = Readonly<{
    executeCommand?: CommandExecutor;
    officialReservationRootPath?: string;
    processMemoryGuard?: ProcessMemoryGuard;
    readRepositoryState?: (
        checkpoint: RepositoryCheckpoint,
        runLog: ActiveLocalRunLog,
    ) => Promise<RepositoryState>;
}>;

export type ProofStorageWidthEvidenceRunResult = Readonly<{
    attachmentPath: string;
    decision: ProofStorageWidthCurveDecision;
}>;

const buildCargoArguments = (): readonly string[] => [
    'test',
    '--locked',
    '--release',
    '-p',
    cargoPackageName,
    '--features',
    cargoFeatureName,
    '--lib',
];

export const buildProofStorageWidthEnvironment = (
    input: {
        readonly baseEnvironment?: NodeJS.ProcessEnv;
        readonly targetDirectoryPath?: string;
    } = {},
): NodeJS.ProcessEnv => {
    const environment: NodeJS.ProcessEnv = {
        ...(input.baseEnvironment ?? process.env),
        CARGO_BUILD_JOBS: '1',
        CARGO_INCREMENTAL: '0',
        CARGO_TARGET_DIR:
            input.targetDirectoryPath ??
            path.resolve(process.cwd(), 'target', 'proof-storage-width'),
        RAYON_NUM_THREADS: '1',
        RUST_BACKTRACE: 'full',
        RUST_TEST_THREADS: '1',
    };
    delete environment[resultPathEnvironmentVariable];
    delete environment[staticPreflightResultPathEnvironmentVariable];
    delete environment[manifestIdentityEnvironmentVariable];
    delete environment[proofStorageWidthCustodyDirectoryEnvironmentVariable];
    delete environment[widthEnvironmentVariable];
    delete environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS;
    delete environment.SEALED_LATTICE_TEST_CHECKPOINT_ROOT;
    return environment;
};

export const buildProofStorageWidthPrecompileCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [...buildCargoArguments(), '--no-run'],
    command: 'cargo',
    description: 'precompile the release proof-storage width owner',
    env: environment,
    logFileSlug: 'cargo-precompile-proof-storage-width',
});

export const buildProofStorageWidthListCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [
        ...buildCargoArguments(),
        proofStorageWidthEvidenceTestFilter,
        '--',
        '--ignored',
        '--list',
        '--test-threads',
        '1',
    ],
    command: 'cargo',
    description: 'list the release proof-storage width owner',
    env: environment,
    logFileSlug: 'cargo-list-proof-storage-width',
});

export const buildProofStorageWidthFeatureListCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [
        ...buildCargoArguments(),
        proofStorageWidthModuleFilter,
        '--',
        '--list',
        '--test-threads',
        '1',
    ],
    command: 'cargo',
    description: 'list every proof-storage width feature test',
    env: environment,
    logFileSlug: 'cargo-list-proof-storage-width-feature-tests',
});

export const buildProofStorageWidthStaticPreflightCommand = (input: {
    readonly baseEnvironment: NodeJS.ProcessEnv;
    readonly resultPath: string;
}): CommandInvocation => {
    if (!path.isAbsolute(input.resultPath)) {
        throw new Error(
            'The proof-storage width static-preflight result path must be absolute.',
        );
    }
    return {
        args: [
            ...buildCargoArguments(),
            proofStorageWidthModuleFilter,
            '--',
            '--nocapture',
            '--test-threads',
            '1',
        ],
        command: 'cargo',
        description:
            'run the proof-storage width non-ignored static feature tests',
        env: {
            ...input.baseEnvironment,
            [staticPreflightResultPathEnvironmentVariable]: input.resultPath,
        },
        logFileSlug: 'cargo-proof-storage-width-static-feature-tests',
    };
};

export const parseProofStorageWidthTestInventory = (
    standardOutput: string,
): string => {
    const inventoryLines = standardOutput
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => /: (?:benchmark|test)$/u.test(line));
    if (inventoryLines.length !== 1) {
        throw new Error(
            `The proof-storage width preflight requires exactly one ignored owner, but listed ${inventoryLines.length}.`,
        );
    }
    const inventoryLine = inventoryLines[0];
    if (inventoryLine === undefined || !inventoryLine.endsWith(': test')) {
        throw new Error(
            'The proof-storage width preflight did not resolve to a Rust test.',
        );
    }
    const exactTestName = inventoryLine.slice(0, -': test'.length);
    if (
        exactTestName !== proofStorageWidthEvidenceTestFilter &&
        !exactTestName.endsWith(`::${proofStorageWidthEvidenceTestFilter}`)
    ) {
        throw new Error(
            `The proof-storage width preflight resolved an unexpected test: ${exactTestName}.`,
        );
    }
    return exactTestName;
};

export const parseProofStorageWidthFeatureInventory = (
    standardOutput: string,
): readonly string[] => {
    const inventoryLines = standardOutput
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => /: (?:benchmark|test)$/u.test(line));
    const benchmarkLines = inventoryLines.filter((line) =>
        line.endsWith(': benchmark'),
    );
    if (benchmarkLines.length !== 0) {
        throw new Error(
            `The proof-storage width feature inventory unexpectedly selected benchmarks: ${benchmarkLines.join(', ')}.`,
        );
    }
    const actualTestNames = inventoryLines.map((line) =>
        line.slice(0, -': test'.length),
    );
    if (new Set(actualTestNames).size !== actualTestNames.length) {
        throw new Error(
            'The proof-storage width feature inventory contains duplicate tests.',
        );
    }
    const actualTestNameSet = new Set(actualTestNames);
    const expectedTestNameSet = new Set<string>(
        proofStorageWidthFeatureTestNames,
    );
    const missing = proofStorageWidthFeatureTestNames.filter(
        (testName) => !actualTestNameSet.has(testName),
    );
    const extra = actualTestNames.filter(
        (testName) => !expectedTestNameSet.has(testName),
    );
    if (missing.length !== 0 || extra.length !== 0) {
        throw new Error(
            `The proof-storage width feature inventory does not match its exact registry. Missing: ${missing.length === 0 ? 'none' : missing.join(', ')}. Extra: ${extra.length === 0 ? 'none' : extra.join(', ')}.`,
        );
    }
    return actualTestNames;
};

export const buildProofStorageWidthSampleCommand = (input: {
    readonly baseEnvironment: NodeJS.ProcessEnv;
    readonly custodyDirectoryPath: string;
    readonly exactTestName: string;
    readonly manifestIdentityShake256Hex: string;
    readonly resultPath: string;
    readonly width: ProofStorageWidth;
}): CommandInvocation => {
    if (!path.isAbsolute(input.resultPath)) {
        throw new Error(
            'The proof-storage width result path must be absolute.',
        );
    }
    const custodyDirectoryPath = requirePrecommittedCustodyDirectoryPath({
        custodyDirectoryPath: input.custodyDirectoryPath,
        resultPath: input.resultPath,
    });
    if (!/^[0-9a-f]{128}$/u.test(input.manifestIdentityShake256Hex)) {
        throw new Error(
            'The proof-storage width manifest identity must be an exact lowercase SHAKE256-512 digest.',
        );
    }
    return {
        args: [
            ...buildCargoArguments(),
            input.exactTestName,
            '--',
            '--exact',
            '--ignored',
            '--nocapture',
            '--test-threads',
            '1',
        ],
        command: 'cargo',
        description: `measure proof storage at public base width ${input.width}`,
        env: {
            ...input.baseEnvironment,
            [proofStorageWidthCustodyDirectoryEnvironmentVariable]:
                custodyDirectoryPath,
            [manifestIdentityEnvironmentVariable]:
                input.manifestIdentityShake256Hex,
            [resultPathEnvironmentVariable]: input.resultPath,
            [widthEnvironmentVariable]: String(input.width),
        },
        logFileSlug: `cargo-proof-storage-width-${input.width}`,
    };
};

const executeRequiredCommand = async (input: {
    readonly command: CommandInvocation;
    readonly executeCommand: CommandExecutor;
    readonly runLog: ActiveLocalRunLog;
}): Promise<CapturedCommandResult> => {
    const result = await input.executeCommand(input.command, input.runLog);
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw new Error(
            `${input.command.description} failed with exit code ${result.exitCode}${
                result.terminationSignal === null
                    ? ''
                    : ` and signal ${result.terminationSignal}`
            }. No replacement sample is permitted.`,
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
            description: `read the ${input.checkpoint} proof-storage width commit`,
            logFileSlug: `git-proof-storage-width-${input.checkpoint}-commit`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    const commitHash = commitResult.stdout.trim();
    if (!exactCommitHashPattern.test(commitHash)) {
        throw new Error(
            `The ${input.checkpoint} proof-storage width commit is not an exact 40-hex hash.`,
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
            description: `read the ${input.checkpoint} proof-storage width status`,
            logFileSlug: `git-proof-storage-width-${input.checkpoint}-status`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    return {
        commitHash,
        treeDirty: statusResult.stdout.length !== 0,
    };
};

const requireCleanPinnedRepository = (
    repositoryState: RepositoryState,
    checkpoint: RepositoryCheckpoint,
): void => {
    if (repositoryState.treeDirty) {
        throw new Error(
            `The proof-storage width lane requires a clean repository tree at its ${checkpoint} checkpoint.`,
        );
    }
};

const requirePathDoesNotExist = async (filePath: string): Promise<void> => {
    try {
        await access(filePath);
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
    throw new Error(`Refusing to overwrite width evidence: ${filePath}.`);
};

export class ProofStorageWidthLeftoverCustodyError extends Error {
    readonly code = 'PROOF_STORAGE_WIDTH_LEFTOVER_CUSTODY';
    readonly cleanupCompleted: boolean;
    readonly custodyPaths: readonly string[];
    readonly originalCause: unknown;

    constructor(input: {
        readonly cause?: unknown;
        readonly cleanupCompleted: boolean;
        readonly custodyPaths: readonly string[];
    }) {
        super(
            `The guarded width sample left ${input.custodyPaths.length} bounded-custody path(s); exact-path cleanup ${input.cleanupCompleted ? 'completed' : 'failed'} and the runner refuses the sample.`,
        );
        this.name = 'ProofStorageWidthLeftoverCustodyError';
        this.cleanupCompleted = input.cleanupCompleted;
        this.custodyPaths = input.custodyPaths;
        this.originalCause = input.cause;
    }
}

const custodyDirectoryUniqueIdentifierPattern =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

const requirePrecommittedCustodyDirectoryPath = (input: {
    readonly custodyDirectoryPath: string;
    readonly resultPath: string;
}): string => {
    if (!path.isAbsolute(input.resultPath)) {
        throw new Error(
            'The proof-storage width result path must be absolute.',
        );
    }
    if (!path.isAbsolute(input.custodyDirectoryPath)) {
        throw new Error(
            'The proof-storage width custody directory path must be absolute.',
        );
    }
    const resolvedResultPath = path.resolve(input.resultPath);
    const resolvedCustodyDirectoryPath = path.resolve(
        input.custodyDirectoryPath,
    );
    if (resolvedResultPath !== input.resultPath) {
        throw new Error(
            'The proof-storage width result path must be canonical.',
        );
    }
    if (resolvedCustodyDirectoryPath !== input.custodyDirectoryPath) {
        throw new Error(
            'The proof-storage width custody directory path must be canonical.',
        );
    }
    if (
        path.dirname(resolvedCustodyDirectoryPath) !==
        path.dirname(resolvedResultPath)
    ) {
        throw new Error(
            'The proof-storage width custody directory must be an immediate child of the result directory.',
        );
    }
    const custodyDirectoryName = path.basename(resolvedCustodyDirectoryPath);
    const custodyDirectoryPrefix = `.${path.basename(resolvedResultPath)}.`;
    const custodyDirectorySuffix = '.bounded-custody';
    if (
        !custodyDirectoryName.startsWith(custodyDirectoryPrefix) ||
        !custodyDirectoryName.endsWith(custodyDirectorySuffix)
    ) {
        throw new Error(
            'The proof-storage width custody directory name is not bound to the result file.',
        );
    }
    const uniqueIdentifier = custodyDirectoryName.slice(
        custodyDirectoryPrefix.length,
        -custodyDirectorySuffix.length,
    );
    if (!custodyDirectoryUniqueIdentifierPattern.test(uniqueIdentifier)) {
        throw new Error(
            'The proof-storage width custody directory name must contain one canonical UUID.',
        );
    }
    return resolvedCustodyDirectoryPath;
};

export const buildProofStorageWidthCustodyDirectoryPath = (input: {
    readonly resultPath: string;
    readonly uniqueIdentifier?: string;
}): string => {
    if (!path.isAbsolute(input.resultPath)) {
        throw new Error(
            'The proof-storage width result path must be absolute.',
        );
    }
    const custodyDirectoryPath = path.join(
        path.dirname(input.resultPath),
        `.${path.basename(input.resultPath)}.${input.uniqueIdentifier ?? randomUUID()}.bounded-custody`,
    );
    return requirePrecommittedCustodyDirectoryPath({
        custodyDirectoryPath,
        resultPath: input.resultPath,
    });
};

const pathExists = async (filePath: string): Promise<boolean> => {
    try {
        await access(filePath);
        return true;
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'ENOENT'
        ) {
            return false;
        }
        throw error;
    }
};

const refuseAndRemovePrecommittedCustodyDirectoryIfPresent = async (input: {
    readonly cause?: unknown;
    readonly custodyDirectoryPath: string;
    readonly resultPath: string;
}): Promise<void> => {
    const custodyDirectoryPath = requirePrecommittedCustodyDirectoryPath({
        custodyDirectoryPath: input.custodyDirectoryPath,
        resultPath: input.resultPath,
    });
    if (!(await pathExists(custodyDirectoryPath))) {
        return;
    }
    try {
        await rm(custodyDirectoryPath, { force: false, recursive: true });
        if (await pathExists(custodyDirectoryPath)) {
            throw new Error(
                'The exact proof-storage width custody directory still exists after cleanup.',
            );
        }
    } catch (error) {
        throw new ProofStorageWidthLeftoverCustodyError({
            cause: error,
            cleanupCompleted: false,
            custodyPaths: [custodyDirectoryPath],
        });
    }
    throw new ProofStorageWidthLeftoverCustodyError({
        cause: input.cause,
        cleanupCompleted: true,
        custodyPaths: [custodyDirectoryPath],
    });
};

const writeJsonAtomicallyAndExclusively = async (
    filePath: string,
    value: unknown,
): Promise<void> => {
    await mkdir(path.dirname(filePath), { recursive: true });
    await requirePathDoesNotExist(filePath);
    const temporaryPath = path.join(
        path.dirname(filePath),
        `.${path.basename(filePath)}.${process.pid}.${randomUUID()}.tmp`,
    );
    const fileHandle = await open(temporaryPath, 'wx');
    let temporaryFileExists = true;
    try {
        await fileHandle.writeFile(`${JSON.stringify(value, null, 2)}\n`, {
            encoding: 'utf8',
        });
        await fileHandle.sync();
        await fileHandle.close();
        await link(temporaryPath, filePath);
        await unlink(temporaryPath);
        temporaryFileExists = false;
    } finally {
        await fileHandle.close().catch(() => undefined);
        if (temporaryFileExists) {
            await unlink(temporaryPath).catch(() => undefined);
        }
    }
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
            Object.entries(value).map(([key, nestedValue]) => [
                key,
                normalizeJsonValue(nestedValue),
            ]),
        );
    }
    return value;
};

const parseJsonEvidence = (
    serialized: string,
    description: string,
): unknown => {
    try {
        return JSON.parse(serialized) as unknown;
    } catch (error) {
        throw Object.assign(
            new Error(`${description} is not valid JSON: ${String(error)}`),
            { cause: error },
        );
    }
};

const validateProcessMemoryGuardLimitBinding = (input: {
    readonly expectedMemoryLimitBytes: number;
    readonly guardJsonLines: string;
    readonly guardName: string;
}): void => {
    const firstLine = input.guardJsonLines
        .split(/\r?\n/u)
        .find((line) => line.length !== 0);
    if (firstLine === undefined) {
        throw new Error(`${input.guardName} process-memory guard is empty.`);
    }
    const guardStartedRecord = requireEvidenceObject(
        parseJsonEvidence(firstLine, `${input.guardName} guard-started record`),
        `${input.guardName} guard-started record`,
    );
    if (
        guardStartedRecord.eventType !== 'guard-started' ||
        guardStartedRecord.memoryLimitBytes !== input.expectedMemoryLimitBytes
    ) {
        throw new Error(
            `${input.guardName} process-memory guard does not bind the expected memory limit.`,
        );
    }
};

const relativeDiagnosticPath = (
    runDirectoryPath: string,
    filePath: string,
): string =>
    path.relative(runDirectoryPath, filePath).split(path.sep).join('/');

const buildManifest = (input: {
    readonly commitHash: string;
    readonly memoryLimitBytes: number;
    readonly officialSampleReservationIdentitySha256Hex: string;
    readonly preflightAttachmentPath: string;
    readonly preflightEvidenceSha256Hex: string;
    readonly staticPreflight: ValidatedProofStorageWidthStaticPreflight;
    readonly staticPreflightAttachmentPath: string;
    readonly staticPreflightEvidenceSha256Hex: string;
    readonly staticPreflightGuardPath: string;
    readonly staticPreflightGuardSha256Hex: string;
}): Readonly<Record<string, unknown>> => {
    const staticGeometry = Object.fromEntries(
        proofStorageWidthSchedule.map((width) => [
            String(width),
            deriveProofStorageWidthGeometry(width),
        ]),
    );
    const absoluteCaps = {
        maximumCommonProofByteLength:
            proofStorageWidthProfile.maximumCommonProofByteLength,
        maximumCopiedBufferByteLength:
            proofStorageWidthProfile.maximumCopiedBufferByteLength,
        maximumLocalRecordSealInvocationCount:
            proofStorageWidthProfile.maximumLocalRecordSealInvocationCount,
        maximumLocalRecordSealedPlaintextByteLength:
            proofStorageWidthProfile.maximumLocalRecordSealedPlaintextByteLength,
        maximumPhysicalObjectCount:
            proofStorageWidthProfile.maximumPhysicalObjectCount,
        maximumStoredScratchByteLength:
            proofStorageWidthProfile.maximumStoredScratchByteLength,
        maximumTransportByteLength:
            proofStorageWidthProfile.maximumTransportByteLength,
        maximumWasmMemoryByteLength:
            proofStorageWidthProfile.maximumWasmMemoryByteLength,
    } as const;
    const applicableAbsoluteCaps = [
        {
            cap: 'common-proof-byte-length',
            enforcedBy: ['static-all-widths', 'native-each-width'],
        },
        {
            cap: 'transport-byte-length',
            enforcedBy: ['static-all-widths', 'native-each-width'],
        },
        {
            cap: 'physical-external-object-count',
            enforcedBy: ['static-all-widths', 'native-each-width'],
        },
        {
            cap: 'stored-scratch-byte-length',
            enforcedBy: ['static-all-widths', 'native-each-width'],
        },
        {
            cap: 'local-record-seal-invocation-count',
            enforcedBy: ['static-all-widths', 'native-each-width'],
        },
        {
            cap: 'local-record-sealed-plaintext-byte-length',
            enforcedBy: ['static-all-widths', 'native-each-width'],
        },
        {
            cap: 'copied-buffer-byte-length',
            enforcedBy: [
                'static-all-widths',
                'release-desktop-browser-width-512',
            ],
        },
        {
            cap: 'wasm-memory-byte-length',
            enforcedBy: [
                'static-all-widths',
                'release-desktop-browser-width-512',
            ],
        },
    ] as const;
    const absoluteCapTable = {
        applicableAbsoluteCaps,
        identifier: proofStorageWidthProfile.absoluteCapTableIdentifier,
        values: absoluteCaps,
    } as const;
    return {
        absoluteCaps,
        absoluteCapTable: {
            ...absoluteCapTable,
            identityShake256Hex: shake256Hex(absoluteCapTable),
        },
        backendProfile: {
            batchingFunctionCount:
                proofStorageWidthProfile.batchingFunctionCount,
            evaluationDomainSize: proofStorageWidthProfile.evaluationDomainSize,
            identifier: proofStorageWidthProfile.backendProfileIdentifier,
            queryRepresentativeCount:
                proofStorageWidthProfile.queryRepresentativeCount,
            sourceOpeningClaimCount:
                proofStorageWidthProfile.sourceOpeningClaimCount,
            traceRowCount: proofStorageWidthProfile.traceRowCount,
        },
        capOwnership: {
            nativeWidthPointsEnforce: [
                'common-proof-byte-length',
                'transport-byte-length',
                'physical-external-object-count',
                'stored-scratch-byte-length',
                'local-record-seal-invocation-count',
                'local-record-sealed-plaintext-byte-length',
            ],
            releaseDesktopBrowserWidth512Pending: [
                'copied-buffer-byte-length',
                'wasm-memory-byte-length',
            ],
        },
        cargoFeatureName,
        cargoProfile: 'release',
        custodyModel: 'bounded-external-storage-replay',
        custodySchema: {
            baseLeafObjectPersistence: 'prohibited',
            externalMemoryChunkByteLength:
                proofStorageWidthProfile.externalMemoryChunkByteLength,
            identifier: proofStorageWidthProfile.custodySchemaIdentifier,
            ldePersistence: 'prohibited',
            maximumNativePathByteLength:
                proofStorageWidthProfile.maximumNativeCustodyPathByteLength,
            model: 'bounded-external-storage-replay',
            version: proofStorageWidthProfile.custodySchemaVersion,
        },
        deterministicPublicColumnInput: {
            algorithm: proofStorageWidthProfile.publicColumnDerivationAlgorithm,
            domain: proofStorageWidthProfile.publicColumnInputDomain,
            frozenInputIdentityHashDomain:
                proofStorageWidthProfile.frozenInputIdentityHashDomain,
            frozenInputIdentityShake256Hex:
                proofStorageWidthProfile.frozenInputIdentityShake256Hex,
            frozenInputRecipeIdentifier:
                proofStorageWidthProfile.frozenInputRecipeIdentifier,
            ordering: 'column-major-row-major-canonical-le-u64',
            seedHex: proofStorageWidthProfile.publicColumnSeedHex,
            widthInputIdentityHashDomain:
                proofStorageWidthProfile.widthInputIdentityHashDomain,
        },
        deterministicWidthFormulae: {
            absorbedLeafValueCount: '393216 * width',
            activeColumnLdeScratchByteLength: '1048576',
            boundaryTransferByteLengthCeiling:
                'max((156 + 32 + 49152) + 80, (156 + 32) + (80 + 88 + 49152)) = 49508',
            browserOperationRegistryByteLengthCeiling:
                'sizeOfRefCellBrowserRegistry + 16 * (sizeOfU32Handle + sizeOfBrowserOperation) + 64',
            canonicalArtifactLiveCopyByteLengthCeiling:
                '2 * canonicalProofByteLengthCeiling',
            copiedBufferByteLengthCeiling:
                'max(156 + 32 + 49152, 80 + 88 + 49152) = 49340',
            extensionDomainWorkingByteLengthCeiling: '10485760',
            freshVerifierPublicOpeningWorkspaceByteLengthCeiling:
                '29280 * width + 1681152',
            legacyBaseLeafObjectByteLength: '65536 * (124 + 16 * width)',
            ldeTransformCount: '6 * width',
            nativeCustodyMetadataByteLengthCeiling: '1112 * (width + 2) + 88',
            openedLeafElementByteLength: '128 + 16 * width',
            openedValueCount: '366 * width',
            publicBaseLeafByteLength: '124 + 16 * width',
            queriedLeafPayloadByteLength: '183 * (124 + 16 * width)',
            rawAbiRequestCopyWorkspaceByteLengthCeiling: '345680',
            rawAbiResponseDecodeWorkspaceByteLengthCeiling: '345704',
            rawAbiTransferWorkspaceByteLengthCeiling: '345704',
            retainedAlgebraicCoefficientByteLengthCeiling: '1048576',
            proverPublicOpeningWorkspaceByteLengthCeiling:
                '17568 * width + 32384',
            sourceCommittedTransactionCount: '24 * width',
            sourceReplayByteLength: '131072 * width',
            wasmMemoryByteLengthCeiling:
                'digestState + digestStateContainer + frozenFixtureAndContainer + activeColumnLdeScratch + retainedAlgebraicCoefficients + extensionDomainWorking + canonicalArtifactLiveCopies + canonicalArtifactContainers + openingArtifactAndTranscript + proverPublicOpeningWorkspace + freshVerifierPublicOpeningWorkspace + freshVerifierOuterVectorContainers + rawAbiTransferWorkspace + browserOperationRegistry',
            widthDependentQueriedBaseOpeningByteLength: '2928 * width',
        },
        exactCandidate: {
            firstDataModulus: proofStorageWidthProfile.firstDataModulus,
            materialRadix: proofStorageWidthProfile.materialRadix,
            plaintextModulus: proofStorageWidthProfile.plaintextModulus,
            ringDimension: proofStorageWidthProfile.ringDimension,
            rosterSize: proofStorageWidthProfile.rosterSize,
        },
        formatVersion: 1,
        guard: {
            aggregateProcessTree: true,
            memoryLimitBytes: input.memoryLimitBytes,
            maximumOperationWindowGapMilliseconds: 500,
            resourceSampleIntervalMilliseconds,
        },
        ledger: {
            algebraicBaseColumnCount:
                proofStorageWidthProfile.algebraicBaseColumnCount,
            batchingFunctionCount:
                proofStorageWidthProfile.batchingFunctionCount,
            sourceOpeningClaimCount:
                proofStorageWidthProfile.sourceOpeningClaimCount,
            evaluationDomainSize: proofStorageWidthProfile.evaluationDomainSize,
            traceRowCount: proofStorageWidthProfile.traceRowCount,
        },
        mandatoryPreflight: {
            attachmentPath: input.preflightAttachmentPath,
            evidenceSha256Hex: input.preflightEvidenceSha256Hex,
            repositoryCommitHash: input.commitHash,
        },
        officialSampleReservation: {
            identitySha256Hex: input.officialSampleReservationIdentitySha256Hex,
            officialOwner: proofStorageWidthMeasurementTestName,
            schemaVersion: 1,
        },
        queryDependentMeasurementBoundary: {
            actualRootBoundQueryLayoutRunsOnlyInOfficialWidthSample: true,
            duplicateWidthWorkloadProhibited: true,
            frozenQueryVectorProhibited: true,
            paddedCanonicalProofProhibited: true,
            staticGateUsesConservativeCanonicalCeilings: true,
            totalProofAffineProjectionProhibited: true,
        },
        releaseTestOwner: proofStorageWidthEvidenceTestFilter,
        intendedReleaseProfile: {
            cargoProfile: 'release',
            identifier: proofStorageWidthProfile.releaseProfileIdentifier,
            representativeBrowserWidth:
                proofStorageWidthProfile.representativeBrowserWidth,
            runtime: proofStorageWidthProfile.intendedReleaseRuntime,
        },
        measurementProfile: {
            cargoProfile: 'release',
            conservativeLayoutParameters: {
                btreeEntryStorageMultiplier:
                    proofStorageWidthProfile.conservativeBtreeEntryStorageMultiplier.toString(),
                heapAllocationOverheadByteLength:
                    proofStorageWidthProfile.conservativeHeapAllocationOverheadByteLength.toString(),
                proofTreeCount:
                    proofStorageWidthProfile.proofTreeCount.toString(),
                queryRepresentativeCount:
                    proofStorageWidthProfile.queryRepresentativeCount.toString(),
            },
            native64LayoutByteLengths: {
                authenticatedMapEntry:
                    proofStorageWidthProfile.authenticatedMapEntryByteLengthNative64.toString(),
                authenticatedTreeOpeningHeader:
                    proofStorageWidthProfile.authenticatedTreeOpeningHeaderByteLengthNative64.toString(),
                btreeMapHeader:
                    proofStorageWidthProfile.btreeMapHeaderByteLengthNative64.toString(),
                proofChallengeExtensionElement:
                    proofStorageWidthProfile.proofChallengeExtensionElementByteLength.toString(),
                proofTreeValue:
                    proofStorageWidthProfile.proofTreeValueByteLengthNative64.toString(),
                vectorHeader:
                    proofStorageWidthProfile.vectorHeaderByteLengthNative64.toString(),
            },
            runtime: proofStorageWidthProfile.measurementRuntime,
        },
        repository: {
            commitHash: input.commitHash,
            treeDirty: false,
        },
        schedule: proofStorageWidthSchedule,
        staticPreflight: {
            attachmentPath: input.staticPreflightAttachmentPath,
            evidenceSha256Hex: input.staticPreflightEvidenceSha256Hex,
            guardPath: input.staticPreflightGuardPath,
            guardSha256Hex: input.staticPreflightGuardSha256Hex,
            points: input.staticPreflight.points,
            repositoryCommitHash: input.commitHash,
        },
        staticGeometry,
        superlinearRule: {
            elapsedFixedTermWidth: 8,
            elapsedSlopeAnchorWidth: 32,
            maximumLinearEnvelopeFactor: 2,
            transactionChunkBoundaryExemptionOnly: true,
            transactionChunkBoundaryNormalizationMultiplier: 2,
        },
        uncappedMeasuredMetrics: [
            'external-io-byte-length',
            'committed-transaction-count',
        ],
    };
};

const shake256Hex = (value: unknown): string =>
    createHash('shake256', { outputLength: 64 })
        .update(JSON.stringify(normalizeJsonValue(value)))
        .digest('hex');

export type ValidatedProofStorageWidthEvidencePoint = Readonly<{
    baselineProcessTreeResidentMemoryByteLength: bigint;
    peakProcessTreeResidentMemoryByteLength: bigint;
    result: ValidatedProofStorageWidthPoint['result'];
    resultRecord: JsonObject;
    scheduleOrdinal: number;
}>;

export type ValidatedProofStorageWidthObservedEvidence = Readonly<{
    decision: ProofStorageWidthCurveDecision;
    manifestIdentityShake256Hex: string;
    officialSampleReservationIdentitySha256Hex: string;
    points: readonly ValidatedProofStorageWidthEvidencePoint[];
    repositoryCommitHash: string;
    staticPreflight: ValidatedProofStorageWidthStaticPreflight;
}>;

export type ValidatedProofStorageWidthEvidence =
    ValidatedProofStorageWidthObservedEvidence &
        Readonly<{
            fullWidthPoint: ValidatedProofStorageWidthEvidencePoint;
            representativePoint: ValidatedProofStorageWidthEvidencePoint;
        }>;

const requireEvidenceObject = (
    value: unknown,
    fieldName: string,
): JsonObject => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${fieldName} must be a JSON object.`);
    }
    return value as JsonObject;
};

const requireEvidenceString = (value: unknown, fieldName: string): string => {
    if (typeof value !== 'string') {
        throw new Error(`${fieldName} must be a string.`);
    }
    return value;
};

const requireEvidenceSha256Hex = (
    value: unknown,
    fieldName: string,
): string => {
    const digest = requireEvidenceString(value, fieldName);
    if (!sha256HexPattern.test(digest)) {
        throw new Error(`${fieldName} must be a lowercase SHA-256 digest.`);
    }
    return digest;
};

const requireEvidenceShake256Hex = (
    value: unknown,
    fieldName: string,
): string => {
    const digest = requireEvidenceString(value, fieldName);
    if (!/^[0-9a-f]{128}$/u.test(digest)) {
        throw new Error(
            `${fieldName} must be a lowercase SHAKE256-512 digest.`,
        );
    }
    return digest;
};

const requireExactRelativeArtifactPath = (input: {
    readonly actual: unknown;
    readonly expected: string;
    readonly fieldName: string;
    readonly runDirectoryPath: string;
}): string => {
    const relativePath = requireEvidenceString(input.actual, input.fieldName);
    if (relativePath !== input.expected || path.isAbsolute(relativePath)) {
        throw new Error(
            `${input.fieldName} must be the exact run-local path ${input.expected}.`,
        );
    }
    const resolvedRunDirectoryPath = path.resolve(input.runDirectoryPath);
    const resolvedArtifactPath = path.resolve(
        resolvedRunDirectoryPath,
        relativePath,
    );
    if (
        resolvedArtifactPath === resolvedRunDirectoryPath ||
        !resolvedArtifactPath.startsWith(
            `${resolvedRunDirectoryPath}${path.sep}`,
        )
    ) {
        throw new Error(`${input.fieldName} escapes the evidence run.`);
    }
    return resolvedArtifactPath;
};

const requirePinnedEvidenceRepositoryState = (input: {
    readonly expectedCommitHash: string;
    readonly fieldName: string;
    readonly value: unknown;
}): RepositoryState => {
    const record = requireEvidenceObject(input.value, input.fieldName);
    if (
        record.commitHash !== input.expectedCommitHash ||
        record.treeDirty !== false
    ) {
        throw new Error(
            `${input.fieldName} must bind the exact clean evidence commit.`,
        );
    }
    return {
        commitHash: input.expectedCommitHash,
        treeDirty: false,
    };
};

const requireArtifactDigest = (input: {
    readonly expectedSha256Hex: string;
    readonly fieldName: string;
    readonly serialized: string;
}): void => {
    const actualSha256Hex = createHash('sha256')
        .update(input.serialized)
        .digest('hex');
    if (actualSha256Hex !== input.expectedSha256Hex) {
        throw new Error(
            `${input.fieldName} SHA-256 digest does not match its evidence binding.`,
        );
    }
};

const validateNativeOfficialReservationArtifact = (input: {
    readonly identitySha256Hex: string;
    readonly manifestIdentityShake256Hex: string;
    readonly scheduleOrdinal: number;
    readonly serialized: string;
    readonly sourceCommitHash: string;
    readonly width: ProofStorageWidth;
}): void => {
    const records = input.serialized
        .split(/\r?\n/u)
        .filter((line) => line.length !== 0)
        .map((line, lineIndex) =>
            requireEvidenceObject(
                parseJsonEvidence(
                    line,
                    `Native reservation line ${lineIndex + 1}`,
                ),
                `Native reservation line ${lineIndex + 1}`,
            ),
        );
    const started = records[0];
    const outcome = records[1];
    if (
        records.length !== 2 ||
        started === undefined ||
        outcome === undefined
    ) {
        throw new Error(
            'The native official reservation must contain exactly one start and one outcome record.',
        );
    }
    if (
        started.eventType !== 'official-native-width-sample-started' ||
        started.identitySha256Hex !== input.identitySha256Hex ||
        started.manifestIdentityShake256Hex !==
            input.manifestIdentityShake256Hex ||
        started.officialOwner !== proofStorageWidthMeasurementTestName ||
        typeof started.recordedAtUnixMilliseconds !== 'number' ||
        !Number.isSafeInteger(started.recordedAtUnixMilliseconds) ||
        started.recordedAtUnixMilliseconds < 0 ||
        started.scheduleOrdinal !== input.scheduleOrdinal ||
        started.sourceCommitHash !== input.sourceCommitHash ||
        started.width !== input.width
    ) {
        throw new Error(
            'The native official reservation start record changed its canonical sample binding.',
        );
    }
    if (
        outcome.eventType !== 'official-sample-outcome' ||
        outcome.outcome !== 'validated' ||
        typeof outcome.recordedAtUnixMilliseconds !== 'number' ||
        !Number.isSafeInteger(outcome.recordedAtUnixMilliseconds) ||
        outcome.recordedAtUnixMilliseconds < started.recordedAtUnixMilliseconds
    ) {
        throw new Error(
            'The native official reservation lacks one validated observed outcome.',
        );
    }
};

const normalizedJsonEquals = (left: unknown, right: unknown): boolean =>
    JSON.stringify(normalizeJsonValue(left)) ===
    JSON.stringify(normalizeJsonValue(right));

export const validateProofStorageWidthObservedEvidenceArtifacts = async (
    evidencePath: string,
    options: Readonly<{ officialReservationRootPath?: string }> = {},
): Promise<ValidatedProofStorageWidthObservedEvidence> => {
    if (!path.isAbsolute(evidencePath)) {
        throw new Error(
            'The proof-storage width evidence path must be absolute.',
        );
    }
    const resolvedEvidencePath = path.resolve(evidencePath);
    const runDirectoryPath = path.resolve(
        path.dirname(resolvedEvidencePath),
        '..',
        '..',
    );
    const officialReservationRootPath =
        options.officialReservationRootPath ??
        defaultProofStorageWidthOfficialReservationRootPath;
    if (!path.isAbsolute(officialReservationRootPath)) {
        throw new Error(
            'The official reservation root used for evidence reopening must be absolute.',
        );
    }
    const resolvedOfficialReservationRootPath = path.resolve(
        officialReservationRootPath,
    );
    const reservationRootRelativeFromRun = path.relative(
        runDirectoryPath,
        resolvedOfficialReservationRootPath,
    );
    if (
        reservationRootRelativeFromRun.length === 0 ||
        (!reservationRootRelativeFromRun.startsWith(`..${path.sep}`) &&
            reservationRootRelativeFromRun !== '..' &&
            !path.isAbsolute(reservationRootRelativeFromRun))
    ) {
        throw new Error(
            'The official reservation root used for evidence reopening must stay outside the run directory.',
        );
    }
    const expectedEvidencePath = path.resolve(
        runDirectoryPath,
        'attachments',
        'proof-storage-width',
        'proof-storage-width-evidence.json',
    );
    if (resolvedEvidencePath !== expectedEvidencePath) {
        throw new Error(
            'The proof-storage width evidence file is outside its exact run attachment location.',
        );
    }
    const evidence = requireEvidenceObject(
        parseJsonEvidence(
            await readFile(resolvedEvidencePath, 'utf8'),
            'Proof-storage width evidence',
        ),
        'Proof-storage width evidence',
    );
    if (evidence.formatVersion !== 3) {
        throw new Error(
            'Proof-storage width evidence must use integrity format version three.',
        );
    }
    const repository = requireEvidenceObject(evidence.repository, 'repository');
    const initialRepository = requireEvidenceObject(
        repository.initial,
        'repository.initial',
    );
    const repositoryCommitHash = requireEvidenceString(
        initialRepository.commitHash,
        'repository.initial.commitHash',
    );
    if (!exactCommitHashPattern.test(repositoryCommitHash)) {
        throw new Error(
            'repository.initial.commitHash must be an exact lowercase 40-hex commit.',
        );
    }
    for (const checkpoint of ['initial', 'before', 'after'] as const) {
        requirePinnedEvidenceRepositoryState({
            expectedCommitHash: repositoryCommitHash,
            fieldName: `repository.${checkpoint}`,
            value: repository[checkpoint],
        });
    }
    const manifestIdentityShake256Hex = requireEvidenceShake256Hex(
        evidence.manifestIdentityShake256Hex,
        'manifestIdentityShake256Hex',
    );
    const officialSampleReservation = requireEvidenceObject(
        evidence.officialSampleReservation,
        'officialSampleReservation',
    );
    const officialSampleReservationIdentitySha256Hex = requireEvidenceSha256Hex(
        officialSampleReservation.identitySha256Hex,
        'officialSampleReservation.identitySha256Hex',
    );
    if (
        officialSampleReservation.officialOwner !==
            proofStorageWidthMeasurementTestName ||
        officialSampleReservation.schemaVersion !== 1
    ) {
        throw new Error(
            'The official sample reservation binding changed its owner or schema.',
        );
    }
    const manifestSha256Hex = requireEvidenceSha256Hex(
        evidence.manifestSha256Hex,
        'manifestSha256Hex',
    );
    const mandatoryPreflight = requireEvidenceObject(
        evidence.mandatoryPreflight,
        'mandatoryPreflight',
    );
    const staticPreflightBinding = requireEvidenceObject(
        evidence.staticPreflight,
        'staticPreflight',
    );
    for (const [fieldName, binding] of [
        ['mandatoryPreflight', mandatoryPreflight],
        ['staticPreflight', staticPreflightBinding],
    ] as const) {
        if (binding.repositoryCommitHash !== repositoryCommitHash) {
            throw new Error(
                `${fieldName}.repositoryCommitHash changed the pinned evidence commit.`,
            );
        }
    }
    const manifestRelativePath =
        'attachments/proof-storage-width/proof-storage-width-manifest.json';
    const preflightRelativePath =
        'attachments/proof-backend-bakeoff-preflight-evidence.json';
    const staticPreflightRelativePath =
        'attachments/proof-storage-width/proof-storage-width-static-preflight.json';
    const staticGuardRelativePath =
        'resources/process-memory-guard-proof-storage-width-static-preflight.jsonl';
    const manifestPath = requireExactRelativeArtifactPath({
        actual: evidence.manifestPath,
        expected: manifestRelativePath,
        fieldName: 'manifestPath',
        runDirectoryPath,
    });
    const preflightPath = requireExactRelativeArtifactPath({
        actual: mandatoryPreflight.attachmentPath,
        expected: preflightRelativePath,
        fieldName: 'mandatoryPreflight.attachmentPath',
        runDirectoryPath,
    });
    const staticPreflightPath = requireExactRelativeArtifactPath({
        actual: staticPreflightBinding.attachmentPath,
        expected: staticPreflightRelativePath,
        fieldName: 'staticPreflight.attachmentPath',
        runDirectoryPath,
    });
    const staticGuardPath = requireExactRelativeArtifactPath({
        actual: staticPreflightBinding.guardPath,
        expected: staticGuardRelativePath,
        fieldName: 'staticPreflight.guardPath',
        runDirectoryPath,
    });
    const [serializedManifest, serializedPreflight, serializedStaticPreflight] =
        await Promise.all([
            readFile(manifestPath, 'utf8'),
            readFile(preflightPath, 'utf8'),
            readFile(staticPreflightPath, 'utf8'),
        ]);
    requireArtifactDigest({
        expectedSha256Hex: manifestSha256Hex,
        fieldName: 'Manifest artifact',
        serialized: serializedManifest,
    });
    const preflightEvidenceSha256Hex = requireEvidenceSha256Hex(
        mandatoryPreflight.evidenceSha256Hex,
        'mandatoryPreflight.evidenceSha256Hex',
    );
    requireArtifactDigest({
        expectedSha256Hex: preflightEvidenceSha256Hex,
        fieldName: 'Mandatory preflight artifact',
        serialized: serializedPreflight,
    });
    const staticPreflightEvidenceSha256Hex = requireEvidenceSha256Hex(
        staticPreflightBinding.evidenceSha256Hex,
        'staticPreflight.evidenceSha256Hex',
    );
    requireArtifactDigest({
        expectedSha256Hex: staticPreflightEvidenceSha256Hex,
        fieldName: 'Static preflight artifact',
        serialized: serializedStaticPreflight,
    });
    const staticPreflightGuardSha256Hex = requireEvidenceSha256Hex(
        staticPreflightBinding.guardSha256Hex,
        'staticPreflight.guardSha256Hex',
    );
    const staticPreflight = validateProofStorageWidthStaticPreflightResult(
        parseJsonEvidence(
            serializedStaticPreflight,
            'Proof-storage width static preflight artifact',
        ),
    );
    const manifestEnvelope = requireEvidenceObject(
        parseJsonEvidence(serializedManifest, 'Proof-storage width manifest'),
        'Proof-storage width manifest',
    );
    const manifest = requireEvidenceObject(
        manifestEnvelope.manifest,
        'manifest',
    );
    const manifestEnvelopeIdentity = requireEvidenceShake256Hex(
        manifestEnvelope.manifestIdentityShake256Hex,
        'manifest.manifestIdentityShake256Hex',
    );
    const recomputedManifestIdentity = shake256Hex(manifest);
    if (
        manifestEnvelopeIdentity !== manifestIdentityShake256Hex ||
        recomputedManifestIdentity !== manifestIdentityShake256Hex
    ) {
        throw new Error(
            'The manifest artifact does not recompute to the evidence manifest identity.',
        );
    }
    const manifestGuard = requireEvidenceObject(
        manifest.guard,
        'manifest.guard',
    );
    if (
        typeof manifestGuard.memoryLimitBytes !== 'number' ||
        !Number.isSafeInteger(manifestGuard.memoryLimitBytes) ||
        manifestGuard.memoryLimitBytes <= 0
    ) {
        throw new Error(
            'manifest.guard.memoryLimitBytes must be a positive safe integer.',
        );
    }
    await validateProofBackendBakeoffPreflightEvidenceArtifacts({
        attachmentPath: preflightPath,
        expectedCommitHash: repositoryCommitHash,
        expectedMemoryLimitBytes: manifestGuard.memoryLimitBytes,
    });
    await readAndValidateCompletedProcessMemoryGuardArtifact({
        diagnosticsPath: staticGuardPath,
        expectedMemoryLimitBytes: manifestGuard.memoryLimitBytes,
        expectedSha256Hex: staticPreflightGuardSha256Hex,
    });
    const expectedOfficialSampleReservation =
        buildProofStorageWidthNativeReservationIdentity({
            memoryLimitBytes: manifestGuard.memoryLimitBytes,
            officialOwner: proofStorageWidthMeasurementTestName,
            sourceCommitHash: repositoryCommitHash,
        });
    if (
        officialSampleReservationIdentitySha256Hex !==
        expectedOfficialSampleReservation.identitySha256Hex
    ) {
        throw new Error(
            'The official sample reservation identity does not match the canonical source, candidate, profile, schedule, cap, guard, and owner tuple.',
        );
    }
    const expectedManifest = buildManifest({
        commitHash: repositoryCommitHash,
        memoryLimitBytes: manifestGuard.memoryLimitBytes,
        officialSampleReservationIdentitySha256Hex,
        preflightAttachmentPath: preflightRelativePath,
        preflightEvidenceSha256Hex,
        staticPreflight,
        staticPreflightAttachmentPath: staticPreflightRelativePath,
        staticPreflightEvidenceSha256Hex,
        staticPreflightGuardPath: staticGuardRelativePath,
        staticPreflightGuardSha256Hex,
    });
    if (!normalizedJsonEquals(manifest, expectedManifest)) {
        throw new Error(
            'The manifest does not match the exact candidate, caps, profiles, custody, schedule, and static-preflight bindings.',
        );
    }
    if (
        !Array.isArray(evidence.sampleArtifacts) ||
        !Array.isArray(evidence.points) ||
        evidence.points.length === 0 ||
        evidence.points.length > proofStorageWidthSchedule.length ||
        evidence.sampleArtifacts.length !== evidence.points.length
    ) {
        throw new Error(
            'Proof-storage width evidence must contain one exact nonempty schedule prefix with one artifact binding per point.',
        );
    }
    const observedSchedule = proofStorageWidthSchedule.slice(
        0,
        evidence.points.length,
    );
    const points: ValidatedProofStorageWidthEvidencePoint[] = [];
    for (const [pointIndex, width] of observedSchedule.entries()) {
        const scheduleOrdinal = pointIndex + 1;
        const sampleArtifact = requireEvidenceObject(
            evidence.sampleArtifacts[pointIndex],
            `sampleArtifacts[${pointIndex}]`,
        );
        if (
            sampleArtifact.width !== width ||
            sampleArtifact.scheduleOrdinal !== scheduleOrdinal
        ) {
            throw new Error(
                `sampleArtifacts[${pointIndex}] changed the precommitted width schedule.`,
            );
        }
        for (const checkpoint of [
            'repositoryBefore',
            'repositoryAfter',
        ] as const) {
            requirePinnedEvidenceRepositoryState({
                expectedCommitHash: repositoryCommitHash,
                fieldName: `sampleArtifacts[${pointIndex}].${checkpoint}`,
                value: sampleArtifact[checkpoint],
            });
        }
        const sampleStem = `width-${String(width).padStart(4, '0')}`;
        const resultPath = requireExactRelativeArtifactPath({
            actual: sampleArtifact.resultPath,
            expected: `attachments/proof-storage-width/samples/${sampleStem}-result.json`,
            fieldName: `sampleArtifacts[${pointIndex}].resultPath`,
            runDirectoryPath,
        });
        const guardPath = requireExactRelativeArtifactPath({
            actual: sampleArtifact.guardPath,
            expected: `resources/process-memory-guard-${sampleStem}.jsonl`,
            fieldName: `sampleArtifacts[${pointIndex}].guardPath`,
            runDirectoryPath,
        });
        const reservationPath = requireExactRelativeArtifactPath({
            actual: sampleArtifact.reservationPath,
            expected: `native/${officialSampleReservationIdentitySha256Hex}/width-${scheduleOrdinal}-started.json`,
            fieldName: `sampleArtifacts[${pointIndex}].reservationPath`,
            runDirectoryPath: resolvedOfficialReservationRootPath,
        });
        const [serializedResult, serializedGuard, serializedReservation] =
            await Promise.all([
                readFile(resultPath, 'utf8'),
                readFile(guardPath, 'utf8'),
                readFile(reservationPath, 'utf8'),
            ]);
        requireArtifactDigest({
            expectedSha256Hex: requireEvidenceSha256Hex(
                sampleArtifact.resultSha256Hex,
                `sampleArtifacts[${pointIndex}].resultSha256Hex`,
            ),
            fieldName: `Width ${width} result artifact`,
            serialized: serializedResult,
        });
        requireArtifactDigest({
            expectedSha256Hex: requireEvidenceSha256Hex(
                sampleArtifact.guardSha256Hex,
                `sampleArtifacts[${pointIndex}].guardSha256Hex`,
            ),
            fieldName: `Width ${width} guard artifact`,
            serialized: serializedGuard,
        });
        requireArtifactDigest({
            expectedSha256Hex: requireEvidenceSha256Hex(
                sampleArtifact.reservationSha256Hex,
                `sampleArtifacts[${pointIndex}].reservationSha256Hex`,
            ),
            fieldName: `Width ${width} official reservation artifact`,
            serialized: serializedReservation,
        });
        validateNativeOfficialReservationArtifact({
            identitySha256Hex: officialSampleReservationIdentitySha256Hex,
            manifestIdentityShake256Hex,
            scheduleOrdinal,
            serialized: serializedReservation,
            sourceCommitHash: repositoryCommitHash,
            width,
        });
        const resultRecord = requireEvidenceObject(
            parseJsonEvidence(
                serializedResult,
                `Proof-storage width ${width} result artifact`,
            ),
            `Proof-storage width ${width} result artifact`,
        );
        validateProcessMemoryGuardLimitBinding({
            expectedMemoryLimitBytes: manifestGuard.memoryLimitBytes,
            guardJsonLines: serializedGuard,
            guardName: `Width ${width}`,
        });
        const point = validateProofStorageWidthPoint({
            expectedScheduleOrdinal: scheduleOrdinal,
            guardJsonLines: serializedGuard,
            result: resultRecord,
        });
        if (
            point.result.manifestIdentityShake256Hex !==
            manifestIdentityShake256Hex
        ) {
            throw new Error(
                `Width ${width} result does not bind the recomputed manifest identity.`,
            );
        }
        const staticPoint = staticPreflight.points[pointIndex];
        if (staticPoint === undefined) {
            throw new Error(`Static preflight omitted width ${width}.`);
        }
        validateProofStorageWidthPointAgainstStaticPreflight({
            point,
            staticPoint,
        });
        if (!normalizedJsonEquals(evidence.points[pointIndex], point)) {
            throw new Error(
                `Serialized width ${width} point does not match the raw result and re-derived guard peak.`,
            );
        }
        points.push({
            ...point,
            resultRecord,
        });
    }
    const decision = evaluateProofStorageWidthCurve(points);
    for (
        let prefixLength = 1;
        prefixLength < points.length;
        prefixLength += 1
    ) {
        const earlierDecision = evaluateProofStorageWidthCurve(
            points.slice(0, prefixLength),
        );
        if (earlierDecision.outcome !== 'continue') {
            throw new Error(
                `Proof-storage width evidence continued after schedule ordinal ${prefixLength} had already produced the decisive ${earlierDecision.outcome} outcome.`,
            );
        }
    }
    if (decision.outcome === 'continue') {
        throw new Error(
            'Proof-storage width evidence stopped before reaching a decisive curve outcome.',
        );
    }
    if (!normalizedJsonEquals(evidence.decision, decision)) {
        throw new Error(
            'The serialized proof-storage width decision is self-asserted or does not match the recomputed curve.',
        );
    }
    return Object.freeze({
        decision,
        manifestIdentityShake256Hex,
        officialSampleReservationIdentitySha256Hex,
        points: Object.freeze(points),
        repositoryCommitHash,
        staticPreflight,
    });
};

export const validateProofStorageWidthEvidenceArtifacts = async (
    evidencePath: string,
    options: Readonly<{ officialReservationRootPath?: string }> = {},
): Promise<ValidatedProofStorageWidthEvidence> => {
    const evidence = await validateProofStorageWidthObservedEvidenceArtifacts(
        evidencePath,
        options,
    );
    if (
        evidence.decision.outcome !== 'full-width-complete' ||
        evidence.points.length !== proofStorageWidthSchedule.length
    ) {
        throw new Error(
            `Recomputed proof-storage width decision is ${evidence.decision.outcome}; serialized full-width eligibility is refused.`,
        );
    }
    const representativePoint = evidence.points.find(
        (point) =>
            point.result.publicBaseLeafColumnCount ===
            proofStorageWidthProfile.representativeBrowserWidth,
    );
    const fullWidthPoint = evidence.points[evidence.points.length - 1];
    if (
        representativePoint === undefined ||
        fullWidthPoint === undefined ||
        fullWidthPoint.result.publicBaseLeafColumnCount !== 3_451
    ) {
        throw new Error(
            'Validated evidence omitted the representative or full-width point.',
        );
    }
    return Object.freeze({
        ...evidence,
        fullWidthPoint,
        representativePoint,
    });
};

const executeProofStorageWidthEvidenceSequenceAttempt = async (input: {
    readonly dependencies?: ProofStorageWidthEvidenceRunnerDependencies;
    readonly runLog: ActiveLocalRunLog;
}): Promise<ProofStorageWidthEvidenceRunResult> => {
    if (
        proofStorageWidthSchedule.length !== 7 ||
        new Set(proofStorageWidthSchedule).size !== 7
    ) {
        throw new Error(
            'The proof-storage width schedule must contain exactly seven distinct points.',
        );
    }
    const executeCommand =
        input.dependencies?.executeCommand ?? defaultCommandExecutor;
    const processMemoryGuard =
        input.dependencies?.processMemoryGuard ??
        createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription:
                'Proof-storage width evidence',
            memoryLimitEnvironmentVariable:
                'SEALED_LATTICE_GUARDED_RUST_MEMORY_LIMIT_GIB',
        });
    const readRepositoryState =
        input.dependencies?.readRepositoryState ??
        ((checkpoint: RepositoryCheckpoint, runLog: ActiveLocalRunLog) =>
            readRepositoryStateWithCommands({
                checkpoint,
                executeCommand,
                runLog,
            }));
    const repositoryStateInitial = await readRepositoryState(
        'initial',
        input.runLog,
    );
    requireCleanPinnedRepository(repositoryStateInitial, 'initial');
    const officialReservationRootPath =
        input.dependencies?.officialReservationRootPath ??
        defaultProofStorageWidthOfficialReservationRootPath;
    const officialSampleReservation =
        buildProofStorageWidthNativeReservationIdentity({
            memoryLimitBytes: processMemoryGuard.memoryLimitBytes,
            officialOwner: proofStorageWidthMeasurementTestName,
            sourceCommitHash: repositoryStateInitial.commitHash,
        });

    const attachmentDirectoryPath = path.join(
        input.runLog.runDirectoryPath,
        'attachments',
        'proof-storage-width',
    );
    const sampleDirectoryPath = path.join(attachmentDirectoryPath, 'samples');
    const resourceDirectoryPath = path.join(
        input.runLog.runDirectoryPath,
        'resources',
    );
    await Promise.all([
        mkdir(sampleDirectoryPath, { recursive: true }),
        mkdir(resourceDirectoryPath, { recursive: true }),
    ]);

    const cargoEnvironment = buildProofStorageWidthEnvironment();
    await executeRequiredCommand({
        command: buildProofStorageWidthPrecompileCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    const featureListResult = await executeRequiredCommand({
        command: buildProofStorageWidthFeatureListCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    parseProofStorageWidthFeatureInventory(featureListResult.stdout);
    const listResult = await executeRequiredCommand({
        command: buildProofStorageWidthListCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    const exactTestName = parseProofStorageWidthTestInventory(
        listResult.stdout,
    );
    await executeRequiredCommand({
        command: processMemoryGuard.buildVerificationCommand(),
        executeCommand,
        runLog: input.runLog,
    });

    const preflightResult = await executeProofBackendBakeoffPreflightSequence({
        dependencies: {
            executeCommand,
            processMemoryGuard,
            readRepositoryState,
        },
        runLog: input.runLog,
    });
    const serializedPreflightEvidence = await readFile(
        preflightResult.attachmentPath,
        'utf8',
    );
    await validateProofBackendBakeoffPreflightEvidenceArtifacts({
        attachmentPath: preflightResult.attachmentPath,
        expectedCommitHash: repositoryStateInitial.commitHash,
        expectedMemoryLimitBytes: processMemoryGuard.memoryLimitBytes,
    });
    const preflightEvidenceSha256Hex = createHash('sha256')
        .update(serializedPreflightEvidence)
        .digest('hex');

    const staticPreflightResultPath = path.join(
        attachmentDirectoryPath,
        'proof-storage-width-static-preflight.json',
    );
    const staticPreflightGuardPath = path.join(
        resourceDirectoryPath,
        'process-memory-guard-proof-storage-width-static-preflight.jsonl',
    );
    await Promise.all([
        requirePathDoesNotExist(staticPreflightResultPath),
        requirePathDoesNotExist(staticPreflightGuardPath),
    ]);
    await executeRequiredCommand({
        command: processMemoryGuard.guardCommand(
            buildProofStorageWidthStaticPreflightCommand({
                baseEnvironment: cargoEnvironment,
                resultPath: staticPreflightResultPath,
            }),
            {
                diagnosticsPath: staticPreflightGuardPath,
                resourceSampleIntervalMilliseconds,
            },
        ),
        executeCommand,
        runLog: input.runLog,
    });
    const [serializedStaticPreflight, staticPreflightGuardSha256Hex] =
        await Promise.all([
            readFile(staticPreflightResultPath, 'utf8'),
            readAndValidateCompletedProcessMemoryGuardArtifact({
                diagnosticsPath: staticPreflightGuardPath,
                expectedMemoryLimitBytes: processMemoryGuard.memoryLimitBytes,
            }),
        ]);
    const staticPreflight = validateProofStorageWidthStaticPreflightResult(
        parseJsonEvidence(
            serializedStaticPreflight,
            'Proof-storage width static preflight result',
        ),
    );
    const staticPreflightEvidenceSha256Hex = createHash('sha256')
        .update(serializedStaticPreflight)
        .digest('hex');
    const repositoryStateBefore = await readRepositoryState(
        'before',
        input.runLog,
    );
    requireCleanPinnedRepository(repositoryStateBefore, 'before');
    if (
        repositoryStateBefore.commitHash !== repositoryStateInitial.commitHash
    ) {
        throw new Error(
            'The repository commit changed during proof-storage width preflight.',
        );
    }
    const manifest = buildManifest({
        commitHash: repositoryStateBefore.commitHash,
        memoryLimitBytes: processMemoryGuard.memoryLimitBytes,
        officialSampleReservationIdentitySha256Hex:
            officialSampleReservation.identitySha256Hex,
        preflightAttachmentPath: relativeDiagnosticPath(
            input.runLog.runDirectoryPath,
            preflightResult.attachmentPath,
        ),
        preflightEvidenceSha256Hex,
        staticPreflight,
        staticPreflightAttachmentPath: relativeDiagnosticPath(
            input.runLog.runDirectoryPath,
            staticPreflightResultPath,
        ),
        staticPreflightEvidenceSha256Hex,
        staticPreflightGuardPath: relativeDiagnosticPath(
            input.runLog.runDirectoryPath,
            staticPreflightGuardPath,
        ),
        staticPreflightGuardSha256Hex,
    });
    const manifestIdentityShake256Hex = shake256Hex(manifest);
    const manifestPath = path.join(
        attachmentDirectoryPath,
        'proof-storage-width-manifest.json',
    );
    await writeJsonAtomicallyAndExclusively(
        manifestPath,
        normalizeJsonValue({ manifest, manifestIdentityShake256Hex }),
    );
    const manifestSha256Hex = createHash('sha256')
        .update(await readFile(manifestPath, 'utf8'))
        .digest('hex');

    const points: ValidatedProofStorageWidthPoint[] = [];
    const sampleArtifacts: Array<
        Readonly<{
            guardPath: string;
            guardSha256Hex: string;
            reservationPath: string;
            reservationSha256Hex: string;
            repositoryAfter: RepositoryState;
            repositoryBefore: RepositoryState;
            resultPath: string;
            resultSha256Hex: string;
            scheduleOrdinal: number;
            width: ProofStorageWidth;
        }>
    > = [];
    let decision: ProofStorageWidthCurveDecision | undefined;
    for (const [widthIndex, width] of proofStorageWidthSchedule.entries()) {
        const scheduleOrdinal = widthIndex + 1;
        const pointRepositoryBefore = await readRepositoryState(
            `width-${width}-before`,
            input.runLog,
        );
        requireCleanPinnedRepository(
            pointRepositoryBefore,
            `width-${width}-before`,
        );
        if (
            pointRepositoryBefore.commitHash !==
            repositoryStateBefore.commitHash
        ) {
            throw new Error(
                `The repository commit changed before width ${width}. No sample was started.`,
            );
        }
        const sampleStem = `width-${String(width).padStart(4, '0')}`;
        const resultPath = path.join(
            sampleDirectoryPath,
            `${sampleStem}-result.json`,
        );
        const guardPath = path.join(
            resourceDirectoryPath,
            `process-memory-guard-${sampleStem}.jsonl`,
        );
        const custodyDirectoryPath = buildProofStorageWidthCustodyDirectoryPath(
            { resultPath },
        );
        await Promise.all([
            requirePathDoesNotExist(resultPath),
            requirePathDoesNotExist(guardPath),
            requirePathDoesNotExist(custodyDirectoryPath),
        ]);
        const guardedCommand = processMemoryGuard.guardCommand(
            buildProofStorageWidthSampleCommand({
                baseEnvironment: cargoEnvironment,
                custodyDirectoryPath,
                exactTestName,
                manifestIdentityShake256Hex,
                resultPath,
                width,
            }),
            {
                diagnosticsPath: guardPath,
                resourceSampleIntervalMilliseconds,
            },
        );
        const reservationPath =
            await createProofStorageWidthNativeSampleReservation({
                identitySha256Hex: officialSampleReservation.identitySha256Hex,
                manifestIdentityShake256Hex,
                officialOwner: proofStorageWidthMeasurementTestName,
                reservationRootPath: officialReservationRootPath,
                runDirectoryPath: input.runLog.runDirectoryPath,
                scheduleOrdinal,
                sourceCommitHash: repositoryStateBefore.commitHash,
                width,
            });
        let attemptError: unknown;
        try {
            await executeRequiredCommand({
                command: guardedCommand,
                executeCommand,
                runLog: input.runLog,
            });
        } catch (error) {
            attemptError = error;
        }
        try {
            await refuseAndRemovePrecommittedCustodyDirectoryIfPresent({
                cause: attemptError,
                custodyDirectoryPath,
                resultPath,
            });
        } catch (error) {
            attemptError = error;
        }
        let pointRepositoryAfter: RepositoryState | undefined;
        try {
            pointRepositoryAfter = await readRepositoryState(
                `width-${width}-after`,
                input.runLog,
            );
            requireCleanPinnedRepository(
                pointRepositoryAfter,
                `width-${width}-after`,
            );
            if (
                pointRepositoryAfter.commitHash !==
                repositoryStateBefore.commitHash
            ) {
                throw new Error(
                    `The repository commit changed during width ${width}. No replacement sample is permitted.`,
                );
            }
        } catch (repositoryError) {
            const sourceDriftError = Object.assign(
                new Error(
                    `The repository state could not be pinned after the observed width ${width} attempt. No replacement sample is permitted.`,
                ),
                { attemptCause: attemptError, cause: repositoryError },
            );
            attemptError = sourceDriftError;
        }
        let serializedResult: string | undefined;
        let guardJsonLines: string | undefined;
        let point: ValidatedProofStorageWidthPoint | undefined;
        if (attemptError === undefined) {
            try {
                [serializedResult, guardJsonLines] = await Promise.all([
                    readFile(resultPath, 'utf8'),
                    readFile(guardPath, 'utf8'),
                ]);
                validateProcessMemoryGuardLimitBinding({
                    expectedMemoryLimitBytes:
                        processMemoryGuard.memoryLimitBytes,
                    guardJsonLines,
                    guardName: `Width ${width}`,
                });
                point = validateProofStorageWidthPoint({
                    expectedScheduleOrdinal: scheduleOrdinal,
                    guardJsonLines,
                    result: parseJsonEvidence(
                        serializedResult,
                        `Proof-storage width ${width} result`,
                    ),
                });
                if (
                    point.result.manifestIdentityShake256Hex !==
                    manifestIdentityShake256Hex
                ) {
                    throw new Error(
                        `Width ${width} did not bind the exact precommitted manifest identity. No replacement sample is permitted.`,
                    );
                }
                const staticPoint = staticPreflight.points[widthIndex];
                if (staticPoint === undefined) {
                    throw new Error(
                        `The static preflight is missing width ${width}. No replacement sample is permitted.`,
                    );
                }
                validateProofStorageWidthPointAgainstStaticPreflight({
                    point,
                    staticPoint,
                });
            } catch (error) {
                attemptError = error;
            }
        }
        try {
            await appendProofStorageWidthOfficialReservationOutcome({
                ...(attemptError instanceof Error
                    ? { failureName: attemptError.name }
                    : attemptError === undefined
                      ? {}
                      : { failureName: typeof attemptError }),
                outcome: attemptError === undefined ? 'validated' : 'failed',
                reservationPath,
            });
        } catch (outcomeError) {
            throw Object.assign(
                new Error(
                    `The durable outcome could not be appended for observed width ${width}; the started reservation remains permanent and no replacement sample is permitted.`,
                ),
                { attemptCause: attemptError, cause: outcomeError },
            );
        }
        if (attemptError !== undefined) {
            if (attemptError instanceof Error) {
                throw attemptError;
            }
            throw Object.assign(
                new Error(
                    'The guarded proof-storage width sample failed with a non-Error rejection value.',
                ),
                { cause: attemptError },
            );
        }
        if (
            pointRepositoryAfter === undefined ||
            serializedResult === undefined ||
            guardJsonLines === undefined ||
            point === undefined
        ) {
            throw new Error(
                'The validated width attempt omitted a required result, guard, or repository binding.',
            );
        }
        const resultSha256Hex = createHash('sha256')
            .update(serializedResult)
            .digest('hex');
        const guardSha256Hex = createHash('sha256')
            .update(guardJsonLines)
            .digest('hex');
        const serializedReservation = await readFile(reservationPath, 'utf8');
        const reservationSha256Hex = createHash('sha256')
            .update(serializedReservation)
            .digest('hex');
        validateNativeOfficialReservationArtifact({
            identitySha256Hex: officialSampleReservation.identitySha256Hex,
            manifestIdentityShake256Hex,
            scheduleOrdinal,
            serialized: serializedReservation,
            sourceCommitHash: repositoryStateBefore.commitHash,
            width,
        });
        points.push(point);
        sampleArtifacts.push({
            guardPath: relativeDiagnosticPath(
                input.runLog.runDirectoryPath,
                guardPath,
            ),
            guardSha256Hex,
            reservationPath: relativeDiagnosticPath(
                officialReservationRootPath,
                reservationPath,
            ),
            reservationSha256Hex,
            repositoryAfter: pointRepositoryAfter,
            repositoryBefore: pointRepositoryBefore,
            resultPath: relativeDiagnosticPath(
                input.runLog.runDirectoryPath,
                resultPath,
            ),
            resultSha256Hex,
            scheduleOrdinal,
            width,
        });
        decision = evaluateProofStorageWidthCurve(points);
        const progressPath = path.join(
            attachmentDirectoryPath,
            `progress-after-${sampleStem}.json`,
        );
        await writeJsonAtomicallyAndExclusively(
            progressPath,
            normalizeJsonValue({
                decision,
                formatVersion: 3,
                manifestIdentityShake256Hex,
                officialSampleReservation: {
                    identitySha256Hex:
                        officialSampleReservation.identitySha256Hex,
                    officialOwner: proofStorageWidthMeasurementTestName,
                    schemaVersion: 1,
                },
                points,
                sampleArtifacts,
            }),
        );
        input.runLog.writeEvent({
            details: {
                decisionOutcome: decision.outcome,
                externalIoByteLength:
                    point.result.externalIoByteLength.toString(),
                manifestIdentityShake256Hex,
                peakProcessTreeResidentMemoryByteLength:
                    point.peakProcessTreeResidentMemoryByteLength.toString(),
                progressPath,
                proofByteLength: point.result.proofByteLength.toString(),
                scheduleOrdinal,
                width,
            },
            eventType: 'proof-storage-width-point-validated',
        });
        if (decision.outcome !== 'continue') {
            break;
        }
    }
    if (decision === undefined) {
        throw new Error('The proof-storage width lane measured no points.');
    }

    const repositoryStateAfter = await readRepositoryState(
        'after',
        input.runLog,
    );
    requireCleanPinnedRepository(repositoryStateAfter, 'after');
    if (repositoryStateAfter.commitHash !== repositoryStateBefore.commitHash) {
        throw new Error(
            'The repository commit changed during proof-storage width measurement.',
        );
    }
    const attachmentPath = path.join(
        attachmentDirectoryPath,
        'proof-storage-width-evidence.json',
    );
    await writeJsonAtomicallyAndExclusively(
        attachmentPath,
        normalizeJsonValue({
            decision,
            formatVersion: 3,
            manifestIdentityShake256Hex,
            manifestPath: relativeDiagnosticPath(
                input.runLog.runDirectoryPath,
                manifestPath,
            ),
            manifestSha256Hex,
            officialSampleReservation: {
                identitySha256Hex: officialSampleReservation.identitySha256Hex,
                officialOwner: proofStorageWidthMeasurementTestName,
                schemaVersion: 1,
            },
            mandatoryPreflight: {
                attachmentPath: relativeDiagnosticPath(
                    input.runLog.runDirectoryPath,
                    preflightResult.attachmentPath,
                ),
                evidenceSha256Hex: preflightEvidenceSha256Hex,
                repositoryCommitHash: repositoryStateBefore.commitHash,
            },
            points,
            repository: {
                after: repositoryStateAfter,
                before: repositoryStateBefore,
                initial: repositoryStateInitial,
            },
            sampleArtifacts,
            staticPreflight: {
                attachmentPath: relativeDiagnosticPath(
                    input.runLog.runDirectoryPath,
                    staticPreflightResultPath,
                ),
                evidenceSha256Hex: staticPreflightEvidenceSha256Hex,
                guardPath: relativeDiagnosticPath(
                    input.runLog.runDirectoryPath,
                    staticPreflightGuardPath,
                ),
                guardSha256Hex: staticPreflightGuardSha256Hex,
                repositoryCommitHash: repositoryStateBefore.commitHash,
            },
        }),
    );
    const validatedObservedEvidence =
        await validateProofStorageWidthObservedEvidenceArtifacts(
            attachmentPath,
            {
                officialReservationRootPath,
            },
        );
    const validatedFullWidthEvidence =
        decision.outcome === 'full-width-complete'
            ? await validateProofStorageWidthEvidenceArtifacts(attachmentPath, {
                  officialReservationRootPath,
              })
            : undefined;
    const evidenceMessage = `Proof-storage width evidence: ${attachmentPath}\n`;
    process.stdout.write(evidenceMessage);
    input.runLog.writeCombinedOutput(evidenceMessage);
    input.runLog.writeEvent({
        details: {
            attachmentPath,
            decisionOutcome: decision.outcome,
            manifestIdentityShake256Hex,
        },
        eventType: 'proof-storage-width-evaluated',
    });

    if (decision.outcome === 'absolute-cap-violation') {
        throw new Error(
            `The proof-storage width curve reached an absolute-cap violation: ${decision.capViolations.join(', ')}.`,
        );
    }
    if (decision.outcome === 'unexplained-superlinear-scaling') {
        throw new Error(
            `The proof-storage width curve reached unexplained superlinear scaling: ${decision.superlinearViolations.join(', ')}.`,
        );
    }
    if (decision.outcome !== 'full-width-complete') {
        throw new Error(
            'The proof-storage width curve ended before the precommitted full width.',
        );
    }
    return {
        attachmentPath,
        decision:
            validatedFullWidthEvidence?.decision ??
            validatedObservedEvidence.decision,
    };
};

export const executeProofStorageWidthEvidenceSequence = async (input: {
    readonly dependencies?: ProofStorageWidthEvidenceRunnerDependencies;
    readonly runLog: ActiveLocalRunLog;
}): Promise<ProofStorageWidthEvidenceRunResult> => {
    const executeCommand =
        input.dependencies?.executeCommand ?? defaultCommandExecutor;
    const processMemoryGuard =
        input.dependencies?.processMemoryGuard ??
        createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription:
                'Proof-storage width evidence',
            memoryLimitEnvironmentVariable:
                'SEALED_LATTICE_GUARDED_RUST_MEMORY_LIMIT_GIB',
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
        const state = await readRepositoryState(checkpoint, runLog);
        if (checkpoint === 'initial') {
            initialCommitHash = state.commitHash;
        }
        return state;
    };

    let attemptError: unknown;
    let result: ProofStorageWidthEvidenceRunResult | undefined;
    try {
        result = await executeProofStorageWidthEvidenceSequenceAttempt({
            dependencies: {
                ...(input.dependencies ?? {}),
                executeCommand,
                processMemoryGuard,
                readRepositoryState: readTrackedRepositoryState,
            },
            runLog: input.runLog,
        });
    } catch (error) {
        attemptError = error;
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
                'closure-after',
            );
            if (closureRepositoryState.commitHash !== initialCommitHash) {
                throw new Error(
                    'The repository commit changed before the proof-storage width lane completed its final closure check.',
                );
            }
        } catch (error) {
            closureRepositoryError = error;
        }
    }

    if (attemptError !== undefined && closureRepositoryError !== undefined) {
        throw Object.assign(
            new Error(
                'The proof-storage width attempt failed and its final repository closure check also failed.',
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
                'The proof-storage width attempt failed with a non-Error rejection value.',
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
                'The proof-storage width final repository closure check failed with a non-Error rejection value.',
            ),
            { cause: closureRepositoryError },
        );
    }
    if (result === undefined) {
        throw new Error(
            'The proof-storage width sequence completed without a result.',
        );
    }
    return result;
};

export const runProofStorageWidthEvidence = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const effectiveArguments = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (effectiveArguments.length !== 0) {
        throw new Error(
            'The proof-storage width evidence runner accepts no arguments.',
        );
    }
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
                    executeProofStorageWidthEvidenceSequence({ runLog }),
                laneLabel,
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runProofStorageWidthEvidence();
}
