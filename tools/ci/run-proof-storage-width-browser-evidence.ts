import { spawn } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
    lstat,
    link,
    mkdir,
    mkdtemp,
    open,
    readFile,
    readdir,
    realpath,
    rmdir,
    unlink,
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
const chainedRecoveryOrdinal = 2;
const thirdRecoveryOrdinal = 3;
const recoveryRepairFilePaths = Object.freeze([
    'tests/node/tools/browser-test-project-selection.test.ts',
    'tests/node/tools/proof-storage-width-browser-evidence-runner.test.ts',
    'tools/ci/browser-test-project-selection.ts',
    'tools/ci/run-proof-storage-width-browser-evidence.ts',
    'vitest.config.ts',
] as const);
const validatorRepairFilePaths = Object.freeze([
    'tests/node/tools/proof-storage-width-browser-evidence-runner.test.ts',
    'tools/ci/run-proof-storage-width-browser-evidence.ts',
] as const);
const firstHarnessRepairCommitHash = '618c55d352d5a2f87db09b446f7e05857831c4dd';
const validatorRepairCommitHash = 'b7398ce150044fc4d3579136989753ddcaad3faa';
const chainedRecoveryPreflightDirectoryName = 'browser-recovery-preflight-2';
const chainedRecoveryOperationDirectoryName = 'browser-recovery-2';
const thirdRecoveryIssuanceCommitHash =
    '17d0b2b15027e0914f55105c27931f2d6e1c5824';
const thirdRecoveryPreflightDirectoryName = 'browser-recovery-preflight-3';
const thirdRecoveryOperationDirectoryName = 'browser-recovery-3';
const thirdRecoveryAttemptDirectoryName = 'preflight-attempted';
const thirdRecoveryStaticObservationDirectoryName = 'static-preflight-observed';
const thirdRecoveryTerminalOutcomeDirectoryName = 'terminal-outcome';
const thirdRecoveryPublishedRecordFileName = 'record.json';
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

export type ProofStorageWidthBrowserChainedRecoveryProfile = Readonly<{
    failedRecoveryArtifacts: Readonly<{
        diagnostics: RecoveryArtifactProfile;
        events: RecoveryArtifactProfile;
        metadata: RecoveryArtifactProfile;
        output: RecoveryArtifactProfile;
        resources: RecoveryArtifactProfile;
        summary: RecoveryArtifactProfile;
    }>;
    failedRecoveryRunDirectoryPath: string;
    failedRecoveryRunRelativePath: string;
    firstHarnessRepairCommitHash: string;
    previousAuthorizationKeySha256Hex: string;
    previousPreflightAttempt: RecoveryArtifactProfile;
    recoveryOrdinal: 2;
    validatorRepairCommitHash: string;
}>;

export const proofStorageWidthBrowserChainedRecoveryProfile = Object.freeze({
    failedRecoveryArtifacts: {
        diagnostics: {
            relativePath: 'diagnostics.txt',
            sha256Hex:
                'e8f1196327bcea0bed1196a5f69e6855fc636d6b6b616305d7b125ae3f9e1c5a',
        },
        events: {
            relativePath: 'events.jsonl',
            sha256Hex:
                'faa70f4693ce18f27d4d99d37971a107f77071b8f4670cd5fcd071c2848cdb98',
        },
        metadata: {
            relativePath: 'metadata.json',
            sha256Hex:
                'a9a91d3f6ada53c571bd339bff419d2d8c7c074fcec0aabe4ecd384cbf9d8534',
        },
        output: {
            relativePath: 'output.log',
            sha256Hex:
                '27c1cf61bfefe962482964199599d20952cd68c0793339aea682671121af72a8',
        },
        resources: {
            relativePath: 'resources.jsonl',
            sha256Hex:
                '8ec3d2772e90b0bf18047c733ca31e9424e8b3142addf7e2bf170a9c194b2c1c',
        },
        summary: {
            relativePath: 'summary.json',
            sha256Hex:
                '213967b4f230628b3765e4501e1eedc22d4f4754ab447c22010d49126e94eab9',
        },
    },
    failedRecoveryRunDirectoryPath: path.resolve(
        'logs',
        '2026-07-23',
        '2026-07-23T11-28-54.155Z-test-browser-proof-storage-width-evidence',
    ),
    failedRecoveryRunRelativePath:
        'logs/2026-07-23/2026-07-23T11-28-54.155Z-test-browser-proof-storage-width-evidence',
    firstHarnessRepairCommitHash,
    previousAuthorizationKeySha256Hex:
        '3eaa2223911f3f55f6f58e020a3cc4f56087bfb6e16678ad2895daa1f7084121',
    previousPreflightAttempt: {
        relativePath:
            'browser-recovery-preflight/3eaa2223911f3f55f6f58e020a3cc4f56087bfb6e16678ad2895daa1f7084121/preflight-attempted.json',
        sha256Hex:
            '5ba1a032f2e5066dfc817062f6c71bf489dfb1833376bc856275618443c3ebe9',
    },
    recoveryOrdinal: chainedRecoveryOrdinal,
    validatorRepairCommitHash,
} satisfies ProofStorageWidthBrowserChainedRecoveryProfile);

export type ProofStorageWidthBrowserThirdRecoveryProfile = Readonly<{
    failedChainedRecoveryArtifacts: Readonly<{
        diagnostics: RecoveryArtifactProfile;
        events: RecoveryArtifactProfile;
        metadata: RecoveryArtifactProfile;
        output: RecoveryArtifactProfile;
        resources: RecoveryArtifactProfile;
        summary: RecoveryArtifactProfile;
    }>;
    failedChainedRecoveryRunDirectoryPath: string;
    failedChainedRecoveryRunRelativePath: string;
    issuanceCommitHash: string;
    previousChainedAuthorizationKeySha256Hex: string;
    previousChainedPreflightAttempt: RecoveryArtifactProfile;
    recoveryOrdinal: 3;
}>;

export const proofStorageWidthBrowserThirdRecoveryProfile = Object.freeze({
    failedChainedRecoveryArtifacts: {
        diagnostics: {
            relativePath: 'diagnostics.txt',
            sha256Hex:
                '884036d558d7ed5f889414784bcd3588ee21dc7ef310a088cc45f4e34c17bc24',
        },
        events: {
            relativePath: 'events.jsonl',
            sha256Hex:
                '3622088a4010aeb1d7caf6c862bb468cc06a4d4a5fb34b17fb839ae6a601b117',
        },
        metadata: {
            relativePath: 'metadata.json',
            sha256Hex:
                '7b1dd4c573e8f667ff62f2b39838b9ab79877679cac1c28b883e1d60d1491be6',
        },
        output: {
            relativePath: 'output.log',
            sha256Hex:
                '8ef173ff3d4939b9c2981ce86ac73586f5852c0caf9d412bab0a7eee78442f19',
        },
        resources: {
            relativePath: 'resources.jsonl',
            sha256Hex:
                'f4aba5860f36ff2aa01d2596a08a6feb0ba0164a27e0f4a588347ad8b13c3835',
        },
        summary: {
            relativePath: 'summary.json',
            sha256Hex:
                'b84accc3a6798526ca2af4fe4b9d1880c47cd658542894027dd42f22cafd8bd7',
        },
    },
    failedChainedRecoveryRunDirectoryPath: path.resolve(
        'logs',
        '2026-07-24',
        '2026-07-24T00-23-57.447Z-test-browser-proof-storage-width-evidence',
    ),
    failedChainedRecoveryRunRelativePath:
        'logs/2026-07-24/2026-07-24T00-23-57.447Z-test-browser-proof-storage-width-evidence',
    issuanceCommitHash: thirdRecoveryIssuanceCommitHash,
    previousChainedAuthorizationKeySha256Hex:
        '5b202992442b62b3ee38274f17819888b1f14623975381f7f41e66f8c3857059',
    previousChainedPreflightAttempt: {
        relativePath:
            'browser-recovery-preflight-2/5b202992442b62b3ee38274f17819888b1f14623975381f7f41e66f8c3857059/preflight-attempted.json',
        sha256Hex:
            '47b83e816b39f87d94212c89459d221e1959c33276bfbcf46e15028d72f6bcfb',
    },
    recoveryOrdinal: thirdRecoveryOrdinal,
} satisfies ProofStorageWidthBrowserThirdRecoveryProfile);

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

type BrowserRecoveryMarkerRecordKind =
    | 'failure-outcome'
    | 'preflight-attempt'
    | 'static-observation'
    | 'validated-outcome';

type BrowserRecoveryMarkerFaultInjection = (
    input: Readonly<{
        markerPath: string;
        recordKind: BrowserRecoveryMarkerRecordKind;
        serializedRecord: string;
        stage:
            | 'after-link-before-durability'
            | 'after-publication-before-reopen'
            | 'after-staged-close-before-validation'
            | 'before-incomplete-canonical-unlink'
            | 'before-staged-write';
    }>,
) =>
    | Promise<Readonly<{ maximumWriteByteLength?: number }> | undefined>
    | Readonly<{ maximumWriteByteLength?: number }>
    | undefined;

export type ProofStorageWidthBrowserEvidenceDependencies = Readonly<{
    browserRecoveryMarkerFaultInjection?: BrowserRecoveryMarkerFaultInjection;
    chainedRecoveryProfile?: ProofStorageWidthBrowserChainedRecoveryProfile;
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
    thirdRecoveryProfile?: ProofStorageWidthBrowserThirdRecoveryProfile;
    runWithLocalRunLog?: typeof runWithLocalRunLog;
    withLocalHeavyLaneLease?: typeof withLocalHeavyLaneLease;
}>;

type ValidatedPreOperationRecovery = Readonly<{
    failedArtifacts: ProofStorageWidthBrowserPreOperationRecoveryProfile['failedArtifacts'];
    failedReservation: ProofStorageWidthBrowserPreOperationRecoveryProfile['failedReservation'];
    failedRunDirectoryPath: string;
    recoveryOrdinal: 1;
}>;

type ValidatedFailedRecoveryAttempt = Readonly<{
    failedArtifacts: ProofStorageWidthBrowserChainedRecoveryProfile['failedRecoveryArtifacts'];
    failedRunDirectoryPath: string;
    previousPreflightAttempt: RecoveryArtifactProfile;
    recoveryOrdinal: 2;
}>;

type ValidatedFailedChainedRecoveryAttempt = Readonly<{
    failedArtifacts: ProofStorageWidthBrowserThirdRecoveryProfile['failedChainedRecoveryArtifacts'];
    failedRunDirectoryPath: string;
    previousChainedPreflightAttempt: RecoveryArtifactProfile;
    recoveryOrdinal: 3;
}>;

type ValidatedHarnessRepairTransition = Readonly<{
    changedFilePaths: readonly string[];
    harnessCommitHash: string;
    nativeSourceCommitHash: string;
}>;

type ValidatedChainedHarnessRepairTransition = Readonly<{
    firstHarnessRepair: ValidatedHarnessRepairTransition;
    recoveryHarnessRepair: ValidatedHarnessRepairTransition;
    validatorRepair: ValidatedHarnessRepairTransition;
}>;

type ValidatedThirdHarnessRepairTransition = Readonly<{
    chainedRecoveryHarness: ValidatedChainedHarnessRepairTransition;
    thirdRecoveryHarness: ValidatedHarnessRepairTransition;
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

type ComparableImmutableWindowsPath = Readonly<{
    rootIdentity: string;
    normalizedRemainder: string;
}>;

const parseComparableImmutableWindowsPath = (
    value: string,
): ComparableImmutableWindowsPath | undefined => {
    if (/^[\\/]{3,}/u.test(value) || /^[\\/]{2}[?.][\\/]/u.test(value)) {
        return undefined;
    }
    const driveMatch = /^([A-Za-z]:)[\\/]+([\s\S]*)$/u.exec(value);
    if (driveMatch !== null) {
        return Object.freeze({
            rootIdentity: `drive:${driveMatch[1] ?? ''}`,
            normalizedRemainder: (driveMatch[2] ?? '').replace(
                /[\\/]+/gu,
                '\\',
            ),
        });
    }
    const uncMatch = /^[\\/]{2}([^\\/]+)[\\/]+([^\\/]+)([\s\S]*)$/u.exec(value);
    if (uncMatch === null) {
        return undefined;
    }
    const remainder = uncMatch[3] ?? '';
    if (remainder.length !== 0 && !/^[\\/]/u.test(remainder)) {
        return undefined;
    }
    return Object.freeze({
        rootIdentity: `unc:${uncMatch[1] ?? ''}\u0000${uncMatch[2] ?? ''}`,
        normalizedRemainder: remainder.replace(/[\\/]+/gu, '\\'),
    });
};

const immutableFailedRunInvocationPathEquals = (
    observed: unknown,
    expected: string,
): boolean => {
    if (typeof observed !== 'string') {
        return false;
    }
    if (observed === expected) {
        return true;
    }
    const observedComparable = parseComparableImmutableWindowsPath(observed);
    const expectedComparable = parseComparableImmutableWindowsPath(expected);
    return (
        observedComparable !== undefined &&
        expectedComparable !== undefined &&
        observedComparable.rootIdentity === expectedComparable.rootIdentity &&
        observedComparable.normalizedRemainder ===
            expectedComparable.normalizedRemainder
    );
};

const immutableFailedRunInvocationEquals = (input: {
    readonly expected: readonly string[];
    readonly observed: unknown;
    readonly pathArgumentIndexes: readonly number[];
}): boolean => {
    const observed = input.observed;
    if (!Array.isArray(observed) || observed.length !== input.expected.length) {
        return false;
    }
    const pathArgumentIndexes = new Set(input.pathArgumentIndexes);
    return input.expected.every((expectedArgument, argumentIndex) =>
        pathArgumentIndexes.has(argumentIndex)
            ? immutableFailedRunInvocationPathEquals(
                  observed[argumentIndex],
                  expectedArgument,
              )
            : observed[argumentIndex] === expectedArgument,
    );
};

export type ImmutableFailedRunMetadataInvocationProfile =
    | Readonly<{
          failedRunDirectoryPath: string;
          nativeEvidencePath: string;
          preOperationRecoveryRunDirectoryPath: string;
          recoveryOrdinal: 1;
      }>
    | Readonly<{
          failedRecoveryAttemptRunDirectoryPath: string;
          failedRunDirectoryPath: string;
          nativeEvidencePath: string;
          preOperationRecoveryRunDirectoryPath: string;
          recoveryOrdinal: 2;
      }>;

export const immutableFailedRunMetadataInvocationEquals = (input: {
    readonly observed: unknown;
    readonly profile: ImmutableFailedRunMetadataInvocationProfile;
}): boolean => {
    if (
        typeof input.observed !== 'object' ||
        input.observed === null ||
        Array.isArray(input.observed)
    ) {
        return false;
    }
    const metadata = input.observed as Readonly<Record<string, unknown>>;
    const expectedCommandLineArguments = [
        '--native-evidence',
        input.profile.nativeEvidencePath,
        '--pre-operation-recovery',
        input.profile.preOperationRecoveryRunDirectoryPath,
        ...(input.profile.recoveryOrdinal === 1
            ? []
            : [
                  '--failed-recovery-attempt',
                  input.profile.failedRecoveryAttemptRunDirectoryPath,
              ]),
    ];
    return (
        metadata.repositoryCommitHash === undefined &&
        metadata.scriptName === scriptName &&
        metadata.runDirectoryPath === input.profile.failedRunDirectoryPath &&
        immutableFailedRunInvocationEquals({
            expected: expectedCommandLineArguments,
            observed: metadata.commandLineArguments,
            pathArgumentIndexes:
                input.profile.recoveryOrdinal === 1 ? [1, 3] : [1, 3, 5],
        })
    );
};

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

const prepareCanonicalCustodyDirectory = async (input: {
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
    const segments = input.relativePath
        .split(/[\\/]/u)
        .filter((segment) => segment.length !== 0);
    if (
        segments.length === 0 ||
        segments.some((segment) => segment === '.' || segment === '..')
    ) {
        throw new Error(`${input.fieldName} has a non-canonical path.`);
    }
    let currentDirectoryPath = canonicalRootPath;
    for (const segment of segments) {
        currentDirectoryPath = path.join(currentDirectoryPath, segment);
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
            fieldName: input.fieldName,
            path: currentDirectoryPath,
        });
        if (
            path.relative(
                path.resolve(currentDirectoryPath),
                canonicalDirectoryPath,
            ).length !== 0 ||
            !isPathWithinRoot(canonicalRootPath, canonicalDirectoryPath)
        ) {
            throw new Error(
                `${input.fieldName} changed its canonical custody path.`,
            );
        }
        currentDirectoryPath = canonicalDirectoryPath;
    }
    return currentDirectoryPath;
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

const requireDirectoryTreeContainsNoOperationArtifacts = async (
    directoryPath: string,
    fieldName: string,
): Promise<void> => {
    let canonicalDirectoryPath: string;
    try {
        canonicalDirectoryPath = await requireExistingPathWithoutLinks({
            expectedType: 'directory',
            fieldName,
            path: directoryPath,
        });
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
    if (
        path.relative(path.resolve(directoryPath), canonicalDirectoryPath)
            .length !== 0
    ) {
        throw new Error(`${fieldName} changed its canonical custody path.`);
    }
    const entries = await readdir(canonicalDirectoryPath, {
        withFileTypes: true,
    });
    for (const entry of entries) {
        if (!entry.isDirectory()) {
            throw new Error(
                `${fieldName} must contain only empty directory scaffolding and no prior operation artifact.`,
            );
        }
        await requireDirectoryTreeContainsNoOperationArtifacts(
            path.join(canonicalDirectoryPath, entry.name),
            fieldName,
        );
    }
};

const listRecursiveRegularFilePaths = async (
    rootDirectoryPath: string,
): Promise<string[]> => {
    const canonicalRootDirectoryPath = await requireCanonicalCustodyRoot(
        rootDirectoryPath,
        'Predecessor run inventory root',
    );
    const filePaths: string[] = [];
    const visitDirectory = async (directoryPath: string): Promise<void> => {
        const resolvedDirectoryPath = path.resolve(directoryPath);
        const canonicalDirectoryPath = await requireExistingPathWithoutLinks({
            expectedType: 'directory',
            fieldName: 'Predecessor run inventory directory',
            path: resolvedDirectoryPath,
        });
        if (
            path.relative(resolvedDirectoryPath, canonicalDirectoryPath)
                .length !== 0 ||
            !isPathWithinRoot(
                canonicalRootDirectoryPath,
                canonicalDirectoryPath,
            )
        ) {
            throw new Error(
                'The predecessor run inventory directory changed its canonical custody path.',
            );
        }
        const entries = await readdir(canonicalDirectoryPath, {
            withFileTypes: true,
        });
        for (const entry of entries) {
            const entryPath = path.join(canonicalDirectoryPath, entry.name);
            if (entry.isDirectory()) {
                await visitDirectory(entryPath);
            } else if (entry.isFile()) {
                const canonicalFilePath = await requireExistingPathWithoutLinks(
                    {
                        expectedType: 'file',
                        fieldName: 'Predecessor run inventory file',
                        path: entryPath,
                    },
                );
                if (
                    path.relative(path.resolve(entryPath), canonicalFilePath)
                        .length !== 0 ||
                    !isPathWithinRoot(
                        canonicalRootDirectoryPath,
                        canonicalFilePath,
                    )
                ) {
                    throw new Error(
                        'The predecessor run inventory file changed its canonical custody path.',
                    );
                }
                filePaths.push(
                    path
                        .relative(canonicalRootDirectoryPath, canonicalFilePath)
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
    await visitDirectory(canonicalRootDirectoryPath);
    return filePaths.sort((left, right) => left.localeCompare(right));
};

const listDirectRegularFilePaths = async (
    rootDirectoryPath: string,
    fieldName: string,
): Promise<string[]> => {
    const canonicalRootDirectoryPath = await requireCanonicalCustodyRoot(
        rootDirectoryPath,
        `${fieldName} root`,
    );
    const entries = await readdir(canonicalRootDirectoryPath, {
        withFileTypes: true,
    });
    const filePaths: string[] = [];
    for (const entry of entries) {
        if (!entry.isFile()) {
            throw new Error(
                `${fieldName} must contain only its exact direct regular files.`,
            );
        }
        const entryPath = path.join(canonicalRootDirectoryPath, entry.name);
        const entryStatistics = await lstat(entryPath);
        if (entryStatistics.nlink !== 1) {
            throw new Error(
                `${fieldName} must not contain multiply linked regular files.`,
            );
        }
        const canonicalFilePath = await requireExistingPathWithoutLinks({
            expectedType: 'file',
            fieldName: `${fieldName} file`,
            path: entryPath,
        });
        if (
            path.relative(path.resolve(entryPath), canonicalFilePath).length !==
                0 ||
            !isPathWithinRoot(canonicalRootDirectoryPath, canonicalFilePath)
        ) {
            throw new Error(`${fieldName} changed its canonical custody path.`);
        }
        filePaths.push(entry.name);
    }
    return filePaths.sort((left, right) => left.localeCompare(right));
};

const requireCustodyPathAbsent = async (input: {
    readonly fieldName: string;
    readonly relativePath: string;
    readonly rootPath: string;
}): Promise<void> => {
    if (path.isAbsolute(input.relativePath)) {
        throw new Error(`${input.fieldName} must be relative to its root.`);
    }
    const canonicalRootPath = await requireCanonicalCustodyRoot(
        input.rootPath,
        `${input.fieldName} root`,
    );
    const segments = input.relativePath
        .split(/[\\/]/u)
        .filter((segment) => segment.length !== 0);
    if (
        segments.length === 0 ||
        segments.some((segment) => segment === '.' || segment === '..')
    ) {
        throw new Error(`${input.fieldName} has a non-canonical path.`);
    }
    let currentPath = canonicalRootPath;
    for (const [segmentIndex, segment] of segments.entries()) {
        currentPath = path.join(currentPath, segment);
        let statistics: Awaited<ReturnType<typeof lstat>>;
        try {
            statistics = await lstat(currentPath);
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
        if (statistics.isSymbolicLink()) {
            throw new Error(
                `${input.fieldName} crosses a symbolic link or junction.`,
            );
        }
        const isFinalSegment = segmentIndex === segments.length - 1;
        if (!isFinalSegment && !statistics.isDirectory()) {
            throw new Error(
                `${input.fieldName} crosses a non-directory ancestor.`,
            );
        }
        const canonicalPath = path.resolve(await realpath(currentPath));
        if (
            path.relative(path.resolve(currentPath), canonicalPath).length !==
                0 ||
            !isPathWithinRoot(canonicalRootPath, canonicalPath)
        ) {
            throw new Error(`${input.fieldName} changed its canonical path.`);
        }
        if (isFinalSegment) {
            throw new Error(`${input.fieldName} already exists.`);
        }
        currentPath = canonicalPath;
    }
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

const parseCanonicalRecoveryJsonLines = (
    serialized: string,
    fieldName: string,
): JsonObject[] => {
    if (
        serialized.length === 0 ||
        !serialized.endsWith('\n') ||
        serialized.includes('\r')
    ) {
        throw new Error(
            `${fieldName} must use exact LF-terminated JSONL bytes.`,
        );
    }
    const recordLines = serialized.slice(0, -1).split('\n');
    if (
        recordLines.length === 0 ||
        recordLines.some((recordLine) => recordLine.length === 0)
    ) {
        throw new Error(`${fieldName} must contain no blank JSONL records.`);
    }
    return recordLines.map((recordLine, recordIndex) =>
        requireJsonObject(
            parseJson(
                recordLine,
                `${fieldName} line ${String(recordIndex + 1)}`,
            ),
            `${fieldName} line ${String(recordIndex + 1)}`,
        ),
    );
};

const literalRecoveryJsonLinesPrefix = (
    serialized: string,
    recordCount: number,
    fieldName: string,
): Buffer => {
    const serializedBytes = Buffer.from(serialized, 'utf8');
    let terminatedRecordCount = 0;
    for (const [byteIndex, byte] of serializedBytes.entries()) {
        if (byte !== 0x0a) {
            continue;
        }
        terminatedRecordCount += 1;
        if (terminatedRecordCount === recordCount) {
            return serializedBytes.subarray(0, byteIndex + 1);
        }
    }
    throw new Error(
        `${fieldName} lacks its exact ${String(recordCount)}-record byte prefix.`,
    );
};

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
                requireDirectoryTreeContainsNoOperationArtifacts(
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

const validateProofStorageWidthBrowserFailedRecoveryAttempt = async (input: {
    readonly failedRecoveryRunDirectoryPath: string;
    readonly nativeEvidence: NativeWidthEvidence;
    readonly officialReservationRootPath: string;
    readonly preOperationRecovery: ValidatedPreOperationRecovery;
    readonly preOperationProfile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    readonly profile: ProofStorageWidthBrowserChainedRecoveryProfile;
}): Promise<ValidatedFailedRecoveryAttempt> => {
    if (!path.isAbsolute(input.failedRecoveryRunDirectoryPath)) {
        throw new Error(
            'The failed recovery-attempt path must be an absolute run directory.',
        );
    }
    const declaredFailedRunDirectoryPath = path.resolve(
        input.failedRecoveryRunDirectoryPath,
    );
    const repositoryRootPath = path.resolve('.');
    const relativeFailedRunDirectoryPath = path.resolve(
        repositoryRootPath,
        input.profile.failedRecoveryRunRelativePath,
    );
    if (
        declaredFailedRunDirectoryPath !==
            path.resolve(input.profile.failedRecoveryRunDirectoryPath) ||
        path.isAbsolute(input.profile.failedRecoveryRunRelativePath) ||
        input.profile.failedRecoveryRunRelativePath.includes('\\') ||
        input.profile.failedRecoveryRunRelativePath
            .split('/')
            .some(
                (segment) =>
                    segment === '' || segment === '.' || segment === '..',
            ) ||
        relativeFailedRunDirectoryPath !== declaredFailedRunDirectoryPath ||
        !isPathWithinRoot(repositoryRootPath, relativeFailedRunDirectoryPath) ||
        canonicalRelativePath(
            repositoryRootPath,
            relativeFailedRunDirectoryPath,
        ) !== input.profile.failedRecoveryRunRelativePath ||
        input.profile.recoveryOrdinal !== chainedRecoveryOrdinal ||
        input.profile.firstHarnessRepairCommitHash !==
            firstHarnessRepairCommitHash ||
        input.profile.validatorRepairCommitHash !== validatorRepairCommitHash
    ) {
        throw new Error(
            'The failed recovery-attempt path or commit chain is not the exact authorized predecessor.',
        );
    }
    const failedRunDirectoryPath = await requireCanonicalCustodyRoot(
        declaredFailedRunDirectoryPath,
        'Failed recovery-attempt custody root',
    );
    const artifactEntries = Object.entries(
        input.profile.failedRecoveryArtifacts,
    ) as Array<
        [
            keyof ProofStorageWidthBrowserChainedRecoveryProfile['failedRecoveryArtifacts'],
            RecoveryArtifactProfile,
        ]
    >;
    const expectedFilePaths = artifactEntries
        .map(([, artifact]) => artifact.relativePath)
        .sort((left, right) => left.localeCompare(right));
    const actualFilePaths = await listDirectRegularFilePaths(
        failedRunDirectoryPath,
        'Failed recovery-attempt inventory',
    );
    if (!normalizedJsonEquals(actualFilePaths, expectedFilePaths)) {
        throw new Error(
            'The failed recovery-attempt exact six-file inventory changed.',
        );
    }
    const artifactBytes = new Map<string, Buffer>();
    for (const [artifactName, artifact] of artifactEntries) {
        if (
            path.isAbsolute(artifact.relativePath) ||
            artifact.relativePath.includes('/') ||
            artifact.relativePath.includes('\\')
        ) {
            throw new Error(
                `The failed recovery ${artifactName} artifact is not a direct file.`,
            );
        }
        const artifactPath = await resolveExistingCustodyFile({
            fieldName: `Failed recovery ${artifactName} artifact`,
            relativePath: artifact.relativePath,
            rootPath: failedRunDirectoryPath,
        });
        const bytes = await readFile(artifactPath);
        if (sha256Hex(bytes) !== artifact.sha256Hex) {
            throw new Error(
                `The failed recovery ${artifactName} artifact changed after the consumed attempt.`,
            );
        }
        artifactBytes.set(artifactName, bytes);
    }
    const summary = requireJsonObject(
        parseJson(
            artifactBytes.get('summary')?.toString('utf8') ?? '',
            'Failed recovery-attempt summary',
        ),
        'Failed recovery-attempt summary',
    );
    const summaryError = requireJsonObject(
        summary.error,
        'Failed recovery-attempt summary error',
    );
    if (
        summary.exitCode !== 1 ||
        summary.repositoryCommitHash !==
            input.profile.firstHarnessRepairCommitHash ||
        summary.repositoryTreeDirty !== false ||
        summary.resultClassification !== 'runner-failure' ||
        summary.failedCommandId !== undefined ||
        summaryError.message !==
            'Failed browser attachments directory must contain no prior operation artifact.'
    ) {
        throw new Error(
            'The failed recovery summary is not the exact empty-scaffolding validator failure.',
        );
    }
    const metadata = requireJsonObject(
        parseJson(
            artifactBytes.get('metadata')?.toString('utf8') ?? '',
            'Failed recovery-attempt metadata',
        ),
        'Failed recovery-attempt metadata',
    );
    if (
        !immutableFailedRunMetadataInvocationEquals({
            observed: metadata,
            profile: {
                failedRunDirectoryPath,
                nativeEvidencePath: input.nativeEvidence.evidencePath,
                preOperationRecoveryRunDirectoryPath:
                    input.preOperationRecovery.failedRunDirectoryPath,
                recoveryOrdinal: 1,
            },
        })
    ) {
        throw new Error(
            'The failed recovery metadata changed its exact predecessor invocation.',
        );
    }
    const events = parseJsonLines(
        artifactBytes.get('events')?.toString('utf8') ?? '',
        'Failed recovery-attempt events',
    );
    const permittedEventTypes = new Set([
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
                !permittedEventTypes.has(event.eventType) ||
                event.eventType.startsWith('command-'),
        )
    ) {
        throw new Error(
            'The failed recovery attempt contains a build, static-list, browser, worker, or measurement event.',
        );
    }
    const resources = parseJsonLines(
        artifactBytes.get('resources')?.toString('utf8') ?? '',
        'Failed recovery-attempt resources',
    );
    if (
        resources.length === 0 ||
        resources.some(
            (resource) =>
                resource.resourceScope !== 'orchestration-process-and-host' ||
                !normalizedJsonEquals(resource.activeCommandIds, []),
        )
    ) {
        throw new Error(
            'The failed recovery resource record contains an active child command.',
        );
    }
    const output = artifactBytes.get('output')?.toString('utf8') ?? '';
    if (
        !output.includes('Acquired local guarded heavy-lane lease') ||
        !output.includes('Released local guarded heavy-lane lease') ||
        output.includes('build-proof-storage-width-browser-evidence') ||
        output.includes('vitest-list-proof-storage-width-browser-evidence') ||
        output.includes('vitest-proof-storage-width-browser-evidence') ||
        output.includes('proof-storage-width-browser-evidence-complete')
    ) {
        throw new Error(
            'The failed recovery output contains evidence work beyond the validator failure.',
        );
    }
    const previousAuthorizationKeySha256Hex =
        buildBrowserRecoveryAuthorizationKey(input.preOperationProfile);
    const previousPreflightAttemptRelativePath = `${firstBrowserRecoveryCustody.preflightDirectoryName}/${previousAuthorizationKeySha256Hex}/preflight-attempted.json`;
    if (
        input.profile.previousAuthorizationKeySha256Hex !==
            previousAuthorizationKeySha256Hex ||
        input.profile.previousPreflightAttempt.relativePath !==
            previousPreflightAttemptRelativePath
    ) {
        throw new Error(
            'The consumed browser recovery authorization or marker path was not derived from its fixed predecessor namespace.',
        );
    }
    const previousAttemptPath = await resolveExistingCustodyFile({
        fieldName: 'Consumed browser recovery marker',
        relativePath: previousPreflightAttemptRelativePath,
        rootPath: input.officialReservationRootPath,
    });
    const previousAttemptBytes = await readFile(previousAttemptPath);
    if (
        sha256Hex(previousAttemptBytes) !==
        input.profile.previousPreflightAttempt.sha256Hex
    ) {
        throw new Error(
            'The consumed browser recovery marker changed after its terminal failure.',
        );
    }
    const previousAttemptRecords = parseCanonicalRecoveryJsonLines(
        previousAttemptBytes.toString('utf8'),
        'Consumed browser recovery marker',
    );
    if (
        previousAttemptRecords.length !== 2 ||
        previousAttemptRecords[0]?.authorizationKeySha256Hex !==
            previousAuthorizationKeySha256Hex ||
        previousAttemptRecords[0]?.eventType !==
            'official-browser-width-recovery-preflight-attempted' ||
        previousAttemptRecords[0]?.failedReservationIdentitySha256Hex !==
            input.preOperationRecovery.failedReservation.identitySha256Hex ||
        previousAttemptRecords[0]?.recoveryOrdinal !== recoveryOrdinal ||
        previousAttemptRecords[1]?.eventType !== 'official-sample-outcome' ||
        previousAttemptRecords[1]?.outcome !== 'failed'
    ) {
        throw new Error(
            'The consumed browser recovery marker is not the exact ordinal-one terminal failure.',
        );
    }
    await requireCustodyPathAbsent({
        fieldName: 'Consumed browser recovery measured-operation reservation',
        relativePath: path.join(
            'browser-recovery',
            previousAuthorizationKeySha256Hex,
            'browser-recovery-started.json',
        ),
        rootPath: input.officialReservationRootPath,
    });
    return Object.freeze({
        failedArtifacts: input.profile.failedRecoveryArtifacts,
        failedRunDirectoryPath,
        previousPreflightAttempt: Object.freeze({
            relativePath: previousPreflightAttemptRelativePath,
            sha256Hex: input.profile.previousPreflightAttempt.sha256Hex,
        }),
        recoveryOrdinal: chainedRecoveryOrdinal,
    });
};

const validateProofStorageWidthBrowserFailedChainedRecoveryAttempt =
    async (input: {
        readonly failedChainedRecoveryRunDirectoryPath: string;
        readonly failedRecoveryAttempt: ValidatedFailedRecoveryAttempt;
        readonly nativeEvidence: NativeWidthEvidence;
        readonly officialReservationRootPath: string;
        readonly preOperationRecovery: ValidatedPreOperationRecovery;
        readonly preOperationProfile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
        readonly chainedProfile: ProofStorageWidthBrowserChainedRecoveryProfile;
        readonly profile: ProofStorageWidthBrowserThirdRecoveryProfile;
    }): Promise<ValidatedFailedChainedRecoveryAttempt> => {
        if (!path.isAbsolute(input.failedChainedRecoveryRunDirectoryPath)) {
            throw new Error(
                'The failed chained-recovery path must be an absolute run directory.',
            );
        }
        const declaredFailedRunDirectoryPath = path.resolve(
            input.failedChainedRecoveryRunDirectoryPath,
        );
        const repositoryRootPath = path.resolve('.');
        const relativeFailedRunDirectoryPath = path.resolve(
            repositoryRootPath,
            input.profile.failedChainedRecoveryRunRelativePath,
        );
        if (
            declaredFailedRunDirectoryPath !==
                path.resolve(
                    input.profile.failedChainedRecoveryRunDirectoryPath,
                ) ||
            path.isAbsolute(
                input.profile.failedChainedRecoveryRunRelativePath,
            ) ||
            input.profile.failedChainedRecoveryRunRelativePath.includes('\\') ||
            input.profile.failedChainedRecoveryRunRelativePath
                .split('/')
                .some(
                    (segment) =>
                        segment === '' || segment === '.' || segment === '..',
                ) ||
            relativeFailedRunDirectoryPath !== declaredFailedRunDirectoryPath ||
            !isPathWithinRoot(
                repositoryRootPath,
                relativeFailedRunDirectoryPath,
            ) ||
            canonicalRelativePath(
                repositoryRootPath,
                relativeFailedRunDirectoryPath,
            ) !== input.profile.failedChainedRecoveryRunRelativePath ||
            input.profile.recoveryOrdinal !== thirdRecoveryOrdinal ||
            input.profile.issuanceCommitHash !== thirdRecoveryIssuanceCommitHash
        ) {
            throw new Error(
                'The failed chained-recovery path or issuance commit is not the exact authorized predecessor.',
            );
        }
        const failedRunDirectoryPath = await requireCanonicalCustodyRoot(
            declaredFailedRunDirectoryPath,
            'Failed chained-recovery custody root',
        );
        const artifactEntries = Object.entries(
            input.profile.failedChainedRecoveryArtifacts,
        ) as Array<
            [
                keyof ProofStorageWidthBrowserThirdRecoveryProfile['failedChainedRecoveryArtifacts'],
                RecoveryArtifactProfile,
            ]
        >;
        const expectedFilePaths = artifactEntries
            .map(([, artifact]) => artifact.relativePath)
            .sort((left, right) => left.localeCompare(right));
        const actualFilePaths = await listDirectRegularFilePaths(
            failedRunDirectoryPath,
            'Failed chained-recovery inventory',
        );
        if (!normalizedJsonEquals(actualFilePaths, expectedFilePaths)) {
            throw new Error(
                'The failed chained-recovery exact six-file inventory changed.',
            );
        }
        const artifactBytes = new Map<string, Buffer>();
        for (const [artifactName, artifact] of artifactEntries) {
            if (
                path.isAbsolute(artifact.relativePath) ||
                artifact.relativePath.includes('/') ||
                artifact.relativePath.includes('\\')
            ) {
                throw new Error(
                    `The failed chained-recovery ${artifactName} artifact is not a direct file.`,
                );
            }
            const artifactPath = await resolveExistingCustodyFile({
                fieldName: `Failed chained-recovery ${artifactName} artifact`,
                relativePath: artifact.relativePath,
                rootPath: failedRunDirectoryPath,
            });
            const bytes = await readFile(artifactPath);
            if (sha256Hex(bytes) !== artifact.sha256Hex) {
                throw new Error(
                    `The failed chained-recovery ${artifactName} artifact changed after the consumed attempt.`,
                );
            }
            artifactBytes.set(artifactName, bytes);
        }
        const summary = requireJsonObject(
            parseJson(
                artifactBytes.get('summary')?.toString('utf8') ?? '',
                'Failed chained-recovery summary',
            ),
            'Failed chained-recovery summary',
        );
        const summaryError = requireJsonObject(
            summary.error,
            'Failed chained-recovery summary error',
        );
        if (
            summary.exitCode !== 1 ||
            summary.repositoryCommitHash !== input.profile.issuanceCommitHash ||
            summary.repositoryTreeDirty !== false ||
            summary.resultClassification !== 'runner-failure' ||
            summary.failedCommandId !== undefined ||
            summaryError.message !==
                'The failed recovery metadata changed its exact predecessor invocation.'
        ) {
            throw new Error(
                'The failed chained-recovery summary is not the exact immutable invocation-comparison failure.',
            );
        }
        const metadata = requireJsonObject(
            parseJson(
                artifactBytes.get('metadata')?.toString('utf8') ?? '',
                'Failed chained-recovery metadata',
            ),
            'Failed chained-recovery metadata',
        );
        if (
            !immutableFailedRunMetadataInvocationEquals({
                observed: metadata,
                profile: {
                    failedRecoveryAttemptRunDirectoryPath:
                        input.failedRecoveryAttempt.failedRunDirectoryPath,
                    failedRunDirectoryPath,
                    nativeEvidencePath: input.nativeEvidence.evidencePath,
                    preOperationRecoveryRunDirectoryPath:
                        input.preOperationRecovery.failedRunDirectoryPath,
                    recoveryOrdinal: 2,
                },
            })
        ) {
            throw new Error(
                'The failed chained-recovery metadata changed its exact predecessor invocation.',
            );
        }
        const events = parseJsonLines(
            artifactBytes.get('events')?.toString('utf8') ?? '',
            'Failed chained-recovery events',
        );
        const permittedEventTypes = new Set([
            'heavy-lane-lease-acquired',
            'heavy-lane-lease-released',
            'heavy-lane-lease-waiting',
            'run-finished',
            'run-heartbeat',
            'run-started',
        ]);
        if (
            events.length === 0 ||
            events.some(
                (event) =>
                    typeof event.eventType !== 'string' ||
                    !permittedEventTypes.has(event.eventType) ||
                    event.eventType.startsWith('command-'),
            )
        ) {
            throw new Error(
                'The failed chained-recovery contains a build, static-list, browser, worker, or measurement event.',
            );
        }
        const resources = parseJsonLines(
            artifactBytes.get('resources')?.toString('utf8') ?? '',
            'Failed chained-recovery resources',
        );
        if (
            resources.length === 0 ||
            resources.some(
                (resource) =>
                    resource.resourceScope !==
                        'orchestration-process-and-host' ||
                    !normalizedJsonEquals(resource.activeCommandIds, []),
            )
        ) {
            throw new Error(
                'The failed chained-recovery resource record contains an active child command.',
            );
        }
        const output = artifactBytes.get('output')?.toString('utf8') ?? '';
        if (
            !output.includes('Acquired local guarded heavy-lane lease') ||
            !output.includes('Released local guarded heavy-lane lease') ||
            output.includes('build-proof-storage-width-browser-evidence') ||
            output.includes(
                'vitest-list-proof-storage-width-browser-evidence',
            ) ||
            output.includes('vitest-proof-storage-width-browser-evidence') ||
            output.includes('proof-storage-width-browser-evidence-complete')
        ) {
            throw new Error(
                'The failed chained-recovery output contains evidence work beyond predecessor validation.',
            );
        }
        const previousChainedAuthorizationKeySha256Hex =
            buildBrowserChainedRecoveryAuthorizationKey({
                chainedProfile: input.chainedProfile,
                preOperationProfile: input.preOperationProfile,
            });
        const previousChainedPreflightAttemptRelativePath = `${chainedRecoveryPreflightDirectoryName}/${previousChainedAuthorizationKeySha256Hex}/preflight-attempted.json`;
        if (
            input.profile.previousChainedAuthorizationKeySha256Hex !==
                previousChainedAuthorizationKeySha256Hex ||
            input.profile.previousChainedPreflightAttempt.relativePath !==
                previousChainedPreflightAttemptRelativePath
        ) {
            throw new Error(
                'The consumed chained recovery authorization or marker path was not rederived from its fixed predecessor namespace.',
            );
        }
        const previousChainedAttemptPath = await resolveExistingCustodyFile({
            fieldName: 'Consumed chained browser recovery marker',
            relativePath: previousChainedPreflightAttemptRelativePath,
            rootPath: input.officialReservationRootPath,
        });
        const previousChainedAttemptBytes = await readFile(
            previousChainedAttemptPath,
        );
        if (
            sha256Hex(previousChainedAttemptBytes) !==
            input.profile.previousChainedPreflightAttempt.sha256Hex
        ) {
            throw new Error(
                'The consumed chained browser recovery marker changed after its terminal failure.',
            );
        }
        const previousChainedAttemptRecords = parseCanonicalRecoveryJsonLines(
            previousChainedAttemptBytes.toString('utf8'),
            'Consumed chained browser recovery marker',
        );
        if (
            previousChainedAttemptRecords.length !== 2 ||
            previousChainedAttemptRecords[0]?.authorizationKeySha256Hex !==
                previousChainedAuthorizationKeySha256Hex ||
            previousChainedAttemptRecords[0]?.eventType !==
                'official-browser-width-recovery-preflight-attempted' ||
            previousChainedAttemptRecords[0]
                ?.failedReservationIdentitySha256Hex !==
                input.preOperationRecovery.failedReservation
                    .identitySha256Hex ||
            previousChainedAttemptRecords[0]
                ?.previousAuthorizationKeySha256Hex !==
                input.chainedProfile.previousAuthorizationKeySha256Hex ||
            previousChainedAttemptRecords[0]
                ?.previousPreflightAttemptSha256Hex !==
                input.chainedProfile.previousPreflightAttempt.sha256Hex ||
            previousChainedAttemptRecords[0]?.recoveryOrdinal !==
                chainedRecoveryOrdinal ||
            previousChainedAttemptRecords[1]?.eventType !==
                'official-sample-outcome' ||
            previousChainedAttemptRecords[1]?.failureName !== 'Error' ||
            previousChainedAttemptRecords[1]?.outcome !== 'failed'
        ) {
            throw new Error(
                'The consumed chained browser recovery marker is not the exact ordinal-two terminal failure.',
            );
        }
        await requireCustodyPathAbsent({
            fieldName:
                'Consumed chained browser recovery measured-operation reservation',
            relativePath: path.join(
                chainedRecoveryOperationDirectoryName,
                previousChainedAuthorizationKeySha256Hex,
                'browser-recovery-started.json',
            ),
            rootPath: input.officialReservationRootPath,
        });
        return Object.freeze({
            failedArtifacts: input.profile.failedChainedRecoveryArtifacts,
            failedRunDirectoryPath,
            previousChainedPreflightAttempt: Object.freeze({
                relativePath: previousChainedPreflightAttemptRelativePath,
                sha256Hex:
                    input.profile.previousChainedPreflightAttempt.sha256Hex,
            }),
            recoveryOrdinal: thirdRecoveryOrdinal,
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

const validateExactHarnessRepairCommitTransition = async (input: {
    readonly changedFilePaths: readonly string[];
    readonly childCommitHash: string;
    readonly executeCommand: CommandExecutor;
    readonly logFileSlug: string;
    readonly parentCommitHash: string;
    readonly runLog: ActiveLocalRunLog;
    readonly transitionLabel: string;
}): Promise<ValidatedHarnessRepairTransition> => {
    const replacementDisabledEnvironment: NodeJS.ProcessEnv = {
        ...process.env,
        GIT_NO_REPLACE_OBJECTS: '1',
        GIT_OPTIONAL_LOCKS: '0',
    };
    const parentResult = await executeRequiredCommand({
        command: {
            args: [
                '--no-replace-objects',
                'cat-file',
                'commit',
                input.childCommitHash,
            ],
            command: 'git',
            description: `validate the ${input.transitionLabel} sole-parent commit`,
            env: replacementDisabledEnvironment,
            logFileSlug: `${input.logFileSlug}-parent`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    const headerTerminatorIndex = parentResult.stdout.indexOf('\n\n');
    const rawCommitHeader =
        headerTerminatorIndex === -1
            ? undefined
            : parentResult.stdout.slice(0, headerTerminatorIndex);
    const parentHeaders =
        rawCommitHeader === undefined ||
        rawCommitHeader.includes('\r') ||
        rawCommitHeader.includes('\0')
            ? []
            : rawCommitHeader
                  .split('\n')
                  .filter((line) => line.startsWith('parent '));
    if (
        parentHeaders.length !== 1 ||
        parentHeaders[0] !== `parent ${input.parentCommitHash}`
    ) {
        throw new Error(
            `The ${input.transitionLabel} commit is not the sole direct child of its authorized parent.`,
        );
    }
    const diffResult = await executeRequiredCommand({
        command: {
            args: [
                '--no-replace-objects',
                'diff',
                '--name-status',
                '-z',
                '--no-renames',
                `${input.parentCommitHash}^{tree}`,
                `${input.childCommitHash}^{tree}`,
                '--',
            ],
            command: 'git',
            description: `validate the ${input.transitionLabel} repair file set`,
            env: replacementDisabledEnvironment,
            logFileSlug: `${input.logFileSlug}-diff`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    const diffTokens = diffResult.stdout.endsWith('\0')
        ? diffResult.stdout.slice(0, -1).split('\0')
        : [];
    const changedFilePaths: string[] = [];
    let diffShapeValid =
        diffTokens.length === input.changedFilePaths.length * 2;
    for (let tokenIndex = 0; tokenIndex < diffTokens.length; tokenIndex += 2) {
        const status = diffTokens[tokenIndex];
        const filePath = diffTokens[tokenIndex + 1];
        if (
            status !== 'M' ||
            filePath === undefined ||
            filePath.length === 0 ||
            changedFilePaths.includes(filePath)
        ) {
            diffShapeValid = false;
        } else {
            changedFilePaths.push(filePath);
        }
    }
    if (
        !diffShapeValid ||
        changedFilePaths.length !== input.changedFilePaths.length ||
        input.changedFilePaths.some(
            (expectedFilePath) => !changedFilePaths.includes(expectedFilePath),
        )
    ) {
        throw new Error(
            `The ${input.transitionLabel} commit diff is not exactly its authorized harness files.`,
        );
    }
    return Object.freeze({
        changedFilePaths,
        harnessCommitHash: input.childCommitHash,
        nativeSourceCommitHash: input.parentCommitHash,
    });
};

const validateHarnessRepairCommitTransition = (input: {
    readonly executeCommand: CommandExecutor;
    readonly harnessCommitHash: string;
    readonly nativeSourceCommitHash: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<ValidatedHarnessRepairTransition> =>
    validateExactHarnessRepairCommitTransition({
        changedFilePaths: recoveryRepairFilePaths,
        childCommitHash: input.harnessCommitHash,
        executeCommand: input.executeCommand,
        logFileSlug: 'git-browser-width-recovery',
        parentCommitHash: input.nativeSourceCommitHash,
        runLog: input.runLog,
        transitionLabel: 'browser recovery harness',
    });

const validateChainedHarnessRepairCommitTransition = async (input: {
    readonly executeCommand: CommandExecutor;
    readonly nativeSourceCommitHash: string;
    readonly profile: ProofStorageWidthBrowserChainedRecoveryProfile;
    readonly recoveryHarnessCommitHash: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<ValidatedChainedHarnessRepairTransition> => {
    const firstHarnessRepair = await validateHarnessRepairCommitTransition({
        executeCommand: input.executeCommand,
        harnessCommitHash: input.profile.firstHarnessRepairCommitHash,
        nativeSourceCommitHash: input.nativeSourceCommitHash,
        runLog: input.runLog,
    });
    const validatorRepair = await validateExactHarnessRepairCommitTransition({
        changedFilePaths: validatorRepairFilePaths,
        childCommitHash: input.profile.validatorRepairCommitHash,
        executeCommand: input.executeCommand,
        logFileSlug: 'git-browser-width-validator-repair',
        parentCommitHash: input.profile.firstHarnessRepairCommitHash,
        runLog: input.runLog,
        transitionLabel: 'browser recovery validator repair',
    });
    const recoveryHarnessRepair =
        await validateExactHarnessRepairCommitTransition({
            changedFilePaths: validatorRepairFilePaths,
            childCommitHash: input.recoveryHarnessCommitHash,
            executeCommand: input.executeCommand,
            logFileSlug: 'git-browser-width-chained-recovery',
            parentCommitHash: input.profile.validatorRepairCommitHash,
            runLog: input.runLog,
            transitionLabel: 'chained browser recovery harness',
        });
    return Object.freeze({
        firstHarnessRepair,
        recoveryHarnessRepair,
        validatorRepair,
    });
};

const validateThirdHarnessRepairCommitTransition = async (input: {
    readonly chainedProfile: ProofStorageWidthBrowserChainedRecoveryProfile;
    readonly executeCommand: CommandExecutor;
    readonly finalHarnessCommitHash: string;
    readonly nativeSourceCommitHash: string;
    readonly runLog: ActiveLocalRunLog;
    readonly thirdProfile: ProofStorageWidthBrowserThirdRecoveryProfile;
}): Promise<ValidatedThirdHarnessRepairTransition> => {
    const chainedRecoveryHarness =
        await validateChainedHarnessRepairCommitTransition({
            executeCommand: input.executeCommand,
            nativeSourceCommitHash: input.nativeSourceCommitHash,
            profile: input.chainedProfile,
            recoveryHarnessCommitHash: input.thirdProfile.issuanceCommitHash,
            runLog: input.runLog,
        });
    const thirdRecoveryHarness =
        await validateExactHarnessRepairCommitTransition({
            changedFilePaths: validatorRepairFilePaths,
            childCommitHash: input.finalHarnessCommitHash,
            executeCommand: input.executeCommand,
            logFileSlug: 'git-browser-width-third-recovery',
            parentCommitHash: input.thirdProfile.issuanceCommitHash,
            runLog: input.runLog,
            transitionLabel: 'third browser recovery harness',
        });
    return Object.freeze({
        chainedRecoveryHarness,
        thirdRecoveryHarness,
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

const buildBrowserChainedRecoveryAuthorizationKey = (input: {
    readonly chainedProfile: ProofStorageWidthBrowserChainedRecoveryProfile;
    readonly preOperationProfile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
}): string =>
    sha256Hex(
        JSON.stringify(
            normalizeJsonValue({
                failedRecoveryArtifacts:
                    input.chainedProfile.failedRecoveryArtifacts,
                failedRecoveryRunRelativePath:
                    input.chainedProfile.failedRecoveryRunRelativePath,
                formatVersion: 2,
                nativeAggregateSha256Hex:
                    input.preOperationProfile.nativeAggregateSha256Hex,
                nativeSourceCommitHash:
                    input.preOperationProfile.nativeSourceCommitHash,
                previousAuthorizationKeySha256Hex:
                    input.chainedProfile.previousAuthorizationKeySha256Hex,
                previousPreflightAttemptSha256Hex:
                    input.chainedProfile.previousPreflightAttempt.sha256Hex,
                recoveryOrdinal: input.chainedProfile.recoveryOrdinal,
                validatorRepairCommitHash:
                    input.chainedProfile.validatorRepairCommitHash,
                width: proofStorageWidthBrowserEvidenceProfile.representativeWidth,
            }),
        ),
    );

const buildBrowserThirdRecoveryAuthorizationKey = (input: {
    readonly chainedProfile: ProofStorageWidthBrowserChainedRecoveryProfile;
    readonly preOperationProfile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    readonly thirdProfile: ProofStorageWidthBrowserThirdRecoveryProfile;
}): string =>
    sha256Hex(
        JSON.stringify(
            normalizeJsonValue({
                failedChainedRecoveryArtifacts:
                    input.thirdProfile.failedChainedRecoveryArtifacts,
                failedChainedRecoveryRunRelativePath:
                    input.thirdProfile.failedChainedRecoveryRunRelativePath,
                failedRecoveryArtifacts:
                    input.chainedProfile.failedRecoveryArtifacts,
                failedRecoveryRunRelativePath:
                    input.chainedProfile.failedRecoveryRunRelativePath,
                formatVersion: 3,
                issuanceCommitHash: input.thirdProfile.issuanceCommitHash,
                nativeAggregateSha256Hex:
                    input.preOperationProfile.nativeAggregateSha256Hex,
                nativeSourceCommitHash:
                    input.preOperationProfile.nativeSourceCommitHash,
                previousAuthorizationKeySha256Hex:
                    input.chainedProfile.previousAuthorizationKeySha256Hex,
                previousChainedAuthorizationKeySha256Hex:
                    input.thirdProfile.previousChainedAuthorizationKeySha256Hex,
                previousChainedPreflightAttemptSha256Hex:
                    input.thirdProfile.previousChainedPreflightAttempt
                        .sha256Hex,
                previousPreflightAttemptSha256Hex:
                    input.chainedProfile.previousPreflightAttempt.sha256Hex,
                recoveryOrdinal: input.thirdProfile.recoveryOrdinal,
                width: proofStorageWidthBrowserEvidenceProfile.representativeWidth,
            }),
        ),
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

const buildBrowserChainedRecoveryReservationIdentity = (input: {
    readonly failedRecoveryAttempt: ValidatedFailedRecoveryAttempt;
    readonly harnessTransition: ValidatedChainedHarnessRepairTransition;
    readonly nativeEvidence: NativeWidthEvidence;
    readonly preOperationRecovery: ValidatedPreOperationRecovery;
    readonly rawWasmSha256Hex: string;
}): RecoveryReservationIdentity => {
    const identityRecord = Object.freeze({
        failedArtifacts: input.preOperationRecovery.failedArtifacts,
        failedRecoveryArtifacts: input.failedRecoveryAttempt.failedArtifacts,
        failedRecoveryRunDirectoryPath:
            input.failedRecoveryAttempt.failedRunDirectoryPath,
        failedReservationIdentitySha256Hex:
            input.preOperationRecovery.failedReservation.identitySha256Hex,
        failedReservationSha256Hex:
            input.preOperationRecovery.failedReservation.sha256Hex,
        firstHarnessRepair: input.harnessTransition.firstHarnessRepair,
        formatVersion: 2,
        nativeAggregateSha256Hex: input.nativeEvidence.evidenceSha256Hex,
        nativeReservationIdentitySha256Hex:
            input.nativeEvidence.officialSampleReservationIdentitySha256Hex,
        nativeSourceCommitHash:
            input.harnessTransition.firstHarnessRepair.nativeSourceCommitHash,
        officialOwner: browserOfficialSampleOwner,
        previousPreflightAttempt:
            input.failedRecoveryAttempt.previousPreflightAttempt,
        rawWasmSha256Hex: input.rawWasmSha256Hex,
        recoveryHarnessRepair: input.harnessTransition.recoveryHarnessRepair,
        recoveryOrdinal: chainedRecoveryOrdinal,
        validatorRepair: input.harnessTransition.validatorRepair,
        width: proofStorageWidthBrowserEvidenceProfile.representativeWidth,
    });
    return Object.freeze({
        identityRecord,
        identitySha256Hex: sha256Hex(JSON.stringify(identityRecord)),
    });
};

const buildBrowserThirdRecoveryReservationIdentity = (input: {
    readonly failedChainedRecoveryAttempt: ValidatedFailedChainedRecoveryAttempt;
    readonly failedRecoveryAttempt: ValidatedFailedRecoveryAttempt;
    readonly harnessTransition: ValidatedThirdHarnessRepairTransition;
    readonly nativeEvidence: NativeWidthEvidence;
    readonly preOperationRecovery: ValidatedPreOperationRecovery;
    readonly rawWasmSha256Hex: string;
}): RecoveryReservationIdentity => {
    const identityRecord = Object.freeze({
        chainedRecoveryHarness: input.harnessTransition.chainedRecoveryHarness,
        failedArtifacts: input.preOperationRecovery.failedArtifacts,
        failedChainedRecoveryArtifacts:
            input.failedChainedRecoveryAttempt.failedArtifacts,
        failedChainedRecoveryRunDirectoryPath:
            input.failedChainedRecoveryAttempt.failedRunDirectoryPath,
        failedRecoveryArtifacts: input.failedRecoveryAttempt.failedArtifacts,
        failedRecoveryRunDirectoryPath:
            input.failedRecoveryAttempt.failedRunDirectoryPath,
        failedReservationIdentitySha256Hex:
            input.preOperationRecovery.failedReservation.identitySha256Hex,
        failedReservationSha256Hex:
            input.preOperationRecovery.failedReservation.sha256Hex,
        formatVersion: 3,
        nativeAggregateSha256Hex: input.nativeEvidence.evidenceSha256Hex,
        nativeReservationIdentitySha256Hex:
            input.nativeEvidence.officialSampleReservationIdentitySha256Hex,
        nativeSourceCommitHash:
            input.harnessTransition.chainedRecoveryHarness.firstHarnessRepair
                .nativeSourceCommitHash,
        officialOwner: browserOfficialSampleOwner,
        previousChainedPreflightAttempt:
            input.failedChainedRecoveryAttempt.previousChainedPreflightAttempt,
        previousPreflightAttempt:
            input.failedRecoveryAttempt.previousPreflightAttempt,
        rawWasmSha256Hex: input.rawWasmSha256Hex,
        recoveryOrdinal: thirdRecoveryOrdinal,
        thirdRecoveryHarness: input.harnessTransition.thirdRecoveryHarness,
        width: proofStorageWidthBrowserEvidenceProfile.representativeWidth,
    });
    return Object.freeze({
        identityRecord,
        identitySha256Hex: sha256Hex(JSON.stringify(identityRecord)),
    });
};

type ThirdRecoveryKeyDirectoryIdentity = Readonly<{
    canonicalPath: string;
    device: bigint;
    inode: bigint;
}>;

const syncDirectoryMetadata = async (directoryPath: string): Promise<void> => {
    const directory = await open(
        directoryPath,
        process.platform === 'win32' ? 'a+' : 'r',
    );
    try {
        await directory.sync();
    } finally {
        await directory.close();
    }
};

const syncRegularFileMetadata = async (filePath: string): Promise<void> => {
    const file = await open(
        filePath,
        process.platform === 'win32' ? 'r+' : 'r',
    );
    try {
        await file.sync();
    } finally {
        await file.close();
    }
};

const readThirdRecoveryKeyDirectoryIdentity = async (
    keyDirectoryPath: string,
): Promise<ThirdRecoveryKeyDirectoryIdentity> => {
    const canonicalPath = await requireExistingPathWithoutLinks({
        expectedType: 'directory',
        fieldName: 'Third browser recovery claimed key directory',
        path: keyDirectoryPath,
    });
    if (
        path.relative(path.resolve(keyDirectoryPath), canonicalPath).length !==
        0
    ) {
        throw new Error(
            'The third browser recovery claimed key directory changed its canonical path.',
        );
    }
    const statistics = await lstat(canonicalPath, { bigint: true });
    if (!statistics.isDirectory() || statistics.isSymbolicLink()) {
        throw new Error(
            'The third browser recovery claimed key path is not one canonical directory.',
        );
    }
    return Object.freeze({
        canonicalPath,
        device: statistics.dev,
        inode: statistics.ino,
    });
};

const requireThirdRecoveryKeyDirectoryIdentity = async (input: {
    readonly expected: ThirdRecoveryKeyDirectoryIdentity;
    readonly keyDirectoryPath: string;
}): Promise<void> => {
    const observed = await readThirdRecoveryKeyDirectoryIdentity(
        input.keyDirectoryPath,
    );
    if (
        observed.canonicalPath !== input.expected.canonicalPath ||
        observed.device !== input.expected.device ||
        observed.inode !== input.expected.inode
    ) {
        throw new Error(
            'The third browser recovery claimed key directory changed filesystem identity.',
        );
    }
};

type ThirdRecoveryLogicalMarker = Readonly<{
    attemptedRecordPath?: string;
    keyDirectoryPath: string;
    serialized: string;
    staticObservationRecordPath?: string;
    terminalOutcomeRecordPath?: string;
}>;

const requireSingleLinkedRegularFile = async (
    filePath: string,
    fieldName: string,
): Promise<string> => {
    const statistics = await lstat(filePath);
    if (!statistics.isFile() || statistics.nlink !== 1) {
        throw new Error(`${fieldName} must be one singly linked regular file.`);
    }
    const canonicalFilePath = await requireExistingPathWithoutLinks({
        expectedType: 'file',
        fieldName,
        path: filePath,
    });
    if (path.relative(path.resolve(filePath), canonicalFilePath).length !== 0) {
        throw new Error(`${fieldName} changed its canonical custody path.`);
    }
    return canonicalFilePath;
};

const readCanonicalPublishedRecoveryRecord = async (input: {
    readonly directoryPath: string;
    readonly fieldName: string;
    readonly fileName: string;
}): Promise<Readonly<{ path: string; serialized: string }>> => {
    const canonicalDirectoryPath = await requireExistingPathWithoutLinks({
        expectedType: 'directory',
        fieldName: `${input.fieldName} directory`,
        path: input.directoryPath,
    });
    if (
        path.relative(path.resolve(input.directoryPath), canonicalDirectoryPath)
            .length !== 0
    ) {
        throw new Error(
            `${input.fieldName} directory changed its canonical custody path.`,
        );
    }
    const entries = await readdir(canonicalDirectoryPath, {
        withFileTypes: true,
    });
    if (
        entries.length !== 1 ||
        entries[0]?.name !== input.fileName ||
        entries[0]?.isFile() !== true
    ) {
        throw new Error(
            `${input.fieldName} directory changed its exact one-file inventory.`,
        );
    }
    const recordPath = await requireSingleLinkedRegularFile(
        path.join(canonicalDirectoryPath, input.fileName),
        input.fieldName,
    );
    const serialized = await readFile(recordPath, 'utf8');
    const records = parseCanonicalRecoveryJsonLines(
        serialized,
        input.fieldName,
    );
    if (records.length !== 1) {
        throw new Error(`${input.fieldName} must contain exactly one record.`);
    }
    return Object.freeze({ path: recordPath, serialized });
};

const readThirdRecoveryLogicalMarker = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly expectedKeyDirectoryIdentity?: ThirdRecoveryKeyDirectoryIdentity;
    readonly reservationRootPath: string;
}): Promise<ThirdRecoveryLogicalMarker> => {
    const keyDirectoryPath = path.resolve(
        input.reservationRootPath,
        thirdRecoveryPreflightDirectoryName,
        input.authorizationKeySha256Hex,
    );
    const observedKeyDirectoryIdentity =
        await readThirdRecoveryKeyDirectoryIdentity(keyDirectoryPath);
    const canonicalKeyDirectoryPath =
        observedKeyDirectoryIdentity.canonicalPath;
    if (
        input.expectedKeyDirectoryIdentity !== undefined &&
        (observedKeyDirectoryIdentity.canonicalPath !==
            input.expectedKeyDirectoryIdentity.canonicalPath ||
            observedKeyDirectoryIdentity.device !==
                input.expectedKeyDirectoryIdentity.device ||
            observedKeyDirectoryIdentity.inode !==
                input.expectedKeyDirectoryIdentity.inode)
    ) {
        throw new Error(
            'The third browser recovery marker directory changed filesystem identity.',
        );
    }
    const entries = await readdir(canonicalKeyDirectoryPath, {
        withFileTypes: true,
    });
    const entriesByName = new Map(entries.map((entry) => [entry.name, entry]));
    const allowedEntryNames = new Set([
        thirdRecoveryAttemptDirectoryName,
        thirdRecoveryStaticObservationDirectoryName,
        thirdRecoveryTerminalOutcomeDirectoryName,
    ]);
    const attemptedEntry = entriesByName.get(thirdRecoveryAttemptDirectoryName);
    const staticEntry = entriesByName.get(
        thirdRecoveryStaticObservationDirectoryName,
    );
    const terminalEntry = entriesByName.get(
        thirdRecoveryTerminalOutcomeDirectoryName,
    );
    if (
        entries.some((entry) => !allowedEntryNames.has(entry.name)) ||
        (attemptedEntry !== undefined && !attemptedEntry.isDirectory()) ||
        (staticEntry !== undefined && !staticEntry.isDirectory()) ||
        (terminalEntry !== undefined && !terminalEntry.isDirectory()) ||
        (attemptedEntry === undefined &&
            (staticEntry !== undefined || terminalEntry !== undefined))
    ) {
        throw new Error(
            'The third browser recovery marker changed its exact record inventory.',
        );
    }
    const attemptedRecord =
        attemptedEntry === undefined
            ? undefined
            : await readCanonicalPublishedRecoveryRecord({
                  directoryPath: path.join(
                      canonicalKeyDirectoryPath,
                      thirdRecoveryAttemptDirectoryName,
                  ),
                  fieldName: 'Third browser recovery attempted record',
                  fileName: thirdRecoveryPublishedRecordFileName,
              });
    const staticRecord =
        staticEntry === undefined
            ? undefined
            : await readCanonicalPublishedRecoveryRecord({
                  directoryPath: path.join(
                      canonicalKeyDirectoryPath,
                      thirdRecoveryStaticObservationDirectoryName,
                  ),
                  fieldName: 'Third browser recovery static observation record',
                  fileName: thirdRecoveryPublishedRecordFileName,
              });
    const terminalRecord =
        terminalEntry === undefined
            ? undefined
            : await readCanonicalPublishedRecoveryRecord({
                  directoryPath: path.join(
                      canonicalKeyDirectoryPath,
                      thirdRecoveryTerminalOutcomeDirectoryName,
                  ),
                  fieldName: 'Third browser recovery terminal outcome record',
                  fileName: thirdRecoveryPublishedRecordFileName,
              });
    const serialized = `${attemptedRecord?.serialized ?? ''}${staticRecord?.serialized ?? ''}${terminalRecord?.serialized ?? ''}`;
    if (serialized.length !== 0) {
        parseCanonicalRecoveryJsonLines(
            serialized,
            'Third browser recovery logical marker',
        );
    }
    return Object.freeze({
        ...(attemptedRecord === undefined
            ? {}
            : { attemptedRecordPath: attemptedRecord.path }),
        keyDirectoryPath: canonicalKeyDirectoryPath,
        serialized,
        ...(staticRecord === undefined
            ? {}
            : { staticObservationRecordPath: staticRecord.path }),
        ...(terminalRecord === undefined
            ? {}
            : { terminalOutcomeRecordPath: terminalRecord.path }),
    });
};

const claimThirdRecoveryKeyDirectory = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly reservationRootPath: string;
}): Promise<ThirdRecoveryKeyDirectoryIdentity> => {
    const canonicalReservationRootPath = await requireCanonicalCustodyRoot(
        input.reservationRootPath,
        'Third browser recovery reservation root',
    );
    const preflightRootPath = await prepareCanonicalCustodyDirectory({
        fieldName: 'Third browser recovery preflight root',
        relativePath: thirdRecoveryPreflightDirectoryName,
        rootPath: canonicalReservationRootPath,
    });
    const keyDirectoryPath = path.join(
        preflightRootPath,
        input.authorizationKeySha256Hex,
    );
    try {
        await mkdir(keyDirectoryPath);
    } catch (error) {
        if (
            typeof error === 'object' &&
            error !== null &&
            'code' in error &&
            error.code === 'EEXIST'
        ) {
            await readThirdRecoveryLogicalMarker({
                authorizationKeySha256Hex: input.authorizationKeySha256Hex,
                reservationRootPath: input.reservationRootPath,
            });
            throw Object.assign(
                new Error(
                    'The one authorized browser recovery already claimed its singleton key directory; no second recovery is permitted.',
                ),
                { cause: error },
            );
        }
        throw error;
    }
    await syncDirectoryMetadata(preflightRootPath);
    await syncDirectoryMetadata(canonicalReservationRootPath);
    const identity =
        await readThirdRecoveryKeyDirectoryIdentity(keyDirectoryPath);
    const claimedState = await readThirdRecoveryLogicalMarker({
        authorizationKeySha256Hex: input.authorizationKeySha256Hex,
        expectedKeyDirectoryIdentity: identity,
        reservationRootPath: input.reservationRootPath,
    });
    if (
        claimedState.serialized !== '' ||
        claimedState.attemptedRecordPath !== undefined ||
        claimedState.staticObservationRecordPath !== undefined ||
        claimedState.terminalOutcomeRecordPath !== undefined
    ) {
        throw new Error(
            'The newly claimed third browser recovery key directory was not empty.',
        );
    }
    return identity;
};

const cleanupUnpublishedRecoveryRecordDirectory = async (input: {
    readonly recordPath: string;
    readonly stagingDirectoryPath: string;
}): Promise<void> => {
    await unlink(input.recordPath).catch((error: unknown) => {
        if (
            typeof error !== 'object' ||
            error === null ||
            !('code' in error) ||
            error.code !== 'ENOENT'
        ) {
            throw error;
        }
    });
    await rmdir(input.stagingDirectoryPath).catch((error: unknown) => {
        if (
            typeof error !== 'object' ||
            error === null ||
            !('code' in error) ||
            error.code !== 'ENOENT'
        ) {
            throw error;
        }
    });
};

const rollbackIncompleteThirdRecoveryRecordPublication = async (input: {
    readonly expectedKeyDirectoryIdentity: ThirdRecoveryKeyDirectoryIdentity;
    readonly expectedSerializedRecord: string;
    readonly faultInjection?: BrowserRecoveryMarkerFaultInjection;
    readonly keyDirectoryPath: string;
    readonly preflightRootPath: string;
    readonly publishedRecordPath: string;
    readonly recordKind: BrowserRecoveryMarkerRecordKind;
    readonly stagingDirectoryPath: string;
    readonly stagedRecordPath: string;
    readonly targetDirectoryPath: string;
}): Promise<void> => {
    await requireThirdRecoveryKeyDirectoryIdentity({
        expected: input.expectedKeyDirectoryIdentity,
        keyDirectoryPath: input.keyDirectoryPath,
    });
    const [publishedRecordPath, stagedRecordPath] = await Promise.all([
        requireExistingPathWithoutLinks({
            expectedType: 'file',
            fieldName: 'Incomplete canonical third browser recovery record',
            path: input.publishedRecordPath,
        }),
        requireExistingPathWithoutLinks({
            expectedType: 'file',
            fieldName: 'Incomplete staged third browser recovery record',
            path: input.stagedRecordPath,
        }),
    ]);
    const [publishedStatistics, stagedStatistics, publishedBytes, stagedBytes] =
        await Promise.all([
            lstat(publishedRecordPath, { bigint: true }),
            lstat(stagedRecordPath, { bigint: true }),
            readFile(publishedRecordPath),
            readFile(stagedRecordPath),
        ]);
    const expectedBytes = Buffer.from(input.expectedSerializedRecord, 'utf8');
    if (
        publishedRecordPath !== path.resolve(input.publishedRecordPath) ||
        stagedRecordPath !== path.resolve(input.stagedRecordPath) ||
        !publishedStatistics.isFile() ||
        !stagedStatistics.isFile() ||
        publishedStatistics.nlink !== 2n ||
        stagedStatistics.nlink !== 2n ||
        publishedStatistics.dev !== stagedStatistics.dev ||
        publishedStatistics.ino !== stagedStatistics.ino ||
        !publishedBytes.equals(expectedBytes) ||
        !stagedBytes.equals(expectedBytes)
    ) {
        throw new Error(
            'The incomplete third browser recovery hard-link pair changed before rollback.',
        );
    }
    await input.faultInjection?.({
        markerPath: publishedRecordPath,
        recordKind: input.recordKind,
        serializedRecord: input.expectedSerializedRecord,
        stage: 'before-incomplete-canonical-unlink',
    });
    await unlink(publishedRecordPath);
    await syncDirectoryMetadata(input.targetDirectoryPath);
    await rmdir(input.targetDirectoryPath);
    await syncDirectoryMetadata(input.keyDirectoryPath);
    await requireThirdRecoveryKeyDirectoryIdentity({
        expected: input.expectedKeyDirectoryIdentity,
        keyDirectoryPath: input.keyDirectoryPath,
    });
    await cleanupUnpublishedRecoveryRecordDirectory({
        recordPath: stagedRecordPath,
        stagingDirectoryPath: input.stagingDirectoryPath,
    });
    await syncDirectoryMetadata(input.preflightRootPath);
};

const publishThirdRecoveryRecordAtomically = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly expectedLogicalPrefix: string;
    readonly expectedKeyDirectoryIdentity: ThirdRecoveryKeyDirectoryIdentity;
    readonly faultInjection?: BrowserRecoveryMarkerFaultInjection;
    readonly recordKind: BrowserRecoveryMarkerRecordKind;
    readonly reservationRootPath: string;
    readonly serializedRecord: string;
    readonly targetDirectoryName:
        | typeof thirdRecoveryAttemptDirectoryName
        | typeof thirdRecoveryStaticObservationDirectoryName
        | typeof thirdRecoveryTerminalOutcomeDirectoryName;
}): Promise<ThirdRecoveryLogicalMarker> => {
    if (
        parseCanonicalRecoveryJsonLines(
            input.serializedRecord,
            `Third browser recovery ${input.recordKind}`,
        ).length !== 1
    ) {
        throw new Error(
            `The third browser recovery ${input.recordKind} publication must contain exactly one canonical record.`,
        );
    }
    const preflightRootPath = await prepareCanonicalCustodyDirectory({
        fieldName: 'Third browser recovery preflight root',
        relativePath: thirdRecoveryPreflightDirectoryName,
        rootPath: input.reservationRootPath,
    });
    const keyDirectoryPath = path.join(
        preflightRootPath,
        input.authorizationKeySha256Hex,
    );
    const currentMarker = await readThirdRecoveryLogicalMarker({
        authorizationKeySha256Hex: input.authorizationKeySha256Hex,
        expectedKeyDirectoryIdentity: input.expectedKeyDirectoryIdentity,
        reservationRootPath: input.reservationRootPath,
    });
    if (currentMarker.serialized !== input.expectedLogicalPrefix) {
        throw new Error(
            'The third browser recovery logical marker changed before record publication.',
        );
    }
    await requireCustodyPathAbsent({
        fieldName: `Third browser recovery ${input.recordKind} publication`,
        relativePath: path.join(
            thirdRecoveryPreflightDirectoryName,
            input.authorizationKeySha256Hex,
            input.targetDirectoryName,
        ),
        rootPath: input.reservationRootPath,
    });
    const stagingDirectoryPath = await mkdtemp(
        path.join(preflightRootPath, '.unpublished-recovery-record-'),
    );
    await syncDirectoryMetadata(preflightRootPath);
    const stagedFileName = thirdRecoveryPublishedRecordFileName;
    const stagedRecordPath = path.join(stagingDirectoryPath, stagedFileName);
    const targetDirectoryPath = path.join(
        keyDirectoryPath,
        input.targetDirectoryName,
    );
    const publishedRecordPath = path.join(targetDirectoryPath, stagedFileName);
    let canonicalLinkCreated = false;
    let durabilityComplete = false;
    let published = false;
    try {
        const file = await open(stagedRecordPath, 'wx');
        try {
            const writeDirective = await input.faultInjection?.({
                markerPath: stagedRecordPath,
                recordKind: input.recordKind,
                serializedRecord: input.serializedRecord,
                stage: 'before-staged-write',
            });
            const serializedBytes = Buffer.from(input.serializedRecord, 'utf8');
            const maximumWriteByteLength =
                writeDirective?.maximumWriteByteLength ??
                serializedBytes.byteLength;
            if (
                !Number.isSafeInteger(maximumWriteByteLength) ||
                maximumWriteByteLength < 0 ||
                maximumWriteByteLength > serializedBytes.byteLength
            ) {
                throw new Error(
                    'The browser recovery marker fault injection returned an invalid staged-write length.',
                );
            }
            const { bytesWritten } =
                maximumWriteByteLength === 0
                    ? { bytesWritten: 0 }
                    : await file.write(
                          serializedBytes,
                          0,
                          maximumWriteByteLength,
                          0,
                      );
            if (bytesWritten !== serializedBytes.byteLength) {
                throw new Error(
                    `The third browser recovery ${input.recordKind} staging write was incomplete.`,
                );
            }
            await file.sync();
        } finally {
            await file.close();
        }
        await syncDirectoryMetadata(stagingDirectoryPath);
        await input.faultInjection?.({
            markerPath: stagedRecordPath,
            recordKind: input.recordKind,
            serializedRecord: input.serializedRecord,
            stage: 'after-staged-close-before-validation',
        });
        const stagedRecord = await readCanonicalPublishedRecoveryRecord({
            directoryPath: stagingDirectoryPath,
            fieldName: `Staged third browser recovery ${input.recordKind}`,
            fileName: stagedFileName,
        });
        if (stagedRecord.serialized !== input.serializedRecord) {
            throw new Error(
                `The staged third browser recovery ${input.recordKind} bytes changed before publication.`,
            );
        }
        const stagedAgainstMarker = await readThirdRecoveryLogicalMarker({
            authorizationKeySha256Hex: input.authorizationKeySha256Hex,
            expectedKeyDirectoryIdentity: input.expectedKeyDirectoryIdentity,
            reservationRootPath: input.reservationRootPath,
        });
        if (stagedAgainstMarker.serialized !== input.expectedLogicalPrefix) {
            throw new Error(
                'The third browser recovery logical marker changed during record staging.',
            );
        }
        await mkdir(targetDirectoryPath);
        await syncDirectoryMetadata(keyDirectoryPath);
        await requireThirdRecoveryKeyDirectoryIdentity({
            expected: input.expectedKeyDirectoryIdentity,
            keyDirectoryPath,
        });
        await link(stagedRecordPath, publishedRecordPath);
        canonicalLinkCreated = true;
        await input.faultInjection?.({
            markerPath: publishedRecordPath,
            recordKind: input.recordKind,
            serializedRecord: input.serializedRecord,
            stage: 'after-link-before-durability',
        });
        await syncRegularFileMetadata(publishedRecordPath);
        await syncDirectoryMetadata(targetDirectoryPath);
        await syncDirectoryMetadata(keyDirectoryPath);
        await requireThirdRecoveryKeyDirectoryIdentity({
            expected: input.expectedKeyDirectoryIdentity,
            keyDirectoryPath,
        });
        durabilityComplete = true;
        await unlink(stagedRecordPath);
        await syncRegularFileMetadata(publishedRecordPath);
        await rmdir(stagingDirectoryPath);
        await syncDirectoryMetadata(preflightRootPath);
        published = true;
        await input.faultInjection?.({
            markerPath: publishedRecordPath,
            recordKind: input.recordKind,
            serializedRecord: input.serializedRecord,
            stage: 'after-publication-before-reopen',
        });
        const reopenedMarker = await readThirdRecoveryLogicalMarker({
            authorizationKeySha256Hex: input.authorizationKeySha256Hex,
            expectedKeyDirectoryIdentity: input.expectedKeyDirectoryIdentity,
            reservationRootPath: input.reservationRootPath,
        });
        if (
            reopenedMarker.serialized !==
            `${input.expectedLogicalPrefix}${input.serializedRecord}`
        ) {
            throw new Error(
                `The published third browser recovery ${input.recordKind} bytes changed at the close boundary.`,
            );
        }
        return reopenedMarker;
    } catch (error) {
        let rollbackError: unknown;
        if (canonicalLinkCreated && !durabilityComplete) {
            try {
                await rollbackIncompleteThirdRecoveryRecordPublication({
                    expectedKeyDirectoryIdentity:
                        input.expectedKeyDirectoryIdentity,
                    expectedSerializedRecord: input.serializedRecord,
                    ...(input.faultInjection === undefined
                        ? {}
                        : { faultInjection: input.faultInjection }),
                    keyDirectoryPath,
                    preflightRootPath,
                    publishedRecordPath,
                    recordKind: input.recordKind,
                    stagedRecordPath,
                    stagingDirectoryPath,
                    targetDirectoryPath,
                });
                canonicalLinkCreated = false;
                published = false;
            } catch (incompletePublicationRollbackError) {
                rollbackError = incompletePublicationRollbackError;
            }
        }
        throw Object.assign(
            new Error(
                `The third browser recovery ${input.recordKind} atomic publication failed.`,
            ),
            {
                cause: error,
                recoveryRecordDurabilityComplete: durabilityComplete,
                recoveryRecordPublished: published,
                ...(rollbackError === undefined
                    ? {}
                    : { recoveryRecordRollbackError: rollbackError }),
            },
        );
    } finally {
        if (!published && !canonicalLinkCreated) {
            await cleanupUnpublishedRecoveryRecordDirectory({
                recordPath: stagedRecordPath,
                stagingDirectoryPath,
            });
        }
    }
};

const recoveryRecordDurabilityCompleted = (error: unknown): boolean =>
    typeof error === 'object' &&
    error !== null &&
    'recoveryRecordDurabilityComplete' in error &&
    error.recoveryRecordDurabilityComplete === true;

const createBrowserRecoveryPreflightAttempt = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly custody: BrowserRecoveryCustody;
    readonly faultInjection?: BrowserRecoveryMarkerFaultInjection;
    readonly markerBinding: BrowserRecoveryMarkerBinding;
    readonly reservationRootPath: string;
}): Promise<
    Readonly<{
        attemptPath: string;
        thirdRecoveryKeyDirectoryIdentity?: ThirdRecoveryKeyDirectoryIdentity;
    }>
> => {
    const attemptRelativePath = path.join(
        input.custody.preflightDirectoryName,
        input.authorizationKeySha256Hex,
        ...(input.custody.schemaVersion === 'browser-recovery-3'
            ? [
                  thirdRecoveryAttemptDirectoryName,
                  thirdRecoveryPublishedRecordFileName,
              ]
            : ['preflight-attempted.json']),
    );
    const serializedAttemptRecord = `${JSON.stringify({
        authorizationKeySha256Hex: input.authorizationKeySha256Hex,
        eventType: 'official-browser-width-recovery-preflight-attempted',
        failedReservationIdentitySha256Hex:
            input.markerBinding.failedReservationIdentitySha256Hex,
        ...(input.markerBinding.previousAuthorizationKeySha256Hex === undefined
            ? {}
            : {
                  previousAuthorizationKeySha256Hex:
                      input.markerBinding.previousAuthorizationKeySha256Hex,
              }),
        ...(input.markerBinding.previousPreflightAttemptSha256Hex === undefined
            ? {}
            : {
                  previousPreflightAttemptSha256Hex:
                      input.markerBinding.previousPreflightAttemptSha256Hex,
              }),
        ...(input.markerBinding.firstAuthorizationKeySha256Hex === undefined
            ? {}
            : {
                  firstAuthorizationKeySha256Hex:
                      input.markerBinding.firstAuthorizationKeySha256Hex,
              }),
        ...(input.markerBinding.firstPreflightAttemptSha256Hex === undefined
            ? {}
            : {
                  firstPreflightAttemptSha256Hex:
                      input.markerBinding.firstPreflightAttemptSha256Hex,
              }),
        recordedAtUnixMilliseconds: Date.now(),
        recoveryOrdinal: input.markerBinding.recoveryOrdinal,
    })}\n`;
    if (input.custody.schemaVersion === 'browser-recovery-3') {
        const keyDirectoryIdentity = await claimThirdRecoveryKeyDirectory({
            authorizationKeySha256Hex: input.authorizationKeySha256Hex,
            reservationRootPath: input.reservationRootPath,
        });
        try {
            const marker = await publishThirdRecoveryRecordAtomically({
                authorizationKeySha256Hex: input.authorizationKeySha256Hex,
                expectedKeyDirectoryIdentity: keyDirectoryIdentity,
                expectedLogicalPrefix: '',
                faultInjection: input.faultInjection,
                recordKind: 'preflight-attempt',
                reservationRootPath: input.reservationRootPath,
                serializedRecord: serializedAttemptRecord,
                targetDirectoryName: thirdRecoveryAttemptDirectoryName,
            });
            if (marker.attemptedRecordPath === undefined) {
                throw new Error(
                    'The claimed third browser recovery omitted its attempted record after publication.',
                );
            }
            return Object.freeze({
                attemptPath: marker.attemptedRecordPath,
                thirdRecoveryKeyDirectoryIdentity: keyDirectoryIdentity,
            });
        } catch (attemptError) {
            if (!recoveryRecordDurabilityCompleted(attemptError)) {
                throw attemptError;
            }
            let marker: ThirdRecoveryLogicalMarker;
            try {
                marker = await readThirdRecoveryLogicalMarker({
                    authorizationKeySha256Hex: input.authorizationKeySha256Hex,
                    expectedKeyDirectoryIdentity: keyDirectoryIdentity,
                    reservationRootPath: input.reservationRootPath,
                });
            } catch (reopenError) {
                throw Object.assign(
                    new Error(
                        'The consumed third browser recovery singleton could not be reopened safely after attempted-record publication failed.',
                    ),
                    { attemptCause: attemptError, cause: reopenError },
                );
            }
            if (marker.serialized === '') {
                throw attemptError;
            }
            if (marker.serialized !== serializedAttemptRecord) {
                throw Object.assign(
                    new Error(
                        'The consumed third browser recovery singleton changed its attempted-record prefix after publication failed.',
                    ),
                    { cause: attemptError },
                );
            }
            const existingRecords = parseCanonicalRecoveryJsonLines(
                marker.serialized,
                'Third browser recovery marker after attempted publication failure',
            );
            if (
                existingRecords[existingRecords.length - 1]?.eventType !==
                'official-sample-outcome'
            ) {
                const serializedFailureRecord = `${JSON.stringify({
                    eventType: 'official-sample-outcome',
                    failureName: errorName(attemptError),
                    outcome: 'failed',
                    recordedAtUnixMilliseconds: Date.now(),
                })}\n`;
                try {
                    marker = await publishThirdRecoveryRecordAtomically({
                        authorizationKeySha256Hex:
                            input.authorizationKeySha256Hex,
                        expectedKeyDirectoryIdentity: keyDirectoryIdentity,
                        expectedLogicalPrefix: marker.serialized,
                        faultInjection: input.faultInjection,
                        recordKind: 'failure-outcome',
                        reservationRootPath: input.reservationRootPath,
                        serializedRecord: serializedFailureRecord,
                        targetDirectoryName:
                            thirdRecoveryTerminalOutcomeDirectoryName,
                    });
                } catch (terminalError) {
                    if (!recoveryRecordDurabilityCompleted(terminalError)) {
                        throw terminalError;
                    }
                    try {
                        const reopenedMarker =
                            await readThirdRecoveryLogicalMarker({
                                authorizationKeySha256Hex:
                                    input.authorizationKeySha256Hex,
                                expectedKeyDirectoryIdentity:
                                    keyDirectoryIdentity,
                                reservationRootPath: input.reservationRootPath,
                            });
                        if (
                            reopenedMarker.serialized !==
                            `${marker.serialized}${serializedFailureRecord}`
                        ) {
                            throw terminalError;
                        }
                        marker = reopenedMarker;
                    } catch (reopenError) {
                        throw Object.assign(
                            new Error(
                                'The third browser recovery singleton was published, but its terminal failed outcome could not be durably recorded; no evidence operation ran.',
                            ),
                            {
                                attemptCause: attemptError,
                                cause: Object.assign(
                                    new Error(
                                        'The terminal publication and custody reopen both failed.',
                                    ),
                                    {
                                        attemptCause: terminalError,
                                        cause: reopenError,
                                    },
                                ),
                            },
                        );
                    }
                }
                const terminalRecords = parseCanonicalRecoveryJsonLines(
                    marker.serialized,
                    'Terminal third browser recovery acquisition failure',
                );
                if (
                    terminalRecords.length !== 2 ||
                    terminalRecords[1]?.eventType !==
                        'official-sample-outcome' ||
                    terminalRecords[1]?.outcome !== 'failed' ||
                    terminalRecords[1]?.failureName !== errorName(attemptError)
                ) {
                    throw Object.assign(
                        new Error(
                            'The third browser recovery acquisition failure did not close with its exact terminal failed record.',
                        ),
                        { cause: attemptError },
                    );
                }
            }
            throw attemptError;
        }
    }
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
        await file.writeFile(serializedAttemptRecord, 'utf8');
        await file.sync();
    } finally {
        await file.close();
    }
    return Object.freeze({ attemptPath });
};

type ValidatedBrowserRecoveryPreflightAttempt = Readonly<{
    outputSha256Hex: string;
    testFile: string;
}>;

type BrowserRecoveryCustody = Readonly<{
    operationDirectoryName: string;
    preflightDirectoryName: string;
    schemaVersion:
        | 'browser-recovery-1'
        | 'browser-recovery-2'
        | 'browser-recovery-3';
}>;

type BrowserRecoveryMarkerBinding = Readonly<{
    failedReservationIdentitySha256Hex: string;
    firstAuthorizationKeySha256Hex?: string;
    firstPreflightAttemptSha256Hex?: string;
    previousAuthorizationKeySha256Hex?: string;
    previousPreflightAttemptSha256Hex?: string;
    recoveryOrdinal: 1 | 2 | 3;
}>;

const firstBrowserRecoveryCustody = Object.freeze({
    operationDirectoryName: 'browser-recovery',
    preflightDirectoryName: 'browser-recovery-preflight',
    schemaVersion: 'browser-recovery-1',
} satisfies BrowserRecoveryCustody);

const chainedBrowserRecoveryCustody = Object.freeze({
    operationDirectoryName: chainedRecoveryOperationDirectoryName,
    preflightDirectoryName: chainedRecoveryPreflightDirectoryName,
    schemaVersion: 'browser-recovery-2',
} satisfies BrowserRecoveryCustody);

const thirdBrowserRecoveryCustody = Object.freeze({
    operationDirectoryName: thirdRecoveryOperationDirectoryName,
    preflightDirectoryName: thirdRecoveryPreflightDirectoryName,
    schemaVersion: 'browser-recovery-3',
} satisfies BrowserRecoveryCustody);

const buildFirstRecoveryMarkerBinding = (
    profile: ProofStorageWidthBrowserPreOperationRecoveryProfile,
): BrowserRecoveryMarkerBinding =>
    Object.freeze({
        failedReservationIdentitySha256Hex:
            profile.failedReservation.identitySha256Hex,
        recoveryOrdinal: profile.recoveryOrdinal,
    });

const buildChainedRecoveryMarkerBinding = (input: {
    readonly chainedProfile: ProofStorageWidthBrowserChainedRecoveryProfile;
    readonly preOperationProfile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
}): BrowserRecoveryMarkerBinding =>
    Object.freeze({
        failedReservationIdentitySha256Hex:
            input.preOperationProfile.failedReservation.identitySha256Hex,
        previousAuthorizationKeySha256Hex:
            input.chainedProfile.previousAuthorizationKeySha256Hex,
        previousPreflightAttemptSha256Hex:
            input.chainedProfile.previousPreflightAttempt.sha256Hex,
        recoveryOrdinal: input.chainedProfile.recoveryOrdinal,
    });

const buildThirdRecoveryMarkerBinding = (input: {
    readonly chainedProfile: ProofStorageWidthBrowserChainedRecoveryProfile;
    readonly preOperationProfile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    readonly thirdProfile: ProofStorageWidthBrowserThirdRecoveryProfile;
}): BrowserRecoveryMarkerBinding =>
    Object.freeze({
        failedReservationIdentitySha256Hex:
            input.preOperationProfile.failedReservation.identitySha256Hex,
        firstAuthorizationKeySha256Hex:
            input.chainedProfile.previousAuthorizationKeySha256Hex,
        firstPreflightAttemptSha256Hex:
            input.chainedProfile.previousPreflightAttempt.sha256Hex,
        previousAuthorizationKeySha256Hex:
            input.thirdProfile.previousChainedAuthorizationKeySha256Hex,
        previousPreflightAttemptSha256Hex:
            input.thirdProfile.previousChainedPreflightAttempt.sha256Hex,
        recoveryOrdinal: input.thirdProfile.recoveryOrdinal,
    });

type BrowserRecoveryAuthorization = Readonly<{
    authorizationKeySha256Hex: string;
    custody: BrowserRecoveryCustody;
    faultInjection?: BrowserRecoveryMarkerFaultInjection;
    markerBinding: BrowserRecoveryMarkerBinding;
    preflightAttemptPath: string;
    chainedProfile?: ProofStorageWidthBrowserChainedRecoveryProfile;
    preOperationProfile: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    recoveryOrdinal: 1 | 2 | 3;
    reservationRootPath: string;
    thirdRecoveryKeyDirectoryIdentity?: ThirdRecoveryKeyDirectoryIdentity;
    thirdProfile?: ProofStorageWidthBrowserThirdRecoveryProfile;
}>;

const appendBrowserRecoveryStaticPreflightObservation = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly custody: BrowserRecoveryCustody;
    readonly faultInjection?: BrowserRecoveryMarkerFaultInjection;
    readonly identity: RecoveryReservationIdentity;
    readonly reservationPath: string;
    readonly reservationRootPath: string;
    readonly result: CapturedCommandResult;
    readonly thirdRecoveryKeyDirectoryIdentity?: ThirdRecoveryKeyDirectoryIdentity;
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
    if (input.custody.schemaVersion === 'browser-recovery-3') {
        if (input.thirdRecoveryKeyDirectoryIdentity === undefined) {
            throw new Error(
                'The third browser recovery static observation lacks its in-memory key-directory claim.',
            );
        }
        const marker = await readThirdRecoveryLogicalMarker({
            authorizationKeySha256Hex: input.authorizationKeySha256Hex,
            expectedKeyDirectoryIdentity:
                input.thirdRecoveryKeyDirectoryIdentity,
            reservationRootPath: input.reservationRootPath,
        });
        if (
            marker.attemptedRecordPath !== path.resolve(input.reservationPath)
        ) {
            throw new Error(
                'The third browser recovery attempted record changed custody paths.',
            );
        }
        const records = parseCanonicalRecoveryJsonLines(
            marker.serialized,
            'Third browser recovery marker before static observation',
        );
        if (
            records.length !== 1 ||
            records[0]?.authorizationKeySha256Hex !==
                input.authorizationKeySha256Hex ||
            records[0]?.recoveryOrdinal !== thirdRecoveryOrdinal
        ) {
            throw new Error(
                'The third browser recovery marker is not pending its one static observation.',
            );
        }
        await publishThirdRecoveryRecordAtomically({
            authorizationKeySha256Hex: input.authorizationKeySha256Hex,
            expectedKeyDirectoryIdentity:
                input.thirdRecoveryKeyDirectoryIdentity,
            expectedLogicalPrefix: marker.serialized,
            faultInjection: input.faultInjection,
            recordKind: 'static-observation',
            reservationRootPath: input.reservationRootPath,
            serializedRecord,
            targetDirectoryName: thirdRecoveryStaticObservationDirectoryName,
        });
        return;
    }
    const custodyReservationPath = await resolveExistingCustodyFile({
        fieldName: 'Browser recovery static preflight marker',
        relativePath: path.join(
            input.custody.preflightDirectoryName,
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
    const file = await open(input.reservationPath, 'r+');
    try {
        const openedCustodyReservationPath = await resolveExistingCustodyFile({
            fieldName: 'Opened browser recovery static preflight marker',
            relativePath: path.join(
                input.custody.preflightDirectoryName,
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
    readonly markerBinding: BrowserRecoveryMarkerBinding;
    readonly serialized: string;
    readonly terminalBinding?: Readonly<{
        attachmentPath: string;
        attachmentSha256Hex: string;
        decisionOutcome: 'eligible' | 'ineligible';
        markerPrefixByteLength: number;
        markerPrefixSha256Hex: string;
        operationReservationPath: string;
        operationReservationSha256Hex: string;
    }>;
    readonly terminalOutcomeRequired: boolean;
}): ValidatedBrowserRecoveryPreflightAttempt => {
    const records = parseCanonicalRecoveryJsonLines(
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
            input.markerBinding.failedReservationIdentitySha256Hex ||
        records[0]?.previousAuthorizationKeySha256Hex !==
            input.markerBinding.previousAuthorizationKeySha256Hex ||
        records[0]?.previousPreflightAttemptSha256Hex !==
            input.markerBinding.previousPreflightAttemptSha256Hex ||
        records[0]?.firstAuthorizationKeySha256Hex !==
            input.markerBinding.firstAuthorizationKeySha256Hex ||
        records[0]?.firstPreflightAttemptSha256Hex !==
            input.markerBinding.firstPreflightAttemptSha256Hex ||
        records[0]?.recoveryOrdinal !== input.markerBinding.recoveryOrdinal ||
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
            (input.terminalBinding !== undefined &&
                (records[2]?.attachmentPath !==
                    input.terminalBinding.attachmentPath ||
                    records[2]?.attachmentSha256Hex !==
                        input.terminalBinding.attachmentSha256Hex ||
                    records[2]?.decisionOutcome !==
                        input.terminalBinding.decisionOutcome ||
                    records[2]?.identitySha256Hex !==
                        input.identity.identitySha256Hex ||
                    records[2]?.markerPrefixByteLength !==
                        input.terminalBinding.markerPrefixByteLength ||
                    records[2]?.markerPrefixSha256Hex !==
                        input.terminalBinding.markerPrefixSha256Hex ||
                    records[2]?.operationReservationPath !==
                        input.terminalBinding.operationReservationPath ||
                    records[2]?.operationReservationSha256Hex !==
                        input.terminalBinding.operationReservationSha256Hex)) ||
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

const browserRecoveryMarkerRelativePath = (
    authorization: BrowserRecoveryAuthorization,
): string =>
    path.join(
        authorization.custody.preflightDirectoryName,
        authorization.authorizationKeySha256Hex,
        'preflight-attempted.json',
    );

const readBrowserRecoveryMarkerSerialization = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly custody: BrowserRecoveryCustody;
    readonly reservationRootPath: string;
    readonly thirdRecoveryKeyDirectoryIdentity?: ThirdRecoveryKeyDirectoryIdentity;
}): Promise<string> => {
    if (input.custody.schemaVersion === 'browser-recovery-3') {
        return (
            await readThirdRecoveryLogicalMarker({
                authorizationKeySha256Hex: input.authorizationKeySha256Hex,
                ...(input.thirdRecoveryKeyDirectoryIdentity === undefined
                    ? {}
                    : {
                          expectedKeyDirectoryIdentity:
                              input.thirdRecoveryKeyDirectoryIdentity,
                      }),
                reservationRootPath: input.reservationRootPath,
            })
        ).serialized;
    }
    const markerPath = await resolveExistingCustodyFile({
        fieldName: 'Browser recovery static preflight marker',
        relativePath: path.join(
            input.custody.preflightDirectoryName,
            input.authorizationKeySha256Hex,
            'preflight-attempted.json',
        ),
        rootPath: input.reservationRootPath,
    });
    return readFile(markerPath, 'utf8');
};

const validateBrowserRecoveryMarkerStart = (
    authorization: BrowserRecoveryAuthorization,
    records: readonly JsonObject[],
): void => {
    if (
        records.length < 1 ||
        records.length > 3 ||
        records[0]?.authorizationKeySha256Hex !==
            authorization.authorizationKeySha256Hex ||
        records[0]?.eventType !==
            'official-browser-width-recovery-preflight-attempted' ||
        records[0]?.failedReservationIdentitySha256Hex !==
            authorization.markerBinding.failedReservationIdentitySha256Hex ||
        records[0]?.previousAuthorizationKeySha256Hex !==
            authorization.markerBinding.previousAuthorizationKeySha256Hex ||
        records[0]?.previousPreflightAttemptSha256Hex !==
            authorization.markerBinding.previousPreflightAttemptSha256Hex ||
        records[0]?.firstAuthorizationKeySha256Hex !==
            authorization.markerBinding.firstAuthorizationKeySha256Hex ||
        records[0]?.firstPreflightAttemptSha256Hex !==
            authorization.markerBinding.firstPreflightAttemptSha256Hex ||
        records[0]?.recoveryOrdinal !==
            authorization.markerBinding.recoveryOrdinal ||
        typeof records[0]?.recordedAtUnixMilliseconds !== 'number'
    ) {
        throw new Error(
            'The browser recovery singleton marker changed before its terminal outcome could be recorded.',
        );
    }
};

const validatePendingBrowserRecoveryStaticObservation = (
    records: readonly JsonObject[],
): void => {
    const staticObservation = records[1];
    const staticListStdout = requireString(
        staticObservation?.staticListStdout,
        'Browser recovery pending static preflight stdout',
    );
    const staticListStderr = requireString(
        staticObservation?.staticListStderr,
        'Browser recovery pending static preflight stderr',
    );
    if (
        staticObservation?.eventType !==
            'official-browser-width-recovery-static-preflight-observed' ||
        staticListStderr !== '' ||
        sha256Hex(staticListStdout) !==
            requireSha256Hex(
                staticObservation?.staticListStdoutSha256Hex,
                'Browser recovery pending static preflight stdout digest',
            ) ||
        sha256Hex(staticListStderr) !==
            requireSha256Hex(
                staticObservation?.staticListStderrSha256Hex,
                'Browser recovery pending static preflight stderr digest',
            )
    ) {
        throw new Error(
            'The browser recovery pending static preflight observation changed.',
        );
    }
    parseProofStorageWidthBrowserStaticPreflightOutput(staticListStdout);
};

const appendBrowserRecoveryFailureOutcomeIfPending = async (input: {
    readonly authorization: BrowserRecoveryAuthorization;
    readonly failure: unknown;
}): Promise<void> => {
    if (input.authorization.custody.schemaVersion === 'browser-recovery-3') {
        const keyDirectoryIdentity =
            input.authorization.thirdRecoveryKeyDirectoryIdentity;
        if (keyDirectoryIdentity === undefined) {
            throw new Error(
                'The third browser recovery failure outcome lacks its in-memory key-directory claim.',
            );
        }
        let marker = await readThirdRecoveryLogicalMarker({
            authorizationKeySha256Hex:
                input.authorization.authorizationKeySha256Hex,
            expectedKeyDirectoryIdentity: keyDirectoryIdentity,
            reservationRootPath: input.authorization.reservationRootPath,
        });
        let records = parseCanonicalRecoveryJsonLines(
            marker.serialized,
            'Third browser recovery marker before terminal failure',
        );
        validateBrowserRecoveryMarkerStart(input.authorization, records);
        const finalRecord = records[records.length - 1];
        if (finalRecord?.eventType === 'official-sample-outcome') {
            if (
                (records.length !== 2 && records.length !== 3) ||
                finalRecord.outcome !== 'failed' ||
                finalRecord.failureName !== errorName(input.failure) ||
                typeof finalRecord.recordedAtUnixMilliseconds !== 'number'
            ) {
                throw new Error(
                    'The third browser recovery singleton already has a different terminal outcome.',
                );
            }
            return;
        }
        if (records.length !== 1 && records.length !== 2) {
            throw new Error(
                'The third browser recovery singleton has an invalid pending shape.',
            );
        }
        if (records.length === 2) {
            validatePendingBrowserRecoveryStaticObservation(records);
        }
        const serializedOutcomeRecord = `${JSON.stringify({
            eventType: 'official-sample-outcome',
            failureName: errorName(input.failure),
            outcome: 'failed',
            recordedAtUnixMilliseconds: Date.now(),
        })}\n`;
        const expectedTerminalSerialization = `${marker.serialized}${serializedOutcomeRecord}`;
        try {
            marker = await publishThirdRecoveryRecordAtomically({
                authorizationKeySha256Hex:
                    input.authorization.authorizationKeySha256Hex,
                expectedKeyDirectoryIdentity: keyDirectoryIdentity,
                expectedLogicalPrefix: marker.serialized,
                ...(input.authorization.faultInjection === undefined
                    ? {}
                    : {
                          faultInjection: input.authorization.faultInjection,
                      }),
                recordKind: 'failure-outcome',
                reservationRootPath: input.authorization.reservationRootPath,
                serializedRecord: serializedOutcomeRecord,
                targetDirectoryName: thirdRecoveryTerminalOutcomeDirectoryName,
            });
        } catch (publicationError) {
            if (!recoveryRecordDurabilityCompleted(publicationError)) {
                throw publicationError;
            }
            const reopenedMarker = await readThirdRecoveryLogicalMarker({
                authorizationKeySha256Hex:
                    input.authorization.authorizationKeySha256Hex,
                expectedKeyDirectoryIdentity: keyDirectoryIdentity,
                reservationRootPath: input.authorization.reservationRootPath,
            }).catch((reopenError: unknown) => {
                throw Object.assign(
                    new Error(
                        'The third browser recovery failed terminal publication could not be reopened.',
                    ),
                    { attemptCause: publicationError, cause: reopenError },
                );
            });
            if (reopenedMarker.serialized !== expectedTerminalSerialization) {
                throw Object.assign(
                    new Error(
                        'The third browser recovery failed terminal publication did not persist its exact logical bytes.',
                    ),
                    { cause: publicationError },
                );
            }
            marker = reopenedMarker;
        }
        records = parseCanonicalRecoveryJsonLines(
            marker.serialized,
            'Terminal third browser recovery failure marker',
        );
        validateBrowserRecoveryMarkerStart(input.authorization, records);
        const terminalRecord = records[records.length - 1];
        if (
            (records.length !== 2 && records.length !== 3) ||
            terminalRecord?.eventType !== 'official-sample-outcome' ||
            terminalRecord.outcome !== 'failed' ||
            terminalRecord.failureName !== errorName(input.failure) ||
            typeof terminalRecord.recordedAtUnixMilliseconds !== 'number'
        ) {
            throw new Error(
                'The third browser recovery failure did not close with its exact terminal record.',
            );
        }
        return;
    }
    const markerRelativePath = browserRecoveryMarkerRelativePath(
        input.authorization,
    );
    const markerPath = await resolveExistingCustodyFile({
        fieldName: 'Browser recovery static preflight marker',
        relativePath: markerRelativePath,
        rootPath: input.authorization.reservationRootPath,
    });
    const file = await open(markerPath, 'r+');
    try {
        const custodyMarkerPath = await resolveExistingCustodyFile({
            fieldName: 'Opened browser recovery static preflight marker',
            relativePath: markerRelativePath,
            rootPath: input.authorization.reservationRootPath,
        });
        if (
            custodyMarkerPath !== markerPath ||
            markerPath !==
                path.resolve(input.authorization.preflightAttemptPath)
        ) {
            throw new Error(
                'The opened browser recovery static preflight marker changed custody paths.',
            );
        }
        const serialized = await file.readFile('utf8');
        const records = parseCanonicalRecoveryJsonLines(
            serialized,
            'Browser recovery static preflight attempt',
        );
        validateBrowserRecoveryMarkerStart(input.authorization, records);
        const finalRecord = records[records.length - 1];
        if (finalRecord?.eventType === 'official-sample-outcome') {
            if (
                (records.length !== 2 && records.length !== 3) ||
                finalRecord.outcome !== 'failed' ||
                finalRecord.failureName !== errorName(input.failure) ||
                typeof finalRecord.recordedAtUnixMilliseconds !== 'number'
            ) {
                throw new Error(
                    'The browser recovery singleton already has a different terminal outcome.',
                );
            }
            return;
        }
        if (records.length !== 1 && records.length !== 2) {
            throw new Error(
                'The browser recovery singleton marker has an invalid pending shape.',
            );
        }
        if (records.length === 2) {
            validatePendingBrowserRecoveryStaticObservation(records);
        }
        const serializedOutcomeRecord = `${JSON.stringify({
            eventType: 'official-sample-outcome',
            failureName: errorName(input.failure),
            outcome: 'failed',
            recordedAtUnixMilliseconds: Date.now(),
        })}\n`;
        const statistics = await file.stat();
        if (statistics.size !== Buffer.byteLength(serialized, 'utf8')) {
            throw new Error(
                'The browser recovery singleton marker changed while recording its failure.',
            );
        }
        const { bytesWritten } = await file.write(
            serializedOutcomeRecord,
            statistics.size,
            'utf8',
        );
        if (
            bytesWritten !== Buffer.byteLength(serializedOutcomeRecord, 'utf8')
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

type ChainedBrowserRecoveryValidatedOutcome = Readonly<{
    attachmentPath: string;
    attachmentSha256Hex: string;
    authorization: BrowserRecoveryAuthorization;
    decisionOutcome: 'eligible' | 'ineligible';
    identity: RecoveryReservationIdentity;
    markerPrefixByteLength: number;
    markerPrefixSha256Hex: string;
    operationReservationPath: string;
    operationReservationSha256Hex: string;
}>;

const finalizeThirdBrowserRecoveryOutcomeAtomically = async (
    input: ChainedBrowserRecoveryValidatedOutcome,
): Promise<void> => {
    const keyDirectoryIdentity =
        input.authorization.thirdRecoveryKeyDirectoryIdentity;
    if (keyDirectoryIdentity === undefined) {
        throw new Error(
            'The third browser recovery validated outcome lacks its in-memory key-directory claim.',
        );
    }
    let marker = await readThirdRecoveryLogicalMarker({
        authorizationKeySha256Hex:
            input.authorization.authorizationKeySha256Hex,
        expectedKeyDirectoryIdentity: keyDirectoryIdentity,
        reservationRootPath: input.authorization.reservationRootPath,
    });
    if (
        marker.attemptedRecordPath !==
        path.resolve(input.authorization.preflightAttemptPath)
    ) {
        throw new Error(
            'The third browser recovery attempted record changed custody paths before finalization.',
        );
    }
    const records = parseCanonicalRecoveryJsonLines(
        marker.serialized,
        'Third browser recovery static preflight attempt',
    );
    validateBrowserRecoveryMarkerStart(input.authorization, records);
    const markerPrefix = literalRecoveryJsonLinesPrefix(
        marker.serialized,
        2,
        'Third browser recovery static preflight marker',
    );
    if (
        markerPrefix.byteLength !== input.markerPrefixByteLength ||
        sha256Hex(markerPrefix) !== input.markerPrefixSha256Hex
    ) {
        throw new Error(
            'The third browser recovery marker prefix changed before finalization.',
        );
    }
    validatePendingBrowserRecoveryStaticObservation(records);
    const attachmentPath = await resolveCanonicalAbsoluteCustodyFile(
        input.attachmentPath,
        'Final third browser recovery attachment',
    );
    if (
        attachmentPath !== path.resolve(input.attachmentPath) ||
        sha256Hex(await readFile(attachmentPath)) !== input.attachmentSha256Hex
    ) {
        throw new Error(
            'The third browser recovery attachment changed before finalization.',
        );
    }
    const expectedOperationReservationPath = `${input.authorization.custody.operationDirectoryName}/${input.authorization.authorizationKeySha256Hex}/browser-recovery-started.json`;
    requireExactRelativeArtifactPath({
        actual: input.operationReservationPath,
        expected: expectedOperationReservationPath,
        fieldName: 'Third browser recovery operation reservation path',
        rootPath: input.authorization.reservationRootPath,
    });
    const operationReservationPath = await resolveExistingCustodyFile({
        fieldName: 'Final third browser recovery operation reservation',
        relativePath: expectedOperationReservationPath,
        rootPath: input.authorization.reservationRootPath,
    });
    const serializedOperationReservation = await readFile(
        operationReservationPath,
        'utf8',
    );
    if (
        sha256Hex(serializedOperationReservation) !==
        input.operationReservationSha256Hex
    ) {
        throw new Error(
            'The third browser recovery operation reservation changed before finalization.',
        );
    }
    validateBrowserRecoveryReservationArtifact({
        authorizationKeySha256Hex:
            input.authorization.authorizationKeySha256Hex,
        identity: input.identity,
        serialized: serializedOperationReservation,
    });
    const terminalBinding = Object.freeze({
        attachmentPath,
        attachmentSha256Hex: input.attachmentSha256Hex,
        decisionOutcome: input.decisionOutcome,
        markerPrefixByteLength: markerPrefix.byteLength,
        markerPrefixSha256Hex: sha256Hex(markerPrefix),
        operationReservationPath: expectedOperationReservationPath,
        operationReservationSha256Hex: input.operationReservationSha256Hex,
    });
    const finalRecord = records[records.length - 1];
    if (finalRecord?.eventType === 'official-sample-outcome') {
        if (records.length !== 3 || finalRecord.outcome !== 'validated') {
            throw new Error(
                'The third browser recovery singleton already has a different terminal outcome.',
            );
        }
        validateBrowserRecoveryPreflightAttempt({
            authorizationKeySha256Hex:
                input.authorization.authorizationKeySha256Hex,
            identity: input.identity,
            markerBinding: input.authorization.markerBinding,
            serialized: marker.serialized,
            terminalBinding,
            terminalOutcomeRequired: true,
        });
        return;
    }
    if (records.length !== 2) {
        throw new Error(
            'The third browser recovery cannot validate before its static observation.',
        );
    }
    const serializedOutcomeRecord = `${JSON.stringify({
        attachmentPath: terminalBinding.attachmentPath,
        attachmentSha256Hex: terminalBinding.attachmentSha256Hex,
        decisionOutcome: terminalBinding.decisionOutcome,
        eventType: 'official-sample-outcome',
        identitySha256Hex: input.identity.identitySha256Hex,
        markerPrefixByteLength: terminalBinding.markerPrefixByteLength,
        markerPrefixSha256Hex: terminalBinding.markerPrefixSha256Hex,
        operationReservationPath: terminalBinding.operationReservationPath,
        operationReservationSha256Hex:
            terminalBinding.operationReservationSha256Hex,
        outcome: 'validated',
        recordedAtUnixMilliseconds: Date.now(),
    })}\n`;
    const expectedTerminalSerialization = `${marker.serialized}${serializedOutcomeRecord}`;
    validateBrowserRecoveryPreflightAttempt({
        authorizationKeySha256Hex:
            input.authorization.authorizationKeySha256Hex,
        identity: input.identity,
        markerBinding: input.authorization.markerBinding,
        serialized: expectedTerminalSerialization,
        terminalBinding,
        terminalOutcomeRequired: true,
    });
    try {
        marker = await publishThirdRecoveryRecordAtomically({
            authorizationKeySha256Hex:
                input.authorization.authorizationKeySha256Hex,
            expectedKeyDirectoryIdentity: keyDirectoryIdentity,
            expectedLogicalPrefix: marker.serialized,
            ...(input.authorization.faultInjection === undefined
                ? {}
                : { faultInjection: input.authorization.faultInjection }),
            recordKind: 'validated-outcome',
            reservationRootPath: input.authorization.reservationRootPath,
            serializedRecord: serializedOutcomeRecord,
            targetDirectoryName: thirdRecoveryTerminalOutcomeDirectoryName,
        });
    } catch (publicationError) {
        if (!recoveryRecordDurabilityCompleted(publicationError)) {
            throw publicationError;
        }
        const reopenedMarker = await readThirdRecoveryLogicalMarker({
            authorizationKeySha256Hex:
                input.authorization.authorizationKeySha256Hex,
            expectedKeyDirectoryIdentity: keyDirectoryIdentity,
            reservationRootPath: input.authorization.reservationRootPath,
        }).catch((reopenError: unknown) => {
            throw Object.assign(
                new Error(
                    'The third browser recovery validated terminal publication could not be reopened.',
                ),
                { attemptCause: publicationError, cause: reopenError },
            );
        });
        if (reopenedMarker.serialized !== expectedTerminalSerialization) {
            throw Object.assign(
                new Error(
                    'The persisted third browser recovery validated terminal bytes differ from the prevalidated record.',
                ),
                { cause: publicationError },
            );
        }
        marker = reopenedMarker;
    }
    if (marker.serialized !== expectedTerminalSerialization) {
        throw new Error(
            'The reopened third browser recovery terminal marker changed its exact logical bytes.',
        );
    }
    validateBrowserRecoveryPreflightAttempt({
        authorizationKeySha256Hex:
            input.authorization.authorizationKeySha256Hex,
        identity: input.identity,
        markerBinding: input.authorization.markerBinding,
        serialized: marker.serialized,
        terminalBinding,
        terminalOutcomeRequired: true,
    });
    const reopenedAttachmentPath = await resolveCanonicalAbsoluteCustodyFile(
        input.attachmentPath,
        'Reopened final third browser recovery attachment',
    );
    const reopenedOperationReservationPath = await resolveExistingCustodyFile({
        fieldName: 'Reopened final third browser recovery reservation',
        relativePath: expectedOperationReservationPath,
        rootPath: input.authorization.reservationRootPath,
    });
    if (
        reopenedAttachmentPath !== attachmentPath ||
        sha256Hex(await readFile(reopenedAttachmentPath)) !==
            input.attachmentSha256Hex ||
        reopenedOperationReservationPath !== operationReservationPath ||
        sha256Hex(await readFile(reopenedOperationReservationPath)) !==
            input.operationReservationSha256Hex
    ) {
        throw new Error(
            'The third browser recovery bound artifacts changed after terminal publication.',
        );
    }
};

const finalizeChainedBrowserRecoveryOutcome = async (
    input: ChainedBrowserRecoveryValidatedOutcome,
): Promise<void> => {
    if (
        (input.authorization.recoveryOrdinal !== chainedRecoveryOrdinal &&
            input.authorization.recoveryOrdinal !== thirdRecoveryOrdinal) ||
        !path.isAbsolute(input.attachmentPath) ||
        !exactSha256HexPattern.test(input.attachmentSha256Hex) ||
        !exactSha256HexPattern.test(input.identity.identitySha256Hex) ||
        !Number.isSafeInteger(input.markerPrefixByteLength) ||
        input.markerPrefixByteLength <= 0 ||
        !exactSha256HexPattern.test(input.markerPrefixSha256Hex) ||
        input.operationReservationPath.length === 0 ||
        !exactSha256HexPattern.test(input.operationReservationSha256Hex)
    ) {
        throw new Error(
            'The chained browser recovery validated outcome lacks its attachment, decision, or identity binding.',
        );
    }
    if (input.authorization.custody.schemaVersion === 'browser-recovery-3') {
        await finalizeThirdBrowserRecoveryOutcomeAtomically(input);
        return;
    }
    const markerRelativePath = browserRecoveryMarkerRelativePath(
        input.authorization,
    );
    const markerPath = await resolveExistingCustodyFile({
        fieldName: 'Browser recovery static preflight marker',
        relativePath: markerRelativePath,
        rootPath: input.authorization.reservationRootPath,
    });
    const file = await open(markerPath, 'r+');
    try {
        const custodyMarkerPath = await resolveExistingCustodyFile({
            fieldName: 'Opened browser recovery static preflight marker',
            relativePath: markerRelativePath,
            rootPath: input.authorization.reservationRootPath,
        });
        if (
            custodyMarkerPath !== markerPath ||
            markerPath !==
                path.resolve(input.authorization.preflightAttemptPath)
        ) {
            throw new Error(
                'The opened browser recovery static preflight marker changed custody paths.',
            );
        }
        const serialized = await file.readFile('utf8');
        const records = parseCanonicalRecoveryJsonLines(
            serialized,
            'Browser recovery static preflight attempt',
        );
        validateBrowserRecoveryMarkerStart(input.authorization, records);
        const markerPrefix = literalRecoveryJsonLinesPrefix(
            serialized,
            2,
            'Browser recovery static preflight marker',
        );
        if (
            markerPrefix.byteLength !== input.markerPrefixByteLength ||
            sha256Hex(markerPrefix) !== input.markerPrefixSha256Hex
        ) {
            throw new Error(
                'The chained browser recovery marker prefix changed before finalization.',
            );
        }
        validatePendingBrowserRecoveryStaticObservation(records);
        const attachmentPath = await resolveCanonicalAbsoluteCustodyFile(
            input.attachmentPath,
            'Final chained browser recovery attachment',
        );
        if (
            attachmentPath !== path.resolve(input.attachmentPath) ||
            sha256Hex(await readFile(attachmentPath)) !==
                input.attachmentSha256Hex
        ) {
            throw new Error(
                'The chained browser recovery attachment changed before finalization.',
            );
        }
        const expectedOperationReservationPath = `${input.authorization.custody.operationDirectoryName}/${input.authorization.authorizationKeySha256Hex}/browser-recovery-started.json`;
        requireExactRelativeArtifactPath({
            actual: input.operationReservationPath,
            expected: expectedOperationReservationPath,
            fieldName: 'Chained browser recovery operation reservation path',
            rootPath: input.authorization.reservationRootPath,
        });
        const operationReservationPath = await resolveExistingCustodyFile({
            fieldName: 'Final chained browser recovery operation reservation',
            relativePath: expectedOperationReservationPath,
            rootPath: input.authorization.reservationRootPath,
        });
        const serializedOperationReservation = await readFile(
            operationReservationPath,
            'utf8',
        );
        if (
            sha256Hex(serializedOperationReservation) !==
            input.operationReservationSha256Hex
        ) {
            throw new Error(
                'The chained browser recovery operation reservation changed before finalization.',
            );
        }
        validateBrowserRecoveryReservationArtifact({
            authorizationKeySha256Hex:
                input.authorization.authorizationKeySha256Hex,
            identity: input.identity,
            serialized: serializedOperationReservation,
        });
        const terminalBinding = Object.freeze({
            attachmentPath,
            attachmentSha256Hex: input.attachmentSha256Hex,
            decisionOutcome: input.decisionOutcome,
            markerPrefixByteLength: markerPrefix.byteLength,
            markerPrefixSha256Hex: sha256Hex(markerPrefix),
            operationReservationPath: expectedOperationReservationPath,
            operationReservationSha256Hex: input.operationReservationSha256Hex,
        });
        const finalRecord = records[records.length - 1];
        if (finalRecord?.eventType === 'official-sample-outcome') {
            if (records.length !== 3 || finalRecord.outcome !== 'validated') {
                throw new Error(
                    'The chained browser recovery singleton already has a different terminal outcome.',
                );
            }
            validateBrowserRecoveryPreflightAttempt({
                authorizationKeySha256Hex:
                    input.authorization.authorizationKeySha256Hex,
                identity: input.identity,
                markerBinding: input.authorization.markerBinding,
                serialized,
                terminalBinding,
                terminalOutcomeRequired: true,
            });
            return;
        }
        if (records.length !== 2) {
            throw new Error(
                'The chained browser recovery cannot validate before its static observation.',
            );
        }
        const serializedOutcomeRecord = `${JSON.stringify({
            attachmentPath: terminalBinding.attachmentPath,
            attachmentSha256Hex: terminalBinding.attachmentSha256Hex,
            decisionOutcome: terminalBinding.decisionOutcome,
            eventType: 'official-sample-outcome',
            identitySha256Hex: input.identity.identitySha256Hex,
            markerPrefixByteLength: terminalBinding.markerPrefixByteLength,
            markerPrefixSha256Hex: terminalBinding.markerPrefixSha256Hex,
            operationReservationPath: terminalBinding.operationReservationPath,
            operationReservationSha256Hex:
                terminalBinding.operationReservationSha256Hex,
            outcome: 'validated',
            recordedAtUnixMilliseconds: Date.now(),
        })}\n`;
        validateBrowserRecoveryPreflightAttempt({
            authorizationKeySha256Hex:
                input.authorization.authorizationKeySha256Hex,
            identity: input.identity,
            markerBinding: input.authorization.markerBinding,
            serialized: `${serialized}${serializedOutcomeRecord}`,
            terminalBinding,
            terminalOutcomeRequired: true,
        });
        const statistics = await file.stat();
        if (statistics.size !== Buffer.byteLength(serialized, 'utf8')) {
            throw new Error(
                'The browser recovery singleton marker changed while finalizing.',
            );
        }
        const { bytesWritten } = await file.write(
            serializedOutcomeRecord,
            statistics.size,
            'utf8',
        );
        if (
            bytesWritten !== Buffer.byteLength(serializedOutcomeRecord, 'utf8')
        ) {
            throw new Error(
                'The browser recovery singleton terminal outcome was only partially appended.',
            );
        }
        await file.sync();
    } finally {
        await file.close();
    }
};

const createBrowserRecoveryReservation = async (input: {
    readonly authorizationKeySha256Hex: string;
    readonly custody: BrowserRecoveryCustody;
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
        input.custody.operationDirectoryName,
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
    const records = parseCanonicalRecoveryJsonLines(
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

type ProofStorageWidthBrowserArtifactValidationOptions = Readonly<{
    chainedRecoveryProfile?: ProofStorageWidthBrowserChainedRecoveryProfile;
    loadNativeWidthEvidence?: NativeWidthEvidenceLoader;
    officialReservationRootPath?: string;
    preOperationRecoveryProfile?: ProofStorageWidthBrowserPreOperationRecoveryProfile;
    processedWasmKernelPath?: string;
    publicSdkWasmKernelPath?: string;
    thirdRecoveryProfile?: ProofStorageWidthBrowserThirdRecoveryProfile;
}>;

const validateProofStorageWidthBrowserEvidenceArtifactsWithMarkerState = async (
    attachmentPath: string,
    options: ProofStorageWidthBrowserArtifactValidationOptions &
        Readonly<{ allowProvisionalChainedRecoveryMarker: boolean }>,
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
    const serializedEvidence = await readFile(custodyAttachmentPath, 'utf8');
    const attachmentSha256Hex = sha256Hex(serializedEvidence);
    const evidence = requireJsonObject(
        parseJson(serializedEvidence, 'Proof-storage width browser evidence'),
        'Proof-storage width browser evidence',
    );
    if (
        evidence.formatVersion !== 4 &&
        evidence.formatVersion !== 5 &&
        evidence.formatVersion !== 6 &&
        evidence.formatVersion !== 7
    ) {
        throw new Error(
            'Proof-storage width browser evidence must use integrity format version four or recovery version five, six, or seven.',
        );
    }
    const isRecoveryEvidence =
        evidence.formatVersion === 5 ||
        evidence.formatVersion === 6 ||
        evidence.formatVersion === 7;
    const isThirdRecoveryEvidence = evidence.formatVersion === 7;
    const isChainedRecoveryEvidence =
        evidence.formatVersion === 6 || isThirdRecoveryEvidence;
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
    let validatedFailedRecoveryAttempt:
        | ValidatedFailedRecoveryAttempt
        | undefined;
    let validatedFailedChainedRecoveryAttempt:
        | ValidatedFailedChainedRecoveryAttempt
        | undefined;
    const preOperationRecoveryProfile =
        options.preOperationRecoveryProfile ??
        proofStorageWidthBrowserPreOperationRecoveryProfile;
    const chainedRecoveryProfile =
        options.chainedRecoveryProfile ??
        proofStorageWidthBrowserChainedRecoveryProfile;
    const thirdRecoveryProfile =
        options.thirdRecoveryProfile ??
        proofStorageWidthBrowserThirdRecoveryProfile;
    if (recovery !== undefined) {
        validatedRecovery =
            await validateProofStorageWidthBrowserPreOperationRecovery({
                failedRunDirectoryPath: requireString(
                    recovery.failedRunDirectoryPath,
                    'recovery.failedRunDirectoryPath',
                ),
                nativeEvidence,
                officialReservationRootPath: reservationRootPath,
                profile: preOperationRecoveryProfile,
            });
        const staticPreflight = requireJsonObject(
            recovery.staticPreflight,
            'recovery.staticPreflight',
        );
        if (isChainedRecoveryEvidence) {
            validatedFailedRecoveryAttempt =
                await validateProofStorageWidthBrowserFailedRecoveryAttempt({
                    failedRecoveryRunDirectoryPath: requireString(
                        recovery.failedRecoveryRunDirectoryPath,
                        'recovery.failedRecoveryRunDirectoryPath',
                    ),
                    nativeEvidence,
                    officialReservationRootPath: reservationRootPath,
                    preOperationRecovery: validatedRecovery,
                    preOperationProfile: preOperationRecoveryProfile,
                    profile: chainedRecoveryProfile,
                });
            if (isThirdRecoveryEvidence) {
                validatedFailedChainedRecoveryAttempt =
                    await validateProofStorageWidthBrowserFailedChainedRecoveryAttempt(
                        {
                            chainedProfile: chainedRecoveryProfile,
                            failedChainedRecoveryRunDirectoryPath:
                                requireString(
                                    recovery.failedChainedRecoveryRunDirectoryPath,
                                    'recovery.failedChainedRecoveryRunDirectoryPath',
                                ),
                            failedRecoveryAttempt:
                                validatedFailedRecoveryAttempt,
                            nativeEvidence,
                            officialReservationRootPath: reservationRootPath,
                            preOperationProfile: preOperationRecoveryProfile,
                            preOperationRecovery: validatedRecovery,
                            profile: thirdRecoveryProfile,
                        },
                    );
            }
            const expectedFirstHarnessRepair = {
                changedFilePaths: recoveryRepairFilePaths,
                harnessCommitHash:
                    chainedRecoveryProfile.firstHarnessRepairCommitHash,
                nativeSourceCommitHash,
            };
            const expectedValidatorRepair = {
                changedFilePaths: validatorRepairFilePaths,
                harnessCommitHash:
                    chainedRecoveryProfile.validatorRepairCommitHash,
                nativeSourceCommitHash:
                    chainedRecoveryProfile.firstHarnessRepairCommitHash,
            };
            const expectedRecoveryHarnessRepair = {
                changedFilePaths: validatorRepairFilePaths,
                harnessCommitHash: isThirdRecoveryEvidence
                    ? thirdRecoveryProfile.issuanceCommitHash
                    : repositoryCommitHash,
                nativeSourceCommitHash:
                    chainedRecoveryProfile.validatorRepairCommitHash,
            };
            const expectedThirdRecoveryHarness = {
                changedFilePaths: validatorRepairFilePaths,
                harnessCommitHash: repositoryCommitHash,
                nativeSourceCommitHash: thirdRecoveryProfile.issuanceCommitHash,
            };
            if (
                recovery.recoveryOrdinal !==
                    (isThirdRecoveryEvidence
                        ? thirdRecoveryOrdinal
                        : chainedRecoveryOrdinal) ||
                !normalizedJsonEquals(
                    recovery.failedRecoveryArtifacts,
                    validatedFailedRecoveryAttempt.failedArtifacts,
                ) ||
                !normalizedJsonEquals(
                    recovery.previousPreflightAttempt,
                    validatedFailedRecoveryAttempt.previousPreflightAttempt,
                ) ||
                !normalizedJsonEquals(
                    recovery.firstHarnessRepair,
                    expectedFirstHarnessRepair,
                ) ||
                !normalizedJsonEquals(
                    recovery.validatorRepair,
                    expectedValidatorRepair,
                ) ||
                !normalizedJsonEquals(
                    recovery.recoveryHarnessRepair,
                    expectedRecoveryHarnessRepair,
                ) ||
                (isThirdRecoveryEvidence &&
                    (recovery.issuanceCommitHash !==
                        thirdRecoveryProfile.issuanceCommitHash ||
                        !normalizedJsonEquals(
                            recovery.failedChainedRecoveryArtifacts,
                            validatedFailedChainedRecoveryAttempt?.failedArtifacts,
                        ) ||
                        !normalizedJsonEquals(
                            recovery.previousChainedPreflightAttempt,
                            validatedFailedChainedRecoveryAttempt?.previousChainedPreflightAttempt,
                        ) ||
                        !normalizedJsonEquals(
                            recovery.thirdRecoveryHarness,
                            expectedThirdRecoveryHarness,
                        )))
            ) {
                throw new Error(
                    'The chained browser recovery closure changed its failed attempt or exact commit transitions.',
                );
            }
        } else if (
            recovery.recoveryOrdinal !== recoveryOrdinal ||
            recovery.harnessCommitHash !== repositoryCommitHash ||
            !normalizedJsonEquals(
                recovery.changedFilePaths,
                recoveryRepairFilePaths,
            )
        ) {
            throw new Error(
                'The browser recovery closure changed its predecessor, commits, repair diff, ordinal, or static preflight binding.',
            );
        }
        if (
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
            : isThirdRecoveryEvidence
              ? validatedFailedRecoveryAttempt === undefined ||
                validatedFailedChainedRecoveryAttempt === undefined
                  ? undefined
                  : buildBrowserThirdRecoveryReservationIdentity({
                        failedChainedRecoveryAttempt:
                            validatedFailedChainedRecoveryAttempt,
                        failedRecoveryAttempt: validatedFailedRecoveryAttempt,
                        harnessTransition: {
                            chainedRecoveryHarness: {
                                firstHarnessRepair: {
                                    changedFilePaths: recoveryRepairFilePaths,
                                    harnessCommitHash:
                                        chainedRecoveryProfile.firstHarnessRepairCommitHash,
                                    nativeSourceCommitHash,
                                },
                                recoveryHarnessRepair: {
                                    changedFilePaths: validatorRepairFilePaths,
                                    harnessCommitHash:
                                        thirdRecoveryProfile.issuanceCommitHash,
                                    nativeSourceCommitHash:
                                        chainedRecoveryProfile.validatorRepairCommitHash,
                                },
                                validatorRepair: {
                                    changedFilePaths: validatorRepairFilePaths,
                                    harnessCommitHash:
                                        chainedRecoveryProfile.validatorRepairCommitHash,
                                    nativeSourceCommitHash:
                                        chainedRecoveryProfile.firstHarnessRepairCommitHash,
                                },
                            },
                            thirdRecoveryHarness: {
                                changedFilePaths: validatorRepairFilePaths,
                                harnessCommitHash: repositoryCommitHash,
                                nativeSourceCommitHash:
                                    thirdRecoveryProfile.issuanceCommitHash,
                            },
                        },
                        nativeEvidence,
                        preOperationRecovery: validatedRecovery,
                        rawWasmSha256Hex,
                    })
              : isChainedRecoveryEvidence
                ? validatedFailedRecoveryAttempt === undefined
                    ? undefined
                    : buildBrowserChainedRecoveryReservationIdentity({
                          failedRecoveryAttempt: validatedFailedRecoveryAttempt,
                          harnessTransition: {
                              firstHarnessRepair: {
                                  changedFilePaths: recoveryRepairFilePaths,
                                  harnessCommitHash:
                                      chainedRecoveryProfile.firstHarnessRepairCommitHash,
                                  nativeSourceCommitHash,
                              },
                              recoveryHarnessRepair: {
                                  changedFilePaths: validatorRepairFilePaths,
                                  harnessCommitHash: repositoryCommitHash,
                                  nativeSourceCommitHash:
                                      chainedRecoveryProfile.validatorRepairCommitHash,
                              },
                              validatorRepair: {
                                  changedFilePaths: validatorRepairFilePaths,
                                  harnessCommitHash:
                                      chainedRecoveryProfile.validatorRepairCommitHash,
                                  nativeSourceCommitHash:
                                      chainedRecoveryProfile.firstHarnessRepairCommitHash,
                              },
                          },
                          nativeEvidence,
                          preOperationRecovery: validatedRecovery,
                          rawWasmSha256Hex,
                      })
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
    const effectivePreOperationRecoveryProfile =
        options.preOperationRecoveryProfile ??
        proofStorageWidthBrowserPreOperationRecoveryProfile;
    const recoveryAuthorizationKeySha256Hex =
        validatedRecovery === undefined
            ? undefined
            : isThirdRecoveryEvidence
              ? buildBrowserThirdRecoveryAuthorizationKey({
                    chainedProfile: chainedRecoveryProfile,
                    preOperationProfile: effectivePreOperationRecoveryProfile,
                    thirdProfile: thirdRecoveryProfile,
                })
              : isChainedRecoveryEvidence
                ? buildBrowserChainedRecoveryAuthorizationKey({
                      chainedProfile: chainedRecoveryProfile,
                      preOperationProfile: effectivePreOperationRecoveryProfile,
                  })
                : buildBrowserRecoveryAuthorizationKey(
                      effectivePreOperationRecoveryProfile,
                  );
    const recoveryCustody = isThirdRecoveryEvidence
        ? thirdBrowserRecoveryCustody
        : isChainedRecoveryEvidence
          ? chainedBrowserRecoveryCustody
          : firstBrowserRecoveryCustody;
    const recoveryMarkerBinding = isThirdRecoveryEvidence
        ? buildThirdRecoveryMarkerBinding({
              chainedProfile: chainedRecoveryProfile,
              preOperationProfile: effectivePreOperationRecoveryProfile,
              thirdProfile: thirdRecoveryProfile,
          })
        : isChainedRecoveryEvidence
          ? buildChainedRecoveryMarkerBinding({
                chainedProfile: chainedRecoveryProfile,
                preOperationProfile: effectivePreOperationRecoveryProfile,
            })
          : buildFirstRecoveryMarkerBinding(
                effectivePreOperationRecoveryProfile,
            );
    const expectedRecoveryOperationReservationPath =
        recovery === undefined
            ? undefined
            : `${recoveryCustody.operationDirectoryName}/${recoveryAuthorizationKeySha256Hex ?? ''}/browser-recovery-started.json`;
    if (recovery !== undefined) {
        const staticPreflight = requireJsonObject(
            recovery.staticPreflight,
            'recovery.staticPreflight',
        );
        const preflightAttempt = requireJsonObject(
            staticPreflight.attempt,
            'recovery.staticPreflight.attempt',
        );
        const preflightAttemptRelativePath =
            recoveryCustody.schemaVersion === 'browser-recovery-3'
                ? `${recoveryCustody.preflightDirectoryName}/${recoveryAuthorizationKeySha256Hex ?? ''}/${thirdRecoveryAttemptDirectoryName}/${thirdRecoveryPublishedRecordFileName}`
                : `${recoveryCustody.preflightDirectoryName}/${recoveryAuthorizationKeySha256Hex ?? ''}/preflight-attempted.json`;
        requireExactRelativeArtifactPath({
            actual: preflightAttempt.path,
            expected: preflightAttemptRelativePath,
            fieldName: 'recovery.staticPreflight.attempt.path',
            rootPath: reservationRootPath,
        });
        await resolveExistingCustodyFile({
            fieldName: 'Browser recovery static preflight marker',
            relativePath: preflightAttemptRelativePath,
            rootPath: reservationRootPath,
        });
        const serializedPreflightAttempt =
            await readBrowserRecoveryMarkerSerialization({
                authorizationKeySha256Hex:
                    recoveryAuthorizationKeySha256Hex ?? '',
                custody: recoveryCustody,
                reservationRootPath,
            });
        const serializedPreflightAttemptRecords =
            parseCanonicalRecoveryJsonLines(
                serializedPreflightAttempt,
                'Browser recovery static preflight marker',
            );
        const serializedPreflightAttemptPrefix = literalRecoveryJsonLinesPrefix(
            serializedPreflightAttempt,
            2,
            'Browser recovery static preflight marker',
        );
        if (isChainedRecoveryEvidence) {
            if (
                preflightAttempt.prefixByteLength !==
                serializedPreflightAttemptPrefix.byteLength
            ) {
                throw new Error(
                    'The chained browser recovery static preflight marker prefix length changed.',
                );
            }
            requireArtifactDigest({
                expectedSha256Hex: preflightAttempt.prefixSha256Hex,
                fieldName:
                    'Chained browser recovery static preflight marker prefix',
                value: serializedPreflightAttemptPrefix,
            });
        } else {
            requireArtifactDigest({
                expectedSha256Hex: preflightAttempt.sha256Hex,
                fieldName: 'Browser recovery static preflight marker',
                value: serializedPreflightAttempt,
            });
        }
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
        if (
            isChainedRecoveryEvidence &&
            serializedPreflightAttemptRecords.length === 2 &&
            !options.allowProvisionalChainedRecoveryMarker
        ) {
            throw new Error(
                'The exported chained browser recovery closure requires its validated terminal marker.',
            );
        }
        const validatedPreflightAttempt =
            validateBrowserRecoveryPreflightAttempt({
                authorizationKeySha256Hex:
                    recoveryAuthorizationKeySha256Hex ?? '',
                identity:
                    recoveryReservationIdentity as RecoveryReservationIdentity,
                markerBinding: recoveryMarkerBinding,
                serialized: serializedPreflightAttempt,
                ...(isChainedRecoveryEvidence
                    ? {
                          terminalBinding: {
                              attachmentPath: custodyAttachmentPath,
                              attachmentSha256Hex,
                              decisionOutcome: decision.outcome,
                              markerPrefixByteLength:
                                  serializedPreflightAttemptPrefix.byteLength,
                              markerPrefixSha256Hex: sha256Hex(
                                  serializedPreflightAttemptPrefix,
                              ),
                              operationReservationPath:
                                  expectedRecoveryOperationReservationPath ??
                                  '',
                              operationReservationSha256Hex: requireSha256Hex(
                                  officialReservation.sha256Hex,
                                  'officialSampleReservation.sha256Hex',
                              ),
                          },
                      }
                    : {}),
                terminalOutcomeRequired:
                    !isChainedRecoveryEvidence ||
                    serializedPreflightAttemptRecords.length === 3,
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
            (recovery === undefined ? 1 : recoveryCustody.schemaVersion)
    ) {
        throw new Error(
            'The browser official reservation identity, owner, or schema changed.',
        );
    }
    const reservationRelativePath =
        recovery === undefined
            ? `browser/${officialReservationIdentitySha256Hex}/browser-started.json`
            : (expectedRecoveryOperationReservationPath ?? '');
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

export const validateProofStorageWidthBrowserEvidenceArtifacts = (
    attachmentPath: string,
    options: ProofStorageWidthBrowserArtifactValidationOptions = {},
): Promise<void> =>
    validateProofStorageWidthBrowserEvidenceArtifactsWithMarkerState(
        attachmentPath,
        {
            ...options,
            allowProvisionalChainedRecoveryMarker: false,
        },
    );

const validateProvisionalProofStorageWidthBrowserEvidenceArtifacts = (
    attachmentPath: string,
    options: ProofStorageWidthBrowserArtifactValidationOptions,
): Promise<void> =>
    validateProofStorageWidthBrowserEvidenceArtifactsWithMarkerState(
        attachmentPath,
        {
            ...options,
            allowProvisionalChainedRecoveryMarker: true,
        },
    );

type BrowserRecoveryAuthorizationPlan = Omit<
    BrowserRecoveryAuthorization,
    'preflightAttemptPath' | 'thirdRecoveryKeyDirectoryIdentity'
>;

const deriveBrowserRecoveryAuthorizationPlanIfSelected = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly failedChainedRecoveryAttemptRunDirectoryPath?: string;
    readonly failedRecoveryAttemptRunDirectoryPath?: string;
    readonly preOperationRecoveryRunDirectoryPath?: string;
}): Promise<BrowserRecoveryAuthorizationPlan | undefined> => {
    if (
        input.preOperationRecoveryRunDirectoryPath === undefined &&
        input.failedRecoveryAttemptRunDirectoryPath === undefined &&
        input.failedChainedRecoveryAttemptRunDirectoryPath === undefined
    ) {
        return undefined;
    }
    if (input.preOperationRecoveryRunDirectoryPath === undefined) {
        throw new Error(
            'A browser recovery cannot name the failed recovery attempt without its pre-operation predecessor.',
        );
    }
    const preOperationProfile =
        input.dependencies?.preOperationRecoveryProfile ??
        proofStorageWidthBrowserPreOperationRecoveryProfile;
    const isChainedRecovery =
        input.failedRecoveryAttemptRunDirectoryPath !== undefined;
    const isThirdRecovery =
        input.failedChainedRecoveryAttemptRunDirectoryPath !== undefined;
    if (isThirdRecovery && !isChainedRecovery) {
        throw new Error(
            'A third browser recovery cannot name the failed chained attempt without both earlier predecessors.',
        );
    }
    const chainedProfile = isChainedRecovery
        ? (input.dependencies?.chainedRecoveryProfile ??
          proofStorageWidthBrowserChainedRecoveryProfile)
        : undefined;
    const thirdProfile = isThirdRecovery
        ? (input.dependencies?.thirdRecoveryProfile ??
          proofStorageWidthBrowserThirdRecoveryProfile)
        : undefined;
    if (
        !path.isAbsolute(input.preOperationRecoveryRunDirectoryPath) ||
        path.resolve(input.preOperationRecoveryRunDirectoryPath) !==
            path.resolve(preOperationProfile.failedRunDirectoryPath) ||
        preOperationProfile.recoveryOrdinal !== recoveryOrdinal ||
        (isChainedRecovery &&
            (chainedProfile === undefined ||
                !path.isAbsolute(
                    input.failedRecoveryAttemptRunDirectoryPath ?? '',
                ) ||
                path.resolve(
                    input.failedRecoveryAttemptRunDirectoryPath ?? '',
                ) !==
                    path.resolve(
                        chainedProfile.failedRecoveryRunDirectoryPath,
                    ) ||
                chainedProfile.recoveryOrdinal !== chainedRecoveryOrdinal)) ||
        (isThirdRecovery &&
            (thirdProfile === undefined ||
                !path.isAbsolute(
                    input.failedChainedRecoveryAttemptRunDirectoryPath ?? '',
                ) ||
                path.resolve(
                    input.failedChainedRecoveryAttemptRunDirectoryPath ?? '',
                ) !==
                    path.resolve(
                        thirdProfile.failedChainedRecoveryRunDirectoryPath,
                    ) ||
                thirdProfile.recoveryOrdinal !== thirdRecoveryOrdinal ||
                thirdProfile.issuanceCommitHash !==
                    thirdRecoveryIssuanceCommitHash))
    ) {
        throw new Error(
            isThirdRecovery
                ? 'The third recovery paths are not the exact authorized failed runs.'
                : isChainedRecovery
                  ? 'The chained recovery paths are not the exact authorized failed runs.'
                  : 'The pre-operation recovery path is not the exact authorized failed run.',
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
        thirdProfile !== undefined && chainedProfile !== undefined
            ? buildBrowserThirdRecoveryAuthorizationKey({
                  chainedProfile,
                  preOperationProfile,
                  thirdProfile,
              })
            : chainedProfile === undefined
              ? buildBrowserRecoveryAuthorizationKey(preOperationProfile)
              : buildBrowserChainedRecoveryAuthorizationKey({
                    chainedProfile,
                    preOperationProfile,
                });
    if (
        (chainedProfile !== undefined &&
            authorizationKeySha256Hex ===
                chainedProfile.previousAuthorizationKeySha256Hex) ||
        (thirdProfile !== undefined &&
            authorizationKeySha256Hex ===
                thirdProfile.previousChainedAuthorizationKeySha256Hex)
    ) {
        throw new Error(
            'The browser recovery derived a consumed authorization key.',
        );
    }
    const markerBinding =
        thirdProfile !== undefined && chainedProfile !== undefined
            ? buildThirdRecoveryMarkerBinding({
                  chainedProfile,
                  preOperationProfile,
                  thirdProfile,
              })
            : chainedProfile === undefined
              ? buildFirstRecoveryMarkerBinding(preOperationProfile)
              : buildChainedRecoveryMarkerBinding({
                    chainedProfile,
                    preOperationProfile,
                });
    const custody =
        thirdProfile !== undefined
            ? thirdBrowserRecoveryCustody
            : chainedProfile === undefined
              ? firstBrowserRecoveryCustody
              : chainedBrowserRecoveryCustody;
    return Object.freeze({
        authorizationKeySha256Hex,
        ...(chainedProfile === undefined ? {} : { chainedProfile }),
        custody,
        ...(input.dependencies?.browserRecoveryMarkerFaultInjection ===
        undefined
            ? {}
            : {
                  faultInjection:
                      input.dependencies.browserRecoveryMarkerFaultInjection,
              }),
        markerBinding,
        preOperationProfile,
        recoveryOrdinal:
            thirdProfile !== undefined
                ? thirdRecoveryOrdinal
                : chainedProfile === undefined
                  ? recoveryOrdinal
                  : chainedRecoveryOrdinal,
        reservationRootPath,
        ...(thirdProfile === undefined ? {} : { thirdProfile }),
    });
};

const createBrowserRecoveryAuthorizationIfSelected = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly failedChainedRecoveryAttemptRunDirectoryPath?: string;
    readonly failedRecoveryAttemptRunDirectoryPath?: string;
    readonly preOperationRecoveryRunDirectoryPath?: string;
}): Promise<BrowserRecoveryAuthorization | undefined> => {
    const plan = await deriveBrowserRecoveryAuthorizationPlanIfSelected(input);
    if (plan === undefined) {
        return undefined;
    }
    const preflightAcquisition = await createBrowserRecoveryPreflightAttempt({
        authorizationKeySha256Hex: plan.authorizationKeySha256Hex,
        custody: plan.custody,
        ...(plan.faultInjection === undefined
            ? {}
            : { faultInjection: plan.faultInjection }),
        markerBinding: plan.markerBinding,
        reservationRootPath: plan.reservationRootPath,
    });
    return Object.freeze({
        ...plan,
        preflightAttemptPath: preflightAcquisition.attemptPath,
        ...(preflightAcquisition.thirdRecoveryKeyDirectoryIdentity === undefined
            ? {}
            : {
                  thirdRecoveryKeyDirectoryIdentity:
                      preflightAcquisition.thirdRecoveryKeyDirectoryIdentity,
              }),
    });
};

const readOnlyRecoveryDryRunLog = Object.freeze({
    createCommandLogFiles: () => {
        throw new Error(
            'The recovery-chain dry-run cannot create command log files.',
        );
    },
    finish: () => Promise.resolve(),
    runDirectoryPath: path.resolve('.'),
    writeCombinedOutput: () => undefined,
    writeCommandOutput: () => undefined,
    writeEvent: () => undefined,
} satisfies ActiveLocalRunLog);

const isPermittedRecoveryDryRunGitInvocation = (
    invocation: CommandInvocation,
): boolean => {
    if (invocation.command !== 'git') {
        return false;
    }
    if (
        normalizedJsonEquals(invocation.args, [
            'rev-parse',
            '--verify',
            'HEAD^{commit}',
        ]) ||
        normalizedJsonEquals(invocation.args, [
            'status',
            '--porcelain=v1',
            '--untracked-files=all',
            '--ignore-submodules=none',
        ])
    ) {
        return true;
    }
    if (
        invocation.args.length === 4 &&
        invocation.args[0] === '--no-replace-objects' &&
        invocation.args[1] === 'cat-file' &&
        invocation.args[2] === 'commit'
    ) {
        return exactCommitHashPattern.test(invocation.args[3] ?? '');
    }
    if (
        invocation.args.length !== 8 ||
        !normalizedJsonEquals(invocation.args.slice(0, 5), [
            '--no-replace-objects',
            'diff',
            '--name-status',
            '-z',
            '--no-renames',
        ]) ||
        invocation.args[7] !== '--'
    ) {
        return false;
    }
    const treePattern = /^[0-9a-f]{40}\^\{tree\}$/u;
    return (
        treePattern.test(invocation.args[5] ?? '') &&
        treePattern.test(invocation.args[6] ?? '')
    );
};

const executeRecoveryDryRunGitCommand: CommandExecutor = (
    invocation,
): Promise<CapturedCommandResult> => {
    if (!isPermittedRecoveryDryRunGitInvocation(invocation)) {
        return Promise.reject(
            new Error(
                'The recovery-chain dry-run attempted a command outside its read-only Git allowlist.',
            ),
        );
    }
    return new Promise((resolve, reject) => {
        const child = spawn(invocation.command, [...invocation.args], {
            cwd: invocation.workingDirectoryPath,
            env: {
                ...process.env,
                ...(invocation.env ?? {}),
                GIT_NO_REPLACE_OBJECTS: '1',
                GIT_OPTIONAL_LOCKS: '0',
            },
            shell: false,
            windowsHide: true,
        });
        const stdoutChunks: Buffer[] = [];
        const stderrChunks: Buffer[] = [];
        child.stdout.on('data', (chunk: Buffer | string) => {
            stdoutChunks.push(Buffer.from(chunk));
        });
        child.stderr.on('data', (chunk: Buffer | string) => {
            stderrChunks.push(Buffer.from(chunk));
        });
        child.once('error', reject);
        child.once('close', (exitCode, terminationSignal) => {
            resolve({
                exitCode: exitCode ?? 1,
                stderr: Buffer.concat(stderrChunks).toString('utf8'),
                stdout: Buffer.concat(stdoutChunks).toString('utf8'),
                terminationSignal,
            });
        });
    });
};

export type ProofStorageWidthBrowserRecoveryChainDryRunResult = Readonly<{
    authorizationKeySha256Hex: string;
    finalHarnessCommitHash: string;
    markerRelativePath: string;
    operationReservationRelativePath: string;
    recoveryOrdinal: 3;
    reservationIdentitySha256Hex: string;
}>;

export const dryRunProofStorageWidthBrowserRecoveryChain = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly failedChainedRecoveryAttemptRunDirectoryPath: string;
    readonly failedRecoveryAttemptRunDirectoryPath: string;
    readonly nativeEvidencePath: string;
    readonly preOperationRecoveryRunDirectoryPath: string;
}): Promise<ProofStorageWidthBrowserRecoveryChainDryRunResult> => {
    const plan = await deriveBrowserRecoveryAuthorizationPlanIfSelected({
        dependencies: input.dependencies,
        failedChainedRecoveryAttemptRunDirectoryPath:
            input.failedChainedRecoveryAttemptRunDirectoryPath,
        failedRecoveryAttemptRunDirectoryPath:
            input.failedRecoveryAttemptRunDirectoryPath,
        preOperationRecoveryRunDirectoryPath:
            input.preOperationRecoveryRunDirectoryPath,
    });
    if (
        plan === undefined ||
        plan.recoveryOrdinal !== thirdRecoveryOrdinal ||
        plan.chainedProfile === undefined ||
        plan.thirdProfile === undefined
    ) {
        throw new Error(
            'The recovery-chain dry-run requires the exact ordinal-three predecessor set.',
        );
    }
    const keyDirectoryRelativePath = path.join(
        plan.custody.preflightDirectoryName,
        plan.authorizationKeySha256Hex,
    );
    const markerRelativePath = path.join(
        keyDirectoryRelativePath,
        thirdRecoveryAttemptDirectoryName,
        thirdRecoveryPublishedRecordFileName,
    );
    const operationReservationRelativePath = path.join(
        plan.custody.operationDirectoryName,
        plan.authorizationKeySha256Hex,
        'browser-recovery-started.json',
    );
    await Promise.all([
        requireCustodyPathAbsent({
            fieldName: 'Third browser recovery singleton key directory',
            relativePath: keyDirectoryRelativePath,
            rootPath: plan.reservationRootPath,
        }),
        requireCustodyPathAbsent({
            fieldName: 'Third browser recovery measured-operation reservation',
            relativePath: operationReservationRelativePath,
            rootPath: plan.reservationRootPath,
        }),
    ]);
    const configuredExecuteCommand =
        input.dependencies?.executeCommand ?? executeRecoveryDryRunGitCommand;
    const executeCommand: CommandExecutor = (invocation, runLog) => {
        if (!isPermittedRecoveryDryRunGitInvocation(invocation)) {
            return Promise.reject(
                new Error(
                    'The recovery-chain dry-run attempted a command outside its read-only Git allowlist.',
                ),
            );
        }
        return configuredExecuteCommand(
            {
                ...invocation,
                env: {
                    ...(invocation.env ?? {}),
                    GIT_NO_REPLACE_OBJECTS: '1',
                    GIT_OPTIONAL_LOCKS: '0',
                },
            },
            runLog,
        );
    };
    const readRepositoryState = (
        checkpoint: RepositoryCheckpoint,
        runLog: ActiveLocalRunLog,
    ): Promise<RepositoryState> =>
        readRepositoryStateWithCommands({
            checkpoint,
            executeCommand,
            runLog,
        });
    const canonicalNativeEvidencePath =
        await resolveCanonicalAbsoluteCustodyFile(
            input.nativeEvidencePath,
            'Native width-evidence aggregate',
        );
    const nativeEvidence = await (
        input.dependencies?.loadNativeWidthEvidence ?? loadNativeWidthEvidence
    )(canonicalNativeEvidencePath, {
        officialReservationRootPath: plan.reservationRootPath,
    });
    const preOperationRecovery =
        await validateProofStorageWidthBrowserPreOperationRecovery({
            failedRunDirectoryPath: input.preOperationRecoveryRunDirectoryPath,
            nativeEvidence,
            officialReservationRootPath: plan.reservationRootPath,
            profile: plan.preOperationProfile,
        });
    const failedRecoveryAttempt =
        await validateProofStorageWidthBrowserFailedRecoveryAttempt({
            failedRecoveryRunDirectoryPath:
                input.failedRecoveryAttemptRunDirectoryPath,
            nativeEvidence,
            officialReservationRootPath: plan.reservationRootPath,
            preOperationRecovery,
            preOperationProfile: plan.preOperationProfile,
            profile: plan.chainedProfile,
        });
    const failedChainedRecoveryAttempt =
        await validateProofStorageWidthBrowserFailedChainedRecoveryAttempt({
            chainedProfile: plan.chainedProfile,
            failedChainedRecoveryRunDirectoryPath:
                input.failedChainedRecoveryAttemptRunDirectoryPath,
            failedRecoveryAttempt,
            nativeEvidence,
            officialReservationRootPath: plan.reservationRootPath,
            preOperationProfile: plan.preOperationProfile,
            preOperationRecovery,
            profile: plan.thirdProfile,
        });
    const initialRepositoryState = await readRepositoryState(
        'initial',
        readOnlyRecoveryDryRunLog,
    );
    if (
        initialRepositoryState.treeDirty ||
        !exactCommitHashPattern.test(initialRepositoryState.commitHash)
    ) {
        throw new Error(
            'The recovery-chain dry-run requires one exact clean final harness commit.',
        );
    }
    const harnessTransition = await validateThirdHarnessRepairCommitTransition({
        chainedProfile: plan.chainedProfile,
        executeCommand,
        finalHarnessCommitHash: initialRepositoryState.commitHash,
        nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
        runLog: readOnlyRecoveryDryRunLog,
        thirdProfile: plan.thirdProfile,
    });
    const reservationIdentity = buildBrowserThirdRecoveryReservationIdentity({
        failedChainedRecoveryAttempt,
        failedRecoveryAttempt,
        harnessTransition,
        nativeEvidence,
        preOperationRecovery,
        rawWasmSha256Hex: plan.preOperationProfile.rawWasmSha256Hex,
    });
    const reopenedPreOperationRecovery =
        await validateProofStorageWidthBrowserPreOperationRecovery({
            failedRunDirectoryPath: input.preOperationRecoveryRunDirectoryPath,
            nativeEvidence,
            officialReservationRootPath: plan.reservationRootPath,
            profile: plan.preOperationProfile,
        });
    const reopenedFailedRecoveryAttempt =
        await validateProofStorageWidthBrowserFailedRecoveryAttempt({
            failedRecoveryRunDirectoryPath:
                input.failedRecoveryAttemptRunDirectoryPath,
            nativeEvidence,
            officialReservationRootPath: plan.reservationRootPath,
            preOperationRecovery: reopenedPreOperationRecovery,
            preOperationProfile: plan.preOperationProfile,
            profile: plan.chainedProfile,
        });
    const reopenedFailedChainedRecoveryAttempt =
        await validateProofStorageWidthBrowserFailedChainedRecoveryAttempt({
            chainedProfile: plan.chainedProfile,
            failedChainedRecoveryRunDirectoryPath:
                input.failedChainedRecoveryAttemptRunDirectoryPath,
            failedRecoveryAttempt: reopenedFailedRecoveryAttempt,
            nativeEvidence,
            officialReservationRootPath: plan.reservationRootPath,
            preOperationProfile: plan.preOperationProfile,
            preOperationRecovery: reopenedPreOperationRecovery,
            profile: plan.thirdProfile,
        });
    if (
        !normalizedJsonEquals(
            reopenedPreOperationRecovery,
            preOperationRecovery,
        ) ||
        !normalizedJsonEquals(
            reopenedFailedRecoveryAttempt,
            failedRecoveryAttempt,
        ) ||
        !normalizedJsonEquals(
            reopenedFailedChainedRecoveryAttempt,
            failedChainedRecoveryAttempt,
        )
    ) {
        throw new Error(
            'The recovery-chain dry-run predecessors changed while being reopened.',
        );
    }
    const closureRepositoryState = await readRepositoryState(
        'closure-after',
        readOnlyRecoveryDryRunLog,
    );
    requireCleanPinnedRepository(
        closureRepositoryState,
        initialRepositoryState.commitHash,
        'recovery-chain dry-run closure',
    );
    await validateThirdHarnessRepairCommitTransition({
        chainedProfile: plan.chainedProfile,
        executeCommand,
        finalHarnessCommitHash: initialRepositoryState.commitHash,
        nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
        runLog: readOnlyRecoveryDryRunLog,
        thirdProfile: plan.thirdProfile,
    });
    await Promise.all([
        requireCustodyPathAbsent({
            fieldName: 'Third browser recovery singleton key directory',
            relativePath: keyDirectoryRelativePath,
            rootPath: plan.reservationRootPath,
        }),
        requireCustodyPathAbsent({
            fieldName: 'Third browser recovery measured-operation reservation',
            relativePath: operationReservationRelativePath,
            rootPath: plan.reservationRootPath,
        }),
    ]);
    return Object.freeze({
        authorizationKeySha256Hex: plan.authorizationKeySha256Hex,
        finalHarnessCommitHash: initialRepositoryState.commitHash,
        markerRelativePath: canonicalRelativePath(
            plan.reservationRootPath,
            path.resolve(plan.reservationRootPath, markerRelativePath),
        ),
        operationReservationRelativePath: canonicalRelativePath(
            plan.reservationRootPath,
            path.resolve(
                plan.reservationRootPath,
                operationReservationRelativePath,
            ),
        ),
        recoveryOrdinal: thirdRecoveryOrdinal,
        reservationIdentitySha256Hex: reservationIdentity.identitySha256Hex,
    });
};

const executeProofStorageWidthBrowserEvidenceAttempt = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly failedChainedRecoveryAttemptRunDirectoryPath?: string;
    readonly failedRecoveryAttemptRunDirectoryPath?: string;
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
    const preOperationRecoveryProfile =
        input.recoveryAuthorization?.preOperationProfile ??
        input.dependencies?.preOperationRecoveryProfile ??
        proofStorageWidthBrowserPreOperationRecoveryProfile;
    const chainedRecoveryProfile =
        input.recoveryAuthorization?.chainedProfile ??
        input.dependencies?.chainedRecoveryProfile ??
        proofStorageWidthBrowserChainedRecoveryProfile;
    const thirdRecoveryProfile =
        input.recoveryAuthorization?.thirdProfile ??
        input.dependencies?.thirdRecoveryProfile ??
        proofStorageWidthBrowserThirdRecoveryProfile;
    const isChainedRecovery =
        input.failedRecoveryAttemptRunDirectoryPath !== undefined;
    const isThirdRecovery =
        input.failedChainedRecoveryAttemptRunDirectoryPath !== undefined;
    const selectedRecoveryOrdinal = isThirdRecovery
        ? thirdRecoveryOrdinal
        : isChainedRecovery
          ? chainedRecoveryOrdinal
          : recoveryOrdinal;
    if (
        (input.preOperationRecoveryRunDirectoryPath === undefined) !==
            (input.recoveryAuthorization === undefined) ||
        (input.recoveryAuthorization !== undefined &&
            input.recoveryAuthorization.recoveryOrdinal !==
                selectedRecoveryOrdinal)
    ) {
        throw new Error(
            'The browser recovery did not carry the singleton authorization for its exact predecessor set.',
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
                  profile: preOperationRecoveryProfile,
              });
    const failedRecoveryAttempt =
        input.failedRecoveryAttemptRunDirectoryPath === undefined ||
        preOperationRecovery === undefined
            ? undefined
            : await validateProofStorageWidthBrowserFailedRecoveryAttempt({
                  failedRecoveryRunDirectoryPath:
                      input.failedRecoveryAttemptRunDirectoryPath,
                  nativeEvidence,
                  officialReservationRootPath,
                  preOperationRecovery,
                  preOperationProfile: preOperationRecoveryProfile,
                  profile: chainedRecoveryProfile,
              });
    const failedChainedRecoveryAttempt =
        input.failedChainedRecoveryAttemptRunDirectoryPath === undefined ||
        preOperationRecovery === undefined ||
        failedRecoveryAttempt === undefined
            ? undefined
            : await validateProofStorageWidthBrowserFailedChainedRecoveryAttempt(
                  {
                      chainedProfile: chainedRecoveryProfile,
                      failedChainedRecoveryRunDirectoryPath:
                          input.failedChainedRecoveryAttemptRunDirectoryPath,
                      failedRecoveryAttempt,
                      nativeEvidence,
                      officialReservationRootPath,
                      preOperationProfile: preOperationRecoveryProfile,
                      preOperationRecovery,
                      profile: thirdRecoveryProfile,
                  },
              );
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
    const firstHarnessTransition =
        preOperationRecovery === undefined
            ? undefined
            : isChainedRecovery || isThirdRecovery
              ? undefined
              : await validateHarnessRepairCommitTransition({
                    executeCommand,
                    harnessCommitHash: expectedHarnessCommitHash,
                    nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
                    runLog: input.runLog,
                });
    const chainedHarnessTransition =
        preOperationRecovery === undefined ||
        !isChainedRecovery ||
        isThirdRecovery
            ? undefined
            : await validateChainedHarnessRepairCommitTransition({
                  executeCommand,
                  nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
                  profile: chainedRecoveryProfile,
                  recoveryHarnessCommitHash: expectedHarnessCommitHash,
                  runLog: input.runLog,
              });
    const thirdHarnessTransition =
        preOperationRecovery === undefined || !isThirdRecovery
            ? undefined
            : await validateThirdHarnessRepairCommitTransition({
                  chainedProfile: chainedRecoveryProfile,
                  executeCommand,
                  finalHarnessCommitHash: expectedHarnessCommitHash,
                  nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
                  runLog: input.runLog,
                  thirdProfile: thirdRecoveryProfile,
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
        wasmBinding.rawSha256Hex !==
            preOperationRecoveryProfile.rawWasmSha256Hex
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
    if (
        preOperationRecovery !== undefined &&
        firstHarnessTransition === undefined &&
        chainedHarnessTransition === undefined &&
        thirdHarnessTransition === undefined
    ) {
        throw new Error(
            'The browser recovery omitted its validated commit transition.',
        );
    }
    const recoveryReservationIdentity =
        preOperationRecovery === undefined
            ? undefined
            : isThirdRecovery
              ? failedRecoveryAttempt === undefined ||
                failedChainedRecoveryAttempt === undefined ||
                thirdHarnessTransition === undefined
                  ? undefined
                  : buildBrowserThirdRecoveryReservationIdentity({
                        failedChainedRecoveryAttempt,
                        failedRecoveryAttempt,
                        harnessTransition: thirdHarnessTransition,
                        nativeEvidence,
                        preOperationRecovery,
                        rawWasmSha256Hex: wasmBinding.rawSha256Hex,
                    })
              : isChainedRecovery
                ? failedRecoveryAttempt === undefined ||
                  chainedHarnessTransition === undefined
                    ? undefined
                    : buildBrowserChainedRecoveryReservationIdentity({
                          failedRecoveryAttempt,
                          harnessTransition: chainedHarnessTransition,
                          nativeEvidence,
                          preOperationRecovery,
                          rawWasmSha256Hex: wasmBinding.rawSha256Hex,
                      })
                : firstHarnessTransition === undefined
                  ? undefined
                  : buildBrowserRecoveryReservationIdentity({
                        harnessTransition: firstHarnessTransition,
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
        preOperationRecovery !== undefined &&
        recoveryReservationIdentity === undefined
    ) {
        throw new Error(
            'The browser recovery omitted its exact predecessor or commit-transition identity; ordinary reservation fallback is prohibited.',
        );
    }
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
            custody:
                input.recoveryAuthorization?.custody ??
                (isThirdRecovery
                    ? thirdBrowserRecoveryCustody
                    : isChainedRecovery
                      ? chainedBrowserRecoveryCustody
                      : firstBrowserRecoveryCustody),
            ...(input.dependencies?.browserRecoveryMarkerFaultInjection ===
            undefined
                ? {}
                : {
                      faultInjection:
                          input.dependencies
                              .browserRecoveryMarkerFaultInjection,
                  }),
            identity: recoveryReservationIdentity,
            reservationPath: recoveryPreflightAttemptPath,
            reservationRootPath: officialReservationRootPath,
            result: staticPreflightResult,
            ...(input.recoveryAuthorization
                ?.thirdRecoveryKeyDirectoryIdentity === undefined
                ? {}
                : {
                      thirdRecoveryKeyDirectoryIdentity:
                          input.recoveryAuthorization
                              .thirdRecoveryKeyDirectoryIdentity,
                  }),
        });
        serializedRecoveryPreflightAttempt =
            await readBrowserRecoveryMarkerSerialization({
                authorizationKeySha256Hex:
                    recoveryAuthorizationKeySha256Hex ?? '',
                custody:
                    input.recoveryAuthorization?.custody ??
                    (isThirdRecovery
                        ? thirdBrowserRecoveryCustody
                        : isChainedRecovery
                          ? chainedBrowserRecoveryCustody
                          : firstBrowserRecoveryCustody),
                reservationRootPath: officialReservationRootPath,
                ...(input.recoveryAuthorization
                    ?.thirdRecoveryKeyDirectoryIdentity === undefined
                    ? {}
                    : {
                          thirdRecoveryKeyDirectoryIdentity:
                              input.recoveryAuthorization
                                  .thirdRecoveryKeyDirectoryIdentity,
                      }),
            });
        validateBrowserRecoveryPreflightAttempt({
            authorizationKeySha256Hex: recoveryAuthorizationKeySha256Hex ?? '',
            identity: recoveryReservationIdentity,
            markerBinding:
                input.recoveryAuthorization?.markerBinding ??
                (isThirdRecovery
                    ? buildThirdRecoveryMarkerBinding({
                          chainedProfile: chainedRecoveryProfile,
                          preOperationProfile: preOperationRecoveryProfile,
                          thirdProfile: thirdRecoveryProfile,
                      })
                    : isChainedRecovery
                      ? buildChainedRecoveryMarkerBinding({
                            chainedProfile: chainedRecoveryProfile,
                            preOperationProfile: preOperationRecoveryProfile,
                        })
                      : buildFirstRecoveryMarkerBinding(
                            preOperationRecoveryProfile,
                        )),
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
    if (firstHarnessTransition !== undefined) {
        await validateHarnessRepairCommitTransition({
            executeCommand,
            harnessCommitHash: firstHarnessTransition.harnessCommitHash,
            nativeSourceCommitHash:
                firstHarnessTransition.nativeSourceCommitHash,
            runLog: input.runLog,
        });
    }
    if (chainedHarnessTransition !== undefined) {
        await validateChainedHarnessRepairCommitTransition({
            executeCommand,
            nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
            profile: chainedRecoveryProfile,
            recoveryHarnessCommitHash: expectedHarnessCommitHash,
            runLog: input.runLog,
        });
    }
    if (thirdHarnessTransition !== undefined) {
        await validateThirdHarnessRepairCommitTransition({
            chainedProfile: chainedRecoveryProfile,
            executeCommand,
            finalHarnessCommitHash: expectedHarnessCommitHash,
            nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
            runLog: input.runLog,
            thirdProfile: thirdRecoveryProfile,
        });
    }
    if (
        isChainedRecovery &&
        preOperationRecovery !== undefined &&
        failedRecoveryAttempt !== undefined &&
        input.preOperationRecoveryRunDirectoryPath !== undefined &&
        input.failedRecoveryAttemptRunDirectoryPath !== undefined
    ) {
        const reopenedPreOperationRecovery =
            await validateProofStorageWidthBrowserPreOperationRecovery({
                failedRunDirectoryPath:
                    input.preOperationRecoveryRunDirectoryPath,
                nativeEvidence,
                officialReservationRootPath,
                profile: preOperationRecoveryProfile,
            });
        const reopenedFailedRecoveryAttempt =
            await validateProofStorageWidthBrowserFailedRecoveryAttempt({
                failedRecoveryRunDirectoryPath:
                    input.failedRecoveryAttemptRunDirectoryPath,
                nativeEvidence,
                officialReservationRootPath,
                preOperationRecovery: reopenedPreOperationRecovery,
                preOperationProfile: preOperationRecoveryProfile,
                profile: chainedRecoveryProfile,
            });
        const reopenedFailedChainedRecoveryAttempt =
            input.failedChainedRecoveryAttemptRunDirectoryPath === undefined
                ? undefined
                : await validateProofStorageWidthBrowserFailedChainedRecoveryAttempt(
                      {
                          chainedProfile: chainedRecoveryProfile,
                          failedChainedRecoveryRunDirectoryPath:
                              input.failedChainedRecoveryAttemptRunDirectoryPath,
                          failedRecoveryAttempt: reopenedFailedRecoveryAttempt,
                          nativeEvidence,
                          officialReservationRootPath,
                          preOperationProfile: preOperationRecoveryProfile,
                          preOperationRecovery: reopenedPreOperationRecovery,
                          profile: thirdRecoveryProfile,
                      },
                  );
        if (
            !normalizedJsonEquals(
                reopenedPreOperationRecovery,
                preOperationRecovery,
            ) ||
            !normalizedJsonEquals(
                reopenedFailedRecoveryAttempt,
                failedRecoveryAttempt,
            ) ||
            (isThirdRecovery &&
                !normalizedJsonEquals(
                    reopenedFailedChainedRecoveryAttempt,
                    failedChainedRecoveryAttempt,
                ))
        ) {
            throw new Error(
                'The chained recovery predecessors changed before operation reservation.',
            );
        }
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
                  custody:
                      input.recoveryAuthorization?.custody ??
                      (isThirdRecovery
                          ? thirdBrowserRecoveryCustody
                          : isChainedRecovery
                            ? chainedBrowserRecoveryCustody
                            : firstBrowserRecoveryCustody),
                  identity: recoveryReservationIdentity,
                  reservationRootPath: officialReservationRootPath,
                  runDirectoryPath: input.runLog.runDirectoryPath,
              });
    let attemptError: unknown;
    try {
        if (
            !isChainedRecovery &&
            recoveryPreflightAttemptPath !== undefined &&
            recoveryReservationIdentity !== undefined
        ) {
            await appendProofStorageWidthOfficialReservationOutcome({
                outcome: 'validated',
                reservationPath: recoveryPreflightAttemptPath,
            });
            serializedRecoveryPreflightAttempt =
                await readBrowserRecoveryMarkerSerialization({
                    authorizationKeySha256Hex:
                        recoveryAuthorizationKeySha256Hex ?? '',
                    custody: firstBrowserRecoveryCustody,
                    reservationRootPath: officialReservationRootPath,
                });
            validateBrowserRecoveryPreflightAttempt({
                authorizationKeySha256Hex:
                    recoveryAuthorizationKeySha256Hex ?? '',
                identity: recoveryReservationIdentity,
                markerBinding: buildFirstRecoveryMarkerBinding(
                    preOperationRecoveryProfile,
                ),
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
                    input.recoveryAuthorization?.custody
                        .operationDirectoryName ??
                        (isThirdRecovery
                            ? thirdRecoveryOperationDirectoryName
                            : isChainedRecovery
                              ? chainedRecoveryOperationDirectoryName
                              : firstBrowserRecoveryCustody.operationDirectoryName),
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
        formatVersion:
            preOperationRecovery === undefined
                ? 4
                : isThirdRecovery
                  ? 7
                  : isChainedRecovery
                    ? 6
                    : 5,
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
                    : (input.recoveryAuthorization?.custody.schemaVersion ??
                      firstBrowserRecoveryCustody.schemaVersion),
            sha256Hex: sha256Hex(serializedReservation),
        },
        projection,
        ...(preOperationRecovery === undefined
            ? {}
            : isThirdRecovery
              ? failedRecoveryAttempt === undefined ||
                failedChainedRecoveryAttempt === undefined ||
                thirdHarnessTransition === undefined
                  ? {}
                  : {
                        recovery: {
                            failedArtifacts:
                                preOperationRecovery.failedArtifacts,
                            failedChainedRecoveryArtifacts:
                                failedChainedRecoveryAttempt.failedArtifacts,
                            failedChainedRecoveryRunDirectoryPath:
                                failedChainedRecoveryAttempt.failedRunDirectoryPath,
                            failedRecoveryArtifacts:
                                failedRecoveryAttempt.failedArtifacts,
                            failedRecoveryRunDirectoryPath:
                                failedRecoveryAttempt.failedRunDirectoryPath,
                            failedReservation:
                                preOperationRecovery.failedReservation,
                            failedRunDirectoryPath:
                                preOperationRecovery.failedRunDirectoryPath,
                            firstHarnessRepair:
                                thirdHarnessTransition.chainedRecoveryHarness
                                    .firstHarnessRepair,
                            issuanceCommitHash:
                                thirdRecoveryProfile.issuanceCommitHash,
                            nativeSourceCommitHash:
                                thirdHarnessTransition.chainedRecoveryHarness
                                    .firstHarnessRepair.nativeSourceCommitHash,
                            previousChainedPreflightAttempt:
                                failedChainedRecoveryAttempt.previousChainedPreflightAttempt,
                            previousPreflightAttempt:
                                failedRecoveryAttempt.previousPreflightAttempt,
                            recoveryHarnessRepair:
                                thirdHarnessTransition.chainedRecoveryHarness
                                    .recoveryHarnessRepair,
                            recoveryOrdinal: thirdRecoveryOrdinal,
                            staticPreflight: {
                                attempt:
                                    recoveryPreflightAttemptPath ===
                                        undefined ||
                                    serializedRecoveryPreflightAttempt ===
                                        undefined
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
                                              prefixByteLength:
                                                  Buffer.byteLength(
                                                      serializedRecoveryPreflightAttempt,
                                                      'utf8',
                                                  ),
                                              prefixSha256Hex: sha256Hex(
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
                            thirdRecoveryHarness:
                                thirdHarnessTransition.thirdRecoveryHarness,
                            validatorRepair:
                                thirdHarnessTransition.chainedRecoveryHarness
                                    .validatorRepair,
                        },
                    }
              : isChainedRecovery
                ? failedRecoveryAttempt === undefined ||
                  chainedHarnessTransition === undefined
                    ? {}
                    : {
                          recovery: {
                              failedArtifacts:
                                  preOperationRecovery.failedArtifacts,
                              failedRecoveryArtifacts:
                                  failedRecoveryAttempt.failedArtifacts,
                              failedRecoveryRunDirectoryPath:
                                  failedRecoveryAttempt.failedRunDirectoryPath,
                              failedReservation:
                                  preOperationRecovery.failedReservation,
                              failedRunDirectoryPath:
                                  preOperationRecovery.failedRunDirectoryPath,
                              firstHarnessRepair:
                                  chainedHarnessTransition.firstHarnessRepair,
                              nativeSourceCommitHash:
                                  chainedHarnessTransition.firstHarnessRepair
                                      .nativeSourceCommitHash,
                              previousPreflightAttempt:
                                  failedRecoveryAttempt.previousPreflightAttempt,
                              recoveryHarnessRepair:
                                  chainedHarnessTransition.recoveryHarnessRepair,
                              recoveryOrdinal: chainedRecoveryOrdinal,
                              staticPreflight: {
                                  attempt:
                                      recoveryPreflightAttemptPath ===
                                          undefined ||
                                      serializedRecoveryPreflightAttempt ===
                                          undefined
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
                                                prefixByteLength:
                                                    Buffer.byteLength(
                                                        serializedRecoveryPreflightAttempt,
                                                        'utf8',
                                                    ),
                                                prefixSha256Hex: sha256Hex(
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
                              validatorRepair:
                                  chainedHarnessTransition.validatorRepair,
                          },
                      }
                : firstHarnessTransition === undefined
                  ? {}
                  : {
                        recovery: {
                            changedFilePaths:
                                firstHarnessTransition.changedFilePaths,
                            failedArtifacts:
                                preOperationRecovery.failedArtifacts,
                            failedReservation:
                                preOperationRecovery.failedReservation,
                            failedRunDirectoryPath:
                                preOperationRecovery.failedRunDirectoryPath,
                            harnessCommitHash:
                                firstHarnessTransition.harnessCommitHash,
                            nativeSourceCommitHash:
                                firstHarnessTransition.nativeSourceCommitHash,
                            recoveryOrdinal,
                            staticPreflight: {
                                attempt:
                                    recoveryPreflightAttemptPath ===
                                        undefined ||
                                    serializedRecoveryPreflightAttempt ===
                                        undefined
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
    const artifactValidationOptions = {
        loadNativeWidthEvidence: loadNativeEvidence,
        officialReservationRootPath,
        chainedRecoveryProfile: input.dependencies?.chainedRecoveryProfile,
        preOperationRecoveryProfile:
            input.dependencies?.preOperationRecoveryProfile,
        processedWasmKernelPath: evidenceProcessedWasmKernelPath,
        publicSdkWasmKernelPath: evidencePublicSdkWasmKernelPath,
        thirdRecoveryProfile: input.dependencies?.thirdRecoveryProfile,
    } satisfies ProofStorageWidthBrowserArtifactValidationOptions;
    await validateProvisionalProofStorageWidthBrowserEvidenceArtifacts(
        attachmentPath,
        artifactValidationOptions,
    );
    if (firstHarnessTransition !== undefined) {
        await validateHarnessRepairCommitTransition({
            executeCommand,
            harnessCommitHash: firstHarnessTransition.harnessCommitHash,
            nativeSourceCommitHash:
                firstHarnessTransition.nativeSourceCommitHash,
            runLog: input.runLog,
        });
    }
    if (chainedHarnessTransition !== undefined) {
        await validateChainedHarnessRepairCommitTransition({
            executeCommand,
            nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
            profile: chainedRecoveryProfile,
            recoveryHarnessCommitHash: expectedHarnessCommitHash,
            runLog: input.runLog,
        });
    }
    if (thirdHarnessTransition !== undefined) {
        await validateThirdHarnessRepairCommitTransition({
            chainedProfile: chainedRecoveryProfile,
            executeCommand,
            finalHarnessCommitHash: expectedHarnessCommitHash,
            nativeSourceCommitHash: nativeEvidence.repositoryCommitHash,
            runLog: input.runLog,
            thirdProfile: thirdRecoveryProfile,
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
        attachmentSha256Hex,
        artifactValidationOptions,
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
        recoveryReservationIdentitySha256Hex:
            recoveryReservationIdentity?.identitySha256Hex,
        recoveryReservationIdentity,
        recoveryMarkerPrefixByteLength:
            isChainedRecovery &&
            serializedRecoveryPreflightAttempt !== undefined
                ? Buffer.byteLength(serializedRecoveryPreflightAttempt, 'utf8')
                : undefined,
        recoveryMarkerPrefixSha256Hex:
            isChainedRecovery &&
            serializedRecoveryPreflightAttempt !== undefined
                ? sha256Hex(serializedRecoveryPreflightAttempt)
                : undefined,
        recoveryOperationReservationPath:
            isChainedRecovery && recoveryReservationIdentity !== undefined
                ? canonicalRelativePath(
                      officialReservationRootPath,
                      reservationPath,
                  )
                : undefined,
        recoveryOperationReservationSha256Hex:
            isChainedRecovery && recoveryReservationIdentity !== undefined
                ? sha256Hex(serializedReservation)
                : undefined,
    };
};

export const executeProofStorageWidthBrowserEvidence = async (input: {
    readonly dependencies?: ProofStorageWidthBrowserEvidenceDependencies;
    readonly failedChainedRecoveryAttemptRunDirectoryPath?: string;
    readonly failedRecoveryAttemptRunDirectoryPath?: string;
    readonly nativeEvidencePath: string;
    readonly preOperationRecoveryRunDirectoryPath?: string;
    readonly runLog: ActiveLocalRunLog;
}): Promise<void> => {
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
    const recoveryAuthorization =
        await createBrowserRecoveryAuthorizationIfSelected({
            dependencies: input.dependencies,
            failedChainedRecoveryAttemptRunDirectoryPath:
                input.failedChainedRecoveryAttemptRunDirectoryPath,
            failedRecoveryAttemptRunDirectoryPath:
                input.failedRecoveryAttemptRunDirectoryPath,
            preOperationRecoveryRunDirectoryPath:
                input.preOperationRecoveryRunDirectoryPath,
        });

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
            ...(input.failedChainedRecoveryAttemptRunDirectoryPath === undefined
                ? {}
                : {
                      failedChainedRecoveryAttemptRunDirectoryPath:
                          input.failedChainedRecoveryAttemptRunDirectoryPath,
                  }),
            nativeEvidencePath: input.nativeEvidencePath,
            ...(input.failedRecoveryAttemptRunDirectoryPath === undefined
                ? {}
                : {
                      failedRecoveryAttemptRunDirectoryPath:
                          input.failedRecoveryAttemptRunDirectoryPath,
                  }),
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
                await appendBrowserRecoveryFailureOutcomeIfPending({
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

    if (
        closureRepositoryError !== undefined &&
        recoveryAuthorization !== undefined
    ) {
        try {
            await appendBrowserRecoveryFailureOutcomeIfPending({
                authorization: recoveryAuthorization,
                failure: closureRepositoryError,
            });
        } catch (outcomeError) {
            closureRepositoryError = Object.assign(
                new Error(
                    'The browser recovery closure failed and its singleton terminal outcome could not be recorded.',
                ),
                { attemptCause: closureRepositoryError, cause: outcomeError },
            );
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
        const missingResultError = new Error(
            'The browser width-evidence attempt completed without a result.',
        );
        if (recoveryAuthorization !== undefined) {
            await appendBrowserRecoveryFailureOutcomeIfPending({
                authorization: recoveryAuthorization,
                failure: missingResultError,
            });
        }
        throw missingResultError;
    }

    if (
        recoveryAuthorization?.recoveryOrdinal === chainedRecoveryOrdinal ||
        recoveryAuthorization?.recoveryOrdinal === thirdRecoveryOrdinal
    ) {
        const recoveryReservationIdentitySha256Hex =
            result.recoveryReservationIdentitySha256Hex;
        const recoveryReservationIdentity = result.recoveryReservationIdentity;
        const recoveryMarkerPrefixByteLength =
            result.recoveryMarkerPrefixByteLength;
        const recoveryMarkerPrefixSha256Hex =
            result.recoveryMarkerPrefixSha256Hex;
        const recoveryOperationReservationPath =
            result.recoveryOperationReservationPath;
        const recoveryOperationReservationSha256Hex =
            result.recoveryOperationReservationSha256Hex;
        if (
            recoveryReservationIdentitySha256Hex === undefined ||
            !exactSha256HexPattern.test(recoveryReservationIdentitySha256Hex) ||
            recoveryReservationIdentity === undefined ||
            recoveryReservationIdentity.identitySha256Hex !==
                recoveryReservationIdentitySha256Hex ||
            typeof recoveryMarkerPrefixByteLength !== 'number' ||
            !Number.isSafeInteger(recoveryMarkerPrefixByteLength) ||
            recoveryMarkerPrefixByteLength <= 0 ||
            typeof recoveryMarkerPrefixSha256Hex !== 'string' ||
            !exactSha256HexPattern.test(recoveryMarkerPrefixSha256Hex) ||
            typeof recoveryOperationReservationPath !== 'string' ||
            recoveryOperationReservationPath.length === 0 ||
            typeof recoveryOperationReservationSha256Hex !== 'string' ||
            !exactSha256HexPattern.test(recoveryOperationReservationSha256Hex)
        ) {
            const missingIdentityError = new Error(
                'The chained browser recovery omitted its final reservation identity.',
            );
            await appendBrowserRecoveryFailureOutcomeIfPending({
                authorization: recoveryAuthorization,
                failure: missingIdentityError,
            });
            throw missingIdentityError;
        }
        try {
            await validateProvisionalProofStorageWidthBrowserEvidenceArtifacts(
                result.attachmentPath,
                result.artifactValidationOptions,
            );
            await finalizeChainedBrowserRecoveryOutcome({
                attachmentPath: result.attachmentPath,
                attachmentSha256Hex: result.attachmentSha256Hex,
                authorization: recoveryAuthorization,
                decisionOutcome: result.decision.outcome,
                identity: recoveryReservationIdentity,
                markerPrefixByteLength: recoveryMarkerPrefixByteLength,
                markerPrefixSha256Hex: recoveryMarkerPrefixSha256Hex,
                operationReservationPath: recoveryOperationReservationPath,
                operationReservationSha256Hex:
                    recoveryOperationReservationSha256Hex,
            });
            await validateProofStorageWidthBrowserEvidenceArtifacts(
                result.attachmentPath,
                result.artifactValidationOptions,
            );
        } catch (error) {
            try {
                await appendBrowserRecoveryFailureOutcomeIfPending({
                    authorization: recoveryAuthorization,
                    failure: error,
                });
            } catch (outcomeError) {
                throw Object.assign(
                    new Error(
                        'The chained browser recovery finalization failed and its pending singleton could not record the failure.',
                    ),
                    { attemptCause: error, cause: outcomeError },
                );
            }
            throw error;
        }
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
    failedChainedRecoveryAttemptRunDirectoryPath?: string;
    failedRecoveryAttemptRunDirectoryPath?: string;
    nativeEvidencePath: string;
    preOperationRecoveryRunDirectoryPath?: string;
    recoveryChainDryRun?: true;
}> => {
    const argumentSeparatorIndexes = rawArguments
        .map((argument, argumentIndex) =>
            argument === '--' ? argumentIndex : -1,
        )
        .filter((argumentIndex) => argumentIndex !== -1);
    if (
        argumentSeparatorIndexes.length > 1 ||
        (argumentSeparatorIndexes.length === 1 &&
            argumentSeparatorIndexes[0] !== 0)
    ) {
        throw new Error(
            'The browser width-evidence runner accepts at most one leading argument separator.',
        );
    }
    const effectiveArguments =
        argumentSeparatorIndexes.length === 1
            ? rawArguments.slice(1)
            : rawArguments;
    const nativeEvidenceFlagIndex =
        effectiveArguments.indexOf('--native-evidence');
    const recoveryFlagIndex = effectiveArguments.indexOf(
        '--pre-operation-recovery',
    );
    const failedRecoveryAttemptFlagIndex = effectiveArguments.indexOf(
        '--failed-recovery-attempt',
    );
    const failedChainedRecoveryAttemptFlagIndex = effectiveArguments.indexOf(
        '--failed-chained-recovery-attempt',
    );
    const recoveryChainDryRunFlagIndex = effectiveArguments.indexOf(
        '--recovery-chain-dry-run',
    );
    const nativeEvidencePath = effectiveArguments[nativeEvidenceFlagIndex + 1];
    const preOperationRecoveryRunDirectoryPath =
        recoveryFlagIndex === -1
            ? undefined
            : effectiveArguments[recoveryFlagIndex + 1];
    const failedRecoveryAttemptRunDirectoryPath =
        failedRecoveryAttemptFlagIndex === -1
            ? undefined
            : effectiveArguments[failedRecoveryAttemptFlagIndex + 1];
    const failedChainedRecoveryAttemptRunDirectoryPath =
        failedChainedRecoveryAttemptFlagIndex === -1
            ? undefined
            : effectiveArguments[failedChainedRecoveryAttemptFlagIndex + 1];
    const hasRecovery = preOperationRecoveryRunDirectoryPath !== undefined;
    const hasChainedRecovery =
        failedRecoveryAttemptRunDirectoryPath !== undefined;
    const hasThirdRecovery =
        failedChainedRecoveryAttemptRunDirectoryPath !== undefined;
    const recoveryChainDryRun = recoveryChainDryRunFlagIndex !== -1;
    const expectedArgumentLength = recoveryChainDryRun
        ? 9
        : hasThirdRecovery
          ? 8
          : hasChainedRecovery
            ? 6
            : hasRecovery
              ? 4
              : 2;
    if (
        effectiveArguments.length !== expectedArgumentLength ||
        nativeEvidenceFlagIndex !== 0 ||
        nativeEvidencePath === undefined ||
        !path.isAbsolute(nativeEvidencePath) ||
        (hasRecovery &&
            (recoveryFlagIndex !== 2 ||
                preOperationRecoveryRunDirectoryPath === undefined ||
                !path.isAbsolute(preOperationRecoveryRunDirectoryPath))) ||
        (hasChainedRecovery &&
            (failedRecoveryAttemptFlagIndex !== 4 ||
                !path.isAbsolute(failedRecoveryAttemptRunDirectoryPath))) ||
        (hasThirdRecovery &&
            (failedChainedRecoveryAttemptFlagIndex !== 6 ||
                !path.isAbsolute(
                    failedChainedRecoveryAttemptRunDirectoryPath,
                ))) ||
        (recoveryChainDryRun &&
            (!hasThirdRecovery || recoveryChainDryRunFlagIndex !== 8)) ||
        (!recoveryChainDryRun && recoveryChainDryRunFlagIndex !== -1) ||
        (!hasRecovery && failedRecoveryAttemptFlagIndex !== -1) ||
        (!hasChainedRecovery && failedChainedRecoveryAttemptFlagIndex !== -1)
    ) {
        throw new Error(
            'The browser width-evidence runner requires --native-evidence followed by one absolute evidence path, ordered absolute predecessor paths for an authorized recovery, and --recovery-chain-dry-run only as the final flag of the complete ordinal-three chain; every path must be absolute.',
        );
    }
    return Object.freeze({
        nativeEvidencePath,
        ...(failedChainedRecoveryAttemptRunDirectoryPath === undefined
            ? {}
            : { failedChainedRecoveryAttemptRunDirectoryPath }),
        ...(failedRecoveryAttemptRunDirectoryPath === undefined
            ? {}
            : { failedRecoveryAttemptRunDirectoryPath }),
        ...(preOperationRecoveryRunDirectoryPath === undefined
            ? {}
            : { preOperationRecoveryRunDirectoryPath }),
        ...(recoveryChainDryRun ? { recoveryChainDryRun: true as const } : {}),
    });
};

export const runProofStorageWidthBrowserEvidence = async (
    rawArguments: readonly string[] = process.argv.slice(2),
    dependencies?: ProofStorageWidthBrowserEvidenceDependencies,
): Promise<void> => {
    const parsedArguments =
        parseProofStorageWidthBrowserEvidenceArguments(rawArguments);
    if (parsedArguments.recoveryChainDryRun === true) {
        const failedChainedRecoveryAttemptRunDirectoryPath =
            parsedArguments.failedChainedRecoveryAttemptRunDirectoryPath;
        const failedRecoveryAttemptRunDirectoryPath =
            parsedArguments.failedRecoveryAttemptRunDirectoryPath;
        const preOperationRecoveryRunDirectoryPath =
            parsedArguments.preOperationRecoveryRunDirectoryPath;
        if (
            failedChainedRecoveryAttemptRunDirectoryPath === undefined ||
            failedRecoveryAttemptRunDirectoryPath === undefined ||
            preOperationRecoveryRunDirectoryPath === undefined
        ) {
            throw new Error(
                'The recovery-chain dry-run omitted an authorized predecessor.',
            );
        }
        const result = await dryRunProofStorageWidthBrowserRecoveryChain({
            ...(dependencies === undefined ? {} : { dependencies }),
            failedChainedRecoveryAttemptRunDirectoryPath,
            failedRecoveryAttemptRunDirectoryPath,
            nativeEvidencePath: parsedArguments.nativeEvidencePath,
            preOperationRecoveryRunDirectoryPath,
        });
        process.stdout.write(
            `Proof-storage width browser recovery-chain dry-run: ${JSON.stringify(result)}\n`,
        );
        return;
    }
    const runWithLocalRunLogForInvocation =
        dependencies?.runWithLocalRunLog ?? runWithLocalRunLog;
    const withLocalHeavyLaneLeaseForInvocation =
        dependencies?.withLocalHeavyLaneLease ?? withLocalHeavyLaneLease;
    await runWithLocalRunLogForInvocation(
        {
            commandLineArguments: rawArguments,
            lanes: [laneLabel],
            resourceSampleIntervalMilliseconds,
            scriptName,
        },
        async (runLog) => {
            await withLocalHeavyLaneLeaseForInvocation({
                action: () =>
                    executeProofStorageWidthBrowserEvidence({
                        ...(dependencies === undefined ? {} : { dependencies }),
                        ...(parsedArguments.failedChainedRecoveryAttemptRunDirectoryPath ===
                        undefined
                            ? {}
                            : {
                                  failedChainedRecoveryAttemptRunDirectoryPath:
                                      parsedArguments.failedChainedRecoveryAttemptRunDirectoryPath,
                              }),
                        ...(parsedArguments.failedRecoveryAttemptRunDirectoryPath ===
                        undefined
                            ? {}
                            : {
                                  failedRecoveryAttemptRunDirectoryPath:
                                      parsedArguments.failedRecoveryAttemptRunDirectoryPath,
                              }),
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
