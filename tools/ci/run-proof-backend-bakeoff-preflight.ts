import { createHash } from 'node:crypto';
import { access, mkdir, readFile } from 'node:fs/promises';
import path from 'node:path';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import { validateProofStorageWidthStaticPreflightResult } from './proof-storage-width-evidence.js';
import {
    runCommandAndCaptureOutput,
    type CapturedCommandResult,
    type CommandInvocation,
} from './run-command.js';
import {
    buildProofBackendBakeoffEnvironment,
    writeJsonAtomicallyAndExclusively,
} from './run-proof-backend-bakeoff.js';

const laneLabel = 'Proof backend bakeoff preflight';
const scriptName = 'test:rust:kernel:proof-backend-bakeoff-preflight';
const cargoFeatureName = 'proof-storage-width-evidence';
const cargoPackageName = 'sealed-lattice-kernel';
const featureTestFilter = 'bgv::proof_suite::proof_backend_bakeoff';
const moduleTestFilter = `${featureTestFilter}::tests`;
const resourceSampleIntervalMilliseconds = 100;
const exactCommitHashPattern = /^[0-9a-f]{40}$/u;
const exactSha256HexPattern = /^[0-9a-f]{64}$/u;
const evidenceFileName = 'proof-backend-bakeoff-preflight-evidence.json';
const staticFeatureTestResultFileName =
    'proof-backend-bakeoff-preflight-width-static-result.json';
const staticFeatureTestResultRelativePath = `attachments/${staticFeatureTestResultFileName}`;
const staticPreflightResultPathEnvironmentVariable =
    'SEALED_LATTICE_PROOF_STORAGE_WIDTH_STATIC_PREFLIGHT_RESULT_PATH';

const proofBackendBakeoffFilteredNonIgnoredFeatureTestNames = [
    `${moduleTestFilter}::frozen_checked_backend_bindings_are_nonplaceholder_and_canonical`,
    `${moduleTestFilter}::frozen_fragment_has_exact_geometry_and_refuses_each_affine_half_mutation`,
    `${featureTestFilter}_fri::canonical_artifact_write_failure_removes_every_partial_custody_object`,
    `${featureTestFilter}_fri::custody_directory_path_refuses_relative_out_of_parent_and_existing_paths`,
    `${featureTestFilter}_fri::custody_finish_continues_cleanup_after_one_object_is_already_missing`,
    `${featureTestFilter}_fri::fresh_public_base_replay_refuses_source_and_statement_root_equivocation`,
    `${featureTestFilter}_fri::native_custody_path_bound_covers_constructed_source_and_artifact_paths`,
    `${featureTestFilter}_fri::observed_public_source_work_counts_fail_closed_independently`,
    `${featureTestFilter}_fri::packed_deep_fri_filter_excludes_every_denominator_and_shift_collision`,
    `${featureTestFilter}_fri::proof_storage_width_browser_evidence::tests::fresh_verifier_refuses_cross_pass_identity_equivocation_and_wrong_base_root`,
    `${featureTestFilter}_fri::proof_storage_width_browser_evidence::tests::occupied_registry_refuses_before_constructing_another_operation`,
    `${featureTestFilter}_fri::proof_storage_width_browser_evidence::tests::pending_append_request_is_encoded_once_after_the_caller_chunk_is_released`,
    `${featureTestFilter}_fri::public_source_constructor_failure_removes_every_partial_custody_object`,
    `${featureTestFilter}_fri::public_source_identity_binds_value_column_row_width_and_orientation`,
    `${featureTestFilter}_fri::public_width_fresh_profile_reconstruction_parses_root_and_width_and_rejects_unbound_input`,
    `${featureTestFilter}_fri::static_wasm_ceiling_includes_prover_and_fresh_verifier_public_opening_workspaces`,
    `${featureTestFilter}_fri::shifted_opening_batch_exposes_the_exact_degree_gap_counterexample`,
    `${featureTestFilter}_fri::shifted_opening_batch_prover_and_verifier_use_the_same_polynomial`,
    `${featureTestFilter}_sumcheck::tests::altered_local_operative_profile_changes_the_transcript`,
    `${featureTestFilter}_sumcheck::tests::canonical_artifact_body_ceiling_matches_the_checked_profile_formula`,
    `${featureTestFilter}_sumcheck::tests::complete_artifact_decoder_rejects_oversized_truncated_and_noncanonical_bodies`,
    `${featureTestFilter}_sumcheck::tests::complete_artifact_wire_rejects_each_query_location_shape_mutation`,
    `${featureTestFilter}_sumcheck::tests::complete_artifact_wire_rejects_schema_and_container_count_mutations`,
    `${featureTestFilter}_sumcheck::tests::complete_artifact_wire_rejects_wrong_size_caps_at_every_location`,
    `${featureTestFilter}_sumcheck::tests::complete_artifact_wire_roundtrips_into_fresh_verifier_types`,
    `${featureTestFilter}_sumcheck::tests::degree_two_round_polynomial_matches_direct_hypercube_sum`,
    `${featureTestFilter}_sumcheck::tests::exact_unique_decoding_query_mask_and_aggregate_bounds_are_minimal`,
    `${featureTestFilter}_sumcheck::tests::fixture_validation_rejects_each_affine_half_mutation`,
    `${featureTestFilter}_sumcheck::tests::hiding_whir_configuration_matches_the_exact_conservative_profile`,
    `${featureTestFilter}_sumcheck::tests::merkle_word_encoding_preserves_all_64_shake256_bytes`,
    `${featureTestFilter}_sumcheck::tests::query_opening_shape_gate_checks_base_and_extension_widths_and_paths`,
    `${featureTestFilter}_sumcheck::tests::query_opening_wire_rejects_malformed_trailing_and_noncanonical_bytes`,
    `${featureTestFilter}_sumcheck::tests::query_opening_wire_uses_stable_external_numeric_tags`,
    `${featureTestFilter}_sumcheck::tests::unique_decoding_algebraic_outer_hash_and_fiat_shamir_bounds_clear_the_floor`,
] as const;

export const proofStorageWidthStaticPreflightTestName =
    'bgv::proof_suite::proof_storage_width_evidence::tests::proof_storage_width_evidence_static_preflight_checks_every_scheduled_width';

export const proofBackendBakeoffNonIgnoredFeatureTestNames = [
    ...proofBackendBakeoffFilteredNonIgnoredFeatureTestNames,
    proofStorageWidthStaticPreflightTestName,
] as const;

export const proofBackendBakeoffPreflightTestNames = [
    `${moduleTestFilter}::frozen_backend_binding_vectors_regenerate_from_exact_columns_and_profiles`,
    `${moduleTestFilter}::packed_deep_fri_fresh_verifier_has_no_witness_side_channel`,
    `${moduleTestFilter}::sumcheck_class_fresh_verifier_has_no_witness_side_channel`,
] as const;

export const proofBackendBakeoffIgnoredTestNames = [
    proofBackendBakeoffPreflightTestNames[0],
    proofBackendBakeoffPreflightTestNames[1],
    proofBackendBakeoffPreflightTestNames[2],
] as const;

export const proofBackendBakeoffFeatureTestNames = [
    ...proofBackendBakeoffNonIgnoredFeatureTestNames,
    ...proofBackendBakeoffIgnoredTestNames,
] as const;

type ProofBackendBakeoffPreflightTestName =
    (typeof proofBackendBakeoffPreflightTestNames)[number];

const preflightTestFileSlugs = {
    [proofBackendBakeoffPreflightTestNames[0]]: 'binding-vectors',
    [proofBackendBakeoffPreflightTestNames[1]]:
        'packed-deep-fri-fresh-verifier',
    [proofBackendBakeoffPreflightTestNames[2]]: 'sumcheck-class-fresh-verifier',
} as const satisfies Record<ProofBackendBakeoffPreflightTestName, string>;

type RepositoryState = Readonly<{
    commitHash: string;
    treeDirty: boolean;
}>;

type RepositoryCheckpoint = 'after' | 'before' | 'initial';

type CommandExecutor = (
    invocation: CommandInvocation,
    runLog: ActiveLocalRunLog,
) => Promise<CapturedCommandResult>;

export type ProofBackendBakeoffPreflightRunnerDependencies = Readonly<{
    executeCommand?: CommandExecutor;
    processMemoryGuard?: ProcessMemoryGuard;
    readRepositoryState?: (
        checkpoint: RepositoryCheckpoint,
        runLog: ActiveLocalRunLog,
    ) => Promise<RepositoryState>;
}>;

export type ProofBackendBakeoffPreflightRunResult = Readonly<{
    attachmentPath: string;
}>;

export type ValidatedProofBackendBakeoffPreflightEvidence = Readonly<{
    attachmentPath: string;
    commitHash: string;
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

const buildProofBackendBakeoffPrecompileCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [...buildCargoArguments(), '--no-run'],
    command: 'cargo',
    description: 'precompile the release proof backend bakeoff fragment',
    env: environment,
    logFileSlug: 'cargo-precompile-proof-backend-bakeoff',
});

export const buildProofBackendBakeoffPreflightListCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [
        ...buildCargoArguments(),
        featureTestFilter,
        '--',
        '--ignored',
        '--list',
        '--test-threads',
        '1',
    ],
    command: 'cargo',
    description: 'list the proof backend bakeoff ignored owners',
    env: environment,
    logFileSlug: 'cargo-list-proof-backend-bakeoff-preflight',
});

export const buildProofBackendBakeoffFeatureListCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [
        ...buildCargoArguments(),
        featureTestFilter,
        '--',
        '--list',
        '--test-threads',
        '1',
    ],
    command: 'cargo',
    description: 'list the proof backend bakeoff feature tests',
    env: environment,
    logFileSlug: 'cargo-list-proof-backend-bakeoff-feature-tests',
});

export const buildProofStorageWidthStaticFeatureListCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [
        ...buildCargoArguments(),
        proofStorageWidthStaticPreflightTestName,
        '--',
        '--exact',
        '--list',
        '--test-threads',
        '1',
    ],
    command: 'cargo',
    description: 'list the proof-storage width static feature test',
    env: environment,
    logFileSlug: 'cargo-list-proof-storage-width-static-feature-test',
});

const listedInventoryLines = (standardOutput: string): readonly string[] =>
    standardOutput
        .split(/\r?\n/u)
        .map((line) => line.trim())
        .filter((line) => /: (?:benchmark|test)$/u.test(line));

const parseExactTestInventory = (input: {
    readonly expectedTestNames: readonly string[];
    readonly inventoryDescription: string;
    readonly standardOutput: string;
}): readonly string[] => {
    const inventoryLines = listedInventoryLines(input.standardOutput);
    if (inventoryLines.length === 0) {
        throw new Error(
            `The ${input.inventoryDescription} inventory selected zero tests.`,
        );
    }
    const benchmarkLines = inventoryLines.filter((line) =>
        line.endsWith(': benchmark'),
    );
    if (benchmarkLines.length !== 0) {
        throw new Error(
            `The ${input.inventoryDescription} inventory unexpectedly selected benchmarks: ${benchmarkLines.join(', ')}.`,
        );
    }
    const actualTestNames = inventoryLines.map((line) =>
        line.slice(0, -': test'.length),
    );
    const duplicateTestNames = actualTestNames.filter(
        (testName, index) => actualTestNames.indexOf(testName) !== index,
    );
    if (duplicateTestNames.length !== 0) {
        throw new Error(
            `The ${input.inventoryDescription} inventory contains duplicate tests: ${[...new Set(duplicateTestNames)].join(', ')}.`,
        );
    }

    const actualTestNameSet = new Set(actualTestNames);
    const expectedTestNameSet = new Set(input.expectedTestNames);
    const missingTestNames = input.expectedTestNames.filter(
        (testName) => !actualTestNameSet.has(testName),
    );
    const extraTestNames = actualTestNames.filter(
        (testName) => !expectedTestNameSet.has(testName),
    );
    if (missingTestNames.length !== 0 || extraTestNames.length !== 0) {
        throw new Error(
            `The ${input.inventoryDescription} inventory does not match its exact registry. Missing: ${missingTestNames.length === 0 ? 'none' : missingTestNames.join(', ')}. Extra: ${extraTestNames.length === 0 ? 'none' : extraTestNames.join(', ')}.`,
        );
    }

    return actualTestNames;
};

export const parseProofBackendBakeoffFeatureInventory = (
    standardOutput: string,
): readonly string[] =>
    parseExactTestInventory({
        expectedTestNames: proofBackendBakeoffFeatureTestNames,
        inventoryDescription: 'proof backend bakeoff feature-test',
        standardOutput,
    });

export const parseProofBackendBakeoffPreflightInventory = (
    standardOutput: string,
): readonly ProofBackendBakeoffPreflightTestName[] => {
    parseExactTestInventory({
        expectedTestNames: proofBackendBakeoffIgnoredTestNames,
        inventoryDescription: 'proof backend bakeoff ignored-owner',
        standardOutput,
    });
    return proofBackendBakeoffPreflightTestNames;
};

export const buildProofBackendBakeoffFeatureTestCommand = (
    environment: NodeJS.ProcessEnv,
): CommandInvocation => ({
    args: [
        ...buildCargoArguments(),
        featureTestFilter,
        '--',
        '--nocapture',
        '--test-threads',
        '1',
    ],
    command: 'cargo',
    description: 'run the proof backend bakeoff non-ignored feature tests',
    env: environment,
    logFileSlug: 'cargo-proof-backend-bakeoff-feature-tests',
});

export const buildProofStorageWidthStaticFeatureTestCommand = (
    input: Readonly<{
        environment: NodeJS.ProcessEnv;
        resultPath: string;
    }>,
): CommandInvocation => {
    if (
        !path.isAbsolute(input.resultPath) ||
        path.resolve(input.resultPath) !== input.resultPath
    ) {
        throw new Error(
            'The proof-storage width static feature-test result path must be an exact absolute path.',
        );
    }
    return {
        args: [
            ...buildCargoArguments(),
            proofStorageWidthStaticPreflightTestName,
            '--',
            '--exact',
            '--nocapture',
            '--test-threads',
            '1',
        ],
        command: 'cargo',
        description:
            'run the proof-storage width static non-ignored feature test',
        env: {
            ...input.environment,
            [staticPreflightResultPathEnvironmentVariable]: input.resultPath,
        },
        logFileSlug: 'cargo-proof-storage-width-static-feature-test',
    };
};

const isPreflightTestName = (
    testName: string,
): testName is ProofBackendBakeoffPreflightTestName =>
    proofBackendBakeoffPreflightTestNames.some(
        (expectedTestName) => expectedTestName === testName,
    );

export const buildProofBackendBakeoffPreflightTestCommand = (input: {
    readonly environment: NodeJS.ProcessEnv;
    readonly exactTestName: string;
}): CommandInvocation => {
    if (!isPreflightTestName(input.exactTestName)) {
        throw new Error(
            `The proof backend bakeoff preflight refuses an unregistered test: ${input.exactTestName}.`,
        );
    }
    const testFileSlug = preflightTestFileSlugs[input.exactTestName];
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
        description: `run proof backend bakeoff preflight ${input.exactTestName}`,
        env: input.environment,
        logFileSlug: `cargo-proof-backend-bakeoff-preflight-${testFileSlug}`,
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
            }.`,
        );
    }
    return result;
};

const defaultCommandExecutor: CommandExecutor = (invocation, runLog) =>
    runCommandAndCaptureOutput(invocation, {
        echoOutput: true,
        runLog,
    });

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
    throw new Error(
        `Refusing to overwrite proof backend bakeoff preflight evidence: ${filePath}.`,
    );
};

const readAndValidateStaticPreflightResult = async (input: {
    readonly resultPath: string;
}): Promise<string> => {
    let resultContents: Buffer;
    try {
        resultContents = await readFile(input.resultPath);
    } catch (error) {
        throw Object.assign(
            new Error(
                'The proof-storage width static feature test did not create its exact result artifact.',
            ),
            { cause: error },
        );
    }
    let parsedResult: unknown;
    try {
        parsedResult = JSON.parse(resultContents.toString('utf8')) as unknown;
    } catch (error) {
        throw Object.assign(
            new Error(
                'The proof-storage width static feature-test result is not valid JSON.',
            ),
            { cause: error },
        );
    }
    validateProofStorageWidthStaticPreflightResult(parsedResult);
    return sha256Hex(resultContents);
};

const readRepositoryStateWithCommands = async (input: {
    readonly checkpoint: RepositoryCheckpoint;
    readonly executeCommand: CommandExecutor;
    readonly runLog: ActiveLocalRunLog;
}): Promise<RepositoryState> => {
    const commitResult = await executeRequiredCommand({
        command: {
            args: ['rev-parse', '--verify', 'HEAD^{commit}'],
            command: 'git',
            description: `read the ${input.checkpoint}-preflight repository commit`,
            logFileSlug: `git-proof-backend-bakeoff-preflight-${input.checkpoint}-commit`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    const commitHash = commitResult.stdout.trim();
    if (!exactCommitHashPattern.test(commitHash)) {
        throw new Error(
            `The ${input.checkpoint}-preflight repository commit is not an exact 40-hex hash.`,
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
            description: `read the ${input.checkpoint}-preflight repository status`,
            logFileSlug: `git-proof-backend-bakeoff-preflight-${input.checkpoint}-status`,
        },
        executeCommand: input.executeCommand,
        runLog: input.runLog,
    });
    return {
        commitHash,
        treeDirty: statusResult.stdout.length !== 0,
    };
};

const requireCleanRepository = (
    repositoryState: RepositoryState,
    checkpoint: RepositoryCheckpoint,
): void => {
    if (repositoryState.treeDirty) {
        throw new Error(
            `The proof backend bakeoff preflight requires a clean repository tree at its ${checkpoint} checkpoint.`,
        );
    }
};

const requireSameCommit = (input: {
    readonly actual: RepositoryState;
    readonly expected: RepositoryState;
    readonly intervalDescription: string;
}): void => {
    if (input.actual.commitHash !== input.expected.commitHash) {
        throw new Error(
            `The repository commit changed ${input.intervalDescription}.`,
        );
    }
};

const relativeDiagnosticPath = (
    runDirectoryPath: string,
    filePath: string,
): string =>
    path.relative(runDirectoryPath, filePath).split(path.sep).join('/');

const featureTestDiagnosticsFileName =
    'process-memory-guard-proof-backend-bakeoff-preflight-feature-tests.jsonl';
const staticFeatureTestDiagnosticsFileName =
    'process-memory-guard-proof-backend-bakeoff-preflight-width-static-test.jsonl';

const preflightTestDiagnosticsFileName = (
    testName: ProofBackendBakeoffPreflightTestName,
): string =>
    `process-memory-guard-proof-backend-bakeoff-preflight-${preflightTestFileSlugs[testName]}.jsonl`;

const featureTestDiagnosticsRelativePath = `resources/${featureTestDiagnosticsFileName}`;
const staticFeatureTestDiagnosticsRelativePath = `resources/${staticFeatureTestDiagnosticsFileName}`;

const preflightTestDiagnosticsRelativePath = (
    testName: ProofBackendBakeoffPreflightTestName,
): string => `resources/${preflightTestDiagnosticsFileName(testName)}`;

const requireJsonObject = (
    value: unknown,
    description: string,
): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${description} must be a JSON object.`);
    }
    return value as Record<string, unknown>;
};

const requireNonnegativeSafeInteger = (
    value: unknown,
    description: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new Error(`${description} must be a nonnegative safe integer.`);
    }
    return value;
};

const requireExactStringArray = (input: {
    readonly actual: unknown;
    readonly description: string;
    readonly expected: readonly string[];
}): void => {
    if (
        !Array.isArray(input.actual) ||
        input.actual.length !== input.expected.length ||
        input.actual.some(
            (value, valueIndex) => value !== input.expected[valueIndex],
        )
    ) {
        throw new Error(
            `${input.description} does not match its exact registered order.`,
        );
    }
};

const sha256Hex = (contents: Uint8Array): string =>
    createHash('sha256').update(contents).digest('hex');

const validateProcessMemoryGuardTelemetry = (input: {
    readonly diagnosticsJsonLines: string;
    readonly diagnosticsPath: string;
    readonly expectedMemoryLimitBytes: number;
}): void => {
    const records = input.diagnosticsJsonLines
        .split(/\r?\n/u)
        .filter((line) => line.length !== 0)
        .map((line, lineIndex) => {
            let parsed: unknown;
            try {
                parsed = JSON.parse(line) as unknown;
            } catch (error) {
                throw Object.assign(
                    new Error(
                        `${input.diagnosticsPath} line ${lineIndex + 1} is not valid JSON.`,
                    ),
                    { cause: error },
                );
            }
            const record = requireJsonObject(
                parsed,
                `${input.diagnosticsPath} line ${lineIndex + 1}`,
            );
            return {
                elapsedMilliseconds: requireNonnegativeSafeInteger(
                    record.elapsedMilliseconds,
                    `${input.diagnosticsPath} line ${lineIndex + 1} elapsedMilliseconds`,
                ),
                record,
                recordedAtUnixMilliseconds: requireNonnegativeSafeInteger(
                    record.recordedAtUnixMilliseconds,
                    `${input.diagnosticsPath} line ${lineIndex + 1} recordedAtUnixMilliseconds`,
                ),
                sequence: requireNonnegativeSafeInteger(
                    record.sequence,
                    `${input.diagnosticsPath} line ${lineIndex + 1} sequence`,
                ),
            };
        });
    if (records.length < 4) {
        throw new Error(
            `${input.diagnosticsPath} must contain guard-started, child-started, at least one resource-sample, and child-exited records.`,
        );
    }
    for (const [recordIndex, currentRecord] of records.entries()) {
        if (currentRecord.sequence !== recordIndex) {
            throw new Error(
                `${input.diagnosticsPath} sequence must start at zero and remain contiguous.`,
            );
        }
        const previousRecord = records[recordIndex - 1];
        if (
            previousRecord !== undefined &&
            (currentRecord.elapsedMilliseconds <
                previousRecord.elapsedMilliseconds ||
                currentRecord.recordedAtUnixMilliseconds <
                    previousRecord.recordedAtUnixMilliseconds)
        ) {
            throw new Error(
                `${input.diagnosticsPath} elapsed and wall time must be nondecreasing.`,
            );
        }
    }

    const guardStartedRecord = records[0];
    const childStartedRecord = records[1];
    const resourceSampleRecords = records.slice(2, -1);
    const childExitedRecord = records[records.length - 1];
    if (
        guardStartedRecord?.record.eventType !== 'guard-started' ||
        childStartedRecord?.record.eventType !== 'child-started' ||
        resourceSampleRecords.some(
            ({ record }) => record.eventType !== 'resource-sample',
        ) ||
        childExitedRecord?.record.eventType !== 'child-exited'
    ) {
        throw new Error(
            `${input.diagnosticsPath} must contain one contiguous guard-started, child-started, resource-sample, and child-exited lifecycle.`,
        );
    }
    if (
        guardStartedRecord.record.resourceSampleIntervalMilliseconds !==
        resourceSampleIntervalMilliseconds
    ) {
        throw new Error(
            `${input.diagnosticsPath} sampling cadence must be exactly 100 milliseconds.`,
        );
    }
    if (guardStartedRecord.record.aggregateProcessTreeMemoryLimit !== true) {
        throw new Error(
            `${input.diagnosticsPath} must cover the aggregate process tree.`,
        );
    }
    if (
        guardStartedRecord.record.memoryLimitBytes !==
        input.expectedMemoryLimitBytes
    ) {
        throw new Error(
            `${input.diagnosticsPath} does not bind the expected process-memory limit.`,
        );
    }
    for (const [sampleIndex, { record }] of resourceSampleRecords.entries()) {
        if (record.sampleError !== null) {
            throw new Error(
                `${input.diagnosticsPath} resource sample ${sampleIndex + 1} must explicitly report no sampling error.`,
            );
        }
        if (record.confirmedMemoryLimitViolation !== false) {
            throw new Error(
                `${input.diagnosticsPath} resource sample ${sampleIndex + 1} must explicitly report no memory-limit violation.`,
            );
        }
        const processTreeResidentMemoryBytes = requireNonnegativeSafeInteger(
            record.processTreeResidentMemoryBytes,
            `${input.diagnosticsPath} resource sample ${sampleIndex + 1} processTreeResidentMemoryBytes`,
        );
        if (processTreeResidentMemoryBytes === 0) {
            throw new Error(
                `${input.diagnosticsPath} resource sample ${sampleIndex + 1} resident memory must be positive.`,
            );
        }
    }
    if (
        childExitedRecord.record.memoryEvidence !== 'completed' ||
        childExitedRecord.record.terminationClassification !== 'completed' ||
        childExitedRecord.record.exitCode !== 0
    ) {
        throw new Error(
            `${input.diagnosticsPath} lacks a terminal completed child-exited record with exit code zero.`,
        );
    }
};

export const readAndValidateCompletedProcessMemoryGuardArtifact =
    async (input: {
        readonly diagnosticsPath: string;
        readonly expectedMemoryLimitBytes: number;
        readonly expectedSha256Hex?: string;
    }): Promise<string> => {
        const diagnosticsContents = await readFile(input.diagnosticsPath);
        const diagnosticsSha256Hex = sha256Hex(diagnosticsContents);
        if (
            input.expectedSha256Hex !== undefined &&
            diagnosticsSha256Hex !== input.expectedSha256Hex
        ) {
            throw new Error(
                `${input.diagnosticsPath} does not match its bound SHA-256 digest.`,
            );
        }
        validateProcessMemoryGuardTelemetry({
            diagnosticsJsonLines: diagnosticsContents.toString('utf8'),
            diagnosticsPath: input.diagnosticsPath,
            expectedMemoryLimitBytes: input.expectedMemoryLimitBytes,
        });
        return diagnosticsSha256Hex;
    };

const requireRepositoryState = (
    value: unknown,
    description: string,
): RepositoryState => {
    const repositoryState = requireJsonObject(value, description);
    if (
        typeof repositoryState.commitHash !== 'string' ||
        !exactCommitHashPattern.test(repositoryState.commitHash)
    ) {
        throw new Error(`${description} commit must be an exact 40-hex hash.`);
    }
    if (repositoryState.treeDirty !== false) {
        throw new Error(`${description} must bind a clean repository tree.`);
    }
    return {
        commitHash: repositoryState.commitHash,
        treeDirty: false,
    };
};

const requireBoundGuardArtifact = async (input: {
    readonly artifact: unknown;
    readonly artifactDescription: string;
    readonly expectedRelativePath: string;
    readonly expectedMemoryLimitBytes: number;
    readonly runDirectoryPath: string;
}): Promise<void> => {
    const artifact = requireJsonObject(
        input.artifact,
        input.artifactDescription,
    );
    if (artifact.diagnosticsPath !== input.expectedRelativePath) {
        throw new Error(
            `${input.artifactDescription} must use the exact path ${input.expectedRelativePath}.`,
        );
    }
    if (
        typeof artifact.diagnosticsSha256Hex !== 'string' ||
        !exactSha256HexPattern.test(artifact.diagnosticsSha256Hex)
    ) {
        throw new Error(
            `${input.artifactDescription} must bind an exact lowercase SHA-256 digest.`,
        );
    }
    await readAndValidateCompletedProcessMemoryGuardArtifact({
        diagnosticsPath: path.join(
            input.runDirectoryPath,
            input.expectedRelativePath,
        ),
        expectedSha256Hex: artifact.diagnosticsSha256Hex,
        expectedMemoryLimitBytes: input.expectedMemoryLimitBytes,
    });
};

const requireBoundStaticPreflightResult = async (input: {
    readonly artifact: Record<string, unknown>;
    readonly runDirectoryPath: string;
}): Promise<void> => {
    if (input.artifact.resultPath !== staticFeatureTestResultRelativePath) {
        throw new Error(
            `The completed proof-storage width static feature test must use the exact result path ${staticFeatureTestResultRelativePath}.`,
        );
    }
    if (
        typeof input.artifact.resultSha256Hex !== 'string' ||
        !exactSha256HexPattern.test(input.artifact.resultSha256Hex)
    ) {
        throw new Error(
            'The completed proof-storage width static feature test must bind an exact lowercase result SHA-256 digest.',
        );
    }
    const resultPath = path.join(
        input.runDirectoryPath,
        staticFeatureTestResultRelativePath,
    );
    const resultContents = await readFile(resultPath);
    if (sha256Hex(resultContents) !== input.artifact.resultSha256Hex) {
        throw new Error(
            `${resultPath} does not match its bound result SHA-256 digest.`,
        );
    }
    let parsedResult: unknown;
    try {
        parsedResult = JSON.parse(resultContents.toString('utf8')) as unknown;
    } catch (error) {
        throw Object.assign(
            new Error(
                'The bound proof-storage width static feature-test result is not valid JSON.',
            ),
            { cause: error },
        );
    }
    validateProofStorageWidthStaticPreflightResult(parsedResult);
};

export const validateProofBackendBakeoffPreflightEvidenceArtifacts = async (
    input: Readonly<{
        attachmentPath: string;
        expectedCommitHash?: string;
        expectedMemoryLimitBytes: number;
    }>,
): Promise<ValidatedProofBackendBakeoffPreflightEvidence> => {
    const resolvedAttachmentPath = path.resolve(input.attachmentPath);
    const attachmentDirectoryPath = path.dirname(resolvedAttachmentPath);
    const runDirectoryPath = path.dirname(attachmentDirectoryPath);
    const exactAttachmentPath = path.join(
        runDirectoryPath,
        'attachments',
        evidenceFileName,
    );
    if (
        !path.isAbsolute(input.attachmentPath) ||
        resolvedAttachmentPath !== input.attachmentPath ||
        resolvedAttachmentPath !== exactAttachmentPath
    ) {
        throw new Error(
            'The proof backend bakeoff preflight evidence file is outside its exact run attachment location.',
        );
    }

    const evidenceContents = await readFile(resolvedAttachmentPath, 'utf8');
    let parsedEvidence: unknown;
    try {
        parsedEvidence = JSON.parse(evidenceContents) as unknown;
    } catch (error) {
        throw Object.assign(
            new Error(
                'The proof backend bakeoff preflight evidence file is not valid JSON.',
            ),
            { cause: error },
        );
    }
    const evidence = requireJsonObject(
        parsedEvidence,
        'Proof backend bakeoff preflight evidence',
    );
    if (evidence.formatVersion !== 5) {
        throw new Error(
            'The proof backend bakeoff preflight evidence format version must be 5.',
        );
    }
    if (
        evidence.resourceSampleIntervalMilliseconds !==
        resourceSampleIntervalMilliseconds
    ) {
        throw new Error(
            'The proof backend bakeoff preflight evidence must bind the exact 100 millisecond guard cadence.',
        );
    }
    const guardParameters = requireJsonObject(
        evidence.processMemoryGuard,
        'Proof backend bakeoff preflight process-memory guard parameters',
    );
    if (
        !Number.isSafeInteger(input.expectedMemoryLimitBytes) ||
        input.expectedMemoryLimitBytes <= 0 ||
        input.expectedMemoryLimitBytes % 1_073_741_824 !== 0
    ) {
        throw new Error(
            'The expected preflight process-memory limit must be a positive whole number of GiB.',
        );
    }
    if (
        guardParameters.memoryLimitBytes !== input.expectedMemoryLimitBytes ||
        guardParameters.memoryLimitGigabytes !==
            input.expectedMemoryLimitBytes / 1_073_741_824
    ) {
        throw new Error(
            'The proof backend bakeoff preflight evidence does not bind the expected process-memory guard.',
        );
    }

    const featureTestInventory = requireJsonObject(
        evidence.featureTestInventory,
        'Proof backend bakeoff preflight feature-test inventory',
    );
    requireExactStringArray({
        actual: featureTestInventory.allTestNames,
        description: 'The complete feature-test inventory',
        expected: proofBackendBakeoffFeatureTestNames,
    });
    requireExactStringArray({
        actual: featureTestInventory.ignoredTestNames,
        description: 'The ignored feature-test inventory',
        expected: proofBackendBakeoffIgnoredTestNames,
    });
    requireExactStringArray({
        actual: featureTestInventory.nonIgnoredTestNames,
        description: 'The non-ignored feature-test inventory',
        expected: proofBackendBakeoffNonIgnoredFeatureTestNames,
    });

    const repository = requireJsonObject(
        evidence.repository,
        'Proof backend bakeoff preflight repository binding',
    );
    const repositoryStateInitial = requireRepositoryState(
        repository.initial,
        'The initial repository state',
    );
    const repositoryStateBefore = requireRepositoryState(
        repository.before,
        'The before repository state',
    );
    const repositoryStateAfter = requireRepositoryState(
        repository.after,
        'The after repository state',
    );
    if (
        repositoryStateInitial.commitHash !==
            repositoryStateBefore.commitHash ||
        repositoryStateBefore.commitHash !== repositoryStateAfter.commitHash
    ) {
        throw new Error(
            'The proof backend bakeoff preflight repository bindings must use one exact commit.',
        );
    }
    if (
        input.expectedCommitHash !== undefined &&
        repositoryStateInitial.commitHash !== input.expectedCommitHash
    ) {
        throw new Error(
            'The proof backend bakeoff preflight evidence does not match the expected commit.',
        );
    }

    const completedFeatureTestPhase = requireJsonObject(
        evidence.completedFeatureTestPhase,
        'The completed non-ignored feature-test phase',
    );
    requireExactStringArray({
        actual: completedFeatureTestPhase.testNames,
        description: 'The completed non-ignored feature-test phase',
        expected: proofBackendBakeoffFilteredNonIgnoredFeatureTestNames,
    });
    await requireBoundGuardArtifact({
        artifact: completedFeatureTestPhase,
        artifactDescription: 'The non-ignored feature-test guard artifact',
        expectedRelativePath: featureTestDiagnosticsRelativePath,
        expectedMemoryLimitBytes: input.expectedMemoryLimitBytes,
        runDirectoryPath,
    });

    const completedStaticFeatureTest = requireJsonObject(
        evidence.completedStaticFeatureTest,
        'The completed proof-storage width static feature test',
    );
    if (
        completedStaticFeatureTest.testName !==
        proofStorageWidthStaticPreflightTestName
    ) {
        throw new Error(
            'The completed proof-storage width static feature test does not match its exact registered test.',
        );
    }
    await requireBoundGuardArtifact({
        artifact: completedStaticFeatureTest,
        artifactDescription:
            'The proof-storage width static feature-test guard artifact',
        expectedRelativePath: staticFeatureTestDiagnosticsRelativePath,
        expectedMemoryLimitBytes: input.expectedMemoryLimitBytes,
        runDirectoryPath,
    });
    await requireBoundStaticPreflightResult({
        artifact: completedStaticFeatureTest,
        runDirectoryPath,
    });

    if (
        !Array.isArray(evidence.completedTests) ||
        evidence.completedTests.length !==
            proofBackendBakeoffPreflightTestNames.length
    ) {
        throw new Error(
            'The proof backend bakeoff preflight evidence must contain exactly three completed ignored owners.',
        );
    }
    for (const [
        testIndex,
        expectedTestName,
    ] of proofBackendBakeoffPreflightTestNames.entries()) {
        const completedTest = requireJsonObject(
            evidence.completedTests[testIndex],
            `Completed ignored owner ${testIndex + 1}`,
        );
        if (completedTest.testName !== expectedTestName) {
            throw new Error(
                `Completed ignored owner ${testIndex + 1} does not match its exact registered test.`,
            );
        }
        await requireBoundGuardArtifact({
            artifact: completedTest,
            artifactDescription: `Completed ignored owner ${testIndex + 1} guard artifact`,
            expectedRelativePath:
                preflightTestDiagnosticsRelativePath(expectedTestName),
            expectedMemoryLimitBytes: input.expectedMemoryLimitBytes,
            runDirectoryPath,
        });
    }

    return {
        attachmentPath: resolvedAttachmentPath,
        commitHash: repositoryStateInitial.commitHash,
    };
};

export const executeProofBackendBakeoffPreflightSequence = async (input: {
    readonly dependencies?: ProofBackendBakeoffPreflightRunnerDependencies;
    readonly runLog: ActiveLocalRunLog;
}): Promise<ProofBackendBakeoffPreflightRunResult> => {
    const configuredTestCount = Array.from(
        proofBackendBakeoffPreflightTestNames,
    ).length;
    if (configuredTestCount !== 3) {
        throw new Error(
            `The proof backend bakeoff preflight requires exactly three configured tests, but received ${configuredTestCount}.`,
        );
    }
    const configuredNonIgnoredFeatureTestCount = Array.from(
        proofBackendBakeoffNonIgnoredFeatureTestNames,
    ).length;
    const configuredIgnoredTestCount = Array.from(
        proofBackendBakeoffIgnoredTestNames,
    ).length;
    const configuredFeatureTestCount = Array.from(
        proofBackendBakeoffFeatureTestNames,
    ).length;
    const distinctFeatureTestCount = new Set(
        proofBackendBakeoffFeatureTestNames,
    ).size;
    if (
        configuredNonIgnoredFeatureTestCount !== 35 ||
        configuredIgnoredTestCount !== 3 ||
        configuredFeatureTestCount !== 38 ||
        distinctFeatureTestCount !== configuredFeatureTestCount
    ) {
        throw new Error(
            `The proof backend bakeoff feature-test registry requires exactly 35 non-ignored and 3 ignored distinct tests, but received ${configuredNonIgnoredFeatureTestCount} non-ignored, ${configuredIgnoredTestCount} ignored, ${configuredFeatureTestCount} total, and ${distinctFeatureTestCount} distinct.`,
        );
    }
    const executeCommand =
        input.dependencies?.executeCommand ?? defaultCommandExecutor;
    const processMemoryGuard =
        input.dependencies?.processMemoryGuard ??
        createProcessMemoryGuard({
            insufficientFreeMemoryRunDescription:
                'Proof backend bakeoff preflight',
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
    requireCleanRepository(repositoryStateInitial, 'initial');

    const cargoEnvironment = buildProofBackendBakeoffEnvironment();
    delete cargoEnvironment[staticPreflightResultPathEnvironmentVariable];
    await executeRequiredCommand({
        command: buildProofBackendBakeoffPrecompileCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    const featureListResult = await executeRequiredCommand({
        command: buildProofBackendBakeoffFeatureListCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    const staticFeatureListResult = await executeRequiredCommand({
        command:
            buildProofStorageWidthStaticFeatureListCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    parseProofBackendBakeoffFeatureInventory(
        `${featureListResult.stdout}\n${staticFeatureListResult.stdout}`,
    );
    const listResult = await executeRequiredCommand({
        command: buildProofBackendBakeoffPreflightListCommand(cargoEnvironment),
        executeCommand,
        runLog: input.runLog,
    });
    const exactTestNames = parseProofBackendBakeoffPreflightInventory(
        listResult.stdout,
    );
    await executeRequiredCommand({
        command: processMemoryGuard.buildVerificationCommand(),
        executeCommand,
        runLog: input.runLog,
    });

    const repositoryStateBefore = await readRepositoryState(
        'before',
        input.runLog,
    );
    requireCleanRepository(repositoryStateBefore, 'before');
    requireSameCommit({
        actual: repositoryStateBefore,
        expected: repositoryStateInitial,
        intervalDescription: 'during proof backend bakeoff preflight inventory',
    });

    const resourceDirectoryPath = path.join(
        input.runLog.runDirectoryPath,
        'resources',
    );
    const attachmentDirectoryPath = path.join(
        input.runLog.runDirectoryPath,
        'attachments',
    );
    await Promise.all([
        mkdir(attachmentDirectoryPath, { recursive: true }),
        mkdir(resourceDirectoryPath, { recursive: true }),
    ]);
    const staticFeatureTestResultPath = path.join(
        attachmentDirectoryPath,
        staticFeatureTestResultFileName,
    );
    await requirePathDoesNotExist(staticFeatureTestResultPath);
    const completedTests: Array<
        Readonly<{
            diagnosticsPath: string;
            diagnosticsSha256Hex: string;
            testName: ProofBackendBakeoffPreflightTestName;
        }>
    > = [];
    const featureTestDiagnosticsPath = path.join(
        resourceDirectoryPath,
        featureTestDiagnosticsFileName,
    );
    const guardedFeatureTestCommand = processMemoryGuard.guardCommand(
        buildProofBackendBakeoffFeatureTestCommand(cargoEnvironment),
        {
            diagnosticsPath: featureTestDiagnosticsPath,
            resourceSampleIntervalMilliseconds,
        },
    );
    await executeRequiredCommand({
        command: guardedFeatureTestCommand,
        executeCommand,
        runLog: input.runLog,
    });
    const featureTestDiagnosticsSha256Hex =
        await readAndValidateCompletedProcessMemoryGuardArtifact({
            diagnosticsPath: featureTestDiagnosticsPath,
            expectedMemoryLimitBytes: processMemoryGuard.memoryLimitBytes,
        });
    const completedFeatureTestPhase = {
        diagnosticsPath: relativeDiagnosticPath(
            input.runLog.runDirectoryPath,
            featureTestDiagnosticsPath,
        ),
        diagnosticsSha256Hex: featureTestDiagnosticsSha256Hex,
        testNames: proofBackendBakeoffFilteredNonIgnoredFeatureTestNames,
    };
    input.runLog.writeEvent({
        details: completedFeatureTestPhase,
        eventType: 'proof-backend-bakeoff-preflight-feature-tests-completed',
    });
    const staticFeatureTestDiagnosticsPath = path.join(
        resourceDirectoryPath,
        staticFeatureTestDiagnosticsFileName,
    );
    const guardedStaticFeatureTestCommand = processMemoryGuard.guardCommand(
        buildProofStorageWidthStaticFeatureTestCommand({
            environment: cargoEnvironment,
            resultPath: staticFeatureTestResultPath,
        }),
        {
            diagnosticsPath: staticFeatureTestDiagnosticsPath,
            resourceSampleIntervalMilliseconds,
        },
    );
    await executeRequiredCommand({
        command: guardedStaticFeatureTestCommand,
        executeCommand,
        runLog: input.runLog,
    });
    const staticFeatureTestResultSha256Hex =
        await readAndValidateStaticPreflightResult({
            resultPath: staticFeatureTestResultPath,
        });
    const staticFeatureTestDiagnosticsSha256Hex =
        await readAndValidateCompletedProcessMemoryGuardArtifact({
            diagnosticsPath: staticFeatureTestDiagnosticsPath,
            expectedMemoryLimitBytes: processMemoryGuard.memoryLimitBytes,
        });
    const completedStaticFeatureTest = {
        diagnosticsPath: relativeDiagnosticPath(
            input.runLog.runDirectoryPath,
            staticFeatureTestDiagnosticsPath,
        ),
        diagnosticsSha256Hex: staticFeatureTestDiagnosticsSha256Hex,
        resultPath: relativeDiagnosticPath(
            input.runLog.runDirectoryPath,
            staticFeatureTestResultPath,
        ),
        resultSha256Hex: staticFeatureTestResultSha256Hex,
        testName: proofStorageWidthStaticPreflightTestName,
    };
    input.runLog.writeEvent({
        details: completedStaticFeatureTest,
        eventType:
            'proof-backend-bakeoff-preflight-static-feature-test-completed',
    });
    for (const exactTestName of exactTestNames) {
        const diagnosticsPath = path.join(
            resourceDirectoryPath,
            preflightTestDiagnosticsFileName(exactTestName),
        );
        const guardedCommand = processMemoryGuard.guardCommand(
            buildProofBackendBakeoffPreflightTestCommand({
                environment: cargoEnvironment,
                exactTestName,
            }),
            {
                diagnosticsPath,
                resourceSampleIntervalMilliseconds,
            },
        );
        await executeRequiredCommand({
            command: guardedCommand,
            executeCommand,
            runLog: input.runLog,
        });
        const diagnosticsSha256Hex =
            await readAndValidateCompletedProcessMemoryGuardArtifact({
                diagnosticsPath,
                expectedMemoryLimitBytes: processMemoryGuard.memoryLimitBytes,
            });
        completedTests.push({
            diagnosticsPath: relativeDiagnosticPath(
                input.runLog.runDirectoryPath,
                diagnosticsPath,
            ),
            diagnosticsSha256Hex,
            testName: exactTestName,
        });
        input.runLog.writeEvent({
            details: {
                diagnosticsPath,
                testName: exactTestName,
            },
            eventType: 'proof-backend-bakeoff-preflight-test-completed',
        });
    }

    const repositoryStateAfter = await readRepositoryState(
        'after',
        input.runLog,
    );
    requireCleanRepository(repositoryStateAfter, 'after');
    requireSameCommit({
        actual: repositoryStateAfter,
        expected: repositoryStateBefore,
        intervalDescription: 'during proof backend bakeoff preflight execution',
    });

    const attachmentPath = path.join(attachmentDirectoryPath, evidenceFileName);
    await writeJsonAtomicallyAndExclusively(attachmentPath, {
        completedFeatureTestPhase,
        completedStaticFeatureTest,
        completedTests,
        featureTestInventory: {
            allTestNames: proofBackendBakeoffFeatureTestNames,
            ignoredTestNames: proofBackendBakeoffIgnoredTestNames,
            nonIgnoredTestNames: proofBackendBakeoffNonIgnoredFeatureTestNames,
        },
        formatVersion: 5,
        processMemoryGuard: {
            memoryLimitBytes: processMemoryGuard.memoryLimitBytes,
            memoryLimitGigabytes: processMemoryGuard.memoryLimitGigabytes,
        },
        repository: {
            after: repositoryStateAfter,
            before: repositoryStateBefore,
            initial: repositoryStateInitial,
        },
        resourceSampleIntervalMilliseconds,
    });
    await validateProofBackendBakeoffPreflightEvidenceArtifacts({
        attachmentPath,
        expectedCommitHash: repositoryStateInitial.commitHash,
        expectedMemoryLimitBytes: processMemoryGuard.memoryLimitBytes,
    });
    input.runLog.writeEvent({
        details: { attachmentPath },
        eventType: 'proof-backend-bakeoff-preflight-completed',
    });
    const evidenceMessage = `Proof backend bakeoff preflight evidence: ${attachmentPath}\n`;
    process.stdout.write(evidenceMessage);
    input.runLog.writeCombinedOutput(evidenceMessage);

    return { attachmentPath };
};

export const runProofBackendBakeoffPreflight = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    const effectiveArguments = rawArguments.filter(
        (argument) => argument !== '--',
    );
    if (effectiveArguments.length !== 0) {
        throw new Error(
            'The proof backend bakeoff preflight runner accepts no arguments.',
        );
    }
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: [laneLabel],
            scriptName,
        },
        async (runLog) => {
            await withLocalHeavyLaneLease({
                action: () =>
                    executeProofBackendBakeoffPreflightSequence({ runLog }),
                laneLabel,
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runProofBackendBakeoffPreflight();
}
