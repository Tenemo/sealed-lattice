import { createHash } from 'node:crypto';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import { buildProofStorageWidthStaticPreflightFixture } from '#tests/support/proof-storage-width-static-preflight';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log';
import type { ProcessMemoryGuard } from '#tools/ci/process-memory-guard';
import type {
    CapturedCommandResult,
    CommandInvocation,
} from '#tools/ci/run-command';
import { buildProofBackendBakeoffEnvironment } from '#tools/ci/run-proof-backend-bakeoff';
import {
    buildProofBackendBakeoffFeatureListCommand,
    buildProofBackendBakeoffFeatureTestCommand,
    buildProofBackendBakeoffPreflightListCommand,
    buildProofBackendBakeoffPreflightTestCommand,
    buildProofStorageWidthStaticFeatureListCommand,
    buildProofStorageWidthStaticFeatureTestCommand,
    executeProofBackendBakeoffPreflightSequence,
    parseProofBackendBakeoffFeatureInventory,
    parseProofBackendBakeoffPreflightInventory,
    proofBackendBakeoffFeatureTestNames,
    proofBackendBakeoffIgnoredTestNames,
    proofBackendBakeoffNonIgnoredFeatureTestNames,
    proofBackendBakeoffPreflightTestNames,
    proofStorageWidthStaticPreflightTestName,
    type ProofBackendBakeoffPreflightRunnerDependencies,
    validateProofBackendBakeoffPreflightEvidenceArtifacts,
} from '#tools/ci/run-proof-backend-bakeoff-preflight';

const commitHash = '12'.repeat(20);
const memoryLimitBytes = 1_073_741_824;
const staticPreflightResultPathEnvironmentVariable =
    'SEALED_LATTICE_PROOF_STORAGE_WIDTH_STATIC_PREFLIGHT_RESULT_PATH';
const staticPreflightFixture = buildProofStorageWidthStaticPreflightFixture();

type MutableBoundGuardArtifact = {
    diagnosticsPath: string;
    diagnosticsSha256Hex: string;
};

type MutablePreflightEvidence = {
    completedFeatureTestPhase: MutableBoundGuardArtifact;
    completedStaticFeatureTest: MutableBoundGuardArtifact & {
        resultPath: string;
        resultSha256Hex: string;
        testName: string;
    };
    completedTests: MutableBoundGuardArtifact[];
    formatVersion: number;
};

const completeFeatureInventoryOutput = (): string =>
    proofBackendBakeoffFeatureTestNames
        .map((testName) => `${testName}: test`)
        .join('\n');

const completeFilteredFeatureInventoryOutput = (): string =>
    proofBackendBakeoffFeatureTestNames
        .filter(
            (testName) => testName !== proofStorageWidthStaticPreflightTestName,
        )
        .map((testName) => `${testName}: test`)
        .join('\n');

const completeStaticFeatureInventoryOutput = (): string =>
    `${proofStorageWidthStaticPreflightTestName}: test`;

const completeIgnoredInventoryOutput = (): string =>
    proofBackendBakeoffIgnoredTestNames
        .map((testName) => `${testName}: test`)
        .join('\n');

const withTemporaryDirectory = async <Result>(
    action: (directoryPath: string) => Promise<Result>,
): Promise<Result> => {
    const directoryPath = await mkdtemp(
        path.join(
            os.tmpdir(),
            'sealed-lattice-proof-backend-bakeoff-preflight-',
        ),
    );
    try {
        return await action(directoryPath);
    } finally {
        await rm(directoryPath, { force: true, recursive: true });
    }
};

const successfulCommandResult = (
    standardOutput = '',
): CapturedCommandResult => ({
    exitCode: 0,
    stderr: '',
    stdout: standardOutput,
    terminationSignal: null,
});

const failedCommandResult = (): CapturedCommandResult => ({
    exitCode: 1,
    stderr: 'intentional preflight test failure',
    stdout: '',
    terminationSignal: null,
});

const validGuardJsonLines = (): string =>
    [
        {
            aggregateProcessTreeMemoryLimit: true,
            elapsedMilliseconds: 0,
            eventType: 'guard-started',
            memoryLimitBytes,
            recordedAtUnixMilliseconds: 1_000,
            resourceSampleIntervalMilliseconds: 100,
            sequence: 0,
        },
        {
            elapsedMilliseconds: 1,
            eventType: 'child-started',
            recordedAtUnixMilliseconds: 1_001,
            sequence: 1,
        },
        {
            confirmedMemoryLimitViolation: false,
            elapsedMilliseconds: 2,
            eventType: 'resource-sample',
            processTreeResidentMemoryBytes: 65_536,
            recordedAtUnixMilliseconds: 1_002,
            sampleError: null,
            sequence: 2,
        },
        {
            elapsedMilliseconds: 3,
            eventType: 'child-exited',
            exitCode: 0,
            memoryEvidence: 'completed',
            recordedAtUnixMilliseconds: 1_003,
            sequence: 3,
            terminationClassification: 'completed',
        },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');

const writeValidGuardArtifact = async (
    invocation: CommandInvocation,
    diagnosticsContents = validGuardJsonLines(),
): Promise<void> => {
    const diagnosticsPathArgumentIndex =
        invocation.args.indexOf('--diagnostics-path');
    const diagnosticsPath = invocation.args[diagnosticsPathArgumentIndex + 1];
    if (
        diagnosticsPathArgumentIndex < 0 ||
        diagnosticsPath === undefined ||
        diagnosticsPath.length === 0
    ) {
        throw new Error('The fake guarded command lacks a diagnostics path.');
    }
    await mkdir(path.dirname(diagnosticsPath), { recursive: true });
    await writeFile(diagnosticsPath, diagnosticsContents, 'utf8');
};

const createRunLog = (runDirectoryPath: string): ActiveLocalRunLog => ({
    createCommandLogFiles: ({ preferredSlug }) => ({
        combinedPath: path.join(
            runDirectoryPath,
            `${preferredSlug ?? 'command'}.log`,
        ),
        commandId: preferredSlug ?? 'command',
    }),
    finish: () => Promise.resolve(),
    runDirectoryPath,
    writeCombinedOutput: () => undefined,
    writeCommandOutput: () => undefined,
    writeEvent: () => undefined,
});

const createProcessMemoryGuard = (): ProcessMemoryGuard => ({
    buildVerificationCommand: () => ({
        args: ['verify'],
        command: 'test-process-memory-guard-verification',
        description: 'verify test process memory guard',
    }),
    guardCommand: (command, options = {}) => ({
        ...command,
        args: [
            '--diagnostics-path',
            options.diagnosticsPath ?? '',
            '--resource-sample-interval-milliseconds',
            String(options.resourceSampleIntervalMilliseconds ?? ''),
            '--',
            command.command,
            ...command.args,
        ],
        command: 'test-process-memory-guard',
        description: `guarded ${command.description}`,
    }),
    memoryLimitBytes: 1_073_741_824,
    memoryLimitGigabytes: 1,
});

const createSequenceDependencies = (input: {
    readonly featureInventoryOutput?: string;
    readonly failGuardedTestAtIndex?: number;
    readonly failPrecompile?: boolean;
    readonly ignoredInventoryOutput?: string;
    readonly invalidGuardAtIndex?: number;
    readonly invalidStaticPreflightResult?: boolean;
    readonly invocations: CommandInvocation[];
    readonly omitStaticPreflightCustodyModel?: boolean;
    readonly omitStaticPreflightResult?: boolean;
    readonly repositoryStates?: readonly {
        readonly commitHash: string;
        readonly treeDirty: boolean;
    }[];
    readonly staticFeatureInventoryOutput?: string;
}): ProofBackendBakeoffPreflightRunnerDependencies => {
    let guardedTestIndex = 0;
    let repositoryStateIndex = 0;
    return {
        executeCommand: async (invocation) => {
            input.invocations.push(invocation);
            if (
                input.failPrecompile === true &&
                invocation.description ===
                    'precompile the release proof backend bakeoff fragment'
            ) {
                return failedCommandResult();
            }
            if (
                invocation.description ===
                'list the proof backend bakeoff feature tests'
            ) {
                return successfulCommandResult(
                    input.featureInventoryOutput ??
                        completeFilteredFeatureInventoryOutput(),
                );
            }
            if (
                invocation.description ===
                'list the proof-storage width static feature test'
            ) {
                return successfulCommandResult(
                    input.staticFeatureInventoryOutput ??
                        completeStaticFeatureInventoryOutput(),
                );
            }
            if (
                invocation.description ===
                'list the proof backend bakeoff ignored owners'
            ) {
                return successfulCommandResult(
                    input.ignoredInventoryOutput ??
                        completeIgnoredInventoryOutput(),
                );
            }
            if (invocation.command === 'test-process-memory-guard') {
                const currentGuardedTestIndex = guardedTestIndex;
                guardedTestIndex += 1;
                if (currentGuardedTestIndex === input.failGuardedTestAtIndex) {
                    return failedCommandResult();
                }
                if (
                    invocation.description ===
                        'guarded run the proof-storage width static non-ignored feature test' &&
                    input.omitStaticPreflightResult !== true
                ) {
                    const staticPreflightResultPath =
                        invocation.env?.[
                            staticPreflightResultPathEnvironmentVariable
                        ];
                    if (staticPreflightResultPath === undefined) {
                        throw new Error(
                            'The fake static feature test lacks its result path.',
                        );
                    }
                    await mkdir(path.dirname(staticPreflightResultPath), {
                        recursive: true,
                    });
                    await writeFile(
                        staticPreflightResultPath,
                        JSON.stringify(
                            input.invalidStaticPreflightResult === true
                                ? {
                                      ...staticPreflightFixture,
                                      formatVersion: 2,
                                  }
                                : input.omitStaticPreflightCustodyModel === true
                                  ? Object.fromEntries(
                                        Object.entries(
                                            staticPreflightFixture,
                                        ).filter(
                                            ([fieldName]) =>
                                                fieldName !== 'custodyModel',
                                        ),
                                    )
                                  : staticPreflightFixture,
                        ),
                        { encoding: 'utf8', flag: 'wx' },
                    );
                }
                await writeValidGuardArtifact(
                    invocation,
                    currentGuardedTestIndex === input.invalidGuardAtIndex
                        ? validGuardJsonLines().replace(
                              '"sampleError":null',
                              '"sampleError":"intentional invalid guard"',
                          )
                        : validGuardJsonLines(),
                );
                return successfulCommandResult();
            }
            return successfulCommandResult();
        },
        processMemoryGuard: createProcessMemoryGuard(),
        readRepositoryState: () => {
            const repositoryState = input.repositoryStates?.[
                repositoryStateIndex
            ] ?? {
                commitHash,
                treeDirty: false,
            };
            repositoryStateIndex += 1;
            return Promise.resolve(repositoryState);
        },
    };
};

const guardedInvocations = (
    invocations: readonly CommandInvocation[],
): readonly CommandInvocation[] =>
    invocations.filter(
        (invocation) => invocation.command === 'test-process-memory-guard',
    );

describe('Proof backend bakeoff preflight runner', () => {
    it('pins the feature phase and one exact ignored owner per fresh guarded command', () => {
        const environment = buildProofBackendBakeoffEnvironment({
            baseEnvironment: {
                SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND:
                    'inherited-backend',
                SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_RESULT_PATH:
                    'inherited-result',
                SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL: '2',
            },
            targetDirectoryPath: 'dedicated-target',
        });
        const featureListCommand =
            buildProofBackendBakeoffFeatureListCommand(environment);
        expect(featureListCommand.args).toEqual(
            expect.arrayContaining([
                '--locked',
                '--release',
                '--features',
                'proof-storage-width-evidence',
                '--lib',
                '--list',
            ]),
        );
        expect(featureListCommand.args).toContain(
            'bgv::proof_suite::proof_backend_bakeoff',
        );
        expect(featureListCommand.args).not.toContain('--ignored');

        const ignoredListCommand =
            buildProofBackendBakeoffPreflightListCommand(environment);
        expect(ignoredListCommand.args).toEqual(
            expect.arrayContaining([
                '--locked',
                '--release',
                '--features',
                'proof-storage-width-evidence',
                '--lib',
                '--ignored',
                '--list',
            ]),
        );
        expect(ignoredListCommand.args).toContain(
            'bgv::proof_suite::proof_backend_bakeoff',
        );

        const featureTestCommand =
            buildProofBackendBakeoffFeatureTestCommand(environment);
        expect(featureTestCommand.args).toContain(
            'bgv::proof_suite::proof_backend_bakeoff',
        );
        expect(featureTestCommand.args).toContain('--nocapture');
        expect(featureTestCommand.args).not.toContain('--exact');
        expect(featureTestCommand.args).not.toContain('--ignored');
        expect(featureTestCommand.env).not.toHaveProperty(
            'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND',
        );
        expect(featureTestCommand.env).not.toHaveProperty(
            'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL',
        );

        const staticFeatureListCommand =
            buildProofStorageWidthStaticFeatureListCommand(environment);
        expect(staticFeatureListCommand.args).toEqual(
            expect.arrayContaining([
                '--features',
                'proof-storage-width-evidence',
                proofStorageWidthStaticPreflightTestName,
                '--exact',
                '--list',
            ]),
        );
        const staticFeatureTestResultPath = path.resolve(
            'proof-storage-width-static-feature-result.json',
        );
        const staticFeatureTestCommand =
            buildProofStorageWidthStaticFeatureTestCommand({
                environment,
                resultPath: staticFeatureTestResultPath,
            });
        expect(staticFeatureTestCommand.args).toEqual(
            expect.arrayContaining([
                '--features',
                'proof-storage-width-evidence',
                proofStorageWidthStaticPreflightTestName,
                '--exact',
                '--nocapture',
            ]),
        );
        expect(staticFeatureTestCommand.args).not.toContain('--ignored');
        expect(staticFeatureTestCommand.env).toMatchObject({
            [staticPreflightResultPathEnvironmentVariable]:
                staticFeatureTestResultPath,
        });
        expect(() =>
            buildProofStorageWidthStaticFeatureTestCommand({
                environment,
                resultPath: 'relative-static-feature-result.json',
            }),
        ).toThrow(/exact absolute path/u);

        for (const exactTestName of proofBackendBakeoffPreflightTestNames) {
            const testCommand = buildProofBackendBakeoffPreflightTestCommand({
                environment,
                exactTestName,
            });
            expect(testCommand.args).toContain(exactTestName);
            expect(testCommand.args).toContain('--exact');
            expect(testCommand.args).toContain('--ignored');
            expect(testCommand.env).not.toHaveProperty(
                'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND',
            );
            expect(testCommand.env).not.toHaveProperty(
                'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL',
            );
        }
        expect(() =>
            buildProofBackendBakeoffPreflightTestCommand({
                environment,
                exactTestName: 'retired::unregistered::measurement_owner',
            }),
        ).toThrow(/unregistered test/u);
    });

    it('requires the exact disjoint feature and ignored inventories', () => {
        expect(proofBackendBakeoffNonIgnoredFeatureTestNames).toHaveLength(35);
        expect(proofBackendBakeoffIgnoredTestNames).toHaveLength(3);
        expect(proofBackendBakeoffFeatureTestNames).toHaveLength(38);
        expect(new Set(proofBackendBakeoffFeatureTestNames)).toHaveProperty(
            'size',
            38,
        );
        expect(proofBackendBakeoffNonIgnoredFeatureTestNames).toContain(
            'bgv::proof_suite::proof_backend_bakeoff_fri::canonical_artifact_write_failure_removes_every_partial_custody_object',
        );
        expect(proofBackendBakeoffNonIgnoredFeatureTestNames).toContain(
            'bgv::proof_suite::proof_backend_bakeoff_fri::fresh_public_base_replay_refuses_source_and_statement_root_equivocation',
        );
        expect(proofBackendBakeoffNonIgnoredFeatureTestNames).toContain(
            'bgv::proof_suite::proof_backend_bakeoff_fri::proof_storage_width_browser_evidence::tests::fresh_verifier_refuses_cross_pass_identity_equivocation_and_wrong_base_root',
        );
        expect(proofBackendBakeoffNonIgnoredFeatureTestNames).toContain(
            'bgv::proof_suite::proof_backend_bakeoff_fri::proof_storage_width_browser_evidence::tests::occupied_registry_refuses_before_constructing_another_operation',
        );
        expect(proofBackendBakeoffNonIgnoredFeatureTestNames).toContain(
            proofStorageWidthStaticPreflightTestName,
        );
        const ignoredTestNameSet = new Set<string>(
            proofBackendBakeoffIgnoredTestNames,
        );
        expect(
            proofBackendBakeoffNonIgnoredFeatureTestNames.filter((testName) =>
                ignoredTestNameSet.has(testName),
            ),
        ).toEqual([]);

        expect(
            parseProofBackendBakeoffFeatureInventory(
                `${completeFeatureInventoryOutput()}\n`,
            ),
        ).toHaveLength(38);
        expect(
            parseProofBackendBakeoffPreflightInventory(
                `${completeIgnoredInventoryOutput()}\n`,
            ),
        ).toEqual(proofBackendBakeoffPreflightTestNames);

        for (const [parser, completeOutput, missingInventory] of [
            [
                parseProofBackendBakeoffFeatureInventory,
                completeFeatureInventoryOutput(),
                proofBackendBakeoffFeatureTestNames.slice(1),
            ],
            [
                parseProofBackendBakeoffPreflightInventory,
                completeIgnoredInventoryOutput(),
                proofBackendBakeoffIgnoredTestNames.slice(1),
            ],
        ] as const) {
            expect(() => parser('')).toThrow(/selected zero tests/u);
            expect(() =>
                parser(
                    missingInventory
                        .map((testName) => `${testName}: test`)
                        .join('\n'),
                ),
            ).toThrow(/Missing:/u);
            expect(() =>
                parser(`${completeOutput}\nother::test_owner: test\n`),
            ).toThrow(/Extra: other::test_owner/u);
            expect(() =>
                parser(`${completeOutput}\n${missingInventory[0]}: test\n`),
            ).toThrow(/duplicate tests/u);
            expect(() =>
                parser(`${completeOutput}\nother::benchmark: benchmark\n`),
            ).toThrow(/unexpectedly selected benchmarks/u);
        }
    });

    it('runs both non-ignored feature phases before exactly three guarded owners and pins evidence', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            const result = await executeProofBackendBakeoffPreflightSequence({
                dependencies: createSequenceDependencies({ invocations }),
                runLog: createRunLog(runDirectoryPath),
            });
            const guardedCommands = guardedInvocations(invocations);
            expect(guardedCommands).toHaveLength(5);
            const precompileIndex = invocations.findIndex(
                (invocation) =>
                    invocation.description ===
                    'precompile the release proof backend bakeoff fragment',
            );
            expect(invocations[precompileIndex]?.args).toEqual(
                expect.arrayContaining([
                    '--features',
                    'proof-storage-width-evidence',
                    '--no-run',
                ]),
            );
            const featureListIndex = invocations.findIndex(
                (invocation) =>
                    invocation.description ===
                    'list the proof backend bakeoff feature tests',
            );
            const ignoredListIndex = invocations.findIndex(
                (invocation) =>
                    invocation.description ===
                    'list the proof backend bakeoff ignored owners',
            );
            const staticFeatureListIndex = invocations.findIndex(
                (invocation) =>
                    invocation.description ===
                    'list the proof-storage width static feature test',
            );
            const featurePhaseIndex = invocations.findIndex(
                (invocation) =>
                    invocation.description ===
                    'guarded run the proof backend bakeoff non-ignored feature tests',
            );
            const staticFeaturePhaseIndex = invocations.findIndex(
                (invocation) =>
                    invocation.description ===
                    'guarded run the proof-storage width static non-ignored feature test',
            );
            expect(precompileIndex).toBeGreaterThanOrEqual(0);
            expect(featureListIndex).toBeGreaterThan(precompileIndex);
            expect(staticFeatureListIndex).toBeGreaterThan(featureListIndex);
            expect(ignoredListIndex).toBeGreaterThan(staticFeatureListIndex);
            expect(featurePhaseIndex).toBeGreaterThan(ignoredListIndex);
            expect(staticFeaturePhaseIndex).toBeGreaterThan(featurePhaseIndex);
            expect(guardedCommands[0]?.args).not.toContain('--ignored');
            expect(guardedCommands[1]?.args).toContain(
                proofStorageWidthStaticPreflightTestName,
            );
            expect(guardedCommands[1]?.args).not.toContain('--ignored');
            const staticFeatureTestResultPath =
                guardedCommands[1]?.env?.[
                    staticPreflightResultPathEnvironmentVariable
                ];
            expect(staticFeatureTestResultPath).toBe(
                path.join(
                    runDirectoryPath,
                    'attachments',
                    'proof-backend-bakeoff-preflight-width-static-result.json',
                ),
            );
            expect(staticFeatureTestResultPath).not.toBe(
                path.join(
                    runDirectoryPath,
                    'attachments',
                    'proof-storage-width',
                    'proof-storage-width-static-preflight.json',
                ),
            );
            expect(
                guardedCommands
                    .filter((_, commandIndex) => commandIndex !== 1)
                    .every(
                        (command) =>
                            command.env?.[
                                staticPreflightResultPathEnvironmentVariable
                            ] === undefined,
                    ),
            ).toBe(true);
            if (staticFeatureTestResultPath === undefined) {
                throw new Error(
                    'The static feature-test result path is absent.',
                );
            }
            expect(
                JSON.parse(await readFile(staticFeatureTestResultPath, 'utf8')),
            ).toEqual(staticPreflightFixture);
            expect(
                guardedCommands
                    .slice(2)
                    .map((command) =>
                        proofBackendBakeoffPreflightTestNames.find((testName) =>
                            command.args.includes(testName),
                        ),
                    ),
            ).toEqual(proofBackendBakeoffPreflightTestNames);
            expect(
                guardedCommands.every(
                    (command) =>
                        command.env?.[
                            'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND'
                        ] === undefined &&
                        command.env?.[
                            'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL'
                        ] === undefined,
                ),
            ).toBe(true);

            const evidence = JSON.parse(
                await readFile(result.attachmentPath, 'utf8'),
            ) as {
                readonly completedFeatureTestPhase: {
                    readonly diagnosticsPath: string;
                    readonly diagnosticsSha256Hex: string;
                    readonly testNames: readonly string[];
                };
                readonly completedStaticFeatureTest: {
                    readonly diagnosticsPath: string;
                    readonly diagnosticsSha256Hex: string;
                    readonly resultPath: string;
                    readonly resultSha256Hex: string;
                    readonly testName: string;
                };
                readonly completedTests: readonly {
                    readonly diagnosticsPath: string;
                    readonly diagnosticsSha256Hex: string;
                    readonly testName: string;
                }[];
                readonly featureTestInventory: {
                    readonly allTestNames: readonly string[];
                    readonly ignoredTestNames: readonly string[];
                    readonly nonIgnoredTestNames: readonly string[];
                };
                readonly formatVersion: number;
                readonly repository: {
                    readonly after: { readonly commitHash: string };
                    readonly before: { readonly commitHash: string };
                    readonly initial: { readonly commitHash: string };
                };
                readonly processMemoryGuard: {
                    readonly memoryLimitBytes: number;
                    readonly memoryLimitGigabytes: number;
                };
            };
            expect(
                evidence.completedTests.map((test) => test.testName),
            ).toEqual(proofBackendBakeoffPreflightTestNames);
            expect(evidence.completedFeatureTestPhase.testNames).toEqual(
                proofBackendBakeoffNonIgnoredFeatureTestNames.filter(
                    (testName) =>
                        testName !== proofStorageWidthStaticPreflightTestName,
                ),
            );
            expect(evidence.completedFeatureTestPhase.diagnosticsPath).toMatch(
                /preflight-feature-tests\.jsonl$/u,
            );
            expect(
                evidence.completedFeatureTestPhase.diagnosticsSha256Hex,
            ).toMatch(/^[0-9a-f]{64}$/u);
            expect(evidence.completedStaticFeatureTest).toMatchObject({
                testName: proofStorageWidthStaticPreflightTestName,
            });
            expect(evidence.completedStaticFeatureTest.diagnosticsPath).toMatch(
                /preflight-width-static-test\.jsonl$/u,
            );
            expect(
                evidence.completedStaticFeatureTest.diagnosticsSha256Hex,
            ).toMatch(/^[0-9a-f]{64}$/u);
            expect(evidence.completedStaticFeatureTest.resultPath).toBe(
                'attachments/proof-backend-bakeoff-preflight-width-static-result.json',
            );
            expect(evidence.completedStaticFeatureTest.resultSha256Hex).toBe(
                createHash('sha256')
                    .update(await readFile(staticFeatureTestResultPath))
                    .digest('hex'),
            );
            expect(
                evidence.completedTests.every(
                    (completedTest) =>
                        /^[0-9a-f]{64}$/u.test(
                            completedTest.diagnosticsSha256Hex,
                        ) &&
                        completedTest.diagnosticsPath.startsWith('resources/'),
                ),
            ).toBe(true);
            expect(evidence.featureTestInventory).toEqual({
                allTestNames: proofBackendBakeoffFeatureTestNames,
                ignoredTestNames: proofBackendBakeoffIgnoredTestNames,
                nonIgnoredTestNames:
                    proofBackendBakeoffNonIgnoredFeatureTestNames,
            });
            expect(evidence.formatVersion).toBe(5);
            expect(evidence.repository).toEqual({
                after: { commitHash, treeDirty: false },
                before: { commitHash, treeDirty: false },
                initial: { commitHash, treeDirty: false },
            });
            expect(evidence.processMemoryGuard).toEqual({
                memoryLimitBytes: 1_073_741_824,
                memoryLimitGigabytes: 1,
            });
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedCommitHash: commitHash,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).resolves.toEqual({
                attachmentPath: result.attachmentPath,
                commitHash,
            });
        }));

    it('reopens every guard artifact and rejects path, digest, and semantic tampering', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            const result = await executeProofBackendBakeoffPreflightSequence({
                dependencies: createSequenceDependencies({ invocations }),
                runLog: createRunLog(runDirectoryPath),
            });
            const originalEvidenceContents = await readFile(
                result.attachmentPath,
                'utf8',
            );
            const evidence = JSON.parse(
                originalEvidenceContents,
            ) as MutablePreflightEvidence;
            const boundGuardArtifacts = [
                evidence.completedFeatureTestPhase,
                evidence.completedStaticFeatureTest,
                ...evidence.completedTests,
            ];
            expect(boundGuardArtifacts).toHaveLength(5);

            for (const boundGuardArtifact of boundGuardArtifacts) {
                const guardPath = path.join(
                    runDirectoryPath,
                    ...boundGuardArtifact.diagnosticsPath.split('/'),
                );
                const originalGuardContents = await readFile(guardPath, 'utf8');
                await writeFile(
                    guardPath,
                    `${originalGuardContents}\n`,
                    'utf8',
                );
                await expect(
                    validateProofBackendBakeoffPreflightEvidenceArtifacts({
                        attachmentPath: result.attachmentPath,
                        expectedMemoryLimitBytes: memoryLimitBytes,
                    }),
                ).rejects.toThrow(/SHA-256 digest/u);
                await writeFile(guardPath, originalGuardContents, 'utf8');
            }

            const firstCompletedTest = evidence.completedTests[0];
            if (firstCompletedTest === undefined) {
                throw new Error('The test evidence lacks its first owner.');
            }
            const originalDiagnosticsPath = firstCompletedTest.diagnosticsPath;
            firstCompletedTest.diagnosticsPath =
                'resources/process-memory-guard-wrong-owner.jsonl';
            await writeFile(
                result.attachmentPath,
                JSON.stringify(evidence),
                'utf8',
            );
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).rejects.toThrow(/must use the exact path/u);
            firstCompletedTest.diagnosticsPath = originalDiagnosticsPath;

            const originalDiagnosticsSha256Hex =
                firstCompletedTest.diagnosticsSha256Hex;
            firstCompletedTest.diagnosticsSha256Hex = '0'.repeat(64);
            await writeFile(
                result.attachmentPath,
                JSON.stringify(evidence),
                'utf8',
            );
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).rejects.toThrow(/SHA-256 digest/u);
            firstCompletedTest.diagnosticsSha256Hex =
                originalDiagnosticsSha256Hex;

            const featureGuardPath = path.join(
                runDirectoryPath,
                ...evidence.completedFeatureTestPhase.diagnosticsPath.split(
                    '/',
                ),
            );
            const originalFeatureGuardContents = await readFile(
                featureGuardPath,
                'utf8',
            );
            const semanticallyInvalidGuardContents =
                originalFeatureGuardContents.replace(
                    '"sampleError":null',
                    '"sampleError":"intentional tamper"',
                );
            expect(semanticallyInvalidGuardContents).not.toBe(
                originalFeatureGuardContents,
            );
            await writeFile(
                featureGuardPath,
                semanticallyInvalidGuardContents,
                'utf8',
            );
            evidence.completedFeatureTestPhase.diagnosticsSha256Hex =
                createHash('sha256')
                    .update(semanticallyInvalidGuardContents)
                    .digest('hex');
            await writeFile(
                result.attachmentPath,
                JSON.stringify(evidence),
                'utf8',
            );
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).rejects.toThrow(/sampling error/u);

            await writeFile(
                result.attachmentPath,
                originalEvidenceContents,
                'utf8',
            );
            await writeFile(
                featureGuardPath,
                originalFeatureGuardContents,
                'utf8',
            );
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedCommitHash: commitHash,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).resolves.toMatchObject({ commitHash });
        }));

    it('reopens the bound static result and rejects format, content, path, digest, and domain tampering', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            const result = await executeProofBackendBakeoffPreflightSequence({
                dependencies: createSequenceDependencies({ invocations }),
                runLog: createRunLog(runDirectoryPath),
            });
            const originalEvidenceContents = await readFile(
                result.attachmentPath,
                'utf8',
            );
            const evidence = JSON.parse(
                originalEvidenceContents,
            ) as MutablePreflightEvidence;
            evidence.formatVersion = 4;
            await writeFile(
                result.attachmentPath,
                JSON.stringify(evidence),
                'utf8',
            );
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).rejects.toThrow(/format version must be 5/u);
            evidence.formatVersion = 5;
            await writeFile(
                result.attachmentPath,
                originalEvidenceContents,
                'utf8',
            );
            const staticResultPath = path.join(
                runDirectoryPath,
                ...evidence.completedStaticFeatureTest.resultPath.split('/'),
            );
            const originalStaticResultContents = await readFile(
                staticResultPath,
                'utf8',
            );
            const semanticallyInvalidStaticResultContents =
                originalStaticResultContents.replace(
                    '"formatVersion":1',
                    '"formatVersion":2',
                );
            expect(semanticallyInvalidStaticResultContents).not.toBe(
                originalStaticResultContents,
            );

            await writeFile(
                staticResultPath,
                semanticallyInvalidStaticResultContents,
                'utf8',
            );
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).rejects.toThrow(/bound result SHA-256 digest/u);
            await writeFile(
                staticResultPath,
                originalStaticResultContents,
                'utf8',
            );

            const originalResultPath =
                evidence.completedStaticFeatureTest.resultPath;
            evidence.completedStaticFeatureTest.resultPath =
                'attachments/wrong-static-result.json';
            await writeFile(
                result.attachmentPath,
                JSON.stringify(evidence),
                'utf8',
            );
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).rejects.toThrow(/exact result path/u);
            evidence.completedStaticFeatureTest.resultPath = originalResultPath;

            const originalResultSha256Hex =
                evidence.completedStaticFeatureTest.resultSha256Hex;
            evidence.completedStaticFeatureTest.resultSha256Hex = '0'.repeat(
                64,
            );
            await writeFile(
                result.attachmentPath,
                JSON.stringify(evidence),
                'utf8',
            );
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).rejects.toThrow(/bound result SHA-256 digest/u);

            evidence.completedStaticFeatureTest.resultSha256Hex = createHash(
                'sha256',
            )
                .update(semanticallyInvalidStaticResultContents)
                .digest('hex');
            await Promise.all([
                writeFile(
                    staticResultPath,
                    semanticallyInvalidStaticResultContents,
                    'utf8',
                ),
                writeFile(
                    result.attachmentPath,
                    JSON.stringify(evidence),
                    'utf8',
                ),
            ]);
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).rejects.toThrow(/formatVersion must be 1/u);

            evidence.completedStaticFeatureTest.resultSha256Hex =
                originalResultSha256Hex;
            await Promise.all([
                writeFile(
                    staticResultPath,
                    originalStaticResultContents,
                    'utf8',
                ),
                writeFile(
                    result.attachmentPath,
                    originalEvidenceContents,
                    'utf8',
                ),
            ]);
            await expect(
                validateProofBackendBakeoffPreflightEvidenceArtifacts({
                    attachmentPath: result.attachmentPath,
                    expectedCommitHash: commitHash,
                    expectedMemoryLimitBytes: memoryLimitBytes,
                }),
            ).resolves.toMatchObject({ commitHash });
        }));

    it('refuses invalid guard telemetry immediately before launching the next phase', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofBackendBakeoffPreflightSequence({
                    dependencies: createSequenceDependencies({
                        invalidGuardAtIndex: 0,
                        invocations,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/sampling error/u);
            expect(guardedInvocations(invocations)).toHaveLength(1);
            await expect(
                readFile(
                    path.join(
                        runDirectoryPath,
                        'attachments',
                        'proof-backend-bakeoff-preflight-evidence.json',
                    ),
                    'utf8',
                ),
            ).rejects.toThrow();
        }));

    it('launches no inventory or guarded owner when precompilation fails', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofBackendBakeoffPreflightSequence({
                    dependencies: createSequenceDependencies({
                        failPrecompile: true,
                        invocations,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/precompile.*failed with exit code 1/u);
            expect(guardedInvocations(invocations)).toHaveLength(0);
            expect(
                invocations.map((invocation) => invocation.description),
            ).toEqual([
                'precompile the release proof backend bakeoff fragment',
            ]);
        }));

    it('refuses missing, extra, or duplicate ownership before guard verification or execution', async () => {
        for (const inventoryOverride of [
            { featureInventoryOutput: '' },
            {
                featureInventoryOutput: `${completeFilteredFeatureInventoryOutput()}\nother::feature_test: test\n`,
            },
            {
                featureInventoryOutput: `${completeFilteredFeatureInventoryOutput()}\n${proofBackendBakeoffFeatureTestNames[0]}: test\n`,
            },
            { staticFeatureInventoryOutput: '' },
            {
                staticFeatureInventoryOutput: `${completeStaticFeatureInventoryOutput()}\nother::static_feature_test: test\n`,
            },
            {
                staticFeatureInventoryOutput: `${completeStaticFeatureInventoryOutput()}\n${completeStaticFeatureInventoryOutput()}\n`,
            },
            { ignoredInventoryOutput: '' },
            {
                ignoredInventoryOutput: `${completeIgnoredInventoryOutput()}\nother::ignored_owner: test\n`,
            },
            {
                ignoredInventoryOutput: `${completeIgnoredInventoryOutput()}\n${proofBackendBakeoffIgnoredTestNames[0]}: test\n`,
            },
        ] as const) {
            await withTemporaryDirectory(async (runDirectoryPath) => {
                const invocations: CommandInvocation[] = [];
                await expect(
                    executeProofBackendBakeoffPreflightSequence({
                        dependencies: createSequenceDependencies({
                            ...inventoryOverride,
                            invocations,
                        }),
                        runLog: createRunLog(runDirectoryPath),
                    }),
                ).rejects.toThrow();
                expect(guardedInvocations(invocations)).toHaveLength(0);
                expect(
                    invocations.some(
                        (invocation) =>
                            invocation.command ===
                            'test-process-memory-guard-verification',
                    ),
                ).toBe(false);
            });
        }
    });

    it('stops after a failed feature phase without launching an ignored owner', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofBackendBakeoffPreflightSequence({
                    dependencies: createSequenceDependencies({
                        failGuardedTestAtIndex: 0,
                        invocations,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/non-ignored feature tests.*failed/u);
            const guardedCommands = guardedInvocations(invocations);
            expect(guardedCommands).toHaveLength(1);
            expect(guardedCommands[0]?.description).toContain(
                'non-ignored feature tests',
            );
            expect(
                proofBackendBakeoffPreflightTestNames.some((testName) =>
                    guardedCommands[0]?.args.includes(testName),
                ),
            ).toBe(false);
        }));

    it('stops after a failed static feature test without launching an ignored owner', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofBackendBakeoffPreflightSequence({
                    dependencies: createSequenceDependencies({
                        failGuardedTestAtIndex: 1,
                        invocations,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/static non-ignored feature test.*failed/u);
            const guardedCommands = guardedInvocations(invocations);
            expect(guardedCommands).toHaveLength(2);
            expect(guardedCommands[1]?.args).toContain(
                proofStorageWidthStaticPreflightTestName,
            );
            expect(
                proofBackendBakeoffPreflightTestNames.some((testName) =>
                    guardedCommands[1]?.args.includes(testName),
                ),
            ).toBe(false);
        }));

    it('refuses a pre-existing static feature-test result before launching any guarded phase', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const staticFeatureTestResultPath = path.join(
                runDirectoryPath,
                'attachments',
                'proof-backend-bakeoff-preflight-width-static-result.json',
            );
            await mkdir(path.dirname(staticFeatureTestResultPath), {
                recursive: true,
            });
            await writeFile(
                staticFeatureTestResultPath,
                JSON.stringify(staticPreflightFixture),
                'utf8',
            );
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofBackendBakeoffPreflightSequence({
                    dependencies: createSequenceDependencies({ invocations }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/Refusing to overwrite/u);
            expect(guardedInvocations(invocations)).toHaveLength(0);
        }));

    it('refuses a missing or semantically invalid static result before launching an ignored owner', async () => {
        for (const dependencyOverride of [
            { omitStaticPreflightResult: true },
            { invalidStaticPreflightResult: true },
            { omitStaticPreflightCustodyModel: true },
        ] as const) {
            await withTemporaryDirectory(async (runDirectoryPath) => {
                const invocations: CommandInvocation[] = [];
                await expect(
                    executeProofBackendBakeoffPreflightSequence({
                        dependencies: createSequenceDependencies({
                            ...dependencyOverride,
                            invocations,
                        }),
                        runLog: createRunLog(runDirectoryPath),
                    }),
                ).rejects.toThrow(
                    dependencyOverride.omitStaticPreflightResult === true
                        ? /did not create its exact result artifact/u
                        : dependencyOverride.invalidStaticPreflightResult ===
                            true
                          ? /formatVersion/u
                          : /custodyModel/u,
                );
                const guardedCommands = guardedInvocations(invocations);
                expect(guardedCommands).toHaveLength(2);
                expect(
                    guardedCommands.some((command) =>
                        proofBackendBakeoffPreflightTestNames.some((testName) =>
                            command.args.includes(testName),
                        ),
                    ),
                ).toBe(false);
            });
        }
    });

    it('stops after the first failed owner without retrying it', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofBackendBakeoffPreflightSequence({
                    dependencies: createSequenceDependencies({
                        failGuardedTestAtIndex: 2,
                        invocations,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/failed with exit code 1/u);
            const guardedCommands = guardedInvocations(invocations);
            expect(guardedCommands).toHaveLength(3);
            expect(
                guardedCommands
                    .slice(2)
                    .map((command) =>
                        proofBackendBakeoffPreflightTestNames.find((testName) =>
                            command.args.includes(testName),
                        ),
                    ),
            ).toEqual(proofBackendBakeoffPreflightTestNames.slice(0, 1));
        }));

    it('checks the clean commit before inventory, execution, and closure', async () => {
        const changedCommitHash = '34'.repeat(20);
        for (const [repositoryStates, expectedGuardedCount] of [
            [[{ commitHash, treeDirty: true }], 0],
            [
                [
                    { commitHash, treeDirty: false },
                    { commitHash: changedCommitHash, treeDirty: false },
                ],
                0,
            ],
            [
                [
                    { commitHash, treeDirty: false },
                    { commitHash, treeDirty: false },
                    { commitHash, treeDirty: true },
                ],
                5,
            ],
        ] as const) {
            await withTemporaryDirectory(async (runDirectoryPath) => {
                const invocations: CommandInvocation[] = [];
                await expect(
                    executeProofBackendBakeoffPreflightSequence({
                        dependencies: createSequenceDependencies({
                            invocations,
                            repositoryStates,
                        }),
                        runLog: createRunLog(runDirectoryPath),
                    }),
                ).rejects.toThrow(/clean repository tree|commit changed/u);
                expect(guardedInvocations(invocations)).toHaveLength(
                    expectedGuardedCount,
                );
            });
        }
    });
});
