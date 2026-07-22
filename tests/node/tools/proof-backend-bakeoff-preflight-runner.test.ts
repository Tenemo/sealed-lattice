import { mkdtemp, readFile, rm } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import type { ActiveLocalRunLog } from '#tools/ci/local-run-log';
import type { ProcessMemoryGuard } from '#tools/ci/process-memory-guard';
import type {
    CapturedCommandResult,
    CommandInvocation,
} from '#tools/ci/run-command';
import { buildProofBackendBakeoffEnvironment } from '#tools/ci/run-proof-backend-bakeoff';
import {
    buildProofBackendBakeoffPreflightListCommand,
    buildProofBackendBakeoffPreflightTestCommand,
    executeProofBackendBakeoffPreflightSequence,
    parseProofBackendBakeoffPreflightInventory,
    proofBackendBakeoffPreflightTestNames,
    type ProofBackendBakeoffPreflightRunnerDependencies,
} from '#tools/ci/run-proof-backend-bakeoff-preflight';

const measurementTestName =
    'bgv::proof_suite::proof_backend_bakeoff::tests::proof_backend_bakeoff_frozen_fragment';
const commitHash = '12'.repeat(20);

const completeInventoryOutput = (): string =>
    [...proofBackendBakeoffPreflightTestNames, measurementTestName]
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
    readonly failGuardedTestAtIndex?: number;
    readonly failPrecompile?: boolean;
    readonly inventoryOutput?: string;
    readonly invocations: CommandInvocation[];
    readonly repositoryStates?: readonly {
        readonly commitHash: string;
        readonly treeDirty: boolean;
    }[];
}): ProofBackendBakeoffPreflightRunnerDependencies => {
    let guardedTestIndex = 0;
    let repositoryStateIndex = 0;
    return {
        executeCommand: (invocation) => {
            input.invocations.push(invocation);
            if (
                input.failPrecompile === true &&
                invocation.description ===
                    'precompile the release proof backend bakeoff fragment'
            ) {
                return Promise.resolve(failedCommandResult());
            }
            if (
                invocation.description ===
                'list the proof backend bakeoff ignored owners'
            ) {
                return Promise.resolve(
                    successfulCommandResult(
                        input.inventoryOutput ?? completeInventoryOutput(),
                    ),
                );
            }
            if (invocation.command === 'test-process-memory-guard') {
                const currentGuardedTestIndex = guardedTestIndex;
                guardedTestIndex += 1;
                return Promise.resolve(
                    currentGuardedTestIndex === input.failGuardedTestAtIndex
                        ? failedCommandResult()
                        : successfulCommandResult(),
                );
            }
            return Promise.resolve(successfulCommandResult());
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
    it('pins one exact ignored owner per fresh guarded command', () => {
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
        const listCommand =
            buildProofBackendBakeoffPreflightListCommand(environment);
        expect(listCommand.args).toEqual(
            expect.arrayContaining([
                '--locked',
                '--release',
                '--features',
                'proof-backend-bakeoff',
                '--lib',
                '--ignored',
                '--list',
            ]),
        );
        expect(listCommand.args).toContain(
            'bgv::proof_suite::proof_backend_bakeoff::tests',
        );

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
                exactTestName: measurementTestName,
            }),
        ).toThrow(/unregistered test/u);
    });

    it('requires the complete exact ignored-owner inventory', () => {
        expect(
            parseProofBackendBakeoffPreflightInventory(
                `${completeInventoryOutput()}\n`,
            ),
        ).toEqual(proofBackendBakeoffPreflightTestNames);

        expect(() => parseProofBackendBakeoffPreflightInventory('')).toThrow(
            /selected zero tests/u,
        );
        expect(() =>
            parseProofBackendBakeoffPreflightInventory(
                [...proofBackendBakeoffPreflightTestNames, measurementTestName]
                    .slice(1)
                    .map((testName) => `${testName}: test`)
                    .join('\n'),
            ),
        ).toThrow(/Missing:/u);
        expect(() =>
            parseProofBackendBakeoffPreflightInventory(
                `${completeInventoryOutput()}\nother::ignored_owner: test\n`,
            ),
        ).toThrow(/Extra: other::ignored_owner/u);
        expect(() =>
            parseProofBackendBakeoffPreflightInventory(
                `${completeInventoryOutput()}\n${measurementTestName}: test\n`,
            ),
        ).toThrow(/duplicate tests/u);
        expect(() =>
            parseProofBackendBakeoffPreflightInventory(
                `${completeInventoryOutput()}\nother::benchmark: benchmark\n`,
            ),
        ).toThrow(/unexpectedly selected benchmarks/u);
    });

    it('runs exactly three guarded children in fixed order and pins evidence', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            const result = await executeProofBackendBakeoffPreflightSequence({
                dependencies: createSequenceDependencies({ invocations }),
                runLog: createRunLog(runDirectoryPath),
            });
            const guardedCommands = guardedInvocations(invocations);
            expect(guardedCommands).toHaveLength(3);
            const precompileIndex = invocations.findIndex(
                (invocation) =>
                    invocation.description ===
                    'precompile the release proof backend bakeoff fragment',
            );
            const listIndex = invocations.findIndex(
                (invocation) =>
                    invocation.description ===
                    'list the proof backend bakeoff ignored owners',
            );
            const firstGuardedOwnerIndex = invocations.findIndex(
                (invocation) =>
                    invocation.command === 'test-process-memory-guard',
            );
            expect(precompileIndex).toBeGreaterThanOrEqual(0);
            expect(listIndex).toBeGreaterThan(precompileIndex);
            expect(firstGuardedOwnerIndex).toBeGreaterThan(listIndex);
            expect(
                guardedCommands.map((command) =>
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
                readonly completedTests: readonly {
                    readonly testName: string;
                }[];
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
            expect(evidence.repository).toEqual({
                after: { commitHash, treeDirty: false },
                before: { commitHash, treeDirty: false },
                initial: { commitHash, treeDirty: false },
            });
            expect(evidence.processMemoryGuard).toEqual({
                memoryLimitBytes: 1_073_741_824,
                memoryLimitGigabytes: 1,
            });
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

    it('refuses missing or extra inventory before guard verification or execution', async () => {
        for (const inventoryOutput of [
            '',
            `${completeInventoryOutput()}\nother::ignored_owner: test\n`,
        ]) {
            await withTemporaryDirectory(async (runDirectoryPath) => {
                const invocations: CommandInvocation[] = [];
                await expect(
                    executeProofBackendBakeoffPreflightSequence({
                        dependencies: createSequenceDependencies({
                            inventoryOutput,
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

    it('stops after the first failed owner without retrying it', () =>
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
            ).rejects.toThrow(/failed with exit code 1/u);
            const guardedCommands = guardedInvocations(invocations);
            expect(guardedCommands).toHaveLength(2);
            expect(
                guardedCommands.map((command) =>
                    proofBackendBakeoffPreflightTestNames.find((testName) =>
                        command.args.includes(testName),
                    ),
                ),
            ).toEqual(proofBackendBakeoffPreflightTestNames.slice(0, 2));
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
                3,
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
