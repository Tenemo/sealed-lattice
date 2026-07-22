import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import type { ActiveLocalRunLog } from '#tools/ci/local-run-log';
import type { ProcessMemoryGuard } from '#tools/ci/process-memory-guard';
import type {
    CapturedCommandResult,
    CommandInvocation,
} from '#tools/ci/run-command';
import {
    buildProofBackendBakeoffEnvironment,
    buildProofBackendBakeoffListCommand,
    buildProofBackendBakeoffPrecompileCommand,
    buildProofBackendBakeoffSampleCommand,
    executeProofBackendBakeoffSequence,
    parseProofBackendBakeoffTestInventory,
    writeJsonAtomicallyAndExclusively,
    type ProofBackendBakeoffRunnerDependencies,
} from '#tools/ci/run-proof-backend-bakeoff';

const exactTestName =
    'bgv::proof_suite::proof_backend_bakeoff::tests::proof_backend_bakeoff_frozen_fragment';
const commitHash = '12'.repeat(20);

const withTemporaryDirectory = async <Result>(
    action: (directoryPath: string) => Promise<Result>,
): Promise<Result> => {
    const directoryPath = await mkdtemp(
        path.join(os.tmpdir(), 'sealed-lattice-proof-backend-bakeoff-'),
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

const requiredEnvironmentValue = (
    environment: NodeJS.ProcessEnv | undefined,
    name: string,
): string => {
    const value = environment?.[name];
    if (value === undefined) {
        throw new Error(`Missing test environment value ${name}.`);
    }
    return value;
};

const buildGuardJsonLines = (input: {
    readonly includeBaseline: boolean;
    readonly peakResidentByteLength: number;
}): string =>
    [
        {
            aggregateProcessTreeMemoryLimit: true,
            elapsedMilliseconds: 0,
            eventType: 'guard-started',
            recordedAtUnixMilliseconds: 800,
            resourceSampleIntervalMilliseconds: 100,
            sequence: 0,
        },
        {
            elapsedMilliseconds: 50,
            eventType: 'child-started',
            recordedAtUnixMilliseconds: 850,
            sequence: 1,
        },
        ...(input.includeBaseline
            ? [
                  {
                      confirmedMemoryLimitViolation: false,
                      elapsedMilliseconds: 100,
                      eventType: 'resource-sample',
                      processTreeResidentMemoryBytes: 40,
                      recordedAtUnixMilliseconds: 900,
                      sampleError: null,
                      sequence: 2,
                  },
              ]
            : []),
        {
            confirmedMemoryLimitViolation: false,
            elapsedMilliseconds: 300,
            eventType: 'resource-sample',
            processTreeResidentMemoryBytes: input.peakResidentByteLength,
            recordedAtUnixMilliseconds: 1_100,
            sampleError: null,
            sequence: input.includeBaseline ? 3 : 2,
        },
        {
            elapsedMilliseconds: 600,
            eventType: 'child-exited',
            exitCode: 0,
            memoryEvidence: 'completed',
            recordedAtUnixMilliseconds: 1_400,
            sequence: input.includeBaseline ? 4 : 3,
            terminationClassification: 'completed',
        },
    ]
        .map((record) => JSON.stringify(record))
        .join('\n');

const createSequenceDependencies = (input: {
    readonly includeBaseline: boolean;
    readonly invocations: CommandInvocation[];
    readonly repositoryStates?: readonly {
        readonly commitHash: string;
        readonly treeDirty: boolean;
    }[];
    readonly sumcheckPeakResidentByteLength?: number;
}): ProofBackendBakeoffRunnerDependencies => {
    let repositoryStateIndex = 0;
    return {
        executeCommand: async (invocation) => {
            input.invocations.push(invocation);
            if (
                invocation.description ===
                'list the release proof backend bakeoff fragment owner'
            ) {
                return successfulCommandResult(`${exactTestName}: test\n`);
            }
            if (invocation.command !== 'test-process-memory-guard') {
                return successfulCommandResult();
            }

            const backend = requiredEnvironmentValue(
                invocation.env,
                'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND',
            );
            const sampleOrdinal = Number.parseInt(
                requiredEnvironmentValue(
                    invocation.env,
                    'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL',
                ),
                10,
            );
            const resultPath = requiredEnvironmentValue(
                invocation.env,
                'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_RESULT_PATH',
            );
            const diagnosticsPathIndex =
                invocation.args.indexOf('--diagnostics-path');
            const diagnosticsPath = invocation.args[diagnosticsPathIndex + 1];
            if (diagnosticsPath === undefined) {
                throw new Error('Missing test diagnostics path.');
            }
            const packedDeepFri = backend === 'packed-deep-fri';
            await Promise.all([
                writeFile(
                    resultPath,
                    `${JSON.stringify(
                        {
                            backend,
                            canonicalProofByteLengthDecimal: packedDeepFri
                                ? '100'
                                : '250',
                            elapsedNanosecondsDecimal: packedDeepFri
                                ? '100'
                                : '250',
                            externalCommittedTransactionCountDecimal: '0',
                            externalReadByteLengthDecimal: '0',
                            externalWrittenByteLengthDecimal: '0',
                            formatVersion: 1,
                            frozenInputIdentityShake256Hex: '34'.repeat(64),
                            operationFinishedAtUnixMilliseconds: 1_300,
                            operationStartedAtUnixMilliseconds: 1_000,
                            proofShake256Hex: packedDeepFri
                                ? '56'.repeat(64)
                                : '78'.repeat(64),
                            sampleOrdinal,
                        },
                        null,
                        2,
                    )}\n`,
                    { encoding: 'utf8', flag: 'wx' },
                ),
                writeFile(
                    diagnosticsPath,
                    `${buildGuardJsonLines({
                        includeBaseline: input.includeBaseline,
                        peakResidentByteLength: packedDeepFri
                            ? 100
                            : (input.sumcheckPeakResidentByteLength ?? 250),
                    })}\n`,
                    { encoding: 'utf8', flag: 'wx' },
                ),
            ]);
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

describe('Proof backend bakeoff runner', () => {
    it('pins the release feature, exact ignored owner, and isolated sample environment', () => {
        const environment = buildProofBackendBakeoffEnvironment({
            baseEnvironment: {
                CARGO_TARGET_DIR: 'inherited-target',
                SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND:
                    'inherited-backend',
                SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_RESULT_PATH:
                    'inherited-result',
                SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL: '9',
                SEALED_LATTICE_RESUME_TEST_CHECKPOINTS: '1',
            },
            targetDirectoryPath: 'dedicated-target',
        });
        expect(environment).toMatchObject({
            CARGO_BUILD_JOBS: '1',
            CARGO_INCREMENTAL: '0',
            CARGO_TARGET_DIR: 'dedicated-target',
            RAYON_NUM_THREADS: '1',
            RUST_TEST_THREADS: '1',
        });
        expect(
            environment.SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND,
        ).toBeUndefined();
        expect(
            environment.SEALED_LATTICE_RESUME_TEST_CHECKPOINTS,
        ).toBeUndefined();

        const precompileCommand =
            buildProofBackendBakeoffPrecompileCommand(environment);
        expect(precompileCommand.args).toEqual(
            expect.arrayContaining([
                '--locked',
                '--release',
                '--features',
                'proof-backend-bakeoff',
                '--lib',
                '--no-run',
            ]),
        );
        const listCommand = buildProofBackendBakeoffListCommand(environment);
        expect(listCommand.args).toContain(
            'proof_backend_bakeoff_frozen_fragment',
        );
        expect(listCommand.args).toContain('--ignored');
        expect(listCommand.args).toContain('--list');

        const sampleCommand = buildProofBackendBakeoffSampleCommand({
            backend: 'sumcheck-class',
            baseEnvironment: environment,
            exactTestName,
            resultPath: path.resolve('sumcheck-result.json'),
            sampleOrdinal: 3,
        });
        expect(sampleCommand.args).toContain('--exact');
        expect(sampleCommand.args).toContain('--ignored');
        expect(sampleCommand.args).toContain('--test-threads');
        expect(sampleCommand.env).toMatchObject({
            SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND: 'sumcheck-class',
            SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL: '3',
        });
    });

    it('requires exactly one matching test during preflight', () => {
        expect(
            parseProofBackendBakeoffTestInventory(`${exactTestName}: test\n`),
        ).toBe(exactTestName);
        expect(() => parseProofBackendBakeoffTestInventory('')).toThrow(
            /exactly one test/u,
        );
        expect(() =>
            parseProofBackendBakeoffTestInventory(
                `${exactTestName}: test\nother::proof_backend_bakeoff_frozen_fragment: test\n`,
            ),
        ).toThrow(/listed 2/u);
        expect(() =>
            parseProofBackendBakeoffTestInventory('other_test: test\n'),
        ).toThrow(/unexpected test/u);
    });

    it('runs exactly six fresh guarded samples in fixed order and writes pinned evidence', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            const result = await executeProofBackendBakeoffSequence({
                dependencies: createSequenceDependencies({
                    includeBaseline: true,
                    invocations,
                }),
                runLog: createRunLog(runDirectoryPath),
            });
            const guardedInvocations = invocations.filter(
                (invocation) =>
                    invocation.command === 'test-process-memory-guard',
            );
            expect(
                guardedInvocations.map((invocation) => [
                    invocation.env?.[
                        'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_BACKEND'
                    ],
                    invocation.env?.[
                        'SEALED_LATTICE_PROOF_BACKEND_BAKEOFF_SAMPLE_ORDINAL'
                    ],
                ]),
            ).toEqual([
                ['packed-deep-fri', '1'],
                ['sumcheck-class', '1'],
                ['packed-deep-fri', '2'],
                ['sumcheck-class', '2'],
                ['packed-deep-fri', '3'],
                ['sumcheck-class', '3'],
            ]);
            expect(
                guardedInvocations.every((invocation) =>
                    invocation.args.includes('100'),
                ),
            ).toBe(true);
            expect(result.decision).toMatchObject({
                outcome: 'selected',
                selectedBackend: 'packed-deep-fri',
            });
            const evidence = JSON.parse(
                await readFile(result.attachmentPath, 'utf8'),
            ) as {
                readonly repository: {
                    readonly after: { readonly commitHash: string };
                    readonly before: { readonly commitHash: string };
                    readonly initial: { readonly commitHash: string };
                };
                readonly samples: readonly unknown[];
            };
            expect(evidence.repository).toEqual({
                after: { commitHash, treeDirty: false },
                before: { commitHash, treeDirty: false },
                initial: { commitHash, treeDirty: false },
            });
            expect(evidence.samples).toHaveLength(6);
            expect(
                await readdir(
                    path.join(
                        runDirectoryPath,
                        'attachments',
                        'proof-backend-bakeoff',
                        'samples',
                    ),
                ),
            ).toHaveLength(6);
        }));

    it('invalidates missing baseline telemetry after the first sample without retrying', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofBackendBakeoffSequence({
                    dependencies: createSequenceDependencies({
                        includeBaseline: false,
                        invocations,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/lacks a pre-operation resident baseline/u);
            expect(
                invocations.filter(
                    (invocation) =>
                        invocation.command === 'test-process-memory-guard',
                ),
            ).toHaveLength(1);
        }));

    it('refuses a dirty starting tree before compilation or measurement', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofBackendBakeoffSequence({
                    dependencies: createSequenceDependencies({
                        includeBaseline: true,
                        invocations,
                        repositoryStates: [{ commitHash, treeDirty: true }],
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/clean repository tree/u);
            expect(invocations).toHaveLength(0);
        }));

    it('re-pins the tree after preflight and refuses dirty or changed source before sample one', async () => {
        for (const [repositoryStateBefore, expectedErrorPattern] of [
            [{ commitHash, treeDirty: true }, /clean repository tree/u],
            [
                { commitHash: '34'.repeat(20), treeDirty: false },
                /changed during proof backend bakeoff preflight/u,
            ],
        ] as const) {
            await withTemporaryDirectory(async (runDirectoryPath) => {
                const invocations: CommandInvocation[] = [];
                await expect(
                    executeProofBackendBakeoffSequence({
                        dependencies: createSequenceDependencies({
                            includeBaseline: true,
                            invocations,
                            repositoryStates: [
                                { commitHash, treeDirty: false },
                                repositoryStateBefore,
                            ],
                        }),
                        runLog: createRunLog(runDirectoryPath),
                    }),
                ).rejects.toThrow(expectedErrorPattern);
                expect(
                    invocations.filter(
                        (invocation) =>
                            invocation.command === 'test-process-memory-guard',
                    ),
                ).toHaveLength(0);
            });
        }
    });

    it('retains the final pin and refuses dirty or changed source after all six samples', async () => {
        for (const [repositoryStateAfter, expectedErrorPattern] of [
            [{ commitHash, treeDirty: true }, /clean repository tree/u],
            [
                { commitHash: '56'.repeat(20), treeDirty: false },
                /commit changed during the proof backend bakeoff/u,
            ],
        ] as const) {
            await withTemporaryDirectory(async (runDirectoryPath) => {
                const invocations: CommandInvocation[] = [];
                await expect(
                    executeProofBackendBakeoffSequence({
                        dependencies: createSequenceDependencies({
                            includeBaseline: true,
                            invocations,
                            repositoryStates: [
                                { commitHash, treeDirty: false },
                                { commitHash, treeDirty: false },
                                repositoryStateAfter,
                            ],
                        }),
                        runLog: createRunLog(runDirectoryPath),
                    }),
                ).rejects.toThrow(expectedErrorPattern);
                expect(
                    invocations.filter(
                        (invocation) =>
                            invocation.command === 'test-process-memory-guard',
                    ),
                ).toHaveLength(6);
            });
        }
    });

    it('writes complete evidence before stopping on an ambiguous decision', () =>
        withTemporaryDirectory(async (runDirectoryPath) => {
            const invocations: CommandInvocation[] = [];
            await expect(
                executeProofBackendBakeoffSequence({
                    dependencies: createSequenceDependencies({
                        includeBaseline: true,
                        invocations,
                        sumcheckPeakResidentByteLength: 150,
                    }),
                    runLog: createRunLog(runDirectoryPath),
                }),
            ).rejects.toThrow(/ambiguous/u);

            const evidencePath = path.join(
                runDirectoryPath,
                'attachments',
                'proof-backend-bakeoff',
                'proof-backend-bakeoff-evidence.json',
            );
            const evidence = JSON.parse(
                await readFile(evidencePath, 'utf8'),
            ) as {
                readonly decision: { readonly outcome: string };
                readonly samples: readonly unknown[];
            };
            expect(evidence.decision.outcome).toBe('ambiguous');
            expect(evidence.samples).toHaveLength(6);
            expect(
                invocations.filter(
                    (invocation) =>
                        invocation.command === 'test-process-memory-guard',
                ),
            ).toHaveLength(6);
        }));

    it('publishes aggregate JSON atomically without overwriting evidence', () =>
        withTemporaryDirectory(async (directoryPath) => {
            const evidencePath = path.join(directoryPath, 'evidence.json');
            await writeJsonAtomicallyAndExclusively(evidencePath, {
                sampleCount: 6,
            });
            await expect(
                writeJsonAtomicallyAndExclusively(evidencePath, {
                    sampleCount: 7,
                }),
            ).rejects.toThrow(/Refusing to overwrite/u);
            expect(JSON.parse(await readFile(evidencePath, 'utf8'))).toEqual({
                sampleCount: 6,
            });
            expect(await readdir(directoryPath)).toEqual(['evidence.json']);
        }));
});
