import { randomBytes } from 'node:crypto';
import { readFile, rm } from 'node:fs/promises';
import path from 'node:path';

import { withLocalHeavyLaneLease } from './heavy-lane-lease.js';
import { runWithLocalRunLog } from './local-run-log.js';
import {
    nodeKernelProofEvidenceCases,
    nodeKernelProofEvidenceProjectName,
    type NodeKernelProofEvidenceCase,
} from './node-kernel-proof-evidence-selection.js';
import { resolvePackageManagerRunner } from './package-manager-runner.js';
import {
    createProcessMemoryGuard,
    type ProcessMemoryGuard,
} from './process-memory-guard.js';
import {
    createPackageManagerCommand,
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from './run-command.js';

export const compactPublicKeyWasmProofEvidenceOutputPathEnvironmentVariable =
    'SEALED_LATTICE_COMPACT_PUBLIC_KEY_WASM_PROOF_EVIDENCE_OUTPUT_PATH';
export const compactPublicKeyWasmProofEvidenceTemporaryDirectoryEnvironmentVariable =
    'SEALED_LATTICE_COMPACT_PUBLIC_KEY_WASM_PROOF_EVIDENCE_TEMPORARY_DIRECTORY';

const memoryLimitEnvironmentVariable =
    'SEALED_LATTICE_WASM_PROOF_EVIDENCE_MEMORY_GIB';
const usage =
    'Usage: run-node-kernel-proof-evidence.ts [<registered evidence filter>].';
let processMemoryGuard: ProcessMemoryGuard | undefined;

const getProcessMemoryGuard = (): ProcessMemoryGuard => {
    processMemoryGuard ??= createProcessMemoryGuard({
        insufficientFreeMemoryRunDescription:
            'Scalar WASM kernel proof evidence',
        memoryLimitEnvironmentVariable,
    });
    return processMemoryGuard;
};

const requireCanonicalRegistry = (
    configuredCases: readonly NodeKernelProofEvidenceCase[],
): void => {
    if (configuredCases.length === 0) {
        throw new Error(
            'The scalar WASM kernel proof-evidence registry is empty.',
        );
    }
    for (const [caseIndex, evidenceCase] of configuredCases.entries()) {
        if (
            evidenceCase.caseIdentifier.length === 0 ||
            evidenceCase.testFilePath.length === 0 ||
            evidenceCase.testName.length === 0 ||
            configuredCases.some(
                (otherCase, otherIndex) =>
                    otherIndex !== caseIndex &&
                    (otherCase.caseIdentifier === evidenceCase.caseIdentifier ||
                        otherCase.testFilePath === evidenceCase.testFilePath ||
                        otherCase.testName === evidenceCase.testName),
            )
        ) {
            throw new Error(
                'The scalar WASM kernel proof-evidence registry is malformed or duplicated.',
            );
        }
    }
};

export const resolveNodeKernelProofEvidenceCases = (input: {
    configuredCases?: readonly NodeKernelProofEvidenceCase[];
    focusedFilter?: string;
}): readonly NodeKernelProofEvidenceCase[] => {
    const configuredCases =
        input.configuredCases ?? nodeKernelProofEvidenceCases;
    requireCanonicalRegistry(configuredCases);
    if (input.focusedFilter === undefined) {
        return configuredCases;
    }
    const focusedFilter = input.focusedFilter.trim();
    if (focusedFilter.length === 0) {
        throw new Error(
            'The scalar WASM kernel proof-evidence filter must be non-empty.',
        );
    }
    const selectedCases = configuredCases.filter(
        (evidenceCase) =>
            evidenceCase.caseIdentifier.includes(focusedFilter) ||
            evidenceCase.testFilePath.includes(focusedFilter) ||
            evidenceCase.testName.includes(focusedFilter),
    );
    if (selectedCases.length === 0) {
        throw new Error(
            `The scalar WASM kernel proof-evidence filter ${focusedFilter} selects zero registered cases.`,
        );
    }
    return Object.freeze([...selectedCases]);
};

export const parseNodeKernelProofEvidenceArguments = (
    commandArguments: readonly string[],
): Readonly<{ focusedFilter?: string }> => {
    const positionalArguments: string[] = [];
    for (const argument of commandArguments) {
        if (argument === '--') {
            continue;
        }
        if (argument.startsWith('-')) {
            throw new Error(`Unknown argument ${argument}. ${usage}`);
        }
        positionalArguments.push(argument);
    }
    if (positionalArguments.length > 1) {
        throw new Error(
            `Scalar WASM kernel proof evidence accepts one optional filter. ${usage}`,
        );
    }
    const focusedFilter = positionalArguments[0]?.trim();
    resolveNodeKernelProofEvidenceCases({
        ...(focusedFilter === undefined ? {} : { focusedFilter }),
    });
    return focusedFilter === undefined ? {} : { focusedFilter };
};

export const validateNodeKernelProofEvidenceInventoryOutput = (input: {
    evidenceCase: NodeKernelProofEvidenceCase;
    stdout: string;
}): void => {
    const inventoryLines = input.stdout
        .split(/\r?\n/gu)
        .map((line) => line.trim())
        .filter((line) => line.length > 0);
    const expectedInventoryLine = `[${nodeKernelProofEvidenceProjectName}] ${input.evidenceCase.testFilePath} > ${input.evidenceCase.testName}`;
    if (
        inventoryLines.length !== 1 ||
        inventoryLines[0] !== expectedInventoryLine
    ) {
        throw new Error(
            `The scalar WASM kernel proof-evidence inventory differs from registered case ${input.evidenceCase.caseIdentifier}.`,
        );
    }
};

const requireEvidenceRecord = async (evidencePath: string): Promise<void> => {
    const parsed: unknown = JSON.parse(await readFile(evidencePath, 'utf8'));
    if (
        typeof parsed !== 'object' ||
        parsed === null ||
        !('schemaVersion' in parsed) ||
        parsed.schemaVersion !== 1 ||
        !('sameByteVerification' in parsed) ||
        typeof parsed.sameByteVerification !== 'object' ||
        parsed.sameByteVerification === null ||
        !('isValid' in parsed.sameByteVerification) ||
        parsed.sameByteVerification.isValid !== true
    ) {
        throw new Error(
            'The scalar WASM proof-evidence test did not emit a valid same-byte verification record.',
        );
    }
};

const removeOwnedTemporaryDirectory = async (
    temporaryDirectoryPath: string,
): Promise<void> => {
    const repositoryTemporaryDirectory = path.resolve(process.cwd(), 'temp');
    const resolvedDirectory = path.resolve(temporaryDirectoryPath);
    const relativeDirectory = path.relative(
        repositoryTemporaryDirectory,
        resolvedDirectory,
    );
    if (
        relativeDirectory === '' ||
        relativeDirectory === '..' ||
        relativeDirectory.startsWith(`..${path.sep}`) ||
        path.isAbsolute(relativeDirectory)
    ) {
        throw new Error(
            'The scalar WASM proof-evidence temporary directory resolved outside repository temp.',
        );
    }
    await rm(resolvedDirectory, { force: true, recursive: true });
};

export const runNodeKernelProofEvidence = async (
    rawArguments: readonly string[] = process.argv.slice(2),
): Promise<void> => {
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Scalar WASM kernel proof evidence'],
            scriptName: 'test:node:kernel:proof-evidence',
        },
        async (runLog) => {
            const parsedArguments =
                parseNodeKernelProofEvidenceArguments(rawArguments);
            const selectedCases = resolveNodeKernelProofEvidenceCases({
                ...(parsedArguments.focusedFilter === undefined
                    ? {}
                    : { focusedFilter: parsedArguments.focusedFilter }),
            });
            const packageManagerRunner = resolvePackageManagerRunner();
            const memoryGuard = getProcessMemoryGuard();
            process.exitCode = await withLocalHeavyLaneLease({
                action: async () => {
                    let exitCode = await runCommandsInSeries(
                        [memoryGuard.buildVerificationCommand()],
                        { outputMode: 'inherit', runLog },
                    );
                    if (exitCode !== 0) {
                        return exitCode;
                    }
                    for (const [
                        caseIndex,
                        evidenceCase,
                    ] of selectedCases.entries()) {
                        const inventoryCommand = createPackageManagerCommand(
                            `inventory scalar WASM kernel proof evidence ${evidenceCase.caseIdentifier}`,
                            [
                                'exec',
                                'vitest',
                                'list',
                                '--project',
                                nodeKernelProofEvidenceProjectName,
                                evidenceCase.testFilePath,
                            ],
                            {
                                logFileSlug: `vitest-list-${evidenceCase.caseIdentifier}`,
                                packageManagerRunner,
                            },
                        );
                        const inventoryResult =
                            await runCommandAndCaptureOutput(
                                memoryGuard.guardCommand(inventoryCommand, {
                                    diagnosticsPath: path.join(
                                        runLog.runDirectoryPath,
                                        'resources',
                                        `process-memory-guard-scalar-wasm-kernel-proof-evidence-inventory-${String(caseIndex + 1).padStart(2, '0')}.jsonl`,
                                    ),
                                }),
                                { runLog },
                            );
                        if (inventoryResult.exitCode !== 0) {
                            return inventoryResult.exitCode;
                        }
                        validateNodeKernelProofEvidenceInventoryOutput({
                            evidenceCase,
                            stdout: inventoryResult.stdout,
                        });
                    }
                    const buildCommand = createPackageManagerCommand(
                        'build the scalar release WASM kernel for proof evidence',
                        [
                            '--filter',
                            '@sealed-lattice/wasm',
                            'run',
                            'build:wasm',
                        ],
                        {
                            logFileSlug:
                                'build-scalar-wasm-kernel-proof-evidence',
                            packageManagerRunner,
                        },
                    );
                    exitCode = await runCommandsInSeries(
                        [
                            memoryGuard.guardCommand(buildCommand, {
                                diagnosticsPath: path.join(
                                    runLog.runDirectoryPath,
                                    'resources',
                                    'process-memory-guard-scalar-wasm-kernel-proof-evidence-build.jsonl',
                                ),
                            }),
                        ],
                        { outputMode: 'inherit', runLog },
                    );
                    if (exitCode !== 0) {
                        return exitCode;
                    }

                    for (const evidenceCase of selectedCases) {
                        const runIdentifier = randomBytes(16).toString('hex');
                        const temporaryDirectoryPath = path.resolve(
                            'temp',
                            `compact-public-key-wasm-proof-evidence-${runIdentifier}`,
                        );
                        const evidencePath = path.join(
                            runLog.runDirectoryPath,
                            'attachments',
                            `${evidenceCase.caseIdentifier}.json`,
                        );
                        const commandEnvironment: NodeJS.ProcessEnv = {
                            ...process.env,
                            [compactPublicKeyWasmProofEvidenceOutputPathEnvironmentVariable]:
                                evidencePath,
                            [compactPublicKeyWasmProofEvidenceTemporaryDirectoryEnvironmentVariable]:
                                temporaryDirectoryPath,
                            SEALED_LATTICE_TEST_PROJECT_LABEL:
                                evidenceCase.caseIdentifier,
                        };
                        const testCommand = createPackageManagerCommand(
                            `run scalar WASM kernel proof evidence ${evidenceCase.caseIdentifier}`,
                            [
                                'exec',
                                'vitest',
                                '--project',
                                nodeKernelProofEvidenceProjectName,
                                '--run',
                                evidenceCase.testFilePath,
                            ],
                            {
                                env: commandEnvironment,
                                logFileSlug: `vitest-${evidenceCase.caseIdentifier}`,
                                packageManagerRunner,
                            },
                        );
                        try {
                            exitCode = await runCommandsInSeries(
                                [
                                    memoryGuard.guardCommand(testCommand, {
                                        diagnosticsPath: path.join(
                                            runLog.runDirectoryPath,
                                            'resources',
                                            `process-memory-guard-${evidenceCase.caseIdentifier}.jsonl`,
                                        ),
                                    }),
                                ],
                                { outputMode: 'inherit', runLog },
                            );
                            if (exitCode !== 0) {
                                return exitCode;
                            }
                            await requireEvidenceRecord(evidencePath);
                        } finally {
                            await removeOwnedTemporaryDirectory(
                                temporaryDirectoryPath,
                            );
                        }
                    }
                    return 0;
                },
                laneLabel: 'Scalar WASM kernel proof evidence',
                runLog,
            });
        },
    );
};

if (import.meta.main) {
    void runNodeKernelProofEvidence();
}
