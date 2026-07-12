import { createHash } from 'node:crypto';
import {
    copyFile,
    mkdtemp,
    mkdir,
    readFile,
    readdir,
    rm,
    writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path, { join } from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    resolvePackageManagerRunnerForPackageManager,
    type PackageManager,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    createPackageManagerCommand,
    runCommandAndCaptureOutput,
    runCommandsInSeries,
    type CapturedCommandResult,
    type CommandInvocation,
} from './run-command.js';
import { serializeErrorDiagnostic } from './run-log-diagnostics.js';
import {
    getRootPackageJsonPath,
    getRootReadmePath,
    stagePublicPackage,
} from './stage-public-package.mjs';

import { normalizeTranscriptCoreKernelBytesForHash } from '#packages/wasm/src/transcript-core-bridge.js';

type PackedFileMetadata = {
    readonly path: string;
};

type PackDryRunMetadataEntry = {
    readonly files: readonly PackedFileMetadata[];
};

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const forbiddenPublishedRuntimePathFragments = ['dist/internal/'] as const;
const forbiddenPublishedTypeSupportPathFragments = [
    'dist/internal/plaintext-oracle.',
] as const;
const forbiddenPublishedOraclePathFragments = [
    'tools/lattigo-oracle/',
    'lattigo-oracle',
    'oracle-vector',
    'oracle-serializer',
] as const;
const forbiddenPublishedTestVectorPathFragments = ['test-vectors/'] as const;
const requiredPublishedPackageFilePaths = [
    'LICENSE',
    'README.md',
    'dist/index.d.ts',
    'dist/index.js',
    'dist/index.js.map',
    'dist/sealed-lattice-kernel.wasm',
    'package.json',
] as const;
const forbiddenPublishedOracleFileNames = new Set([
    'Dockerfile',
    'go.mod',
    'go.sum',
]);
const publishedKernelHashPattern =
    /expectedKernelSha256Hex:\s*(?<hash>undefined|['"][a-f0-9]{64}['"])/u;

const createDryRunPackArguments = (): readonly string[] => [
    'pack',
    '--dry-run',
    '--json',
    '--ignore-scripts',
];

const createPackArguments = (packDirectory: string): readonly string[] => [
    'pack',
    '--pack-destination',
    packDirectory,
];

const createInstallArguments = (
    packageManager: PackageManager,
    tarballPath: string,
): readonly string[] =>
    packageManager === 'npm'
        ? ['install', '--ignore-scripts', tarballPath]
        : ['add', '--ignore-scripts', tarballPath];

export const createIsolatedNpmEnvironment = (
    npmCacheDirectoryPath: string,
    baseEnvironment: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv => {
    const environment = { ...baseEnvironment };
    for (const environmentVariableName of Object.keys(environment)) {
        if (environmentVariableName.toLowerCase() === 'npm_config_cache') {
            delete environment[environmentVariableName];
        }
    }

    return {
        ...environment,
        npm_config_cache: npmCacheDirectoryPath,
    };
};

export const resolvePackedPackageNpmCacheDirectory = (
    defaultCacheDirectoryPath: string,
    environment: NodeJS.ProcessEnv = process.env,
): string =>
    Object.entries(environment).find(
        ([environmentVariableName]) =>
            environmentVariableName.toLowerCase() === 'npm_config_cache',
    )?.[1] ?? defaultCacheDirectoryPath;

const isPackedFileMetadata = (value: unknown): value is PackedFileMetadata => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }

    return typeof (value as { readonly path?: unknown }).path === 'string';
};

const isPackDryRunMetadataEntry = (
    value: unknown,
): value is PackDryRunMetadataEntry => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }

    const metadataEntry = value as { readonly files?: unknown };

    return (
        Array.isArray(metadataEntry.files) &&
        metadataEntry.files.every(isPackedFileMetadata)
    );
};

export const parsePackDryRunFilePaths = (
    packDryRunOutput: string,
): string[] => {
    const parsedMetadata = JSON.parse(packDryRunOutput) as unknown;

    if (!Array.isArray(parsedMetadata)) {
        throw new Error(
            'npm pack --dry-run --json returned an unexpected shape',
        );
    }

    const metadataEntries: readonly unknown[] = parsedMetadata;
    const metadataEntry = metadataEntries[0];
    if (!isPackDryRunMetadataEntry(metadataEntry)) {
        throw new Error(
            'npm pack --dry-run --json returned an unexpected shape',
        );
    }

    return metadataEntry.files
        .map((fileMetadata) => fileMetadata.path)
        .sort((left, right) => left.localeCompare(right));
};

export const validatePublishedPackageFilePaths = (
    publishedPackageFilePaths: readonly string[],
): string[] => {
    const failures: string[] = [];

    for (const requiredFilePath of requiredPublishedPackageFilePaths) {
        if (!publishedPackageFilePaths.includes(requiredFilePath)) {
            failures.push(
                `Published package is missing required file: ${requiredFilePath}`,
            );
        }
    }

    for (const publishedPackageFilePath of publishedPackageFilePaths) {
        if (publishedPackageFilePath.endsWith('.tsbuildinfo')) {
            failures.push(
                `Published package must not include TypeScript build metadata: ${publishedPackageFilePath}`,
            );
        }
        if (
            forbiddenPublishedRuntimePathFragments.some((fragment) =>
                publishedPackageFilePath.includes(fragment),
            )
        ) {
            failures.push(
                `Published package must not include internal protocol runtime: ${publishedPackageFilePath}`,
            );
        }
        if (
            forbiddenPublishedTypeSupportPathFragments.some((fragment) =>
                publishedPackageFilePath.includes(fragment),
            )
        ) {
            failures.push(
                `Published package must not include test-only type support: ${publishedPackageFilePath}`,
            );
        }
        if (
            forbiddenPublishedTestVectorPathFragments.some((fragment) =>
                publishedPackageFilePath.includes(fragment),
            )
        ) {
            failures.push(
                `Published package must not include repository test vectors: ${publishedPackageFilePath}`,
            );
        }

        const publishedPackageBaseName = path.basename(
            publishedPackageFilePath,
        );
        if (
            forbiddenPublishedOraclePathFragments.some((fragment) =>
                publishedPackageFilePath.includes(fragment),
            ) ||
            forbiddenPublishedOracleFileNames.has(publishedPackageBaseName) ||
            publishedPackageFilePath.endsWith('.go')
        ) {
            failures.push(
                `Published package must not include development oracle artifact: ${publishedPackageFilePath}`,
            );
        }
    }

    return failures;
};

export const validatePublishedPackageMetadata = (
    publishedPackageJson: Record<string, unknown>,
    expectedDescription: string,
): string[] => {
    const failures: string[] = [];

    if (publishedPackageJson.description !== expectedDescription) {
        failures.push(
            'Published package metadata description must match the root package description',
        );
    }
    if ('devDependencies' in publishedPackageJson) {
        failures.push(
            'Published package metadata must not include devDependencies',
        );
    }
    if ('scripts' in publishedPackageJson) {
        failures.push('Published package metadata must not include scripts');
    }

    return failures;
};

export const hashPublishedKernelBytesSha256Hex = (bytes: Uint8Array): string =>
    createHash('sha256')
        .update(normalizeTranscriptCoreKernelBytesForHash(bytes))
        .digest('hex');

export const extractPublishedKernelHash = (
    kernelRuntimeText: string,
): string | undefined => {
    const match = publishedKernelHashPattern.exec(kernelRuntimeText);
    const hash = match?.groups?.hash;
    if (hash === undefined || hash === 'undefined') {
        return undefined;
    }

    return hash.slice(1, -1);
};

export const validatePublishedKernelIntegrity = (
    kernelRuntimeText: string,
    kernelBytes: Uint8Array,
): string[] => {
    const expectedHash = extractPublishedKernelHash(kernelRuntimeText);
    if (expectedHash === undefined) {
        return [
            'Published package kernel loader must pin the packaged transcript-core WASM hash',
        ];
    }

    const actualHash = hashPublishedKernelBytesSha256Hex(kernelBytes);
    if (actualHash !== expectedHash) {
        return [
            `Published package kernel hash mismatch: expected ${expectedHash}, received ${actualHash}`,
        ];
    }

    return [];
};

const formatCapturedCommandFailure = (
    description: string,
    result: CapturedCommandResult,
): Error => {
    const output = [result.stdout.trim(), result.stderr.trim()]
        .filter((entry) => entry.length > 0)
        .join('\n');
    const termination =
        result.terminationSignal === null
            ? `exit code ${String(result.exitCode)}`
            : `signal ${result.terminationSignal}`;

    return new Error(
        `${description} failed with ${termination}${
            output.length === 0 ? '.' : `:\n${output}`
        }`,
    );
};

const runCapturedCommand = async (
    runLog: ActiveLocalRunLog,
    invocation: CommandInvocation,
): Promise<string> => {
    const result = await runCommandAndCaptureOutput(invocation, { runLog });
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        throw formatCapturedCommandFailure(invocation.description, result);
    }

    return result.stdout;
};

const runCapturedPackageManagerCommand = async (
    runLog: ActiveLocalRunLog,
    input: {
        readonly arguments: readonly string[];
        readonly description: string;
        readonly environment?: NodeJS.ProcessEnv;
        readonly logFileSlug: string;
        readonly packageManagerRunner: PackageManagerRunner;
        readonly workingDirectoryPath: string;
    },
): Promise<string> =>
    runCapturedCommand(runLog, {
        args: [
            ...input.packageManagerRunner.commandArgumentsPrefix,
            ...input.arguments,
        ],
        command: input.packageManagerRunner.command,
        description: input.description,
        env: input.environment,
        logFileSlug: input.logFileSlug,
        workingDirectoryPath: input.workingDirectoryPath,
    });

const runPublint = async (
    runLog: ActiveLocalRunLog,
    packageDirectory: string,
): Promise<void> => {
    await runCapturedPackageManagerCommand(runLog, {
        arguments: [
            'exec',
            'publint',
            'run',
            packageDirectory,
            '--pack',
            'false',
            '--strict',
        ],
        description: 'Run Publint against the staged package',
        logFileSlug: 'publint',
        packageManagerRunner: resolvePackageManagerRunner(),
        workingDirectoryPath: repoRoot,
    });
};

const runSmokeEntryPoint = async (
    runLog: ActiveLocalRunLog,
    consumerDirectory: string,
): Promise<void> => {
    await runCapturedCommand(runLog, {
        args: ['smoke.mjs'],
        command: process.execPath,
        description: 'Run the packed-package runtime smoke entry point',
        logFileSlug: 'runtime-smoke',
        workingDirectoryPath: consumerDirectory,
    });
};

const runSmokeTypeEntryPoint = async (
    runLog: ActiveLocalRunLog,
    consumerDirectory: string,
): Promise<void> => {
    const typeScriptEntryPointPath = path.resolve(
        repoRoot,
        'node_modules',
        'typescript',
        'bin',
        'tsc',
    );
    await runCapturedCommand(runLog, {
        args: [
            typeScriptEntryPointPath,
            '--module',
            'NodeNext',
            '--moduleResolution',
            'NodeNext',
            '--noEmit',
            '--strict',
            '--target',
            'ES2020',
            'smoke.ts',
        ],
        command: process.execPath,
        description: 'Type-check the packed-package consumer entry point',
        logFileSlug: 'type-smoke',
        workingDirectoryPath: consumerDirectory,
    });
};

type PackedPackageSmokeOptions = {
    readonly buildWorkspace: boolean;
};

export const parsePackedPackageSmokeArguments = (
    commandArguments: readonly string[],
): PackedPackageSmokeOptions => {
    const argumentsWithoutSeparators = commandArguments.filter(
        (argument) => argument !== '--',
    );
    if (argumentsWithoutSeparators.length === 0) {
        return { buildWorkspace: false };
    }
    if (
        argumentsWithoutSeparators.length === 1 &&
        argumentsWithoutSeparators[0] === '--build'
    ) {
        return { buildWorkspace: true };
    }

    throw new Error(
        'Packed-package smoke verification accepts only the optional --build flag.',
    );
};

const runPackedPackagePhase = async <Result>(
    runLog: ActiveLocalRunLog,
    phase: string,
    action: () => Result | Promise<Result>,
): Promise<Result> => {
    const startedAtMilliseconds = performance.now();
    runLog.writeEvent({
        details: { phase },
        eventType: 'package-smoke-phase-started',
    });
    try {
        const result = await action();
        runLog.writeEvent({
            details: {
                durationMilliseconds: Math.round(
                    performance.now() - startedAtMilliseconds,
                ),
                phase,
            },
            eventType: 'package-smoke-phase-finished',
        });

        return result;
    } catch (error) {
        runLog.writeEvent({
            details: {
                durationMilliseconds: Math.round(
                    performance.now() - startedAtMilliseconds,
                ),
                error: serializeErrorDiagnostic(error),
                phase,
            },
            eventType: 'package-smoke-phase-failed',
        });
        throw error;
    }
};

const runPackedPackageSmoke = async (
    runLog: ActiveLocalRunLog,
): Promise<void> => {
    const packageManagerRunner =
        resolvePackageManagerRunnerForPackageManager('npm');
    const tempRoot = await mkdtemp(join(tmpdir(), 'sealed-lattice-packed-'));
    const packDirectory = join(tempRoot, 'pack');
    const consumerDirectory = join(tempRoot, 'consumer');
    const packageDirectory = join(tempRoot, 'package');
    const packageManagerEnvironment = createIsolatedNpmEnvironment(
        resolvePackedPackageNpmCacheDirectory(join(tempRoot, 'npm-cache')),
    );

    try {
        const stagedPackage = await runPackedPackagePhase(
            runLog,
            'stage public package',
            async () => {
                await mkdir(packDirectory, { recursive: true });
                await mkdir(consumerDirectory, { recursive: true });

                return stagePublicPackage({
                    destinationPath: packageDirectory,
                });
            },
        );

        const publishedPackageJson = await runPackedPackagePhase(
            runLog,
            'validate staged package metadata',
            async () => {
                const [rootReadmeText, stagedReadmeText] = await Promise.all([
                    readFile(getRootReadmePath(repoRoot), 'utf8'),
                    readFile(stagedPackage.readmePath, 'utf8'),
                ]);
                if (stagedReadmeText !== rootReadmeText) {
                    throw new Error(
                        'Staged public package README must be copied from the repository root README',
                    );
                }

                const stagedManifest = JSON.parse(
                    await readFile(
                        join(packageDirectory, 'package.json'),
                        'utf8',
                    ),
                ) as Record<string, unknown>;
                const rootPackageJson = JSON.parse(
                    await readFile(getRootPackageJsonPath(repoRoot), 'utf8'),
                ) as Record<string, unknown>;
                if (
                    typeof rootPackageJson.description !== 'string' ||
                    rootPackageJson.description.length === 0
                ) {
                    throw new Error(
                        'Root package.json must define package description.',
                    );
                }

                const metadataFailures = validatePublishedPackageMetadata(
                    stagedManifest,
                    rootPackageJson.description,
                );
                if (metadataFailures.length > 0) {
                    throw new Error(metadataFailures.join('\n'));
                }

                return stagedManifest;
            },
        );

        await runPackedPackagePhase(runLog, 'run Publint', () =>
            runPublint(runLog, packageDirectory),
        );

        const publishedPackageFilePaths = await runPackedPackagePhase(
            runLog,
            'validate packed file manifest',
            async () => {
                const filePaths = parsePackDryRunFilePaths(
                    await runCapturedPackageManagerCommand(runLog, {
                        arguments: createDryRunPackArguments(),
                        description: 'Inspect the staged package file manifest',
                        environment: packageManagerEnvironment,
                        logFileSlug: 'pack-dry-run',
                        packageManagerRunner,
                        workingDirectoryPath: packageDirectory,
                    }),
                );
                const pathFailures =
                    validatePublishedPackageFilePaths(filePaths);
                if (pathFailures.length > 0) {
                    throw new Error(pathFailures.join('\n'));
                }

                return filePaths;
            },
        );

        await runPackedPackagePhase(
            runLog,
            'validate packaged kernel integrity',
            async () => {
                const kernelIntegrityFailures =
                    validatePublishedKernelIntegrity(
                        await readFile(
                            join(packageDirectory, 'dist', 'index.js'),
                            'utf8',
                        ),
                        await readFile(
                            join(
                                packageDirectory,
                                'dist',
                                'sealed-lattice-kernel.wasm',
                            ),
                        ),
                    );
                if (kernelIntegrityFailures.length > 0) {
                    throw new Error(kernelIntegrityFailures.join('\n'));
                }
            },
        );

        const tarballPath = await runPackedPackagePhase(
            runLog,
            'create package tarball',
            async () => {
                await runCapturedPackageManagerCommand(runLog, {
                    arguments: createPackArguments(packDirectory),
                    description: 'Create the packed-package tarball',
                    environment: packageManagerEnvironment,
                    logFileSlug: 'pack-tarball',
                    packageManagerRunner,
                    workingDirectoryPath: packageDirectory,
                });

                const tarballs = (await readdir(packDirectory)).filter(
                    (entry) => entry.endsWith('.tgz'),
                );
                if (tarballs.length !== 1) {
                    throw new Error(
                        `Expected exactly one packed tarball, received ${tarballs.length}`,
                    );
                }

                return join(packDirectory, tarballs[0] ?? '');
            },
        );

        await runPackedPackagePhase(
            runLog,
            'prepare packed-package consumer',
            async () => {
                await writeFile(
                    join(consumerDirectory, 'package.json'),
                    `${JSON.stringify(
                        {
                            name: 'sealed-lattice-smoke-consumer',
                            private: true,
                            type: 'module',
                        },
                        null,
                        2,
                    )}\n`,
                    'utf8',
                );
                await copyFile(
                    path.join(
                        repoRoot,
                        'tools',
                        'ci',
                        'packed-package-smoke.mjs',
                    ),
                    join(consumerDirectory, 'smoke.mjs'),
                );
                await writeFile(
                    join(consumerDirectory, 'smoke.ts'),
                    [
                        "import { deriveThresholdParameters, validatePollSpec, type PollSpecInput, type ThresholdParameters } from 'sealed-lattice';",
                        '',
                        'const pollSpecInput: PollSpecInput = {',
                        "    pollId: 'packed-package-types',",
                        "    question: 'Which option?',",
                        "    options: ['A', 'B'],",
                        '    topOptionCount: 1,',
                        '};',
                        'const pollValidation = validatePollSpec(pollSpecInput);',
                        "if (!pollValidation.isValid) throw new Error('Packed poll validation failed.');",
                        'const parameters: ThresholdParameters = deriveThresholdParameters({ rosterSize: 10 });',
                        'void pollValidation.normalized;',
                        'void parameters;',
                        '',
                    ].join('\n'),
                    'utf8',
                );
            },
        );

        await runPackedPackagePhase(runLog, 'install packed package', () =>
            runCapturedPackageManagerCommand(runLog, {
                arguments: createInstallArguments(
                    packageManagerRunner.kind,
                    tarballPath,
                ),
                description: 'Install the tarball into the smoke consumer',
                environment: packageManagerEnvironment,
                logFileSlug: 'install-tarball',
                packageManagerRunner,
                workingDirectoryPath: consumerDirectory,
            }),
        );
        await runPackedPackagePhase(runLog, 'run package runtime smoke', () =>
            runSmokeEntryPoint(runLog, consumerDirectory),
        );
        await runPackedPackagePhase(runLog, 'run package type smoke', () =>
            runSmokeTypeEntryPoint(runLog, consumerDirectory),
        );

        const tarballBytes = await readFile(tarballPath);
        const packageEvidence = {
            objectVersion: 'sealed-lattice-package-smoke-evidence-v1',
            packageName: publishedPackageJson.name,
            packageVersion: publishedPackageJson.version,
            publishedFilePaths: publishedPackageFilePaths,
            tarballByteLength: tarballBytes.byteLength,
            tarballFileName: path.basename(tarballPath),
            tarballSha256Hex: createHash('sha256')
                .update(tarballBytes)
                .digest('hex'),
        };
        await writeFile(
            path.join(runLog.runDirectoryPath, 'package-smoke-evidence.json'),
            `${JSON.stringify(packageEvidence, null, 2)}\n`,
            'utf8',
        );
        runLog.writeEvent({
            details: packageEvidence,
            eventType: 'package-smoke-evidence-recorded',
        });

        console.log(
            `Packed package smoke test passed with ${packageManagerRunner.kind}.`,
        );
    } finally {
        await rm(tempRoot, { recursive: true, force: true });
    }
};

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    await runWithLocalRunLog(
        {
            commandLineArguments: rawArguments,
            lanes: ['Packed package smoke'],
            scriptName: 'smoke:pack:npm',
        },
        async (runLog) => {
            const options = parsePackedPackageSmokeArguments(rawArguments);
            if (options.buildWorkspace) {
                const exitCode = await runCommandsInSeries(
                    [
                        createPackageManagerCommand(
                            'Build workspace packages for packed-package smoke',
                            ['run', 'build'],
                            {
                                logFileSlug: 'build',
                                packageManagerRunner:
                                    resolvePackageManagerRunner(),
                            },
                        ),
                    ],
                    { runLog },
                );
                if (exitCode !== 0) {
                    process.exitCode = exitCode;
                    throw new Error(
                        `Packed-package smoke build failed with exit code ${exitCode}.`,
                    );
                }
            }

            await runPackedPackageSmoke(runLog);
        },
    );
};

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    void main();
}
