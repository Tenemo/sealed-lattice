import { createHash } from 'node:crypto';
import {
    copyFile,
    mkdtemp,
    mkdir,
    readFile,
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
import { stagePublicPackage } from './stage-public-package.mjs';

import { normalizeTranscriptCoreKernelBytesForHash } from '#packages/wasm/src/transcript-core-bridge.js';
import { extractModuleSpecifiers } from '#tools/internal/module-specifiers.js';

type PackedFileMetadata = {
    readonly path: string;
};

type PackMetadataEntry = {
    readonly filename: string;
    readonly files: readonly PackedFileMetadata[];
};

const repoRoot = fileURLToPath(new URL('../../', import.meta.url));
const expectedPublishedPackageFilePaths = [
    'LICENSE',
    'README.md',
    'dist/index.d.ts',
    'dist/index.js',
    'dist/index.js.map',
    'dist/sealed-lattice-kernel.wasm',
    'package.json',
] as const;
const publishedKernelHashPattern =
    /expectedKernelSha256Hex:\s*(?<hash>undefined|['"][a-f0-9]{64}['"])/u;
const unresolvedKernelHashToken =
    '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__';

const createPackArguments = (packDirectory: string): readonly string[] => [
    'pack',
    '--json',
    '--ignore-scripts',
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

const isPackMetadataEntry = (value: unknown): value is PackMetadataEntry => {
    if (typeof value !== 'object' || value === null) {
        return false;
    }

    const metadataEntry = value as {
        readonly filename?: unknown;
        readonly files?: unknown;
    };

    return (
        typeof metadataEntry.filename === 'string' &&
        Array.isArray(metadataEntry.files) &&
        metadataEntry.files.every(isPackedFileMetadata)
    );
};

export const parsePackMetadata = (
    packOutput: string,
): { readonly filename: string; readonly filePaths: readonly string[] } => {
    const parsedMetadata = JSON.parse(packOutput) as unknown;

    if (!Array.isArray(parsedMetadata) || parsedMetadata.length !== 1) {
        throw new Error('npm pack --json returned an unexpected shape');
    }

    const metadataEntries: readonly unknown[] = parsedMetadata;
    const metadataEntry = metadataEntries[0];
    if (!isPackMetadataEntry(metadataEntry)) {
        throw new Error('npm pack --json returned an unexpected shape');
    }

    return {
        filename: metadataEntry.filename,
        filePaths: metadataEntry.files
            .map((fileMetadata) => fileMetadata.path)
            .sort((left, right) => left.localeCompare(right)),
    };
};

export const validatePublishedPackageFilePaths = (
    publishedPackageFilePaths: readonly string[],
): string[] => {
    const actualFilePaths = [...publishedPackageFilePaths].sort((left, right) =>
        left.localeCompare(right),
    );
    const expectedFilePaths = [...expectedPublishedPackageFilePaths].sort(
        (left, right) => left.localeCompare(right),
    );
    return JSON.stringify(actualFilePaths) === JSON.stringify(expectedFilePaths)
        ? []
        : [
              `Published package file set mismatch. Expected ${expectedFilePaths.join(', ')}; received ${actualFilePaths.join(', ')}`,
          ];
};

export const validatePublishedPackageBundle = (input: {
    readonly declarationSourceText: string;
    readonly runtimeSourceText: string;
}): string[] => {
    const failures: string[] = [];
    for (const [outputLabel, sourceText] of [
        ['runtime', input.runtimeSourceText],
        ['declaration', input.declarationSourceText],
    ] as const) {
        for (const moduleSpecifier of extractModuleSpecifiers(sourceText)) {
            if (moduleSpecifier.startsWith('@sealed-lattice/')) {
                failures.push(
                    `Published ${outputLabel} output must bundle internal workspace import "${moduleSpecifier}"`,
                );
            }
        }
    }
    if (input.runtimeSourceText.includes(unresolvedKernelHashToken)) {
        failures.push(
            'Published runtime output contains the unresolved WASM integrity token',
        );
    }
    return failures.sort((left, right) => left.localeCompare(right));
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
        await runPackedPackagePhase(
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

        const publishedPackageJson = JSON.parse(
            await readFile(join(packageDirectory, 'package.json'), 'utf8'),
        ) as Record<string, unknown>;

        await runPackedPackagePhase(runLog, 'run Publint', () =>
            runPublint(runLog, packageDirectory),
        );

        await runPackedPackagePhase(
            runLog,
            'validate bundled output and kernel integrity',
            async () => {
                const [runtimeSourceText, declarationSourceText, kernelBytes] =
                    await Promise.all([
                        readFile(
                            join(packageDirectory, 'dist', 'index.js'),
                            'utf8',
                        ),
                        readFile(
                            join(packageDirectory, 'dist', 'index.d.ts'),
                            'utf8',
                        ),
                        readFile(
                            join(
                                packageDirectory,
                                'dist',
                                'sealed-lattice-kernel.wasm',
                            ),
                        ),
                    ]);
                const bundleFailures = validatePublishedPackageBundle({
                    declarationSourceText,
                    runtimeSourceText,
                });
                const kernelIntegrityFailures =
                    validatePublishedKernelIntegrity(
                        runtimeSourceText,
                        kernelBytes,
                    );
                const failures = [
                    ...bundleFailures,
                    ...kernelIntegrityFailures,
                ];
                if (failures.length > 0) {
                    throw new Error(failures.join('\n'));
                }
            },
        );

        const packedPackage = await runPackedPackagePhase(
            runLog,
            'create and inspect package tarball',
            async () => {
                const packMetadata = parsePackMetadata(
                    await runCapturedPackageManagerCommand(runLog, {
                        arguments: createPackArguments(packDirectory),
                        description: 'Create the packed-package tarball',
                        environment: packageManagerEnvironment,
                        logFileSlug: 'pack-tarball',
                        packageManagerRunner,
                        workingDirectoryPath: packageDirectory,
                    }),
                );
                const pathFailures = validatePublishedPackageFilePaths(
                    packMetadata.filePaths,
                );
                if (pathFailures.length > 0) {
                    throw new Error(pathFailures.join('\n'));
                }
                const tarballPath = path.resolve(
                    packDirectory,
                    packMetadata.filename,
                );
                if (path.dirname(tarballPath) !== path.resolve(packDirectory)) {
                    throw new Error(
                        'npm pack returned a filename outside the package directory.',
                    );
                }

                return {
                    filePaths: packMetadata.filePaths,
                    tarballPath,
                };
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
                        "import { verifyPrivateVssShare, type PrivateVssShareVerification, type VerifyPrivateVssShareInput } from 'sealed-lattice';",
                        '',
                        'declare const input: VerifyPrivateVssShareInput;',
                        'const verification: Promise<PrivateVssShareVerification> = verifyPrivateVssShare(input);',
                        'void verification;',
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
                    packedPackage.tarballPath,
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

        const tarballBytes = await readFile(packedPackage.tarballPath);
        const packageEvidence = {
            objectVersion: 'sealed-lattice-package-smoke-evidence-v1',
            packageName: publishedPackageJson.name,
            packageVersion: publishedPackageJson.version,
            publishedFilePaths: packedPackage.filePaths,
            tarballByteLength: tarballBytes.byteLength,
            tarballFileName: path.basename(packedPackage.tarballPath),
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
