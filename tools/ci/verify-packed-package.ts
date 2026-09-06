import { createHash } from 'node:crypto';
import { constants as fileSystemConstants } from 'node:fs';
import {
    appendFile,
    copyFile,
    cp,
    mkdir,
    mkdtemp,
    readFile,
    rm,
    writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    resolvePackageManagerRunnerForPackageManager,
    type PackageManagerRunner,
} from './package-manager-runner.js';
import {
    runCommandAndCaptureOutput,
    type CommandInvocation,
} from './run-command.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const expectedPackageFiles = [
    'LICENSE',
    'README.md',
    'dist/index.d.ts',
    'dist/index.js',
    'dist/index.js.map',
    'dist/sealed-lattice-kernel.wasm',
    'package.json',
] as const;

type PackMetadata = {
    readonly filename: string;
    readonly files: readonly string[];
    readonly integrity: string;
    readonly name: string;
    readonly version: string;
};

const requireRecord = (
    value: unknown,
    description: string,
): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${description} is not an object.`);
    }
    return value as Record<string, unknown>;
};

const parsePackMetadata = (output: string): PackMetadata => {
    const parsed = JSON.parse(output) as unknown;
    if (!Array.isArray(parsed) || parsed.length !== 1) {
        throw new Error('npm pack returned an unexpected result.');
    }
    const entry = requireRecord(parsed[0], 'npm pack result');
    if (
        typeof entry.filename !== 'string' ||
        !Array.isArray(entry.files) ||
        typeof entry.integrity !== 'string' ||
        typeof entry.name !== 'string' ||
        typeof entry.version !== 'string'
    ) {
        throw new Error('npm pack omitted required metadata.');
    }
    const files = entry.files.map((file, index) => {
        const metadata = requireRecord(file, `npm pack file ${String(index)}`);
        if (typeof metadata.path !== 'string') {
            throw new Error('npm pack returned a file without a path.');
        }
        return metadata.path;
    });
    return {
        filename: entry.filename,
        files,
        integrity: entry.integrity,
        name: entry.name,
        version: entry.version,
    };
};

const runCommand = async (
    runLog: ActiveLocalRunLog,
    invocation: CommandInvocation,
): Promise<string> => {
    const result = await runCommandAndCaptureOutput(invocation, { runLog });
    if (result.exitCode !== 0 || result.terminationSignal !== null) {
        const output = [result.stdout.trim(), result.stderr.trim()]
            .filter(Boolean)
            .join('\n');
        throw new Error(
            `${invocation.description} failed${
                output.length === 0 ? '.' : `:\n${output}`
            }`,
        );
    }
    return result.stdout;
};

const runPackageManager = (
    runLog: ActiveLocalRunLog,
    runner: PackageManagerRunner,
    arguments_: readonly string[],
    input: {
        readonly description: string;
        readonly environment?: NodeJS.ProcessEnv;
        readonly workingDirectoryPath: string;
    },
): Promise<string> =>
    runCommand(runLog, {
        args: [...runner.commandArgumentsPrefix, ...arguments_],
        command: runner.command,
        description: input.description,
        env: input.environment,
        workingDirectoryPath: input.workingDirectoryPath,
    });

const stagePublicPackage = async (destinationPath: string): Promise<void> => {
    const sourcePath = path.join(repositoryRoot, 'packages', 'sdk');
    await mkdir(destinationPath);
    const manifest = JSON.parse(
        await readFile(path.join(sourcePath, 'package.json'), 'utf8'),
    ) as Record<string, unknown>;
    delete manifest.devDependencies;
    delete manifest.scripts;
    await Promise.all([
        cp(path.join(sourcePath, 'dist'), path.join(destinationPath, 'dist'), {
            recursive: true,
        }),
        copyFile(
            path.join(repositoryRoot, 'README.md'),
            path.join(destinationPath, 'README.md'),
        ),
        copyFile(
            path.join(repositoryRoot, 'LICENSE'),
            path.join(destinationPath, 'LICENSE'),
        ),
        writeFile(
            path.join(destinationPath, 'package.json'),
            `${JSON.stringify(manifest, null, 4)}\n`,
            'utf8',
        ),
    ]);
};

const npmEnvironment = (cacheDirectoryPath: string): NodeJS.ProcessEnv => ({
    ...Object.fromEntries(
        Object.entries(process.env).filter(
            ([name]) => name.toLowerCase() !== 'npm_config_cache',
        ),
    ),
    npm_config_cache: cacheDirectoryPath,
});

const requireExactPackageFiles = (actualFiles: readonly string[]): void => {
    const actual = [...actualFiles].sort();
    const expected = [...expectedPackageFiles].sort();
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
        throw new Error(
            `Published package files differ. Expected ${expected.join(', ')}; received ${actual.join(', ')}.`,
        );
    }
};

const requireSelfContainedBundle = async (
    packageDirectoryPath: string,
): Promise<void> => {
    const [runtimeSource, declarationSource] = await Promise.all([
        readFile(path.join(packageDirectoryPath, 'dist', 'index.js'), 'utf8'),
        readFile(path.join(packageDirectoryPath, 'dist', 'index.d.ts'), 'utf8'),
    ]);
    if (runtimeSource.includes('@sealed-lattice/')) {
        throw new Error('Published runtime output retains a workspace import.');
    }
    if (declarationSource.includes('@sealed-lattice/')) {
        throw new Error(
            'Published declaration output retains a workspace import.',
        );
    }
    if (runtimeSource.includes('__SEALED_LATTICE_KERNEL_SHA256_HEX__')) {
        throw new Error(
            'Published runtime output has an unresolved kernel hash.',
        );
    }
};

const requireFoundationOnlyKernel = async (
    packageDirectoryPath: string,
): Promise<void> => {
    const kernel = new WebAssembly.Module(
        await readFile(
            path.join(
                packageDirectoryPath,
                'dist',
                'sealed-lattice-kernel.wasm',
            ),
        ),
    );
    const exportNames = WebAssembly.Module.exports(kernel)
        .map((entry) => entry.name)
        .sort();
    const expectedExportNames = [
        '__data_end',
        '__heap_base',
        'memory',
        'sealed_lattice_allocate',
        'sealed_lattice_deallocate',
        'sealed_lattice_foundation_command_with_length',
    ].sort();
    if (JSON.stringify(exportNames) !== JSON.stringify(expectedExportNames)) {
        throw new Error(
            `Published WebAssembly exports differ from the foundation-only inventory: ${exportNames.join(', ')}.`,
        );
    }
};

const writeConsumer = async (consumerDirectoryPath: string): Promise<void> => {
    await mkdir(consumerDirectoryPath);
    await Promise.all([
        writeFile(
            path.join(consumerDirectoryPath, 'package.json'),
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
        ),
        writeFile(
            path.join(consumerDirectoryPath, 'smoke.mjs'),
            [
                "import { createCanonicalBoardPolicy, verifyCanonicalBoardPolicy } from 'sealed-lattice';",
                "const policy = await createCanonicalBoardPolicy({ boardOriginIdentifier: 'https://board.example' });",
                'const verification = await verifyCanonicalBoardPolicy(policy.canonicalBytes);',
                "if (!verification.isValid) throw new Error('Packed WASM verification refused.');",
                '',
            ].join('\n'),
            'utf8',
        ),
        writeFile(
            path.join(consumerDirectoryPath, 'smoke.ts'),
            [
                "import { createCanonicalBoardPolicy, type CanonicalFoundationBoardPolicy } from 'sealed-lattice';",
                "const policy: Promise<CanonicalFoundationBoardPolicy> = createCanonicalBoardPolicy({ boardOriginIdentifier: 'https://board.example' });",
                'void policy;',
                '',
            ].join('\n'),
            'utf8',
        ),
    ]);
};

const parseOutputPath = (arguments_: readonly string[]): string | undefined => {
    const normalizedArguments =
        arguments_[0] === '--' ? arguments_.slice(1) : arguments_;
    if (normalizedArguments.length === 0) return undefined;
    if (
        normalizedArguments.length === 2 &&
        normalizedArguments[0] === '--out' &&
        normalizedArguments[1] !== undefined
    ) {
        return path.resolve(normalizedArguments[1]);
    }
    throw new Error('Usage: verify-packed-package.ts [--out <tarball-path>].');
};

const verifyPackedPackage = async (
    runLog: ActiveLocalRunLog,
    retainedTarballPath?: string,
): Promise<{ readonly integrity: string; readonly tarballPath?: string }> => {
    const temporaryRoot = await mkdtemp(
        path.join(tmpdir(), 'sealed-lattice-packed-'),
    );
    const packageDirectory = path.join(temporaryRoot, 'package');
    const packDirectory = path.join(temporaryRoot, 'pack');
    const consumerDirectory = path.join(temporaryRoot, 'consumer');
    const npmRunner = resolvePackageManagerRunnerForPackageManager('npm');
    const environment = npmEnvironment(path.join(temporaryRoot, 'npm-cache'));

    try {
        await mkdir(packDirectory);
        await stagePublicPackage(packageDirectory);
        await requireSelfContainedBundle(packageDirectory);
        await requireFoundationOnlyKernel(packageDirectory);
        await runPackageManager(
            runLog,
            resolvePackageManagerRunner(),
            [
                'exec',
                'publint',
                'run',
                packageDirectory,
                '--pack',
                'false',
                '--strict',
            ],
            {
                description: 'Run Publint against the staged package',
                workingDirectoryPath: repositoryRoot,
            },
        );

        const packed = parsePackMetadata(
            await runPackageManager(
                runLog,
                npmRunner,
                [
                    'pack',
                    '--json',
                    '--ignore-scripts',
                    '--pack-destination',
                    packDirectory,
                ],
                {
                    description: 'Create the public package tarball',
                    environment,
                    workingDirectoryPath: packageDirectory,
                },
            ),
        );
        requireExactPackageFiles(packed.files);
        const manifest = JSON.parse(
            await readFile(path.join(packageDirectory, 'package.json'), 'utf8'),
        ) as Record<string, unknown>;
        if ('devDependencies' in manifest || 'scripts' in manifest) {
            throw new Error(
                'The public package retains workspace-only manifest fields.',
            );
        }
        if (
            packed.name !== manifest.name ||
            packed.version !== manifest.version
        ) {
            throw new Error(
                `npm packed ${packed.name}@${packed.version}, expected ${String(manifest.name)}@${String(manifest.version)}.`,
            );
        }
        const tarballPath = path.resolve(packDirectory, packed.filename);
        if (path.dirname(tarballPath) !== path.resolve(packDirectory)) {
            throw new Error(
                'npm pack returned a path outside its destination.',
            );
        }

        await writeConsumer(consumerDirectory);
        await runPackageManager(
            runLog,
            npmRunner,
            [
                'install',
                '--ignore-scripts',
                '--no-audit',
                '--no-fund',
                tarballPath,
            ],
            {
                description: 'Install the public tarball in an empty consumer',
                environment,
                workingDirectoryPath: consumerDirectory,
            },
        );
        await runCommand(runLog, {
            args: ['smoke.mjs'],
            command: process.execPath,
            description: 'Execute the packed WebAssembly API',
            workingDirectoryPath: consumerDirectory,
        });
        await runCommand(runLog, {
            args: [
                path.join(
                    repositoryRoot,
                    'node_modules',
                    'typescript',
                    'bin',
                    'tsc',
                ),
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
            description: 'Type-check a strict packed-package consumer',
            workingDirectoryPath: consumerDirectory,
        });

        const integrity = `sha512-${createHash('sha512')
            .update(await readFile(tarballPath))
            .digest('base64')}`;
        if (integrity !== packed.integrity) {
            throw new Error('npm pack reported the wrong tarball integrity.');
        }
        if (retainedTarballPath !== undefined) {
            await mkdir(path.dirname(retainedTarballPath), { recursive: true });
            await copyFile(
                tarballPath,
                retainedTarballPath,
                fileSystemConstants.COPYFILE_EXCL,
            );
        }
        runLog.writeEvent({
            details: {
                integrity,
                packageName: packed.name,
                packageVersion: packed.version,
            },
            eventType: 'package-smoke-passed',
        });
        return {
            integrity,
            ...(retainedTarballPath === undefined
                ? {}
                : { tarballPath: retainedTarballPath }),
        };
    } finally {
        await rm(temporaryRoot, { force: true, recursive: true });
    }
};

const main = async (): Promise<void> => {
    const arguments_ = process.argv.slice(2);
    await runWithLocalRunLog(
        {
            commandLineArguments: arguments_,
            lanes: ['Packed package smoke'],
            scriptName: 'smoke:pack:npm',
        },
        async (runLog) => {
            const result = await verifyPackedPackage(
                runLog,
                parseOutputPath(arguments_),
            );
            if (
                result.tarballPath !== undefined &&
                process.env.GITHUB_OUTPUT !== undefined
            ) {
                await appendFile(
                    process.env.GITHUB_OUTPUT,
                    `tarball=${result.tarballPath}\nintegrity=${result.integrity}\n`,
                    'utf8',
                );
            }
            console.log('Packed package smoke test passed.');
        },
    );
};

if (import.meta.main) void main();
