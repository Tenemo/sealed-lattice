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

import {
    checkParticipantModule,
    participantRuntimeIdentity,
} from './build-participant-module.js';
import { runCheckedCommand, type CommandInvocation } from './command-runner.js';
import { runWithLocalRunLog, type ActiveLocalRunLog } from './local-run-log.js';
import {
    resolvePackageManagerRunner,
    resolvePackageManagerRunnerForPackageManager,
    type PackageManagerRunner,
} from './package-manager-runner.js';

import { helperFunctions } from '#packages/sdk/src/participant/worker/module/parallel-helper-instance.js';
import { moduleFunctions } from '#packages/sdk/src/participant/worker/module/participant-module.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const expectedPackageFiles = [
    'LICENSE',
    'README.md',
    'dist/index.d.ts',
    'dist/index.js',
    'dist/index.js.map',
    'dist/participant-source-manifest.json',
    'dist/participant-worker.js',
    'dist/participant.wasm',
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

const runCommand = (
    runLog: ActiveLocalRunLog,
    invocation: CommandInvocation,
): Promise<string> => runCheckedCommand(invocation, { runLog });

const runPackageManager = (
    runLog: ActiveLocalRunLog,
    runner: PackageManagerRunner,
    commandLineArguments: readonly string[],
    input: {
        readonly description: string;
        readonly environment?: NodeJS.ProcessEnv;
        readonly workingDirectoryPath: string;
    },
): Promise<string> =>
    runCommand(runLog, {
        args: [...runner.commandArgumentsPrefix, ...commandLineArguments],
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
};

// The published participant module exports exactly what the worker and its
// helpers call, the worker is one self-contained module, and the source manifest names no
// machine path. Returns the digests of the published files that the SDK
// passes its worker.
const requireParticipantRuntime = async (packageDirectoryPath: string) => {
    const dist = path.join(packageDirectoryPath, 'dist');
    const [module, worker, manifest] = await Promise.all([
        readFile(path.join(dist, 'participant.wasm')),
        readFile(path.join(dist, 'participant-worker.js'), 'utf8'),
        readFile(path.join(dist, 'participant-source-manifest.json'), 'utf8'),
    ]);
    await checkParticipantModule(module);
    const exportNames = WebAssembly.Module.exports(
        new WebAssembly.Module(module),
    )
        .map((entry) => entry.name)
        .sort();
    const expectedExportNames = [
        ...moduleFunctions,
        ...helperFunctions,
        '__data_end',
        '__heap_base',
        'memory',
    ].sort();
    if (JSON.stringify(exportNames) !== JSON.stringify(expectedExportNames))
        throw new Error(
            `Published participant module exports differ from the worker's inventory: ${exportNames.join(', ')}.`,
        );
    if (
        /^\s*import(?:\s+[\w$*{"']|\s*[{*"'])|\bimport\s*\(/mu.test(worker) ||
        worker.includes('@sealed-lattice/')
    )
        throw new Error('The published participant worker imports a module.');
    const parsed = JSON.parse(manifest) as unknown;
    const record = requireRecord(parsed, 'Participant source manifest');
    const files = record.files;
    const tools = requireRecord(record.tools, 'Participant build tools');
    if (
        typeof record.compiler !== 'string' ||
        !Array.isArray(record.flags) ||
        !record.flags.every((value) => typeof value === 'string') ||
        Object.keys(tools).join(',') !== 'rolldown,tsdown,typescript' ||
        !Object.values(tools).every(
            (version) =>
                typeof version === 'string' && /^\d+\.\d+\.\d+$/u.test(version),
        ) ||
        !Array.isArray(files) ||
        files.length === 0 ||
        !files.every((value, index) => {
            const entry = requireRecord(value, 'Participant source');
            return (
                typeof entry.file === 'string' &&
                typeof entry.sha512 === 'string' &&
                /^[0-9a-f]{128}$/u.test(entry.sha512) &&
                Number.isSafeInteger(entry.bytes) &&
                (index === 0 ||
                    String(
                        requireRecord(files[index - 1], 'Participant source')
                            .file,
                    ) < entry.file)
            );
        }) ||
        /[A-Za-z]:[\\/]|\/(?:home|Users)\//u.test(manifest) ||
        manifest !== JSON.stringify(parsed) + '\n'
    )
        throw new Error(
            'The published participant source manifest is malformed.',
        );
    const identity = participantRuntimeIdentity(
        Buffer.from(manifest),
        module,
        Buffer.from(worker),
    );
    return {
        source: identity.source,
        module: identity.module,
        worker: identity.worker,
    };
};

// Runs the installed participant API against stand-in workers, which check
// that the API starts the published worker's exact source and passes it the
// digests of the published files, the published module's URL, the
// namespace, the normalized relay and whether evaluation is separate. A
// refused request ends its one worker. A worker that answers that it
// evaluated ends, and a fresh one runs the same command without separating
// evaluation, whose result also reports the evaluating worker's memory.
const participantConsumer = [
    "import { resolveObjectURL } from 'node:buffer';",
    "import { readFile } from 'node:fs/promises';",
    '',
    'const expected = JSON.parse(process.argv[2]);',
    "const entry = import.meta.resolve('sealed-lattice');",
    "const worker = await readFile(new URL('./participant-worker.js', entry), 'utf8');",
    'let started = 0;',
    'let running = 0;',
    'const commands = [];',
    'const answers = [];',
    'globalThis.Worker = class {',
    '    constructor(url, options) {',
    '        started++;',
    '        running++;',
    "        if (running > 1) throw new Error('The participant API started a worker beside another.');",
    '        this.source = resolveObjectURL(url).text();',
    "        if (options?.type !== 'module') throw new Error('The participant worker is not a module.');",
    '    }',
    '    postMessage(command) {',
    '        void this.source.then((source) => {',
    "            if (source !== worker) throw new Error('The participant API started another worker.');",
    '            commands.push(JSON.stringify(command));',
    '            this.onmessage({ data: answers.shift() });',
    '        });',
    '    }',
    '    terminate() {',
    '        running--;',
    '    }',
    '};',
    'const command = (operation, separateEvaluation) =>',
    '    JSON.stringify({',
    '        operation,',
    '        parameters: {},',
    "        namespace: 'smoke-poll',",
    "        relay: 'https://relay.example/polls/',",
    "        module: new URL('./participant.wasm', entry).href,",
    '        identity: expected,',
    '        separateEvaluation,',
    '    });',
    "const { openParticipant } = await import('sealed-lattice');",
    "const participant = openParticipant({ namespace: 'smoke-poll', relay: 'https://relay.example/polls' });",
    "answers.push({ status: 'refused' });",
    "const refused = await participant.run({ operation: 'status' });",
    "if (refused.status !== 'refused' || started !== 1 || running !== 0 || commands[0] !== command('status', true))",
    "    throw new Error('The participant API did not return the worker result: ' + commands[0]);",
    'answers.push(',
    "    { status: 'evaluated', memory: { workerBytes: 2 } },",
    "    { status: 'completed', details: { memory: { workerBytes: 1 } } },",
    ');',
    "const released = await participant.run({ operation: 'release' });",
    'if (',
    '    started !== 3 ||',
    '    running !== 0 ||',
    "    commands[1] !== command('release', true) ||",
    "    commands[2] !== command('release', false) ||",
    '    JSON.stringify(released) !==',
    // Node offers no storage manager, so the storage stays best-effort.
    "        JSON.stringify({ status: 'completed', details: { memory: { workerBytes: 1 }, evaluationMemory: { workerBytes: 2 }, isStoragePersistent: false } })",
    ')',
    "    throw new Error('The participant API did not run a separate evaluation: ' + JSON.stringify(released));",
    '',
].join('\n');

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
            path.join(consumerDirectoryPath, 'participant.mjs'),
            participantConsumer,
            'utf8',
        ),
        writeFile(
            path.join(consumerDirectoryPath, 'smoke.ts'),
            [
                "import { openParticipant, type ParticipantResponse, type ParticipantSummary } from 'sealed-lattice';",
                "const participant = openParticipant({ namespace: 'smoke-poll', relay: 'https://relay.example/polls' });",
                "const result: Promise<ParticipantResponse> = participant.run({ operation: 'status' });",
                "const options: ParticipantSummary['options'] = [{ identifier: 'option-0', label: 'Option 0' }];",
                'void result;',
                'void options;',
                '',
            ].join('\n'),
            'utf8',
        ),
    ]);
};

const parseOutputPath = (
    commandLineArguments: readonly string[],
): string | undefined => {
    const normalizedArguments =
        commandLineArguments[0] === '--'
            ? commandLineArguments.slice(1)
            : commandLineArguments;
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
        const participantIdentity =
            await requireParticipantRuntime(packageDirectory);
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
            args: ['participant.mjs', JSON.stringify(participantIdentity)],
            command: process.execPath,
            description: 'Start the packed participant worker',
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
    const commandLineArguments = process.argv.slice(2);
    await runWithLocalRunLog(
        {
            commandLineArguments: commandLineArguments,
            lanes: ['Packed package smoke'],
            scriptName: 'smoke:pack:npm',
        },
        async (runLog) => {
            const result = await verifyPackedPackage(
                runLog,
                parseOutputPath(commandLineArguments),
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
