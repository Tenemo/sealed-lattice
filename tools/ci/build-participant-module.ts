import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import binaryen from 'binaryen';

import { participantRuntimeLabel } from '#packages/sdk/src/participant/worker/identity.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const workspace = path.join(repositoryRoot, 'crates', 'protocol-research');
// The participant module's linear memory never exceeds the absolute bound.
const maximumMemoryBytes = 671_088_640;
const rustflagSeparator = '\x1f';
const compilerCommit = '59807616e1fa2540724bfbac14d7976d7e4a3860';

// The imports the participant module may declare, by module and name.
const allowedImports = [
    'allocator.exhausted',
    'ballot.fill_random',
    'contribution.public_chunk',
    'enrollment.fill_random',
    'enrollment.staged_chunk',
    'parallel.discard',
    'parallel.helpers',
    'parallel.release',
    'parallel.share',
    'parallel.submit',
    'parallel.take',
    'parallel.wait',
    'setup_witness.fill_random',
    'word_proof.fill_random',
];

// The sources the participant module and worker are built from, beside the
// Rust workspace: the worker's own sources, the archive client, transcript
// format and foundation runtime the worker bundles, and the scripts that
// build both.
const sourceDirectories = [
    'crates/protocol-research',
    'packages/sdk/src/participant/worker',
    'packages/sdk/src/public-archive.ts',
    'packages/sdk/src/transcript-archive.ts',
    'packages/wasm/src',
];
const buildScripts = [
    'tools/ci/build-participant-module.ts',
    'tools/ci/build-sdk-package.ts',
];

export type ParticipantModuleBuild = Readonly<{
    module: Buffer;
    // The compiler's version report without its host line, and the compiler
    // flags with the machine's paths replaced by their names, so neither
    // depends on the machine that built the module.
    compiler: string;
    flags: readonly string[];
}>;

const run = (
    command: string,
    argumentsList: readonly string[],
    environment: NodeJS.ProcessEnv,
    capture: boolean,
): string => {
    const result = spawnSync(command, argumentsList, {
        cwd: workspace,
        encoding: 'utf8',
        env: environment,
        stdio: ['ignore', capture ? 'pipe' : 'inherit', 'inherit'],
        windowsHide: true,
    });
    if (result.error !== undefined) throw result.error;
    if (result.status !== 0)
        throw new Error(
            `${command} failed${result.signal === null ? ` with status ${String(result.status)}` : ` with signal ${result.signal}`}.`,
        );
    return capture ? result.stdout : '';
};

// Checks that a participant module has only scalar code, the bounded
// memory and the imports the worker supplies.
export const checkParticipantModule = async (
    module: Uint8Array,
): Promise<void> => {
    const inspected = binaryen.readBinary(module);
    try {
        if (
            /\b(?:v128|i8x16|i16x8|i32x4|i64x2|f32x4|f64x2)\./u.test(
                inspected.emitText(),
            )
        )
            throw new Error(
                'The participant module contains vector instructions.',
            );
        const memory = inspected.getMemoryInfo();
        if (
            memory.shared ||
            memory.is64 ||
            memory.max !== maximumMemoryBytes / 65_536
        )
            throw new Error(
                'The participant module memory is not the bounded scalar memory.',
            );
    } finally {
        inspected.dispose();
    }
    const imports = WebAssembly.Module.imports(
        await WebAssembly.compile(new Uint8Array(module)),
    );
    if (
        !imports.every(
            (value) =>
                value.kind === 'function' &&
                allowedImports.includes(value.module + '.' + value.name),
        )
    )
        throw new Error(
            'The participant module declares an unexpected import.',
        );
};

// Builds the scalar participant module from the research workspace and
// checks its scalar code, bounded memory and imports. A feature builds a
// corrupt client's module in its own target directory.
export const buildParticipantModule = async (
    feature?: string,
): Promise<ParticipantModuleBuild> => {
    if ((process.env.CARGO_ENCODED_RUSTFLAGS?.length ?? 0) > 0)
        throw new Error(
            'CARGO_ENCODED_RUSTFLAGS must be unset for the participant module build.',
        );
    const { RUSTFLAGS: _ignored, ...inherited } = process.env;
    const version = run('rustc', ['+1.95.0', '-Vv'], inherited, true);
    if (!version.includes(`commit-hash: ${compilerCommit}`))
        throw new Error('The participant module needs Rust 1.95.0.');
    const compiler = version
        .split(/\r?\n/u)
        .filter((line) => line.length > 0 && !line.startsWith('host: '))
        .join('\n');
    const cargoHome = path.resolve(
        process.env.CARGO_HOME ?? path.join(os.homedir(), '.cargo'),
    );
    const flag = (repositoryPath: string, cargoPath: string) => [
        '--remap-path-prefix',
        `${repositoryPath}=/workspace`,
        '--remap-path-prefix',
        `${cargoPath}=/cargo`,
        '-C',
        'target-feature=-simd128',
        '-C',
        `link-arg=--max-memory=${String(maximumMemoryBytes)}`,
    ];
    const targetDirectory = path.join(
        repositoryRoot,
        'target',
        feature === undefined
            ? 'participant-module'
            : `participant-module-${feature}`,
    );
    run(
        'cargo',
        [
            '+1.95.0',
            'build',
            '--offline',
            '--locked',
            '--release',
            '-p',
            'registration-enrollment',
            ...(feature === undefined ? [] : ['--features', feature]),
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
        ],
        {
            ...inherited,
            CARGO_ENCODED_RUSTFLAGS: flag(
                path.resolve(repositoryRoot),
                cargoHome,
            ).join(rustflagSeparator),
            CARGO_INCREMENTAL: '0',
            CARGO_TARGET_DIR: targetDirectory,
            SOURCE_DATE_EPOCH: '0',
        },
        false,
    );
    const module = await readFile(
        path.join(
            targetDirectory,
            'wasm32-unknown-unknown',
            'release',
            'registration_enrollment.wasm',
        ),
    );
    await checkParticipantModule(module);
    return {
        module,
        compiler,
        flags: flag('<repository>', '<cargo-home>'),
    };
};

// Lists every tracked or unignored file of a directory, relative to the
// repository root with forward slashes.
const listedFiles = (directory: string): string[] => {
    const result = spawnSync(
        'git',
        [
            'ls-files',
            '--cached',
            '--others',
            '--exclude-standard',
            '-z',
            '--',
            directory,
        ],
        { cwd: repositoryRoot, encoding: 'utf8', windowsHide: true },
    );
    if (result.error !== undefined) throw result.error;
    if (result.status !== 0)
        throw new Error('The participant sources could not be listed.');
    return result.stdout.split('\0').filter((file) => file.length > 0);
};

// The canonical source manifest: the compiler, its flags and the digest and
// length of every source file, in path order. Its digest is the source
// component of the runtime identity.
export const participantSourceManifest = async (
    build: ParticipantModuleBuild,
): Promise<string> => {
    const names = [
        ...new Set([
            ...sourceDirectories.flatMap(listedFiles),
            ...buildScripts,
        ]),
    ].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    const files = [];
    for (const file of names) {
        const bytes = await readFile(path.join(repositoryRoot, file));
        files.push({
            file,
            sha512: createHash('sha512').update(bytes).digest('hex'),
            bytes: bytes.length,
        });
    }
    return (
        JSON.stringify({
            compiler: build.compiler,
            flags: build.flags,
            files,
        }) + '\n'
    );
};

// The runtime identity the worker recomputes from the packaged files, beside
// the digests it combines.
export const participantRuntimeIdentity = (
    sourceManifest: Uint8Array,
    module: Uint8Array,
    worker: Uint8Array,
) => {
    const [source, moduleDigest, workerDigest] = [
        sourceManifest,
        module,
        worker,
    ].map((bytes) => createHash('sha512').update(bytes).digest());
    return {
        runtime: createHash('sha512')
            .update(participantRuntimeLabel)
            .update(source)
            .update(moduleDigest)
            .update(workerDigest)
            .digest('hex'),
        source: source.toString('hex'),
        module: moduleDigest.toString('hex'),
        worker: workerDigest.toString('hex'),
    };
};
