import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import binaryen from 'binaryen';

import {
    compiledRustSources,
    requireCheckoutBytes,
} from './compiled-inputs.js';
import { rustCompilerCommit, rustToolchain } from './rust-toolchain.js';

import { participantRuntimeLabel } from '#packages/sdk/src/participant/worker/identity.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const workspace = path.join(repositoryRoot, 'crates', 'protocol-research');
// The participant module's linear memory never exceeds the absolute bound.
export const participantLinearMemoryBytes = 671_088_640;
const rustflagSeparator = '\x1f';

// The imports the participant module may declare, by module and name.
const allowedImports = [
    'allocator.exhausted',
    'contribution.public_chunk',
    'enrollment.fill_random',
    'enrollment.staged_chunk',
    'parallel.discard',
    'parallel.ended',
    'parallel.helpers',
    'parallel.read',
    'parallel.release',
    'parallel.share',
    'parallel.submit',
    'parallel.take',
    'parallel.wait',
    'setup_witness.fill_random',
    'word_proof.fill_random',
];

// The build definitions beside the compiled sources: the lockfile the Rust
// build resolves, the package manifest and TypeScript configurations the
// bundler reads, and the build scripts. Every Cargo manifest above a compiled
// Rust source joins them.
const buildDefinitions = [
    'crates/protocol-research/Cargo.lock',
    'packages/sdk/package.json',
    'packages/sdk/tsconfig.json',
    'tools/ci/build-participant-module.ts',
    'tools/ci/build-sdk-package.ts',
    'tools/ci/compiled-inputs.ts',
    'tools/ci/rust-toolchain.ts',
    'tools/ci/sdk-package-tsdown.config.ts',
    'tsconfig.base.json',
];
// The packages whose installed versions bundle the worker and the SDK entry
// and emit the entry's declarations.
const buildTools = ['rolldown', 'tsdown', 'typescript'];

export type ParticipantModuleBuild = Readonly<{
    module: Buffer;
    // The compiler's version report without its host line, and the compiler
    // flags with the machine's paths replaced by their names, so neither
    // depends on the machine that built the module.
    compiler: string;
    flags: readonly string[];
    // The repository files the compiler read for the module.
    sources: readonly string[];
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
            memory.max !== participantLinearMemoryBytes / 65_536
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
    const version = run('rustc', [rustToolchain, '-Vv'], inherited, true);
    if (!version.includes(`commit-hash: ${rustCompilerCommit}`))
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
        `link-arg=--max-memory=${String(participantLinearMemoryBytes)}`,
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
            rustToolchain,
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
    const releaseDirectory = path.join(
        targetDirectory,
        'wasm32-unknown-unknown',
        'release',
    );
    const module = await readFile(
        path.join(releaseDirectory, 'registration_enrollment.wasm'),
    );
    await checkParticipantModule(module);
    return {
        module,
        compiler,
        flags: flag('<repository>', '<cargo-home>'),
        sources: await compiledRustSources(
            path.join(releaseDirectory, 'registration_enrollment.d'),
        ),
    };
};

// Every Cargo manifest in the directories above the compiled Rust sources,
// up to the repository root, where package and workspace definitions live.
const cargoManifests = (sources: readonly string[]): string[] => {
    const directories = new Set<string>();
    for (const source of sources) {
        if (!source.startsWith('crates/')) continue;
        for (
            let directory = path.posix.dirname(source);
            directory !== '.';
            directory = path.posix.dirname(directory)
        )
            directories.add(directory);
        directories.add('.');
    }
    return [...directories]
        .map((directory) => path.posix.join(directory, 'Cargo.toml'))
        .filter((file) => existsSync(path.join(repositoryRoot, file)));
};

// The installed version of each build tool, by package name.
const toolVersions = (): Record<string, string> => {
    const resolveFromRoot = createRequire(
        path.join(repositoryRoot, 'package.json'),
    );
    const resolveFromBundler = createRequire(
        resolveFromRoot.resolve('tsdown/package.json'),
    );
    return Object.fromEntries(
        buildTools.map((name) => {
            const manifest = JSON.parse(
                readFileSync(
                    (name === 'rolldown'
                        ? resolveFromBundler
                        : resolveFromRoot
                    ).resolve(name + '/package.json'),
                    'utf8',
                ),
            ) as { version?: unknown };
            if (typeof manifest.version !== 'string')
                throw new Error('A build tool reports no version: ' + name);
            return [name, manifest.version];
        }),
    );
};

// The canonical source manifest: the compiler, its flags, the build tools'
// versions and the digest and length of every compiled source and build
// definition, in path order. The compiled sources are every repository file
// the compiler and the bundler read for the packaged module, worker and SDK
// entry, so documentation, tests and crates outside
// those builds leave it unchanged. Its digest is the source component of the
// runtime identity.
export const participantSourceManifest = async (
    build: ParticipantModuleBuild,
    compiled: readonly string[],
): Promise<string> => {
    const names = [
        ...new Set([
            ...build.sources,
            ...compiled,
            ...cargoManifests([...build.sources, ...compiled]),
            ...buildDefinitions,
        ]),
    ].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
    requireCheckoutBytes(names);
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
            tools: toolVersions(),
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
