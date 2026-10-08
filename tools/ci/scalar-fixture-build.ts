import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';

import binaryen from 'binaryen';

import { runCommandAndCaptureOutput } from '#tools/ci/command-runner.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';

export type FixtureBuildContext = Readonly<{
    root: string;
    log: ActiveLocalRunLog;
    environment: NodeJS.ProcessEnv;
}>;
export const executeFixtureCommand = async (
    context: FixtureBuildContext,
    command: string,
    args: string[],
    name: string,
) => {
    const result = await runCommandAndCaptureOutput(
        {
            command,
            args,
            env: context.environment,
            workingDirectoryPath: path.join(
                context.root,
                'crates/protocol-research',
            ),
            description: name,
            logFileSlug: name,
        },
        {
            runLog: context.log,
            echoOutput: true,
            signal: AbortSignal.timeout(600_000),
        },
    );
    assert.equal(result.exitCode, 0, name);
    assert.equal(result.terminationSignal, null, name);
    return result.stdout;
};
export const readFixtureCompiler = async (context: FixtureBuildContext) => {
    const compiler = await executeFixtureCommand(
        context,
        'rustc',
        ['+1.95.0', '-Vv'],
        'compiler',
    );
    assert.ok(compiler.includes('commit-hash: ' + compilerCommit));
    return compiler;
};
export const scalarFixtureBuildFlags = (repository: string, cargo: string) => [
    '--remap-path-prefix',
    repository + '=/workspace',
    '--remap-path-prefix',
    cargo + '=/cargo',
    '-C',
    'target-feature=-simd128',
    '-C',
    'link-arg=--max-memory=' + String(scalarLinearMemoryLimit),
];
export const scalarLinearMemoryLimit = 671_088_640;
export const fixtureProcessMemoryLimit = 1_073_741_824;
const compilerCommit = '59807616e1fa2540724bfbac14d7976d7e4a3860';
const allowedImports = new Set([
    'helpers',
    'share',
    'release',
    'submit',
    'wait',
    'take',
    'discard',
    'ended',
    'read',
]);

// The key source screen module may import only the scalar helper queries and
// its setup entropy, and must export its bounded screen ABI.
export const inspectScalarFixtureModule = async (bytes: Uint8Array) => {
    const inspected = binaryen.readBinary(bytes);
    try {
        assert.doesNotMatch(
            inspected.emitText(),
            /\b(?:v128|i8x16|i16x8|i32x4|i64x2|f32x4|f64x2)\./u,
            'The scalar module must contain scalar instructions only.',
        );
        const memory = inspected.getMemoryInfo();
        assert.ok(
            !memory.shared &&
                !memory.is64 &&
                memory.max === scalarLinearMemoryLimit / 65_536,
            'The scalar module memory is not bounded unshared scalar memory.',
        );
    } finally {
        inspected.dispose();
    }
    const module = await WebAssembly.compile(new Uint8Array(bytes));
    const imports = WebAssembly.Module.imports(module);
    assert.ok(
        imports.every(
            (entry) =>
                entry.kind === 'function' &&
                ((entry.module === 'parallel' &&
                    allowedImports.has(entry.name)) ||
                    (entry.module === 'setup_witness' &&
                        entry.name === 'fill_random')),
        ),
        'The scalar module declares an unknown host import.',
    );
    const exports = WebAssembly.Module.exports(module);
    for (const name of [
        'begin',
        'phase',
        'step',
        'next_output',
        'output_pointer',
        'output_length',
        'output_capacity',
        'ack_output',
    ])
        assert.ok(
            exports.some(
                (entry) =>
                    entry.kind === 'function' &&
                    entry.name === 'key_source_screen_' + name,
            ),
            'The scalar module is missing its bounded ABI.',
        );
    assert.ok(
        exports.some(
            (entry) => entry.kind === 'memory' && entry.name === 'memory',
        ),
    );
    return { imports, exports };
};

export const buildScalarFixtureModule = async (
    context: FixtureBuildContext,
) => {
    const targetDirectory = path.join(
        context.root,
        'target/fhe-key-source-scalar',
    );
    const cargoHome = path.resolve(
        process.env.CARGO_HOME ?? path.join(homedir(), '.cargo'),
    );
    await executeFixtureCommand(
        {
            ...context,
            environment: {
                ...context.environment,
                CARGO_TARGET_DIR: targetDirectory,
                CARGO_ENCODED_RUSTFLAGS: scalarFixtureBuildFlags(
                    context.root,
                    cargoHome,
                ).join('\x1f'),
            },
        },
        'cargo',
        [
            '+1.95.0',
            'rustc',
            '--offline',
            '--locked',
            '--release',
            '--no-default-features',
            '-p',
            'setup-witness',
            '--features',
            'key-source-screen',
            '--crate-type',
            'cdylib',
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
        ],
        'build-scalar',
    );
    const moduleBytes = await readFile(
        path.join(
            targetDirectory,
            'wasm32-unknown-unknown/release/setup_witness.wasm',
        ),
    );
    const inspected = await inspectScalarFixtureModule(moduleBytes);
    const moduleFile = path.join(
        context.log.artifactDirectoryPath,
        'fhe-key-source.wasm',
    );
    await writeFile(moduleFile, moduleBytes, { flag: 'wx' });
    return {
        moduleFile,
        inspected,
        moduleSha512: createHash('sha512').update(moduleBytes).digest('hex'),
    };
};
