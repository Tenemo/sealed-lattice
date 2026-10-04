import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';

import binaryen from 'binaryen';

import { compiledRustSources } from '#tools/ci/compiled-inputs.js';
import type { ActiveLocalRunLog } from '#tools/ci/local-run-log.js';
import { runCommandAndCaptureOutput } from '#tools/ci/run-command.js';

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

export const inspectScalarFixtureModule = async (
    bytes: Uint8Array,
    generation = false,
    relation:
        'seed-sharing' | 'opening-share' | 'public-operator' = 'seed-sharing',
) => {
    assert.ok(
        relation !== 'public-operator' || !generation,
        'A public operator screen has no proof-generation mode.',
    );
    const inspected = binaryen.readBinary(bytes);
    try {
        assert.doesNotMatch(
            inspected.emitText(),
            /\b(?:v128|i8x16|i16x8|i32x4|i64x2|f32x4|f64x2)\./u,
            'The verifier must contain scalar instructions only.',
        );
        const memory = inspected.getMemoryInfo();
        assert.ok(
            !memory.shared &&
                !memory.is64 &&
                memory.max === scalarLinearMemoryLimit / 65_536,
            'The verifier memory is not bounded unshared scalar memory.',
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
                    (generation &&
                        entry.module === 'word_proof' &&
                        entry.name === 'fill_random')),
        ),
        'The verifier declares an unknown host import.',
    );
    const exports = WebAssembly.Module.exports(module);
    const required =
        relation === 'public-operator'
            ? [
                  'begin',
                  'phase',
                  'step',
                  'next_output',
                  'output_pointer',
                  'output_length',
                  'output_capacity',
                  'ack_output',
              ].map((name) => 'operator_screen_' + name)
            : relation === 'opening-share'
              ? [
                    'opening_input_pointer',
                    'opening_input_capacity',
                    'opening_header_length',
                    ...['source', 'verifier'].flatMap((role) =>
                        ['begin', 'push', 'finish'].map(
                            (name) => 'opening_' + role + '_' + name,
                        ),
                    ),
                ]
              : [
                    'input_pointer',
                    'input_capacity',
                    'header_length',
                    'begin',
                    'push',
                    'finish',
                ].map((name) => 'seed_verifier_' + name);
    for (const name of required)
        assert.ok(
            exports.some(
                (entry) => entry.kind === 'function' && entry.name === name,
            ),
            'The verifier is missing its bounded ABI.',
        );
    assert.ok(
        exports.some(
            (entry) => entry.kind === 'memory' && entry.name === 'memory',
        ),
    );
    if (generation)
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
                        entry.name ===
                            (relation === 'opening-share'
                                ? 'opening'
                                : 'seed') +
                                '_prover_' +
                                name,
                ),
                'The prover is missing its bounded ABI.',
            );
    return { imports, exports };
};

export const buildScalarFixtureModule = async (
    context: FixtureBuildContext,
    kind: 'seed-sharing' | 'opening-share' | 'public-operator',
    feature?: 'scalar-fixture' | 'scalar-prover-fixture',
) => {
    const generation = feature === 'scalar-prover-fixture';
    const crateName =
        kind === 'public-operator' ? 'public-operator-screen' : kind + '-proof';
    const stem = crateName.replace(/-/gu, '_');
    const targetDirectory = path.join(
        context.root,
        'target/' + kind + '-scalar' + (generation ? '-prover' : ''),
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
            'build',
            '--offline',
            '--locked',
            '--release',
            '--no-default-features',
            '-p',
            crateName,
            ...(feature === undefined ? [] : ['--features', feature]),
            '--lib',
            '--target',
            'wasm32-unknown-unknown',
        ],
        generation ? 'build-scalar-prover' : 'build-scalar',
    );
    const builtDirectory = path.join(
        targetDirectory,
        'wasm32-unknown-unknown/release',
    );
    const moduleBytes = await readFile(
        path.join(builtDirectory, stem + '.wasm'),
    );
    const inspected = await inspectScalarFixtureModule(
        moduleBytes,
        generation,
        kind,
    );
    const moduleFile = path.join(
        context.log.artifactDirectoryPath,
        kind +
            (kind === 'public-operator'
                ? ''
                : generation
                  ? '-prover'
                  : '-verifier') +
            '.wasm',
    );
    await writeFile(moduleFile, moduleBytes, { flag: 'wx' });
    const compiled = await compiledRustSources(
        path.join(builtDirectory, stem + '.d'),
    );
    return {
        feature,
        moduleBytes,
        moduleFile,
        inspected,
        compiled,
        moduleSha512: createHash('sha512').update(moduleBytes).digest('hex'),
    };
};
