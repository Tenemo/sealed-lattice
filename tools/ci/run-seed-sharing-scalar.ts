import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { freemem, homedir } from 'node:os';
import path from 'node:path';
import { setTimeout } from 'node:timers/promises';

import binaryen from 'binaryen';

import {
    compiledRustSources,
    requireCheckoutBytes,
} from '#tools/ci/compiled-inputs.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from '#tools/ci/run-command.js';
import {
    fileDigest,
    readSeedSharingNativeSource,
} from '#tools/ci/seed-sharing-scalar-source.js';

const linearMemoryLimit = 671_088_640;
const processMemoryLimit = 1_073_741_824;
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

export const inspectSeedSharingScalarModule = async (bytes: Uint8Array) => {
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
                memory.max === linearMemoryLimit / 65_536,
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
                entry.module === 'parallel' &&
                allowedImports.has(entry.name),
        ),
        'The verifier declares an unknown host import.',
    );
    const exports = WebAssembly.Module.exports(module);
    for (const name of [
        'input_pointer',
        'input_capacity',
        'header_length',
        'begin',
        'push',
        'finish',
    ])
        assert.ok(
            exports.some(
                (entry) =>
                    entry.kind === 'function' &&
                    entry.name === 'seed_verifier_' + name,
            ),
            'The verifier is missing its bounded ABI.',
        );
    assert.ok(
        exports.some(
            (entry) => entry.kind === 'memory' && entry.name === 'memory',
        ),
    );
    return { imports, exports };
};

export const runSeedSharingScalar = async (sourceDirectory: string) => {
    const root = path.resolve('.');
    const workspace = path.join(root, 'crates/protocol-research');
    await runWithLocalRunLog(
        {
            scriptName: 'research:protocol',
            commandLineArguments: ['scalar-seed-sharing', sourceDirectory],
            lanes: [
                'Pin native proof inputs',
                'Build bounded scalar verifier',
                'Native and scalar verification of identical proof bytes',
            ],
        },
        async (log) => {
            const unlock = await acquireProtocolResearchLock(
                log.runDirectoryPath,
                root,
            );
            try {
                assert.ok(
                    freemem() >= 2 * processMemoryLimit,
                    'Insufficient host memory before scalar verification.',
                );
                const source = await readSeedSharingNativeSource(
                    sourceDirectory,
                    root,
                );
                const inputDirectory = path.join(
                    log.artifactDirectoryPath,
                    'seed-sharing',
                );
                await mkdir(inputDirectory, { recursive: true });
                const proofs = [];
                for (const proof of source.proofs) {
                    const file = path.join(inputDirectory, proof.name);
                    await copyFile(proof.file, file);
                    assert.equal(
                        await fileDigest(file),
                        proof.sha512,
                        'A proof changed while it was pinned.',
                    );
                    proofs.push({ ...proof, file });
                }
                const environment: NodeJS.ProcessEnv = {
                    ...process.env,
                    RUSTFLAGS: '',
                    CARGO_ENCODED_RUSTFLAGS: '',
                    CARGO_INCREMENTAL: '0',
                    SOURCE_DATE_EPOCH: '0',
                    CARGO_TARGET_DIR: path.join(workspace, 'target'),
                };
                delete environment.SEALED_LATTICE_SIMULATED_HELPERS;
                const execute = async (
                    command: string,
                    args: string[],
                    name: string,
                    env = environment,
                ) => {
                    const result = await runCommandAndCaptureOutput(
                        {
                            command,
                            args,
                            env,
                            workingDirectoryPath: workspace,
                            description: name,
                            logFileSlug: name,
                        },
                        {
                            runLog: log,
                            echoOutput: true,
                            signal: AbortSignal.timeout(600_000),
                        },
                    );
                    assert.equal(result.exitCode, 0, name);
                    assert.equal(result.terminationSignal, null, name);
                    return result.stdout;
                };
                const compiler = await execute(
                    'rustc',
                    ['+1.95.0', '-Vv'],
                    'compiler',
                );
                assert.ok(compiler.includes('commit-hash: ' + compilerCommit));
                const targetDirectory = path.join(
                    root,
                    'target/seed-sharing-scalar',
                );
                const cargoHome = path.resolve(
                    process.env.CARGO_HOME ?? path.join(homedir(), '.cargo'),
                );
                const flags = (repository: string, cargo: string) => [
                    '--remap-path-prefix',
                    repository + '=/workspace',
                    '--remap-path-prefix',
                    cargo + '=/cargo',
                    '-C',
                    'target-feature=-simd128',
                    '-C',
                    'link-arg=--max-memory=' + String(linearMemoryLimit),
                ];
                await execute(
                    'cargo',
                    [
                        '+1.95.0',
                        'build',
                        '--offline',
                        '--locked',
                        '--release',
                        '--no-default-features',
                        '-p',
                        'seed-sharing-proof',
                        '--features',
                        'scalar-fixture',
                        '--lib',
                        '--target',
                        'wasm32-unknown-unknown',
                    ],
                    'build-scalar',
                    {
                        ...environment,
                        CARGO_TARGET_DIR: targetDirectory,
                        CARGO_ENCODED_RUSTFLAGS: flags(root, cargoHome).join(
                            '\x1f',
                        ),
                    },
                );
                const builtDirectory = path.join(
                    targetDirectory,
                    'wasm32-unknown-unknown/release',
                );
                const moduleBytes = await readFile(
                    path.join(builtDirectory, 'seed_sharing_proof.wasm'),
                );
                const inspected =
                    await inspectSeedSharingScalarModule(moduleBytes);
                const moduleFile = path.join(
                    log.artifactDirectoryPath,
                    'seed-sharing-verifier.wasm',
                );
                await writeFile(moduleFile, moduleBytes, { flag: 'wx' });
                const compiled = await compiledRustSources(
                    path.join(builtDirectory, 'seed_sharing_proof.d'),
                );
                const files = new Set([
                    ...compiled,
                    'crates/protocol-research/Cargo.toml',
                    'crates/protocol-research/Cargo.lock',
                    'crates/protocol-research/seed-sharing-proof/src/bin/check-seed-sharing-proof.rs',
                    'crates/protocol-research/seed-sharing-proof/src/proof.rs',
                    'tools/ci/run-seed-sharing-scalar.ts',
                    'tools/ci/seed-sharing-scalar-source.ts',
                    'tools/ci/seed-sharing-scalar-worker.mjs',
                ]);
                for (const file of compiled) {
                    let directory = path.posix.dirname(file);
                    while (directory.startsWith('crates/')) {
                        const manifest = path.posix.join(
                            directory,
                            'Cargo.toml',
                        );
                        if (existsSync(path.join(root, manifest)))
                            files.add(manifest);
                        directory = path.posix.dirname(directory);
                    }
                }
                requireCheckoutBytes([...files]);
                // The verifier adapter was extracted without changing the native
                // core relations. New bridge/build wiring is pinned separately.
                const adapted = new Set(
                    [
                        'Cargo.toml',
                        'src/lib.rs',
                        'src/proof.rs',
                        'src/verification.rs',
                        'src/browser.rs',
                        'src/bin/check-seed-sharing-proof.rs',
                    ].map(
                        (file) =>
                            'crates/protocol-research/seed-sharing-proof/' +
                            file,
                    ),
                );
                const sources = [];
                const unchangedNativeInputs = [];
                for (const file of [...files].sort()) {
                    const bytes = await readFile(path.join(root, file));
                    const sha512 = createHash('sha512')
                        .update(bytes)
                        .digest('hex');
                    const previous = source.sources.get(file);
                    if (compiled.includes(file) && !adapted.has(file)) {
                        assert.ok(
                            previous,
                            'The scalar verifier introduced an unreviewed shared input: ' +
                                file,
                        );
                        assert.equal(
                            sha512,
                            previous.sha512,
                            'A native relation or shared verifier source changed: ' +
                                file,
                        );
                        assert.equal(bytes.length, previous.bytes);
                        unchangedNativeInputs.push(file);
                    }
                    const destination = path.join(
                        log.runDirectoryPath,
                        'sources',
                        file,
                    );
                    await mkdir(path.dirname(destination), { recursive: true });
                    await writeFile(destination, bytes, { flag: 'wx' });
                    sources.push({ file, bytes: bytes.length, sha512 });
                }
                const sourceManifest = Buffer.from(
                    JSON.stringify(
                        {
                            compiler,
                            flags: flags('<repository>', '<cargo-home>'),
                            sources,
                        },
                        null,
                        2,
                    ) + '\n',
                );
                await writeFile(
                    path.join(log.runDirectoryPath, 'source-manifest.json'),
                    sourceManifest,
                    { flag: 'wx' },
                );
                const moduleSha512 = createHash('sha512')
                    .update(moduleBytes)
                    .digest('hex');
                const identity = createHash('sha512')
                    .update('sealed-lattice/seed-sharing-scalar-research/v1')
                    .update(sourceManifest)
                    .update(moduleBytes)
                    .digest('hex');
                const bindings = {
                    source: source.directory,
                    nativeExecutableSha512: source.nativeExecutableSha512,
                    diagnosticDigests: source.diagnosticDigests,
                    proofs,
                    unchangedNativeInputs,
                    moduleSha512,
                    identity,
                    ...inspected,
                    linearMemoryLimit,
                    processMemoryLimit,
                };
                await writeFile(
                    path.join(log.runDirectoryPath, 'input-bindings.json'),
                    JSON.stringify(bindings, null, 2) + '\n',
                    { flag: 'wx' },
                );
                const guarded = async (
                    command: string,
                    args: string[],
                    name: string,
                ) => {
                    assert.ok(freemem() >= 2 * processMemoryLimit);
                    const controller = new AbortController();
                    let active = false,
                        peakMemory = 0,
                        samples = 0,
                        output = '';
                    let monitor: Promise<void> | undefined;
                    const started = performance.now();
                    const exitCode = await runCommandsInSeries(
                        [
                            {
                                command,
                                args,
                                env: environment,
                                workingDirectoryPath: root,
                                description: name,
                                logFileSlug: name,
                            },
                        ],
                        {
                            runLog: log,
                            outputMode: 'inherit',
                            signal: AbortSignal.any([
                                controller.signal,
                                AbortSignal.timeout(600_000),
                            ]),
                            observer: {
                                onCommandOutput({ chunk, streamName }) {
                                    if (streamName === 'stdout') {
                                        output += chunk;
                                        if (output.length > 1_048_576)
                                            controller.abort(
                                                new Error(
                                                    'Verifier diagnostics exceed their bound.',
                                                ),
                                            );
                                    }
                                },
                                onCommandStart({ processIdentifier }) {
                                    assert.ok(processIdentifier);
                                    active = true;
                                    monitor = (async () => {
                                        while (active) {
                                            const bytes =
                                                await readProtocolProcessTree(
                                                    processIdentifier,
                                                );
                                            if (bytes !== undefined) {
                                                samples++;
                                                peakMemory = Math.max(
                                                    peakMemory,
                                                    bytes,
                                                );
                                                log.writeEvent({
                                                    eventType:
                                                        'scalar-verifier-process-memory',
                                                    details: {
                                                        name,
                                                        bytes,
                                                        limit: processMemoryLimit,
                                                    },
                                                });
                                                assert.ok(
                                                    bytes <= processMemoryLimit,
                                                    'Verifier process-tree memory guard exceeded.',
                                                );
                                            }
                                            if (active) await setTimeout(1000);
                                        }
                                    })().catch((error: unknown) =>
                                        controller.abort(error),
                                    );
                                },
                                onCommandExit() {
                                    active = false;
                                },
                            },
                        },
                    ).finally(async () => {
                        active = false;
                        await monitor;
                    });
                    assert.equal(
                        controller.signal.aborted,
                        false,
                        String(controller.signal.reason),
                    );
                    assert.equal(exitCode, 0);
                    assert.ok(samples > 0);
                    return {
                        result: JSON.parse(
                            output.trim().split(/\r?\n/u).pop()!,
                        ) as Record<string, unknown>,
                        peakMemory,
                        samples,
                        milliseconds: performance.now() - started,
                    };
                };
                await execute(
                    'cargo',
                    [
                        '+1.95.0',
                        'build',
                        '--offline',
                        '--locked',
                        '--release',
                        '--no-default-features',
                        '-p',
                        'seed-sharing-proof',
                        '--features',
                        'native-fixture',
                        '--bin',
                        'check-seed-sharing-proof',
                    ],
                    'build-native-reader',
                );
                const nativeExecutable = path.join(
                    workspace,
                    'target/release/check-seed-sharing-proof' +
                        (process.platform === 'win32' ? '.exe' : ''),
                );
                const native = await guarded(
                    nativeExecutable,
                    ['--verify-existing', inputDirectory],
                    'native-verification',
                );
                assert.equal(
                    native.result.kind,
                    'seed-sharing-existing-verification',
                );
                assert.equal(native.result.positive, 1);
                assert.equal(native.result.falseWitnesses, 1);
                assert.equal(native.result.falseStatements, 1);
                assert.deepEqual(
                    native.result.proofBytes,
                    proofs.map((proof) => proof.bytes),
                );
                const configuration = path.join(
                    log.runDirectoryPath,
                    'worker-input.json',
                );
                await writeFile(
                    configuration,
                    JSON.stringify({
                        module: moduleFile,
                        moduleSha512,
                        proofs,
                    }) + '\n',
                    { flag: 'wx' },
                );
                const scalar = await guarded(
                    process.execPath,
                    [
                        path.join(
                            root,
                            'tools/ci/seed-sharing-scalar-worker.mjs',
                        ),
                        configuration,
                    ],
                    'scalar-verification',
                );
                assert.equal(
                    scalar.result.kind,
                    'scalar-seed-sharing-verification',
                );
                assert.ok(
                    Array.isArray(scalar.result.results) &&
                        scalar.result.results.length === 8,
                );
                for (const entry of sources)
                    assert.equal(
                        await fileDigest(path.join(root, entry.file)),
                        entry.sha512,
                        'A source changed during verification.',
                    );
                for (const [index, proof] of proofs.entries()) {
                    assert.equal(await fileDigest(proof.file), proof.sha512);
                    assert.equal(
                        await fileDigest(source.proofs[index].file),
                        proof.sha512,
                        'A historical archive changed during verification.',
                    );
                }
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify(
                        {
                            case: 'scalar-seed-sharing',
                            identity,
                            source: source.directory,
                            moduleSha512,
                            currentNativeExecutableSha512:
                                await fileDigest(nativeExecutable),
                            native,
                            scalar,
                            scope: 'Current native and Node worker scalar WebAssembly verifiers consumed identical pinned proof bytes from the historical native run. Archive digests were first recorded by this scalar run. This is bounded relation verification development evidence, not proof generation in a browser, distributed setup, an admitted capability or phone qualification.',
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
            } finally {
                await unlock();
            }
        },
    );
};
