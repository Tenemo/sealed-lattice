import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { copyFile, mkdir, readFile, writeFile } from 'node:fs/promises';
import { freemem } from 'node:os';
import path from 'node:path';

import { compileBoundedOpeningShareProofResources } from '#tests/recoverable-setup-resource-model.js';
import { requireCheckoutBytes } from '#tools/ci/compiled-inputs.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { openingShareProbes } from '#tools/ci/opening-share-scalar.mjs';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { runGuardedFixture } from '#tools/ci/run-guarded-fixture.js';
import {
    generateBoundedProofInChrome,
    boundedBrowserSources,
    verifyBoundedProofInChrome,
} from '#tools/ci/run-seed-sharing-browser.js';
import {
    buildScalarFixtureModule,
    executeFixtureCommand,
    readFixtureCompiler,
    scalarFixtureBuildFlags,
    scalarLinearMemoryLimit as linearMemoryLimit,
    fixtureProcessMemoryLimit as processMemoryLimit,
} from '#tools/ci/scalar-fixture-build.js';
import { seedSharingChunkBytes } from '#tools/ci/seed-sharing-browser-input.mjs';
import {
    fileDigest,
    readSeedSharingNativeSource,
    readOpeningShareNativeSource,
    assertOpeningShareSourceStable,
    assertSeedSharingSourceStable,
    assertScalarNativeInputs,
    compareNativeReferenceArtifacts,
} from '#tools/ci/seed-sharing-scalar-source.js';

export const runScalarProofFixture = async (
    sourceDirectory: string,
    host: 'node' | 'chrome' = 'node',
    operation: 'verify' | 'generate' = 'verify',
    relation: 'seed-sharing' | 'opening-share' = 'seed-sharing',
) => {
    const caseName =
        (host === 'chrome' ? 'browser-' : 'scalar-') +
        relation +
        (operation === 'generate' ? '-generation' : '');
    const fixturePackage = relation + '-proof';
    const root = path.resolve('.');
    const workspace = path.join(root, 'crates/protocol-research');
    await runWithLocalRunLog(
        {
            scriptName: 'research:protocol',
            commandLineArguments: [caseName, sourceDirectory],
            lanes: [
                'Pin native proof inputs',
                'Build bounded scalar verifier',
                ...(operation === 'generate'
                    ? [
                          'Generate the pinned positive proof through bounded scalar calls',
                      ]
                    : []),
                host === 'chrome'
                    ? 'Native and external Chrome verification of identical proof bytes'
                    : 'Native and scalar verification of identical proof bytes',
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
                const openingSource =
                    relation === 'opening-share'
                        ? await readOpeningShareNativeSource(
                              sourceDirectory,
                              root,
                          )
                        : undefined;
                const source =
                    openingSource ??
                    (await readSeedSharingNativeSource(sourceDirectory, root));
                assert.ok(
                    source.compiledInputs.size > 0,
                    'Scalar execution requires a native baseline with recorded compiled inputs.',
                );
                if (openingSource !== undefined) {
                    const resources =
                        compileBoundedOpeningShareProofResources();
                    assert.ok(
                        resources.openingStageBytes +
                            BigInt(seedSharingChunkBytes) <=
                            resources.nativeProofPlanningBytes,
                    );
                    assert.ok(
                        resources.nativeProofPlanningBytes <
                            BigInt(processMemoryLimit),
                    );
                    await writeFile(
                        path.join(log.runDirectoryPath, 'resource-inputs.json'),
                        JSON.stringify(
                            {
                                resources,
                                scalarInputCapacityBound: seedSharingChunkBytes,
                                processMemoryLimit,
                                linearMemoryLimit,
                            },
                            (_key, value: unknown) =>
                                typeof value === 'bigint'
                                    ? String(value)
                                    : value,
                        ) + '\n',
                        { flag: 'wx' },
                    );
                }
                const inputDirectory = path.join(
                    log.artifactDirectoryPath,
                    relation,
                );
                await mkdir(inputDirectory, { recursive: true });
                const proofs = [];
                for (const [index, proof] of source.proofs.entries()) {
                    const file = path.join(inputDirectory, proof.name);
                    if (operation !== 'generate' || index !== 0) {
                        await copyFile(proof.file, file);
                        assert.equal(
                            await fileDigest(file),
                            proof.sha512,
                            'A proof changed while it was pinned.',
                        );
                    }
                    proofs.push({ ...proof, file });
                }
                const predecessors = [];
                const statementInputs = [];
                if (openingSource !== undefined) {
                    const directory = path.join(
                        log.artifactDirectoryPath,
                        'predecessors',
                    );
                    await mkdir(directory);
                    for (const proof of openingSource.predecessors) {
                        const file = path.join(directory, proof.name);
                        await copyFile(proof.file, file);
                        assert.equal(await fileDigest(file), proof.sha512);
                        predecessors.push({ ...proof, file });
                    }
                    for (const artifact of openingSource.artifacts.filter(
                        (entry) => entry.name.startsWith('statement-'),
                    )) {
                        const file = path.join(inputDirectory, artifact.name);
                        await copyFile(artifact.file, file);
                        assert.equal(await fileDigest(file), artifact.sha512);
                        statementInputs.push({ ...artifact, file });
                    }
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
                const buildContext = { root, log, environment };
                const execute = (
                    command: string,
                    args: string[],
                    name: string,
                    env = environment,
                ) =>
                    executeFixtureCommand(
                        { ...buildContext, environment: env },
                        command,
                        args,
                        name,
                    );
                const compiler = await readFixtureCompiler(buildContext);
                const buildModule = (
                    feature: 'scalar-fixture' | 'scalar-prover-fixture',
                ) => buildScalarFixtureModule(buildContext, relation, feature);
                const verifierModule = await buildModule('scalar-fixture');
                const proverModule =
                    operation === 'generate'
                        ? await buildModule('scalar-prover-fixture')
                        : undefined;
                const { moduleBytes, moduleFile, inspected, moduleSha512 } =
                    verifierModule;
                const compiled = [
                    ...new Set([
                        ...verifierModule.compiled,
                        ...(proverModule?.compiled ?? []),
                    ]),
                ];
                const files = new Set([
                    ...compiled,
                    'crates/protocol-research/Cargo.toml',
                    'crates/protocol-research/Cargo.lock',
                    'crates/protocol-research/' +
                        fixturePackage +
                        '/src/bin/check-' +
                        fixturePackage +
                        '.rs',
                    'crates/protocol-research/' +
                        fixturePackage +
                        '/src/proof.rs',
                    'tools/ci/run-seed-sharing-scalar.ts',
                    'tools/ci/native-operation-guard.ts',
                    'tools/ci/run-guarded-fixture.ts',
                    'tools/ci/scalar-fixture-build.ts',
                    'tools/ci/compiled-inputs.ts',
                    'tools/ci/protocol-research-registry.ts',
                    'tools/ci/scalar-proof-file-reader.mjs',
                    'tools/ci/scalar-proof-stream.mjs',
                    'tools/ci/opening-share-scalar.mjs',
                    'tests/recoverable-setup-resource-model.ts',
                    'tests/recoverable-opening-share-model.ts',
                    'tools/ci/seed-sharing-scalar-source.ts',
                    'tools/ci/seed-sharing-scalar-worker.mjs',
                    'tools/ci/seed-sharing-scalar-verifier.mjs',
                    'tools/ci/seed-sharing-scalar-prover.mjs',
                    'tools/ci/bounded-output-worker.mjs',
                    'tools/ci/operator-process-gates.mjs',
                    ...boundedBrowserSources,
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
                const { targetAdapters, unchangedNativeInputs } =
                    await assertScalarNativeInputs(
                        source,
                        [...files],
                        compiler,
                        root,
                        relation,
                    );
                const sources = [];
                for (const file of [...files].sort()) {
                    const bytes = await readFile(path.join(root, file));
                    const sha512 = createHash('sha512')
                        .update(bytes)
                        .digest('hex');
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
                            flags: scalarFixtureBuildFlags(
                                '<repository>',
                                '<cargo-home>',
                            ),
                            features: [
                                verifierModule.feature,
                                ...(proverModule === undefined
                                    ? []
                                    : [proverModule.feature]),
                            ],
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
                const identity = createHash('sha512')
                    .update(
                        'sealed-lattice/' +
                            relation +
                            (host === 'chrome'
                                ? '-browser-research/v1'
                                : '-scalar-research/v1'),
                    )
                    .update(sourceManifest)
                    .update(moduleBytes)
                    .update(proverModule?.moduleBytes ?? new Uint8Array())
                    .digest('hex');
                const bindings = {
                    source: source.directory,
                    nativeExecutableSha512: source.nativeExecutableSha512,
                    diagnosticDigests: source.diagnosticDigests,
                    proofs,
                    predecessors,
                    statementInputs,
                    relation,
                    targetAdapters,
                    unchangedNativeInputs,
                    moduleSha512,
                    identity,
                    ...inspected,
                    linearMemoryLimit,
                    processMemoryLimit,
                    operation,
                    ...(proverModule === undefined
                        ? {}
                        : {
                              proverModuleSha512: proverModule.moduleSha512,
                              proverImports: proverModule.inspected.imports,
                              proverExports: proverModule.inspected.exports,
                          }),
                };
                await writeFile(
                    path.join(log.runDirectoryPath, 'input-bindings.json'),
                    JSON.stringify(bindings, null, 2) + '\n',
                    { flag: 'wx' },
                );
                const guarded = (
                    command: string,
                    args: string[],
                    name: string,
                    handshake = false,
                ) =>
                    runGuardedFixture({
                        root,
                        log,
                        environment,
                        processMemoryLimit,
                        command,
                        args,
                        name,
                        ...(handshake
                            ? { handshake: 'verifier' as const }
                            : {}),
                    });
                let nativeExecutable: string | undefined;
                let native: Awaited<ReturnType<typeof guarded>> | undefined;
                if (openingSource === undefined) {
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
                    nativeExecutable = path.join(
                        workspace,
                        'target/release/check-seed-sharing-proof' +
                            (process.platform === 'win32' ? '.exe' : ''),
                    );
                    native = await guarded(
                        nativeExecutable,
                        [
                            '--verify-existing',
                            operation === 'generate'
                                ? source.archive
                                : inputDirectory,
                        ],
                        'native-verification',
                        true,
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
                }
                let generation;
                let generatedNative;
                if (proverModule !== undefined) {
                    const expected = proofs[0];
                    if (host === 'chrome') {
                        generation = await generateBoundedProofInChrome({
                            root,
                            log,
                            relation,
                            predecessors,
                            moduleFile: proverModule.moduleFile,
                            moduleSha512: proverModule.moduleSha512,
                            outputFile: expected.file,
                            expectedBytes: expected.bytes,
                            expectedSha512: expected.sha512,
                            processMemoryLimit,
                            linearMemoryLimit,
                        });
                    } else {
                        const configuration = path.join(
                            log.runDirectoryPath,
                            'prover-input.json',
                        );
                        await writeFile(
                            configuration,
                            JSON.stringify({
                                relation,
                                predecessors,
                                module: proverModule.moduleFile,
                                moduleSha512: proverModule.moduleSha512,
                                outputFile: expected.file,
                                expectedBytes: expected.bytes,
                                expectedSha512: expected.sha512,
                            }) + '\n',
                            { flag: 'wx' },
                        );
                        generation = await guarded(
                            process.execPath,
                            [
                                path.join(
                                    root,
                                    'tools/ci/bounded-output-worker.mjs',
                                ),
                                configuration,
                            ],
                            'scalar-generation',
                        );
                    }
                    assert.equal(
                        generation.result.kind,
                        (host === 'chrome' ? 'browser-' : 'scalar-') +
                            relation +
                            '-generation',
                    );
                    assert.equal(generation.result.bytes, expected.bytes);
                    assert.ok(
                        typeof generation.result.maximumLinearMemoryBytes ===
                            'number' &&
                            generation.result.maximumLinearMemoryBytes <=
                                linearMemoryLimit,
                        'The generated proof exceeded the bounded module memory.',
                    );
                    assert.equal(
                        await fileDigest(expected.file),
                        expected.sha512,
                        'The generated positive proof differs from the pinned native bytes.',
                    );
                    await compareNativeReferenceArtifacts(
                        [source.proofs[0]],
                        inputDirectory,
                    );
                    if (
                        nativeExecutable !== undefined &&
                        native !== undefined
                    ) {
                        generatedNative = await guarded(
                            nativeExecutable,
                            ['--verify-existing', inputDirectory],
                            'native-generated-verification',
                            true,
                        );
                        assert.deepEqual(generatedNative.result, native.result);
                    }
                }
                let verified;
                if (host === 'chrome') {
                    verified = await verifyBoundedProofInChrome({
                        root,
                        log,
                        moduleFile,
                        moduleSha512,
                        proofs,
                        relation,
                        predecessors,
                        processMemoryLimit,
                        linearMemoryLimit,
                    });
                } else {
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
                            relation,
                            predecessors,
                        }) + '\n',
                        { flag: 'wx' },
                    );
                    verified = await guarded(
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
                }
                assert.equal(
                    verified.result.kind,
                    (host === 'chrome' ? 'browser-' : 'scalar-') +
                        relation +
                        '-verification',
                );
                assert.ok(
                    Array.isArray(verified.result.results) &&
                        verified.result.results.length ===
                            (openingSource === undefined
                                ? 8
                                : openingShareProbes.length),
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
                for (const artifact of [...predecessors, ...statementInputs])
                    assert.equal(
                        await fileDigest(artifact.file),
                        artifact.sha512,
                    );
                if (openingSource !== undefined)
                    await assertOpeningShareSourceStable(openingSource, root);
                else await assertSeedSharingSourceStable(source, root);
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify(
                        {
                            case: caseName,
                            identity,
                            source: source.directory,
                            moduleSha512,
                            ...(nativeExecutable === undefined
                                ? { nativeBaseline: source.directory }
                                : {
                                      currentNativeExecutableSha512:
                                          await fileDigest(nativeExecutable),
                                      native,
                                  }),
                            ...(generation === undefined
                                ? {}
                                : {
                                      generation,
                                      generatedNative,
                                      proverModuleSha512:
                                          proverModule?.moduleSha512,
                                  }),
                            ...(host === 'chrome'
                                ? { browser: verified }
                                : { scalar: verified }),
                            scope:
                                openingSource !== undefined
                                    ? 'Fixed synthetic opening-share scalar fixture. Each fresh worker verifies both pinned outer predecessors before opening verification or generation. Honest and genuine shifted-statement proofs use their exact contexts; generated positive bytes match the source-matched native baseline. The fixed selection descriptor grants no broadcast, registration, disclosure or participant capability. This is development evidence, not supported-phone qualification.'
                                    : operation === 'generate'
                                      ? 'The fixed positive fixture was generated through staged scalar WebAssembly calls and an acknowledged bounded output sink, matched the current-native-verified reference length and SHA-512, and passed unchanged native and WebAssembly verifier controls. Replay randomness remains inside Rust. This is bounded synthetic generation development evidence, not participant state, distributed setup, complete protocol security or physical-phone qualification.'
                                      : host === 'chrome'
                                        ? 'Current native and dedicated external desktop Chrome worker scalar WebAssembly verifiers consumed identical pinned proof bytes from the source-matched native baseline. Browser transfers authenticated bounded chunks with trusted SHA-512 identities. This is bounded relation verification development evidence, not browser proof generation, distributed setup, an admitted capability or physical-phone qualification.'
                                        : 'Current native and Node worker scalar WebAssembly verifiers consumed identical pinned proof bytes from the source-matched native baseline. Recorded archive digests and compiled input identities match the native baseline. This is bounded relation verification development evidence, not proof generation in a browser, distributed setup, an admitted capability or phone qualification.',
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
