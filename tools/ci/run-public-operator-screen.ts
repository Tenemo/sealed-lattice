import assert from 'node:assert/strict';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { freemem } from 'node:os';
import path from 'node:path';

import { compilePublicOperatorScreenResources } from '#tests/recoverable-setup-resource-model.js';
import {
    checkFixtureSources,
    compiledFixtureFiles,
    snapshotResearchSources,
} from '#tools/ci/fixture-sources.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { publicOperatorPhases } from '#tools/ci/public-operator-scalar.mjs';
import {
    assertPublicOperatorSourceStable,
    parsePublicOperatorReport,
    readPublicOperatorNativeSource,
} from '#tools/ci/public-operator-source.js';
import { runGuardedFixture } from '#tools/ci/run-guarded-fixture.js';
import {
    boundedBrowserSources,
    runPublicOperatorInChrome,
} from '#tools/ci/run-seed-sharing-browser.js';
import {
    buildScalarFixtureModule,
    executeFixtureCommand,
    fixtureProcessMemoryLimit,
    readFixtureCompiler,
    scalarFixtureBuildFlags,
    scalarLinearMemoryLimit,
} from '#tools/ci/scalar-fixture-build.js';
import {
    assertScalarNativeInputs,
    compareNativeReferenceArtifacts,
    fileDigest,
} from '#tools/ci/seed-sharing-scalar-source.js';

const packageName = 'public-operator-screen';
const binaryName = 'screen-public-operator';
const kinds = ['seed', 'opening'] as const;
const sourcesForHost = [
    'tools/ci/run-public-operator-screen.ts',
    'tools/ci/public-operator-source.ts',
    'tools/ci/fixture-sources.ts',
    'tools/ci/protocol-research-registry.ts',
    'tools/ci/run-guarded-fixture.ts',
    'tools/ci/native-operation-guard.ts',
    'tools/ci/scalar-fixture-build.ts',
    'tools/ci/compiled-inputs.ts',
    'tools/ci/seed-sharing-scalar-source.ts',
    'tools/ci/bounded-output-worker.mjs',
    'tools/ci/operator-process-gates.mjs',
    'tools/ci/scalar-proof-file-reader.mjs',
    'tools/ci/seed-sharing-scalar-prover.mjs',
    'tools/ci/seed-sharing-scalar-verifier.mjs',
    'tests/recoverable-setup-resource-model.ts',
    'tests/recoverable-opening-share-model.ts',
    'tests/public-polynomial-operator-resource-model.ts',
    ...boundedBrowserSources,
];

export const runPublicOperatorFixture = async (
    host: 'native' | 'node' | 'chrome',
    sourceDirectory?: string,
) => {
    assert.equal(sourceDirectory === undefined, host === 'native');
    const name =
        host === 'native'
            ? 'native-public-operator'
            : host === 'node'
              ? 'scalar-public-operator'
              : 'browser-public-operator';
    const root = path.resolve('.');
    const workspace = path.join(root, 'crates/protocol-research');
    await runWithLocalRunLog(
        {
            scriptName: 'research:protocol',
            commandLineArguments: [
                name,
                ...(sourceDirectory === undefined ? [] : [sourceDirectory]),
            ],
            lanes: [
                'Pin public operator inputs',
                'Build public arithmetic fixture',
                host === 'native'
                    ? 'Native public operator screens'
                    : 'Source-matched bounded scalar public operator screens',
            ],
        },
        async (log) => {
            const unlock = await acquireProtocolResearchLock(
                log.runDirectoryPath,
                root,
            );
            try {
                assert.ok(freemem() >= 2 * fixtureProcessMemoryLimit);
                const models = kinds.map((kind) =>
                    compilePublicOperatorScreenResources(kind),
                );
                assert.ok(models.length > 0);
                for (const model of models) {
                    assert.ok(
                        model.planningBytes < BigInt(fixtureProcessMemoryLimit),
                    );
                    assert.ok(
                        model.planningBytes < BigInt(scalarLinearMemoryLimit),
                    );
                    assert.ok(
                        model.reportBytes <= model.outputCapacity &&
                            model.outputCapacity <= 1n << 20n,
                    );
                }
                await writeFile(
                    path.join(log.runDirectoryPath, 'resource-inputs.json'),
                    JSON.stringify(
                        {
                            models,
                            phaseLabels: publicOperatorPhases,
                            processMemoryLimit: fixtureProcessMemoryLimit,
                            linearMemoryLimit: scalarLinearMemoryLimit,
                            scope: 'Public recipe and operator construction is phase 1; actual query evaluation is phase 4. Coordinate checks, whole-operator digest, query references and report comparison are instrumentation. Planning counts buffers and its stated allowance; enforced sampled process/linear limits remain independent.',
                        },
                        (_key, value: unknown) =>
                            typeof value === 'bigint' ? String(value) : value,
                    ) + '\n',
                    { flag: 'wx' },
                );
                const environment: NodeJS.ProcessEnv = {
                    ...process.env,
                    RUSTFLAGS: '',
                    CARGO_ENCODED_RUSTFLAGS: '',
                    CARGO_INCREMENTAL: '0',
                    SOURCE_DATE_EPOCH: '0',
                    CARGO_TARGET_DIR: path.join(workspace, 'target'),
                };
                delete environment.SEALED_LATTICE_SIMULATED_HELPERS;
                const context = { root, log, environment };
                const compiler = await readFixtureCompiler(context);
                const source =
                    sourceDirectory === undefined
                        ? undefined
                        : await readPublicOperatorNativeSource(
                              sourceDirectory,
                              root,
                          );
                if (source)
                    await writeFile(
                        path.join(log.runDirectoryPath, 'native-inputs.json'),
                        JSON.stringify(
                            {
                                directory: source.directory,
                                diagnosticDigests: source.diagnosticDigests,
                                artifacts: source.artifacts,
                            },
                            null,
                            2,
                        ) + '\n',
                        { flag: 'wx' },
                    );
                const snapshot = await snapshotResearchSources(
                    log,
                    root,
                    sourcesForHost,
                );
                await mkdir(log.artifactDirectoryPath, { recursive: true });
                const output = path.join(
                    log.artifactDirectoryPath,
                    'public-operator',
                );
                await mkdir(output);
                let executable: string | undefined;
                let module:
                    | Awaited<ReturnType<typeof buildScalarFixtureModule>>
                    | undefined;
                let files: string[];
                let admission:
                    | Awaited<ReturnType<typeof assertScalarNativeInputs>>
                    | undefined;
                if (host === 'native') {
                    await executeFixtureCommand(
                        context,
                        'cargo',
                        ['+1.95.0', 'fmt', '-p', packageName, '--', '--check'],
                        'format',
                    );
                    await executeFixtureCommand(
                        context,
                        'cargo',
                        [
                            '+1.95.0',
                            'clippy',
                            '--offline',
                            '--locked',
                            '--no-default-features',
                            '-p',
                            packageName,
                            '--all-targets',
                            '--',
                            '-D',
                            'warnings',
                        ],
                        'clippy',
                    );
                    await executeFixtureCommand(
                        context,
                        'cargo',
                        [
                            '+1.95.0',
                            'test',
                            '--offline',
                            '--locked',
                            '-p',
                            packageName,
                            '--lib',
                            '--bin',
                            binaryName,
                        ],
                        'bounded-unit-tests',
                    );
                    await executeFixtureCommand(
                        context,
                        'cargo',
                        [
                            '+1.95.0',
                            'build',
                            '--offline',
                            '--locked',
                            '--release',
                            '--no-default-features',
                            '-p',
                            packageName,
                            '--bin',
                            binaryName,
                        ],
                        'build-native',
                    );
                    executable = path.join(
                        workspace,
                        'target/release/' +
                            binaryName +
                            (process.platform === 'win32' ? '.exe' : ''),
                    );
                    files = await compiledFixtureFiles(
                        path.join(
                            workspace,
                            'target/release/' + binaryName + '.d',
                        ),
                        snapshot,
                    );
                } else {
                    assert.ok(source);
                    module = await buildScalarFixtureModule(
                        context,
                        'public-operator',
                    );
                    const dependencyFile = path.join(
                        root,
                        'target/public-operator-scalar/wasm32-unknown-unknown/release/public_operator_screen.d',
                    );
                    files = await compiledFixtureFiles(
                        dependencyFile,
                        snapshot,
                    );
                    admission = await assertScalarNativeInputs(
                        source,
                        files,
                        compiler,
                        root,
                        'public-operator',
                    );
                }
                const compiledInputs = await checkFixtureSources(
                    root,
                    snapshot,
                    files,
                );
                const pinnedSources =
                    host === 'native'
                        ? snapshot
                        : snapshot.filter(
                              (entry) =>
                                  files.includes(entry.file) ||
                                  sourcesForHost.includes(entry.file),
                          );
                await writeFile(
                    path.join(log.runDirectoryPath, 'source-manifest.json'),
                    JSON.stringify(
                        {
                            compiler,
                            ...(module === undefined
                                ? {}
                                : {
                                      flags: scalarFixtureBuildFlags(
                                          '<repository>',
                                          '<cargo-home>',
                                      ),
                                  }),
                            sources: pinnedSources,
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
                const runtimeFile = module?.moduleFile ?? executable;
                assert.ok(runtimeFile);
                const runtimeIdentity = await fileDigest(runtimeFile);
                await writeFile(
                    path.join(log.artifactDirectoryPath, 'runtime.bin'),
                    Buffer.from(runtimeIdentity, 'hex'),
                    { flag: 'wx' },
                );
                const native = [];
                const scalar = [];
                const artifacts = [];
                const reports = [];
                for (const model of models) {
                    const artifactName = 'operator-' + model.caseId + '.bin';
                    const file = path.join(output, artifactName);
                    if (executable !== undefined) {
                        const result = await runGuardedFixture({
                            root,
                            log,
                            environment,
                            processMemoryLimit: fixtureProcessMemoryLimit,
                            command: executable,
                            args: [String(model.caseId), file],
                            name: 'native-operator-' + model.kind,
                            handshake: 'operator',
                        });
                        assert.equal(
                            result.result.kind,
                            'public-operator-screen',
                        );
                        assert.equal(result.result.case, model.kind);
                        assert.equal(
                            result.result.reportBytes,
                            Number(model.reportBytes),
                        );
                        native.push(result);
                    } else {
                        assert.ok(source && module);
                        const expected = source.artifacts[model.caseId];
                        let result;
                        if (host === 'chrome')
                            result = await runPublicOperatorInChrome({
                                root,
                                log,
                                moduleFile: module.moduleFile,
                                moduleSha512: module.moduleSha512,
                                outputFile: file,
                                expectedBytes: expected.bytes,
                                expectedSha512: expected.sha512,
                                processMemoryLimit: fixtureProcessMemoryLimit,
                                linearMemoryLimit: scalarLinearMemoryLimit,
                                caseIndex: model.caseId as 0 | 1,
                            });
                        else {
                            const configuration = path.join(
                                log.runDirectoryPath,
                                'operator-' + model.caseId + '-input.json',
                            );
                            await writeFile(
                                configuration,
                                JSON.stringify({
                                    operation: 'public-operator',
                                    caseIndex: model.caseId,
                                    module: module.moduleFile,
                                    moduleSha512: module.moduleSha512,
                                    outputFile: file,
                                    expectedBytes: expected.bytes,
                                    expectedSha512: expected.sha512,
                                }) + '\n',
                                { flag: 'wx' },
                            );
                            result = await runGuardedFixture({
                                root,
                                log,
                                environment,
                                processMemoryLimit: fixtureProcessMemoryLimit,
                                command: process.execPath,
                                args: [
                                    path.join(
                                        root,
                                        'tools/ci/bounded-output-worker.mjs',
                                    ),
                                    configuration,
                                ],
                                name: 'scalar-operator-' + model.kind,
                                handshake: 'operator',
                            });
                        }
                        assert.equal(
                            result.result.kind,
                            host === 'chrome'
                                ? 'browser-public-operator-screen'
                                : 'scalar-public-operator-screen',
                        );
                        assert.equal(result.result.caseIndex, model.caseId);
                        assert.equal(
                            result.result.bytes,
                            Number(model.reportBytes),
                        );
                        assert.equal(result.result.controlCases, 5);
                        assert.ok(
                            typeof result.result.maximumLinearMemoryBytes ===
                                'number' &&
                                result.result.maximumLinearMemoryBytes <=
                                    scalarLinearMemoryLimit,
                        );
                        await compareNativeReferenceArtifacts(
                            [expected],
                            output,
                        );
                        scalar.push(result);
                    }
                    assert.equal(
                        BigInt((await stat(file)).size),
                        model.reportBytes,
                    );
                    reports.push(
                        parsePublicOperatorReport(
                            await readFile(file),
                            model.kind,
                        ),
                    );
                    artifacts.push({
                        name: artifactName,
                        bytes: Number(model.reportBytes),
                        sha512: await fileDigest(file),
                    });
                }
                if (source !== undefined)
                    await assertPublicOperatorSourceStable(source, root);
                await checkFixtureSources(
                    root,
                    pinnedSources,
                    host === 'native'
                        ? [...files, ...sourcesForHost]
                        : undefined,
                );
                assert.equal(
                    await fileDigest(runtimeFile),
                    runtimeIdentity,
                    'The operator runtime changed during execution.',
                );
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify(
                        {
                            case: name,
                            participantCount: 4,
                            optionCount: 2,
                            simulatedHelpers: 0,
                            output,
                            runtimeIdentity,
                            compiledInputs,
                            artifacts,
                            reports,
                            ...(host === 'native'
                                ? { native }
                                : {
                                      source: source?.directory,
                                      sourceDiagnostics:
                                          source?.diagnosticDigests,
                                      admission,
                                      module: module?.inspected,
                                      scalar,
                                  }),
                            scope: 'Public arithmetic at the full physical ring using streamed synthetic public polynomials and the full paired query list. Original-equation coordinate checks and streamed column/query references check the operator; matching reports compare native and scalar execution. Construction/query timings are separated from reference/digest instrumentation. No witness, proof, predecessor capability, disclosure, participant state or phone qualification is created.',
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
                log.writeEvent({
                    eventType: 'public-operator-completed',
                    details: { host, runtimeIdentity, artifacts },
                });
            } finally {
                await unlock();
            }
        },
    );
};
