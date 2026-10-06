import assert from 'node:assert/strict';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { freemem } from 'node:os';
import path from 'node:path';

import { compileFheKeySourceScreenResources } from '#tests/fhe-key-source-resource-model.js';
import {
    boundedBrowserSources,
    runFheKeySourceInChrome,
} from '#tools/ci/bounded-output-browser.js';
import {
    assertFheKeySourceStable,
    assertScalarNativeInputs,
    compareNativeReferenceArtifacts,
    fheKeySourceProgressLines,
    parseFheKeySourceOutput,
    parseFheKeySourceReport,
    readFheKeySourceNativeSource,
} from '#tools/ci/fhe-key-source-report.js';
import { fheKeySourcePhases } from '#tools/ci/fhe-key-source-scalar.mjs';
import {
    checkFixtureSources,
    compiledFixtureFiles,
    fileDigest,
    snapshotResearchSources,
} from '#tools/ci/fixture-sources.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { runGuardedFixture } from '#tools/ci/run-guarded-fixture.js';
import {
    buildScalarFixtureModule,
    executeFixtureCommand,
    fixtureProcessMemoryLimit,
    readFixtureCompiler,
    scalarFixtureBuildFlags,
    scalarLinearMemoryLimit,
} from '#tools/ci/scalar-fixture-build.js';

const screenKind = 'fhe-key-source';
const packageName = 'setup-witness';
const binaryName = 'screen-fhe-key-source';
const features = ['--features', 'key-source-screen'];
const sourcesForHost = [
    'tools/ci/run-arithmetic-screen.ts',
    'tools/ci/fhe-key-source-report.ts',
    'tests/fhe-key-source-resource-model.ts',
    'tools/ci/fixture-sources.ts',
    'tools/ci/protocol-research-registry.ts',
    'tools/ci/run-guarded-fixture.ts',
    'tools/ci/native-operation-guard.ts',
    'tools/ci/scalar-fixture-build.ts',
    'tools/ci/compiled-inputs.ts',
    'tools/ci/bounded-output-worker.mjs',
    'tools/ci/operator-process-gates.mjs',
    ...boundedBrowserSources,
];

export const runArithmeticScreenFixture = async (
    host: 'native' | 'node' | 'chrome',
    sourceDirectory?: string,
) => {
    assert.equal(sourceDirectory === undefined, host === 'native');
    const name =
        (host === 'node'
            ? 'scalar'
            : host === 'chrome'
              ? 'browser'
              : 'native') +
        '-' +
        screenKind;
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
                'Pin arithmetic screen inputs',
                'Build arithmetic screen fixture',
                host === 'native'
                    ? 'Native arithmetic screens'
                    : 'Source-matched bounded scalar arithmetic screens',
            ],
        },
        async (log) => {
            const unlock = await acquireProtocolResearchLock(
                log.runDirectoryPath,
                root,
            );
            try {
                assert.ok(freemem() >= 2 * fixtureProcessMemoryLimit);
                const resources = compileFheKeySourceScreenResources();
                const models = [
                    {
                        ...resources,
                        kind: 'key-source' as const,
                        planningBytes:
                            host === 'native'
                                ? resources.nativePlanningBytes
                                : resources.scalarPlanningBytes,
                    },
                ];
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
                            phaseLabels: fheKeySourcePhases,
                            processMemoryLimit: fixtureProcessMemoryLimit,
                            linearMemoryLimit: scalarLinearMemoryLimit,
                            scope: 'Original FHE source creation, public-coordinate emission, restoration into a contribution, first-gadget generation and independent coordinate checks. Planning and sampled process/linear limits remain distinct; no proof or participant capability is created.',
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
                        : await readFheKeySourceNativeSource(
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
                const output = path.join(log.artifactDirectoryPath, screenKind);
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
                            ...features,
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
                            ...features,
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
                            ...features,
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
                    module = await buildScalarFixtureModule(context);
                    const dependencyFile = path.join(
                        root,
                        'target/' +
                            screenKind +
                            '-scalar/wasm32-unknown-unknown/release/setup_witness.d',
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
                    const artifactName = 'key-source-' + model.caseId + '.bin';
                    const file = path.join(output, artifactName);
                    if (executable !== undefined) {
                        const result = await runGuardedFixture({
                            root,
                            log,
                            environment,
                            processMemoryLimit: fixtureProcessMemoryLimit,
                            command: executable,
                            args: [file],
                            name: 'native-operator-' + model.kind,
                            handshake: true,
                            nativeProgressLines: fheKeySourceProgressLines,
                            parseResult: parseFheKeySourceOutput,
                        });
                        assert.equal(
                            result.result.kind,
                            screenKind + '-screen',
                        );
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
                            result = await runFheKeySourceInChrome({
                                root,
                                log,
                                moduleFile: module.moduleFile,
                                moduleSha512: module.moduleSha512,
                                outputFile: file,
                                expectedBytes: expected.bytes,
                                expectedSha512: expected.sha512,
                                processMemoryLimit: fixtureProcessMemoryLimit,
                                linearMemoryLimit: scalarLinearMemoryLimit,
                            });
                        else {
                            const configuration = path.join(
                                log.runDirectoryPath,
                                'operator-' + model.caseId + '-input.json',
                            );
                            await writeFile(
                                configuration,
                                JSON.stringify({
                                    operation: screenKind,
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
                                handshake: true,
                            });
                        }
                        assert.equal(
                            result.result.kind,
                            host === 'chrome'
                                ? 'browser-' + screenKind + '-screen'
                                : 'scalar-' + screenKind + '-screen',
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
                    reports.push(parseFheKeySourceReport(await readFile(file)));
                    artifacts.push({
                        name: artifactName,
                        bytes: Number(model.reportBytes),
                        sha512: await fileDigest(file),
                    });
                }
                if (source !== undefined)
                    await assertFheKeySourceStable(source, root);
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
                            participantCount: 3,
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
                            scope: 'A fixed synthetic FHE source emits its original public coordinate and restores that coordinate into the first contribution gadget. Independent coordinate checks and identical public reports compare native and scalar execution. Other gadget randomness comes from the native operating system or secure scalar host. No proof, registration, participant capability or phone qualification is created.',
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
                log.writeEvent({
                    eventType: screenKind + '-completed',
                    details: { host, runtimeIdentity, artifacts },
                });
            } finally {
                await unlock();
            }
        },
    );
};
