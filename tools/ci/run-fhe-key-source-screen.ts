import assert from 'node:assert/strict';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { freemem } from 'node:os';
import path from 'node:path';

import { compileFheKeySourceScreenResources } from '#tests/fhe-key-source-resource-model.js';
import {
    boundedBrowserWorker,
    runFheKeySourceInChrome,
} from '#tools/ci/bounded-output-browser.js';
import { participantLinearMemoryBytes } from '#tools/ci/build-participant-module.js';
import {
    assertFheKeySourceStable,
    assertScalarNativeInputs,
    compareNativeReferenceArtifacts,
    fheKeySourceProgressLines,
    parseFheKeySourceOutput,
    parseFheKeySourceReport,
    readFheKeySourceNativeRun,
} from '#tools/ci/fhe-key-source-report.js';
import { fheKeySourcePhases } from '#tools/ci/fhe-key-source-scalar.mjs';
import { importClosure } from '#tools/ci/import-closure.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { runGuardedScreen } from '#tools/ci/run-guarded-screen.js';
import {
    checkRunSources,
    compiledRunFiles,
    fileDigest,
    snapshotResearchSources,
} from '#tools/ci/run-sources.js';
import {
    rustToolchain,
    workspaceCargoEnvironment,
} from '#tools/ci/rust-toolchain.js';
import {
    buildScalarScreenModule,
    executeScreenCommand,
    readScreenCompiler,
    scalarScreenBuildFlags,
    screenProcessMemoryLimit,
} from '#tools/ci/scalar-screen-build.js';

const screenKind = 'fhe-key-source';
const packageName = 'setup-witness';
const binaryName = 'screen-fhe-key-source';
const features = ['--features', 'key-source-screen'];
// The research runner that starts the screen, the worker thread the screen
// starts and the browser worker it serves, which only their paths reach.
const hostEntries = [
    'tools/ci/run-protocol-research.ts',
    'tools/ci/fhe-key-source-scalar-worker.mjs',
    boundedBrowserWorker,
];

export const runFheKeySourceScreen = async (
    host: 'native' | 'scalar' | 'browser',
    nativeRunDirectory?: string,
) => {
    assert.equal(nativeRunDirectory === undefined, host === 'native');
    const name = `${host}-${screenKind}`;
    const root = path.resolve('.');
    const workspace = path.join(root, 'crates/protocol-research');
    await runWithLocalRunLog(
        {
            scriptName: 'research:protocol',
            commandLineArguments: [
                name,
                ...(nativeRunDirectory === undefined
                    ? []
                    : [nativeRunDirectory]),
            ],
        },
        async (log) => {
            const unlock = await acquireProtocolResearchLock(
                log.runDirectoryPath,
                root,
            );
            try {
                assert.ok(freemem() >= 2 * screenProcessMemoryLimit);
                const resources = compileFheKeySourceScreenResources();
                const model = {
                    ...resources,
                    kind: 'key-source' as const,
                    planningBytes:
                        host === 'native'
                            ? resources.nativePlanningBytes
                            : resources.scalarPlanningBytes,
                };
                assert.ok(
                    model.planningBytes < BigInt(screenProcessMemoryLimit),
                );
                assert.ok(
                    model.planningBytes < BigInt(participantLinearMemoryBytes),
                );
                assert.ok(
                    model.reportBytes <= model.outputCapacity &&
                        model.outputCapacity <= 1n << 20n,
                );
                await writeFile(
                    path.join(log.runDirectoryPath, 'resource-inputs.json'),
                    JSON.stringify(
                        {
                            model,
                            phaseLabels: fheKeySourcePhases,
                            processMemoryLimit: screenProcessMemoryLimit,
                            linearMemoryLimit: participantLinearMemoryBytes,
                        },
                        (_key, value: unknown) =>
                            typeof value === 'bigint' ? String(value) : value,
                    ) + '\n',
                    { flag: 'wx' },
                );
                const environment: NodeJS.ProcessEnv = {
                    ...workspaceCargoEnvironment(workspace),
                    SOURCE_DATE_EPOCH: '0',
                };
                delete environment.SEALED_LATTICE_SIMULATED_HELPERS;
                const context = { root, log, environment };
                const compiler = await readScreenCompiler(context);
                const nativeRun =
                    nativeRunDirectory === undefined
                        ? undefined
                        : await readFheKeySourceNativeRun(
                              nativeRunDirectory,
                              root,
                          );
                if (nativeRun)
                    await writeFile(
                        path.join(log.runDirectoryPath, 'native-inputs.json'),
                        JSON.stringify(
                            {
                                directory: nativeRun.directory,
                                diagnosticDigests: nativeRun.diagnosticDigests,
                                artifacts: nativeRun.artifacts,
                            },
                            null,
                            2,
                        ) + '\n',
                        { flag: 'wx' },
                    );
                const sourcesForHost = await importClosure(hostEntries, root);
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
                    | Awaited<ReturnType<typeof buildScalarScreenModule>>
                    | undefined;
                let files: string[];
                let admission:
                    | Awaited<ReturnType<typeof assertScalarNativeInputs>>
                    | undefined;
                if (host === 'native') {
                    await executeScreenCommand(
                        context,
                        'cargo',
                        [
                            rustToolchain,
                            'fmt',
                            '-p',
                            packageName,
                            '--',
                            '--check',
                        ],
                        'format',
                    );
                    await executeScreenCommand(
                        context,
                        'cargo',
                        [
                            rustToolchain,
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
                    await executeScreenCommand(
                        context,
                        'cargo',
                        [
                            rustToolchain,
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
                    await executeScreenCommand(
                        context,
                        'cargo',
                        [
                            rustToolchain,
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
                    files = await compiledRunFiles(
                        path.join(
                            workspace,
                            'target/release/' + binaryName + '.d',
                        ),
                        snapshot,
                    );
                } else {
                    assert.ok(nativeRun);
                    module = await buildScalarScreenModule(context);
                    const dependencyFile = path.join(
                        root,
                        'target/' +
                            screenKind +
                            '-scalar/wasm32-unknown-unknown/release/setup_witness.d',
                    );
                    files = await compiledRunFiles(dependencyFile, snapshot);
                    admission = await assertScalarNativeInputs(
                        nativeRun,
                        files,
                        compiler,
                        root,
                    );
                }
                const compiledInputs = await checkRunSources(
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
                                      flags: scalarScreenBuildFlags(
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
                const artifactName = 'key-source.bin';
                const file = path.join(output, artifactName);
                if (executable !== undefined) {
                    const result = await runGuardedScreen({
                        root,
                        log,
                        environment,
                        processMemoryLimit: screenProcessMemoryLimit,
                        command: executable,
                        args: [file],
                        name: 'native-screen-' + model.kind,
                        nativeProgressLines: fheKeySourceProgressLines,
                        parseResult: parseFheKeySourceOutput,
                    });
                    assert.equal(result.result.kind, screenKind + '-screen');
                    assert.equal(
                        result.result.reportBytes,
                        Number(model.reportBytes),
                    );
                    native.push(result);
                } else {
                    assert.ok(nativeRun && module);
                    const [expected] = nativeRun.artifacts;
                    let result;
                    if (host === 'browser')
                        result = await runFheKeySourceInChrome({
                            root,
                            log,
                            moduleFile: module.moduleFile,
                            moduleSha512: module.moduleSha512,
                            outputFile: file,
                            expectedBytes: expected.bytes,
                            expectedSha512: expected.sha512,
                            processMemoryLimit: screenProcessMemoryLimit,
                            linearMemoryLimit: participantLinearMemoryBytes,
                        });
                    else {
                        const configuration = path.join(
                            log.runDirectoryPath,
                            'screen-input.json',
                        );
                        await writeFile(
                            configuration,
                            JSON.stringify({
                                operation: screenKind,
                                module: module.moduleFile,
                                moduleSha512: module.moduleSha512,
                                outputFile: file,
                                expectedBytes: expected.bytes,
                                expectedSha512: expected.sha512,
                            }) + '\n',
                            { flag: 'wx' },
                        );
                        result = await runGuardedScreen({
                            root,
                            log,
                            environment,
                            processMemoryLimit: screenProcessMemoryLimit,
                            command: process.execPath,
                            args: [
                                path.join(
                                    root,
                                    'tools/ci/fhe-key-source-scalar-worker.mjs',
                                ),
                                configuration,
                            ],
                            name: 'scalar-screen-' + model.kind,
                        });
                    }
                    assert.equal(
                        result.result.kind,
                        host === 'browser'
                            ? 'browser-' + screenKind + '-screen'
                            : 'scalar-' + screenKind + '-screen',
                    );
                    assert.equal(
                        result.result.bytes,
                        Number(model.reportBytes),
                    );
                    assert.equal(result.result.controlCases, 5);
                    assert.ok(
                        typeof result.result.maximumLinearMemoryBytes ===
                            'number' &&
                            result.result.maximumLinearMemoryBytes <=
                                participantLinearMemoryBytes,
                    );
                    await compareNativeReferenceArtifacts([expected], output);
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
                if (nativeRun !== undefined)
                    await assertFheKeySourceStable(nativeRun, root);
                await checkRunSources(
                    root,
                    pinnedSources,
                    host === 'native'
                        ? [...files, ...sourcesForHost]
                        : undefined,
                );
                assert.equal(
                    await fileDigest(runtimeFile),
                    runtimeIdentity,
                    'The screen runtime changed during execution.',
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
                                      source: nativeRun?.directory,
                                      sourceDiagnostics:
                                          nativeRun?.diagnosticDigests,
                                      admission,
                                      module: module?.inspected,
                                      scalar,
                                  }),
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
