import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import path from 'node:path';

import binaryen from 'binaryen';

import { participantLinearMemoryBytes } from '#tools/ci/build-participant-module.js';
import { importClosure } from '#tools/ci/import-closure.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { runCompactRankBrowser } from '#tools/ci/run-compact-rank-browser.js';
import { runGuardedScreen } from '#tools/ci/run-guarded-screen.js';
import {
    checkRunSources,
    fileDigest,
    snapshotResearchSources,
} from '#tools/ci/run-sources.js';
import {
    rustToolchain,
    workspaceCargoEnvironment,
} from '#tools/ci/rust-toolchain.js';
import {
    executeScreenCommand,
    readScreenCompiler,
    scalarScreenBuildFlags,
    screenProcessMemoryLimit,
} from '#tools/ci/scalar-screen-build.js';

type Artifact = { file: string; bytes: number; sha512: string };
type Fixture = {
    name: string;
    role: string;
    context: string;
    statement: Artifact;
    proof: Artifact;
    accepted: boolean;
};
const localPath = (root: string, file: string) => {
    assert.ok(file && !path.isAbsolute(file));
    const resolved = path.resolve(root, file);
    assert.ok(resolved.startsWith(root + path.sep));
    return resolved;
};

export const runCompactRankScreen = async (fixtureManifest: string) => {
    const root = path.resolve('.'),
        workspace = path.join(root, 'crates/protocol-research');
    const manifestPath = localPath(root, fixtureManifest);
    const manifestBytes = await readFile(manifestPath);
    const manifest = JSON.parse(manifestBytes.toString('utf8')) as {
        cases: Fixture[];
    };
    assert.ok(
        Array.isArray(manifest.cases) &&
            manifest.cases.length > 0 &&
            manifest.cases.length <= 32,
    );
    assert.ok(
        manifest.cases.some((entry) => entry.accepted === true) &&
            manifest.cases.some((entry) => entry.accepted === false),
    );
    assert.equal(
        new Set(manifest.cases.map((entry) => entry.name)).size,
        manifest.cases.length,
    );
    for (const entry of manifest.cases) {
        assert.ok(
            typeof entry.name === 'string' &&
                entry.name &&
                typeof entry.role === 'string' &&
                typeof entry.context === 'string' &&
                typeof entry.accepted === 'boolean',
        );
        for (const artifact of [entry.statement, entry.proof]) {
            assert.ok(
                Number.isSafeInteger(artifact.bytes) &&
                    artifact.bytes > 0 &&
                    artifact.bytes <= 8 << 20,
            );
            assert.match(artifact.sha512, /^[0-9a-f]{128}$/u);
            const file = localPath(root, artifact.file);
            assert.equal((await readFile(file)).length, artifact.bytes);
            assert.equal(await fileDigest(file), artifact.sha512);
        }
    }
    await runWithLocalRunLog(
        {
            scriptName: 'research:protocol',
            commandLineArguments: ['compact-rank-proof', fixtureManifest],
        },
        async (log) => {
            const unlock = await acquireProtocolResearchLock(
                log.runDirectoryPath,
                root,
            );
            try {
                await mkdir(log.artifactDirectoryPath, { recursive: true });
                await writeFile(
                    path.join(log.runDirectoryPath, 'fixtures.json'),
                    manifestBytes,
                    { flag: 'wx' },
                );
                const environment = workspaceCargoEnvironment(workspace);
                const context = { root, log, environment };
                const sources = await snapshotResearchSources(
                    log,
                    root,
                    await importClosure([
                        'tools/ci/run-protocol-research.ts',
                        'tools/ci/compact-rank-screen-worker.mjs',
                        'tools/ci/compact-rank-browser-worker.mjs',
                    ]),
                );
                const compiler = await readScreenCompiler(context);
                await executeScreenCommand(
                    context,
                    'cargo',
                    [
                        rustToolchain,
                        'build',
                        '--offline',
                        '--locked',
                        '--release',
                        '-p',
                        'compact-rank-proof',
                        '--example',
                        'verify-rank-proof',
                        '--features',
                        'screen',
                    ],
                    'build-native-rank',
                );
                const scalarTarget = path.join(
                    root,
                    'target/compact-rank-scalar',
                );
                const cargoHome = path.resolve(
                    process.env.CARGO_HOME ?? path.join(homedir(), '.cargo'),
                );
                await executeScreenCommand(
                    {
                        ...context,
                        environment: {
                            ...environment,
                            CARGO_TARGET_DIR: scalarTarget,
                            CARGO_ENCODED_RUSTFLAGS: scalarScreenBuildFlags(
                                root,
                                cargoHome,
                            ).join('\x1f'),
                        },
                    },
                    'cargo',
                    [
                        rustToolchain,
                        'rustc',
                        '--offline',
                        '--locked',
                        '--release',
                        '-p',
                        'compact-rank-proof',
                        '--features',
                        'screen',
                        '--crate-type',
                        'cdylib',
                        '--lib',
                        '--target',
                        'wasm32-unknown-unknown',
                    ],
                    'build-scalar-rank',
                );
                const bytes = await readFile(
                    path.join(
                        scalarTarget,
                        'wasm32-unknown-unknown/release/compact_rank_proof.wasm',
                    ),
                );
                const inspected = binaryen.readBinary(bytes);
                try {
                    assert.doesNotMatch(
                        inspected.emitText(),
                        /\b(?:v128|i8x16|i16x8|i32x4|i64x2|f32x4|f64x2)\./u,
                    );
                    const memory = inspected.getMemoryInfo();
                    assert.ok(
                        !memory.shared &&
                            !memory.is64 &&
                            memory.max === participantLinearMemoryBytes / 65536,
                    );
                } finally {
                    inspected.dispose();
                }
                const module = await WebAssembly.compile(bytes);
                assert.deepEqual(WebAssembly.Module.imports(module), []);
                const moduleFile = path.join(
                    log.artifactDirectoryPath,
                    'compact-rank-proof.wasm',
                );
                await writeFile(moduleFile, bytes, { flag: 'wx' });
                const moduleArtifact = {
                    file: moduleFile,
                    bytes: bytes.length,
                    sha512: await fileDigest(moduleFile),
                };
                const executable = path.join(
                    workspace,
                    'target/release/examples/verify-rank-proof' +
                        (process.platform === 'win32' ? '.exe' : ''),
                );
                const reports = [];
                for (const host of ['native', 'scalar'] as const) {
                    const configuration = path.join(
                        log.runDirectoryPath,
                        host + '-configuration.json',
                    );
                    await writeFile(
                        configuration,
                        JSON.stringify({
                            host,
                            executable,
                            module: moduleArtifact,
                            cases: manifest.cases,
                        }),
                        { flag: 'wx' },
                    );
                    const report = await runGuardedScreen({
                        root,
                        log,
                        environment,
                        processMemoryLimit: screenProcessMemoryLimit,
                        command: process.execPath,
                        args: [
                            path.join(
                                root,
                                'tools/ci/compact-rank-screen-worker.mjs',
                            ),
                            configuration,
                        ],
                        name: host + '-compact-rank',
                    });
                    reports.push(report);
                }
                const browser = await runCompactRankBrowser(
                    root,
                    log,
                    moduleFile,
                    manifest.cases,
                );
                const checkedSources = await checkRunSources(root, sources);
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify(
                        {
                            compiler,
                            module: moduleArtifact,
                            executableSha512: await fileDigest(executable),
                            reports,
                            sources: checkedSources,
                            browser,
                            scope: 'Complete mathematical rank relation and canonical byte verification. No original signing-owner or predecessor admission, voting capability, phone qualification, or complete security theorem.',
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
