import assert from 'node:assert/strict';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
    checkFixtureSources,
    snapshotResearchSources,
} from '#tools/ci/fixture-sources.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { registrationSessionTest } from '#tools/ci/protocol-research-registry.js';
import { runGuardedFixture } from '#tools/ci/run-guarded-fixture.js';
import {
    executeFixtureCommand,
    fixtureProcessMemoryLimit,
    readFixtureCompiler,
} from '#tools/ci/scalar-fixture-build.js';

export const parseRegistrationSessionResult = (output: string) => {
    const lines = output.split(/\r?\n/u).map((line) => line.trim());
    assert.equal(
        lines.filter(
            (line) => line === `test ${registrationSessionTest} ... ok`,
        ).length,
        1,
    );
    const summaries = lines.filter((line) => line.startsWith('test result:'));
    assert.equal(summaries.length, 1);
    assert.match(
        summaries[0],
        /^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out;/u,
    );
    return { kind: 'registration-session', passed: 1, ignored: 0 };
};

export const runRegistrationSession = async () => {
    const root = path.resolve('.');
    await runWithLocalRunLog(
        {
            scriptName: 'research:protocol',
            commandLineArguments: ['registration-session'],
            lanes: [
                'Verify registered test',
                'Original registration and checkpoint ownership',
            ],
        },
        async (log) => {
            const unlock = await acquireProtocolResearchLock(
                log.runDirectoryPath,
                root,
            );
            try {
                const environment: NodeJS.ProcessEnv = {
                    ...process.env,
                    CARGO_INCREMENTAL: '0',
                    RUSTFLAGS: '',
                    CARGO_ENCODED_RUSTFLAGS: '',
                    CARGO_TARGET_DIR: path.join(
                        root,
                        'crates/protocol-research/target',
                    ),
                };
                delete environment.SEALED_LATTICE_SIMULATED_HELPERS;
                const context = { root, log, environment };
                const compiler = await readFixtureCompiler(context);
                const sources = await snapshotResearchSources(log, root, [
                    'tools/ci/run-registration-session.ts',
                    'tools/ci/protocol-research-registry.ts',
                    'tools/ci/run-guarded-fixture.ts',
                    'tools/ci/native-operation-guard.ts',
                    'tools/ci/scalar-fixture-build.ts',
                    'tools/ci/fixture-sources.ts',
                ]);
                const args = [
                    '+1.95.0',
                    'test',
                    '--release',
                    '--offline',
                    '--locked',
                    '--manifest-path',
                    path.join(root, 'crates/protocol-research/Cargo.toml'),
                    '-p',
                    'registration-enrollment',
                    '--lib',
                    registrationSessionTest,
                    '--',
                    '--exact',
                    '--test-threads=1',
                ];
                const listing = await executeFixtureCommand(
                    context,
                    'cargo',
                    [...args, '--list', '--format=terse'],
                    'registered-test-list',
                );
                assert.deepEqual(
                    listing
                        .split(/\r?\n/u)
                        .filter((line) => line.endsWith(': test')),
                    [`${registrationSessionTest}: test`],
                );
                await checkFixtureSources(root, sources);
                const result = await runGuardedFixture({
                    root,
                    log,
                    environment,
                    processMemoryLimit: fixtureProcessMemoryLimit,
                    command: 'cargo',
                    args,
                    name: 'registration-session',
                    parseResult: parseRegistrationSessionResult,
                });
                await checkFixtureSources(root, sources);
                await writeFile(
                    path.join(
                        log.runDirectoryPath,
                        'registration-session.json',
                    ),
                    JSON.stringify(
                        {
                            compiler,
                            sources,
                            registeredTest: registrationSessionTest,
                            processMemoryLimit: fixtureProcessMemoryLimit,
                            ...result,
                            scope: 'One genuine signed registration with streamed positive/hostile key verification and original-owner partial checkpoint import. Other roster entries and the partial checkpoint are framing fixtures; no complete setup or resumed contribution proof is claimed.',
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
