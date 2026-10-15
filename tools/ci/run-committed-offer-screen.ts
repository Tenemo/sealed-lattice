import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdir, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import { freemem } from 'node:os';
import path from 'node:path';

import { compileFullWordProofLayout } from '#tests/full-word-proof-layout-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { runCheckedCommand } from '#tools/ci/command-runner.js';
import { importClosure } from '#tools/ci/import-closure.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { snapshotResearchSources } from '#tools/ci/run-sources.js';
import {
    rustToolchain,
    workspaceCargoEnvironment,
} from '#tools/ci/rust-toolchain.js';

// One genuine offer, before any selected-set or full-ceremony corpus exists.
export const runCommittedOfferScreen = async () => {
    const root = path.resolve('.');
    const workspace = path.join(root, 'crates/protocol-research');
    const memoryLimit = 1_073_741_824;
    await runWithLocalRunLog(
        {
            scriptName: 'research:protocol',
            commandLineArguments: ['native-committed-offer'],
        },
        async (log) => {
            const unlock = await acquireProtocolResearchLock(
                log.runDirectoryPath,
                root,
            );
            try {
                assert.ok(freemem() >= 2 * memoryLimit);
                const environment = workspaceCargoEnvironment(workspace);
                delete environment.SEALED_LATTICE_SIMULATED_HELPERS;
                const sources = await importClosure(
                    ['tools/ci/run-protocol-research.ts'],
                    root,
                );
                await snapshotResearchSources(log, root, sources);
                await runCheckedCommand(
                    {
                        command: 'cargo',
                        args: [
                            rustToolchain,
                            'build',
                            '--offline',
                            '--locked',
                            '--release',
                            '-p',
                            'native-ceremony',
                        ],
                        env: environment,
                        workingDirectoryPath: workspace,
                        description: 'Build committed offer screen',
                        logFileSlug: 'build',
                    },
                    {
                        runLog: log,
                        echoOutput: true,
                        guard: { timeoutMilliseconds: 1_800_000 },
                    },
                );
                const executable = path.join(
                    workspace,
                    'target/release/native-ceremony' +
                        (process.platform === 'win32' ? '.exe' : ''),
                );
                await mkdir(log.artifactDirectoryPath, { recursive: true });
                const runtime = path.join(
                    log.artifactDirectoryPath,
                    'runtime.bin',
                );
                await writeFile(
                    runtime,
                    createHash('sha512')
                        .update(await readFile(executable))
                        .digest(),
                    { flag: 'wx' },
                );
                const scratch = path.join(log.artifactDirectoryPath, 'scratch');
                await mkdir(scratch);
                const output = path.join(log.artifactDirectoryPath, 'offer');
                const layout = compileFullWordProofLayout(
                    deriveSupportedProfile(3, 2),
                );
                await writeFile(
                    path.join(log.runDirectoryPath, 'inputs.json'),
                    JSON.stringify(
                        { memoryLimit, layout },
                        (_key, value: unknown) =>
                            typeof value === 'bigint' ? String(value) : value,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
                await runCheckedCommand(
                    {
                        command: executable,
                        args: [
                            output,
                            runtime,
                            scratch,
                            '3',
                            '2',
                            'committed-offer',
                        ],
                        env: environment,
                        workingDirectoryPath: workspace,
                        description: 'Generate and verify committed offer',
                        logFileSlug: 'offer',
                    },
                    {
                        runLog: log,
                        echoOutput: true,
                        guard: {
                            timeoutMilliseconds: 2_700_000,
                            memory: {
                                limitBytes: memoryLimit,
                                sampleIntervalMilliseconds: 1000,
                                sampleEventType: 'committed-offer-memory',
                                exceededMessage:
                                    'The committed offer screen exceeded its process-tree memory limit.',
                            },
                        },
                    },
                );
                const contributions = await readdir(
                    path.join(output, 'contribution-0'),
                );
                assert.equal(contributions.length, 1);
                const proofBytes = (
                    await stat(
                        path.join(
                            output,
                            'contribution-0',
                            contributions[0],
                            'proof.bin',
                        ),
                    )
                ).size;
                assert.ok(BigInt(proofBytes) <= layout.maximumMultiproofBytes);
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify({ proofBytes }) + '\n',
                    { flag: 'wx' },
                );
            } finally {
                await unlock();
            }
        },
    );
};
