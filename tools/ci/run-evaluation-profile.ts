import assert from 'node:assert/strict';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { toolArguments } from '#tools/ci/command-line.js';
import { runCommandsInSeries } from '#tools/ci/command-runner.js';
import { importClosure } from '#tools/ci/import-closure.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { snapshotRunSources } from '#tools/ci/run-sources.js';

const argumentsList = toolArguments(process.argv.slice(2));
assert.equal(
    argumentsList.length,
    1,
    'Select one passed browser run with retained public records.',
);
const source = path.resolve(argumentsList[0]);
const summary = JSON.parse(
    await readFile(path.join(source, 'summary.json'), 'utf8'),
) as { result: string; scriptName: string };
assert.equal(summary.result, 'passed');
assert.equal(summary.scriptName, 'research:participant');
await runWithLocalRunLog(
    {
        scriptName: 'research:evaluation-profile',
        commandLineArguments: [source],
    },
    async (log) => {
        const root = process.cwd();
        const release = await acquireProtocolResearchLock(
            log.runDirectoryPath,
            root,
        );
        try {
            await mkdir(log.artifactDirectoryPath, { recursive: true });
            await snapshotRunSources(
                log,
                root,
                await importClosure(
                    [
                        'tools/ci/run-evaluation-profile.ts',
                        'tools/ci/participant-evaluation-replay.ts',
                    ],
                    root,
                ),
            );
            await writeFile(
                path.join(log.runDirectoryPath, 'fixture.json'),
                JSON.stringify({ source }, null, 2) + '\n',
                { flag: 'wx' },
            );
            const exitCode = await runCommandsInSeries(
                [
                    {
                        command: process.execPath,
                        args: [
                            '--import',
                            'tsx',
                            'tools/ci/participant-evaluation-replay.ts',
                            source,
                            log.runDirectoryPath,
                            log.artifactDirectoryPath,
                        ],
                        description:
                            'Compare scalar target and phase diagnostics on verified public records',
                        logFileSlug: 'evaluation',
                    },
                ],
                {
                    runLog: log,
                    outputMode: 'inherit',
                    guard: {
                        timeoutMilliseconds: 3_600_000,
                        memory: {
                            limitBytes: 2_147_483_648,
                            exceededMessage:
                                'The evaluation replay exceeded its process-tree memory bound.',
                            sampleEventType: 'evaluation-memory',
                        },
                    },
                },
            );
            assert.equal(exitCode, 0, 'Evaluation replay failed.');
            console.log(log.runDirectoryPath);
        } finally {
            await release();
        }
    },
);
