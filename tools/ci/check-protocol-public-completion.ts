import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { copyFile, mkdir, readFile, writeFile, stat } from 'node:fs/promises';
import { freemem } from 'node:os';
import path from 'node:path';

import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { selectPublicCompletionCase } from '#tools/ci/protocol-research-registry.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from '#tools/ci/run-command.js';

type PublicCompletionRun = {
    completedNative: boolean;
    emptyCase: boolean;
    source: string;
    maximumBodyBytes: number;
    publicConfiguration: {
        participantCount: number;
        inventoryIdentity: string;
        polynomials: { index: number; bytes: number; width: number }[];
    };
    terminal?: { kind: string; identifiers: string[] };
};
type TerminalResult = {
    kind: 'result' | 'no-result';
    identifiers: string[];
    certificateAuthors: number[];
    releaseAuthors: number[];
    unavailableVotes: number[];
    invalidVotes: number[];
    invalidReleases: number[];
};
type CertificateResult = {
    kind: 'certified-target';
    encrypted: boolean;
    certificateAuthors: number[];
};
type ReleaseResult = {
    kind: 'verified-release';
    releaseAuthor: number;
    certificateAuthors: number[];
};

const selected = selectPublicCompletionCase(process.argv.slice(2)),
    source = path.resolve(selected.source);
await runWithLocalRunLog(
    {
        commandLineArguments: [
            selected.name,
            source,
            ...(selected.completionDirectory
                ? [selected.completionDirectory]
                : []),
        ],
        lanes: ['Independent public setup, target and completion verification'],
        scriptName: 'research:protocol:public',
    },
    async (log) => {
        const releaseLock = await acquireProtocolResearchLock(
            log.runDirectoryPath,
            process.cwd(),
        );
        try {
            assert.ok(freemem() >= 2147483648);
            const summary = JSON.parse(
                await readFile(path.join(source, 'summary.json'), 'utf8'),
            ) as { result: string };
            assert.equal(summary.result, 'passed');
            const prior = JSON.parse(
                await readFile(path.join(source, 'result.json'), 'utf8'),
            ) as PublicCompletionRun;
            let directory: string;
            if (selected.name === 'available-records') {
                assert.equal(prior.completedNative, true);
                assert.equal(prior.emptyCase, false);
                const producer = JSON.parse(
                        await readFile(
                            path.join(prior.source, 'result.json'),
                            'utf8',
                        ),
                    ) as { output: string },
                    original = path.join(producer.output, 'completion');
                directory = path.join(
                    log.runDirectoryPath,
                    'available-completion',
                );
                await mkdir(directory);
                const files = [
                    'target.bin',
                    ...[2, 3, 4, 5, 6, 7, 9].map(
                        (index) => 'target-vote-' + index + '.bin',
                    ),
                    ...[1, 4, 6, 8].flatMap((index) => [
                        'release-envelope-' + index + '.bin',
                        'release-' + index + '.bin',
                    ]),
                ];
                for (const file of files)
                    await copyFile(
                        path.join(original, file),
                        path.join(directory, file),
                    );
                // A bad extra vote and a bad extra share precede later valid evidence.
                const badVote = await readFile(
                    path.join(original, 'target-vote-0.bin'),
                );
                badVote[100] ^= 1;
                await writeFile(
                    path.join(directory, 'target-vote-0.bin'),
                    badVote,
                    { flag: 'wx' },
                );
                await copyFile(
                    path.join(original, 'release-envelope-2.bin'),
                    path.join(directory, 'release-envelope-2.bin'),
                );
                const badBody = await readFile(
                    path.join(original, 'release-2.bin'),
                );
                badBody[badBody.length - 1] ^= 1;
                await writeFile(
                    path.join(directory, 'release-2.bin'),
                    badBody,
                    {
                        flag: 'wx',
                    },
                );
            } else {
                assert.ok(selected.completionDirectory);
                directory = path.resolve(selected.completionDirectory);
                assert.ok((await stat(directory)).isDirectory());
            }
            const paths = (
                await readFile(path.join(source, 'public-paths.txt'), 'utf8')
            )
                .trimEnd()
                .split(/\r?\n/u);
            assert.equal(paths.length, 60);
            paths[5] = path.resolve(
                'temp',
                'threshold-reader-' + path.basename(log.runDirectoryPath),
            );
            const manifest = path.join(
                log.runDirectoryPath,
                'public-paths.txt',
            );
            await writeFile(manifest, paths.join('\n') + '\n', { flag: 'wx' });
            const workspace = path.resolve('crates/protocol-research'),
                environment = {
                    ...process.env,
                    RUSTFLAGS: '',
                    PROTOC: process.env.PROTOC,
                };
            const execute = async (
                command: string,
                args: string[],
                name: string,
            ) => {
                const result = await runCommandAndCaptureOutput(
                    {
                        command,
                        args,
                        env: environment,
                        workingDirectoryPath: workspace,
                        description: name,
                        logFileSlug: name,
                    },
                    {
                        runLog: log,
                        echoOutput: true,
                        signal: AbortSignal.timeout(900000),
                    },
                );
                assert.equal(result.exitCode, 0, name);
                return result;
            };
            await execute(
                'cargo',
                [
                    '+1.95.0',
                    'clippy',
                    '--offline',
                    '--locked',
                    '-p',
                    'evaluation-target',
                    '--all-targets',
                    '--',
                    '-D',
                    'warnings',
                ],
                'clippy',
            );
            await execute(
                'cargo',
                [
                    '+1.95.0',
                    'build',
                    '--offline',
                    '--locked',
                    '--release',
                    '-p',
                    'evaluation-target',
                    '--bin',
                    'check-target',
                ],
                'build',
            );
            const executable = path.join(
                    workspace,
                    'target/release/check-target' +
                        (process.platform === 'win32' ? '.exe' : ''),
                ),
                output = path.join(log.runDirectoryPath, 'verification');
            for (const file of [
                'crates/protocol-research/evaluation-target/src/public-completion-check.rs',
                'crates/protocol-research/evaluation-target/src/bin/check-target.rs',
                import.meta.filename,
            ])
                await writeFile(
                    path.join(log.runDirectoryPath, path.basename(file)),
                    await readFile(file),
                    { flag: 'wx' },
                );
            const controller = new AbortController();
            let active = false,
                monitor: Promise<void> | undefined,
                peakMemory = 0,
                samples = 0;
            const exitCode = await runCommandsInSeries(
                [
                    {
                        command: executable,
                        args: [
                            manifest,
                            output,
                            directory,
                            ...(selected.stage !== 'terminal'
                                ? [selected.stage]
                                : []),
                        ],
                        env: environment,
                        workingDirectoryPath: workspace,
                        description: 'Verify only available completion records',
                        logFileSlug: 'verification',
                    },
                ],
                {
                    runLog: log,
                    outputMode: 'inherit',
                    signal: AbortSignal.any([
                        controller.signal,
                        AbortSignal.timeout(900000),
                    ]),
                    observer: {
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
                                                'threshold-reader-memory',
                                            details: {
                                                bytes,
                                                limit: 1073741824,
                                            },
                                        });
                                        assert.ok(
                                            bytes <= 1073741824,
                                            'Reader process-tree memory guard exceeded.',
                                        );
                                    }
                                    if (active)
                                        await new Promise((resolve) =>
                                            setTimeout(resolve, 1000),
                                        );
                                }
                            })().catch((error) => controller.abort(error));
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
            const verified = JSON.parse(
                await readFile(
                    path.join(output, selected.stage + '.json'),
                    'utf8',
                ),
            ) as TerminalResult | CertificateResult | ReleaseResult;
            const report = JSON.parse(
                await readFile(path.join(output, 'result.json'), 'utf8'),
            ) as Record<string, unknown>;
            const emptyCase = report.ciphertextSha512 === '';
            assert.ok(
                verified.certificateAuthors.length >=
                    prior.publicConfiguration.participantCount -
                        Math.floor(
                            (prior.publicConfiguration.participantCount - 1) /
                                3,
                        ),
            );
            if (selected.stage === 'certificate') {
                assert.ok(verified.kind === 'certified-target');
                assert.equal(verified.encrypted, !emptyCase);
            } else if (selected.stage === 'release') {
                assert.ok(verified.kind === 'verified-release');
                assert.equal(emptyCase, false);
                assert.ok(
                    Number.isInteger(verified.releaseAuthor) &&
                        verified.releaseAuthor >= 0 &&
                        verified.releaseAuthor <
                            prior.publicConfiguration.participantCount,
                );
            } else {
                assert.ok(
                    verified.kind === 'result' || verified.kind === 'no-result',
                );
                assert.equal(verified.kind, emptyCase ? 'no-result' : 'result');
                if (prior.terminal) {
                    assert.equal(verified.kind, prior.terminal.kind);
                    if (!emptyCase)
                        assert.deepEqual(
                            verified.identifiers,
                            prior.terminal.identifiers,
                        );
                }
            }
            if (selected.name === 'available-records') {
                const terminal = verified as TerminalResult;
                assert.equal(terminal.kind, 'result');
                assert.ok(prior.terminal);
                assert.deepEqual(
                    terminal.identifiers,
                    prior.terminal.identifiers,
                );
                assert.deepEqual(
                    terminal.certificateAuthors,
                    [2, 3, 4, 5, 6, 7, 9],
                );
                assert.deepEqual(terminal.releaseAuthors, [1, 4, 6, 8]);
                assert.deepEqual(terminal.unavailableVotes, [1, 8]);
                assert.deepEqual(terminal.invalidVotes, [0]);
                assert.ok(terminal.invalidReleases.includes(2));
                for (const file of [
                    'target-vote-1.bin',
                    'target-vote-8.bin',
                    'release-0.bin',
                    'release-3.bin',
                    'release-5.bin',
                    'release-7.bin',
                    'release-9.bin',
                ])
                    await assert.rejects(stat(path.join(directory, file)), {
                        code: 'ENOENT',
                    });
            }
            await writeFile(
                path.join(log.runDirectoryPath, 'result.json'),
                JSON.stringify(
                    {
                        source:
                            selected.name === 'available-records'
                                ? prior.source
                                : source,
                        publicCompletionBaseline: source,
                        completedNative: true,
                        emptyCase,
                        stage: selected.stage,
                        output,
                        completionDirectory: directory,
                        certificateRecordsDirectory: path.join(
                            output,
                            'certificate-records',
                        ),
                        publicConfiguration: prior.publicConfiguration,
                        maximumBodyBytes: prior.maximumBodyBytes,
                        [selected.stage]: verified,
                        peakMemory,
                        samples,
                        executableSha512: createHash('sha512')
                            .update(await readFile(executable))
                            .digest('hex'),
                        scope:
                            selected.name === 'available-records'
                                ? 'Actual original signatures and proofs with missing files and corrupted extras. Public setup and target are recomputed. This tests threshold-driven retrieval after generation; it does not simulate authors leaving before generating their shares.'
                                : selected.stage === 'certificate'
                                  ? 'Public setup, source classification, deterministic target and available certificate signatures are independently recomputed and verified. No release is generated or required. Durable certificate publication and post-boundary disappearance remain separate gates.'
                                  : selected.stage === 'release'
                                    ? 'One supplied release message passes original-key authentication and the complete owning proof verifier after public setup, target and certificate recomputation. Wrong-target, incomplete-proof, altered-proof and duplicate controls run at that author. One share cannot reconstruct a terminal. This is component evidence, not terminal availability or a complete security argument.'
                                    : 'Public setup, source classification, deterministic target, available certificate signatures and release proofs are independently verified from supplied public files. No participant private state is consumed; durable delivery and actual departure chronology remain separate gates.',
                        result: report,
                    },
                    null,
                    2,
                ) + '\n',
                { flag: 'wx' },
            );
            process.stdout.write(log.runDirectoryPath + '\n');
        } finally {
            await releaseLock();
        }
    },
);
