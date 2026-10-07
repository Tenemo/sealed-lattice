import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    copyFile,
    mkdir,
    readFile,
    rm,
    writeFile,
    stat,
} from 'node:fs/promises';
import { freemem } from 'node:os';
import path from 'node:path';

import {
    runArtifactDirectoryPath,
    runWithLocalRunLog,
} from '#tools/ci/local-run-log.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { selectPublicCompletionCase } from '#tools/ci/protocol-research-registry.js';
import { deriveResearchScenario } from '#tools/ci/protocol-research-scenario.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from '#tools/ci/run-command.js';

// A passed research run. The ceremony directory among its artifacts holds
// the public setup, close and completion records the reader verifies.
type ResearchRun = {
    case: string;
    participantCount: number;
    optionCount: number;
    result: { kind: 'result' | 'no-result'; identifiers?: string[] };
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
            const run = JSON.parse(
                await readFile(path.join(source, 'result.json'), 'utf8'),
            ) as ResearchRun;
            assert.match(
                run.case,
                /^native-(?:result|empty|invalid-only|setup-departure|selection-fork)$/u,
            );
            const ceremony = path.join(
                runArtifactDirectoryPath(source),
                'ceremony',
            );
            assert.ok((await stat(path.join(ceremony, 'close'))).isDirectory());
            const scenario = deriveResearchScenario(
                run.participantCount,
                run.optionCount,
                run.case === 'native-setup-departure',
                run.case === 'native-selection-fork',
            );
            // Release shares from positions spread evenly over the roster,
            // so no two are adjacent, and a bad share just after the first.
            const releaseAuthors = Array.from(
                { length: scenario.releaseThreshold },
                (_unused, index) =>
                    Math.floor(
                        (index * (scenario.participantCount - 1)) /
                            (scenario.releaseThreshold - 1),
                    ),
            );
            const badRelease =
                run.case === 'native-setup-departure'
                    ? 2
                    : releaseAuthors[0] + 1;
            // A bad extra vote takes the first corrupt position's file, since
            // every corrupt participant withholds its vote.
            const certificateAuthors =
                run.case === 'native-selection-fork'
                    ? [0, 1, 3]
                    : scenario.signers;
            const badVotes =
                run.case === 'native-selection-fork'
                    ? [2]
                    : run.case === 'native-setup-departure'
                      ? []
                      : scenario.corrupt.slice(0, 1);
            let directory: string;
            if (selected.name === 'available-records') {
                assert.equal(run.result.kind, 'result');
                const original = path.join(ceremony, 'completion');
                directory = path.join(
                    log.artifactDirectoryPath,
                    'available-completion',
                );
                await mkdir(directory, { recursive: true });
                // The native certificate has exactly the honest votes, so
                // every one is needed; the corrupt participants signed none.
                assert.equal(
                    certificateAuthors.length,
                    scenario.certificateThreshold,
                );
                const files = [
                    'target.bin',
                    ...certificateAuthors.map(
                        (index) => 'target-vote-' + index + '.bin',
                    ),
                    ...releaseAuthors.flatMap((index) => [
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
                for (const position of badVotes) {
                    const badVote = await readFile(
                        path.join(
                            original,
                            'target-vote-' +
                                scenario.signers[scenario.signers.length - 1] +
                                '.bin',
                        ),
                    );
                    badVote[100] ^= 1;
                    await writeFile(
                        path.join(
                            directory,
                            'target-vote-' + position + '.bin',
                        ),
                        badVote,
                        { flag: 'wx' },
                    );
                }
                await copyFile(
                    path.join(
                        original,
                        'release-envelope-' + badRelease + '.bin',
                    ),
                    path.join(
                        directory,
                        'release-envelope-' + badRelease + '.bin',
                    ),
                );
                const badBody = await readFile(
                    path.join(original, 'release-' + badRelease + '.bin'),
                );
                badBody[badBody.length - 1] ^= 1;
                await writeFile(
                    path.join(directory, 'release-' + badRelease + '.bin'),
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
            const scratch = path.resolve(
                'temp',
                'threshold-reader-' + path.basename(log.runDirectoryPath),
            );
            // The reader runs the binary at the workspace's own target
            // directory, so an inherited one cannot substitute a stale build.
            const workspace = path.resolve('crates/protocol-research'),
                environment = {
                    ...process.env,
                    CARGO_TARGET_DIR: path.join(workspace, 'target'),
                    RUSTFLAGS: '',
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
                output = path.join(log.artifactDirectoryPath, 'verification');
            // The reader creates each output directory inside the artifact
            // directory.
            await mkdir(log.artifactDirectoryPath, { recursive: true });
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
            // One reader process over a ceremony and completion directory,
            // inside the process-tree memory guard. The reader verifies one
            // setup contribution per participant, which dominates its
            // duration.
            const verificationTimeout = 900_000 * scenario.participantCount;
            const verifyRecords = async (
                ceremonyDirectory: string,
                completionDirectory: string,
                outputDirectory: string,
                scratchDirectory: string,
                slug: string,
            ) => {
                // The reader's scratch holds only its working values.
                try {
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
                                    ceremonyDirectory,
                                    scratchDirectory,
                                    outputDirectory,
                                    completionDirectory,
                                    ...(selected.stage !== 'terminal'
                                        ? [selected.stage]
                                        : []),
                                ],
                                env: environment,
                                workingDirectoryPath: workspace,
                                description:
                                    'Verify only available completion records',
                                logFileSlug: slug,
                            },
                        ],
                        {
                            runLog: log,
                            outputMode: 'inherit',
                            signal: AbortSignal.any([
                                controller.signal,
                                AbortSignal.timeout(verificationTimeout),
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
                                    })().catch((error) =>
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
                    assert.ok(samples > 0);
                    return { exitCode, peakMemory, samples };
                } finally {
                    await rm(scratchDirectory, {
                        recursive: true,
                        force: true,
                    });
                }
            };
            const { exitCode, peakMemory, samples } = await verifyRecords(
                ceremony,
                directory,
                output,
                scratch,
                'verification',
            );
            assert.equal(exitCode, 0);
            const verified = JSON.parse(
                await readFile(
                    path.join(output, selected.stage + '.json'),
                    'utf8',
                ),
            ) as TerminalResult | CertificateResult | ReleaseResult;
            const report = JSON.parse(
                await readFile(path.join(output, 'result.json'), 'utf8'),
            ) as Record<string, unknown> & { participantCount: number };
            const emptyCase = report.ciphertextBytes === 0;
            const participantCount = report.participantCount;
            assert.equal(emptyCase, run.result.kind === 'no-result');
            assert.ok(
                verified.certificateAuthors.length >=
                    participantCount - Math.floor((participantCount - 1) / 3),
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
                        verified.releaseAuthor < participantCount,
                );
            } else {
                assert.ok(
                    verified.kind === 'result' || verified.kind === 'no-result',
                );
                assert.equal(verified.kind, run.result.kind);
                if (!emptyCase)
                    assert.deepEqual(
                        verified.identifiers,
                        run.result.identifiers,
                    );
            }
            if (selected.name === 'available-records') {
                const terminal = verified as TerminalResult;
                assert.equal(terminal.kind, 'result');
                assert.deepEqual(
                    terminal.certificateAuthors,
                    certificateAuthors,
                );
                assert.deepEqual(terminal.releaseAuthors, releaseAuthors);
                const withheld = Array.from(
                    { length: scenario.participantCount },
                    (_, position) => position,
                ).filter(
                    (position) =>
                        !certificateAuthors.includes(position) &&
                        !badVotes.includes(position),
                );
                assert.deepEqual(terminal.unavailableVotes, withheld);
                assert.deepEqual(terminal.invalidVotes, badVotes);
                assert.ok(terminal.invalidReleases.includes(badRelease));
                const absentReleases = Array.from(
                    { length: scenario.participantCount },
                    (_unused, position) => position,
                ).filter(
                    (position) =>
                        position !== badRelease &&
                        !releaseAuthors.includes(position),
                );
                for (const file of [
                    ...withheld.map(
                        (position) => 'target-vote-' + position + '.bin',
                    ),
                    ...absentReleases.map(
                        (position) => 'release-' + position + '.bin',
                    ),
                ])
                    await assert.rejects(stat(path.join(directory, file)), {
                        code: 'ENOENT',
                    });
            }
            await writeFile(
                path.join(log.runDirectoryPath, 'result.json'),
                JSON.stringify(
                    {
                        source,
                        ceremony,
                        emptyCase,
                        participantCount,
                        stage: selected.stage,
                        output,
                        completionDirectory: directory,
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
                                  ? 'Public setup, close barrier, usable-slot classification, deterministic target and available certificate signatures are independently recomputed and verified. No release is generated or required. Durable certificate publication and post-boundary disappearance remain separate gates.'
                                  : selected.stage === 'release'
                                    ? 'One supplied release message passes original-key authentication and the complete owning proof verifier after public setup, target and certificate recomputation. Wrong-target, incomplete-proof, altered-proof and duplicate controls run at that author. One share cannot reconstruct a terminal. This is component evidence, not terminal availability or a complete security argument.'
                                    : 'Public setup, close barrier, usable-slot classification, deterministic target, available certificate signatures and release proofs are independently verified from supplied public files. No participant private state is consumed; durable delivery and actual departure chronology remain separate gates.',
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
