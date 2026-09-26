import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
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

import { createFoundationCeremonyRuntimeLoader } from '#packages/wasm/src/index.js';
import { startPublicArchiveReplica } from '#tools/archive/public-archive-replica.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { layParticipantCeremony } from '#tools/ci/participant-public-ceremony.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import {
    directoryArchiveStore,
    encodeArchiveRoutes,
    materializeArchiveRoutes,
    type ArchiveRoute,
} from '#tools/ci/protocol-public-archive.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';
import { selectPublicCompletionCase } from '#tools/ci/protocol-research-registry.js';
import { deriveResearchScenario } from '#tools/ci/protocol-research-scenario.js';
import {
    runCommandAndCaptureOutput,
    runCommandsInSeries,
} from '#tools/ci/run-command.js';

// A passed research run. Its ceremony directory holds the public setup,
// close and completion records the reader verifies.
type ResearchRun = {
    case: string;
    participantCount: number;
    optionCount: number;
    output: string;
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
            ) as { result: string; scriptName: string };
            assert.equal(summary.result, 'passed');
            // A browser cohort's relayed records are laid out as the reader
            // takes them, and supply only the archived closure.
            let participantCeremony: string | undefined;
            let run: ResearchRun;
            if (summary.scriptName === 'research:participant') {
                assert.equal(
                    selected.name,
                    'archived-records',
                    'A browser participant run supplies only its archived records.',
                );
                participantCeremony = path.resolve(
                    'temp',
                    'participant-ceremony-' +
                        path.basename(log.runDirectoryPath),
                );
                const participant = await layParticipantCeremony(
                    source,
                    participantCeremony,
                );
                run = {
                    case: 'browser-' + participant.result.kind,
                    participantCount: participant.participantCount,
                    optionCount: participant.optionCount,
                    output: participantCeremony,
                    result:
                        participant.result.kind === 'result'
                            ? {
                                  kind: 'result',
                                  identifiers: [
                                      ...participant.result.identifiers,
                                  ],
                              }
                            : { kind: 'no-result' },
                };
            } else {
                run = JSON.parse(
                    await readFile(path.join(source, 'result.json'), 'utf8'),
                ) as ResearchRun;
                assert.match(
                    run.case,
                    /^native-(?:result|empty|invalid-only)$/u,
                );
            }
            const ceremony = run.output;
            assert.ok((await stat(path.join(ceremony, 'close'))).isDirectory());
            const scenario = deriveResearchScenario(
                run.participantCount,
                run.optionCount,
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
            const badRelease = releaseAuthors[0] + 1;
            // A bad extra vote takes the first corrupt position's file, since
            // every corrupt participant withholds its vote.
            const badVotes = scenario.corrupt.slice(0, 1);
            let directory: string;
            if (selected.name === 'available-records') {
                assert.equal(run.case, 'native-result');
                const original = path.join(ceremony, 'completion');
                directory = path.join(
                    log.runDirectoryPath,
                    'available-completion',
                );
                await mkdir(directory);
                // The native certificate has exactly the honest votes, so
                // every one is needed; the corrupt participants signed none.
                assert.equal(
                    scenario.signers.length,
                    scenario.certificateThreshold,
                );
                const files = [
                    'target.bin',
                    ...scenario.signers.map(
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
            } else if (selected.name === 'archived-records') {
                // Every record the owning verifiers depend on is archived
                // from the source run, then retrieved by a fresh reader.
                directory = path.join(ceremony, 'completion');
                assert.ok((await stat(directory)).isDirectory());
            } else {
                assert.ok(selected.completionDirectory);
                directory = path.resolve(selected.completionDirectory);
                assert.ok((await stat(directory)).isDirectory());
            }
            const scratch = path.resolve(
                'temp',
                'threshold-reader-' + path.basename(log.runDirectoryPath),
            );
            const workspace = path.resolve('crates/protocol-research'),
                environment = {
                    ...process.env,
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
                output = path.join(log.runDirectoryPath, 'verification');
            for (const file of [
                'crates/protocol-research/evaluation-target/src/public-completion-check.rs',
                'crates/protocol-research/evaluation-target/src/bin/check-target.rs',
                'tools/ci/protocol-public-archive.ts',
                'tools/ci/participant-public-ceremony.ts',
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
                assert.ok(samples > 0);
                return { exitCode, peakMemory, samples };
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
                assert.deepEqual(terminal.certificateAuthors, scenario.signers);
                assert.deepEqual(terminal.releaseAuthors, releaseAuthors);
                const withheld = scenario.corrupt.filter(
                    (position) => !badVotes.includes(position),
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
            let archive: Record<string, unknown> | undefined;
            if (selected.name === 'archived-records') {
                const { createPublicArchive } =
                    await import('#packages/sdk/dist/index.js');
                const context = String(report.pollIdentity);
                assert.match(context, /^[0-9a-f]{128}$/u);
                const dependencies = (
                    await readFile(
                        path.join(output, 'dependencies.txt'),
                        'utf8',
                    )
                )
                    .trimEnd()
                    .split('\n');
                const archiveScratch = path.resolve(
                    'temp',
                    'public-archive-' + path.basename(log.runDirectoryPath),
                );
                await mkdir(archiveScratch);
                // The needed submissions keep their index order under new
                // consecutive transport names; the index lists only them.
                const routes: ArchiveRoute[] = [];
                const lines: string[] = [];
                const submissionIndex = await readFile(
                    path.join(ceremony, 'close', 'submissions.txt'),
                    'utf8',
                );
                // A close that lists no submission has an empty index.
                for (const line of submissionIndex === ''
                    ? []
                    : submissionIndex.trimEnd().split(/\r?\n/u)) {
                    const [name, body] = line.split(' ');
                    assert.ok(body, 'Malformed submission index line.');
                    if (!dependencies.includes('ceremony/close/' + name))
                        continue;
                    const renamed = 'submission-' + lines.length + '.bin';
                    routes.push({
                        route: 'ceremony/close/' + renamed,
                        file: path.join(ceremony, 'close', name),
                    });
                    lines.push(renamed + ' ' + body);
                }
                const index = path.join(archiveScratch, 'submissions.txt');
                await writeFile(
                    index,
                    lines.map((line) => line + '\n').join(''),
                    { flag: 'wx' },
                );
                for (const route of dependencies) {
                    if (/^ceremony\/close\/submission-\d+\.bin$/u.test(route))
                        continue;
                    const [root, ...parts] = route.split('/');
                    assert.ok(root === 'ceremony' || root === 'completion');
                    routes.push({
                        route,
                        file:
                            route === 'ceremony/close/submissions.txt'
                                ? index
                                : path.join(
                                      root === 'ceremony'
                                          ? ceremony
                                          : directory,
                                      ...parts,
                                  ),
                    });
                }
                assert.equal(
                    lines.length,
                    dependencies.filter((route) =>
                        /^ceremony\/close\/submission-\d+\.bin$/u.test(route),
                    ).length,
                );
                const kernel = new URL(
                    '../../packages/wasm/dist/sealed-lattice-kernel.wasm',
                    import.meta.url,
                );
                const runtime = await createFoundationCeremonyRuntimeLoader(
                    kernel,
                    {
                        expectedKernelSha256Hex: createHash('sha256')
                            .update(await readFile(kernel))
                            .digest('hex'),
                    },
                )();
                const keys = Array.from(
                    { length: 3 },
                    () => generateKeyPairSync('ml-dsa-65').privateKey,
                );
                const policy = {
                    faultBound: 1,
                    verificationKeys: keys.map((key) =>
                        createPublicKey(key)
                            .export({ format: 'der', type: 'spki' })
                            .subarray(-1952),
                    ),
                };
                const limits = {
                    maximumRecords: 65_536,
                    maximumTotalBytes: 4_294_967_291,
                };
                const replicas: Awaited<
                    ReturnType<typeof startPublicArchiveReplica>
                >[] = [];
                let shutdown: PromiseSettledResult<void>[] = [];
                try {
                    for (let position = 0; position < keys.length; position++)
                        replicas.push(
                            await startPublicArchiveReplica({
                                directory: path.join(
                                    archiveScratch,
                                    'replica-' + position,
                                ),
                                context,
                                policy,
                                replicaPosition: position,
                                privateKey: keys[position],
                                runtime,
                                ...limits,
                            }),
                        );
                    const configuration = (archiveContext: string) => ({
                        context: archiveContext,
                        faultBound: policy.faultBound,
                        replicas: replicas.map((replica, position) => ({
                            baseUrl: replica.baseUrl,
                            verificationKey: policy.verificationKeys[position],
                        })),
                        ...limits,
                    });
                    const publisher = await createPublicArchive(
                        configuration(context),
                    );
                    const sourceStore = await directoryArchiveStore(
                        path.join(archiveScratch, 'source'),
                    );
                    const target = await readFile(
                        path.join(output, 'target.bin'),
                    );
                    const encoded = await encodeArchiveRoutes(
                        publisher,
                        routes,
                        target,
                        sourceStore,
                    );
                    assert.ok(
                        encoded.records <= limits.maximumRecords &&
                            encoded.byteLength <= limits.maximumTotalBytes,
                        'The closure exceeds the archive retrieval bounds.',
                    );
                    const acknowledged = await publisher.publish(
                        encoded.root,
                        sourceStore,
                    );
                    assert.ok(acknowledged.length > policy.faultBound);
                    // Readers have only the replicas, and one acknowledging
                    // replica is gone.
                    const unavailableReplica = acknowledged[0];
                    await replicas[unavailableReplica].close();
                    // A reader bound to another poll refuses every record.
                    const otherContext =
                        context.slice(0, -1) +
                        (context.endsWith('0') ? '1' : '0');
                    await assert.rejects(
                        (
                            await createPublicArchive(
                                configuration(otherContext),
                            )
                        ).retrieve(
                            encoded.root,
                            await directoryArchiveStore(
                                path.join(archiveScratch, 'other-context'),
                            ),
                        ),
                    );
                    const reader = await createPublicArchive(
                        configuration(context),
                    );
                    const retrievedStore = await directoryArchiveStore(
                        path.join(archiveScratch, 'retrieved'),
                    );
                    const retrieved = await reader.retrieve(
                        encoded.root,
                        retrievedStore,
                    );
                    assert.equal(retrieved.recordCount, encoded.records);
                    assert.equal(retrieved.byteLength, encoded.byteLength);
                    const materialize = async (name: string) => {
                        const directoryPath = path.join(archiveScratch, name);
                        const materialized = await materializeArchiveRoutes(
                            reader,
                            encoded.root,
                            retrievedStore,
                            directoryPath,
                        );
                        assert.deepEqual(
                            materialized.routes,
                            routes.map((value) => value.route).sort(),
                        );
                        assert.deepEqual(
                            Buffer.from(materialized.payload),
                            target,
                        );
                        return directoryPath;
                    };
                    // The owning verifiers accept the retrieved files and
                    // depend on every one of them.
                    const reconstruction = await materialize('reconstruction');
                    const archivedOutput = path.join(
                        log.runDirectoryPath,
                        'verification-archived',
                    );
                    const archived = await verifyRecords(
                        path.join(reconstruction, 'ceremony'),
                        path.join(reconstruction, 'completion'),
                        archivedOutput,
                        scratch + '-archived',
                        'verification-archived',
                    );
                    assert.equal(archived.exitCode, 0);
                    assert.deepEqual(
                        (
                            await readFile(
                                path.join(archivedOutput, 'dependencies.txt'),
                                'utf8',
                            )
                        )
                            .trimEnd()
                            .split('\n'),
                        routes.map((value) => value.route).sort(),
                    );
                    assert.deepEqual(
                        await readFile(path.join(archivedOutput, 'target.bin')),
                        target,
                    );
                    const archivedReport = JSON.parse(
                        await readFile(
                            path.join(archivedOutput, 'result.json'),
                            'utf8',
                        ),
                    ) as Record<string, unknown>;
                    assert.equal(archivedReport.pollIdentity, context);
                    const archivedTerminal = JSON.parse(
                        await readFile(
                            path.join(archivedOutput, 'terminal.json'),
                            'utf8',
                        ),
                    ) as TerminalResult;
                    assert.equal(archivedTerminal.kind, verified.kind);
                    assert.deepEqual(
                        archivedTerminal.identifiers,
                        (verified as TerminalResult).identifiers,
                    );
                    // A closure without one usable body is refused.
                    const omittedRoute = lines
                        .map((line) => 'ceremony/' + line.split(' ')[1])
                        .find((route) =>
                            routes.some((value) => value.route === route),
                        );
                    let omittedExitCode: number | undefined;
                    if (omittedRoute !== undefined) {
                        const omitted = await materialize('omitted');
                        await rm(
                            path.join(omitted, ...omittedRoute.split('/')),
                        );
                        omittedExitCode = (
                            await verifyRecords(
                                path.join(omitted, 'ceremony'),
                                path.join(omitted, 'completion'),
                                path.join(
                                    log.runDirectoryPath,
                                    'verification-omitted',
                                ),
                                scratch + '-omitted',
                                'verification-omitted',
                            )
                        ).exitCode;
                        assert.notEqual(omittedExitCode, 0);
                    }
                    archive = {
                        context,
                        routes: routes.length,
                        records: encoded.records,
                        byteLength: encoded.byteLength,
                        root: encoded.root,
                        acknowledged,
                        unavailableReplica,
                        retrieved,
                        archivedPeakMemory: archived.peakMemory,
                        omittedRoute,
                        omittedExitCode,
                    };
                } finally {
                    shutdown = await Promise.allSettled(
                        replicas.map((replica) => replica.close()),
                    );
                }
                assert.ok(
                    shutdown.every((value) => value.status === 'fulfilled'),
                    'Replica shutdown failed.',
                );
                await rm(archiveScratch, { recursive: true });
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
                        certificateRecordsDirectory: path.join(
                            output,
                            'certificate-records',
                        ),
                        [selected.stage]: verified,
                        peakMemory,
                        samples,
                        archive,
                        executableSha512: createHash('sha512')
                            .update(await readFile(executable))
                            .digest('hex'),
                        scope:
                            selected.name === 'available-records'
                                ? 'Actual original signatures and proofs with missing files and corrupted extras. Public setup and target are recomputed. This tests threshold-driven retrieval after generation; it does not simulate authors leaving before generating their shares.'
                                : selected.name === 'archived-records'
                                  ? (participantCeremony === undefined
                                        ? ''
                                        : "A browser cohort's relayed records are laid out as the native reader takes them in a scratch directory. ") +
                                    'The records the owning verifiers depend on are published through the maintained public archive to three local replicas, retrieved by a fresh native reader after the source and one acknowledging replica are gone, and verified again from only the retrieved files, which the verifiers depend on exactly. A reader bound to another poll refuses the closure and a closure without one usable body is refused. Local replicas on one host do not establish independent fault domains, and no browser reader ' +
                                    (participantCeremony === undefined
                                        ? 'or departure chronology is exercised.'
                                        : "is exercised; only the source cohort's own departures precede the archive.")
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
            if (participantCeremony !== undefined)
                await rm(participantCeremony, { recursive: true });
            process.stdout.write(log.runDirectoryPath + '\n');
        } finally {
            await releaseLock();
        }
    },
);
