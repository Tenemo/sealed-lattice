import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { open, readFile, readdir, stat, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

import {
    createTranscriptRecorder,
    openTranscriptSource,
} from '#packages/sdk/src/participant/worker/transcript.js';
import { openPublicArchive } from '#packages/sdk/src/public-archive.js';
import { createTranscriptFileEncoder } from '#packages/sdk/src/transcript-archive.js';
import { createFoundationCeremonyRuntimeLoader } from '#packages/wasm/src/index.js';
import { startPublicArchiveReplica } from '#tools/archive/public-archive-replica.js';
import {
    runArtifactDirectoryPath,
    runWithLocalRunLog,
} from '#tools/ci/local-run-log.js';
import {
    emptyParticipantTransfer,
    observeParticipantTransfer,
} from '#tools/ci/participant-transfer.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';

// A storage-only experiment over complete public files from a passed cohort.
// It does not restore private authority or assert protocol verification. The
// same recorder, encodings, acknowledgements and cold reader run in both modes.
const [mode, sourceArgument, ...extra] = process.argv.slice(2);
assert.ok(
    (mode === 'upload' || mode === 'prepopulate' || mode === 'reuse') &&
        sourceArgument?.trim() &&
        extra.length === 0,
    'Select upload, prepopulate or reuse and a passed participant run.',
);
const source = path.resolve(sourceArgument);
const limits = { maximumRecords: 4096, maximumTotalBytes: 256 << 20 };
const memoryLimit = 1_073_741_824;
const sha512 = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');

await runWithLocalRunLog(
    {
        scriptName: 'measure:archive-transfer',
        commandLineArguments: [mode, source],
        lanes: ['Public archive transfer experiment'],
        resourceSampleIntervalMilliseconds: 1000,
    },
    async (log) => {
        const unlock = await acquireProtocolResearchLock(
            log.runDirectoryPath,
            path.resolve('.'),
        );
        const hosts: Awaited<ReturnType<typeof startPublicArchiveReplica>>[] =
            [];
        const controller = new AbortController();
        const timer = setTimeout(
            () =>
                controller.abort(
                    new Error('Archive experiment exceeded its deadline.'),
                ),
            600_000,
        );
        let peakProcessTreeBytes = 0;
        let memoryFailure: Error | undefined;
        let monitoring = false;
        const monitor = setInterval(() => {
            if (monitoring) return;
            monitoring = true;
            void readProtocolProcessTree(process.pid)
                .then((bytes) => {
                    if (bytes === undefined) return;
                    peakProcessTreeBytes = Math.max(
                        peakProcessTreeBytes,
                        bytes,
                    );
                    log.writeEvent({
                        eventType: 'archive-memory',
                        details: { bytes, limit: memoryLimit },
                    });
                    if (bytes > memoryLimit)
                        throw new Error(
                            'Archive experiment memory guard exceeded.',
                        );
                })
                .catch((error: unknown) => {
                    memoryFailure =
                        error instanceof Error
                            ? error
                            : new Error(String(error));
                    controller.abort(error);
                })
                .finally(() => {
                    monitoring = false;
                });
        }, 1000);
        try {
            assert.equal(
                (
                    JSON.parse(
                        await readFile(
                            path.join(source, 'summary.json'),
                            'utf8',
                        ),
                    ) as { exitCode: number }
                ).exitCode,
                0,
            );
            const cohort = JSON.parse(
                await readFile(path.join(source, 'result.json'), 'utf8'),
            ) as {
                poll: string;
                recordIds: string[];
                runtimeIdentity: unknown;
            };
            const publicDirectory = path.join(
                runArtifactDirectoryPath(source),
                'public',
            );
            const directories = [
                'registration/' + cohort.recordIds[0],
                'ballot-0',
            ];
            const routes: string[] = [
                'poll-definition.bin',
                'poll-signature.bin',
                'contribution-0/polynomial-01.bin',
            ];
            const visit = async (directory: string) => {
                for (const entry of await readdir(
                    path.join(publicDirectory, directory),
                    { withFileTypes: true },
                )) {
                    const route = directory + '/' + entry.name;
                    if (entry.isDirectory()) await visit(route);
                    else routes.push(route);
                }
            };
            for (const directory of directories) await visit(directory);
            routes.sort();
            let sourceBytes = 0;
            for (const route of routes)
                sourceBytes += (await stat(path.join(publicDirectory, route)))
                    .size;
            assert.ok(
                routes.length > 3 &&
                    sourceBytes > 0 &&
                    sourceBytes <= limits.maximumTotalBytes / 2,
            );
            const kernel = path.resolve(
                'packages/wasm/dist/sealed-lattice-kernel.wasm',
            );
            const kernelDigest = createHash('sha256')
                .update(await readFile(kernel))
                .digest('hex');
            const runtime = await createFoundationCeremonyRuntimeLoader(
                pathToFileURL(kernel),
                {
                    expectedKernelSha256Hex: kernelDigest,
                },
            )();
            const keys = Array.from(
                { length: 3 },
                () => generateKeyPairSync('ml-dsa-65').privateKey,
            );
            const verificationKeys = keys.map((key) =>
                createPublicKey(key)
                    .export({ type: 'spki', format: 'der' })
                    .subarray(-1952),
            );
            const policy = { faultBound: 1, verificationKeys };
            let activeTransfer = emptyParticipantTransfer();
            for (const [replicaPosition, privateKey] of keys.entries())
                hosts.push(
                    await startPublicArchiveReplica({
                        directory: path.join(
                            log.artifactDirectoryPath,
                            'replica-' + String(replicaPosition),
                        ),
                        context: cohort.poll,
                        policy,
                        replicaPosition,
                        privateKey,
                        runtime,
                        ...limits,
                        maximumStoredRecords: limits.maximumRecords,
                        maximumStoredBytes: limits.maximumTotalBytes,
                        observeRequest: (request, response) =>
                            observeParticipantTransfer(
                                request,
                                response,
                                activeTransfer,
                            ),
                    }),
                );
            const replicas = hosts.map((host, index) => ({
                baseUrl: host.baseUrl,
                verificationKey: verificationKeys[index],
            }));
            const makeArchive = () =>
                openPublicArchive(runtime, {
                    context: cohort.poll,
                    ...policy,
                    replicas,
                    ...limits,
                });
            const opened = {
                faultBound: 1,
                archive: makeArchive(),
                replicas: replicas.map((replica) =>
                    openPublicArchive(runtime, {
                        context: cohort.poll,
                        faultBound: 0,
                        replicas: [replica],
                        ...limits,
                    }),
                ),
            };
            const sourceHashes = new Map<string, string>();
            const stream = async (
                route: string,
                consume: (bytes: Uint8Array) => Promise<void>,
            ) => {
                const handle = await open(
                    path.join(publicDirectory, route),
                    'r',
                );
                const hash = createHash('sha512');
                try {
                    const buffer = Buffer.alloc(1 << 20);
                    for (;;) {
                        controller.signal.throwIfAborted();
                        const { bytesRead } = await handle.read(buffer);
                        if (bytesRead === 0) break;
                        const bytes = buffer.subarray(0, bytesRead);
                        hash.update(bytes);
                        await consume(bytes);
                    }
                } finally {
                    await handle.close();
                }
                const digest = hash.digest('hex');
                const expected = sourceHashes.get(route);
                if (expected !== undefined) assert.equal(digest, expected);
                sourceHashes.set(route, digest);
            };
            const serviceStart = performance.now();
            if (mode === 'prepopulate') {
                // The relay holds these public files already. It encodes and sends
                // bytes, without verifying proofs or producing any capability.
                for (const route of routes) {
                    const encoder = createTranscriptFileEncoder(
                        opened.archive,
                        route,
                        async (record) => {
                            await Promise.all(
                                opened.replicas.map((replica) =>
                                    replica.store(record, controller.signal),
                                ),
                            );
                        },
                    );
                    await stream(route, encoder.write);
                    await encoder.finish();
                }
            }
            const service = {
                milliseconds: performance.now() - serviceStart,
                transfers: activeTransfer,
            };
            activeTransfer = emptyParticipantTransfer();
            let priorPublication: Readonly<Record<string, unknown>> | undefined;
            let priorIndex;
            if (mode === 'reuse') {
                const priorStart = performance.now();
                const prior = createTranscriptRecorder(opened);
                for (const route of routes) {
                    const file = prior.open(route);
                    await stream(route, file.write);
                    await file.finish();
                }
                const archived = await prior.archive();
                priorIndex = archived.transcript;
                priorPublication = {
                    milliseconds: performance.now() - priorStart,
                    transfers: activeTransfer,
                    ...archived,
                };
                activeTransfer = emptyParticipantTransfer();
            }
            const start = performance.now();
            const recorder = createTranscriptRecorder(opened);
            if (priorIndex !== undefined) await recorder.reuse(priorIndex);
            else {
                for (const route of routes) {
                    const file = recorder.open(route);
                    await stream(route, file.write);
                    await file.finish();
                }
            }
            const archived = await recorder.archive();
            const publication = {
                milliseconds: performance.now() - start,
                transfers: activeTransfer,
                ...archived,
            };
            activeTransfer = emptyParticipantTransfer();
            const readStart = performance.now();
            const reader = await openTranscriptSource(
                { ...opened, archive: makeArchive() },
                archived.transcript,
            );
            for (const route of routes) {
                const hash = createHash('sha512');
                await reader.read(route, limits.maximumTotalBytes, (bytes) => {
                    hash.update(bytes);
                });
                assert.equal(hash.digest('hex'), sourceHashes.get(route));
            }
            const retrieval = {
                milliseconds: performance.now() - readStart,
                transfers: activeTransfer,
            };
            // Lose one replica and start another reader without a public cache.
            await hosts[0].close();
            activeTransfer = emptyParticipantTransfer();
            const recoveryStart = performance.now();
            const cold = await openTranscriptSource(
                { ...opened, archive: makeArchive() },
                archived.transcript,
            );
            for (const route of routes) {
                const hash = createHash('sha512');
                await cold.read(route, limits.maximumTotalBytes, (bytes) => {
                    hash.update(bytes);
                });
                assert.equal(hash.digest('hex'), sourceHashes.get(route));
            }
            const recovery = {
                milliseconds: performance.now() - recoveryStart,
                transfers: activeTransfer,
            };
            if (memoryFailure !== undefined) throw memoryFailure;
            const files = [
                'packages/sdk/src/public-archive.ts',
                'packages/sdk/src/transcript-archive.ts',
                'packages/sdk/src/participant/worker/transcript.ts',
                'tools/archive/public-archive-replica.ts',
                'tools/ci/measure-archive-transfer.ts',
            ];
            const result = {
                mode,
                source,
                sourceRuntime: cohort.runtimeIdentity,
                kernelDigest,
                sources: await Promise.all(
                    files.map(async (file) => ({
                        file,
                        sha512: sha512(await readFile(file)),
                    })),
                ),
                files: [...sourceHashes].map(([route, digest]) => ({
                    route,
                    sha512: digest,
                })),
                sourceBytes,
                service,
                priorPublication,
                publication,
                retrieval,
                recovery,
                peakProcessTreeBytes,
                memoryLimit,
                scope: 'Node scalar archive storage over complete unchanged public fixture files. No participant proof verification, browser measurement, productive visit or full workflow is measured. Server and client share this process tree. Service replication traffic remains charged separately; public-file source reads are local disk reads, not participant downloads. Cold readers match independent SHA-512 digests of every source file.',
                unmeasured: [
                    'Browser and worker memory',
                    'Transient memory peaks',
                    'HTTP headers and link overhead',
                    'Service-to-client source download time',
                    'Complete protocol execution',
                ],
            };
            await writeFile(
                path.join(log.runDirectoryPath, 'result.json'),
                JSON.stringify(result, null, 2) + '\n',
            );
            process.stdout.write(
                JSON.stringify({
                    mode,
                    sourceBytes,
                    service,
                    publication,
                    retrieval,
                    recovery,
                    peakProcessTreeBytes,
                }) + '\n',
            );
        } finally {
            clearInterval(monitor);
            clearTimeout(timer);
            controller.abort();
            for (const host of hosts) await host.close();
            await unlock();
        }
    },
);
