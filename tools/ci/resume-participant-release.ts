import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
import { createReadStream } from 'node:fs';
import {
    cp,
    mkdir,
    open,
    readFile,
    readdir,
    stat,
    writeFile,
} from 'node:fs/promises';
import { createServer, type Server } from 'node:http';
import { freemem } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

import { proposalRecordIds } from '#packages/sdk/src/participant/worker/roster.js';
import {
    evaluatedTargetName,
    namespacedName,
    setupCacheName,
} from '#packages/sdk/src/participant/worker/storage.js';
import { openPublicArchive } from '#packages/sdk/src/public-archive.js';
import { retrieveTranscript } from '#packages/sdk/src/transcript-archive.js';
import { createFoundationCeremonyRuntimeLoader } from '#packages/wasm/src/index.js';
import { startPublicArchiveReplica } from '#tools/archive/public-archive-replica.js';
import { participantRuntimeIdentity } from '#tools/ci/build-participant-module.js';
import {
    runArtifactDirectoryPath,
    runWithLocalRunLog,
} from '#tools/ci/local-run-log.js';
import {
    launchChromeParticipant,
    type ChromeParticipant,
} from '#tools/ci/participant-runtime-chrome.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { directoryArchiveStore } from '#tools/ci/protocol-public-archive.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';

// A bounded continuation of an existing action, not a replacement cohort.
// It opens only the original preserved profiles at their original origins,
// checks the archived runtime byte-for-byte and invokes no creation method.
// Replica keys may be renewed when repairing public custody; participant
// keys, seeds, roots and one-shot authority are never copied or migrated.
const arguments_ = process.argv.slice(2).filter((value) => value !== '--');
const [mode, sourceArgument] = arguments_;
assert.ok(
    arguments_.length === 2 &&
        (mode === 'inspect' || mode === 'release') &&
        sourceArgument?.trim(),
    'Select inspect or release and one preserved participant run.',
);
const source = path.resolve(sourceArgument);
const root = path.resolve('.');
const namespace = 'research-cohort';
const memoryLimit = 3_221_225_472;
const routePattern = /^(?:[a-z0-9][a-z0-9.-]*\/)*[a-z0-9][a-z0-9.-]*$/u;
const sha512 = (bytes: Uint8Array) =>
    createHash('sha512').update(bytes).digest('hex');

await runWithLocalRunLog(
    {
        scriptName: 'research:participant',
        commandLineArguments: ['resume-release', mode, source],
        lanes: ['Original-state release recovery and archive retrieval'],
    },
    async (log) => {
        const unlock = await acquireProtocolResearchLock(
            log.runDirectoryPath,
            root,
        );
        const servers: Server[] = [];
        const replicas: Awaited<
            ReturnType<typeof startPublicArchiveReplica>
        >[] = [];
        let browser: ChromeParticipant | undefined;
        let monitoring = true;
        let memoryFailure: Error | undefined;
        let serviceFailure: Error | undefined;
        let peakMemory = 0;
        const monitor = (async () => {
            while (monitoring) {
                if (browser !== undefined) {
                    const bytes = await readProtocolProcessTree(
                        browser.processIdentifier,
                    );
                    if (bytes !== undefined) {
                        peakMemory = Math.max(peakMemory, bytes);
                        log.writeEvent({
                            eventType: 'recovery-browser-memory',
                            details: {
                                bytes,
                                limit: memoryLimit,
                                heaps: browser.heaps(),
                                storage: browser.storage(),
                            },
                        });
                        if (bytes > memoryLimit) {
                            memoryFailure = new Error(
                                'Recovery browser memory guard exceeded.',
                            );
                            await browser.crash();
                        }
                    }
                }
                await delay(1000);
            }
        })().catch((error: unknown) => {
            memoryFailure =
                error instanceof Error ? error : new Error(String(error));
        });
        try {
            assert.ok(
                freemem() >= 3 * memoryLimit,
                'Insufficient host memory for bounded recovery.',
            );
            const metadata = JSON.parse(
                await readFile(path.join(source, 'metadata.json'), 'utf8'),
            ) as { commandLineArguments: string[] };
            const [participantCount, optionCount] =
                metadata.commandLineArguments.slice(0, 2).map(Number);
            assert.ok(
                Number.isInteger(participantCount) &&
                    participantCount >= 3 &&
                    participantCount <= 20 &&
                    Number.isInteger(optionCount) &&
                    optionCount >= 2 &&
                    optionCount <= 20,
            );
            const basePort = Number(
                metadata.commandLineArguments
                    .find((value) => value.startsWith('--base-port='))
                    ?.split('=')[1] ?? 43_600,
            );
            assert.ok(
                Number.isInteger(basePort) &&
                    basePort >= 1024 &&
                    basePort + participantCount <= 65535,
            );
            const events = (
                await readFile(path.join(source, 'events.jsonl'), 'utf8')
            )
                .trim()
                .split('\n')
                .map(
                    (line) =>
                        JSON.parse(line) as {
                            eventType: string;
                            details?: Record<string, unknown>;
                        },
                );
            const preserved = [...events]
                .reverse()
                .find(
                    (event) =>
                        event.eventType === 'participant-checkpoint-preserved',
                )?.details?.directory;
            assert.ok(
                typeof preserved === 'string',
                'The source run retained no private checkpoint.',
            );
            const profiles = path.resolve(preserved);
            assert.ok(
                profiles.startsWith(path.join(root, 'temp') + path.sep),
                'The checkpoint lies outside this repository.',
            );
            const original = runArtifactDirectoryPath(source);
            const sdk = await readFile(path.join(original, 'index.js'));
            const module = await readFile(
                path.join(original, 'participant.wasm'),
            );
            const worker = await readFile(path.join(original, 'worker.js'));
            const kernel = await readFile(
                path.join(original, 'sealed-lattice-kernel.wasm'),
            );
            const manifest = await readFile(
                path.join(source, 'source-manifest.json'),
            );
            const identity = participantRuntimeIdentity(
                manifest,
                module,
                worker,
            );
            for (const [file, bytes] of [
                ['index.js', sdk],
                ['participant.wasm', module],
                ['participant-worker.js', worker],
                ['sealed-lattice-kernel.wasm', kernel],
                ['participant-source-manifest.json', manifest],
            ] as const)
                assert.equal(
                    sha512(
                        await readFile(
                            path.join(root, 'packages/sdk/dist', file),
                        ),
                    ),
                    sha512(bytes),
                    'Recovery must use the original runtime: ' + file,
                );
            const publicDirectory = path.join(
                log.artifactDirectoryPath,
                'public',
            );
            await mkdir(log.artifactDirectoryPath, { recursive: true });
            await cp(path.join(original, 'public'), publicDirectory, {
                recursive: true,
                errorOnExist: true,
                force: false,
            });
            await writeFile(
                path.join(log.runDirectoryPath, 'source-manifest.json'),
                manifest,
                { flag: 'wx' },
            );
            const recordIds = proposalRecordIds(
                new Uint8Array(
                    await readFile(path.join(publicDirectory, 'proposal.bin')),
                ),
            );
            assert.equal(recordIds.length, participantCount);
            const created = events.find(
                (event) =>
                    event.eventType === 'participant-operation' &&
                    event.details?.operation === 'create' &&
                    event.details.position === 0,
            )?.details?.result as { details: { poll: string } };
            const poll = created.details.poll;
            assert.match(poll, /^[0-9a-f]{128}$/u);
            const survivors = (await readdir(profiles))
                .filter((name) => /^participant-\d+$/u.test(name))
                .map((name) => Number(name.slice('participant-'.length)))
                .filter((position) => position < participantCount)
                .sort((left, right) => left - right);
            assert.ok(
                survivors.length > 0,
                'The preserved cohort has no remaining profile.',
            );
            const runtime = await createFoundationCeremonyRuntimeLoader(
                pathToFileURL(
                    path.join(original, 'sealed-lattice-kernel.wasm'),
                ),
                {
                    expectedKernelSha256Hex: createHash('sha256')
                        .update(kernel)
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
            for (const [position, privateKey] of keys.entries()) {
                const directory = path.join(
                    log.artifactDirectoryPath,
                    'replicas',
                    String(position),
                );
                await cp(
                    path.join(profiles, 'archive', String(position)),
                    directory,
                    { recursive: true, errorOnExist: true, force: false },
                );
                replicas.push(
                    await startPublicArchiveReplica({
                        directory,
                        context: poll,
                        policy,
                        replicaPosition: position,
                        privateKey,
                        runtime,
                        ...limits,
                        maximumStoredRecords: 65_536,
                        maximumStoredBytes: 4_294_967_291,
                    }),
                );
            }
            const archive = {
                faultBound: 1,
                replicas: replicas.map((replica, position) => ({
                    baseUrl: replica.baseUrl,
                    verificationKey:
                        policy.verificationKeys[position].toString('hex'),
                })),
            };
            const withheld = new Set<number>();
            const page = `<!doctype html><meta charset="utf-8"><script type="module">
import {openParticipant} from '/sdk/index.js';
const archive = ${JSON.stringify(archive)};
window.runParticipant = (operation, parameters = {}) => openParticipant({namespace:${JSON.stringify(namespace)},relay:location.origin+'/',archive:{faultBound:archive.faultBound,replicas:archive.replicas.map((replica)=>({...replica,verificationKey:Uint8Array.from(replica.verificationKey.match(/../g),(part)=>parseInt(part,16))}))}}).run({operation,parameters});
</script>`;
            for (const position of survivors) {
                const origin = `http://127.0.0.1:${String(basePort + position)}`;
                const server = createServer((request, response) => {
                    void (async () => {
                        response.setHeader(
                            'Cross-Origin-Opener-Policy',
                            'same-origin',
                        );
                        response.setHeader(
                            'Cross-Origin-Embedder-Policy',
                            'require-corp',
                        );
                        const url = new URL(request.url ?? '/', origin);
                        const fixed = new Map<
                            string,
                            readonly [string, Buffer | string]
                        >([
                            ['/', ['text/html', page]],
                            ['/sdk/index.js', ['text/javascript', sdk]],
                            [
                                '/sdk/participant.wasm',
                                ['application/wasm', module],
                            ],
                            [
                                '/sdk/sealed-lattice-kernel.wasm',
                                ['application/wasm', kernel],
                            ],
                        ]).get(url.pathname);
                        if (request.method === 'GET' && fixed !== undefined) {
                            response
                                .writeHead(200, { 'Content-Type': fixed[0] })
                                .end(fixed[1]);
                            return;
                        }
                        const reading = url.pathname.startsWith('/public/');
                        const writing = url.pathname.startsWith('/publish/');
                        const name = url.pathname.slice(reading ? 8 : 9);
                        if (
                            (!reading && !writing) ||
                            !routePattern.test(name)
                        ) {
                            response.writeHead(404).end();
                            return;
                        }
                        const file = path.join(publicDirectory, name);
                        if (
                            reading &&
                            request.method === 'GET' &&
                            !withheld.has(position)
                        ) {
                            const info = await stat(file);
                            response.writeHead(200, {
                                'Content-Type': 'application/octet-stream',
                                'Content-Length': info.size,
                                'Cache-Control': 'no-store',
                            });
                            createReadStream(file).pipe(response);
                            return;
                        }
                        if (
                            writing &&
                            request.method === 'POST' &&
                            request.headers.origin === origin
                        ) {
                            const offset = Number(
                                url.searchParams.get('offset'),
                            );
                            assert.ok(
                                Number.isSafeInteger(offset) && offset >= 0,
                            );
                            const chunks: Buffer[] = [];
                            let length = 0;
                            for await (const chunk of request as AsyncIterable<Buffer>) {
                                length += chunk.length;
                                assert.ok(length <= 1 << 20);
                                chunks.push(chunk);
                            }
                            const bytes = Buffer.concat(chunks);
                            await mkdir(path.dirname(file), {
                                recursive: true,
                            });
                            const existing = await stat(file).catch(
                                (error: NodeJS.ErrnoException) => {
                                    if (error.code === 'ENOENT')
                                        return undefined;
                                    throw error;
                                },
                            );
                            assert.ok(
                                offset <= (existing?.size ?? 0),
                                'A publication skipped bytes.',
                            );
                            if (offset < (existing?.size ?? 0)) {
                                const input = await open(file, 'r');
                                try {
                                    const found = Buffer.alloc(bytes.length);
                                    const { bytesRead } = await input.read(
                                        found,
                                        0,
                                        found.length,
                                        offset,
                                    );
                                    assert.equal(bytesRead, bytes.length);
                                    assert.ok(
                                        found.equals(bytes),
                                        'A publication changed retained bytes.',
                                    );
                                } finally {
                                    await input.close();
                                }
                            } else {
                                const output = await open(
                                    file,
                                    existing === undefined ? 'wx' : 'a',
                                );
                                try {
                                    await output.writeFile(bytes);
                                    await output.sync();
                                } finally {
                                    await output.close();
                                }
                            }
                            response.writeHead(200).end();
                            return;
                        }
                        response.writeHead(404).end();
                    })().catch((error: unknown) => {
                        const missing =
                            error instanceof Error &&
                            (error as NodeJS.ErrnoException).code === 'ENOENT';
                        if (!missing) {
                            serviceFailure =
                                error instanceof Error
                                    ? error
                                    : new Error(String(error));
                            log.writeEvent({
                                eventType: 'recovery-service-failure',
                                details: { message: serviceFailure.message },
                            });
                        }
                        if (!response.headersSent)
                            response.writeHead(missing ? 404 : 500);
                        response.end();
                    });
                });
                await new Promise<void>((resolve, reject) => {
                    server.once('error', reject);
                    server.listen(basePort + position, '127.0.0.1', resolve);
                });
                servers.push(server);
            }
            const run = async (
                position: number,
                operation: string,
                parameters = {},
            ) => {
                const started = performance.now();
                const deadline = new AbortController();
                const result = (await Promise.race([
                    browser!.evaluate(
                        `window.runParticipant(${JSON.stringify(operation)},${JSON.stringify(parameters)})`,
                    ),
                    delay(3_600_000, undefined, {
                        signal: deadline.signal,
                    }).then(() => {
                        throw new Error('Recovery operation deadline.');
                    }),
                ]).finally(() => deadline.abort())) as {
                    status: string;
                    reason?: string;
                    details?: Record<string, unknown>;
                };
                if (memoryFailure !== undefined) throw memoryFailure;
                if (serviceFailure !== undefined) throw serviceFailure;
                log.writeEvent({
                    eventType: 'participant-operation',
                    details: {
                        position,
                        operation,
                        milliseconds: performance.now() - started,
                        recovery: true,
                        result,
                    },
                });
                assert.equal(
                    result.status,
                    'completed',
                    JSON.stringify(result),
                );
                return result.details!;
            };
            const inBrowser = async (
                position: number,
                action: () => Promise<void>,
            ) => {
                browser = await launchChromeParticipant(
                    path.join(profiles, 'participant-' + String(position)),
                    `http://127.0.0.1:${String(basePort + position)}`,
                );
                try {
                    await action();
                } finally {
                    await browser.crash();
                    browser = undefined;
                }
            };
            const restored: Record<string, unknown> = {};
            let independentClosure:
                { identity: string; byteLength: number } | undefined;
            for (const position of survivors)
                await inBrowser(position, async () => {
                    const state = await run(position, 'status');
                    assert.equal(
                        state.poll,
                        poll,
                        'The profile belongs to another action.',
                    );
                    restored[position] = state;
                    if (mode === 'release') {
                        assert.ok(
                            typeof state.generation === 'number' &&
                                state.generation >= 21,
                            'No completed close awaits release recovery.',
                        );
                        if (independentClosure === undefined) {
                            const hints = (await run(position, 'transcripts'))
                                .transcripts as {
                                identity: string;
                                byteLength: number;
                            }[];
                            assert.ok(
                                hints.length > 0,
                                'The interrupted release retained no certified archive.',
                            );
                            independentClosure = hints[0];
                        }
                        const released = await run(position, 'release');
                        assert.equal(released.generation, 29);
                    }
                });
            if (mode === 'inspect') {
                await writeFile(
                    path.join(log.runDirectoryPath, 'inspection.json'),
                    JSON.stringify(
                        { source, profiles, identity, restored },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
                return;
            }
            const combining = survivors[survivors.length - 1];
            let result!: Record<string, unknown>;
            let archived!: Record<string, unknown>;
            await inBrowser(combining, async () => {
                result = await run(combining, 'result');
                archived = await run(combining, 'archive');
                assert.deepEqual(archived.identifiers, result.identifiers);
            });
            const transcript = archived.transcript as {
                identity: string;
                byteLength: number;
            };
            assert.equal(result.encrypted, true);
            assert.ok(independentClosure !== undefined);
            await replicas[0].close();
            const reader = survivors[0];
            withheld.add(reader);
            await inBrowser(reader, async () => {
                const names = [setupCacheName, evaluatedTargetName].map(
                    (name) => namespacedName(name, namespace),
                );
                await browser!.evaluate(
                    `Promise.all(${JSON.stringify(names)}.map((name)=>new Promise((resolve,reject)=>{const deletion=indexedDB.deleteDatabase(name);deletion.onsuccess=()=>resolve(undefined);deletion.onerror=()=>reject(deletion.error);})))`,
                );
                const retrieved = await run(reader, 'result', { transcript });
                assert.deepEqual(retrieved.identifiers, result.identifiers);
            });
            for (const server of servers) {
                server.closeAllConnections();
                await new Promise<void>((resolve) =>
                    server.close(() => resolve()),
                );
            }
            const readerArchive = openPublicArchive(runtime, {
                context: poll,
                ...limits,
                faultBound: 1,
                replicas: replicas.map((replica, position) => ({
                    baseUrl: replica.baseUrl,
                    verificationKey: policy.verificationKeys[position],
                })),
            });
            for (const [stage, index] of [
                ['closure', independentClosure],
                ['terminal', transcript],
            ] as const)
                await retrieveTranscript(
                    readerArchive,
                    index,
                    await directoryArchiveStore(
                        path.join(
                            log.artifactDirectoryPath,
                            'archived-' + stage,
                        ),
                    ),
                );
            await writeFile(
                path.join(log.runDirectoryPath, 'result.json'),
                JSON.stringify(
                    {
                        continuationOf: source,
                        participantCount,
                        optionCount,
                        poll,
                        recordIds,
                        runtimeIdentity: identity.runtime,
                        restored,
                        peakProcessTreeBytes: peakMemory,
                        result: {
                            kind: 'result',
                            identifiers: result.identifiers,
                        },
                        archive: {
                            transcript,
                            independentClosure,
                            verificationKeys: policy.verificationKeys.map(
                                (key) => key.toString('hex'),
                            ),
                            unavailableReplica: 0,
                            sourceServiceUnavailable: true,
                        },
                        scope: 'The original surviving participant profiles resumed their release suffix under the identical archived runtime. No participant was created or private authority moved. The published target predates this run. The terminal archive is retrieved after source shutdown and one replica loss; the reader first lost its public caches. Earlier cohort faults retain their own scope and diagnostic run.',
                    },
                    null,
                    2,
                ) + '\n',
                { flag: 'wx' },
            );
            process.stdout.write(log.runDirectoryPath + '\n');
        } finally {
            monitoring = false;
            await monitor;
            if (browser !== undefined) await browser.crash();
            for (const replica of replicas) await replica.close();
            for (const server of servers) {
                server.closeAllConnections();
                await new Promise<void>((resolve) =>
                    server.close(() => resolve()),
                );
            }
            await unlock();
        }
    },
);
