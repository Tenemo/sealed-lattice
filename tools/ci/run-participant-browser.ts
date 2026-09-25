import assert from 'node:assert/strict';
import {
    mkdir,
    mkdtemp,
    open,
    readFile,
    rm,
    stat,
    writeFile,
} from 'node:fs/promises';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { freemem } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import type { WorkerResult } from '#tools/ci/participant-runtime/worker.js';
import {
    assembleParticipantRuntime,
    deriveParticipantDescriptor,
} from '#tools/ci/participant-runtime-assembly.js';
import type { ParticipantRuntime } from '#tools/ci/participant-runtime-assembly.js';
import { launchChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import type { ChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';

// Runs a browser cohort of the selected profile through the maintained
// participant runtime: each participant is its own origin with its own
// external Chrome profile, and a local relay only stores and serves the
// public records the participants publish.
const counts = process.argv.slice(2).filter((value) => value !== '--');
assert.ok(
    counts.length === 0 ||
        (counts.length === 2 &&
            counts.every((value) => /^[1-9]\d*$/u.test(value))),
    'Optionally select the participant and option counts.',
);
const [participantCount, optionCount] =
    counts.length === 0 ? [3, 2] : counts.map(Number);
const root = path.resolve('.');
const basePort = 43_600;
// The host guard for each participant's Chrome process tree.
const participantMemoryLimit = 3_221_225_472;
const operationMilliseconds = 3_600_000;

// The relay's layout: lower-case path segments of letters, digits, dots and
// hyphens, with no traversal.
const publicPath = /^(?:[a-z0-9][a-z0-9.-]*\/)*[a-z0-9][a-z0-9.-]*$/u;

type Relay = Readonly<{
    servers: Server[];
    // The origin that first published each path; only it may add to it.
    owners: Map<string, string>;
}>;

const readBody = async (request: IncomingMessage, maximum: number) => {
    const parts: Buffer[] = [];
    let length = 0;
    for await (const chunk of request as AsyncIterable<Buffer>) {
        length += chunk.length;
        if (length > maximum)
            throw new Error('A publication exceeds its bound.');
        parts.push(chunk);
    }
    return Buffer.concat(parts);
};

const page = (runtime: ParticipantRuntime) =>
    `<!doctype html><meta charset="utf-8"><title>Participant</title><script>
const runtime = ${JSON.stringify({ descriptor: runtime.descriptor, identity: runtime.identity })};
window.runParticipant = async (operation, parameters) => {
    const response = await fetch('/worker.js', { cache: 'no-store' });
    const bytes = new Uint8Array(await response.arrayBuffer());
    const digest = Array.from(
        new Uint8Array(await crypto.subtle.digest('SHA-512', bytes)),
        (value) => value.toString(16).padStart(2, '0'),
    ).join('');
    if (digest !== runtime.identity.worker) throw new Error('The worker changed.');
    const url = URL.createObjectURL(new Blob([bytes], { type: 'text/javascript' }));
    const worker = new Worker(url, { type: 'module' });
    return new Promise((resolve, reject) => {
        const finish = () => {
            worker.terminate();
            URL.revokeObjectURL(url);
        };
        worker.onmessage = ({ data }) => {
            finish();
            resolve(data);
        };
        worker.onerror = (event) => {
            finish();
            reject(new Error(event.message || 'The participant worker failed.'));
        };
        worker.postMessage({
            operation,
            origin: location.origin,
            descriptor: runtime.descriptor,
            identity: runtime.identity,
            parameters,
        });
    });
};
</script>`;

const startRelay = async (
    runtime: ParticipantRuntime,
    publicDirectory: string,
): Promise<Relay> => {
    const owners = new Map<string, string>();
    const html = page(runtime);
    const handle = async (
        origin: string,
        request: IncomingMessage,
        response: ServerResponse,
    ) => {
        const url = new URL(request.url ?? '/', origin);
        if (request.method === 'GET') {
            const asset =
                url.pathname === '/'
                    ? { type: 'text/html', bytes: Buffer.from(html) }
                    : url.pathname === '/worker.js'
                      ? { type: 'text/javascript', bytes: runtime.worker }
                      : url.pathname === '/participant.wasm'
                        ? { type: 'application/wasm', bytes: runtime.module }
                        : undefined;
            if (asset !== undefined) {
                response.writeHead(200, {
                    'Content-Type': asset.type,
                    'Cache-Control': 'no-store',
                });
                response.end(asset.bytes);
                return;
            }
            const name = url.pathname.slice('/public/'.length);
            if (url.pathname.startsWith('/public/') && publicPath.test(name)) {
                const file = path.join(publicDirectory, name);
                const bytes = await readFile(file).catch(() => undefined);
                if (bytes !== undefined) {
                    response.writeHead(200, {
                        'Content-Type': 'application/octet-stream',
                        'Cache-Control': 'no-store',
                    });
                    response.end(bytes);
                    return;
                }
            }
        }
        const name = url.pathname.slice('/publish/'.length);
        const offset = Number(url.searchParams.get('offset'));
        if (
            request.method !== 'POST' ||
            request.headers.origin !== origin ||
            !url.pathname.startsWith('/publish/') ||
            !publicPath.test(name) ||
            !Number.isSafeInteger(offset) ||
            offset < 0 ||
            (owners.get(name) ?? origin) !== origin
        ) {
            response.writeHead(404);
            response.end();
            return;
        }
        const bytes = await readBody(request, 1 << 20);
        const file = path.join(publicDirectory, name);
        await mkdir(path.dirname(file), { recursive: true });
        const existing = await stat(file).catch(() => undefined);
        const length = existing?.size ?? 0;
        // A chunk extends the record at its end or repeats identical bytes.
        if (offset < length) {
            const handleFile = await open(file, 'r');
            try {
                const current = Buffer.alloc(bytes.length);
                const { bytesRead } = await handleFile.read(
                    current,
                    0,
                    bytes.length,
                    offset,
                );
                if (bytesRead !== bytes.length || !current.equals(bytes)) {
                    response.writeHead(409);
                    response.end();
                    return;
                }
            } finally {
                await handleFile.close();
            }
        } else if (offset === length) {
            await writeFile(file, bytes, { flag: 'a' });
            owners.set(name, origin);
        } else {
            response.writeHead(409);
            response.end();
            return;
        }
        response.writeHead(204);
        response.end();
    };
    const servers: Server[] = [];
    for (let position = 0; position < participantCount; position++) {
        const origin = `http://127.0.0.1:${String(basePort + position)}`;
        const server = createServer((request, response) => {
            handle(origin, request, response).catch(() => {
                response.writeHead(500);
                response.end();
            });
        });
        await new Promise<void>((resolve, reject) => {
            server.once('error', reject);
            server.listen(basePort + position, '127.0.0.1', () => resolve());
        });
        servers.push(server);
    }
    return { servers, owners };
};

await runWithLocalRunLog(
    {
        commandLineArguments: [String(participantCount), String(optionCount)],
        lanes: [
            'Participant runtime assembly',
            'Browser registration and roster agreement',
            'Browser setup contribution',
            'Browser setup verification',
            'Browser signed ballots',
            'Browser close responses',
            'Browser target votes',
        ],
        scriptName: 'research:participant',
    },
    async (log) => {
        const releaseLock = await acquireProtocolResearchLock(
            log.runDirectoryPath,
            root,
        );
        const chromes: (ChromeParticipant | undefined)[] = [];
        let relay: Relay | undefined;
        let sampling = true;
        let monitor: Promise<void> | undefined;
        // The participants' private state lives only as long as the run.
        let profiles: string | undefined;
        let guardFailure: Error | undefined;
        try {
            assert.ok(
                freemem() >= 2 * participantCount * participantMemoryLimit,
                'Insufficient host memory for the browser cohort.',
            );
            const descriptor = deriveParticipantDescriptor(
                participantCount,
                optionCount,
            );
            const runtime = await assembleParticipantRuntime(log, descriptor);
            const publicDirectory = path.join(log.runDirectoryPath, 'public');
            await mkdir(publicDirectory);
            relay = await startRelay(runtime, publicDirectory);
            profiles = await mkdtemp(
                path.join(root, 'temp/participant-browser-'),
            );
            const profileDirectory = profiles;
            const peaks = new Array<number>(participantCount).fill(0);
            monitor = (async () => {
                while (sampling) {
                    for (const [position, chrome] of chromes.entries()) {
                        if (chrome === undefined) continue;
                        const bytes = await readProtocolProcessTree(
                            chrome.processIdentifier,
                        );
                        if (bytes === undefined) continue;
                        peaks[position] = Math.max(peaks[position], bytes);
                        log.writeEvent({
                            eventType: 'participant-process-memory',
                            details: { position, bytes },
                        });
                        if (bytes > participantMemoryLimit)
                            guardFailure ??= new Error(
                                'Participant process-tree memory guard exceeded.',
                            );
                    }
                    await delay(2000);
                }
            })();
            const origin = (position: number) =>
                `http://127.0.0.1:${String(basePort + position)}`;
            const participant = async (position: number) => {
                const existing = chromes[position];
                if (existing !== undefined) return existing;
                const chrome = await launchChromeParticipant(
                    path.join(
                        profileDirectory,
                        `participant-${String(position)}`,
                    ),
                    origin(position),
                );
                chromes[position] = chrome;
                log.writeEvent({
                    eventType: 'participant-browser',
                    details: {
                        position,
                        version: chrome.version,
                        launchArguments: chrome.launchArguments,
                    },
                });
                return chrome;
            };
            const request = async (
                position: number,
                operation: string,
                parameters: Record<string, unknown> = {},
            ) => {
                const chrome = await participant(position);
                const started = performance.now();
                // The deadline ends with its operation so that no timer
                // outlives the run.
                const deadline = new AbortController();
                let result: WorkerResult;
                try {
                    result = (await Promise.race([
                        chrome.evaluate(
                            `window.runParticipant(${JSON.stringify(operation)}, ${JSON.stringify(parameters)})`,
                        ),
                        delay(operationMilliseconds, undefined, {
                            signal: deadline.signal,
                        }).then(() => {
                            throw new Error('Participant operation deadline.');
                        }),
                    ])) as WorkerResult;
                } finally {
                    deadline.abort();
                }
                if (guardFailure !== undefined) throw guardFailure;
                log.writeEvent({
                    eventType: 'participant-operation',
                    details: {
                        position,
                        operation,
                        milliseconds: performance.now() - started,
                        result,
                    },
                });
                return result;
            };
            const run = async (
                position: number,
                operation: string,
                parameters: Record<string, unknown> = {},
            ) => {
                const result = await request(position, operation, parameters);
                assert.ok(
                    result.status === 'completed',
                    `${operation} at position ${String(position)}: ${JSON.stringify(result)}`,
                );
                return result.details;
            };
            const expectStatus = async (
                position: number,
                operation: string,
                status: WorkerResult['status'],
                parameters: Record<string, unknown> = {},
            ) => {
                const result = await request(position, operation, parameters);
                assert.equal(
                    result.status,
                    status,
                    `${operation} at position ${String(position)}: ${JSON.stringify(result)}`,
                );
            };
            const positions = Array.from(
                { length: participantCount },
                (_unused, position) => position,
            );
            // Each participant scores every option differently, across the
            // descriptor's score range.
            const { minimumScore, maximumScore } = runtime.descriptor.ballot;
            const ballotScores = (position: number) =>
                Array.from(
                    { length: optionCount },
                    (_unused, option) =>
                        minimumScore +
                        ((position * (optionCount + 1) + option) %
                            (maximumScore - minimumScore + 1)),
                );
            const everyone = async (operation: string, generation: number) => {
                const results = await Promise.all(
                    positions.map((position) => run(position, operation)),
                );
                for (const details of results)
                    assert.equal(details.generation, generation);
            };
            const { createCanonicalManifest } =
                await import('#packages/sdk/dist/index.js');
            const manifest = await createCanonicalManifest({
                question: 'Verify the complete signed ballot path',
                options: Array.from(
                    { length: optionCount },
                    (_unused, index) => `Option ${String(index)}`,
                ),
            });
            const hexadecimal = (bytes: Uint8Array) =>
                Buffer.from(bytes).toString('hex');
            const organizer = await run(0, 'create', {
                role: 'creator',
                manifest: hexadecimal(manifest.canonicalBytes),
                topCount: optionCount,
                username: 'Organizer',
            });
            assert.equal(organizer.isOrganizer, true);
            await run(0, 'publish');
            const definition = await readFile(
                path.join(publicDirectory, 'poll-definition.bin'),
            );
            const definitionSignature = await readFile(
                path.join(publicDirectory, 'poll-signature.bin'),
            );
            const joined = await Promise.all(
                Array.from(
                    { length: participantCount - 1 },
                    async (_unused, index) => {
                        const position = index + 1;
                        const details = await run(position, 'create', {
                            role: 'join',
                            poll: organizer.poll,
                            definition: hexadecimal(definition),
                            definitionSignature:
                                hexadecimal(definitionSignature),
                            username: `Participant ${String(position)}`,
                        });
                        assert.equal(details.isOrganizer, false);
                        assert.equal(details.poll, organizer.poll);
                        await run(position, 'publish');
                        return details;
                    },
                ),
            );
            const recordIds = [organizer, ...joined].map((value) =>
                String(value.bodyDigest),
            );
            const proposed = await run(0, 'propose-roster', { recordIds });
            assert.equal(proposed.generation, 3);
            await run(0, 'publish');
            const accepted = await Promise.all(
                joined.map((_details, index) =>
                    run(index + 1, 'accept-roster', { recordIds }),
                ),
            );
            for (const details of accepted) assert.equal(details.generation, 3);
            // A second proposal, acceptance or enrollment is refused, and
            // every participant restores its retained state.
            await expectStatus(0, 'propose-roster', 'refused', { recordIds });
            await expectStatus(1, 'accept-roster', 'refused', { recordIds });
            await expectStatus(1, 'create', 'refused', {
                role: 'join',
                poll: organizer.poll,
                definition: hexadecimal(definition),
                definitionSignature: hexadecimal(definitionSignature),
                username: 'Participant again',
            });
            for (const position of positions) {
                const status = await run(position, 'status');
                assert.equal(status.generation, 3);
                assert.equal(status.poll, organizer.poll);
            }
            // Every participant generates and retains its contribution body
            // and confirms it. No opening precedes the complete confirmation
            // inventory.
            await everyone('contribute', 7);
            await expectStatus(0, 'contribute', 'refused');
            assert.equal((await run(0, 'confirm')).generation, 9);
            await expectStatus(0, 'open', 'pending');
            assert.equal((await run(0, 'status')).generation, 9);
            await Promise.all(
                positions.slice(1).map(async (position) => {
                    assert.equal(
                        (await run(position, 'confirm')).generation,
                        9,
                    );
                }),
            );
            await everyone('open', 11);
            // Every participant verifies the complete setup and retains its
            // reference once.
            // A ballot needs the verified setup.
            await expectStatus(0, 'ballot', 'refused', {
                scores: ballotScores(0),
            });
            await everyone('verify-setup', 12);
            await expectStatus(0, 'verify-setup', 'refused');
            // Every participant signs one ballot. A signed ballot refuses other
            // scores and is only delivered again.
            await Promise.all(
                positions.map(async (position) => {
                    assert.equal(
                        (
                            await run(position, 'ballot', {
                                scores: ballotScores(position),
                            })
                        ).generation,
                        17,
                    );
                }),
            );
            await expectStatus(0, 'ballot', 'refused', {
                scores: ballotScores(1),
            });
            assert.equal((await run(0, 'ballot')).generation, 17);
            const ballotBounds = runtime.descriptor.ballot;
            for (const position of positions) {
                const directory = path.join(
                    publicDirectory,
                    `ballot-${String(position)}`,
                );
                const envelope = await readFile(
                    path.join(directory, 'envelope.bin'),
                );
                const body = await stat(path.join(directory, 'body.bin'));
                assert.equal(envelope.length, ballotBounds.envelopeBytes);
                assert.equal(envelope.readBigUInt64LE(142), BigInt(body.size));
                assert.ok(
                    body.size >= ballotBounds.minimumBodyBytes &&
                        body.size <= ballotBounds.maximumBodyBytes,
                );
                assert.equal(
                    (await stat(path.join(directory, 'signature.bin'))).size,
                    runtime.descriptor.registration.signatureBytes,
                );
            }
            // The organizer's close time is the second-latest ballot time, so
            // a strictly later ballot is late: the intent lock retires it
            // wherever it was delivered, and no response lists it.
            const ballotTimes = await Promise.all(
                positions.map(async (position) =>
                    Number(
                        (
                            await readFile(
                                path.join(
                                    publicDirectory,
                                    `ballot-${String(position)}`,
                                    'envelope.bin',
                                ),
                            )
                        ).readBigUInt64LE(134),
                    ),
                ),
            );
            const closeTime = [...ballotTimes].sort(
                (left, right) => left - right,
            )[participantCount - 2];
            const onTime = (position: number) =>
                ballotTimes[position] <= closeTime;
            const others = (position: number) =>
                positions.filter((other) => other !== position);
            const submissions = (kind: string, authors: readonly number[]) =>
                authors.map((position) => ({ kind, position }));
            // Every other participant collects the published ballots, its own
            // first, before any intent exists.
            await Promise.all(
                positions.slice(1).map(async (position) => {
                    const details = await run(position, 'close', {
                        deliver: others(position),
                    });
                    assert.equal(details.generation, 17);
                    assert.deepEqual(details.closeEvents, [
                        ...submissions('own', [position]),
                        ...submissions('held', others(position)),
                    ]);
                }),
            );
            // The organizer learns one on-time envelope without its body,
            // opens the close and locks its own intent.
            const announced = others(0).find(onTime);
            assert.ok(announced !== undefined);
            const organizerDeliveries = others(0).filter(
                (position) => position !== announced,
            );
            await expectStatus(1, 'close', 'refused', { closeTime });
            const opened = await run(0, 'close', {
                deliver: organizerDeliveries,
                announce: [announced],
                closeTime,
            });
            assert.equal(opened.generation, 19);
            const organizerCollected = [
                ...submissions('own', [0].filter(onTime)),
                ...submissions('held', organizerDeliveries.filter(onTime)),
                ...submissions('known', [announced]),
            ];
            assert.deepEqual(opened.closeEvents, [
                ...organizerCollected,
                { kind: 'lock' },
            ]);
            await expectStatus(0, 'close', 'refused', { closeTime });
            // Every other participant locks the intent and responds at once.
            await Promise.all(
                positions.slice(1).map(async (position) => {
                    const details = await run(position, 'close');
                    assert.equal(details.generation, 21);
                    assert.deepEqual(details.closeEvents, [
                        ...submissions('own', [position].filter(onTime)),
                        ...submissions('held', others(position).filter(onTime)),
                        { kind: 'lock' },
                    ]);
                }),
            );
            // The organizer takes the other responses, fetches the body they
            // list that it lacks, responds and proposes.
            const concluded = await run(0, 'close');
            assert.equal(concluded.generation, 22);
            assert.deepEqual(concluded.closeEvents, [
                ...organizerCollected,
                { kind: 'lock' },
                ...submissions('response', others(0)),
                ...submissions('held', [announced]),
            ]);
            // Completed close work is only delivered again.
            assert.equal((await run(1, 'close')).generation, 21);
            assert.equal((await run(0, 'close')).generation, 22);
            const closeBounds = runtime.descriptor.close;
            const signatureBytes =
                runtime.descriptor.registration.signatureBytes;
            const closeDirectory = path.join(publicDirectory, 'close');
            const intent = await readFile(
                path.join(closeDirectory, 'intent.bin'),
            );
            assert.equal(
                intent.length,
                4 + closeBounds.intentBodyBytes + signatureBytes,
            );
            assert.equal(
                intent.readBigUInt64LE(4 + closeBounds.intentBodyBytes - 8),
                BigInt(closeTime),
            );
            for (const position of positions) {
                const response = await readFile(
                    path.join(
                        closeDirectory,
                        `response-${String(position)}.bin`,
                    ),
                );
                const length = response.readUInt32LE(0);
                assert.ok(
                    length >= closeBounds.minimumResponseBodyBytes &&
                        length <= closeBounds.maximumResponseBodyBytes,
                );
                assert.equal(response.length, 4 + length + signatureBytes);
                // The listing holds exactly the on-time ballots.
                const listed = [];
                for (
                    let offset = 4 + closeBounds.minimumResponseBodyBytes;
                    offset < 4 + length;
                    offset += 66
                )
                    listed.push(response.readUInt16LE(offset));
                assert.deepEqual(listed, positions.filter(onTime));
            }
            // The proposal names the organizer's response and the first other
            // responses it took, up to the close quorum.
            const proposal = await readFile(
                path.join(closeDirectory, 'proposal.bin'),
            );
            assert.equal(
                proposal.length,
                4 + closeBounds.proposalBodyBytes + signatureBytes,
            );
            const named = [];
            for (let index = 0; index < closeBounds.quorum; index++)
                named.push(
                    proposal.readUInt16LE(
                        4 +
                            closeBounds.proposalBodyBytes -
                            (closeBounds.quorum - index) * 66,
                    ),
                );
            assert.deepEqual(named, positions.slice(0, closeBounds.quorum));
            // Every participant verifies the barrier, classifies each usable
            // ballot, evaluates the target and signs its vote. Every on-time
            // ballot is usable and valid, and a late one is reported late.
            const onTimeCount = positions.filter(onTime).length;
            await Promise.all(
                positions.map(async (position) => {
                    const details = await run(position, 'target');
                    assert.equal(details.generation, 24);
                    assert.equal(
                        details.ballotStatus,
                        onTime(position) ? 'included' : 'late',
                    );
                    assert.equal(details.validBallots, onTimeCount);
                }),
            );
            // A signed vote is only delivered again.
            const repeated = await run(1, 'target');
            assert.equal(repeated.generation, 24);
            assert.equal(repeated.ballotStatus, undefined);
            const targetBounds = runtime.descriptor.target;
            const completionDirectory = path.join(
                publicDirectory,
                'completion',
            );
            const target = await readFile(
                path.join(completionDirectory, 'target.bin'),
            );
            assert.ok(
                target.length > 0 &&
                    target.length <= targetBounds.maximumBodyBytes,
            );
            // Every vote names its signer and one target identity.
            const targetIdentities = new Set<string>();
            for (const position of positions) {
                const vote = await readFile(
                    path.join(
                        completionDirectory,
                        `target-vote-${String(position)}.bin`,
                    ),
                );
                assert.equal(vote.length, targetBounds.votePacketBytes);
                assert.equal(vote.readUInt16LE(0), position);
                targetIdentities.add(vote.subarray(2, 66).toString('hex'));
            }
            assert.equal(targetIdentities.size, 1);
            await writeFile(
                path.join(log.runDirectoryPath, 'result.json'),
                JSON.stringify(
                    {
                        participantCount,
                        optionCount,
                        poll: organizer.poll,
                        recordIds,
                        runtimeIdentity: runtime.identity.runtime,
                        peakProcessTreeBytes: peaks,
                        closeTime,
                        lateBallots: positions.filter(
                            (position) => !onTime(position),
                        ),
                        scope: "Browser registration, roster agreement, setup contribution, setup verification, signed ballots, close responses with the organizer's proposal, and target evaluation and votes in the maintained participant runtime in external Chrome. Release and later protocol stages are not exercised.",
                    },
                    null,
                    2,
                ) + '\n',
                { flag: 'wx' },
            );
            process.stdout.write(log.runDirectoryPath + '\n');
        } finally {
            sampling = false;
            await monitor;
            for (const chrome of chromes)
                await chrome?.close().catch(() => undefined);
            for (const server of relay?.servers ?? [])
                await new Promise((resolve) => server.close(resolve));
            if (profiles !== undefined)
                await rm(profiles, { recursive: true, force: true });
            await releaseLock();
        }
    },
);
