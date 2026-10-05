import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    cp,
    mkdir,
    mkdtemp,
    open,
    readdir,
    readFile,
    rm,
    stat,
    writeFile,
} from 'node:fs/promises';
import { createServer } from 'node:http';
import type { IncomingMessage, Server, ServerResponse } from 'node:http';
import { availableParallelism, freemem } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { build } from 'tsdown';

import { tupleFields } from '#packages/sdk/src/participant/worker/bytes.js';
import {
    decodeCandidateManifest,
    decodeCandidatePage,
    decodeCandidateReceipt,
    encodeCandidateManifest,
} from '#packages/sdk/src/participant/worker/candidate-codec.js';
import { completedClosePhase } from '#packages/sdk/src/participant/worker/close-state.js';
import {
    closureBodyFile,
    closureSubmissionFile,
} from '#packages/sdk/src/participant/worker/close.js';
import { chunkBytes } from '#packages/sdk/src/participant/worker/root.js';
import {
    evaluatedTargetName,
    namespacedName,
    participantDatabaseName,
    setupCacheName,
} from '#packages/sdk/src/participant/worker/storage.js';
import { targetPhase } from '#packages/sdk/src/participant/worker/target-state.js';
import type { WorkerResult } from '#packages/sdk/src/participant/worker/worker.js';
import { compileOperationProofDraws } from '#tests/operation-seed-model.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import {
    encodeSetupSelectionModel,
    setupSelectionIdentityModel,
} from '#tests/setup-selection-wire-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { sampleFileAllocation } from '#tools/ci/file-allocation.js';
import {
    runArtifactDirectoryPath,
    runWithLocalRunLog,
} from '#tools/ci/local-run-log.js';
import { selectParticipantBrowserOptions } from '#tools/ci/participant-browser-options.js';
import { createBrowserPool } from '#tools/ci/participant-browser-pool.js';
import { serveParticipantCandidates } from '#tools/ci/participant-candidate-http.js';
import { participantCandidateView } from '#tools/ci/participant-candidate-view.js';
import type { ViewedParticipantRecord } from '#tools/ci/participant-candidate-view.js';
import { summarizeCpuTrace } from '#tools/ci/participant-cpu-profile.js';
import type { CpuProfileSummary } from '#tools/ci/participant-cpu-profile.js';
import {
    participantOfferAnnouncements,
    serveOfferAnnouncements,
} from '#tools/ci/participant-offer-announcements.js';
import {
    paddingHaltingClient,
    preparationHaltingClient,
    validatePaddingObservation,
} from '#tools/ci/participant-padding-halt.js';
import type {
    PaddingCut,
    PaddingHaltObservation,
    PaddingSlotObservation,
    PreparationCut,
} from '#tools/ci/participant-padding-halt.js';
import type {
    CheckpointCustodyObservation,
    SourceCustodyObservation,
} from '#tools/ci/participant-preparation-storage.js';
import { participantRelayStore } from '#tools/ci/participant-relay-record.js';
import { assembleParticipantRuntime } from '#tools/ci/participant-runtime-assembly.js';
import type {
    CorruptParticipantClient,
    ParticipantRuntime,
} from '#tools/ci/participant-runtime-assembly.js';
import { launchChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import type { ChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import {
    emptyParticipantTransfer,
    observeParticipantTransfer,
    type ParticipantTransfer,
} from '#tools/ci/participant-transfer.js';
import {
    summarizeParticipantWorkflow,
    type ParticipantBootstrapMeasurement,
    type ParticipantOperationMeasurement,
} from '#tools/ci/participant-workflow-measurements.js';
import {
    readProtocolProcesses,
    sumProtocolProcessTree,
} from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';

// Runs a browser cohort of the selected profile through the maintained
// participant runtime: each participant is its own origin with its own
// external Chrome profile, and a local relay only stores and serves the
// public records the participants publish. Participants never need to be
// online together, so none waits for another's browser: every participant
// whose inputs exist acts at once, in as many browsers as the host has room
// for, and a browser stays open between its participant's operations until
// another needs its room. A no-result run closes with one
// valid on-time ballot fewer than the minimum turnout, and with a corrupt
// participant's authentic invalid ballot on time when the profile tolerates
// one. An empty run closes with no ballot at all. A result run of a profile
// that tolerates two corrupt participants also closes without two honest
// ones: one departs after preparation and casts nothing, and the relay omits
// the other's on-time ballot. Another poll's passed cohort of the same
// profile, named by its run directory, supplies the records a relay view
// serves one participant as this poll's. A rosters run has a corrupt
// organizer complete a second roster of the same poll beside the first,
// each roster with the organizer as its only corrupt member, and serves each
// roster's records to a member of the other. A plain run carries one roster
// of honest participants through each stage once, with no crash, forgery or
// other roster. With --profile, Chrome records every operation's CPU samples,
// and their summary lies beside the run. With --base-port, the origins start
// at another port, so runs of other checkouts may run beside this one. With
// --memory-pressure, a plain run's second contributor first contributes in a
// browser that caps each WebAssembly memory below what its contribution
// needs, which must leave it pending rather than stopped, and its next visit
// completes the contribution. With --scalar, the origins are not isolated,
// so every operation uses one scalar worker without optional helpers. With
// --top-count=<count>, the poll requests that many ranked option identifiers.
// --setup-departure selects four participants and two options, removes honest
// eligible position one immediately after roster publication, and completes
// with positions zero, two and three, where corrupt position two cooperates.
// --unselected-checkpoint instead keeps all four original members available:
// position one endorses and activates the winning setup while its unused
// own contribution remains at the genuine first-oracle checkpoint.
const {
    participantCount,
    optionCount,
    mode,
    foreignPoll,
    profiling,
    scalar,
    setupDeparture,
    unselectedCheckpoint,
    selectionFork,
    memoryPressure,
    publicationFaults,
    sequential,
    recovery: measureRecovery,
    basePort,
    topCount,
    commandLineArguments,
} = selectParticipantBrowserOptions(process.argv.slice(2));
const noResult = mode !== 'result';
const root = path.resolve('.');
// A registrant that the organizer leaves out of the roster has the origin
// after the roster participants'. In a rosters run the second roster's
// registrants take the origins from there on instead.
const leftOut = participantCount;
const originCount = mode === 'rosters' ? 2 * participantCount - 1 : leftOut + 1;
// The copy of the corrupt organizer's private state that proposes the second
// roster, which reaches that roster's records under its own path of the
// organizer's origin.
const secondRosterCopy = 'second-roster';
const secondRosterPath = '/second-roster/';
// The host guard for each participant's Chrome process tree.
const participantMemoryLimit = 3_221_225_472;
// The WebAssembly pages each memory of a pressured browser may hold, fewer
// than a contribution's worker needs.
const pressurePages = 2048;
// Each browser's page starts a helper per spare processor, up to eight,
// beside the operation's worker, so the host runs as many browsers at once
// as it has processors for all of their workers, and no operation's work
// waits for another's.
const browserProcessors = scalar ? 1 : Math.min(availableParallelism(), 9);
// The functions each operation's CPU profile summary ranks.
const cpuProfileEntries = 60;
const operationMilliseconds = 3_600_000;

const requireScalarMemory = (details: Readonly<Record<string, unknown>>) => {
    assert.ok(
        details.memory !== undefined,
        'The scalar operation reported no memory.',
    );
    for (const memory of [details.memory, details.evaluationMemory]) {
        if (memory === undefined) continue;
        assert.ok(
            memory !== null &&
                typeof memory === 'object' &&
                'helpers' in memory &&
                'helperBytes' in memory &&
                'arenaBytes' in memory,
            'The scalar operation reported incomplete memory.',
        );
        assert.equal(memory.helpers, 0);
        assert.equal(memory.helperBytes, 0);
        assert.equal(memory.arenaBytes, 0);
    }
};

// The relay's layout: lower-case path segments of letters, digits, dots and
// hyphens, with no traversal.
const publicPath = /^(?:[a-z0-9][a-z0-9.-]*\/)*[a-z0-9][a-z0-9.-]*$/u;

// What a relay view serves a participant instead of a stored record: other
// bytes, the record another relay stored in the named file, or nothing when
// the value is undefined.
type ViewedRecord = ViewedParticipantRecord;

type Relay = Readonly<{
    servers: Server[];
    views: Map<string, ViewedRecord>[];
    // Publications the relay refuses to store.
    refusedKeys: Set<string>;
    refusedCandidates: Map<string, Uint8Array>;
    publicationFaultEvidence: {
        key: string;
        empty: string;
        changed?: string;
    }[];
    // The halting client a participant's origin serves instead of the
    // runtime's page and worker while one is set.
    halting: Map<number, HaltingClient>;
    // The public records the relay delivered to each position, by name.
    delivered: Set<string>[];
    candidateReads: Set<string>[];
    // Successfully served public payloads, by exact route, for cost accounting.
    reads: Map<string, Readonly<{ requests: number; bytes: number }>>[];
    publicationAttempts: number[];
}>;

type HaltingClient = Readonly<{
    generation: number;
    worker: Buffer;
    digest: string;
    preparationCut?: PreparationCut;
}>;

// The runtime's worker, except that it stops for good once its participant
// durably enters the generation, before any later work or publication.
const haltingClient = (worker: Buffer, generation: number): HaltingClient => {
    const committed =
        '\treturn {\n\t\thead,\n\t\tplaintext: reopened,\n\t\tmanifest\n\t};\n';
    const bundled = worker.toString('utf8');
    assert.equal(
        bundled.split(committed).length,
        2,
        'The worker bundle does not return one committed root.',
    );
    const patched = Buffer.from(
        bundled.replace(
            committed,
            `\tif (head.generation === ${String(generation)} && predecessor.head.generation !== ${String(generation)}) await new Promise(() => undefined);\n` +
                committed,
        ),
    );
    return {
        generation,
        worker: patched,
        digest: createHash('sha512').update(patched).digest('hex'),
    };
};

// Each participant keeps its state under this namespace of its own origin.
const participantNamespace = 'research-cohort';
const participantDatabase = participantDatabaseName(participantNamespace);

// An honest participant's page runs every operation through the SDK's
// participant API, which carries the packaged worker; the relay serves it
// beside the packaged module. The page also runs the SDK's
// standalone verifier for the poll the runner names, from the same relay.
const participantPage = `<!doctype html><meta charset="utf-8"><title>Participant</title><script type="module">
import { openParticipant, verifyOutcome } from '/sdk/index.js';
const relay = new URL('./', location.href).href;
window.verifyOutcome = (poll) => verifyOutcome({ poll, relay });
window.runParticipant = (operation, parameters) =>
    openParticipant({ namespace: ${JSON.stringify(participantNamespace)}, relay }).run({ operation, parameters });
</script>`;

// A patched client's page checks the patched worker against the digest it
// names and sends the SDK's commands, claiming the runtime's identity.
const clientPage = (runtime: ParticipantRuntime, workerDigest: string) =>
    `<!doctype html><meta charset="utf-8"><title>Participant</title><script>
const runtime = ${JSON.stringify({ identity: runtime.identity, worker: workerDigest })};
window.runParticipant = async (operation, parameters) => {
    window.paddingReplay = {slots: [], halt: null};
    window.preparationHalt = null;
    const response = await fetch('/worker.js', { cache: 'no-store' });
    const bytes = new Uint8Array(await response.arrayBuffer());
    const digest = Array.from(
        new Uint8Array(await crypto.subtle.digest('SHA-512', bytes)),
        (value) => value.toString(16).padStart(2, '0'),
    ).join('');
    if (digest !== runtime.worker) throw new Error('The worker changed.');
    const url = URL.createObjectURL(new Blob([bytes], { type: 'text/javascript' }));
    const worker = new Worker(url, { type: 'module' });
    return new Promise((resolve, reject) => {
        const finish = () => {
            worker.terminate();
            URL.revokeObjectURL(url);
        };
        worker.onmessage = ({ data }) => {
            if (data?.type === 'participant-padding-slot') { window.paddingReplay.slots.push(data); return; }
            if (data?.type === 'participant-padding-halt') { window.paddingReplay.halt = data; return; }
            if (data?.type === 'participant-preparation-halt') { window.preparationHalt = data; return; }
            finish();
            resolve(data);
        };
        worker.onerror = (event) => {
            finish();
            reject(new Error(event.message || 'The participant worker failed.'));
        };
        worker.postMessage({
            operation,
            parameters,
            namespace: ${JSON.stringify(participantNamespace)},
            relay: location.origin + '/',
            module: location.origin + '/sdk/participant.wasm',
            identity: runtime.identity,
        });
    });
};
</script>`;

// Every origin serves the SDK's participant API and module and an honest
// participant's page, except that a corrupt participant's origin serves its
// client's page and worker and its client's module. With a second roster,
// its registrants' origins and the second roster's path store and serve its
// own records.
const startRelay = async (
    runtime: ParticipantRuntime,
    publicDirectory: string,
    corrupt:
        | Readonly<{ position: number; client: CorruptParticipantClient }>
        | undefined,
    secondRoster: string | undefined,
    transfers: readonly ParticipantTransfer[],
): Promise<Relay> => {
    const views = Array.from(
        { length: originCount },
        () => new Map<string, ViewedRecord>(),
    );
    const refusedKeys = new Set<string>();
    const refusedCandidates = new Map<string, Uint8Array>();
    const poisoned = new Set<string>();
    const publicationFaultEvidence: Relay['publicationFaultEvidence'] = [];
    const candidateStores = new Map<
        string,
        {
            store: ReturnType<typeof participantRelayStore>;
            projection: ReturnType<typeof participantCandidateView>;
        }
    >();
    const announcementStores = new Map<
        string,
        ReturnType<typeof participantOfferAnnouncements>
    >();
    const publicationAttempts = new Array<number>(originCount).fill(0);
    const candidateReads = Array.from(
        { length: originCount },
        () => new Set<string>(),
    );
    const delivered = Array.from(
        { length: originCount },
        () => new Set<string>(),
    );
    const reads: Relay['reads'] = Array.from(
        { length: originCount },
        () => new Map<string, Readonly<{ requests: number; bytes: number }>>(),
    );
    const assets = (position: number) => {
        const client =
            corrupt?.position === position ? corrupt.client : undefined;
        return new Map([
            [
                '/',
                {
                    type: 'text/html',
                    bytes: Buffer.from(
                        client === undefined
                            ? participantPage
                            : clientPage(runtime, client.workerDigest),
                    ),
                },
            ],
            ['/sdk/index.js', { type: 'text/javascript', bytes: runtime.sdk }],
            [
                '/sdk/participant.wasm',
                { type: 'application/wasm', bytes: runtime.module },
            ],
            ...(client === undefined
                ? []
                : ([
                      [
                          '/worker.js',
                          { type: 'text/javascript', bytes: client.worker },
                      ],
                      [
                          '/' + client.path,
                          { type: 'application/wasm', bytes: client.module },
                      ],
                  ] as const)),
        ]);
    };
    const handle = async (
        origin: string,
        served: ReadonlyMap<string, Readonly<{ type: string; bytes: Buffer }>>,
        view: ReadonlyMap<string, ViewedRecord>,
        delivering: Set<string>,
        ownRecords: string,
        request: IncomingMessage,
        response: ServerResponse,
    ) => {
        observeParticipantTransfer(
            request,
            response,
            transfers[Number(new URL(origin).port) - basePort],
        );
        const requested = new URL(request.url ?? '/', origin);
        const second =
            secondRoster !== undefined &&
            requested.pathname.startsWith(secondRosterPath);
        const url = second
            ? new URL(
                  requested.pathname.slice(secondRosterPath.length - 1) +
                      requested.search,
                  origin,
              )
            : requested;
        const records = (second ? secondRoster : undefined) ?? ownRecords;
        if (url.pathname.startsWith('/offers/')) {
            let store = announcementStores.get(records);
            if (store === undefined) {
                store = participantOfferAnnouncements(
                    path.join(
                        path.dirname(records),
                        path.basename(records) + '-offers',
                    ),
                );
                announcementStores.set(records, store);
            }
            if (request.method === 'POST')
                publicationAttempts[Number(new URL(origin).port) - basePort]++;
            const page = await serveOfferAnnouncements(
                store,
                participantCount,
                request,
                response,
                url,
            );
            if (page !== undefined) {
                delivering.add(page.route);
                const consumed = reads[Number(new URL(origin).port) - basePort];
                const previous = consumed.get(page.route);
                consumed.set(page.route, {
                    requests: (previous?.requests ?? 0) + 1,
                    bytes: (previous?.bytes ?? 0) + page.bytes,
                });
            }
            return;
        }
        if (request.method === 'GET') {
            const asset = served.get(url.pathname);
            if (asset !== undefined) {
                response.writeHead(200, {
                    'Content-Type': asset.type,
                    'Cache-Control': 'no-store',
                });
                response.end(asset.bytes);
                return;
            }
        }
        if (
            request.method === 'POST' &&
            (url.pathname === '/chunks' ||
                url.pathname.startsWith('/candidates/'))
        )
            publicationAttempts[Number(new URL(origin).port) - basePort]++;
        let candidateStore = candidateStores.get(records);
        if (candidateStore === undefined) {
            const store = participantRelayStore(
                path.join(records, 'transport'),
            );
            candidateStore = {
                store,
                projection: participantCandidateView(store, records),
            };
            candidateStores.set(records, candidateStore);
        }
        const { store, projection } = candidateStore;
        const reader = projection.forReader(view, (name, bytes) => {
            delivering.add(name);
            const recordsRead = reads[Number(new URL(origin).port) - basePort];
            const previous = recordsRead.get(name);
            recordsRead.set(name, {
                requests: (previous?.requests ?? 0) + 1,
                bytes: (previous?.bytes ?? 0) + bytes,
            });
        });
        if (
            await serveParticipantCandidates(store, request, response, url, {
                ...reader,
                manifest: async (candidate) => {
                    candidateReads[Number(new URL(origin).port) - basePort].add(
                        candidate.id,
                    );
                    return reader.manifest(candidate);
                },
                accept: async (key, bytes) => {
                    if (refusedKeys.has(key)) {
                        refusedCandidates.set(key, new Uint8Array(bytes));
                        return false;
                    }
                    if (
                        publicationFaults &&
                        !poisoned.has(records + '/' + key)
                    ) {
                        poisoned.add(records + '/' + key);
                        const empty = await store.append(
                            key,
                            encodeCandidateManifest({
                                files: [
                                    {
                                        name: 'empty.bin',
                                        length: 0,
                                        chunks: [],
                                    },
                                ],
                            }),
                        );
                        const manifest = decodeCandidateManifest(bytes);
                        const target = manifest.files.find((file) =>
                            [
                                'signature.bin',
                                'offer-signature.bin',
                                'vote.bin',
                                'endorsement.bin',
                                'certificate.bin',
                                'intent.bin',
                                'response.bin',
                                'envelope.bin',
                            ].includes(file.name),
                        );
                        let changed: string | undefined;
                        if (target !== undefined && target.chunks.length > 0) {
                            const wrong = await store.chunk(target.chunks[0]);
                            wrong[0] ^= 1;
                            const id = await store.putChunk(wrong);
                            changed = (
                                await store.append(
                                    key,
                                    encodeCandidateManifest({
                                        files: manifest.files.map((file) =>
                                            file === target
                                                ? {
                                                      ...file,
                                                      chunks: [
                                                          id,
                                                          ...file.chunks.slice(
                                                              1,
                                                          ),
                                                      ],
                                                  }
                                                : file,
                                        ),
                                    }),
                                )
                            ).id;
                        }
                        publicationFaultEvidence.push({
                            key,
                            empty: empty.id,
                            ...(changed === undefined ? {} : { changed }),
                        });
                    }
                    return true;
                },
                published: projection.published,
            })
        )
            return;
        response.writeHead(404);
        response.end();
    };
    const halting = new Map<number, HaltingClient>();
    const servers: Server[] = [];
    for (let position = 0; position < originCount; position++) {
        const origin = `http://127.0.0.1:${String(basePort + position)}`;
        const served = assets(position);
        const ownRecords =
            secondRoster !== undefined && position >= participantCount
                ? secondRoster
                : publicDirectory;
        const server = createServer((request, response) => {
            // Nonisolated pages exercise the required single-worker path;
            // isolated pages may also start optional parallel helpers.
            if (!scalar) {
                response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
                response.setHeader(
                    'Cross-Origin-Embedder-Policy',
                    'require-corp',
                );
            }
            const client = halting.get(position);
            handle(
                origin,
                client === undefined
                    ? served
                    : new Map([
                          ...served,
                          [
                              '/',
                              {
                                  type: 'text/html',
                                  bytes: Buffer.from(
                                      clientPage(runtime, client.digest),
                                  ),
                              },
                          ],
                          [
                              '/worker.js',
                              {
                                  type: 'text/javascript',
                                  bytes: client.worker,
                              },
                          ],
                      ]),
                views[position],
                delivered[position],
                ownRecords,
                request,
                response,
            ).catch(() => {
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
    return {
        servers,
        publicationAttempts,
        candidateReads,
        views,
        refusedKeys,
        refusedCandidates,
        publicationFaultEvidence,
        halting,
        delivered,
        reads,
    };
};

type ForeignPoll = Readonly<{
    // The passed cohort's run directory, relative to the repository.
    run: string;
    poll: string;
    recordIds: readonly string[];
    // The registration of the registrant its organizer left out of the
    // roster, when the other poll's run records one.
    leftOut: string | undefined;
    publicDirectory: string;
}>;

const identifierPattern = /^[0-9a-f]{128}$/u;

// Reads another passed cohort of this profile: its result names its poll and
// its roster's registrations, and its relay's records lie among its artifacts.
const loadForeignPoll = async (run: string): Promise<ForeignPoll> => {
    const directory = path.resolve(run);
    const result = JSON.parse(
        await readFile(path.join(directory, 'result.json'), 'utf8'),
    ) as Readonly<Record<string, unknown>>;
    assert.ok(
        result.participantCount === participantCount &&
            result.optionCount === optionCount,
        'The foreign poll has another profile.',
    );
    const { poll } = result;
    const recordIds: readonly unknown[] = Array.isArray(result.recordIds)
        ? (result.recordIds as unknown[])
        : [];
    assert.ok(
        typeof poll === 'string' &&
            identifierPattern.test(poll) &&
            recordIds.length === participantCount &&
            recordIds.every(
                (id) => typeof id === 'string' && identifierPattern.test(id),
            ),
        'The foreign poll names a malformed poll or roster.',
    );
    const leftOutDigest = (
        result.leftOut as { bodyDigest?: unknown } | undefined
    )?.bodyDigest;
    assert.ok(
        leftOutDigest === undefined ||
            (typeof leftOutDigest === 'string' &&
                identifierPattern.test(leftOutDigest)),
        'The foreign poll names a malformed registrant left out of its roster.',
    );
    const publicDirectory = path.join(
        runArtifactDirectoryPath(directory),
        'public',
    );
    assert.ok(
        (await stat(publicDirectory)).isDirectory(),
        'The foreign poll has no public records.',
    );
    return {
        run: path.relative(root, directory).split(path.sep).join('/'),
        poll,
        recordIds: recordIds.map(String),
        leftOut: leftOutDigest,
        publicDirectory,
    };
};

// The names of the records a relay stored.
const publicRecordNames = async (directory: string) =>
    (await readdir(directory, { recursive: true }))
        .map((name) => name.split(path.sep).join('/'))
        .filter((name) => publicPath.test(name) && name.endsWith('.bin'));

// The healthy fixture generates one immutable body per offered position.
// Discovery hints are deliberately not used as authority for this assertion.
const generatedOfferIdentity = async (directory: string, position: number) => {
    const entries = await readdir(
        path.join(directory, 'contribution-' + String(position)),
        { withFileTypes: true },
    );
    const bodies = entries.filter(
        (entry) => entry.isDirectory() && /^[0-9a-f]{128}$/u.test(entry.name),
    );
    assert.equal(
        bodies.length,
        1,
        'The original contributor generated another body.',
    );
    return Buffer.from(bodies[0].name, 'hex');
};

// The record families a relay view replaces with another poll's, each with
// the refusal of the first of them a result visit reads. A result visit
// restores the verified setup and the evaluated target, so it reads no
// contribution or close record.
const foreignFamilies = [
    {
        family: 'registrations',
        pattern: /^registration\//u,
        reason: 'A registration header was refused.',
    },
    {
        family: 'contributions',
        pattern: /^contribution-\d+\//u,
        reason: undefined,
    },
    {
        family: 'close records',
        pattern: /^close\//u,
        reason: undefined,
    },
    {
        family: 'target votes',
        pattern: /^completion\/target-vote-\d+\.bin$/u,
        reason: 'The target votes are incomplete.',
    },
    {
        family: 'release shares',
        pattern: /^completion\/release-(?:envelope-)?\d+\.bin$/u,
        reason: 'The release shares are incomplete.',
    },
] as const;

// Serves another poll's records of one family under this poll's names, and
// nothing where the other poll has none: its registrations by roster
// position under this poll's record identifiers, and its other records under
// their own names.
const foreignRecordView = async (
    foreign: Pick<ForeignPoll, 'publicDirectory' | 'recordIds' | 'leftOut'>,
    publicDirectory: string,
    recordIds: readonly string[],
    pattern: RegExp,
) => {
    const view = new Map<string, ViewedRecord>();
    for (const name of await publicRecordNames(publicDirectory))
        if (pattern.test(name)) view.set(name, undefined);
    let served = 0;
    for (const name of await publicRecordNames(foreign.publicDirectory)) {
        if (!pattern.test(name)) continue;
        const registration = /^registration\/([0-9a-f]{128})\/(.+)$/u.exec(
            name,
        );
        const position =
            registration === null
                ? undefined
                : foreign.recordIds.indexOf(registration[1]);
        // The registrant the other poll's organizer left out of its roster
        // has no roster position to take in this poll.
        if (registration !== null && registration[1] === foreign.leftOut)
            continue;
        assert.ok(
            position === undefined || position >= 0,
            'A foreign registration is not in its roster.',
        );
        view.set(
            registration === null || position === undefined
                ? name
                : `registration/${recordIds[position]}/${registration[2]}`,
            { file: path.join(foreign.publicDirectory, name) },
        );
        served++;
    }
    return { view, served };
};

// Lists words as prose.
const prose = (words: readonly string[]) =>
    words.length < 2
        ? words.join('')
        : `${words.slice(0, -1).join(', ')} or ${words[words.length - 1]}`;

await runWithLocalRunLog(
    {
        commandLineArguments,
        lanes: [
            'Participant runtime assembly',
            'Browser registration and roster agreement',
            'Browser setup contribution',
            'Browser setup verification',
            'Browser signed ballots',
            'Browser close responses',
            'Browser target votes',
            'Browser release shares',
            'Browser result',
            'Browser relay forgeries',
            'Browser records of another poll',
            'Browser altered and lost storage',
        ],
        scriptName: 'research:participant',
    },
    async (log) => {
        const releaseLock = await acquireProtocolResearchLock(
            log.runDirectoryPath,
            root,
        );
        // Each browser runs a participant or a copy of a participant's
        // private state, at that participant's origin.
        const browserDetails = new Map<
            string,
            Readonly<{ position: number; copy?: string }>
        >();
        const browsers = createBrowserPool<ChromeParticipant>({
            browsers: sequential
                ? 1
                : Math.floor(availableParallelism() / browserProcessors),
            guardBytes: participantMemoryLimit,
            freeMemory: freemem,
            onEndedForRoom: (key) => {
                log.writeEvent({
                    eventType: 'participant-browser-ended-for-room',
                    details: browserDetails.get(key),
                });
            },
        });
        // Copies of a participant's private state by name, each with its own
        // Chrome profile at that participant's origin: the equivocator's, and
        // an honest participant's whose records are then lost.
        const copies = new Map<string, number>();
        // The participants whose next browser caps its WebAssembly memories,
        // and the operations that ran under that cap.
        const pressured = new Set<number>();
        const memoryPressures: Readonly<{
            position: number;
            operation: string;
            pages: number;
            before: number;
            generation: number;
            reason: string;
        }>[] = [];
        let relay: Relay | undefined;
        let sampling = true;
        let monitor: Promise<void> | undefined;
        let allocationMonitor: Promise<void> | undefined;
        let finishAllocation: (() => Promise<void>) | undefined;
        // Failed runs retain their original profiles; a completed run deletes
        // its test profiles.
        let profiles: string | undefined;
        let guardFailure: Error | undefined;
        let completed = false;
        const ordinaryOperations: ParticipantOperationMeasurement[] = [];
        const ordinaryBootstraps: ParticipantBootstrapMeasurement[] = [];
        const measureWorkflow =
            mode === 'plain' &&
            !memoryPressure &&
            !setupDeparture &&
            !unselectedCheckpoint &&
            !publicationFaults;
        const measuredStages = Array.from({ length: participantCount }, () => [
            0,
        ]);
        const browserSessions = new WeakMap<ChromeParticipant, number>();
        let nextBrowserSession = 0;
        let nextMeasuredOperation = 0;
        const transfers = Array.from(
            { length: originCount },
            emptyParticipantTransfer,
        );
        try {
            const {
                maximumCorruptParticipantCount,
                minimumTurnout,
                releaseThreshold,
                setupContributorCount,
            } = deriveSupportedProfile(participantCount, optionCount);
            const foreign =
                foreignPoll === undefined
                    ? undefined
                    : await loadForeignPoll(foreignPoll);
            // In a result run the last corrupt position equivocates, as in
            // the native result ceremony: two copies of its private state
            // sign two more ballots.
            const equivocator =
                setupDeparture ||
                unselectedCheckpoint ||
                noResult ||
                maximumCorruptParticipantCount === 0
                    ? undefined
                    : maximumCorruptParticipantCount;
            // The corrupt positions follow the organizer, as in the native
            // ceremonies; forgeries and altered state are shown to honest ones.
            const honest = (position: number) =>
                selectionFork
                    ? position !== 0
                    : setupDeparture || unselectedCheckpoint
                      ? position !== 2
                      : position === 0 ||
                        position > maximumCorruptParticipantCount;
            const copyNames =
                equivocator === undefined ? [] : ['conflicting', 'late'];
            // In a no-result run the last corrupt position runs a client that
            // signs an authentic invalid ballot, and casts it on time.
            const invalidAuthor =
                mode === 'no-result' && maximumCorruptParticipantCount > 0
                    ? maximumCorruptParticipantCount
                    : undefined;
            // The bounds the worker derives, as the independent models give
            // them, for the expected sizes of the cohort's records.
            const bounds = compileParticipantRuntimeProfile(
                participantCount,
                optionCount,
            );
            const eligibleContributorCount = bounds.eligibleContributorCount;
            // The proof randomness an honest ballot and release draw from
            // their seeds when no candidate is rejected, as the independent
            // models derive it.
            const proofDraws = compileOperationProofDraws(
                deriveSupportedProfile(participantCount, optionCount),
            );
            for (const file of [
                'tools/ci/run-participant-browser.ts',
                'tools/ci/participant-browser-options.ts',
                'tools/ci/participant-workflow-measurements.ts',
                'tests/setup-selection-model.ts',
                'tests/threshold-completion-model.ts',
                'tools/ci/participant-padding-halt.ts',
                'tools/ci/participant-relay-record.ts',
                'tools/ci/participant-offer-announcements.ts',
                ...(mode === 'preparation' || unselectedCheckpoint
                    ? [
                          'tools/ci/participant-padding-corruption.ts',
                          'tools/ci/participant-preparation-storage.ts',
                      ]
                    : []),
            ]) {
                const runnerSnapshot = path.join(
                    log.runDirectoryPath,
                    'sources',
                    file,
                );
                await mkdir(path.dirname(runnerSnapshot), { recursive: true });
                await writeFile(runnerSnapshot, await readFile(file), {
                    flag: 'wx',
                });
            }
            const { runtime, invalidBallotClient } =
                await assembleParticipantRuntime(
                    log,
                    invalidAuthor !== undefined,
                );
            const paddingClients =
                mode === 'preparation'
                    ? new Map(
                          (['padding', 'final-slot'] as const).map((cut) => [
                              cut,
                              paddingHaltingClient(runtime.worker, cut),
                          ]),
                      )
                    : undefined;
            let preparationStorageBundle: string | undefined;
            if (mode === 'preparation' || unselectedCheckpoint) {
                const bundles = await build({
                    config: false,
                    clean: false,
                    write: false,
                    dts: false,
                    entry: {
                        preparationStorage: path.join(
                            root,
                            'tools/ci/participant-preparation-storage.ts',
                        ),
                    },
                    format: 'iife',
                    globalName: 'participantPreparationFixture',
                    platform: 'browser',
                    target: 'es2022',
                    minify: false,
                    sourcemap: false,
                    report: false,
                    logLevel: 'warn',
                    failOnWarn: true,
                    tsconfig: path.join(root, 'tsconfig.tools.json'),
                    outputOptions: { codeSplitting: false },
                });
                const chunks = bundles.flatMap((bundle) => bundle.chunks);
                assert.equal(
                    chunks.length,
                    1,
                    'The browser storage fixture must be self-contained.',
                );
                assert.equal(chunks[0].type, 'chunk');
                if (chunks[0].type === 'chunk')
                    preparationStorageBundle = chunks[0].code;
                assert.ok(preparationStorageBundle);
                await writeFile(
                    path.join(
                        log.runDirectoryPath,
                        'preparation-storage-fixture.js',
                    ),
                    preparationStorageBundle,
                    { flag: 'wx' },
                );
                for (const client of paddingClients?.values() ?? [])
                    await writeFile(
                        path.join(
                            log.runDirectoryPath,
                            'padding-' + client.cut + '-worker.js',
                        ),
                        client.worker,
                        { flag: 'wx' },
                    );
            }
            const corrupt =
                invalidAuthor === undefined || invalidBallotClient === undefined
                    ? undefined
                    : { position: invalidAuthor, client: invalidBallotClient };
            assert.equal(corrupt === undefined, invalidAuthor === undefined);
            const corruptClient =
                corrupt === undefined
                    ? undefined
                    : {
                          position: corrupt.position,
                          feature: corrupt.client.feature,
                          module: corrupt.client.moduleDigest,
                          worker: corrupt.client.workerDigest,
                      };
            if (corruptClient !== undefined)
                log.writeEvent({
                    eventType: 'participant-corrupt-client',
                    details: corruptClient,
                });
            // The relay stores every published record among the run's
            // artifacts.
            const publicDirectory = path.join(
                log.artifactDirectoryPath,
                'public',
            );
            await mkdir(publicDirectory, { recursive: true });
            const secondRosterDirectory =
                mode === 'rosters'
                    ? path.join(
                          log.artifactDirectoryPath,
                          'second-roster-public',
                      )
                    : undefined;
            if (secondRosterDirectory !== undefined)
                await mkdir(secondRosterDirectory);
            relay = await startRelay(
                runtime,
                publicDirectory,
                corrupt,
                secondRosterDirectory,
                transfers,
            );
            const {
                views,
                halting,
                delivered: deliveredRecords,
                candidateReads,
            } = relay;
            profiles = await mkdtemp(
                path.join(root, 'temp/participant-browser-'),
            );
            const profileDirectory = profiles;
            const allocationSummaries = new Map<
                string,
                {
                    samples: number;
                    peakFileBytes: number;
                    peakAllocatedBytes: number;
                    peakIndexedDatabaseFileBytes: number;
                    peakIndexedDatabaseAllocatedBytes: number;
                    missingEntries: number;
                    unreadableEntries: number;
                    skippedLinks: number;
                    multiplyLinkedFileObservations: number;
                }
            >();
            const sampleStorageFiles = async (phase: 'running' | 'closed') => {
                const directories = [
                    ...(await readdir(profileDirectory)).map((name) => ({
                        key: name,
                        directory: path.join(profileDirectory, name),
                    })),
                    {
                        key: 'public transport',
                        directory: path.join(publicDirectory, 'transport'),
                    },
                    {
                        key: 'public with diagnostics',
                        directory: publicDirectory,
                    },
                    ...(secondRosterDirectory === undefined
                        ? []
                        : [
                              {
                                  key: 'second roster transport',
                                  directory: path.join(
                                      secondRosterDirectory,
                                      'transport',
                                  ),
                              },
                              {
                                  key: 'second roster with diagnostics',
                                  directory: secondRosterDirectory,
                              },
                          ]),
                ];
                const started = performance.now();
                const samples = await sampleFileAllocation(
                    directories.map(({ directory }) => directory),
                );
                const finished = performance.now();
                for (const [index, sample] of samples.entries()) {
                    const { key } = directories[index];
                    const summary = allocationSummaries.get(key) ?? {
                        samples: 0,
                        peakFileBytes: 0,
                        peakAllocatedBytes: 0,
                        peakIndexedDatabaseFileBytes: 0,
                        peakIndexedDatabaseAllocatedBytes: 0,
                        missingEntries: 0,
                        unreadableEntries: 0,
                        skippedLinks: 0,
                        multiplyLinkedFileObservations: 0,
                    };
                    summary.samples++;
                    summary.peakFileBytes = Math.max(
                        summary.peakFileBytes,
                        sample.fileBytes,
                    );
                    summary.peakAllocatedBytes = Math.max(
                        summary.peakAllocatedBytes,
                        sample.allocatedBytes,
                    );
                    summary.peakIndexedDatabaseFileBytes = Math.max(
                        summary.peakIndexedDatabaseFileBytes,
                        sample.indexedDatabaseFileBytes,
                    );
                    summary.peakIndexedDatabaseAllocatedBytes = Math.max(
                        summary.peakIndexedDatabaseAllocatedBytes,
                        sample.indexedDatabaseAllocatedBytes,
                    );
                    summary.missingEntries += sample.missingEntries;
                    summary.unreadableEntries += sample.unreadableEntries;
                    summary.skippedLinks += sample.skippedLinks;
                    summary.multiplyLinkedFileObservations +=
                        sample.multiplyLinkedFiles;
                    allocationSummaries.set(key, summary);
                    log.writeEvent({
                        eventType: 'participant-file-allocation',
                        details: { key, phase, started, finished, ...sample },
                    });
                }
            };
            allocationMonitor = (async () => {
                while (sampling) {
                    await sampleStorageFiles('running');
                    await delay(5000);
                }
            })().catch((error: unknown) => {
                guardFailure ??=
                    error instanceof Error ? error : new Error(String(error));
            });
            let allocationFinished = false;
            finishAllocation = async () => {
                if (allocationFinished) return;
                allocationFinished = true;
                sampling = false;
                await monitor;
                await allocationMonitor;
                await browsers.closeAll();
                await sampleStorageFiles('closed');
                await writeFile(
                    path.join(
                        log.runDirectoryPath,
                        'file-allocation-summary.json',
                    ),
                    JSON.stringify(
                        {
                            method:
                                process.platform === 'win32'
                                    ? 'FILE_STANDARD_INFO AllocationSize and EndOfFile'
                                    : 'lstat size and blocks times 512',
                            scope: 'Per-path default file streams, including browser database journals, Blob files and profile overhead. Transport-only directories are nested within the separately reported diagnostic public directories; those rows must not be added. Samples are not atomic snapshots, do not include volume metadata or filesystem journals, and can miss transient peaks and unlinked open files. Multiple hard links count by path and are reported explicitly.',
                            directories:
                                Object.fromEntries(allocationSummaries),
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
                if (guardFailure !== undefined) throw guardFailure;
            };
            const peaks = new Array<number>(originCount).fill(0);
            const sampledResources = Array.from(
                { length: originCount },
                () => ({
                    browserProcessBytes: 0,
                    javaScriptUsedBytes: null as number | null,
                    javaScriptBackingBytes: null as number | null,
                    originStorageBytes: null as number | null,
                    incompleteHeapSamples: 0,
                    missingStorageSamples: 0,
                }),
            );
            const copyPeaks = new Map<string, number>();
            // Samples every open browser's process tree against the guard,
            // from one snapshot of the host's processes.
            monitor = (async () => {
                while (sampling) {
                    const processes = await readProtocolProcesses();
                    for (const {
                        key,
                        browser,
                        sampled,
                    } of browsers.launched()) {
                        const details = browserDetails.get(key);
                        const bytes = sumProtocolProcessTree(
                            browser.processIdentifier,
                            processes,
                        );
                        if (details === undefined || bytes === undefined)
                            continue;
                        sampled(bytes);
                        const heaps = browser.heaps();
                        const storage = browser.storage();
                        log.writeEvent({
                            eventType: 'participant-process-memory',
                            details: {
                                ...details,
                                bytes,
                                heaps,
                                storage,
                            },
                        });
                        if (bytes > participantMemoryLimit) {
                            guardFailure ??= new Error(
                                'Participant process-tree memory guard exceeded.',
                            );
                            await browsers.crash(key);
                        }
                        if (details.copy === undefined) {
                            const resources =
                                sampledResources[details.position];
                            resources.browserProcessBytes = Math.max(
                                resources.browserProcessBytes,
                                bytes,
                            );
                            if (heaps.reported > 0) {
                                resources.javaScriptUsedBytes = Math.max(
                                    resources.javaScriptUsedBytes ?? 0,
                                    heaps.usedBytes,
                                );
                                resources.javaScriptBackingBytes = Math.max(
                                    resources.javaScriptBackingBytes ?? 0,
                                    heaps.backingBytes,
                                );
                            }
                            if (heaps.reported < heaps.sessions)
                                resources.incompleteHeapSamples++;
                            if (storage.reported)
                                resources.originStorageBytes = Math.max(
                                    resources.originStorageBytes ?? 0,
                                    storage.usageBytes,
                                );
                            else resources.missingStorageSamples++;
                            peaks[details.position] = Math.max(
                                peaks[details.position],
                                bytes,
                            );
                        } else
                            copyPeaks.set(
                                details.copy,
                                Math.max(
                                    copyPeaks.get(details.copy) ?? 0,
                                    bytes,
                                ),
                            );
                    }
                    await delay(2000);
                }
            })().catch((error: unknown) => {
                // Unsampled browsers leave the guard unenforced, so the run
                // fails once its running operations end.
                guardFailure ??=
                    error instanceof Error ? error : new Error(String(error));
            });
            const origin = (position: number) =>
                `http://127.0.0.1:${String(basePort + position)}`;
            const profile = (position: number) =>
                path.join(profileDirectory, `participant-${String(position)}`);
            const copyProfile = (copy: string) =>
                path.join(profileDirectory, `copy-${copy}`);
            const participantBrowser = (position: number) =>
                `participant-${String(position)}`;
            const copyBrowser = (copy: string) => `copy-${copy}`;
            // A departed participant's browser and private state are gone.
            // Its browser ends at once, as its device leaving would: the
            // shutdown work Chrome does for a profile about to be deleted is
            // no participant's, and after heavy storage churn it can outlast
            // any fixed deadline.
            const departed = new Set<number>();
            const depart = async (position: number) => {
                await browsers.crash(participantBrowser(position));
                departed.add(position);
                await rm(profile(position), {
                    recursive: true,
                    maxRetries: 10,
                    retryDelay: 500,
                });
            };
            // Runs an action in a participant's browser, or in the browser of
            // a copy of its private state, opening the browser when it is not
            // open.
            const inBrowser = async <Result>(
                position: number,
                copy: string | undefined,
                action: (chrome: ChromeParticipant) => Promise<Result>,
            ) => {
                assert.ok(
                    copy !== undefined || !departed.has(position),
                    'The participant departed.',
                );
                assert.ok(
                    copy === undefined || copies.get(copy) === position,
                    'The copy does not exist.',
                );
                const key =
                    copy === undefined
                        ? participantBrowser(position)
                        : copyBrowser(copy);
                const details = {
                    position,
                    ...(copy === undefined ? {} : { copy }),
                };
                return browsers.use(
                    key,
                    async () => {
                        // This callback starts only after the pool has room;
                        // pool queueing and another browser's eviction stay outside.
                        const session = nextBrowserSession++;
                        const launching = performance.now();
                        let chrome: ChromeParticipant | undefined;
                        try {
                            chrome = await launchChromeParticipant(
                                copy === undefined
                                    ? profile(position)
                                    : copyProfile(copy),
                                origin(position) +
                                    (copy === secondRosterCopy
                                        ? secondRosterPath
                                        : ''),
                                copy === undefined && pressured.has(position)
                                    ? `--wasm-max-mem-pages=${String(pressurePages)}`
                                    : undefined,
                            );
                            assert.equal(
                                await chrome.evaluate('crossOriginIsolated'),
                                !scalar,
                                'The browser isolation differs from the selected execution mode.',
                            );
                            assert.equal(
                                await chrome.evaluate(
                                    "typeof window.runParticipant === 'function'",
                                ),
                                true,
                                'The participant page SDK did not initialize.',
                            );
                        } catch (error) {
                            const bootstrap = {
                                session,
                                position,
                                started: launching,
                                finished: performance.now(),
                            };
                            if (
                                measureWorkflow &&
                                copy === undefined &&
                                position < participantCount
                            )
                                ordinaryBootstraps.push(bootstrap);
                            log.writeEvent({
                                eventType:
                                    'participant-browser-bootstrap-failed',
                                details: { ...details, ...bootstrap },
                            });
                            await chrome?.crash();
                            throw error;
                        }
                        const bootstrap = {
                            session,
                            position,
                            started: launching,
                            finished: performance.now(),
                        };
                        browserDetails.set(key, details);
                        browserSessions.set(chrome, session);
                        if (
                            measureWorkflow &&
                            copy === undefined &&
                            position < participantCount
                        )
                            ordinaryBootstraps.push(bootstrap);
                        log.writeEvent({
                            eventType: 'participant-browser',
                            details: {
                                ...details,
                                ...bootstrap,
                                milliseconds:
                                    bootstrap.finished - bootstrap.started,
                                version: chrome.version,
                                launchArguments: chrome.launchArguments,
                                scalar,
                            },
                        });
                        return chrome;
                    },
                    action,
                );
            };
            // With profiling, each operation's summary of CPU samples, in
            // the order the operations ended.
            const cpuProfileDirectory = profiling
                ? path.join(log.runDirectoryPath, 'cpu-profiles')
                : undefined;
            if (cpuProfileDirectory !== undefined)
                await mkdir(cpuProfileDirectory);
            let profiledOperations = 0;
            const recoveryOperations = new Map<number, string>();
            // Runs one operation in a participant's page, or in a copy of its
            // private state.
            const request = async (
                position: number,
                operation: string,
                parameters: Record<string, unknown> = {},
                copy?: string,
            ) =>
                inBrowser(position, copy, async (chrome) => {
                    const started = performance.now();
                    const measured =
                        measureWorkflow &&
                        copy === undefined &&
                        position < participantCount
                            ? {
                                  id: nextMeasuredOperation++,
                                  position,
                                  operation,
                                  started,
                                  stages: [...measuredStages[position]],
                                  session: browserSessions.get(chrome)!,
                              }
                            : undefined;
                    const recordAttempt = (
                        outcome: ParticipantOperationMeasurement['outcome'],
                        details?: Record<string, unknown>,
                    ) => {
                        if (measured === undefined) return;
                        const resources = (details ?? {}) as Pick<
                            ParticipantOperationMeasurement,
                            'generation' | 'memory' | 'evaluationMemory'
                        >;
                        const entry = {
                            ...measured,
                            finished: performance.now(),
                            outcome,
                            generation: resources.generation,
                            memory: resources.memory,
                            evaluationMemory: resources.evaluationMemory,
                        };
                        ordinaryOperations.push(entry);
                        log.writeEvent({
                            eventType: 'participant-visit-attempt',
                            details: entry,
                        });
                    };
                    const beforeReads = new Map(relay?.reads[position]);
                    const publicRecordReads = () =>
                        [...(relay?.reads[position] ?? [])].flatMap(
                            ([route, value]) => {
                                const before = beforeReads.get(route);
                                const requests =
                                    value.requests - (before?.requests ?? 0);
                                return requests === 0
                                    ? []
                                    : [
                                          {
                                              route,
                                              requests,
                                              bytes:
                                                  value.bytes -
                                                  (before?.bytes ?? 0),
                                          },
                                      ];
                            },
                        );
                    const recovery =
                        copy === undefined && recoveryOperations.has(position);
                    const interruptedOperation = recovery
                        ? recoveryOperations.get(position)
                        : undefined;
                    // The deadline ends with its operation so that no timer
                    // outlives the run.
                    const deadline = new AbortController();
                    const evaluation = async () =>
                        (await Promise.race([
                            chrome.evaluate(
                                `window.runParticipant(${JSON.stringify(operation)}, ${JSON.stringify(parameters)})`,
                            ),
                            delay(operationMilliseconds, undefined, {
                                signal: deadline.signal,
                            }).then(() => {
                                throw new Error(
                                    'Participant operation deadline.',
                                );
                            }),
                        ])) as WorkerResult;
                    let result: WorkerResult;
                    let cpuProfile: CpuProfileSummary | undefined;
                    try {
                        if (cpuProfileDirectory === undefined)
                            result = await evaluation();
                        else {
                            const traced = await chrome.trace(evaluation);
                            result = traced.result;
                            cpuProfile = summarizeCpuTrace(
                                traced.events,
                                cpuProfileEntries,
                            );
                        }
                    } catch (error) {
                        recordAttempt('interrupted');
                        log.writeEvent({
                            eventType: 'participant-interrupted-operation',
                            details: {
                                position,
                                operation,
                                ...(copy === undefined ? {} : { copy }),
                                milliseconds: performance.now() - started,
                                recovery,
                                interruptedOperation,
                                originTransfer: { ...transfers[position] },
                                publicRecordReads: publicRecordReads(),
                            },
                        });
                        throw guardFailure ?? error;
                    } finally {
                        deadline.abort();
                    }
                    assert.ok(result.status !== 'evaluated');
                    recordAttempt(
                        result.status,
                        result.status === 'completed'
                            ? result.details
                            : undefined,
                    );
                    if (guardFailure !== undefined) throw guardFailure;
                    if (scalar && result.status === 'completed')
                        requireScalarMemory(result.details);
                    const milliseconds = performance.now() - started;
                    if (
                        recovery &&
                        result.status === 'completed' &&
                        operation !== 'status'
                    )
                        recoveryOperations.delete(position);
                    // A ballot or release generated in this visit drew the
                    // modelled proof randomness.
                    if (
                        result.status === 'completed' &&
                        result.details.proofRandomBytes !== undefined
                    )
                        assert.equal(
                            BigInt(result.details.proofRandomBytes as number),
                            operation === 'ballot'
                                ? proofDraws.ballot
                                : proofDraws.release,
                            `${operation} at position ${String(position)} drew other proof randomness.`,
                        );
                    log.writeEvent({
                        eventType: 'participant-operation',
                        details: {
                            position,
                            ...(copy === undefined ? {} : { copy }),
                            operation,
                            milliseconds,
                            recovery,
                            interruptedOperation,
                            originTransfer: { ...transfers[position] },
                            publicRecordReads: publicRecordReads(),
                            result,
                        },
                    });
                    if (
                        cpuProfile !== undefined &&
                        cpuProfileDirectory !== undefined
                    )
                        await writeFile(
                            path.join(
                                cpuProfileDirectory,
                                `${String(++profiledOperations).padStart(4, '0')}-${String(position)}${copy === undefined ? '' : '-' + copy}-${operation}.json`,
                            ),
                            JSON.stringify(
                                {
                                    position,
                                    ...(copy === undefined ? {} : { copy }),
                                    operation,
                                    status: result.status,
                                    milliseconds,
                                    ...cpuProfile,
                                },
                                null,
                                2,
                            ) + '\n',
                            { flag: 'wx' },
                        );
                    return result;
                });
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
            // In a result run of a profile that tolerates two corrupt
            // participants, the organizer's proposal can leave out two honest
            // ones, the last two before the last position. The departing one
            // leaves with its private state after preparation, casting
            // nothing. The relay hides the other's on-time ballot from every
            // other participant and delays its close response until the
            // proposal exists, so the proposal omits that ballot.
            const outsiders =
                mode === 'result' && maximumCorruptParticipantCount >= 2
                    ? positions
                          .filter(
                              (position) =>
                                  position > 0 &&
                                  position < participantCount - 1 &&
                                  honest(position),
                          )
                          .slice(-2)
                    : [];
            const omittedVoter: number | undefined = outsiders[0];
            const departing: number | undefined = outsiders[1];
            // Reads the generation of a participant's committed head from its
            // own page, reading nothing else.
            const headGeneration = async (position: number, copy?: string) =>
                Number(
                    await inBrowser(position, copy, (chrome) =>
                        chrome.evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open(${JSON.stringify(participantDatabase)});
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
        const database = opening.result;
        const reading = database.transaction('head').objectStore('head').get(0);
        reading.onsuccess = () => { database.close(); resolve(reading.result?.generation ?? 0); };
        reading.onerror = () => { database.close(); reject(reading.error); };
    };
})`),
                    ),
                );
            const retainedHead = async (position: number, copy?: string) =>
                inBrowser(position, copy, (chrome) =>
                    chrome.evaluate(`new Promise((resolve,reject) => {
    const opening=indexedDB.open(${JSON.stringify(participantDatabase)});
    opening.onerror=()=>reject(opening.error);
    opening.onsuccess=()=>{ const database=opening.result; const reading=database.transaction('head').objectStore('head').get(0);
        reading.onsuccess=()=>{database.close();resolve(reading.result);};
        reading.onerror=()=>{database.close();reject(reading.error);}; };
})`),
                ) as Promise<{
                    generation: number;
                    hash: string;
                    runtime: string;
                }>;
            // Counts a participant's records in one store from its own page,
            // reading none of them.
            const storedRecords = async (position: number, store: string) =>
                Number(
                    await inBrowser(position, undefined, (chrome) =>
                        chrome.evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open(${JSON.stringify(participantDatabase)});
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
        const database = opening.result;
        const counting = database.transaction(${JSON.stringify(store)}).objectStore(${JSON.stringify(store)}).count();
        counting.onsuccess = () => { database.close(); resolve(counting.result); };
        counting.onerror = () => { database.close(); reject(counting.error); };
    };
})`),
                    ),
                );
            // Ends a participant's browser as a crash would. Its committed
            // state is what the next launch finds, while Chrome's own
            // shutdown can outlast its deadline when other browsers write.
            const endBrowser = async (position: number) => {
                await browsers.crash(participantBrowser(position));
            };
            // Runs a participant's operation in a browser that caps each
            // WebAssembly memory at the pressure pages. Exhausting that bound
            // leaves the participant pending, not stopped, whatever its
            // operation retained; the capped browser then ends.
            const pressure = async (position: number, operation: string) => {
                await endBrowser(position);
                pressured.add(position);
                try {
                    const before = await headGeneration(position);
                    const result = await request(position, operation);
                    assert.ok(
                        result.status === 'pending' &&
                            result.cause === 'resource' &&
                            result.reason.includes(
                                'exhausted its memory bound',
                            ),
                        `${operation} at position ${String(position)} under memory pressure: ${JSON.stringify(result)}`,
                    );
                    const details = {
                        position,
                        operation,
                        pages: pressurePages,
                        before,
                        generation: await headGeneration(position),
                        reason: result.reason,
                    };
                    memoryPressures.push(details);
                    log.writeEvent({
                        eventType: 'participant-memory-pressure',
                        details,
                    });
                } finally {
                    await endBrowser(position);
                    pressured.delete(position);
                }
            };
            // Copies a participant's private state into its own Chrome
            // profile at the participant's origin, whose browser opens when
            // the copy acts. The participant's browser ends first, so the
            // copy holds exactly the committed state its next launch would
            // find; crash reporting state is not participant state, and its
            // handler can outlive the browser.
            const copyState = async (position: number, copy: string) => {
                await endBrowser(position);
                await cp(profile(position), copyProfile(copy), {
                    recursive: true,
                    errorOnExist: true,
                    force: false,
                    filter: (source) =>
                        path.relative(profile(position), source) !== 'Crashpad',
                });
                copies.set(copy, position);
            };
            const removeCopy = async (copy: string) => {
                await browsers.crash(copyBrowser(copy));
                copies.delete(copy);
                await rm(copyProfile(copy), {
                    recursive: true,
                    maxRetries: 10,
                    retryDelay: 500,
                });
            };
            const sourceCustody: (SourceCustodyObservation & {
                position: number;
                stage: string;
            })[] = [];
            const sourceRefusals: Record<string, unknown>[] = [];
            const inspectSourceCustody = async (
                position: number,
                stage: string,
                copy?: string,
                mutation?: 'missing' | 'damaged',
            ) => {
                assert.ok(preparationStorageBundle);
                const observed = (await inBrowser(position, copy, (chrome) =>
                    chrome.evaluate(
                        preparationStorageBundle +
                            '\nparticipantPreparationFixture.inspectParticipantSourceCustody(' +
                            JSON.stringify({
                                namespace: participantNamespace,
                                runtimeIdentity: runtime.identity.runtime,
                                moduleDigest: runtime.identity.module,
                                mutation,
                            }) +
                            ');',
                    ),
                )) as SourceCustodyObservation;
                const required = observed.generation < 12;
                assert.equal(
                    observed.dataKeyBytes,
                    required ? 3 * 32 : 2 * 32,
                    'The root retained another data-key inventory.',
                );
                assert.equal(
                    observed.sourceReferences,
                    required ? 1 : 0,
                    'The root retained another source reference inventory.',
                );
                assert.equal(
                    observed.sourceRecords,
                    required ? 1 : 0,
                    'The data store retained another source capsule inventory.',
                );
                const details = { position, stage, ...observed };
                if (copy === undefined) sourceCustody.push(details);
                log.writeEvent({
                    eventType: 'participant-source-custody',
                    details: { ...details, copy, mutation },
                });
                return observed;
            };
            const refuseLostSource = async (
                position: number,
                operation: string,
            ) => {
                assert.ok(honest(position));
                assert.ok(relay);
                for (const mutation of ['missing', 'damaged'] as const) {
                    const copy = `source-${mutation}-${position}-${operation}`;
                    await copyState(position, copy);
                    try {
                        const before = await retainedHead(position, copy);
                        const observed = await inspectSourceCustody(
                            position,
                            'before fault',
                            copy,
                            mutation,
                        );
                        assert.ok(observed.generation < 12);
                        const publications: number =
                            relay.publicationAttempts[position];
                        const refused = await request(
                            position,
                            operation,
                            {},
                            copy,
                        );
                        assert.deepEqual(refused, {
                            status: 'stopped',
                            stopPersistence: 'confirmed',
                            reason:
                                mutation === 'missing'
                                    ? 'Participant data inventory changed.'
                                    : 'A participant data record changed.',
                        });
                        assert.deepEqual(
                            await retainedHead(position, copy),
                            before,
                            'A damaged source replaced the original root authority.',
                        );
                        await browsers.crash(copyBrowser(copy));
                        const stopped = await request(
                            position,
                            'status',
                            {},
                            copy,
                        );
                        assert.deepEqual(stopped, {
                            status: 'stopped',
                            stopPersistence: 'confirmed',
                            reason: 'Missing or inconsistent participant authority.',
                        });
                        const replacement = await request(
                            position,
                            'create',
                            {
                                role: 'join',
                                poll: organizer.poll,
                                definition: hexadecimal(definition),
                                definitionSignature:
                                    hexadecimal(definitionSignature),
                                username: 'Replacement refused',
                            },
                            copy,
                        );
                        assert.deepEqual(replacement, {
                            status: 'refused',
                            reason: 'participant exists',
                        });
                        assert.deepEqual(
                            await retainedHead(position, copy),
                            before,
                        );
                        assert.equal(
                            relay.publicationAttempts[position],
                            publications,
                            'A source fault caused a relay publication attempt.',
                        );
                        const details = {
                            position,
                            generation: observed.generation,
                            operation,
                            mutation,
                            result: refused,
                            coldResult: stopped,
                            replacement,
                            publicationAttempts: 0,
                        };
                        sourceRefusals.push(details);
                        log.writeEvent({
                            eventType: 'participant-source-refusal',
                            details,
                        });
                    } finally {
                        await removeCopy(copy);
                    }
                }
            };
            // Loses the last record of one store in a copy of an honest
            // participant's state and runs the operation there: the copy
            // stops with its stop persisted and stays stopped, and the copy
            // is deleted. The participant itself continues unaffected.
            const stateLosses: {
                position: number;
                store: string;
                record: unknown;
                operation: string;
                generation: number;
                reason: string;
            }[] = [];
            const loseState = async (
                position: number,
                store: string,
                operation: string,
                noPublications = false,
            ) => {
                assert.ok(honest(position), 'Only honest state is lost.');
                const copy = `lost-${store}-${String(position)}`;
                await copyState(position, copy);
                try {
                    const generation = await headGeneration(position, copy);
                    const record: unknown = await inBrowser(
                        position,
                        copy,
                        (chrome) =>
                            chrome.evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open(${JSON.stringify(participantDatabase)});
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
        const database = opening.result;
        const fail = (error) => { database.close(); reject(error); };
        const deleting = database.transaction(${JSON.stringify(store)}, 'readwrite');
        const reading = deleting.objectStore(${JSON.stringify(store)}).openCursor(null, 'prev');
        let key;
        reading.onerror = () => fail(reading.error);
        reading.onsuccess = () => {
            if (reading.result === null) return fail(new Error('No record to lose.'));
            key = reading.result.key;
            reading.result.delete();
        };
        deleting.oncomplete = () => { database.close(); resolve(key); };
        deleting.onabort = () => fail(deleting.error);
    };
})`),
                    );
                    const publicationAttempts =
                        relay!.publicationAttempts[position];
                    const result = await request(position, operation, {}, copy);
                    assert.ok(
                        result.status === 'stopped' &&
                            result.stopPersistence === 'confirmed',
                        `${operation} after losing a ${store} record at position ${String(position)}: ${JSON.stringify(result)}`,
                    );
                    assert.deepEqual(
                        await request(position, 'status', {}, copy),
                        {
                            status: 'stopped',
                            reason: 'Missing or inconsistent participant authority.',
                            stopPersistence: 'confirmed',
                        },
                    );
                    if (noPublications)
                        assert.equal(
                            relay!.publicationAttempts[position],
                            publicationAttempts,
                            'Missing required preparation state caused a relay publication.',
                        );
                    const loss = {
                        position,
                        store,
                        record,
                        operation,
                        generation,
                        reason: result.reason,
                        ...(noPublications ? { publicationAttempts: 0 } : {}),
                    };
                    stateLosses.push(loss);
                    log.writeEvent({
                        eventType: 'participant-state-loss',
                        details: loss,
                    });
                } finally {
                    await removeCopy(copy);
                }
            };
            // Loads a halting client in the participant's next browser, whose
            // participant stops for good once it durably enters the
            // generation.
            const armHalt = async (position: number, generation: number) => {
                assert.ok(honest(position), 'Only an honest client halts.');
                await endBrowser(position);
                halting.set(
                    position,
                    haltingClient(runtime.worker, generation),
                );
            };
            // Runs an operation in a halting client. The browser crashes once
            // its participant enters the generation, with no shutdown work
            // after that commit, and the next visit runs the runtime's own
            // worker again.
            const interruptions: {
                position: number;
                operation: string;
                generation: number;
                // The records an interrupted operation had stored ahead of
                // its next root.
                staged?: Readonly<{ store: string; records: number }>;
                // The public record the relay had delivered to the
                // interrupted operation.
                delivered?: string;
                preparation?: PreparationCut;
            }[] = [];
            const interrupt = async (
                position: number,
                operation: string,
                parameters: Record<string, unknown>,
                generation: number,
            ) => {
                if (halting.get(position)?.generation !== generation)
                    await armHalt(position, generation);
                try {
                    const halted = request(position, operation, parameters);
                    for (;;) {
                        const settled = await Promise.race([
                            halted.then(
                                (result) => JSON.stringify(result),
                                (error: unknown) => String(error),
                            ),
                            delay(500, undefined),
                        ]);
                        assert.equal(
                            settled,
                            undefined,
                            `${operation} at position ${String(position)} ended before generation ${String(generation)}: ${String(settled)}`,
                        );
                        if ((await headGeneration(position)) === generation)
                            break;
                    }
                    await endBrowser(position);
                    await assert.rejects(halted);
                } finally {
                    halting.delete(position);
                }
                recoveryOperations.set(position, operation);
                interruptions.push({ position, operation, generation });
                log.writeEvent({
                    eventType: 'participant-interruption',
                    details: { position, operation, generation },
                });
            };
            const interruptPreparation = async (
                position: number,
                operation: string,
                cut: PreparationCut,
            ) => {
                assert.ok(honest(position));
                await endBrowser(position);
                halting.set(
                    position,
                    preparationHaltingClient(runtime.worker, cut),
                );
                try {
                    const pending = request(position, operation);
                    for (;;) {
                        const outcome = await Promise.race([
                            pending.then(
                                (result) => JSON.stringify(result),
                                (error: unknown) => String(error),
                            ),
                            delay(250, undefined),
                        ]);
                        assert.equal(
                            outcome,
                            undefined,
                            `${operation} ended before ${cut.kind} phase ${String(cut.phase)}: ${String(outcome)}`,
                        );
                        const reached = await inBrowser(
                            position,
                            undefined,
                            (chrome) =>
                                chrome.evaluate('window.preparationHalt'),
                        );
                        if (reached !== null && reached !== undefined) {
                            assert.deepEqual(reached, {
                                type: 'participant-preparation-halt',
                                ...cut,
                            });
                            break;
                        }
                    }
                    assert.equal(await headGeneration(position), 4);
                    await endBrowser(position);
                    await assert.rejects(pending);
                } finally {
                    halting.delete(position);
                }
                recoveryOperations.set(position, operation);
                interruptions.push({
                    position,
                    operation,
                    generation: 4,
                    preparation: cut,
                });
                log.writeEvent({
                    eventType: 'participant-preparation-interruption',
                    details: { position, operation, ...cut },
                });
            };
            // Crashes a participant's browser while its operation, in the
            // generation it durably entered, has reached a point ahead of its
            // next root, and records that point. The next visit discards what
            // the operation stored and runs it again from its retained state.
            const interruptWhen = async (
                position: number,
                operation: string,
                generation: number,
                reached: () => Promise<boolean>,
                point: () => Promise<
                    Pick<(typeof interruptions)[number], 'staged' | 'delivered'>
                >,
            ) => {
                const interrupted = request(position, operation);
                for (;;) {
                    const outcome = await Promise.race([
                        interrupted.then(
                            () => 'settled',
                            () => 'settled',
                        ),
                        delay(250, 'waiting'),
                    ]);
                    assert.equal(
                        outcome,
                        'waiting',
                        `${operation} at position ${String(position)} ended before its interruption in generation ${String(generation)}.`,
                    );
                    if (
                        (await headGeneration(position)) === generation &&
                        (await reached())
                    )
                        break;
                }
                await endBrowser(position);
                await assert.rejects(interrupted);
                assert.equal(
                    await headGeneration(position),
                    generation,
                    'The interrupted operation committed its next root first.',
                );
                const details = {
                    position,
                    operation,
                    generation,
                    ...(await point()),
                };
                recoveryOperations.set(position, operation);
                interruptions.push(details);
                log.writeEvent({
                    eventType: 'participant-interruption',
                    details,
                });
            };
            // Interrupts an operation once it stored at least the given
            // records in one store.
            const interruptStaged = (
                position: number,
                operation: string,
                generation: number,
                store: string,
                records: number,
            ) =>
                interruptWhen(
                    position,
                    operation,
                    generation,
                    async () =>
                        (await storedRecords(position, store)) >= records,
                    async () => ({
                        staged: {
                            store,
                            records: await storedRecords(position, store),
                        },
                    }),
                );
            const paddingInterruptions: {
                position: number;
                observation: Readonly<{
                    slots: readonly PaddingSlotObservation[];
                    halt: PaddingHaltObservation;
                }>;
                head: Readonly<{
                    generation: number;
                    hash: string;
                    runtime: string;
                }>;
                checkpointRecords: number;
                originalWorkerSha512: string;
                instrumentedWorkerSha512: string;
                instrumentationMilliseconds: number;
            }[] = [];
            const interruptPadding = async (
                position: number,
                cut: PaddingCut,
            ) => {
                const client = paddingClients?.get(cut);
                assert.ok(client);
                await endBrowser(position);
                halting.set(position, client);
                try {
                    const before = await retainedHead(position);
                    assert.equal(before.generation, 4);
                    const checkpointRecords = await storedRecords(
                        position,
                        'checkpoint',
                    );
                    assert.ok(checkpointRecords > 0);
                    const interrupted = request(position, 'contribute');
                    let observation: {
                        slots: PaddingSlotObservation[];
                        halt: PaddingHaltObservation | null;
                    };
                    for (;;) {
                        const settled = await Promise.race([
                            interrupted.then(
                                () => true,
                                () => true,
                            ),
                            delay(250, false),
                        ]);
                        assert.equal(
                            settled,
                            false,
                            'Contribution ended without reaching the requested padding cut; no reseed or skipped case is allowed.',
                        );
                        observation = (await inBrowser(
                            position,
                            undefined,
                            (chrome) => chrome.evaluate('window.paddingReplay'),
                        )) as typeof observation;
                        if (observation.halt !== null) break;
                    }
                    assert.ok(observation.halt);
                    assert.equal(observation.halt.cut, cut);
                    const captured = {
                        slots: observation.slots,
                        halt: observation.halt,
                    };
                    validatePaddingObservation(
                        captured,
                        bounds.contribution,
                        chunkBytes,
                    );
                    assert.deepEqual(
                        await retainedHead(position),
                        before,
                        'Padding changed its original continuation root before the cut.',
                    );
                    assert.equal(
                        await storedRecords(position, 'checkpoint'),
                        checkpointRecords,
                    );
                    assert.equal(
                        await storedRecords(position, 'contribution'),
                        bounds.contribution.publicRecords.length +
                            captured.slots.length,
                    );
                    await endBrowser(position);
                    await assert.rejects(interrupted);
                    const entry = {
                        position,
                        observation: captured,
                        head: before,
                        checkpointRecords,
                        originalWorkerSha512: client.originalDigest,
                        instrumentedWorkerSha512: client.digest,
                        instrumentationMilliseconds: captured.slots.reduce(
                            (sum, slot) =>
                                sum + slot.instrumentationMilliseconds,
                            0,
                        ),
                    };
                    paddingInterruptions.push(entry);
                    interruptions.push({
                        position,
                        operation: 'contribute',
                        generation: 4,
                        preparation: { kind: 'contribution', phase: 6 },
                        staged: {
                            store: 'contribution',
                            records:
                                bounds.contribution.publicRecords.length +
                                captured.slots.length,
                        },
                    });
                    recoveryOperations.set(position, 'contribute');
                    log.writeEvent({
                        eventType: 'participant-padding-interruption',
                        details: entry,
                    });
                } finally {
                    halting.delete(position);
                }
            };
            // Interrupts an operation once the relay delivered it the named
            // public record.
            const interruptDelivered = (
                position: number,
                operation: string,
                generation: number,
                name: string,
            ) => {
                deliveredRecords[position].clear();
                return interruptWhen(
                    position,
                    operation,
                    generation,
                    () => Promise.resolve(deliveredRecords[position].has(name)),
                    () => Promise.resolve({ delivered: name }),
                );
            };
            // Each participant scores every option differently, across the
            // supported score range, and the result lists one option fewer
            // than the complete ranking. In a result run the first honest
            // participant after the organizer casts the all-minimum ballot,
            // an ordinary valid ballot that counts like any other.
            const { minimumScore, maximumScore } = bounds.ballot;
            const minimumBallotAuthor =
                mode === 'result'
                    ? positions.find(
                          (position) => position > 0 && honest(position),
                      )
                    : undefined;
            const ballotScores = (position: number) =>
                Array.from({ length: optionCount }, (_unused, option) =>
                    position === minimumBallotAuthor
                        ? minimumScore
                        : minimumScore +
                          ((position * (optionCount + 1) + option) %
                              (maximumScore - minimumScore + 1)),
                );
            const question =
                mode === 'preparation'
                    ? 'Verify original participant preparation'
                    : 'Verify the complete signed ballot path';
            const labels = Array.from(
                { length: optionCount },
                (_unused, index) => `Option ${String(index)}`,
            );
            const hexadecimal = (bytes: Uint8Array) =>
                Buffer.from(bytes).toString('hex');
            // The poll admits exactly the roster's participants.
            const organizer = await run(0, 'create', {
                role: 'creator',
                question,
                options: labels,
                topCount,
                maximumParticipants: participantCount,
                username: 'Organizer',
            });
            assert.equal(organizer.isOrganizer, true);
            // Every participant reports the poll its module verified: the
            // question, each option's identifier and label, and the result
            // length.
            const verifiedPoll = (details: Record<string, unknown>) => ({
                question: details.question,
                options: details.options,
                topCount: details.topCount,
            });
            const createdPoll = {
                question,
                options: labels.map((label, index) => ({
                    identifier: `option-${String(index)}`,
                    label,
                })),
                topCount,
            };
            assert.deepEqual(verifiedPoll(organizer), createdPoll);
            // The page asked the browser to keep the origin's storage, which
            // it grants by its own policy.
            assert.equal(typeof organizer.persistentStorage, 'boolean');
            await run(0, 'publish');
            // An operation on an empty namespace is refused and leaves it
            // empty, so that participant still joins below.
            if (mode !== 'plain') await expectStatus(1, 'status', 'refused');
            const definition = await readFile(
                path.join(publicDirectory, 'poll-definition.bin'),
            );
            const definitionSignature = await readFile(
                path.join(publicDirectory, 'poll-signature.bin'),
            );
            const join = async (position: number, username: string) => {
                const details = await run(position, 'create', {
                    role: 'join',
                    poll: organizer.poll,
                    definition: hexadecimal(definition),
                    definitionSignature: hexadecimal(definitionSignature),
                    username,
                });
                assert.equal(details.isOrganizer, false);
                assert.equal(details.poll, organizer.poll);
                assert.deepEqual(verifiedPoll(details), createdPoll);
                await run(position, 'publish');
                return details;
            };
            // A roster member acts at its origin, or in a copy of the
            // organizer's private state.
            type Member = Readonly<{ origin: number; copy?: string }>;
            const act = async (
                member: Member,
                operation: string,
                parameters: Record<string, unknown> = {},
            ) => {
                const result = await request(
                    member.origin,
                    operation,
                    parameters,
                    member.copy,
                );
                assert.ok(
                    result.status === 'completed',
                    `${operation} at origin ${String(member.origin)}${member.copy === undefined ? '' : ' in copy ' + member.copy}: ${JSON.stringify(result)}`,
                );
                return result.details;
            };
            // A roster's record identifiers: the organizer's registration,
            // then the joined participants' in order.
            const rosterRecordIds = (
                joined: readonly Record<string, unknown>[],
            ) =>
                [organizer, ...joined].map((details) =>
                    String(details.bodyDigest),
                );
            // The ordered option identifiers the scores rank first.
            const rankedIdentifiers = (
                scores: readonly (readonly number[])[],
            ) => {
                const optionTotals = Array.from(
                    { length: optionCount },
                    (_unused, option) =>
                        scores.reduce(
                            (total, score) => total + score[option],
                            0,
                        ),
                );
                return Array.from(
                    { length: optionCount },
                    (_unused, option) => option,
                )
                    .sort(
                        (left, right) =>
                            optionTotals[right] - optionTotals[left] ||
                            left - right,
                    )
                    .slice(0, topCount)
                    .map((option) => `option-${String(option)}`);
            };
            // Completes one roster from its proposal to its combined
            // result, every member acting as soon as its inputs exist.
            // Every member casts a counted ballot and releases. Ordinary
            // measurement also gives every member target and result work;
            // fault schedules retain quorum target voters and one combiner.
            const setupDiscoveryFaults: Record<string, unknown>[] = [];
            const publicationRecoveryEvidence: Record<string, unknown>[] = [];
            const incompleteResponseEvidence: Record<string, unknown>[] = [];
            const unselectedCheckpointEvidence: Record<string, unknown>[] = [];
            const selectionForkEvidence: Record<string, unknown>[] = [];
            const inspectCheckpoint = async (
                stage: string,
                copy?: string,
                damageCheckpoint = false,
            ) => {
                assert.ok(preparationStorageBundle);
                const started = performance.now();
                const observation = (await inBrowser(1, copy, (chrome) =>
                    chrome.evaluate(
                        preparationStorageBundle +
                            '\nparticipantPreparationFixture.inspectParticipantCheckpointCustody(' +
                            JSON.stringify({
                                namespace: participantNamespace,
                                runtimeIdentity: runtime.identity.runtime,
                                moduleDigest: runtime.identity.module,
                                damageCheckpoint,
                            }) +
                            ');',
                    ),
                )) as CheckpointCustodyObservation;
                assert.equal(observation.position, 1);
                const entry = {
                    stage,
                    copy,
                    ...observation,
                    instrumentationMilliseconds: performance.now() - started,
                };
                unselectedCheckpointEvidence.push(entry);
                log.writeEvent({
                    eventType: 'participant-unselected-checkpoint',
                    details: entry,
                });
                return observation;
            };
            const sameOwnCheckpoint = (
                before: CheckpointCustodyObservation,
                after: CheckpointCustodyObservation,
            ) => {
                for (const field of [
                    'phase',
                    'position',
                    'ownJournalSha512',
                    'headerSha512',
                    'recordInventorySha512',
                    'contributionRecords',
                    'checkpointRecords',
                ] as const)
                    assert.deepEqual(
                        after[field],
                        before[field],
                        'Endorsement changed the original own checkpoint: ' +
                            field,
                    );
            };
            const completeRoster = async (
                members: readonly Member[],
                recordIds: readonly string[],
                scores: readonly (readonly number[])[],
                absent?: number,
            ) => {
                const organizing = members[0];
                const incompleteResponder =
                    publicationFaults && maximumCorruptParticipantCount > 0
                        ? 1
                        : undefined;
                let active = members.flatMap((member, position) =>
                    position === absent ? [] : [{ member, position }],
                );
                let accepting = active.filter(({ position }) => position !== 0);
                const markStage = (stages: number[], actors = active) => {
                    if (measureWorkflow)
                        for (const { member } of actors)
                            measuredStages[member.origin] = [...stages];
                };
                const each = async (
                    actors: typeof active,
                    action: (member: (typeof active)[number]) => Promise<void>,
                ) => {
                    if (sequential) {
                        for (const member of actors) await action(member);
                    } else await Promise.all(actors.map(action));
                };
                const contributing = active
                    .filter(
                        ({ position }) =>
                            position < eligibleContributorCount &&
                            !(unselectedCheckpoint && position === 1),
                    )
                    .slice(
                        0,
                        selectionFork
                            ? eligibleContributorCount
                            : setupContributorCount,
                    );
                assert.equal(
                    contributing.length,
                    selectionFork
                        ? eligibleContributorCount
                        : setupContributorCount,
                );
                const confirmAndContribute = async (
                    value: (typeof active)[number],
                ) => {
                    assert.equal(
                        (await act(value.member, 'confirm')).generation,
                        4,
                    );
                    if (
                        contributing.some(
                            ({ position }) => position === value.position,
                        )
                    ) {
                        if (measureRecovery && value.position === 0) {
                            assert.equal(value.member.copy, undefined);
                            await interruptPreparation(
                                value.member.origin,
                                'contribute',
                                { kind: 'contribution', phase: 5 },
                            );
                        }
                        assert.equal(
                            (await act(value.member, 'contribute')).generation,
                            4,
                        );
                    }
                };
                markStage([1]);
                assert.equal(
                    (await act(organizing, 'propose-roster', { recordIds }))
                        .generation,
                    3,
                );
                await act(organizing, 'publish');
                if (absent !== undefined) await depart(members[absent].origin);
                if (measureWorkflow) {
                    await confirmAndContribute(active[0]);
                    await each(accepting, async (value) => {
                        assert.equal(
                            (
                                await act(value.member, 'accept-roster', {
                                    recordIds,
                                })
                            ).generation,
                            3,
                        );
                        await confirmAndContribute(value);
                    });
                } else {
                    for (const details of await Promise.all(
                        accepting.map(({ member }) =>
                            act(member, 'accept-roster', { recordIds }),
                        ),
                    ))
                        assert.equal(details.generation, 3);
                    await Promise.all(
                        active.map(async ({ member }) => {
                            assert.equal(
                                (await act(member, 'confirm')).generation,
                                4,
                            );
                        }),
                    );
                }
                let originalCheckpoint:
                    CheckpointCustodyObservation | undefined;
                if (unselectedCheckpoint) {
                    assert.deepEqual(
                        active.map(({ position }) => position),
                        [0, 1, 2, 3],
                    );
                    assert.deepEqual(
                        contributing.map(({ position }) => position),
                        [0, 2],
                    );
                    await interruptPreparation(1, 'contribute', {
                        kind: 'contribution',
                        phase: 5,
                    });
                    originalCheckpoint = await inspectCheckpoint(
                        'original checkpoint',
                    );
                    assert.equal(originalCheckpoint.generation, 4);
                    assert.equal(originalCheckpoint.phase, 5);
                    assert.equal(originalCheckpoint.endorsement, null);
                    assert.ok(
                        originalCheckpoint.checkpointRecords > 0 &&
                            originalCheckpoint.contributionRecords > 0,
                    );
                    assert.match(
                        originalCheckpoint.ownJournalSha512 ?? '',
                        /^[0-9a-f]{128}$/u,
                    );
                    assert.equal(
                        await stat(
                            path.join(publicDirectory, 'contribution-1'),
                        ).catch(() => undefined),
                        undefined,
                    );
                }
                if (memoryPressure)
                    await pressure(contributing[1].member.origin, 'contribute');
                const contribute = async (member: Member) =>
                    assert.equal(
                        (await act(member, 'contribute')).generation,
                        4,
                    );
                if (absent !== undefined) {
                    assert.deepEqual(
                        contributing.map(({ position }) => position),
                        positions
                            .filter(
                                (position) =>
                                    position < eligibleContributorCount &&
                                    position !== absent,
                            )
                            .slice(0, setupContributorCount),
                    );
                    await contribute(contributing[0].member);
                    const badIdentity = 'a5'.repeat(64);
                    const announced = await inBrowser(2, undefined, (chrome) =>
                        chrome.evaluate(
                            `fetch('/offers/2', { method: 'POST', body: new Uint8Array(64).fill(165) }).then(response => response.status)`,
                        ),
                    );
                    assert.equal(announced, 204);
                    const before = await retainedHead(0);
                    assert.equal(before.generation, 4);
                    const pending = await request(0, 'select-setup');
                    assert.deepEqual(pending, {
                        status: 'pending',
                        cause: 'public input',
                        reason: 'Too few complete eligible contribution offers are available.',
                    });
                    assert.deepEqual(
                        await retainedHead(0),
                        before,
                        'An invalid discovery hint consumed the selection intent.',
                    );
                    assert.equal(
                        await stat(
                            path.join(publicDirectory, 'selection.bin'),
                        ).catch(() => undefined),
                        undefined,
                    );
                    await Promise.all(
                        contributing
                            .slice(1)
                            .map(({ member }) => contribute(member)),
                    );
                    const announcements = await inBrowser(
                        2,
                        undefined,
                        (chrome) =>
                            chrome.evaluate(`fetch('/offers/2?offset=0').then(async response => {
                        if (!response.ok) throw new Error('Offer announcements unavailable.');
                        const bytes = new Uint8Array(await response.arrayBuffer());
                        const view = new DataView(bytes.buffer);
                        const count = view.getUint32(8, true);
                        if (view.getBigUint64(0, true) !== 2n || bytes.length !== 12 + count * 64) throw new Error('Malformed discovery page.');
                        return Array.from({ length: count }, (_, index) => Array.from(bytes.subarray(12 + index * 64, 12 + (index + 1) * 64), value => value.toString(16).padStart(2, '0')).join(''));
                    })`),
                    );
                    assert.deepEqual(announcements, [
                        badIdentity,
                        (
                            await generatedOfferIdentity(publicDirectory, 2)
                        ).toString('hex'),
                    ]);
                    const fault = {
                        position: 2,
                        invalidAnnouncementFirst: true,
                        laterValidAnnouncementPreserved: true,
                        result: pending,
                        originalSelectionIntentUnused: true,
                    };
                    setupDiscoveryFaults.push(fault);
                    log.writeEvent({
                        eventType: 'participant-offer-discovery-fault',
                        details: fault,
                    });
                } else if (!measureWorkflow)
                    await Promise.all(
                        contributing.map(({ member }) => contribute(member)),
                    );
                if (
                    absent !== undefined &&
                    maximumCorruptParticipantCount === 2
                ) {
                    // The original signed offer remains a selected input after
                    // its author loses its entire profile, before selection.
                    await depart(members[2].origin);
                    active = active.filter(({ position }) => position !== 2);
                    accepting = accepting.filter(
                        ({ position }) => position !== 2,
                    );
                    assert.equal(departed.size, maximumCorruptParticipantCount);
                    assert.equal(
                        active.length,
                        participantCount - maximumCorruptParticipantCount,
                    );
                    log.writeEvent({
                        eventType: 'participant-departed-after-offer',
                        details: {
                            position: 2,
                            originalOffer: (
                                await generatedOfferIdentity(publicDirectory, 2)
                            ).toString('hex'),
                        },
                    });
                }
                markStage([2]);
                if (selectionFork) {
                    const copy = 'losing-selection';
                    await copyState(0, copy);
                    try {
                        await act({ origin: 0, copy }, 'select-setup');
                        const losingBody = await readFile(
                            path.join(publicDirectory, 'selection.bin'),
                        );
                        await act(active[1].member, 'endorse-setup');
                        const originalEndorsement = await readFile(
                            path.join(
                                publicDirectory,
                                'selection-endorsement-1.bin',
                            ),
                        );
                        const hidden =
                            'contribution-1/' +
                            (
                                await generatedOfferIdentity(publicDirectory, 1)
                            ).toString('hex') +
                            '/offer.bin';
                        views[0].set(hidden, undefined);
                        try {
                            await act(organizing, 'select-setup');
                        } finally {
                            views[0].delete(hidden);
                        }
                        const winningBody = await readFile(
                            path.join(publicDirectory, 'selection.bin'),
                        );
                        const winningSignature = await readFile(
                            path.join(
                                publicDirectory,
                                'selection-signature.bin',
                            ),
                        );
                        assert.notDeepEqual(winningBody, losingBody);
                        const selectedPositions = (body: Uint8Array) => {
                            const fields = tupleFields(body);
                            const entries = Buffer.from(fields[2]);
                            return Array.from(
                                { length: entries.readUInt32LE(4) },
                                (_, index) =>
                                    entries.readUInt16LE(8 + index * 66),
                            );
                        };
                        assert.deepEqual(selectedPositions(losingBody), [0, 1]);
                        assert.deepEqual(
                            selectedPositions(winningBody),
                            [0, 2],
                        );
                        for (const position of [2, 3, 1]) {
                            const before =
                                position === 1
                                    ? await retainedHead(position)
                                    : undefined;
                            views[position].set('selection.bin', winningBody);
                            views[position].set(
                                'selection-signature.bin',
                                winningSignature,
                            );
                            try {
                                await act(
                                    active[position].member,
                                    'endorse-setup',
                                );
                            } finally {
                                views[position].delete('selection.bin');
                                views[position].delete(
                                    'selection-signature.bin',
                                );
                            }
                            if (position === 1)
                                assert.deepEqual(
                                    await retainedHead(position),
                                    before,
                                );
                        }
                        assert.deepEqual(
                            await readFile(
                                path.join(
                                    publicDirectory,
                                    'selection-endorsement-1.bin',
                                ),
                            ),
                            originalEndorsement,
                        );
                        const evidence = {
                            corruptOrganizer: 0,
                            losingEndorser: 1,
                            losingPositions: selectedPositions(losingBody),
                            winningPositions: selectedPositions(winningBody),
                            originalEndorsementRetained: true,
                        };
                        selectionForkEvidence.push(evidence);
                        log.writeEvent({
                            eventType:
                                'participant-losing-endorsement-retained',
                            details: evidence,
                        });
                    } finally {
                        await removeCopy(copy);
                    }
                } else {
                    assert.equal(
                        (await act(organizing, 'select-setup')).generation,
                        4,
                    );
                    await each(accepting, async ({ member }) => {
                        assert.equal(
                            (await act(member, 'endorse-setup')).generation,
                            4,
                        );
                    });
                }
                if (unselectedCheckpoint) {
                    assert.ok(originalCheckpoint);
                    assert.ok(relay);
                    const endorsed = await inspectCheckpoint(
                        'endorsed with unused checkpoint',
                    );
                    assert.equal(endorsed.generation, 4);
                    assert.equal(endorsed.endorsement, 'signed');
                    sameOwnCheckpoint(originalCheckpoint, endorsed);
                    assert.equal(
                        await stat(
                            path.join(publicDirectory, 'contribution-1'),
                        ).catch(() => undefined),
                        undefined,
                    );
                    const copy = 'damaged-unselected-checkpoint';
                    await copyState(1, copy);
                    try {
                        const before = await retainedHead(1, copy);
                        const damaged = await inspectCheckpoint(
                            'damaged isolated checkpoint copy',
                            copy,
                            true,
                        );
                        sameOwnCheckpoint(originalCheckpoint, damaged);
                        assert.ok(damaged.damagedRecord);
                        assert.notEqual(
                            damaged.damagedRecord.beforeSha512,
                            damaged.damagedRecord.afterSha512,
                        );
                        const attempts = relay.publicationAttempts[1];
                        const rejected = await request(
                            1,
                            'verify-setup',
                            {},
                            copy,
                        );
                        assert.ok(
                            rejected.status === 'stopped' &&
                                rejected.stopPersistence === 'confirmed',
                            JSON.stringify(rejected),
                        );
                        assert.deepEqual(
                            await retainedHead(1, copy),
                            before,
                            'Damaged activation replaced the original preparation root.',
                        );
                        assert.equal(
                            relay.publicationAttempts[1],
                            attempts,
                            'Damaged checkpoint activation attempted a publication.',
                        );
                        await browsers.crash(copyBrowser(copy));
                        assert.deepEqual(await request(1, 'status', {}, copy), {
                            status: 'stopped',
                            reason: 'Missing or inconsistent participant authority.',
                            stopPersistence: 'confirmed',
                        });
                        assert.equal(relay.publicationAttempts[1], attempts);
                        const fault = {
                            stage: 'damaged checkpoint activation refused',
                            position: 1,
                            result: rejected,
                            publicationAttempts: 0,
                        };
                        unselectedCheckpointEvidence.push(fault);
                        log.writeEvent({
                            eventType:
                                'participant-unselected-checkpoint-fault',
                            details: fault,
                        });
                    } finally {
                        await removeCopy(copy);
                    }
                    const healthy = await inspectCheckpoint(
                        'healthy original before activation',
                    );
                    sameOwnCheckpoint(originalCheckpoint, healthy);
                    assert.equal(healthy.endorsement, 'signed');
                }
                const castBallot = async ({
                    member,
                    position,
                }: (typeof active)[number]) => {
                    if (
                        publicationFaults &&
                        (position === 0 || position === incompleteResponder)
                    ) {
                        assert.ok(relay);
                        const key = 'ballot-' + String(position);
                        relay.refusedKeys.add(key);
                        try {
                            const pending = await request(
                                member.origin,
                                'ballot',
                                { scores: scores[position] },
                                member.copy,
                            );
                            assert.equal(pending.status, 'pending');
                            const head = await retainedHead(
                                member.origin,
                                member.copy,
                            );
                            assert.equal(head.generation, 17);
                            assert.equal(
                                await stat(
                                    path.join(
                                        publicDirectory,
                                        key + '/submission.bin',
                                    ),
                                ).catch(() => undefined),
                                undefined,
                            );
                            const evidence = {
                                position,
                                stage: 'signed ballot without completed publication',
                                result: pending,
                                generation: head.generation,
                            };
                            publicationRecoveryEvidence.push(evidence);
                            log.writeEvent({
                                eventType:
                                    'participant-publication-interruption',
                                details: evidence,
                            });
                        } finally {
                            relay.refusedKeys.delete(key);
                        }
                    } else {
                        if (measureRecovery && position === 0)
                            await interrupt(
                                member.origin,
                                'ballot',
                                { scores: scores[position] },
                                15,
                            );
                        assert.equal(
                            (
                                await act(member, 'ballot', {
                                    scores: scores[position],
                                })
                            ).generation,
                            17,
                        );
                    }
                };
                markStage([3]);
                await each(active, async ({ member, position }) => {
                    const verified = await act(member, 'verify-setup');
                    assert.equal(verified.generation, 12);
                    assert.equal(verified.ballot, 'open');
                    if (measureWorkflow) await castBallot({ member, position });
                });
                if (unselectedCheckpoint) {
                    const retired = await inspectCheckpoint(
                        'certified setup retired unused checkpoint',
                    );
                    assert.equal(retired.generation, 12);
                    assert.equal(retired.phase, null);
                    assert.equal(retired.ownJournalSha512, null);
                    assert.equal(retired.endorsement, null);
                    assert.equal(retired.contributionRecords, 0);
                    assert.equal(retired.checkpointRecords, 0);
                    assert.equal(
                        await stat(
                            path.join(publicDirectory, 'contribution-1'),
                        ).catch(() => undefined),
                        undefined,
                    );
                }
                if (!measureWorkflow) await Promise.all(active.map(castBallot));
                // A close collects every other participant's published ballot
                // with its body.
                markStage([4]);
                const authors = active.map(({ position }) => position);
                const collectsEvery = (position: number) => [
                    { kind: 'own', position },
                    ...authors
                        .filter(
                            (author) =>
                                author !== position &&
                                (!publicationFaults ||
                                    (author !== 0 &&
                                        author !== incompleteResponder)),
                        )
                        .map((author) => ({ kind: 'held', position: author })),
                ];
                await Promise.all(
                    accepting.map(async ({ member, position }) => {
                        const collected = await act(member, 'close');
                        assert.equal(collected.generation, 17);
                        assert.deepEqual(
                            collected.closeEvents,
                            collectsEvery(position),
                        );
                    }),
                );
                const opened = await act(organizing, 'close', {
                    closeTime: Date.now(),
                });
                assert.equal(opened.generation, 19);
                assert.deepEqual(opened.closeEvents, [
                    ...collectsEvery(0),
                    { kind: 'lock' },
                ]);
                await Promise.all(
                    accepting.map(async ({ member, position }) => {
                        if (position === incompleteResponder) {
                            assert.ok(relay);
                            const key = 'close-response-' + String(position);
                            relay.refusedKeys.add(key);
                            try {
                                const pending = await request(
                                    member.origin,
                                    'close',
                                    {},
                                    member.copy,
                                );
                                assert.equal(pending.status, 'pending');
                                assert.equal(
                                    await headGeneration(
                                        member.origin,
                                        member.copy,
                                    ),
                                    21,
                                );
                            } finally {
                                relay.refusedKeys.delete(key);
                            }
                            const complete = relay.refusedCandidates.get(key);
                            assert.ok(complete);
                            const original = decodeCandidateManifest(complete);
                            const files = original.files.filter(
                                (file) =>
                                    file.name === 'response.bin' ||
                                    file.name === 'submissions.bin',
                            );
                            assert.equal(files.length, 2);
                            assert.ok(original.files.length > files.length);
                            // A corrupt sender publishes its real signed response
                            // and envelopes, withholding every body reference.
                            const carrier = encodeCandidateManifest({ files });
                            const published = await fetch(
                                origin(position) + '/candidates/' + key,
                                {
                                    method: 'POST',
                                    body: new Uint8Array(carrier),
                                },
                            );
                            assert.equal(published.status, 200);
                            await published.arrayBuffer();
                            return;
                        }
                        assert.equal(
                            (await act(member, 'close')).generation,
                            21,
                        );
                    }),
                );
                if (incompleteResponder !== undefined) {
                    await depart(members[incompleteResponder].origin);
                    active = active.filter(
                        ({ position }) => position !== incompleteResponder,
                    );
                }
                markStage([4, 5], [active[0]]);
                const concluded = await act(organizing, 'close');
                assert.equal(concluded.generation, 22);
                if (incompleteResponder !== undefined) {
                    const receivedResponses = (
                        concluded.closeEvents as { kind: string }[]
                    ).filter((event) => event.kind === 'response').length;
                    assert.equal(receivedResponses, bounds.close.quorum);
                    const proposal = await readFile(
                        path.join(publicDirectory, 'close/proposal.bin'),
                    );
                    assert.equal(
                        proposal.length,
                        4 +
                            bounds.close.proposalBodyBytes +
                            bounds.registration.signatureBytes,
                    );
                    const proposalResponders = Array.from(
                        { length: bounds.close.quorum },
                        (_, ordinal) =>
                            proposal.readUInt16LE(
                                4 +
                                    bounds.close.proposalBodyBytes -
                                    (bounds.close.quorum - ordinal) * 66,
                            ),
                    );
                    assert.deepEqual(
                        proposalResponders,
                        active
                            .slice(0, bounds.close.quorum)
                            .map(({ position }) => position),
                    );
                    const evidence = {
                        unavailableResponder: incompleteResponder,
                        receivedResponses,
                        proposalResponders,
                    };
                    incompleteResponseEvidence.push(evidence);
                    log.writeEvent({
                        eventType: 'participant-incomplete-close-response',
                        details: evidence,
                    });
                }
                markStage([5]);
                await each(
                    measureWorkflow
                        ? active
                        : active.slice(0, bounds.close.quorum),
                    async ({ member, position }) => {
                        if (measureRecovery && position === 0)
                            await interrupt(
                                member.origin,
                                'target',
                                {},
                                targetPhase.intent,
                            );
                        const voted = await act(member, 'target');
                        assert.equal(voted.generation, 24);
                        assert.equal(voted.ballotStatus, 'included');
                        assert.equal(voted.usableBallots, active.length);
                        assert.equal(voted.validBallots, active.length);
                    },
                );
                markStage([6]);
                await each(active, async ({ member, position }) => {
                    if (measureRecovery && position === 0)
                        await interrupt(member.origin, 'release', {}, 27);
                    const details = await act(member, 'release');
                    assert.equal(details.generation, 29);
                    assert.equal(details.encrypted, true);
                });
                markStage([7]);
                const expected = rankedIdentifiers(
                    active.map(({ position }) => scores[position]),
                );
                await each(
                    measureWorkflow ? active : [active[active.length - 1]],
                    async ({ member }) => {
                        const combined = await act(member, 'result');
                        assert.equal(combined.encrypted, true);
                        assert.deepEqual(combined.identifiers, expected);
                    },
                );
                return expected;
            };
            if (
                mode === 'plain' ||
                setupDeparture ||
                unselectedCheckpoint ||
                selectionFork
            ) {
                // Every other participant joins, and the roster completes
                // each stage once.
                const joined = await Promise.all(
                    positions
                        .slice(1)
                        .map((position) =>
                            join(position, `Participant ${String(position)}`),
                        ),
                );
                const plainRecordIds = rosterRecordIds(joined);
                const identifiers = await completeRoster(
                    positions.map((position) => ({ origin: position })),
                    plainRecordIds,
                    positions.map(ballotScores),
                    setupDeparture ? 1 : undefined,
                );
                let independentOutcome: WorkerResult | undefined;
                let standaloneMilliseconds: number | undefined;
                if (measureRecovery) {
                    assert.deepEqual(
                        interruptions.map((cut) => [
                            cut.position,
                            cut.operation,
                            cut.preparation?.phase ?? cut.generation,
                        ]),
                        [
                            [0, 'contribute', 5],
                            [0, 'ballot', 15],
                            [0, 'target', targetPhase.intent],
                            [0, 'release', 27],
                        ],
                    );
                    assert.equal(
                        ordinaryOperations.filter(
                            (operation) => operation.outcome === 'interrupted',
                        ).length,
                        4,
                    );
                    assert.equal(recoveryOperations.size, 0);
                    for (const position of positions) await depart(position);
                    const started = performance.now();
                    independentOutcome = (await inBrowser(
                        leftOut,
                        undefined,
                        (chrome) =>
                            chrome.evaluate(
                                'window.verifyOutcome(' +
                                    JSON.stringify(organizer.poll) +
                                    ')',
                            ),
                    )) as WorkerResult;
                    standaloneMilliseconds = performance.now() - started;
                    assert.ok(independentOutcome.status === 'completed');
                    assert.deepEqual(
                        independentOutcome.details.identifiers,
                        identifiers,
                    );
                    if (scalar) requireScalarMemory(independentOutcome.details);
                    log.writeEvent({
                        eventType: 'participant-recovery-public-outcome',
                        details: {
                            milliseconds: standaloneMilliseconds,
                            retiredOriginalParticipants: [...departed],
                            independentOutcome,
                        },
                    });
                }

                if (setupDeparture || unselectedCheckpoint) {
                    assert.deepEqual(
                        [...departed],
                        setupDeparture
                            ? participantCount === 7
                                ? [1, 2]
                                : [1]
                            : [],
                    );
                    assert.equal(
                        await stat(
                            path.join(publicDirectory, 'contribution-1'),
                        ).catch(() => undefined),
                        undefined,
                    );
                    if (setupDeparture)
                        assert.equal(
                            await stat(
                                path.join(
                                    publicDirectory,
                                    'selection-endorsement-1.bin',
                                ),
                            ).catch(() => undefined),
                            undefined,
                        );
                    const selection = await readFile(
                        path.join(publicDirectory, 'selection.bin'),
                    );
                    const fields = tupleFields(selection);
                    assert.equal(fields.length, 3);
                    const rosterIdentity = Buffer.from(fields[1]).toString(
                        'hex',
                    );
                    const selected = await Promise.all(
                        positions
                            .filter(
                                (position) =>
                                    position < eligibleContributorCount &&
                                    position !== 1,
                            )
                            .slice(0, setupContributorCount)
                            .map(async (position) => ({
                                position,
                                bodyIdentity: (
                                    await generatedOfferIdentity(
                                        publicDirectory,
                                        position,
                                    )
                                ).toString('hex'),
                            })),
                    );
                    assert.deepEqual(
                        selection,
                        encodeSetupSelectionModel(
                            participantCount,
                            rosterIdentity,
                            selected,
                        ),
                    );
                    assert.equal(
                        (
                            await readFile(
                                path.join(
                                    publicDirectory,
                                    'setup-identity.bin',
                                ),
                            )
                        ).toString('hex'),
                        setupSelectionIdentityModel(
                            participantCount,
                            rosterIdentity,
                            selected,
                        ),
                    );
                    const certificate = await readFile(
                        path.join(publicDirectory, 'setup-certificate.bin'),
                    );
                    assert.equal(
                        certificate.subarray(0, 4).toString('ascii'),
                        'SSC1',
                    );
                    const endorsementOffset =
                        8 +
                        certificate.readUInt32LE(4) +
                        bounds.registration.signatureBytes;
                    assert.deepEqual(
                        Array.from(
                            { length: bounds.close.quorum },
                            (_, ordinal) =>
                                certificate.readUInt16LE(
                                    endorsementOffset +
                                        ordinal *
                                            (2 +
                                                bounds.registration
                                                    .signatureBytes),
                                ),
                        ),
                        positions
                            .filter((position) => !departed.has(position))
                            .slice(0, bounds.close.quorum),
                    );
                    independentOutcome = (await inBrowser(
                        leftOut,
                        undefined,
                        (chrome) =>
                            chrome.evaluate(
                                `window.verifyOutcome(${JSON.stringify(organizer.poll)})`,
                            ),
                    )) as WorkerResult;
                    assert.equal(independentOutcome.status, 'completed');
                    assert.ok(independentOutcome.status === 'completed');
                    assert.equal(independentOutcome.details.encrypted, true);
                    assert.deepEqual(
                        independentOutcome.details.identifiers,
                        identifiers,
                    );
                }
                if (publicationFaults) {
                    assert.equal(
                        publicationRecoveryEvidence.length,
                        maximumCorruptParticipantCount > 0 ? 2 : 1,
                    );
                    assert.equal(
                        incompleteResponseEvidence.length,
                        maximumCorruptParticipantCount > 0 ? 1 : 0,
                    );
                    assert.ok(relay.publicationFaultEvidence.length > 0);
                    for (const key of [
                        'poll',
                        'roster',
                        'selection',
                        'setup-certificate',
                        'close-intent',
                        'close-proposal',
                        'target-vote-0',
                        'release-0',
                    ])
                        assert.ok(
                            relay.publicationFaultEvidence.some(
                                (entry) =>
                                    entry.key === key &&
                                    entry.changed !== undefined,
                            ),
                            'Missing genuine-verifier refusal control for ' +
                                key,
                        );
                    for (const position of positions)
                        if (!departed.has(position)) await depart(position);
                    independentOutcome = (await inBrowser(
                        leftOut,
                        undefined,
                        (chrome) =>
                            chrome.evaluate(
                                'window.verifyOutcome(' +
                                    JSON.stringify(organizer.poll) +
                                    ')',
                            ),
                    )) as WorkerResult;
                    assert.ok(independentOutcome.status === 'completed');
                    assert.deepEqual(
                        independentOutcome.details.identifiers,
                        identifiers,
                    );
                    log.writeEvent({
                        eventType:
                            'participant-publication-candidates-verified',
                        details: {
                            candidates: relay.publicationFaultEvidence,
                            retiredOriginalParticipants: [...departed],
                            independentOutcome,
                        },
                    });
                }
                if (selectionFork) {
                    assert.equal(selectionForkEvidence.length, 1);
                    independentOutcome = (await inBrowser(
                        leftOut,
                        undefined,
                        (chrome) =>
                            chrome.evaluate(
                                'window.verifyOutcome(' +
                                    JSON.stringify(organizer.poll) +
                                    ')',
                            ),
                    )) as WorkerResult;
                    assert.ok(independentOutcome.status === 'completed');
                    assert.deepEqual(
                        independentOutcome.details.identifiers,
                        identifiers,
                    );
                }
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify(
                        {
                            participantCount,
                            optionCount,
                            mode,
                            sequential,
                            recovery: measureRecovery,
                            ...(measureRecovery
                                ? {
                                      interruptions,
                                      standaloneMilliseconds,
                                  }
                                : {}),
                            scalar,
                            setupDeparture,
                            unselectedCheckpoint,
                            publicationFaults,
                            selectionFork,
                            ...(selectionFork ? { selectionForkEvidence } : {}),
                            ...(publicationFaults
                                ? {
                                      publicationFaultEvidence:
                                          relay.publicationFaultEvidence,
                                      publicationRecoveryEvidence,
                                      incompleteResponseEvidence,
                                  }
                                : {}),
                            ...(setupDeparture
                                ? {
                                      departedAfterRoster: 1,
                                      ...(participantCount === 7
                                          ? { departedAfterOffer: 2 }
                                          : {}),
                                      cooperativeCorruptPositions: [2],
                                      activePositions: positions.filter(
                                          (position) => !departed.has(position),
                                      ),
                                      selectedPositions: positions
                                          .filter(
                                              (position) =>
                                                  position <
                                                      eligibleContributorCount &&
                                                  position !== 1,
                                          )
                                          .slice(0, setupContributorCount),
                                  }
                                : {}),
                            ...(unselectedCheckpoint
                                ? {
                                      cooperativeCorruptPositions: [2],
                                      activePositions: [0, 1, 2, 3],
                                      selectedPositions: [0, 2],
                                      unselectedCheckpointEvidence,
                                      interruptions,
                                  }
                                : {}),
                            independentOutcome,
                            setupDiscoveryFaults,
                            poll: organizer.poll,
                            recordIds: plainRecordIds,
                            runtimeIdentity: runtime.identity.runtime,
                            peakProcessTreeBytes: peaks,
                            identifiers,
                            topCount,
                            profiled: profiling,
                            memoryPressures,
                            transfers,
                            sampledResources,
                            unmeasured: [
                                measureWorkflow
                                    ? 'Exact within-call allocation of organizer close work; explicit visit durations are conservative upper bounds'
                                    : 'Productive-visit traversal for this fault schedule',
                                'Exact transient browser and JavaScript memory peaks between samples',
                                'HTTP headers and link-layer transfer overhead',
                                'Human delays between visits',
                                'Physical-device performance and power use',
                            ],
                            workflow: measureWorkflow
                                ? summarizeParticipantWorkflow(
                                      ordinaryOperations,
                                      participantCount,
                                      sequential,
                                      ordinaryBootstraps,
                                  )
                                : null,
                            scope: [
                                setupDeparture
                                    ? "Original registrations fix one roster; honest eligible position one disappears immediately after roster publication, before confirmation or contribution. Position two announces an invalid body identity before its valid original offer; the organizer stays pending without consuming selection authority and later accepts the valid offer behind that hint. In the seven-participant case, position two also loses its entire profile after completing its offer but before selection, so the remaining quorum certifies setup containing the departed author's original contribution. Every surviving original member votes, closes, certifies the target and releases the verified result. Original positions and thresholds remain unchanged; the diagnostic fields identify the selected and active sets. This is the named external Chrome schedule, not a general adversarial-scheduling proof."
                                    : unselectedCheckpoint
                                      ? 'All four original participants remain available, with cooperative corrupt position two and no permanent departure in the real branch. Honest eligible position one retains its genuine phase-five checkpoint while positions zero and two are selected. It endorses without completing its own offer, preserves the original nested own state and encrypted records, then retires them only on certified setup activation and casts a ballot and releases. An isolated damaged-checkpoint copy stops before activation or publication; the healthy original continues. Diagnostic fingerprints stay separate from protocol authority. This is desktop development evidence, not phone qualification.'
                                      : 'Browser registration, roster confirmation, signed clear contribution offers, quorum setup selection and verification, ballots, close responses, target votes, release shares and the combined result of one roster, with the recorded stage and recovery schedule in the maintained participant runtime in external Chrome.',
                                ...(measureRecovery
                                    ? [
                                          'Original participant zero loses its worker and browser at the retained contribution checkpoint, ballot body, target signing intent and release body. Each following visit restores the original state. Workflow totals include every interrupted attempt, cold startup and completed recovery; the recorded cuts define this recovery workload. A fresh public reader verifies the outcome after every original participant departs, with its startup and work reported separately.',
                                      ]
                                    : []),
                                ...(profiling
                                    ? [
                                          'Chrome recorded the CPU samples of every operation, which slows it.',
                                      ]
                                    : []),
                                ...(selectionFork
                                    ? [
                                          'A corrupt organizer signs two selections from the same original credential in separate private copies. Honest position one keeps its one losing endorsement, accepts the certified selection of positions zero and two, and completes its ballot and release without issuing another endorsement. A fresh public reader verifies the same outcome.',
                                      ]
                                    : []),
                                ...(memoryPressure
                                    ? [
                                          'The second contributor first contributed in a browser that caps each WebAssembly memory below what its contribution needs, which left it pending, and its next visit completed the contribution.',
                                      ]
                                    : []),
                                ...(publicationFaults
                                    ? [
                                          'Every publication key receives an empty and a corrupted candidate before the genuine carrier. The organizer retains a signed ballot whose publication is refused and closes without retrying that ballot. Its closure publishes the exact required body, and a fresh standalone verifier retrieves the result after every original participant has departed.',
                                      ]
                                    : []),
                            ].join(' '),
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
                await finishAllocation();
                completed = true;
                process.stdout.write(log.runDirectoryPath + '\n');
                return;
            }
            if (mode === 'rosters') {
                // The organizer is corrupt: its private state is copied
                // before it proposes a roster, and the copy proposes a second
                // roster of the same poll to other registrants. The relay
                // serves each roster only its own records and shows the
                // second roster the poll and the organizer's registration.
                // The organizer is each roster's only corrupt member.
                assert.ok(
                    maximumCorruptParticipantCount >= 1 &&
                        secondRosterDirectory !== undefined,
                    'Two rosters need a profile that tolerates the corrupt organizer.',
                );
                await copyState(0, secondRosterCopy);
                for (const name of [
                    'poll-definition.bin',
                    'poll-signature.bin',
                    'registration/' + String(organizer.bodyDigest),
                    'transport',
                ])
                    await cp(
                        path.join(publicDirectory, name),
                        path.join(secondRosterDirectory, name),
                        { recursive: true, errorOnExist: true, force: false },
                    );
                const firstMembers: readonly Member[] = positions.map(
                    (position) => ({ origin: position }),
                );
                const secondMembers: readonly Member[] = positions.map(
                    (position) =>
                        position === 0
                            ? { origin: 0, copy: secondRosterCopy }
                            : { origin: participantCount - 1 + position },
                );
                const registrations = await Promise.all(
                    [...firstMembers.slice(1), ...secondMembers.slice(1)].map(
                        (member) =>
                            join(
                                member.origin,
                                `Participant ${String(member.origin)}`,
                            ),
                    ),
                );
                const firstRecordIds = rosterRecordIds(
                    registrations.slice(0, participantCount - 1),
                );
                const secondRecordIds = rosterRecordIds(
                    registrations.slice(participantCount - 1),
                );
                const [firstIdentifiers, secondIdentifiers] = await Promise.all(
                    [
                        completeRoster(
                            firstMembers,
                            firstRecordIds,
                            positions.map(ballotScores),
                        ),
                        completeRoster(
                            secondMembers,
                            secondRecordIds,
                            positions.map((position) =>
                                ballotScores(participantCount + position),
                            ),
                        ),
                    ],
                );
                // A relay view serves the second member of each roster the
                // other roster's records of one family at a time under its
                // own roster's names, the registrations by roster position.
                // The first record of each family its result visit reads is
                // refused, and it stays pending; the other roster's valid
                // registrations of the same poll are refused only as a
                // roster. The families its result visit does not read leave
                // it its roster's outcome, which it also reaches with the
                // relay's own records.
                const crossRosterProbes: {
                    origin: number;
                    family: string;
                    served: number;
                    hidden: number;
                    reason?: string;
                }[] = [];
                for (const [member, records, recordIds, other, identifiers] of [
                    [
                        firstMembers[1],
                        publicDirectory,
                        firstRecordIds,
                        {
                            publicDirectory: secondRosterDirectory,
                            recordIds: secondRecordIds,
                            leftOut: undefined,
                        },
                        firstIdentifiers,
                    ],
                    [
                        secondMembers[1],
                        secondRosterDirectory,
                        secondRecordIds,
                        {
                            publicDirectory,
                            recordIds: firstRecordIds,
                            leftOut: undefined,
                        },
                        secondIdentifiers,
                    ],
                ] as const) {
                    for (const { family, pattern, reason } of foreignFamilies) {
                        const { view, served } = await foreignRecordView(
                            other,
                            records,
                            recordIds,
                            pattern,
                        );
                        assert.ok(
                            served > 0,
                            `The other roster has no ${family}.`,
                        );
                        for (const [name, bytes] of view)
                            views[member.origin].set(name, bytes);
                        try {
                            if (reason === undefined)
                                assert.deepEqual(
                                    (await act(member, 'result')).identifiers,
                                    identifiers,
                                );
                            else
                                assert.deepEqual(
                                    await request(member.origin, 'result'),
                                    {
                                        status: 'pending',
                                        cause: 'public input',
                                        reason,
                                    },
                                );
                        } finally {
                            views[member.origin].clear();
                        }
                        crossRosterProbes.push({
                            origin: member.origin,
                            family,
                            served,
                            hidden: view.size - served,
                            reason,
                        });
                    }
                    assert.deepEqual(
                        (await act(member, 'result')).identifiers,
                        identifiers,
                    );
                }
                // Both rosters retain signed-envelope-before-body ordering.
                const rostersScope = [
                    "A corrupt organizer's private state is copied after its registration, and the copy proposes a second roster of the same poll to other registrants under its own path of the organizer's origin, where the relay serves that roster's records. Both rosters, whose only corrupt member is the organizer, complete roster agreement, setup contribution and verification, signed ballots, close responses, target votes, release shares and the combined result in parallel in the maintained participant runtime in external Chrome.",
                    `Relay views that serve one roster's ${prose(foreignFamilies.filter(({ reason }) => reason !== undefined).map(({ family }) => family))} under the other roster's names leave a member of each roster pending, and with the relay's own records it reaches its roster's outcome; its ${prose(foreignFamilies.filter(({ reason }) => reason === undefined).map(({ family }) => family))}, which a result visit that restores the verified setup and the evaluated target does not read, leave that member its roster's outcome.`,
                ].join(' ');
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify(
                        {
                            participantCount,
                            optionCount,
                            mode,
                            poll: organizer.poll,
                            recordIds: firstRecordIds,
                            runtimeIdentity: runtime.identity.runtime,
                            peakProcessTreeBytes: peaks,
                            copyPeakProcessTreeBytes:
                                Object.fromEntries(copyPeaks),
                            secondRoster: {
                                copy: secondRosterCopy,
                                origins: secondMembers.map(
                                    (member) => member.origin,
                                ),
                                recordIds: secondRecordIds,
                            },
                            results: {
                                first: firstIdentifiers,
                                second: secondIdentifiers,
                            },
                            crossRosterProbes,
                            topCount,
                            scope: rostersScope,
                            scalar,
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
                await finishAllocation();
                completed = true;
                process.stdout.write(log.runDirectoryPath + '\n');
                return;
            }
            // One more registrant joins beside the participants, and the
            // organizer leaves it out of the roster.
            const [joined, leftOutRegistration] = await Promise.all([
                Promise.all(
                    Array.from(
                        { length: participantCount - 1 },
                        (_unused, index) =>
                            join(index + 1, `Participant ${String(index + 1)}`),
                    ),
                ),
                join(leftOut, 'Registrant left out'),
            ]);
            const recordIds = [organizer, ...joined].map((value) =>
                String(value.bodyDigest),
            );
            // A proposal that also lists the registrant left out exceeds the
            // poll's participant maximum and is refused.
            assert.deepEqual(
                await request(0, 'propose-roster', {
                    recordIds: [
                        ...recordIds,
                        String(leftOutRegistration.bodyDigest),
                    ],
                }),
                { status: 'refused', reason: 'invalid request' },
            );
            // The organizer crashes with its proposal intent, and its next
            // visit verifies the records again and signs the locked proposal
            // deterministically. The last honest participant crashes
            // right after it retains the accepted roster, and its next visit
            // continues from that roster.
            await interrupt(0, 'propose-roster', { recordIds }, 2);
            const proposed = await run(0, 'propose-roster', { recordIds });
            assert.equal(proposed.generation, 3);
            await run(0, 'publish');
            const rosterReplay = [...positions]
                .reverse()
                .find((position) => position > 0 && honest(position));
            assert.ok(rosterReplay !== undefined);
            const accepted = await Promise.all(
                joined.map(async (_details, index) => {
                    const position = index + 1;
                    if (position !== rosterReplay)
                        return run(position, 'accept-roster', { recordIds });
                    await interrupt(
                        position,
                        'accept-roster',
                        { recordIds },
                        3,
                    );
                    return run(position, 'status');
                }),
            );
            for (const details of accepted) assert.equal(details.generation, 3);
            // The registrant left out stays pending when shown the roster
            // and keeps its registration; its browser then ends.
            assert.deepEqual(
                await request(leftOut, 'accept-roster', { recordIds }),
                {
                    status: 'pending',
                    cause: 'public input',
                    reason: 'The proposal omits this participant.',
                },
            );
            const leftOutStatus = await run(leftOut, 'status');
            assert.equal(leftOutStatus.generation, 1);
            assert.equal(
                leftOutStatus.bodyDigest,
                leftOutRegistration.bodyDigest,
            );
            await endBrowser(leftOut);
            // A second proposal, acceptance or enrollment is refused, and
            // every participant restores its retained state.
            await expectStatus(0, 'propose-roster', 'refused', { recordIds });
            await expectStatus(1, 'accept-roster', 'refused', { recordIds });
            // A malformed request is refused; the participant continues
            // below.
            assert.deepEqual(
                await request(1, 'accept-roster', {
                    recordIds: recordIds.map((id) => id.toUpperCase()),
                }),
                { status: 'refused', reason: 'invalid request' },
            );
            await expectStatus(1, 'create', 'refused', {
                role: 'join',
                poll: organizer.poll,
                definition: hexadecimal(definition),
                definitionSignature: hexadecimal(definitionSignature),
                username: 'Participant again',
            });
            // Eligibility is the fixed redundant pool; selection still uses d.
            const contributors = positions.slice(0, setupContributorCount);
            const noncontributors = positions.slice(eligibleContributorCount);
            const otherMembers = positions.filter(
                (position) => !contributors.includes(position),
            );
            for (const position of positions) {
                const status = await run(position, 'status');
                assert.equal(status.generation, 3);
                assert.equal(status.poll, organizer.poll);
                assert.equal(
                    status.isEligibleContributor,
                    position < eligibleContributorCount,
                );
                await expectStatus(position, 'contribute', 'refused');
            }
            const setupReplay = [...contributors].reverse().find(honest);
            assert.ok(setupReplay !== undefined);
            await interrupt(setupReplay, 'confirm', {}, 4);
            for (const position of positions)
                assert.equal((await run(position, 'confirm')).generation, 4);
            for (const position of noncontributors)
                await expectStatus(position, 'contribute', 'refused');
            await expectStatus(0, 'verify-setup', 'pending');
            await expectStatus(0, 'select-setup', 'pending');
            await expectStatus(1, 'select-setup', 'refused');
            if (mode === 'preparation') {
                for (const position of positions)
                    await inspectSourceCustody(position, 'confirmed roster');
                await refuseLostSource(setupReplay, 'contribute');
            }
            const bodyRecords = bounds.contribution.publicRecords.length;
            await Promise.all(
                contributors.map(async (position) => {
                    if (position === setupReplay) {
                        await interruptStaged(
                            position,
                            'contribute',
                            4,
                            'checkpoint',
                            1,
                        );
                        await interruptPreparation(position, 'contribute', {
                            kind: 'contribution',
                            phase: 5,
                        });
                        // Generic public retransmission must authenticate the
                        // same required own checkpoint as other g4 operations.
                        await loseState(
                            position,
                            'checkpoint',
                            'publish',
                            true,
                        );
                        await interruptStaged(
                            position,
                            'contribute',
                            4,
                            'contribution',
                            bodyRecords + 1,
                        );
                        if (mode === 'preparation') {
                            await interruptPadding(position, 'padding');
                            await interruptPadding(position, 'final-slot');
                            const [padding, final] = paddingInterruptions;
                            assert.deepEqual(
                                padding.head,
                                final.head,
                                'Padding replay recreated its continuation intent.',
                            );
                            assert.equal(
                                padding.observation.halt.proofBytes,
                                final.observation.halt.proofBytes,
                            );
                            for (const [
                                index,
                                slot,
                            ] of padding.observation.slots.entries())
                                assert.equal(
                                    slot.sha512,
                                    final.observation.slots[index].sha512,
                                    'Padding replay changed its original proof bytes.',
                                );
                            // Keep the unsigned complete body for authenticated
                            // damaged-padding probes before any offer publication.
                            await interruptPreparation(position, 'contribute', {
                                kind: 'contribution',
                                phase: 7,
                            });
                            return;
                        }
                        await interruptPreparation(position, 'contribute', {
                            kind: 'contribution',
                            phase: 8,
                        });
                    }
                    assert.equal(
                        (await run(position, 'contribute')).generation,
                        4,
                    );
                }),
            );
            const paddingRefusals: Record<string, unknown>[] = [];
            if (mode === 'preparation') {
                assert.ok(
                    preparationStorageBundle && setupReplay !== undefined,
                );
                for (const kind of ['missing', 'nonzero'] as const) {
                    const copy = 'padding-' + kind;
                    await copyState(setupReplay, copy);
                    try {
                        const mutation = await inBrowser(
                            setupReplay,
                            copy,
                            (chrome) =>
                                chrome.evaluate(
                                    preparationStorageBundle +
                                        '\nparticipantPreparationFixture.mutateParticipantPadding(' +
                                        JSON.stringify({
                                            namespace: participantNamespace,
                                            runtimeIdentity:
                                                runtime.identity.runtime,
                                            moduleDigest:
                                                runtime.identity.module,
                                            participants: participantCount,
                                            options: optionCount,
                                            position: setupReplay,
                                            kind,
                                        }) +
                                        ');',
                                ),
                        );
                        const before: number =
                            relay.publicationAttempts[setupReplay];
                        const rejected = await request(
                            setupReplay,
                            'contribute',
                            {},
                            copy,
                        );
                        assert.deepEqual(rejected, {
                            status: 'stopped',
                            stopPersistence: 'confirmed',
                            reason:
                                kind === 'nonzero'
                                    ? 'The private proof padding is nonzero.'
                                    : 'The contribution records changed.',
                        });
                        assert.equal(
                            relay.publicationAttempts[setupReplay],
                            before,
                            'A damaged private proof caused a relay publication attempt.',
                        );
                        const recorded = {
                            position: setupReplay,
                            kind,
                            mutation,
                            result: rejected,
                            publicationAttempts: 0,
                        };
                        paddingRefusals.push(recorded);
                        log.writeEvent({
                            eventType: 'participant-padding-refusal',
                            details: recorded,
                        });
                    } finally {
                        await removeCopy(copy);
                    }
                }
            }
            if (mode === 'preparation') {
                await interruptPreparation(setupReplay, 'contribute', {
                    kind: 'contribution',
                    phase: 8,
                });
                assert.equal(
                    (await run(setupReplay, 'contribute')).generation,
                    4,
                );
            }
            const offerDirectory = async (position: number) => {
                const identity = await generatedOfferIdentity(
                    publicDirectory,
                    position,
                );
                assert.equal(identity.length, 64);
                return (
                    'contribution-' +
                    String(position) +
                    '/' +
                    identity.toString('hex') +
                    '/'
                );
            };
            const replayedOffer = await offerDirectory(setupReplay);
            const replayedEnvelope = await readFile(
                path.join(publicDirectory, replayedOffer, 'offer.bin'),
            );
            const replayedSignature = await readFile(
                path.join(
                    publicDirectory,
                    replayedOffer,
                    'offer-signature.bin',
                ),
            );
            assert.equal((await run(setupReplay, 'contribute')).generation, 4);
            assert.deepEqual(
                await readFile(
                    path.join(publicDirectory, replayedOffer, 'offer.bin'),
                ),
                replayedEnvelope,
            );
            assert.deepEqual(
                await readFile(
                    path.join(
                        publicDirectory,
                        replayedOffer,
                        'offer-signature.bin',
                    ),
                ),
                replayedSignature,
            );
            const selectionReadbackFaults: Record<string, unknown>[] = [];
            await interruptPreparation(0, 'select-setup', {
                kind: 'selection',
                phase: 1,
            });
            await interruptPreparation(0, 'select-setup', {
                kind: 'selection',
                phase: 2,
            });
            const selectionHead = await retainedHead(0);
            for (const fault of ['missing', 'changed'] as const) {
                const name = 'selection-signature.bin';
                let changed: Buffer | undefined;
                if (fault === 'changed') {
                    changed = await readFile(path.join(publicDirectory, name));
                    changed[0] ^= 1;
                }
                views[0].set(name, changed);
                try {
                    const result = await request(0, 'select-setup');
                    assert.ok(
                        result.status === 'pending' &&
                            result.cause === 'public input',
                        JSON.stringify(result),
                    );
                    assert.deepEqual(
                        await retainedHead(0),
                        selectionHead,
                        'Failed selection readback changed the original signed selection or created endorsement intent.',
                    );
                    await assert.rejects(
                        stat(
                            path.join(
                                publicDirectory,
                                'selection-endorsement-0.bin',
                            ),
                        ),
                        { code: 'ENOENT' },
                    );
                    const recorded = {
                        fault,
                        result,
                        signedSelectionHead: selectionHead,
                    };
                    selectionReadbackFaults.push(recorded);
                    log.writeEvent({
                        eventType: 'participant-selection-readback-fault',
                        details: recorded,
                    });
                } finally {
                    views[0].delete(name);
                }
            }
            await interruptPreparation(0, 'select-setup', {
                kind: 'selection-readback',
                phase: 1,
            });
            for (const phase of [1, 2])
                await interruptPreparation(0, 'select-setup', {
                    kind: 'endorsement',
                    phase,
                });
            assert.equal((await run(0, 'select-setup')).generation, 4);
            const selectedBytes = await readFile(
                path.join(publicDirectory, 'selection.bin'),
            );
            assert.equal((await run(0, 'select-setup')).generation, 4);
            assert.deepEqual(
                await readFile(path.join(publicDirectory, 'selection.bin')),
                selectedBytes,
            );
            const endorsementReplay = [...positions].reverse().find(honest);
            assert.ok(endorsementReplay !== undefined);
            const finalOffer = await offerDirectory(
                contributors[contributors.length - 1],
            );
            const selectedProofFaults: Record<string, unknown>[] = [];
            const setupCacheSnapshot = async (position: number) =>
                (await inBrowser(position, undefined, (chrome) =>
                    chrome.evaluate(`new Promise((resolve, reject) => {
                const opening = indexedDB.open(${JSON.stringify(namespacedName(setupCacheName, participantNamespace))});
                opening.onerror = () => reject(opening.error);
                opening.onsuccess = () => {
                    const database = opening.result;
                    if (!database.objectStoreNames.contains('aggregate')) { database.close(); reject(new Error('No aggregate cache exists.')); return; }
                    const reading = database.transaction('aggregate').objectStore('aggregate').getAllKeys();
                    reading.onerror = () => { database.close(); reject(reading.error); };
                    reading.onsuccess = () => {
                        const keys = reading.result;
                        const ordinals = [...new Set(keys.filter(key => Array.isArray(key) && key.length === 3).map(key => key[0]))].sort();
                        database.close(); resolve({records: keys.length, ordinals});
                    };
                };
            })`),
                )) as { records: number; ordinals: number[] };
            if (mode === 'preparation') {
                const proofName = finalOffer + 'proof.bin';
                const faultDirectory = path.join(
                    log.artifactDirectoryPath,
                    'fault-inputs',
                );
                await mkdir(faultDirectory, { recursive: true });
                const damaged = path.join(
                    faultDirectory,
                    'late-selected-proof.bin',
                );
                const originalProofBytes = (
                    await stat(path.join(publicDirectory, proofName))
                ).size;
                assert.ok(
                    originalProofBytes >=
                        bounds.contribution.minimumProofBytes &&
                        originalProofBytes <=
                            bounds.contribution.maximumProofBytes,
                );
                await cp(path.join(publicDirectory, proofName), damaged, {
                    errorOnExist: true,
                    force: false,
                });
                const proof = await open(damaged, 'r+');
                try {
                    const length = (await proof.stat()).size;
                    assert.equal(length, originalProofBytes);
                    const last = Buffer.alloc(1);
                    assert.equal(
                        (await proof.read(last, 0, 1, length - 1)).bytesRead,
                        1,
                    );
                    last[0] ^= 1;
                    await proof.write(last, 0, 1, length - 1);
                    await proof.sync();
                } finally {
                    await proof.close();
                }
                let proofReads = 0;
                let overwritten:
                    { records: number; ordinals: number[] } | undefined;
                const head = await retainedHead(endorsementReplay);
                const attempts: number =
                    relay.publicationAttempts[endorsementReplay];
                views[endorsementReplay].set(proofName, {
                    file: damaged,
                    beforeServe: async () => {
                        proofReads++;
                        if (proofReads === 2) {
                            overwritten =
                                await setupCacheSnapshot(endorsementReplay);
                            assert.ok(overwritten.records > 0);
                            assert.deepEqual(
                                overwritten.ordinals,
                                [setupContributorCount - 1],
                                'The late-proof control did not observe replaced selected-polynomial chunks.',
                            );
                        }
                    },
                });
                try {
                    const result = await request(
                        endorsementReplay,
                        'endorse-setup',
                    );
                    assert.ok(
                        result.status === 'pending' &&
                            result.cause === 'public input',
                        JSON.stringify(result),
                    );
                    assert.ok(overwritten);
                    assert.deepEqual(
                        await setupCacheSnapshot(endorsementReplay),
                        { records: 0, ordinals: [] },
                    );
                    assert.deepEqual(
                        await retainedHead(endorsementReplay),
                        head,
                    );
                    assert.equal(
                        relay.publicationAttempts[endorsementReplay],
                        attempts,
                    );
                    const recorded = {
                        position: endorsementReplay,
                        proofReads,
                        overwritten,
                        result,
                        publicationAttempts: 0,
                    };
                    selectedProofFaults.push(recorded);
                    log.writeEvent({
                        eventType: 'participant-selected-proof-fault',
                        details: recorded,
                    });
                } finally {
                    views[endorsementReplay].delete(proofName);
                }
            }
            await Promise.all(
                positions.map(async (position) => {
                    if (position === endorsementReplay) {
                        // The first endorsement verifies all clear bodies;
                        // later activation may use its retained verification.
                        await interruptDelivered(
                            position,
                            'endorse-setup',
                            4,
                            finalOffer + 'offer.bin',
                        );
                        await interruptPreparation(position, 'endorse-setup', {
                            kind: 'endorsement',
                            phase: 1,
                        });
                        await interruptPreparation(position, 'endorse-setup', {
                            kind: 'endorsement',
                            phase: 2,
                        });
                    }
                    assert.equal(
                        (await run(position, 'endorse-setup')).generation,
                        4,
                    );
                    if (
                        mode === 'preparation' &&
                        position === endorsementReplay
                    ) {
                        const cache = await setupCacheSnapshot(position);
                        assert.ok(cache.records > 0);
                        assert.deepEqual(cache.ordinals, [
                            setupContributorCount - 1,
                        ]);
                        const recorded = {
                            position,
                            stage: 'original selected proof retry',
                            cache,
                        };
                        selectedProofFaults.push(recorded);
                        log.writeEvent({
                            eventType: 'participant-selected-proof-retry',
                            details: recorded,
                        });
                    }
                }),
            );
            await expectStatus(0, 'ballot', 'refused', {
                scores: ballotScores(0),
            });
            // A successful POST is insufficient: activation must read back
            // the complete named certificate before retiring preparation.
            // These views affect GET only; the relay still accepts each write.
            const setupPublicationFaults: Record<string, unknown>[] = [];
            const activationHead = await retainedHead(setupReplay);
            assert.equal(activationHead.generation, 4);
            const activationRecords = {
                contribution: await storedRecords(setupReplay, 'contribution'),
                checkpoint: await storedRecords(setupReplay, 'checkpoint'),
            };
            assert.ok(activationRecords.contribution > 0);
            assert.equal(
                await stat(
                    path.join(publicDirectory, 'setup-certificate.bin'),
                ).catch(() => undefined),
                undefined,
            );
            for (const changed of [undefined, Buffer.from([0])]) {
                const hidden = 'setup-certificate.bin';
                views[setupReplay].set(hidden, changed);
                const before = relay.publicationAttempts[setupReplay];
                try {
                    const pending = await request(setupReplay, 'verify-setup');
                    assert.deepEqual(pending, {
                        status: 'pending',
                        cause: 'public input',
                        reason:
                            changed === undefined
                                ? 'A public record is unavailable.'
                                : 'Published manifest readback differs.',
                    });
                    assert.ok(
                        relay.publicationAttempts[setupReplay] > before,
                        'Activation did not attempt the acknowledged setup publication.',
                    );
                    assert.ok(
                        (await stat(path.join(publicDirectory, hidden))).size >
                            0,
                        'The relay did not retain the acknowledged setup write.',
                    );
                    assert.deepEqual(
                        await retainedHead(setupReplay),
                        activationHead,
                        'A setup publication without readback changed the preparation root.',
                    );
                    assert.deepEqual(
                        {
                            contribution: await storedRecords(
                                setupReplay,
                                'contribution',
                            ),
                            checkpoint: await storedRecords(
                                setupReplay,
                                'checkpoint',
                            ),
                        },
                        activationRecords,
                        'A setup publication without readback retired own preparation.',
                    );
                    const fault = {
                        position: setupReplay,
                        hidden,
                        generation: 4,
                        result: pending,
                        acknowledgedWriteRetained: true,
                        originalPreparationRetained: true,
                    };
                    setupPublicationFaults.push(fault);
                    log.writeEvent({
                        eventType: 'participant-setup-publication-fault',
                        details: fault,
                    });
                } finally {
                    views[setupReplay].delete(hidden);
                }
            }
            const lateSetup =
                mode === 'empty' ? participantCount - 1 : undefined;
            const verificationReplay = [
                ...otherMembers,
                ...[...contributors].reverse(),
            ].find((position) => honest(position) && position !== lateSetup);
            assert.ok(verificationReplay !== undefined);
            if (mode === 'preparation')
                await refuseLostSource(verificationReplay, 'verify-setup');
            await Promise.all(
                positions
                    .filter((position) => position !== lateSetup)
                    .map(async (position) => {
                        if (position === verificationReplay) {
                            await interrupt(position, 'verify-setup', {}, 12);
                            const status = await run(position, 'status');
                            assert.equal(status.generation, 12);
                            assert.equal(status.ballot, 'open');
                            return;
                        }
                        const verified = await run(position, 'verify-setup');
                        assert.equal(verified.generation, 12);
                        assert.equal(verified.ballot, 'open');
                    }),
            );
            for (const position of positions.filter(
                (candidate) => candidate !== lateSetup,
            ))
                for (const operation of [
                    'confirm',
                    'contribute',
                    'select-setup',
                    'endorse-setup',
                    'verify-setup',
                ])
                    await expectStatus(position, operation, 'refused');
            if (mode === 'preparation') {
                const sourceRestarts: Record<string, unknown>[] = [];
                const publishedShape = async () =>
                    Promise.all(
                        (await publicRecordNames(publicDirectory))
                            .sort()
                            .map(async (name) => ({
                                name,
                                bytes: (
                                    await stat(path.join(publicDirectory, name))
                                ).size,
                            })),
                    );
                const publicBefore = await publishedShape();
                for (const position of positions) {
                    const before = await retainedHead(position);
                    assert.equal(before.generation, 12);
                    await inspectSourceCustody(position, 'verified setup');
                    await endBrowser(position);
                    const restored = await run(position, 'status');
                    assert.equal(restored.generation, 12);
                    assert.equal(restored.bodyDigest, recordIds[position]);
                    assert.equal(restored.ballot, 'open');
                    // With no closeTime and no published intent, close only
                    // restores the credential-authenticated setup and scans
                    // the empty ballot inventory; it creates no close intent.
                    const attempts: number =
                        relay.publicationAttempts[position];
                    const ready = await run(position, 'close');
                    assert.equal(ready.generation, 12);
                    assert.equal(ready.ballot, 'open');
                    assert.equal(relay.publicationAttempts[position], attempts);
                    assert.equal(
                        await storedRecords(position, 'contribution'),
                        0,
                    );
                    assert.equal(
                        await storedRecords(position, 'checkpoint'),
                        0,
                    );
                    assert.deepEqual(
                        await retainedHead(position),
                        before,
                        'Prepared recovery replaced the original root.',
                    );
                    await inspectSourceCustody(
                        position,
                        'cold prepared recovery',
                    );
                    const details = {
                        position,
                        generation: 12,
                        originalBodyDigest: recordIds[position],
                        restoredSetup: true,
                        privatePreparationRetired: true,
                    };
                    sourceRestarts.push(details);
                    log.writeEvent({
                        eventType: 'participant-prepared-source-recovery',
                        details,
                    });
                }
                // The relay compares every repeated span byte-for-byte;
                // unchanged names and lengths also exclude appended records.
                assert.deepEqual(
                    await publishedShape(),
                    publicBefore,
                    'Prepared recovery extended or replaced public setup records.',
                );
                assert.equal(paddingInterruptions.length, 2);
                const last = paddingInterruptions[1];
                const proofPath = path.join(
                    publicDirectory,
                    (await offerDirectory(last.position)) + 'proof.bin',
                );
                const header = await readFile(
                    path.join(
                        publicDirectory,
                        (await offerDirectory(last.position)) +
                            'body-header.bin',
                    ),
                );
                assert.equal(
                    header.length,
                    bounds.contribution.bodyHeaderBytes,
                );
                assert.equal(header.subarray(0, 4).toString('ascii'), 'SCB2');
                assert.equal(
                    header.readBigUInt64LE(4),
                    BigInt(last.observation.halt.proofBytes),
                );
                assert.equal(
                    (await stat(proofPath)).size,
                    last.observation.halt.proofBytes,
                    'Publication extended the logical proof with private padding.',
                );
                const published = await open(proofPath, 'r');
                const slotBytes = Buffer.alloc(chunkBytes);
                try {
                    for (const slot of last.observation.slots) {
                        slotBytes.fill(0);
                        const used = Math.max(
                            0,
                            Math.min(
                                slot.length,
                                last.observation.halt.proofBytes - slot.offset,
                            ),
                        );
                        let read = 0;
                        while (read < used) {
                            const result = await published.read(
                                slotBytes,
                                read,
                                used - read,
                                slot.offset + read,
                            );
                            assert.ok(result.bytesRead > 0);
                            read += result.bytesRead;
                        }
                        assert.equal(
                            createHash('sha512')
                                .update(slotBytes.subarray(0, slot.length))
                                .digest('hex'),
                            slot.sha512,
                            'Published proof differs from the private replay diagnostic.',
                        );
                    }
                } finally {
                    slotBytes.fill(0);
                    await published.close();
                }
                const [first, final] = paddingInterruptions.map(
                    (entry) => entry.observation.halt,
                );
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify(
                        {
                            participantCount,
                            optionCount,
                            mode,
                            scalar,
                            poll: organizer.poll,
                            recordIds,
                            runtimeIdentity: runtime.identity.runtime,
                            peakProcessTreeBytes: peaks,
                            transfers,
                            sampledResources,
                            interruptions,
                            paddingInterruptions,
                            paddingRefusals,
                            sourceCustody,
                            sourceRefusals,
                            stateLosses,
                            setupPublicationFaults,
                            selectionReadbackFaults,
                            selectedProofFaults,
                            sourceRestarts,
                            coincidentPaddingCuts:
                                first.slotOffset === final.slotOffset,
                            logicalProofBytes: last.observation.halt.proofBytes,
                            scope: 'Clear fixed-roster preparation only: local confirmation, real signed-offer generation and original-intent restart, organizer selection, quorum endorsements and every original member setup verifier. Missing or damaged required source capsules stop copied original namespaces; verified setup retires its source capsule and wrapping key, and cold recovery restores the original credential and setup without them. Before certification, contributors retransmit identical signed offers; certification retires private preparation while the public records remain retrievable. Harness-only pauses and private plaintext proof digests measure padding replay; their work is included in interrupted operations. This instrumented development run does not exercise departure tolerance, ballots or outcome and establishes no exact-build qualification or phone support.',
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
                await finishAllocation();
                completed = true;
                process.stdout.write(log.runDirectoryPath + '\n');
                return;
            }
            // The departing participant leaves after its preparation.
            if (departing !== undefined) await depart(departing);
            // Every participant that did not depart signs one ballot, the late
            // ones after the others. A result closes with every ballot but the
            // last on time, or with every ballot when a position equivocates.
            // A no-result target has one valid on-time ballot fewer than the
            // minimum turnout, from the honest positions just before the last,
            // and the invalid author's ballot on time, which would meet the
            // turnout if it counted. An empty close has no ballot at all. A
            // signed ballot refuses other scores and is only delivered again.
            const lastPosition = participantCount - 1;
            const ballotAuthors =
                mode === 'empty'
                    ? []
                    : positions.filter((position) => !departed.has(position));
            const onTimeCount =
                mode === 'empty'
                    ? 0
                    : noResult
                      ? minimumTurnout -
                        1 +
                        (invalidAuthor === undefined ? 0 : 1)
                      : equivocator === undefined
                        ? ballotAuthors.length - 1
                        : ballotAuthors.length;
            // The equivocator's slot is conflicting, so no ballot of it counts,
            // the omitted ballot is in no slot, and the invalid author's slot
            // is usable but its ballot invalid.
            const usableCount =
                onTimeCount -
                (equivocator === undefined ? 0 : 1) -
                (omittedVoter === undefined ? 0 : 1);
            const validCount =
                usableCount - (invalidAuthor === undefined ? 0 : 1);
            assert.ok(
                validCount >= (mode === 'empty' ? 0 : 1) &&
                    validCount >= minimumTurnout !== noResult,
            );
            const onTimeBallots =
                mode === 'no-result'
                    ? [
                          ...(invalidAuthor === undefined
                              ? []
                              : [invalidAuthor]),
                          ...positions
                              .filter(
                                  (position) =>
                                      position !== lastPosition &&
                                      honest(position),
                              )
                              .slice(1 - minimumTurnout),
                      ].sort((left, right) => left - right)
                    : ballotAuthors.slice(0, onTimeCount);
            assert.equal(onTimeBallots.length, onTimeCount);
            const lateBallots = ballotAuthors.filter(
                (position) => !onTimeBallots.includes(position),
            );
            // Before its ballot the equivocator's private state is copied
            // twice, and each copy acts in its own browser at the same origin.
            // All three correlated publications complete. Explicit discovery
            // views below choose which signed envelope each recipient sees.
            const ballotDiscoveryName = (author: number) =>
                'ballot-' + String(author) + '/submission.bin';
            if (equivocator !== undefined) {
                for (const copy of copyNames)
                    await copyState(equivocator, copy);
            }
            // The first honest authors halt between them at every ballot
            // generation: after the attempt lock, with the seed retained,
            // with the body and signing intent retained, and with the
            // signed ballot before its delivery.
            const ballotHalts = new Map(
                ballotAuthors
                    .filter(honest)
                    .slice(0, 3)
                    .map(
                        (position, index) =>
                            [position, [[13, 17], [14], [15]][index]] as const,
                    ),
            );
            const signBallot = async (position: number) => {
                const scores = ballotScores(position);
                // A signed ballot is only delivered again. A copy of the state
                // with the retained body loses a body record and stops.
                const halts = ballotHalts.get(position) ?? [];
                for (const generation of halts) {
                    await interrupt(position, 'ballot', { scores }, generation);
                    if (generation === 15)
                        await loseState(position, 'ballot', 'ballot');
                }
                assert.equal(
                    (
                        await run(
                            position,
                            'ballot',
                            halts.includes(17) ? {} : { scores },
                        )
                    ).generation,
                    17,
                );
            };
            // Each copy of the equivocator's state signs other scores.
            const signCopy = async (copy: string) => {
                assert.ok(equivocator !== undefined);
                const result = await request(
                    equivocator,
                    'ballot',
                    {
                        scores: ballotScores(
                            participantCount + copyNames.indexOf(copy),
                        ),
                    },
                    copy,
                );
                assert.ok(
                    result.status === 'completed',
                    JSON.stringify(result),
                );
                assert.equal(result.details.generation, 17);
            };
            // The on-time ballots and the conflicting copy's are signed
            // together, and the late ones, the late copy's among them, only
            // once every on-time ballot is signed, so that each late ballot is
            // timed after every on-time one.
            const copyBallots = (copy: string) =>
                equivocator === undefined ? [] : [signCopy(copy)];
            await Promise.all([
                ...onTimeBallots.map(signBallot),
                ...copyBallots('conflicting'),
            ]);
            await Promise.all([
                ...lateBallots.map(signBallot),
                ...copyBallots('late'),
            ]);
            if (equivocator !== undefined) {
                // Retransmit the original bytes and restore the diagnostic
                // inspection index before deleting the corrupt copies.
                assert.equal((await run(equivocator, 'ballot')).generation, 17);
                for (const copy of copyNames) await removeCopy(copy);
            }
            if (ballotAuthors.includes(0)) {
                await expectStatus(0, 'ballot', 'refused', {
                    scores: ballotScores(1),
                });
                assert.equal((await run(0, 'ballot')).generation, 17);
            }
            const ballotBounds = bounds.ballot;
            // The diagnostic index names an original submission for fixture inspection.
            const submissionDirectory = async (author: number) =>
                path.join(
                    publicDirectory,
                    'ballot-' + String(author),
                    (
                        await readFile(
                            path.join(
                                publicDirectory,
                                ballotDiscoveryName(author),
                            ),
                        )
                    ).toString('hex'),
                );
            for (const position of ballotAuthors) {
                const directory = await submissionDirectory(position);
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
                    bounds.registration.signatureBytes,
                );
            }
            // The organizer's close time is the latest on-time ballot time, so
            // a strictly later ballot is late: the intent lock retires it
            // wherever it was delivered, and no response lists it. An empty
            // close takes the time the organizer closes.
            const ballotTime = async (directory: string) =>
                Number(
                    (
                        await readFile(path.join(directory, 'envelope.bin'))
                    ).readBigUInt64LE(134),
                );
            const ballotTimes = new Map(
                await Promise.all(
                    ballotAuthors.map(
                        async (position) =>
                            [
                                position,
                                await ballotTime(
                                    await submissionDirectory(position),
                                ),
                            ] as const,
                    ),
                ),
            );
            // The equivocator's directory also holds one ballot from each
            // copy, the late copy's timed last.
            const equivocation =
                equivocator === undefined
                    ? undefined
                    : await (async () => {
                          const directory = path.join(
                              publicDirectory,
                              'ballot-' + String(equivocator),
                          );
                          const original = path.basename(
                              await submissionDirectory(equivocator),
                          );
                          const copied = await Promise.all(
                              (await readdir(directory))
                                  .filter(
                                      (entry) =>
                                          /^[0-9a-f]{128}$/u.test(entry) &&
                                          entry !== original,
                                  )
                                  .map(async (identity) => ({
                                      identity,
                                      time: await ballotTime(
                                          path.join(directory, identity),
                                      ),
                                  })),
                          );
                          assert.equal(copied.length, copyNames.length);
                          const [conflicting, late] = copied.sort(
                              (left, right) => left.time - right.time,
                          );
                          return {
                              position: equivocator,
                              original,
                              conflicting,
                              late,
                          };
                      })();
            if (equivocation !== undefined)
                for (const view of views)
                    view.set(
                        ballotDiscoveryName(equivocation.position),
                        Buffer.from(equivocation.original, 'hex'),
                    );
            const closeTime =
                mode === 'empty'
                    ? Date.now()
                    : Math.max(
                          ...onTimeBallots.map((position) => {
                              const time = ballotTimes.get(position);
                              assert.ok(time !== undefined);
                              return time;
                          }),
                          ...(equivocation === undefined
                              ? []
                              : [equivocation.conflicting.time]),
                      );
            const onTime = (position: number) =>
                (ballotTimes.get(position) ?? Infinity) <= closeTime;
            assert.deepEqual(
                ballotAuthors.filter((position) => !onTime(position)),
                lateBallots,
            );
            if (equivocation !== undefined)
                assert.ok(equivocation.late.time > closeTime);
            const others = (position: number) =>
                positions.filter((other) => other !== position);
            // The given positions that signed a ballot, and the generation a
            // participant's completed ballot or verified setup leaves.
            const cast = (authors: readonly number[]) =>
                authors.filter((author) => ballotAuthors.includes(author));
            // The relay shows the omitted ballot to its author alone.
            const shown = (position: number, authors: readonly number[]) =>
                authors.filter(
                    (author) =>
                        author !== omittedVoter || position === omittedVoter,
                );
            const beforeClose = mode === 'empty' ? 12 : 17;
            const submissions = (kind: string, authors: readonly number[]) =>
                authors.map((position) => ({ kind, position }));
            // Hide candidate discovery temporarily, preserving any earlier
            // explicit selection or omission when the view is restored.
            const hideBallotDiscovery = (
                position: number,
                authors: readonly number[],
            ) => {
                const hidden = authors.map((author) => {
                    const name = ballotDiscoveryName(author);
                    return {
                        name,
                        existed: views[position].has(name),
                        value: views[position].get(name),
                    };
                });
                for (const { name } of hidden)
                    views[position].set(name, undefined);
                return () => {
                    for (const { name, existed, value } of hidden) {
                        if (existed) views[position].set(name, value);
                        else views[position].delete(name);
                    }
                };
            };
            // The relay shows one honest verifier no other author's pointer
            // until it responds, so it holds only its own ballot. Its later
            // target checks must consume every other body from the public
            // source even when other participants reuse custody.
            const publicBodyProbe =
                mode === 'empty'
                    ? undefined
                    : positions.find(
                          (position) =>
                              position !== 0 &&
                              honest(position) &&
                              !departed.has(position),
                      );
            // The probe holds no close record to lose, so the participants
            // that lose state are chosen with the probe last.
            const probeLast = (candidates: number[]) =>
                candidates.sort(
                    (left, right) =>
                        Number(left === publicBodyProbe) -
                        Number(right === publicBodyProbe),
                );
            // The relay serves every other participant none of the omitted
            // ballot's records until the target votes are published.
            const omission: string[] = [];
            if (omittedVoter !== undefined) {
                const directory = await submissionDirectory(omittedVoter);
                omission.push(
                    ballotDiscoveryName(omittedVoter),
                    ...(await readdir(directory)).map((file) =>
                        path
                            .relative(
                                publicDirectory,
                                path.join(directory, file),
                            )
                            .split(path.sep)
                            .join('/'),
                    ),
                );
                for (const position of others(omittedVoter))
                    for (const name of omission)
                        views[position].set(name, undefined);
            }
            // The relay's pointer to the equivocator's ballot names its late
            // copy's ballot to the last participant, and its conflicting
            // copy's to the organizer's first collection.
            const discoveryIdentity = (identity: string) =>
                Buffer.from(identity, 'hex');
            if (equivocation !== undefined)
                views[lastPosition].set(
                    ballotDiscoveryName(equivocation.position),
                    discoveryIdentity(equivocation.late.identity),
                );
            const restoreProbeDiscovery =
                publicBodyProbe === undefined
                    ? () => undefined
                    : hideBallotDiscovery(
                          publicBodyProbe,
                          others(publicBodyProbe),
                      );
            // Every other participant with its verified setup collects the
            // published ballots, its own first, before any intent exists;
            // with no ballot it collects nothing and commits nothing.
            await Promise.all(
                positions
                    .slice(1)
                    .filter(
                        (position) =>
                            position !== lateSetup && !departed.has(position),
                    )
                    .map(async (position) => {
                        const details = await run(position, 'close');
                        assert.equal(details.generation, beforeClose);
                        assert.deepEqual(details.closeEvents, [
                            ...submissions('own', cast([position])),
                            ...submissions(
                                'held',
                                position === publicBodyProbe
                                    ? []
                                    : shown(position, cast(others(position))),
                            ),
                        ]);
                    }),
            );
            // The organizer's first collection sees only the pointer to the
            // equivocator's conflicting copy.
            const equivocatorHeld =
                equivocation === undefined ? [] : [equivocation.position];
            if (equivocation !== undefined) {
                views[0].set(
                    ballotDiscoveryName(equivocation.position),
                    discoveryIdentity(equivocation.conflicting.identity),
                );
                const restoreOrganizerDiscovery = hideBallotDiscovery(
                    0,
                    others(0).filter(
                        (author) => author !== equivocation.position,
                    ),
                );
                const collected = await run(0, 'close');
                restoreOrganizerDiscovery();
                views[0].set(
                    ballotDiscoveryName(equivocation.position),
                    discoveryIdentity(equivocation.original),
                );
                assert.equal(collected.generation, 17);
                assert.deepEqual(collected.closeEvents, [
                    ...submissions('own', [0]),
                    ...submissions('held', equivocatorHeld),
                ]);
            }
            // The relay hides one honest on-time ballot's pointer from the
            // organizer until its proposal exists, so the organizer opens the
            // close and locks its own intent without that ballot and learns
            // its envelope only from the responses. It then holds both of the
            // equivocator's on-time envelopes. With no ballot it learns
            // nothing.
            const withheld = shown(0, others(0)).find(
                (position) =>
                    onTime(position) &&
                    position !== equivocator &&
                    honest(position),
            );
            assert.equal(withheld === undefined, mode === 'empty');
            const withheldList = withheld === undefined ? [] : [withheld];
            const restoreWithheldDiscovery = hideBallotDiscovery(
                0,
                withheldList,
            );
            const organizerDeliveries = shown(0, cast(others(0))).filter(
                (position) => position !== withheld,
            );
            await expectStatus(1, 'close', 'refused', { closeTime });
            // The organizer halts with its intent before signing it, and its
            // next visit signs the retained intent without a close time.
            await interrupt(0, 'close', { closeTime }, 18);
            const opened = await run(0, 'close');
            assert.equal(opened.generation, 19);
            const organizerCollected = [
                ...submissions('own', [0].filter(onTime)),
                ...submissions('held', equivocatorHeld),
                ...submissions('held', organizerDeliveries.filter(onTime)),
            ];
            assert.deepEqual(opened.closeEvents, [
                ...organizerCollected,
                { kind: 'lock' },
            ]);
            await expectStatus(0, 'close', 'refused', { closeTime });
            // The last participant's setup arrives only after the organizer's
            // close intent: once the setup is retained, the participant
            // learns that ballot submission closed, locks the intent and can
            // no longer vote.
            if (lateSetup !== undefined) {
                const verified = await run(lateSetup, 'verify-setup');
                assert.equal(verified.generation, 19);
                assert.equal(verified.ballot, 'could not vote');
                await expectStatus(lateSetup, 'ballot', 'refused', {
                    scores: ballotScores(lateSetup),
                });
            }
            // A copy of honest state loses its last close record, or its last
            // data record when it holds no close record, as when every ballot
            // it held was late or none was cast, and stops.
            const closeStore = async (position: number) =>
                (await storedRecords(position, 'close')) > 0 ? 'close' : 'data';
            // Every other participant locks the intent and responds at once.
            // The last participant's lock retires the late ballot it held
            // from the equivocator.
            const heldOnTime = (position: number) =>
                shown(position, others(position)).filter(
                    (author) =>
                        onTime(author) &&
                        !(author === equivocator && position === lastPosition),
                );
            // The omitted voter responds only after the proposal exists.
            const responders = positions
                .slice(1)
                .filter((position) => !outsiders.includes(position));
            // The first two other honest responders halt after locking the
            // intent and with their response intent.
            const responseHalts = new Map(
                probeLast(responders.filter(honest))
                    .slice(0, 2)
                    .map((position, index) => [position, [19, 20][index]]),
            );
            // They collect nothing more: the public body probe still sees no
            // other pointer, and the last participant still sees only the
            // equivocator's late copy.
            await Promise.all(
                responders.map(async (position) => {
                    const halt = responseHalts.get(position);
                    if (halt !== undefined)
                        await interrupt(position, 'close', {}, halt);
                    if (halt === 19)
                        await loseState(
                            position,
                            await closeStore(position),
                            'close',
                        );
                    const details = await run(position, 'close');
                    assert.equal(details.generation, 21);
                    assert.deepEqual(details.closeEvents, [
                        ...submissions('own', [position].filter(onTime)),
                        ...submissions(
                            'held',
                            position === publicBodyProbe
                                ? []
                                : heldOnTime(position),
                        ),
                        { kind: 'lock' },
                    ]);
                }),
            );
            restoreProbeDiscovery();
            if (equivocation !== undefined)
                views[lastPosition].delete(
                    ballotDiscoveryName(equivocation.position),
                );
            // The lock ended the ballot window, so a participant without a
            // ballot starts none.
            if (mode === 'empty')
                await expectStatus(1, 'ballot', 'refused', {
                    scores: ballotScores(1),
                });
            // The organizer takes the other responses, fetches the body they
            // list that it lacks, responds and proposes. It halts with its
            // signed response and retained proposal intent, and with its
            // signed proposal before delivering it. The withheld pointer keeps
            // it from collecting that ballot itself, so it fetches only the
            // listed body.
            await interrupt(0, 'close', {}, 21);
            await interrupt(0, 'close', {}, 22);
            // Its next visit restores the completed close without replaying
            // the log, so the retained events name no author or responder;
            // the published proposal below names the responses it took.
            const concluded = await run(0, 'close');
            assert.equal(concluded.generation, 22);
            const responseEvents = (
                concluded.closeEvents as { kind: string }[]
            ).filter((event) => event.kind === 'response');
            assert.ok(responseEvents.length >= bounds.close.quorum - 1);
            assert.ok(responseEvents.length <= responders.length);
            assert.deepEqual(
                (concluded.closeEvents as { kind: string }[]).filter(
                    (event) => event.kind !== 'response',
                ),
                [
                    ...organizerCollected,
                    { kind: 'lock' },
                    ...submissions('held', withheldList),
                ].map(({ kind }) => ({ kind })),
            );
            restoreWithheldDiscovery();
            // Completed close work is only delivered again.
            assert.equal((await run(1, 'close')).generation, 21);
            assert.equal((await run(0, 'close')).generation, 22);
            // The omitted voter then locks the intent and responds, listing
            // its own ballot, which no response in the proposal lists.
            if (omittedVoter !== undefined) {
                const details = await run(omittedVoter, 'close');
                assert.equal(details.generation, 21);
                assert.deepEqual(details.closeEvents, [
                    ...submissions('own', [omittedVoter].filter(onTime)),
                    ...submissions('held', heldOnTime(omittedVoter)),
                    { kind: 'lock' },
                ]);
            }
            const closeBounds = bounds.close;
            const signatureBytes = bounds.registration.signatureBytes;
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
            for (const position of positions.filter(
                (responder) => !departed.has(responder),
            )) {
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
                // The listing holds exactly the on-time ballots its responder
                // holds: the organizer lists both of the equivocator's
                // on-time envelopes, which makes its slot conflicting, the
                // last participant, which held only the late one, none, and
                // only the omitted voter its own ballot.
                const listed = [];
                for (
                    let offset = 4 + closeBounds.minimumResponseBodyBytes;
                    offset < 4 + length;
                    offset += 66
                )
                    listed.push(response.readUInt16LE(offset));
                assert.deepEqual(
                    listed,
                    shown(position, positions.filter(onTime))
                        .filter(
                            (author) =>
                                position !== publicBodyProbe ||
                                author === position,
                        )
                        .flatMap((author) =>
                            author !== equivocator
                                ? [author]
                                : position === 0
                                  ? [author, author]
                                  : position === lastPosition
                                    ? []
                                    : [author],
                        ),
                );
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
            assert.deepEqual(
                named,
                [0, ...responders].slice(0, closeBounds.quorum),
            );
            // The profile's inventory certificate threshold is also the close
            // quorum. The last corrupt positions beyond it among the
            // participants that did not depart sign no target vote; they
            // release later from their completed close.
            const nonVoters = positions.slice(
                1 +
                    maximumCorruptParticipantCount -
                    (participantCount - departed.size - closeBounds.quorum),
                1 + maximumCorruptParticipantCount,
            );
            const voters = positions.filter(
                (position) =>
                    !nonVoters.includes(position) && !departed.has(position),
            );
            assert.equal(voters.length, closeBounds.quorum);
            // Every voter verifies the barrier, classifies each usable
            // ballot, evaluates the target and signs its vote. Every on-time
            // ballot but the equivocator's and the omitted one is usable,
            // every usable ballot but the invalid author's is valid, the
            // omitted voter's ballot is reported omitted, a late one late,
            // and a participant without a ballot has none cast.
            // The equivocator and the invalid author are non-voters.
            assert.ok(
                [equivocator, invalidAuthor].every(
                    (position) =>
                        position === undefined || nonVoters.includes(position),
                ),
            );
            // The first other honest voter halts with its target intent, and
            // the organizer with its signed vote before delivering it, so its
            // next visit only delivers the vote.
            const targetHalts = new Map([
                ...probeLast(
                    voters.filter(
                        (position) => position !== 0 && honest(position),
                    ),
                )
                    .slice(0, 1)
                    .map((position) => [position, 23] as const),
                [0, 24] as const,
            ]);
            // A conflicting slot leaves the equivocator's ballot omitted.
            const ballotStatus = (position: number) =>
                position === omittedVoter || position === equivocator
                    ? 'omitted'
                    : onTime(position)
                      ? 'included'
                      : ballotAuthors.includes(position)
                        ? 'late'
                        : 'not cast';
            await Promise.all(
                voters.map(async (position) => {
                    const halt = targetHalts.get(position);
                    if (halt !== undefined)
                        await interrupt(position, 'target', {}, halt);
                    if (halt === 23)
                        await loseState(
                            position,
                            await closeStore(position),
                            'target',
                        );
                    const details = await run(position, 'target');
                    assert.equal(details.generation, 24);
                    // The signing state retains the own ballot's status, so
                    // a visit that only delivers the vote reports it too.
                    assert.equal(details.ballotStatus, ballotStatus(position));
                    if (halt === 24) return;
                    assert.equal(details.usableBallots, usableCount);
                    assert.equal(details.validBallots, validCount);
                }),
            );
            // A signed vote is only delivered again, and every later visit
            // reports the retained status.
            const repeated = await run(voters[voters.length - 1], 'target');
            assert.equal(repeated.generation, 24);
            assert.equal(
                repeated.ballotStatus,
                ballotStatus(voters[voters.length - 1]),
            );
            assert.equal(
                (await run(voters[voters.length - 1], 'status')).ballotStatus,
                ballotStatus(voters[voters.length - 1]),
            );
            const targetBounds = bounds.target;
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
            // Every vote names its signer and one target identity, and no
            // other participant published one.
            const silent = positions.filter(
                (position) => !voters.includes(position),
            );
            for (const position of silent)
                await assert.rejects(
                    stat(
                        path.join(
                            completionDirectory,
                            `target-vote-${String(position)}.bin`,
                        ),
                    ),
                    { code: 'ENOENT' },
                );
            const targetIdentities = new Set<string>();
            for (const position of voters) {
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
            // Every vote is published, so the certificate exists, and the
            // relay serves the omitted ballot again. The organizer then
            // departs before any release exists: its browser ends and its
            // private state is deleted.
            for (const view of views)
                for (const name of omission) view.delete(name);
            await depart(0);
            const remaining = positions.filter(
                (position) => !departed.has(position),
            );
            const combiningPosition = remaining[remaining.length - 1];
            const releaseBounds = bounds.release;
            const completionFile = (name: string, position: number) =>
                path.join(
                    completionDirectory,
                    name + String(position) + '.bin',
                );
            // A voter releases after its signed target and a non-voter after
            // its completed close.
            const predecessor = (position: number) =>
                voters.includes(position)
                    ? targetPhase.signed
                    : completedClosePhase(false);
            let interruption:
                | Readonly<{
                      position: number;
                      resumedFrom: Readonly<{ generation: number }>;
                  }>
                | undefined;
            if (noResult) {
                // The certified target carries no result, so each remaining
                // participant's release certifies it and creates nothing.
                for (const position of remaining) {
                    const details = await run(position, 'release');
                    assert.equal(details.generation, predecessor(position));
                    assert.equal(details.encrypted, false);
                    assert.equal(details.predecessor, undefined);
                    assert.equal(details.resumedFrom, undefined);
                    // A non-voter reads its status from the certified target.
                    assert.equal(details.ballotStatus, ballotStatus(position));
                }
            } else {
                // Every remaining participant certifies the target from the
                // published votes, retains the seed of its release
                // randomness, and generates and signs its release share. The
                // first remaining voter's browser closes while it generates
                // its share from the retained seed, and its next visit
                // generates it again from that seed.
                const interruptedPosition = remaining.find((position) =>
                    voters.includes(position),
                );
                assert.ok(interruptedPosition !== undefined);
                const interruptRelease = async () => {
                    const interrupted = request(interruptedPosition, 'release');
                    for (;;) {
                        const outcome = await Promise.race([
                            interrupted.then(
                                (result) => ({ result }),
                                (error: unknown) => ({
                                    error:
                                        error instanceof Error
                                            ? error.message
                                            : String(error),
                                }),
                            ),
                            delay(1000, 'waiting'),
                        ]);
                        assert.equal(
                            outcome,
                            'waiting',
                            'The release ended before its interruption: ' +
                                JSON.stringify(outcome),
                        );
                        if ((await headGeneration(interruptedPosition)) === 26)
                            break;
                    }
                    await endBrowser(interruptedPosition);
                    await assert.rejects(interrupted);
                    recoveryOperations.set(interruptedPosition, 'release');
                    const details = await run(interruptedPosition, 'release');
                    assert.equal(details.generation, 29);
                    assert.equal(details.encrypted, true);
                    assert.equal(
                        details.ballotStatus,
                        ballotStatus(interruptedPosition),
                    );
                    assert.equal(
                        details.predecessor,
                        predecessor(interruptedPosition),
                    );
                    const resumedFrom = details.resumedFrom as {
                        generation: number;
                    };
                    assert.equal(resumedFrom.generation, 26);
                    return resumedFrom;
                };
                const [resumedFrom] = await Promise.all([
                    interruptRelease(),
                    ...remaining
                        .filter(
                            (position) =>
                                position !== interruptedPosition &&
                                position !== combiningPosition,
                        )
                        .map(async (position) => {
                            const details = await run(position, 'release');
                            assert.equal(details.generation, 29);
                            assert.equal(details.resumedFrom, undefined);
                            assert.equal(details.encrypted, true);
                            assert.equal(
                                details.ballotStatus,
                                ballotStatus(position),
                            );
                            assert.equal(
                                details.predecessor,
                                predecessor(position),
                            );
                        }),
                ]);
                interruption = { position: interruptedPosition, resumedFrom };
                // The combining participant halts at every generation after
                // its target lock, the last with its signed release before
                // delivery, which its next visit only delivers.
                for (const generation of [26, 27, 29])
                    await interrupt(
                        combiningPosition,
                        'release',
                        {},
                        generation,
                    );
                const delivered = await run(combiningPosition, 'release');
                assert.equal(delivered.generation, 29);
                assert.equal(delivered.encrypted, undefined);
                // A release after the completed close spent the target
                // purpose, and its lock retains the own ballot's status.
                for (const position of nonVoters) {
                    await expectStatus(position, 'target', 'refused');
                    assert.equal(
                        (await run(position, 'status')).ballotStatus,
                        ballotStatus(position),
                    );
                }
                // A signed release is only delivered again.
                const rereleased = await run(combiningPosition, 'release');
                assert.equal(rereleased.generation, 29);
                assert.equal(rereleased.encrypted, undefined);
                for (const position of remaining) {
                    const body = await stat(
                        completionFile('release-', position),
                    );
                    assert.ok(
                        body.size >= releaseBounds.minimumBodyBytes &&
                            body.size <= releaseBounds.maximumBodyBytes,
                    );
                    const packet = await readFile(
                        completionFile('release-envelope-', position),
                    );
                    assert.equal(
                        packet.length,
                        releaseBounds.envelopeBytes + signatureBytes,
                    );
                    // The envelope ends with the body length and identity.
                    assert.equal(
                        Number(
                            packet.readBigUInt64LE(
                                releaseBounds.envelopeBytes - 64 - 8,
                            ),
                        ),
                        body.size,
                    );
                }
            }
            // No departed participant released, and nobody releases for a
            // no-result target.
            for (const position of noResult ? positions : departed)
                for (const name of ['release-', 'release-envelope-'])
                    await assert.rejects(stat(completionFile(name, position)), {
                        code: 'ENOENT',
                    });
            // The last remaining participant combines the published shares
            // into the requested prefix of the ranking of the on-time ballots'
            // score totals, ties to the lower option, or finds that the
            // certified target carries no result. The equivocator's ballots
            // and the omitted ballot are not counted. The departed organizer's
            // share is absent, so the first share it tries is unavailable, and
            // the lowest remaining shares include a non-voter's when one
            // exists and the interrupted voter's.
            const totals = Array.from(
                { length: optionCount },
                (_unused, option) =>
                    positions
                        .filter(
                            (position) =>
                                onTime(position) &&
                                position !== equivocator &&
                                position !== omittedVoter,
                        )
                        .reduce(
                            (total, position) =>
                                total + ballotScores(position)[option],
                            0,
                        ),
            );
            const expectedResult = Array.from(
                { length: optionCount },
                (_unused, option) => option,
            )
                .sort(
                    (left, right) =>
                        totals[right] - totals[left] || left - right,
                )
                .slice(0, topCount)
                .map((option) => `option-${String(option)}`);
            // Meanwhile a malicious relay shows each other remaining honest
            // participant forged records in its own view. Each view would
            // complete the work only if a forgery counted, so its participant
            // stays pending. One view hides the second voter's vote behind the
            // last voter's vote relabeled with that position, and replays the
            // last voter's vote in every slot without a vote. Another replays the
            // combining participant's share in every departed slot, alters
            // the first remaining participant's body, and relabels that share
            // for each other remaining slot but the last release threshold
            // minus one.
            const probes = remaining.filter(
                (position) =>
                    position !== combiningPosition && honest(position),
            );
            const voteProbe = probes[0];
            const shareProbe = probes[probes.length - 1];
            const publicName = (name: string, position: number) =>
                'completion/' + name + String(position) + '.bin';
            const hiddenVoter = voters[1];
            const lastVoter = voters[voters.length - 1];
            assert.notEqual(hiddenVoter, lastVoter);
            const lastVote = await readFile(
                completionFile('target-vote-', lastVoter),
            );
            const relabeledVote = Buffer.from(lastVote);
            relabeledVote.writeUInt16LE(hiddenVoter, 0);
            // Replay genuine immutable candidates through the public transport.
            // A flat diagnostic path alone cannot populate an empty discovery key.
            const replayCandidate = async (
                sourceKey: string,
                targetKey: string,
            ) => {
                const base = origin(leftOut);
                const listed = await fetch(
                    base + '/candidates/' + sourceKey + '?offset=0',
                );
                assert.equal(listed.status, 200);
                const page = decodeCandidatePage(
                    new Uint8Array(await listed.arrayBuffer()),
                );
                assert.ok(page.ids.length > 0);
                const source = await fetch(base + '/candidate/' + page.ids[0]);
                assert.equal(source.status, 200);
                const manifest = new Uint8Array(await source.arrayBuffer());
                decodeCandidateManifest(manifest);
                const posted = await fetch(base + '/candidates/' + targetKey, {
                    method: 'POST',
                    body: manifest,
                });
                assert.equal(posted.status, 200);
                const receipt = decodeCandidateReceipt(
                    new Uint8Array(await posted.arrayBuffer()),
                );
                const readback = await fetch(base + '/candidate/' + receipt.id);
                assert.equal(readback.status, 200);
                assert.deepEqual(
                    new Uint8Array(await readback.arrayBuffer()),
                    manifest,
                );
                const discovery = await fetch(
                    base +
                        '/candidates/' +
                        targetKey +
                        '?offset=' +
                        String(receipt.index),
                );
                assert.equal(discovery.status, 200);
                assert.equal(
                    decodeCandidatePage(
                        new Uint8Array(await discovery.arrayBuffer()),
                    ).ids[0],
                    receipt.id,
                );
                log.writeEvent({
                    eventType: 'participant-replayed-candidate',
                    details: { sourceKey, targetKey, candidate: receipt.id },
                });
                return receipt.id;
            };
            const voteReplays: string[] = [];
            for (const position of silent)
                voteReplays.push(
                    await replayCandidate(
                        'target-vote-' + String(lastVoter),
                        'target-vote-' + String(position),
                    ),
                );
            const shareReplays: string[] = [];
            if (!noResult)
                for (const position of departed)
                    shareReplays.push(
                        await replayCandidate(
                            'release-' + String(combiningPosition),
                            'release-' + String(position),
                        ),
                    );
            const voteForgeries = new Map([
                [publicName('target-vote-', hiddenVoter), relabeledVote],
                ...silent.map(
                    (position) =>
                        [
                            publicName('target-vote-', position),
                            lastVote,
                        ] as const,
                ),
            ]);
            const shareForgeries = new Map<string, Buffer>();
            if (!noResult) {
                const replaced = remaining.slice(
                    0,
                    remaining.length - (releaseThreshold - 1),
                );
                const envelope = await readFile(
                    completionFile('release-envelope-', combiningPosition),
                );
                const body = await readFile(
                    completionFile('release-', combiningPosition),
                );
                for (const position of departed) {
                    shareForgeries.set(
                        publicName('release-envelope-', position),
                        envelope,
                    );
                    shareForgeries.set(publicName('release-', position), body);
                }
                const altered = await readFile(
                    completionFile('release-', replaced[0]),
                );
                altered[altered.length - 1] ^= 1;
                shareForgeries.set(
                    publicName('release-', replaced[0]),
                    altered,
                );
                // The envelope ends with its signer's position, then the body
                // length and identity.
                for (const position of replaced.slice(1)) {
                    const relabeled = Buffer.from(envelope);
                    relabeled.writeUInt16LE(
                        position,
                        releaseBounds.envelopeBytes - 64 - 8 - 2,
                    );
                    shareForgeries.set(
                        publicName('release-envelope-', position),
                        relabeled,
                    );
                    shareForgeries.set(publicName('release-', position), body);
                }
            }
            // A third view swaps the first two registrations under each
            // other's body digests. Each is a valid registration for the
            // poll, so only the retained roster tells them apart, and every
            // visit verifies the setup again from them first.
            const registrationForgeries = new Map<string, Buffer>();
            for (const [from, to] of [
                [0, 1],
                [1, 0],
            ] as const)
                for (const file of await readdir(
                    path.join(publicDirectory, 'registration', recordIds[from]),
                ))
                    registrationForgeries.set(
                        'registration/' + recordIds[to] + '/' + file,
                        await readFile(
                            path.join(
                                publicDirectory,
                                'registration',
                                recordIds[from],
                                file,
                            ),
                        ),
                    );
            // With ballots cast, a fourth set of views forges another ballot
            // that the certified target counts, which the vote probe reads
            // from the public records: its body altered or withheld, its
            // submission replaced by another counted author's authentic one,
            // or its signature altered. The refused votes of the first view
            // discard the vote probe's evaluated target, so each of these
            // visits evaluates the target again from the public close records
            // and verifies the close barrier; none of them withdraws or
            // replaces the accepted ballot, and its participant stays pending.
            // When the vote probe's own ballot is the only one counted, the
            // probe reads no counted ballot from the public records, and
            // there is no such view.
            const countedBallots = onTimeBallots.filter(
                (position) =>
                    ![equivocator, omittedVoter, invalidAuthor].includes(
                        position,
                    ),
            );
            const ballotForgeries: {
                forgery: string;
                forgeries: ReadonlyMap<string, ViewedRecord>;
                reason: string;
            }[] = [];
            const forgedAuthor = countedBallots.find(
                (position) => position !== voteProbe,
            );
            const replacingAuthor = countedBallots.find(
                (position) => position !== forgedAuthor,
            );
            if (mode !== 'empty') {
                assert.equal(voteProbe, publicBodyProbe);
                assert.ok(countedBallots.includes(voteProbe));
            }
            if (forgedAuthor !== undefined) {
                assert.ok(replacingAuthor !== undefined);
                const directory = await submissionDirectory(forgedAuthor);
                const replacing = await submissionDirectory(replacingAuthor);
                const submissionIdentity = Buffer.from(
                    path.basename(directory),
                    'hex',
                );
                const forwardedBody =
                    'close/closure/' + closureBodyFile(submissionIdentity);
                const forwardedSubmission =
                    'close/closure/' +
                    closureSubmissionFile(submissionIdentity);
                const originalEnvelope = await readFile(
                    path.join(directory, 'envelope.bin'),
                );
                const replacingSubmission = Buffer.concat([
                    await readFile(path.join(replacing, 'envelope.bin')),
                    await readFile(path.join(replacing, 'signature.bin')),
                ]);
                const ballotName = (file: string) =>
                    path
                        .relative(publicDirectory, path.join(directory, file))
                        .split(path.sep)
                        .join('/');
                const alteredBody = await readFile(
                    path.join(directory, 'body.bin'),
                );
                alteredBody[alteredBody.length - 1] ^= 1;
                const alteredSignature = await readFile(
                    path.join(directory, 'signature.bin'),
                );
                alteredSignature[0] ^= 1;
                ballotForgeries.push(
                    {
                        forgery: 'altered body',
                        forgeries: new Map<string, ViewedRecord>([
                            [ballotName('body.bin'), alteredBody],
                            [forwardedBody, alteredBody],
                        ]),
                        reason: 'No valid complete candidate is available: close-proposal',
                    },
                    {
                        forgery: 'withheld body',
                        forgeries: new Map<string, ViewedRecord>([
                            [ballotName('body.bin'), undefined],
                            [forwardedBody, undefined],
                        ]),
                        reason: 'No valid complete candidate is available: close-proposal',
                    },
                    {
                        forgery: 'replaced submission',
                        forgeries: new Map<string, ViewedRecord>([
                            [forwardedSubmission, replacingSubmission],
                        ]),
                        reason: 'No valid complete candidate is available: close-proposal',
                    },
                    {
                        forgery: 'altered signature',
                        forgeries: new Map<string, ViewedRecord>([
                            [
                                forwardedSubmission,
                                Buffer.concat([
                                    originalEnvelope,
                                    alteredSignature,
                                ]),
                            ],
                        ]),
                        reason: 'No valid complete candidate is available: close-proposal',
                    },
                );
            }
            // A fifth set of views serves the other poll's records of one
            // family at a time. The first of them a result visit reads is
            // refused, so its participant stays pending; a family it does not
            // read leaves it the outcome of the relay's own records.
            const foreignProbes: {
                family: string;
                served: number;
                hidden: number;
                reason?: string;
            }[] = [];
            const unreadOutcomes: {
                family: string;
                encrypted: unknown;
                identifiers: unknown;
            }[] = [];
            const probeForeignPoll = async (position: number) => {
                if (foreign === undefined) return;
                assert.notEqual(foreign.poll, organizer.poll);
                for (const { family, pattern, reason } of foreignFamilies) {
                    // Only an encrypted target's result reads release shares,
                    // and only a result run of the other poll released any.
                    if (family === 'release shares' && noResult) continue;
                    const { view, served } = await foreignRecordView(
                        foreign,
                        publicDirectory,
                        recordIds,
                        pattern,
                    );
                    if (family === 'release shares' && served === 0) continue;
                    assert.ok(served > 0, `The foreign poll has no ${family}.`);
                    if (reason === undefined) {
                        const { encrypted, identifiers } = await probeUnread(
                            position,
                            view,
                        );
                        unreadOutcomes.push({ family, encrypted, identifiers });
                    } else await probe(position, view, reason);
                    foreignProbes.push({
                        family,
                        served,
                        hidden: view.size - served,
                        reason,
                    });
                }
            };
            const probe = async (
                position: number,
                forgeries: ReadonlyMap<string, ViewedRecord>,
                reason: string | readonly string[],
            ) => {
                deliveredRecords[position].clear();
                candidateReads[position].clear();
                for (const [name, bytes] of forgeries)
                    views[position].set(name, bytes);
                try {
                    const result = await request(position, 'result');
                    assert.ok(result.status === 'pending');
                    const reasons =
                        typeof reason === 'string' ? [reason] : reason;
                    assert.ok(reasons.includes(result.reason), result.reason);
                    assert.deepEqual(result, {
                        status: 'pending',
                        cause: 'public input',
                        reason: result.reason,
                    });
                    if (
                        [...forgeries.values()].some(
                            (value) => value !== undefined,
                        )
                    )
                        assert.ok(
                            [...forgeries.keys()].some((name) =>
                                deliveredRecords[position].has(name),
                            ),
                            'The refused operation did not read its forged inputs.',
                        );
                } finally {
                    views[position].clear();
                }
            };
            // A result visit that reads none of the served records completes.
            const probeUnread = async (
                position: number,
                forgeries: ReadonlyMap<string, ViewedRecord>,
            ) => {
                deliveredRecords[position].clear();
                for (const [name, bytes] of forgeries)
                    views[position].set(name, bytes);
                try {
                    const result = await run(position, 'result');
                    assert.ok(
                        [...forgeries.keys()].every(
                            (name) => !deliveredRecords[position].has(name),
                        ),
                        'The cached result consumed a replaced input.',
                    );
                    return result;
                } finally {
                    views[position].clear();
                }
            };
            const [result] = await Promise.all([
                run(combiningPosition, 'result'),
                ...[...new Set([voteProbe, shareProbe])].map(
                    async (position) => {
                        // The vote probe reads the forged ballots before any
                        // share view, whose visit retains the target it
                        // evaluates.
                        if (position === voteProbe) {
                            await probe(
                                position,
                                voteForgeries,
                                'The target votes are incomplete.',
                            );
                            for (const id of voteReplays)
                                assert.ok(
                                    candidateReads[position].has(id),
                                    'The verifier did not encounter the replayed target candidate.',
                                );
                            for (const { forgeries, reason } of ballotForgeries)
                                await probe(position, forgeries, reason);
                            await probe(
                                position,
                                registrationForgeries,
                                recordIds
                                    .slice(0, 2)
                                    .map(
                                        (id) =>
                                            'No valid complete candidate is available: registration/' +
                                            id,
                                    ),
                            );
                        }
                        if (position === shareProbe && !noResult) {
                            await probe(
                                position,
                                shareForgeries,
                                'The release shares are incomplete.',
                            );
                            for (const id of shareReplays)
                                assert.ok(
                                    candidateReads[position].has(id),
                                    'The verifier did not encounter the replayed release candidate.',
                                );
                        }
                        if (position === voteProbe)
                            await probeForeignPoll(position);
                    },
                ),
            ]);
            assert.equal(result.encrypted, !noResult);
            assert.deepEqual(
                result.identifiers,
                noResult ? [] : expectedResult,
            );
            for (const { family, encrypted, identifiers } of unreadOutcomes) {
                assert.equal(encrypted, result.encrypted, family);
                assert.deepEqual(identifiers, result.identifiers, family);
            }
            // None of the forged views stopped its participant or withdrew
            // its ballot: with the relay's own records it combines the same
            // outcome.
            const recovered = await run(voteProbe, 'result');
            assert.equal(recovered.encrypted, result.encrypted);
            assert.deepEqual(recovered.identifiers, result.identifiers);
            // This untrusted public cache is outside the authenticated
            // participant root. A damaged credential-keyed target must be
            // discarded and recomputed from the actual close inputs.
            await inBrowser(voteProbe, undefined, (chrome) =>
                chrome.evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open(${JSON.stringify(namespacedName(evaluatedTargetName, participantNamespace))});
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
        const database = opening.result;
        const reading = database.transaction('target').objectStore('target').get(0);
        reading.onerror = () => { database.close(); reject(reading.error); };
        reading.onsuccess = () => {
            const stored = reading.result;
            if (!(stored instanceof Blob) || stored.size === 0) { database.close(); reject(new Error('No evaluated target cache.')); return; }
            stored.slice(-1).arrayBuffer().then((buffer) => {
                const tail = new Uint8Array(buffer); tail[0] ^= 1;
                const writing = database.transaction('target', 'readwrite');
                writing.objectStore('target').put(new Blob([stored.slice(0, -1), tail]), 0);
                writing.oncomplete = () => { database.close(); resolve(undefined); };
                writing.onabort = () => { database.close(); reject(writing.error); };
            }).catch((error) => { database.close(); reject(error); });
        };
    };
})`),
            );
            deliveredRecords[voteProbe].clear();
            const recomputed = await run(voteProbe, 'result');
            assert.equal(recomputed.encrypted, result.encrypted);
            assert.deepEqual(recomputed.identifiers, result.identifiers);
            assert.ok(
                deliveredRecords[voteProbe].has('close/proposal.bin'),
                'A damaged target cache bypassed recomputation.',
            );
            log.writeEvent({
                eventType: 'participant-damaged-target-recomputed',
                details: { position: voteProbe },
            });
            // Altered retained state stops an honest participant at its next
            // visit, and the stop outlasts restoring the exact bytes. The
            // first byte of its first data record is flipped from its own
            // page, and a second flip restores it.
            const stoppedPosition = probes[0];
            const flipDataRecord = async () =>
                inBrowser(stoppedPosition, undefined, (chrome) =>
                    chrome.evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open(${JSON.stringify(participantDatabase)});
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
        const database = opening.result;
        const fail = (error) => { database.close(); reject(error); };
        const reading = database.transaction('data').objectStore('data').openCursor();
        reading.onerror = () => fail(reading.error);
        reading.onsuccess = () => {
            if (reading.result === null) return fail(new Error('No data record.'));
            const { key, value } = reading.result;
            value.arrayBuffer().then((buffer) => {
                const bytes = new Uint8Array(buffer);
                bytes[0] ^= 1;
                const writing = database.transaction('data', 'readwrite');
                writing.oncomplete = () => { database.close(); resolve(key); };
                writing.onabort = () => fail(writing.error);
                writing.objectStore('data').put(new Blob([bytes]), key);
            }, fail);
        };
    };
})`),
                );
            const alteredRecord = await flipDataRecord();
            assert.deepEqual(await request(stoppedPosition, 'status'), {
                status: 'stopped',
                reason: 'A participant data record changed.',
                stopPersistence: 'confirmed',
            });
            assert.deepEqual(await flipDataRecord(), alteredRecord);
            assert.deepEqual(await request(stoppedPosition, 'status'), {
                status: 'stopped',
                reason: 'Missing or inconsistent participant authority.',
                stopPersistence: 'confirmed',
            });
            // The stopped participant, and the registrant left out of the
            // roster, which holds no part in the poll, verify the outcome
            // with the standalone verifier from the poll's identity and the
            // relay's public records alone.
            for (const position of [stoppedPosition, leftOut]) {
                const started = performance.now();
                const deadline = new AbortController();
                const verification = await inBrowser(
                    position,
                    undefined,
                    (chrome) =>
                        Promise.race([
                            chrome.evaluate(
                                `window.verifyOutcome(${JSON.stringify(organizer.poll)})`,
                            ),
                            delay(operationMilliseconds, undefined, {
                                signal: deadline.signal,
                            }).then(() => {
                                throw new Error(
                                    'Standalone verification deadline.',
                                );
                            }),
                        ]).finally(() => deadline.abort()),
                );
                const verified = verification as WorkerResult;
                log.writeEvent({
                    eventType: 'standalone-verification',
                    details: {
                        position,
                        milliseconds: performance.now() - started,
                        ...(verified.status === 'completed'
                            ? { memory: verified.details.memory }
                            : { result: verified }),
                    },
                });
                assert.ok(
                    verified.status === 'completed',
                    'The standalone verification did not complete.',
                );
                assert.equal(verified.details.poll, organizer.poll);
                if (scalar) requireScalarMemory(verified.details);
                assert.equal(verified.details.encrypted, result.encrypted);
                assert.deepEqual(
                    verified.details.identifiers,
                    result.identifiers,
                );
            }
            const scope = [
                mode === 'empty'
                    ? "Browser registration, roster agreement, setup contribution and setup verification with no ballot cast, a participant whose setup is retained only after the organizer's close intent and so can no longer vote, close responses that list nothing under the organizer's proposal, a participant refused a ballot after its intent lock, target evaluation and votes, and a certified no-result target for which the participants remaining after the organizer departs with its private state release nothing, in the maintained participant runtime in external Chrome."
                    : noResult
                      ? "Browser registration, roster agreement, setup contribution, setup verification, signed ballots, close responses with the organizer's proposal at a close time that leaves one valid on-time ballot fewer than the minimum turnout, beside a corrupt participant's authentic invalid ballot when the profile tolerates one, target evaluation and votes, and a certified no-result target for which the participants remaining after the organizer departs with its private state release nothing, in the maintained participant runtime in external Chrome."
                      : "Browser registration, roster agreement, setup contribution, setup verification, signed ballots, one of them the all-minimum ballot, close responses with the organizer's proposal, and target evaluation and votes, release shares after the organizer departs with its private state, one of them generated again from its retained seed after its browser closed while generating it, and any beyond the certificate quorum released without a target vote, and the combined shorter result in the maintained participant runtime in external Chrome. A corrupt participant that copies its private state signs two more ballots, one of them late, and the relay's views make its slot conflicting, so none of its ballots counts.",
                ...(departing === undefined || omittedVoter === undefined
                    ? []
                    : [
                          "An honest participant departs with its private state after preparation and before the close, casting nothing. The relay hides another honest voter's on-time ballot from every other participant and serves its close response only after the organizer's proposal, so the proposal omits that ballot and its voter's target reports the omission.",
                      ]),
                'A registrant that the organizer leaves out of the roster stays pending when shown it.',
                'The organizer crashes with its roster proposal intent and the last honest participant right after it retains the accepted roster, and an honest participant crashes while it verifies the setup and right after it retains the verified setup; each next visit continues from its retained state, verifying the setup again from the public records after the first of those crashes.',
                'Every participant locally confirms the fixed roster. Selected eligible contributors publish signed clear offers; the organizer proposes the selection and members endorse it before setup activation. The cohort interrupts original contribution and continuation work, the offer-signing intent, the organizer selection intent and one endorsement intent; each next visit preserves its original seed, checkpoint, signing intent and independently retained preparation state.',
                `Honest browsers crash right after their participants durably enter each ${mode === 'empty' ? 'close and target' : noResult ? 'ballot, close and target' : 'ballot, close, target and release'} generation, and each next visit continues from the retained state.`,
                mode === 'empty'
                    ? "Copies of honest participants' state that lose their last data record before their close response or target vote stop for good."
                    : "Copies of honest participants' state stop for good once they lose their last ballot record with the ballot body retained, or, before their close response or target vote, their last close record or, holding none, their last data record.",
                `Relay views that ${noResult ? 'relabel or replay votes' : 'relabel, replay or alter votes and shares'} or swap two registrations under each other's names leave their participants pending until the relay's own records let them finish, and altered retained state stops a participant for good.`,
                ...(mode === 'empty'
                    ? []
                    : [
                          "Relay views that alter or withhold the body of a participant's own counted ballot, replace its submission with another counted author's authentic one or alter its signature leave that participant's result visit pending, and with the relay's own records it reaches the same outcome from the certified target that counts the ballot.",
                      ]),
                ...(foreign === undefined
                    ? []
                    : [
                          `Relay views that serve another poll's ${prose(foreignProbes.filter(({ reason }) => reason !== undefined).map(({ family }) => family))} under this poll's names leave a participant pending, and its ${prose(unreadOutcomes.map(({ family }) => family))}, which a result visit that restores the verified setup and the evaluated target does not read, leave that visit the same outcome.`,
                      ]),
                "Once its altered retained state stops a participant, that participant and the registrant left out of the roster each verify the same outcome with the standalone verifier from the poll's identity and the relay's public records alone.",
            ].join(' ');
            await writeFile(
                path.join(log.runDirectoryPath, 'result.json'),
                JSON.stringify(
                    {
                        participantCount,
                        optionCount,
                        poll: organizer.poll,
                        recordIds,
                        runtimeIdentity: runtime.identity.runtime,
                        corruptClient,
                        peakProcessTreeBytes: peaks.slice(0, leftOut),
                        leftOut: {
                            bodyDigest: leftOutRegistration.bodyDigest,
                            peakProcessTreeBytes: peaks[leftOut],
                        },
                        copyPeakProcessTreeBytes: Object.fromEntries(copyPeaks),
                        closeTime,
                        lateBallots,
                        minimumBallot: minimumBallotAuthor,
                        couldNotVote: lateSetup,
                        departedBeforeClose: departing,
                        omittedBallot: omittedVoter,
                        nonVoters,
                        departed: [...departed],
                        interrupted: interruption,
                        interruptions,
                        stateLosses,
                        setupPublicationFaults,
                        selectionReadbackFaults,
                        selectedProofFaults,
                        equivocation:
                            equivocation === undefined
                                ? undefined
                                : {
                                      position: equivocation.position,
                                      conflicting:
                                          equivocation.conflicting.identity,
                                      late: equivocation.late.identity,
                                  },
                        forgeries: {
                            votes: {
                                position: voteProbe,
                                paths: [...voteForgeries.keys()],
                            },
                            registrations: {
                                position: voteProbe,
                                paths: [...registrationForgeries.keys()],
                            },
                            ...(forgedAuthor === undefined
                                ? {}
                                : {
                                      ballot: {
                                          position: voteProbe,
                                          forgedAuthor,
                                          replacingAuthor,
                                          probes: ballotForgeries.map(
                                              ({
                                                  forgery,
                                                  forgeries,
                                                  reason,
                                              }) => ({
                                                  forgery,
                                                  paths: [...forgeries.keys()],
                                                  reason,
                                              }),
                                          ),
                                      },
                                  }),
                            ...(noResult
                                ? {}
                                : {
                                      shares: {
                                          position: shareProbe,
                                          paths: [...shareForgeries.keys()],
                                      },
                                  }),
                        },
                        stopped: {
                            position: stoppedPosition,
                            record: alteredRecord,
                        },
                        foreignPoll:
                            foreign === undefined
                                ? undefined
                                : {
                                      run: foreign.run,
                                      poll: foreign.poll,
                                      position: voteProbe,
                                      probes: foreignProbes,
                                  },
                        topCount,
                        scalar,
                        result: noResult
                            ? { kind: 'no-result' }
                            : { kind: 'result', identifiers: expectedResult },
                        scope,
                    },
                    null,
                    2,
                ) + '\n',
                { flag: 'wx' },
            );
            await finishAllocation();
            completed = true;
            process.stdout.write(log.runDirectoryPath + '\n');
        } finally {
            sampling = false;
            await monitor;
            await allocationMonitor;
            await browsers.closeAll();
            for (const server of relay?.servers ?? [])
                await new Promise((resolve) => server.close(resolve));
            try {
                await finishAllocation?.();
            } catch (error) {
                guardFailure ??=
                    error instanceof Error ? error : new Error(String(error));
            }
            if (guardFailure !== undefined) completed = false;
            log.writeEvent({
                eventType: 'participant-transfer-summary',
                details: { participants: transfers },
            });
            if (profiles !== undefined && completed)
                await rm(profiles, { recursive: true, force: true });
            else if (profiles !== undefined)
                log.writeEvent({
                    eventType: 'participant-checkpoint-preserved',
                    details: { directory: profiles, runtimeBound: true },
                });
            await releaseLock();
        }
    },
);
