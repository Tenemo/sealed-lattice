import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
    type IncomingMessage,
    type Server,
    type ServerResponse,
    createServer,
} from 'node:http';
import path from 'node:path';

import {
    decodeCandidateManifest,
    encodeCandidateManifest,
} from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import { participantDatabaseName } from '#packages/sdk/src/participant/worker/storage/database.js';
import { serveParticipantCandidates } from '#tools/ci/participant-candidate-http.js';
import {
    type ViewedParticipantRecord,
    participantCandidateView,
} from '#tools/ci/participant-candidate-view.js';
import {
    participantOfferAnnouncements,
    serveOfferAnnouncements,
} from '#tools/ci/participant-offer-announcements.js';
import type { PreparationCut } from '#tools/ci/participant-padding-halt.js';
import { participantRelayStore } from '#tools/ci/participant-relay-record.js';
import type {
    CorruptParticipantClient,
    ParticipantRuntime,
} from '#tools/ci/participant-runtime-assembly.js';
import {
    type ParticipantTransfer,
    observeParticipantTransfer,
} from '#tools/ci/participant-transfer.js';

// The path of the organizer's origin under which the relay stores and
// serves the second roster's records.
export const secondRosterPath = '/second-roster/';

// What a relay view serves a participant instead of a stored record: other
// bytes, the record another relay stored in the named file, or nothing when
// the value is undefined.
export type ViewedRecord = ViewedParticipantRecord;

export type Relay = Readonly<{
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
export const haltingClient = (
    worker: Buffer,
    generation: number,
): HaltingClient => {
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
export const participantNamespace = 'research-cohort';
export const participantDatabase =
    participantDatabaseName(participantNamespace);

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
export const startRelay = async (
    settings: Readonly<{
        originCount: number;
        basePort: number;
        participantCount: number;
        publicationFaults: boolean;
        scalar: boolean;
    }>,
    runtime: ParticipantRuntime,
    publicDirectory: string,
    corrupt:
        | Readonly<{ position: number; client: CorruptParticipantClient }>
        | undefined,
    secondRoster: string | undefined,
    transfers: readonly ParticipantTransfer[],
): Promise<Relay> => {
    const {
        originCount,
        basePort,
        participantCount,
        publicationFaults,
        scalar,
    } = settings;
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
