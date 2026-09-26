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
import { freemem } from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';

import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { runWithLocalRunLog } from '#tools/ci/local-run-log.js';
import { completedClosePhase } from '#tools/ci/participant-runtime/close-state.js';
import { targetPhase } from '#tools/ci/participant-runtime/target-state.js';
import type { WorkerResult } from '#tools/ci/participant-runtime/worker.js';
import {
    assembleParticipantRuntime,
    deriveParticipantDescriptor,
} from '#tools/ci/participant-runtime-assembly.js';
import type {
    CorruptParticipantClient,
    ParticipantRuntime,
} from '#tools/ci/participant-runtime-assembly.js';
import { launchChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import type { ChromeParticipant } from '#tools/ci/participant-runtime-chrome.js';
import { readProtocolProcessTree } from '#tools/ci/protocol-process-memory.js';
import { acquireProtocolResearchLock } from '#tools/ci/protocol-research-lock.js';

// Runs a browser cohort of the selected profile through the maintained
// participant runtime: each participant is its own origin with its own
// external Chrome profile, and a local relay only stores and serves the
// public records the participants publish. A no-result run closes with one
// valid on-time ballot fewer than the minimum turnout, and with a corrupt
// participant's authentic invalid ballot on time when the profile tolerates
// one. An empty run closes with no ballot at all. Another poll's passed
// cohort of the same profile, named by its run directory, supplies the
// records a relay view serves one participant as this poll's.
const foreignOption = '--foreign-poll=';
const allArguments = process.argv.slice(2).filter((value) => value !== '--');
const foreignPoll = allArguments
    .find((value) => value.startsWith(foreignOption))
    ?.slice(foreignOption.length);
const commandArguments = allArguments.filter(
    (value) => !value.startsWith(foreignOption),
);
const mode =
    (['no-result', 'empty'] as const).find(
        (value) => value === commandArguments[commandArguments.length - 1],
    ) ?? 'result';
const noResult = mode !== 'result';
const counts =
    mode === 'result' ? commandArguments : commandArguments.slice(0, -1);
assert.ok(
    counts.length === 0 ||
        (counts.length === 2 &&
            counts.every((value) => /^[1-9]\d*$/u.test(value))),
    'Optionally select the participant and option counts, then no-result or empty, and another poll with --foreign-poll=<run directory>.',
);
const [participantCount, optionCount] =
    counts.length === 0 ? [3, 2] : counts.map(Number);
const root = path.resolve('.');
const basePort = 43_600;
// The host guard for each participant's Chrome process tree.
const participantMemoryLimit = 3_221_225_472;
const operationMilliseconds = 3_600_000;
// A late ballot starts this much later, so that the organizer's close time
// makes exactly the late ballots late. It exceeds the variation in the time
// from a ballot request to its attempt lock across concurrent browsers.
const lateBallotMilliseconds = 5_000;

// The relay's layout: lower-case path segments of letters, digits, dots and
// hyphens, with no traversal.
const publicPath = /^(?:[a-z0-9][a-z0-9.-]*\/)*[a-z0-9][a-z0-9.-]*$/u;

// What a relay view serves a participant instead of a stored record: other
// bytes, the record another relay stored in the named file, or nothing when
// the value is undefined.
type ViewedRecord = Buffer | Readonly<{ file: string }> | undefined;

type Relay = Readonly<{
    servers: Server[];
    // The origin that first published each path; only it may add to it.
    owners: Map<string, string>;
    views: Map<string, ViewedRecord>[];
    // Publications the relay refuses to store.
    refused: Set<string>;
    // Contribution records other than the confirmation and the opening that
    // arrived before their author's signed opening.
    earlyContributionRecords: string[];
    // The halting client a participant's origin serves instead of the
    // runtime's page and worker while one is set.
    halting: Map<number, HaltingClient>;
}>;

// Records a participant may publish from its contribution before its signed
// opening: the committed confirmation and the opening itself.
const preOpeningContributionRecords = new Set([
    'confirmation.bin',
    'confirmation-signature.bin',
    'opening.bin',
    'opening-signature.bin',
]);

type HaltingClient = Readonly<{
    generation: number;
    worker: Buffer;
    digest: string;
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

// The page checks the delivered worker against the digest it names, which
// is the runtime's own worker except on a corrupt client's page.
const page = (runtime: ParticipantRuntime, workerDigest: string) =>
    `<!doctype html><meta charset="utf-8"><title>Participant</title><script>
const runtime = ${JSON.stringify({ descriptor: runtime.descriptor, identity: runtime.identity, worker: workerDigest })};
window.runParticipant = async (operation, parameters) => {
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

// Every origin serves the runtime's page, worker and module, except that a
// corrupt participant's origin serves its client's page and worker and its
// client's module beside the honest one.
const startRelay = async (
    runtime: ParticipantRuntime,
    publicDirectory: string,
    corrupt:
        | Readonly<{ position: number; client: CorruptParticipantClient }>
        | undefined,
): Promise<Relay> => {
    const owners = new Map<string, string>();
    const views = Array.from(
        { length: participantCount },
        () => new Map<string, ViewedRecord>(),
    );
    const refused = new Set<string>();
    const earlyContributionRecords: string[] = [];
    const assets = (position: number) => {
        const client =
            corrupt?.position === position ? corrupt.client : undefined;
        return new Map([
            [
                '/',
                {
                    type: 'text/html',
                    bytes: Buffer.from(
                        page(
                            runtime,
                            client?.workerDigest ?? runtime.identity.worker,
                        ),
                    ),
                },
            ],
            [
                '/worker.js',
                {
                    type: 'text/javascript',
                    bytes: client?.worker ?? runtime.worker,
                },
            ],
            [
                '/participant.wasm',
                { type: 'application/wasm', bytes: runtime.module },
            ],
            ...(client === undefined
                ? []
                : [
                      [
                          '/' + client.path,
                          { type: 'application/wasm', bytes: client.module },
                      ] as const,
                  ]),
        ]);
    };
    const handle = async (
        origin: string,
        served: ReadonlyMap<string, Readonly<{ type: string; bytes: Buffer }>>,
        view: ReadonlyMap<string, ViewedRecord>,
        request: IncomingMessage,
        response: ServerResponse,
    ) => {
        const url = new URL(request.url ?? '/', origin);
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
            const name = url.pathname.slice('/public/'.length);
            if (url.pathname.startsWith('/public/') && publicPath.test(name)) {
                const file = path.join(publicDirectory, name);
                const viewed = view.get(name);
                const bytes = !view.has(name)
                    ? await readFile(file).catch(() => undefined)
                    : viewed === undefined || Buffer.isBuffer(viewed)
                      ? viewed
                      : await readFile(viewed.file);
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
            refused.has(name) ||
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
        const [directory, record] = name.split('/');
        if (
            /^contribution-\d+$/u.test(directory) &&
            !preOpeningContributionRecords.has(record) &&
            (await stat(
                path.join(publicDirectory, directory, 'opening-signature.bin'),
            ).catch(() => undefined)) === undefined
        )
            earlyContributionRecords.push(name);
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
    const halting = new Map<number, HaltingClient>();
    const servers: Server[] = [];
    for (let position = 0; position < participantCount; position++) {
        const origin = `http://127.0.0.1:${String(basePort + position)}`;
        const served = assets(position);
        const server = createServer((request, response) => {
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
                                      page(runtime, client.digest),
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
        owners,
        views,
        refused,
        earlyContributionRecords,
        halting,
    };
};

type ForeignPoll = Readonly<{
    // The passed cohort's run directory, relative to the repository.
    run: string;
    poll: string;
    recordIds: readonly string[];
    publicDirectory: string;
}>;

const identifierPattern = /^[0-9a-f]{128}$/u;

// Reads another passed cohort of this profile: its result names its poll and
// its roster's registrations, and its relay's records lie beside it.
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
    const publicDirectory = path.join(directory, 'public');
    assert.ok(
        (await stat(publicDirectory)).isDirectory(),
        'The foreign poll has no public records.',
    );
    return {
        run: path.relative(root, directory).split(path.sep).join('/'),
        poll,
        recordIds: recordIds.map(String),
        publicDirectory,
    };
};

// The names of the records a relay stored.
const publicRecordNames = async (directory: string) =>
    (await readdir(directory, { recursive: true }))
        .map((name) => name.split(path.sep).join('/'))
        .filter((name) => publicPath.test(name) && name.endsWith('.bin'));

// The record families a relay view replaces with another poll's, each with
// the refusal of the first of them a result visit reads.
const foreignFamilies = [
    {
        family: 'registrations',
        pattern: /^registration\//u,
        reason: 'A registration header was refused.',
    },
    {
        family: 'contributions',
        pattern: /^contribution-\d+\//u,
        reason: 'An opening was refused.',
    },
    {
        family: 'close records',
        pattern: /^close\//u,
        reason: 'The close intent was refused.',
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
    foreign: ForeignPoll,
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
        commandLineArguments: [
            String(participantCount),
            String(optionCount),
            ...(mode === 'result' ? [] : [mode]),
            ...(foreignPoll === undefined ? [] : [foreignOption + foreignPoll]),
        ],
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
        const chromes: (ChromeParticipant | undefined)[] = [];
        // Copies of a participant's private state, each its own Chrome
        // process at that participant's origin: the equivocator's, and an
        // honest participant's whose records are then lost.
        const copies = new Map<
            string,
            Readonly<{ position: number; chrome: ChromeParticipant }>
        >();
        let relay: Relay | undefined;
        let sampling = true;
        let monitor: Promise<void> | undefined;
        // The participants' private state lives only as long as the run.
        let profiles: string | undefined;
        let guardFailure: Error | undefined;
        try {
            const {
                maximumCorruptParticipantCount,
                minimumTurnout,
                releaseThreshold,
            } = deriveSupportedProfile(participantCount, optionCount);
            const foreign =
                foreignPoll === undefined
                    ? undefined
                    : await loadForeignPoll(foreignPoll);
            // In a result run the last corrupt position equivocates, as in
            // the native result ceremony: two copies of its private state
            // sign two more ballots.
            const equivocator =
                noResult || maximumCorruptParticipantCount === 0
                    ? undefined
                    : maximumCorruptParticipantCount;
            // The corrupt positions follow the organizer, as in the native
            // ceremonies; forgeries and altered state are shown to honest ones.
            const honest = (position: number) =>
                position === 0 || position > maximumCorruptParticipantCount;
            const copyNames =
                equivocator === undefined ? [] : ['conflicting', 'late'];
            // In a no-result run the last corrupt position runs a client that
            // signs an authentic invalid ballot, and casts it on time.
            const invalidAuthor =
                mode === 'no-result' && maximumCorruptParticipantCount > 0
                    ? maximumCorruptParticipantCount
                    : undefined;
            assert.ok(
                freemem() >=
                    2 *
                        (participantCount + copyNames.length) *
                        participantMemoryLimit,
                'Insufficient host memory for the browser cohort.',
            );
            const descriptor = deriveParticipantDescriptor(
                participantCount,
                optionCount,
            );
            const { runtime, invalidBallotClient } =
                await assembleParticipantRuntime(
                    log,
                    descriptor,
                    invalidAuthor !== undefined,
                );
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
            const publicDirectory = path.join(log.runDirectoryPath, 'public');
            await mkdir(publicDirectory);
            relay = await startRelay(runtime, publicDirectory, corrupt);
            const { views, refused: refusedPublications, halting } = relay;
            profiles = await mkdtemp(
                path.join(root, 'temp/participant-browser-'),
            );
            const profileDirectory = profiles;
            const peaks = new Array<number>(participantCount).fill(0);
            const copyPeaks = new Map<string, number>();
            // Samples one Chrome process tree against the guard.
            const sample = async (
                chrome: ChromeParticipant,
                details: Readonly<{ position: number; copy?: string }>,
            ) => {
                const bytes = await readProtocolProcessTree(
                    chrome.processIdentifier,
                );
                if (bytes === undefined) return 0;
                log.writeEvent({
                    eventType: 'participant-process-memory',
                    details: { ...details, bytes },
                });
                if (bytes > participantMemoryLimit)
                    guardFailure ??= new Error(
                        'Participant process-tree memory guard exceeded.',
                    );
                return bytes;
            };
            monitor = (async () => {
                while (sampling) {
                    for (const [position, chrome] of chromes.entries())
                        if (chrome !== undefined)
                            peaks[position] = Math.max(
                                peaks[position],
                                await sample(chrome, { position }),
                            );
                    for (const [copy, { position, chrome }] of copies)
                        copyPeaks.set(
                            copy,
                            Math.max(
                                copyPeaks.get(copy) ?? 0,
                                await sample(chrome, { position, copy }),
                            ),
                        );
                    await delay(2000);
                }
            })();
            const origin = (position: number) =>
                `http://127.0.0.1:${String(basePort + position)}`;
            const profile = (position: number) =>
                path.join(profileDirectory, `participant-${String(position)}`);
            // A departed participant's browser and private state are gone.
            const departed = new Set<number>();
            const participant = async (position: number) => {
                assert.ok(!departed.has(position), 'The participant departed.');
                const existing = chromes[position];
                if (existing !== undefined) return existing;
                const chrome = await launchChromeParticipant(
                    profile(position),
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
            // Runs one operation in a participant's page, or in a copy of its
            // private state.
            const request = async (
                position: number,
                operation: string,
                parameters: Record<string, unknown> = {},
                copy?: string,
            ) => {
                const chrome =
                    copy === undefined
                        ? await participant(position)
                        : copies.get(copy)?.chrome;
                assert.ok(chrome !== undefined, 'The copy is not running.');
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
                        ...(copy === undefined ? {} : { copy }),
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
            // Reads the generation of a participant's committed head from its
            // own page, reading nothing else.
            const headGeneration = async (position: number) =>
                Number(
                    await (
                        await participant(position)
                    ).evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open('sealed-lattice-participant');
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
        const database = opening.result;
        const reading = database.transaction('head').objectStore('head').get(0);
        reading.onsuccess = () => { database.close(); resolve(reading.result?.generation ?? 0); };
        reading.onerror = () => { database.close(); reject(reading.error); };
    };
})`),
                );
            // Counts a participant's records in one store from its own page,
            // reading none of them.
            const storedRecords = async (position: number, store: string) =>
                Number(
                    await (
                        await participant(position)
                    ).evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open('sealed-lattice-participant');
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
        const database = opening.result;
        const counting = database.transaction(${JSON.stringify(store)}).objectStore(${JSON.stringify(store)}).count();
        counting.onsuccess = () => { database.close(); resolve(counting.result); };
        counting.onerror = () => { database.close(); reject(counting.error); };
    };
})`),
                );
            const copyProfile = (copy: string) =>
                path.join(profileDirectory, `copy-${copy}`);
            // Ends a participant's browser as a crash would. Its committed
            // state is what the next launch finds, while Chrome's own
            // shutdown can outlast its deadline when other browsers write.
            const endBrowser = async (position: number) => {
                await chromes[position]?.crash();
                chromes[position] = undefined;
            };
            // Copies a participant's private state into its own Chrome
            // process at the participant's origin. The participant's browser
            // ends first, so the copy holds exactly the committed state its
            // next launch would find; crash reporting state is not
            // participant state, and its handler can outlive the browser.
            const copyParticipant = async (position: number, copy: string) => {
                await endBrowser(position);
                await cp(profile(position), copyProfile(copy), {
                    recursive: true,
                    errorOnExist: true,
                    force: false,
                    filter: (source) =>
                        path.relative(profile(position), source) !== 'Crashpad',
                });
                const chrome = await launchChromeParticipant(
                    copyProfile(copy),
                    origin(position),
                );
                copies.set(copy, { position, chrome });
                log.writeEvent({
                    eventType: 'participant-browser',
                    details: {
                        position,
                        copy,
                        version: chrome.version,
                        launchArguments: chrome.launchArguments,
                    },
                });
                return chrome;
            };
            const removeCopy = async (copy: string) => {
                await copies.get(copy)?.chrome.crash();
                copies.delete(copy);
                await rm(copyProfile(copy), {
                    recursive: true,
                    maxRetries: 10,
                    retryDelay: 500,
                });
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
            ) => {
                assert.ok(honest(position), 'Only honest state is lost.');
                const copy = `lost-${store}-${String(position)}`;
                const chrome = await copyParticipant(position, copy);
                try {
                    const generation = Number(
                        await chrome.evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open('sealed-lattice-participant');
    opening.onerror = () => reject(opening.error);
    opening.onsuccess = () => {
        const database = opening.result;
        const reading = database.transaction('head').objectStore('head').get(0);
        reading.onsuccess = () => { database.close(); resolve(reading.result?.generation ?? 0); };
        reading.onerror = () => { database.close(); reject(reading.error); };
    };
})`),
                    );
                    const record: unknown =
                        await chrome.evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open('sealed-lattice-participant');
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
})`);
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
                    const loss = {
                        position,
                        store,
                        record,
                        operation,
                        generation,
                        reason: result.reason,
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
            // Loads a halting client in the participant's browser, whose
            // participant stops for good once it durably enters the
            // generation.
            const armHalt = async (position: number, generation: number) => {
                assert.ok(honest(position), 'Only an honest client halts.');
                await endBrowser(position);
                halting.set(
                    position,
                    haltingClient(runtime.worker, generation),
                );
                await participant(position);
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
                    await chromes[position]?.crash();
                    chromes[position] = undefined;
                    await assert.rejects(halted);
                } finally {
                    halting.delete(position);
                }
                interruptions.push({ position, operation, generation });
                log.writeEvent({
                    eventType: 'participant-interruption',
                    details: { position, operation, generation },
                });
            };
            // Crashes a participant's browser while its operation, in the
            // generation it durably entered, has stored at least the given
            // records in one store ahead of its next root. The next visit
            // discards them and runs the operation again from its retained
            // seed.
            const interruptStaged = async (
                position: number,
                operation: string,
                generation: number,
                store: string,
                records: number,
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
                        (await storedRecords(position, store)) >= records
                    )
                        break;
                }
                await chromes[position]?.crash();
                chromes[position] = undefined;
                await assert.rejects(interrupted);
                assert.equal(
                    await headGeneration(position),
                    generation,
                    'The interrupted operation committed its next root first.',
                );
                const staged = {
                    store,
                    records: await storedRecords(position, store),
                };
                interruptions.push({ position, operation, generation, staged });
                log.writeEvent({
                    eventType: 'participant-interruption',
                    details: { position, operation, generation, staged },
                });
            };
            // Each participant scores every option differently, across the
            // descriptor's score range, and the result lists one option fewer
            // than the complete ranking. In a result run the first honest
            // participant after the organizer casts the all-minimum ballot,
            // an ordinary valid ballot that counts like any other.
            const { minimumScore, maximumScore } = runtime.descriptor.ballot;
            const topCount = Math.max(1, optionCount - 1);
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
                topCount,
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
            // A malformed request is refused as public input; the participant
            // continues below.
            assert.deepEqual(
                await request(1, 'accept-roster', {
                    recordIds: recordIds.map((id) => id.toUpperCase()),
                }),
                {
                    status: 'pending',
                    reason: 'Malformed proposed record identifiers.',
                },
            );
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
            // inventory. The first honest participant after the organizer
            // crashes during its generation once checkpoint records are
            // stored, during its continuation once proof records are stored,
            // and with its confirmation and opening intents; the next honest
            // one with its checkpoint retained. Each next visit discards what
            // an interrupted operation stored and continues from its retained
            // seed or coins.
            const setupReplay = positions.find(
                (position) => position > 0 && honest(position),
            );
            const setupCheckpoint = positions.find(
                (position) =>
                    setupReplay !== undefined &&
                    position > setupReplay &&
                    honest(position),
            );
            const bodyRecords =
                runtime.descriptor.contribution.publicRecords.length;
            await Promise.all(
                positions.map(async (position) => {
                    if (position === setupReplay) {
                        await interruptStaged(
                            position,
                            'contribute',
                            4,
                            'checkpoint',
                            1,
                        );
                        await interruptStaged(
                            position,
                            'contribute',
                            6,
                            'contribution',
                            bodyRecords + 1,
                        );
                    }
                    if (position === setupCheckpoint)
                        await interrupt(position, 'contribute', {}, 5);
                    assert.equal(
                        (await run(position, 'contribute')).generation,
                        7,
                    );
                }),
            );
            await expectStatus(0, 'contribute', 'refused');
            assert.equal((await run(0, 'confirm')).generation, 9);
            assert.deepEqual(await request(0, 'open'), {
                status: 'pending',
                reason: 'A public record is unavailable.',
            });
            assert.equal((await run(0, 'status')).generation, 9);
            await Promise.all(
                positions.slice(1).map(async (position) => {
                    if (position === setupReplay)
                        await interrupt(position, 'confirm', {}, 8);
                    assert.equal(
                        (await run(position, 'confirm')).generation,
                        9,
                    );
                }),
            );
            await Promise.all(
                positions.map(async (position) => {
                    if (position === setupReplay)
                        await interrupt(position, 'open', {}, 10);
                    assert.equal((await run(position, 'open')).generation, 11);
                }),
            );
            // Before its signed opening a participant publishes nothing
            // derived from its contribution body but the committed
            // confirmation, as the late-materialization argument assumes.
            assert.deepEqual(relay.earlyContributionRecords, []);
            // Every participant verifies the complete setup and retains its
            // reference once, which opens its ballot. In an empty run the
            // last participant's setup arrives only after the organizer's
            // close intent, below.
            // A ballot needs the verified setup.
            await expectStatus(0, 'ballot', 'refused', {
                scores: ballotScores(0),
            });
            const lateSetup =
                mode === 'empty' ? participantCount - 1 : undefined;
            await Promise.all(
                positions
                    .filter((position) => position !== lateSetup)
                    .map(async (position) => {
                        const verified = await run(position, 'verify-setup');
                        assert.equal(verified.generation, 12);
                        assert.equal(verified.ballot, 'open');
                    }),
            );
            await expectStatus(0, 'verify-setup', 'refused');
            // Every participant signs one ballot, the late ones starting later.
            // A result closes with every ballot but the last on time, or with
            // every ballot when a position equivocates. A no-result target has
            // one valid on-time ballot fewer than the minimum turnout, from the
            // honest positions just before the last, and the invalid author's
            // ballot on time, which would meet the turnout if it counted. An
            // empty close has no ballot at all. A signed ballot refuses other
            // scores and is only delivered again.
            const lastPosition = participantCount - 1;
            const ballotAuthors = mode === 'empty' ? [] : positions;
            const onTimeCount =
                mode === 'empty'
                    ? 0
                    : noResult
                      ? minimumTurnout -
                        1 +
                        (invalidAuthor === undefined ? 0 : 1)
                      : equivocator === undefined
                        ? participantCount - 1
                        : participantCount;
            // The equivocator's slot is conflicting, so no ballot of it counts,
            // and the invalid author's slot is usable but its ballot invalid.
            const usableCount =
                onTimeCount - (equivocator === undefined ? 0 : 1);
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
                    : positions.slice(0, onTimeCount);
            assert.equal(onTimeBallots.length, onTimeCount);
            const lateBallots = ballotAuthors.filter(
                (position) => !onTimeBallots.includes(position),
            );
            // Before its ballot the equivocator copies its private state,
            // and each copy runs as its own Chrome process at the same origin.
            // The relay refuses the pointer to the equivocator's ballot until
            // every ballot is signed, so that the pointer it stores names the
            // original ballot.
            const pointerName = (author: number) =>
                'ballot-' + String(author) + '/submission.bin';
            if (equivocator !== undefined) {
                for (const copy of copyNames)
                    await copyParticipant(equivocator, copy);
                // The original browser runs again before any ballot starts.
                await participant(equivocator);
                refusedPublications.add(pointerName(equivocator));
            }
            const refusedDelivery = {
                status: 'pending',
                reason: 'Public delivery was refused.',
            };
            // The first honest authors halt between them at every ballot
            // generation: after the attempt lock, with the journal complete,
            // with the body partly retained, with the signature intent, and
            // with the signed ballot before its delivery. Each first halt is
            // loaded before any ballot starts, so that its attempt locks with
            // the others.
            const ballotHalts = new Map(
                ballotAuthors
                    .filter(honest)
                    .slice(0, 3)
                    .map(
                        (position, index) =>
                            [
                                position,
                                [[13, 16, 17], [14], [15]][index],
                            ] as const,
                    ),
            );
            for (const [position, halts] of ballotHalts)
                await armHalt(position, halts[0]);
            await Promise.all([
                ...ballotAuthors.map(async (position) => {
                    if (lateBallots.includes(position))
                        await delay(lateBallotMilliseconds);
                    const scores = ballotScores(position);
                    if (position === equivocator)
                        assert.deepEqual(
                            await request(position, 'ballot', { scores }),
                            refusedDelivery,
                        );
                    else {
                        // A signed ballot is only delivered again. A copy of
                        // the state with the complete journal loses a
                        // journal record and stops.
                        const halts = ballotHalts.get(position) ?? [];
                        for (const generation of halts) {
                            await interrupt(
                                position,
                                'ballot',
                                { scores },
                                generation,
                            );
                            if (generation === 14)
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
                    }
                }),
                // Each copy signs other scores, the late one starting later.
                ...(equivocator === undefined
                    ? []
                    : copyNames.map(async (copy, index) => {
                          if (copy === 'late')
                              await delay(lateBallotMilliseconds);
                          assert.deepEqual(
                              await request(
                                  equivocator,
                                  'ballot',
                                  {
                                      scores: ballotScores(
                                          participantCount + index,
                                      ),
                                  },
                                  copy,
                              ),
                              refusedDelivery,
                          );
                      })),
            ]);
            if (equivocator !== undefined) {
                // The original ballot is only delivered again, now with its
                // pointer, and the copies' private state is deleted.
                refusedPublications.delete(pointerName(equivocator));
                assert.equal((await run(equivocator, 'ballot')).generation, 17);
                for (const copy of copyNames) await removeCopy(copy);
            }
            if (ballotAuthors.includes(0)) {
                await expectStatus(0, 'ballot', 'refused', {
                    scores: ballotScores(1),
                });
                assert.equal((await run(0, 'ballot')).generation, 17);
            }
            const ballotBounds = runtime.descriptor.ballot;
            // An author's pointer names the directory of its submission.
            const submissionDirectory = async (author: number) =>
                path.join(
                    publicDirectory,
                    'ballot-' + String(author),
                    (
                        await readFile(
                            path.join(publicDirectory, pointerName(author)),
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
                    runtime.descriptor.registration.signatureBytes,
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
                          return { position: equivocator, conflicting, late };
                      })();
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
            const beforeClose = mode === 'empty' ? 12 : 17;
            const submissions = (kind: string, authors: readonly number[]) =>
                authors.map((position) => ({ kind, position }));
            // The relay's pointer to the equivocator's ballot names its late
            // copy's ballot to the last participant, and its conflicting
            // copy's to the organizer's first collection.
            const pointerTo = (identity: string) =>
                Buffer.from(identity, 'hex');
            if (equivocation !== undefined)
                views[lastPosition].set(
                    pointerName(equivocation.position),
                    pointerTo(equivocation.late.identity),
                );
            // Every other participant with its verified setup collects the
            // published ballots, its own first, before any intent exists;
            // with no ballot it collects nothing and commits nothing.
            await Promise.all(
                positions
                    .slice(1)
                    .filter((position) => position !== lateSetup)
                    .map(async (position) => {
                        const details = await run(position, 'close', {
                            deliver: cast(others(position)),
                        });
                        assert.equal(details.generation, beforeClose);
                        assert.deepEqual(details.closeEvents, [
                            ...submissions('own', cast([position])),
                            ...submissions('held', cast(others(position))),
                        ]);
                    }),
            );
            views[lastPosition].clear();
            const equivocatorHeld =
                equivocation === undefined ? [] : [equivocation.position];
            if (equivocation !== undefined) {
                views[0].set(
                    pointerName(equivocation.position),
                    pointerTo(equivocation.conflicting.identity),
                );
                const collected = await run(0, 'close', {
                    deliver: equivocatorHeld,
                });
                views[0].clear();
                assert.equal(collected.generation, 17);
                assert.deepEqual(collected.closeEvents, [
                    ...submissions('own', [0]),
                    ...submissions('held', equivocatorHeld),
                ]);
            }
            // The organizer learns one honest on-time envelope without its
            // body, opens the close and locks its own intent. It then holds
            // both of the equivocator's on-time envelopes. With no ballot it
            // learns nothing.
            const announced = others(0).find(
                (position) => onTime(position) && position !== equivocator,
            );
            assert.equal(announced === undefined, mode === 'empty');
            const announcedList = announced === undefined ? [] : [announced];
            const organizerDeliveries = cast(others(0)).filter(
                (position) => position !== announced,
            );
            await expectStatus(1, 'close', 'refused', { closeTime });
            // The organizer halts with its intent before signing it, and its
            // next visit signs the retained intent without a close time.
            await interrupt(
                0,
                'close',
                {
                    deliver: organizerDeliveries,
                    announce: announcedList,
                    closeTime,
                },
                18,
            );
            const opened = await run(0, 'close');
            assert.equal(opened.generation, 19);
            const organizerCollected = [
                ...submissions('own', [0].filter(onTime)),
                ...submissions('held', equivocatorHeld),
                ...submissions('held', organizerDeliveries.filter(onTime)),
                ...submissions('known', announcedList),
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
                others(position).filter(
                    (author) =>
                        onTime(author) &&
                        !(author === equivocator && position === lastPosition),
                );
            // The first two other honest responders halt after locking the
            // intent and with their response intent.
            const responseHalts = new Map(
                positions
                    .slice(1)
                    .filter(honest)
                    .slice(0, 2)
                    .map((position, index) => [position, [19, 20][index]]),
            );
            await Promise.all(
                positions.slice(1).map(async (position) => {
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
                        ...submissions('held', heldOnTime(position)),
                        { kind: 'lock' },
                    ]);
                }),
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
            // signed proposal before delivering it.
            await interrupt(0, 'close', {}, 21);
            await interrupt(0, 'close', {}, 22);
            // Its next visit restores the completed close without replaying
            // the log, so the retained events name no author or responder;
            // the published proposal below names the responses it took.
            const concluded = await run(0, 'close');
            assert.equal(concluded.generation, 22);
            assert.deepEqual(
                concluded.closeEvents,
                [
                    ...organizerCollected,
                    { kind: 'lock' },
                    ...submissions('response', others(0)),
                    ...submissions('held', announcedList),
                ].map(({ kind }) => ({ kind })),
            );
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
                // The listing holds exactly the on-time ballots its responder
                // holds: the organizer lists both of the equivocator's
                // on-time envelopes, which makes its slot conflicting, and
                // the last participant, which held only the late one, none.
                const listed = [];
                for (
                    let offset = 4 + closeBounds.minimumResponseBodyBytes;
                    offset < 4 + length;
                    offset += 66
                )
                    listed.push(response.readUInt16LE(offset));
                assert.deepEqual(
                    listed,
                    positions
                        .filter(onTime)
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
            assert.deepEqual(named, positions.slice(0, closeBounds.quorum));
            // The profile's inventory certificate threshold is also the close
            // quorum. The participants after the organizer beyond it sign no
            // target vote; they release later from their completed close.
            const nonVoters = positions.slice(
                1,
                1 + participantCount - closeBounds.quorum,
            );
            const voters = positions.filter(
                (position) => !nonVoters.includes(position),
            );
            // Every voter verifies the barrier, classifies each usable
            // ballot, evaluates the target and signs its vote. Every on-time
            // ballot but the equivocator's is usable, every usable ballot but
            // the invalid author's is valid, a late one is reported late, and
            // a participant without a ballot has none cast.
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
                ...voters
                    .filter((position) => position !== 0 && honest(position))
                    .slice(0, 1)
                    .map((position) => [position, 23] as const),
                [0, 24] as const,
            ]);
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
                    if (halt === 24) {
                        assert.equal(details.ballotStatus, undefined);
                        return;
                    }
                    assert.equal(
                        details.ballotStatus,
                        onTime(position)
                            ? 'included'
                            : ballotAuthors.includes(position)
                              ? 'late'
                              : 'not cast',
                    );
                    assert.equal(details.usableBallots, usableCount);
                    assert.equal(details.validBallots, validCount);
                }),
            );
            // A signed vote is only delivered again.
            const repeated = await run(voters[voters.length - 1], 'target');
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
            // Every vote names its signer and one target identity, and no
            // non-voter published one.
            for (const position of nonVoters)
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
            // Every vote is published, so the certificate exists. The
            // organizer then departs before any release exists: its browser
            // closes and its private state is deleted.
            const organizerPosition = 0;
            await chromes[organizerPosition]?.close();
            chromes[organizerPosition] = undefined;
            departed.add(organizerPosition);
            await rm(profile(organizerPosition), {
                recursive: true,
                maxRetries: 10,
                retryDelay: 500,
            });
            const remaining = positions.filter(
                (position) => !departed.has(position),
            );
            const combiningPosition = remaining[remaining.length - 1];
            const releaseBounds = runtime.descriptor.release;
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
                      resumedFrom: Readonly<{
                          generation: number;
                          journalRecords: number;
                      }>;
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
                }
            } else {
                // Every remaining participant certifies the target from the
                // published votes, appends its journal of original random
                // bytes, and generates and signs its release share. The first
                // remaining voter's browser closes once a third of its journal
                // is committed, and its next visit continues from the retained
                // records.
                const { journalRecords } = releaseBounds;
                const interruptedPosition = remaining.find((position) =>
                    voters.includes(position),
                );
                assert.ok(interruptedPosition !== undefined);
                const interruptionRecords = Math.ceil(journalRecords / 3);
                const interruptRelease = async () => {
                    const interrupted = request(interruptedPosition, 'release');
                    for (;;) {
                        const outcome = await Promise.race([
                            interrupted.then(
                                () => 'settled',
                                () => 'settled',
                            ),
                            delay(1000, 'waiting'),
                        ]);
                        assert.equal(
                            outcome,
                            'waiting',
                            'The release ended before its interruption.',
                        );
                        if (
                            (await storedRecords(
                                interruptedPosition,
                                'release',
                            )) >= interruptionRecords
                        )
                            break;
                    }
                    await chromes[interruptedPosition]?.close();
                    chromes[interruptedPosition] = undefined;
                    await assert.rejects(interrupted);
                    const details = await run(interruptedPosition, 'release');
                    assert.equal(details.generation, 29);
                    assert.equal(details.encrypted, true);
                    assert.equal(
                        details.predecessor,
                        predecessor(interruptedPosition),
                    );
                    const resumedFrom = details.resumedFrom as {
                        generation: number;
                        journalRecords: number;
                    };
                    assert.equal(resumedFrom.generation, 25);
                    assert.ok(
                        resumedFrom.journalRecords >= interruptionRecords &&
                            resumedFrom.journalRecords < journalRecords,
                    );
                    return resumedFrom;
                };
                const [resumedFrom] = await Promise.all([
                    interruptRelease(),
                    ...remaining
                        .filter((position) => position !== interruptedPosition)
                        .map(async (position) => {
                            // The combining participant halts at every
                            // generation after its journal, the last with
                            // its signed release before delivery, which its
                            // next visit only delivers.
                            const halts =
                                position === combiningPosition
                                    ? [26, 27, 28, 29]
                                    : [];
                            for (const generation of halts)
                                await interrupt(
                                    position,
                                    'release',
                                    {},
                                    generation,
                                );
                            const details = await run(position, 'release');
                            assert.equal(details.generation, 29);
                            assert.equal(details.resumedFrom, undefined);
                            if (halts.length > 0) {
                                assert.equal(details.encrypted, undefined);
                                return;
                            }
                            assert.equal(details.encrypted, true);
                            assert.equal(
                                details.predecessor,
                                predecessor(position),
                            );
                        }),
                ]);
                interruption = { position: interruptedPosition, resumedFrom };
                // A release after the completed close spent the target purpose.
                for (const position of nonVoters)
                    await expectStatus(position, 'target', 'refused');
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
            // are not counted. The departed organizer's share is absent, so the
            // first share it tries is unavailable, and the lowest remaining
            // shares include a non-voter's when one exists and the interrupted
            // voter's.
            const totals = Array.from(
                { length: optionCount },
                (_unused, option) =>
                    positions
                        .filter(
                            (position) =>
                                onTime(position) && position !== equivocator,
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
            // last voter's vote in every non-voter's slot. Another replays the
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
            const voteForgeries = new Map([
                [publicName('target-vote-', hiddenVoter), relabeledVote],
                ...nonVoters.map(
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
            // A fourth set of views serves the other poll's records of one
            // family at a time. The first of them a result visit reads is
            // refused, so its participant stays pending.
            const foreignProbes: {
                family: string;
                served: number;
                hidden: number;
                reason: string;
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
                    await probe(position, view, reason);
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
                reason: string,
            ) => {
                for (const [name, bytes] of forgeries)
                    views[position].set(name, bytes);
                try {
                    assert.deepEqual(await request(position, 'result'), {
                        status: 'pending',
                        reason,
                    });
                } finally {
                    views[position].clear();
                }
            };
            const [result] = await Promise.all([
                run(combiningPosition, 'result'),
                ...[...new Set([voteProbe, shareProbe])].map(
                    async (position) => {
                        if (position === voteProbe)
                            await probe(
                                position,
                                voteForgeries,
                                'The target votes are incomplete.',
                            );
                        if (position === shareProbe && !noResult)
                            await probe(
                                position,
                                shareForgeries,
                                'The release shares are incomplete.',
                            );
                        if (position === voteProbe) {
                            await probe(
                                position,
                                registrationForgeries,
                                'The published registrations are not the retained roster.',
                            );
                            await probeForeignPoll(position);
                        }
                    },
                ),
            ]);
            assert.equal(result.encrypted, !noResult);
            assert.deepEqual(
                result.identifiers,
                noResult ? [] : expectedResult,
            );
            // None of the forged views stopped its participant: with the
            // relay's own records it combines the same outcome.
            const recovered = await run(voteProbe, 'result');
            assert.equal(recovered.encrypted, result.encrypted);
            assert.deepEqual(recovered.identifiers, result.identifiers);
            // Altered retained state stops an honest participant at its next
            // visit, and the stop outlasts restoring the exact bytes. The
            // first byte of its first data record is flipped from its own
            // page, and a second flip restores it.
            const stoppedPosition = probes[0];
            const flipDataRecord = async () =>
                (await participant(stoppedPosition))
                    .evaluate(`new Promise((resolve, reject) => {
    const opening = indexedDB.open('sealed-lattice-participant');
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
})`);
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
            const scope = [
                mode === 'empty'
                    ? "Browser registration, roster agreement, setup contribution and setup verification with no ballot cast, a participant whose setup is retained only after the organizer's close intent and so can no longer vote, close responses that list nothing under the organizer's proposal, a participant refused a ballot after its intent lock, target evaluation and votes, and a certified no-result target for which the participants remaining after the organizer departs with its private state release nothing, in the maintained participant runtime in external Chrome."
                    : noResult
                      ? "Browser registration, roster agreement, setup contribution, setup verification, signed ballots, close responses with the organizer's proposal at a close time that leaves one valid on-time ballot fewer than the minimum turnout, beside a corrupt participant's authentic invalid ballot when the profile tolerates one, target evaluation and votes, and a certified no-result target for which the participants remaining after the organizer departs with its private state release nothing, in the maintained participant runtime in external Chrome."
                      : "Browser registration, roster agreement, setup contribution, setup verification, signed ballots, one of them the all-minimum ballot, close responses with the organizer's proposal, and target evaluation and votes, release shares after the organizer departs with its private state, one of them continued after its browser closed mid-journal and any beyond the certificate quorum released without a target vote, and the combined shorter result in the maintained participant runtime in external Chrome. A corrupt participant that copies its private state signs two more ballots, one of them late, and the relay's views make its slot conflicting, so none of its ballots counts.",
                'An honest browser crashes during its contribution generation and during its continuation once it stored records ahead of its next root, and with its confirmation and opening intents, and another with its retained checkpoint; each next visit discards what an interrupted operation stored and continues from its retained seed or state.',
                `Honest browsers crash right after their participants durably enter each ${mode === 'empty' ? 'close and target' : noResult ? 'ballot, close and target' : 'ballot, close, target and release'} generation, and each next visit continues from the retained state.`,
                mode === 'empty'
                    ? "Copies of honest participants' state that lose their last data record before their close response or target vote stop for good."
                    : "Copies of honest participants' state stop for good once they lose their last ballot record with the ballot journal complete, or, before their close response or target vote, their last close record or, holding none, their last data record.",
                `Relay views that ${noResult ? 'relabel or replay votes' : 'relabel, replay or alter votes and shares'} or swap two registrations under each other's names leave their participants pending until the relay's own records let them finish, and altered retained state stops a participant for good.`,
                ...(foreign === undefined
                    ? []
                    : [
                          `Relay views that serve another poll's ${prose(foreignProbes.map(({ family }) => family))} under this poll's names leave a participant pending.`,
                      ]),
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
                        peakProcessTreeBytes: peaks,
                        copyPeakProcessTreeBytes: Object.fromEntries(copyPeaks),
                        closeTime,
                        lateBallots,
                        minimumBallot: minimumBallotAuthor,
                        couldNotVote: lateSetup,
                        nonVoters,
                        departed: [...departed],
                        interrupted: interruption,
                        interruptions,
                        stateLosses,
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
            process.stdout.write(log.runDirectoryPath + '\n');
        } finally {
            sampling = false;
            await monitor;
            for (const chrome of [
                ...chromes,
                ...[...copies.values()].map((value) => value.chrome),
            ])
                await chrome?.close().catch(() => undefined);
            for (const server of relay?.servers ?? [])
                await new Promise((resolve) => server.close(resolve));
            if (profiles !== undefined)
                await rm(profiles, { recursive: true, force: true });
            await releaseLock();
        }
    },
);
