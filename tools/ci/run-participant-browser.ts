import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync } from 'node:crypto';
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
import { pathToFileURL } from 'node:url';

import { completedClosePhase } from '#packages/sdk/src/participant/worker/close-state.js';
import { registrationFile } from '#packages/sdk/src/participant/worker/roster.js';
import {
    evaluatedTargetName,
    namespacedName,
    participantDatabaseName,
    setupCacheName,
} from '#packages/sdk/src/participant/worker/storage.js';
import { targetPhase } from '#packages/sdk/src/participant/worker/target-state.js';
import type { WorkerResult } from '#packages/sdk/src/participant/worker/worker.js';
import { openPublicArchive } from '#packages/sdk/src/public-archive.js';
import {
    createTranscriptFileEncoder,
    readTranscript,
    retrieveTranscript,
} from '#packages/sdk/src/transcript-archive.js';
import { createFoundationCeremonyRuntimeLoader } from '#packages/wasm/src/index.js';
import { compileOperationProofDraws } from '#tests/operation-seed-model.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';
import { startPublicArchiveReplica } from '#tools/archive/public-archive-replica.js';
import {
    runArtifactDirectoryPath,
    runWithLocalRunLog,
} from '#tools/ci/local-run-log.js';
import { createBrowserPool } from '#tools/ci/participant-browser-pool.js';
import { summarizeCpuTrace } from '#tools/ci/participant-cpu-profile.js';
import type { CpuProfileSummary } from '#tools/ci/participant-cpu-profile.js';
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
    type ParticipantOperationMeasurement,
} from '#tools/ci/participant-workflow-measurements.js';
import {
    readProtocolProcesses,
    sumProtocolProcessTree,
} from '#tools/ci/protocol-process-memory.js';
import { directoryArchiveStore } from '#tools/ci/protocol-public-archive.js';
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
// completes the contribution.
const foreignOption = '--foreign-poll=';
const profileOption = '--profile';
const basePortOption = '--base-port=';
const memoryPressureOption = '--memory-pressure';
const sequentialOption = '--sequential';
const prepopulateOption = '--prepopulate-archive';
const preserveProfilesOption = '--preserve-profiles';
const allArguments = process.argv.slice(2).filter((value) => value !== '--');
const foreignPoll = allArguments
    .find((value) => value.startsWith(foreignOption))
    ?.slice(foreignOption.length);
const profiling = allArguments.includes(profileOption);
const memoryPressure = allArguments.includes(memoryPressureOption);
const sequential = allArguments.includes(sequentialOption);
const prepopulateArchive = allArguments.includes(prepopulateOption);
const preserveProfiles = allArguments.includes(preserveProfilesOption);
const basePortArgument = allArguments
    .find((value) => value.startsWith(basePortOption))
    ?.slice(basePortOption.length);
const commandArguments = allArguments.filter(
    (value) =>
        !value.startsWith(foreignOption) &&
        value !== profileOption &&
        value !== memoryPressureOption &&
        value !== sequentialOption &&
        value !== prepopulateOption &&
        value !== preserveProfilesOption &&
        !value.startsWith(basePortOption),
);
const mode =
    (['no-result', 'empty', 'rosters', 'plain'] as const).find(
        (value) => value === commandArguments[commandArguments.length - 1],
    ) ?? 'result';
const noResult = mode !== 'result';
const counts =
    mode === 'result' ? commandArguments : commandArguments.slice(0, -1);
assert.ok(
    counts.length === 0 ||
        (counts.length === 2 &&
            counts.every((value) => /^[1-9]\d*$/u.test(value))),
    'Optionally select the participant and option counts, then no-result, empty, rosters or plain, another poll with --foreign-poll=<run directory>, --profile, --memory-pressure and --base-port=<port>.',
);
assert.ok(
    !memoryPressure || mode === 'plain',
    'Only a plain run applies memory pressure.',
);
assert.ok(
    !sequential || mode === 'plain',
    'Only an ordinary plain run selects sequential execution.',
);
assert.ok(
    !preserveProfiles || mode === 'plain',
    'Only an ordinary run preserves completed profiles for a subsequent exact-build comparison.',
);
assert.ok(
    !prepopulateArchive || mode !== 'rosters',
    'Archive prepopulation selects one roster.',
);
assert.ok(
    (mode !== 'rosters' && mode !== 'plain') || foreignPoll === undefined,
    'Rosters and plain runs serve no other poll.',
);
const [participantCount, optionCount] =
    counts.length === 0 ? [3, 2] : counts.map(Number);
assert.ok(
    mode !== 'rosters' ||
        deriveSupportedProfile(participantCount, optionCount)
            .maximumCorruptParticipantCount >= 1,
    'Two rosters need a profile that tolerates the corrupt organizer.',
);
const root = path.resolve('.');
const basePort =
    basePortArgument === undefined ? 43_600 : Number(basePortArgument);
assert.ok(
    /^[1-9]\d*$/u.test(basePortArgument ?? '1') &&
        basePort >= 1024 &&
        basePort + 2 * participantCount + 1 <= 65_535,
    'The base port leaves no room for every origin.',
);
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
const browserProcessors = Math.min(availableParallelism(), 9);
// The functions each operation's CPU profile summary ranks.
const cpuProfileEntries = 60;
const operationMilliseconds = 3_600_000;

// The relay's layout: lower-case path segments of letters, digits, dots and
// hyphens, with no traversal.
const publicPath = /^(?:[a-z0-9][a-z0-9.-]*\/)*[a-z0-9][a-z0-9.-]*$/u;

// What a relay view serves a participant instead of a stored record: other
// bytes, the record another relay stored in the named file, or nothing when
// the value is undefined.
type ViewedRecord = Buffer | Readonly<{ file: string }> | undefined;

type Relay = Readonly<{
    servers: Server[];
    // The origin that first published each stored file; only it may add
    // to it.
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
    // The archive every honest page configures once the replicas run.
    archive: { configuration: string | undefined };
    // Positions the relay serves no public record.
    withheld: Set<number>;
    // The public records the relay delivered to each position, by name.
    delivered: Set<string>[];
    // Successfully served public payloads, by exact route, for cost accounting.
    reads: Map<string, Readonly<{ requests: number; bytes: number }>>[];
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

// Each participant keeps its state under this namespace of its own origin.
const participantNamespace = 'research-cohort';
const participantDatabase = participantDatabaseName(participantNamespace);

// An honest participant's page runs every operation through the SDK's
// participant API, which carries the packaged worker; the relay serves it
// beside the packaged module and kernel, and names the archive once its
// replicas run.
const participantPage = `<!doctype html><meta charset="utf-8"><title>Participant</title><script type="module">
import { openParticipant } from '/sdk/index.js';
const bytes = (value) => Uint8Array.from(value.match(/../g), (byte) => Number.parseInt(byte, 16));
window.runParticipant = async (operation, parameters) => {
    const response = await fetch('/archive.json', { cache: 'no-store' });
    const archive = response.ok ? await response.json() : undefined;
    return openParticipant({
        namespace: ${JSON.stringify(participantNamespace)},
        relay: new URL('./', location.href).href,
        ...(archive === undefined
            ? {}
            : {
                  archive: {
                      faultBound: archive.faultBound,
                      replicas: archive.replicas.map((replica) => ({
                          baseUrl: replica.baseUrl,
                          verificationKey: bytes(replica.verificationKey),
                      })),
                  },
              }),
    }).run({ operation, parameters });
};
</script>`;

// A patched client's page checks the patched worker against the digest it
// names and sends the SDK's commands, claiming the runtime's identity. A
// halting client stands in for an honest page, so it also names the archive
// as that page does, with the foundation kernel the SDK pins.
const clientPage = (
    runtime: ParticipantRuntime,
    workerDigest: string,
    namesArchive: boolean,
) =>
    `<!doctype html><meta charset="utf-8"><title>Participant</title><script>
const runtime = ${JSON.stringify({
        identity: runtime.identity,
        worker: workerDigest,
        ...(namesArchive
            ? {
                  kernelSha256: createHash('sha256')
                      .update(runtime.kernel)
                      .digest('hex'),
              }
            : {}),
    })};
window.runParticipant = async (operation, parameters) => {
    const configuration = runtime.kernelSha256 === undefined
        ? undefined
        : await fetch('/archive.json', { cache: 'no-store' });
    const archive = configuration?.ok ? await configuration.json() : undefined;
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
            parameters,
            namespace: ${JSON.stringify(participantNamespace)},
            relay: location.origin + '/',
            module: location.origin + '/sdk/participant.wasm',
            identity: runtime.identity,
            ...(archive === undefined
                ? {}
                : {
                      archive: {
                          faultBound: archive.faultBound,
                          replicas: archive.replicas.map((replica) => ({
                              baseUrl: new URL(replica.baseUrl).href,
                              verificationKey: replica.verificationKey,
                          })),
                          kernel: location.origin + '/sdk/sealed-lattice-kernel.wasm',
                          kernelSha256: runtime.kernelSha256,
                      },
                  }),
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
    const owners = new Map<string, string>();
    const views = Array.from(
        { length: originCount },
        () => new Map<string, ViewedRecord>(),
    );
    const refused = new Set<string>();
    const earlyContributionRecords: string[] = [];
    const archive: Relay['archive'] = { configuration: undefined };
    const withheld = new Set<number>();
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
                            : clientPage(runtime, client.workerDigest, false),
                    ),
                },
            ],
            ['/sdk/index.js', { type: 'text/javascript', bytes: runtime.sdk }],
            [
                '/sdk/participant.wasm',
                { type: 'application/wasm', bytes: runtime.module },
            ],
            [
                '/sdk/sealed-lattice-kernel.wasm',
                { type: 'application/wasm', bytes: runtime.kernel },
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
        servesPublic: boolean,
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
            if (
                url.pathname === '/archive.json' &&
                archive.configuration !== undefined
            ) {
                response.writeHead(200, {
                    'Content-Type': 'application/json',
                    'Cache-Control': 'no-store',
                });
                response.end(archive.configuration);
                return;
            }
            const name = url.pathname.slice('/public/'.length);
            if (
                servesPublic &&
                url.pathname.startsWith('/public/') &&
                publicPath.test(name)
            ) {
                const file = path.join(records, name);
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
                    delivering.add(name);
                    const recordsRead =
                        reads[Number(new URL(origin).port) - basePort];
                    const previous = recordsRead.get(name);
                    recordsRead.set(name, {
                        requests: (previous?.requests ?? 0) + 1,
                        bytes: (previous?.bytes ?? 0) + bytes.length,
                    });
                    return;
                }
            }
        }
        const name = url.pathname.slice('/publish/'.length);
        const offset = Number(url.searchParams.get('offset'));
        const file = path.join(records, name);
        if (
            request.method !== 'POST' ||
            request.headers.origin !== origin ||
            !url.pathname.startsWith('/publish/') ||
            !publicPath.test(name) ||
            refused.has(name) ||
            !Number.isSafeInteger(offset) ||
            offset < 0 ||
            (owners.get(file) ?? origin) !== origin
        ) {
            response.writeHead(404);
            response.end();
            return;
        }
        const bytes = await readBody(request, 1 << 20);
        const [directory, record] = name.split('/');
        if (
            /^contribution-\d+$/u.test(directory) &&
            !preOpeningContributionRecords.has(record) &&
            (await stat(
                path.join(records, directory, 'opening-signature.bin'),
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
            owners.set(file, origin);
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
    for (let position = 0; position < originCount; position++) {
        const origin = `http://127.0.0.1:${String(basePort + position)}`;
        const served = assets(position);
        const ownRecords =
            secondRoster !== undefined && position >= participantCount
                ? secondRoster
                : publicDirectory;
        const server = createServer((request, response) => {
            // Every page is cross-origin isolated, so its worker may start
            // parallel helpers.
            response.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
            response.setHeader('Cross-Origin-Embedder-Policy', 'require-corp');
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
                                      clientPage(runtime, client.digest, true),
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
                !withheld.has(position),
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
        owners,
        views,
        refused,
        earlyContributionRecords,
        halting,
        archive,
        withheld,
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
        commandLineArguments: [
            String(participantCount),
            String(optionCount),
            ...(mode === 'result' ? [] : [mode]),
            ...(foreignPoll === undefined ? [] : [foreignOption + foreignPoll]),
            ...(profiling ? [profileOption] : []),
            ...(sequential ? [sequentialOption] : []),
            ...(prepopulateArchive ? [prepopulateOption] : []),
            ...(preserveProfiles ? [preserveProfilesOption] : []),
            ...(memoryPressure ? [memoryPressureOption] : []),
            ...(basePortArgument === undefined
                ? []
                : [basePortOption + basePortArgument]),
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
        // Failed runs retain their original profiles for same-runtime
        // continuation; a completed run may retire its test profiles.
        let profiles: string | undefined;
        let guardFailure: Error | undefined;
        // The local archive replicas, available from setup verification on.
        const archiveServers: { close(): Promise<void> }[] = [];
        let completed = false;
        const ordinaryOperations: ParticipantOperationMeasurement[] = [];
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
            // The bounds the worker derives, as the independent models give
            // them, for the expected sizes of the cohort's records.
            const bounds = compileParticipantRuntimeProfile(
                participantCount,
                optionCount,
            );
            // The proof randomness an honest ballot and release draw from
            // their seeds when no candidate is rejected, as the independent
            // models derive it.
            const proofDraws = compileOperationProofDraws(
                deriveSupportedProfile(participantCount, optionCount),
            );
            const runnerSnapshot = path.join(
                log.runDirectoryPath,
                'sources/tools/ci/run-participant-browser.ts',
            );
            await mkdir(path.dirname(runnerSnapshot), { recursive: true });
            await writeFile(
                runnerSnapshot,
                await readFile(import.meta.filename),
                { flag: 'wx' },
            );
            const { runtime, invalidBallotClient } =
                await assembleParticipantRuntime(
                    log,
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
                refused: refusedPublications,
                halting,
                delivered: deliveredRecords,
            } = relay;
            profiles = await mkdtemp(
                path.join(root, 'temp/participant-browser-'),
            );
            const profileDirectory = profiles;
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
                        const launching = performance.now();
                        const chrome = await launchChromeParticipant(
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
                        browserDetails.set(key, details);
                        log.writeEvent({
                            eventType: 'participant-browser',
                            details: {
                                ...details,
                                milliseconds: performance.now() - launching,
                                version: chrome.version,
                                launchArguments: chrome.launchArguments,
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
                    // The page names the archive that the relay configures
                    // when the operation starts, unless it is the corrupt
                    // client's.
                    const namesArchive =
                        relay?.archive.configuration !== undefined &&
                        corrupt?.position !== position;
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
                    if (guardFailure !== undefined) throw guardFailure;
                    const milliseconds = performance.now() - started;
                    if (result.status === 'completed') {
                        const { archiveBytes } = result.details.memory as {
                            archiveBytes: number;
                        };
                        assert.ok(
                            Number.isSafeInteger(archiveBytes) &&
                                archiveBytes >= 0,
                        );
                        if (
                            ['verify-setup', 'archive', 'transcripts'].includes(
                                operation,
                            )
                        )
                            assert.equal(
                                archiveBytes > 0,
                                namesArchive,
                                'Archive memory must match the configured client at position ' +
                                    String(position) +
                                    ' during ' +
                                    operation +
                                    '.',
                            );
                    }
                    if (
                        recovery &&
                        result.status === 'completed' &&
                        !['status', 'transcripts'].includes(operation)
                    )
                        recoveryOperations.delete(position);
                    if (mode === 'plain' && result.status === 'completed') {
                        if (operation === 'release' || operation === 'archive')
                            assert.deepEqual(
                                publicRecordReads().filter(({ route }) =>
                                    /^contribution-\d+\/(?:polynomial-\d+|proof)\.bin$/u.test(
                                        route,
                                    ),
                                ),
                                [],
                                'A healthy recording visit must reuse its authenticated setup archive.',
                            );
                        const details = result.details as unknown as Pick<
                            ParticipantOperationMeasurement,
                            'generation' | 'memory' | 'evaluationMemory'
                        >;
                        ordinaryOperations.push({
                            position,
                            operation,
                            started,
                            finished: started + milliseconds,
                            generation: details.generation,
                            memory: details.memory,
                            evaluationMemory: details.evaluationMemory,
                        });
                    }
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
            // Deletes a participant's public caches from its own page: the
            // verified setup's aggregate and the target it evaluated, which
            // hold no authority. Its next visit rebuilds them by verifying
            // the setup and evaluating the target again from whatever public
            // records it reads.
            const discardPublicCaches = async (position: number) => {
                const names = [setupCacheName, evaluatedTargetName].map(
                    (name) => namespacedName(name, participantNamespace),
                );
                await inBrowser(position, undefined, (chrome) =>
                    chrome.evaluate(`Promise.all(${JSON.stringify(names)}.map((name) => new Promise((resolve, reject) => {
    const deleting = indexedDB.deleteDatabase(name);
    deleting.onsuccess = () => resolve(undefined);
    deleting.onerror = () => reject(deleting.error);
})))`),
                );
            };
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
            // Every member casts a counted ballot, the organizer closes
            // at the current time after every ballot, the first quorum of
            // members vote on the target, and every member releases.
            const servicePrepopulation: Readonly<Record<string, unknown>>[] =
                [];
            const createArchives = async () => {
                assert.ok(relay);
                const archiveKeys = Array.from(
                    { length: mode === 'plain' ? 3 : 4 },
                    () => generateKeyPairSync('ml-dsa-65').privateKey,
                );
                const archivePolicy = {
                    faultBound: 1,
                    verificationKeys: archiveKeys.map((key) =>
                        createPublicKey(key)
                            .export({ type: 'spki', format: 'der' })
                            .subarray(-1952),
                    ),
                };
                const archiveRuntime =
                    await createFoundationCeremonyRuntimeLoader(
                        pathToFileURL(
                            path.join(
                                root,
                                'packages/sdk/dist/sealed-lattice-kernel.wasm',
                            ),
                        ),
                        {
                            expectedKernelSha256Hex: createHash('sha256')
                                .update(runtime.kernel)
                                .digest('hex'),
                        },
                    )();
                let silentBase: string | undefined;
                if (mode !== 'plain') {
                    const silentReplica = createServer(() => {
                        /* A replica that accepts connections and never answers. */
                    });
                    archiveServers.push({
                        close: () =>
                            new Promise<void>((resolve) => {
                                silentReplica.closeAllConnections();
                                silentReplica.close(() => resolve());
                            }),
                    });
                    await new Promise<void>((resolve) => {
                        silentReplica.listen(0, '127.0.0.1', resolve);
                    });
                    const silentAddress = silentReplica.address();
                    assert.ok(
                        silentAddress !== null &&
                            typeof silentAddress === 'object',
                    );
                    silentBase = `http://127.0.0.1:${String(silentAddress.port)}/`;
                }
                const archiveContext = organizer.poll;
                assert.ok(typeof archiveContext === 'string');
                const replicas: Awaited<
                    ReturnType<typeof startPublicArchiveReplica>
                >[] = [];
                let serviceTransfer: ParticipantTransfer | undefined;
                for (const [replicaPosition, privateKey] of archiveKeys
                    .slice(0, 3)
                    .entries()) {
                    const replica = await startPublicArchiveReplica({
                        directory: path.join(
                            profileDirectory,
                            'archive',
                            String(replicaPosition),
                        ),
                        context: archiveContext,
                        policy: archivePolicy,
                        replicaPosition,
                        privateKey,
                        runtime: archiveRuntime,
                        maximumRecords: 65_536,
                        maximumTotalBytes: 4_294_967_291,
                        maximumStoredRecords: 65_536,
                        maximumStoredBytes: 4_294_967_291,
                        observeRequest: (incoming, response) => {
                            const position = positions.find(
                                (candidate) =>
                                    incoming.headers.origin ===
                                    origin(candidate),
                            );
                            if (position !== undefined)
                                observeParticipantTransfer(
                                    incoming,
                                    response,
                                    transfers[position],
                                );
                            else if (serviceTransfer !== undefined)
                                observeParticipantTransfer(
                                    incoming,
                                    response,
                                    serviceTransfer,
                                );
                        },
                    });
                    archiveServers.push(replica);
                    replicas.push(replica);
                }
                relay.archive.configuration = JSON.stringify({
                    faultBound: archivePolicy.faultBound,
                    replicas: [
                        ...replicas.map((replica) => replica.baseUrl),
                        ...(silentBase === undefined ? [] : [silentBase]),
                    ].map((baseUrl, replicaPosition) => ({
                        baseUrl,
                        verificationKey:
                            archivePolicy.verificationKeys[
                                replicaPosition
                            ].toString('hex'),
                    })),
                });
                const populated = new Set<string>();
                const prepopulate = async () => {
                    if (!prepopulateArchive) return;
                    // Only copy public relay bytes. Participants still encode
                    // the bytes their verifiers consume, check the resulting
                    // identities, and require complete-closure acknowledgements.
                    const files = (
                        await readdir(publicDirectory, {
                            recursive: true,
                            withFileTypes: true,
                        })
                    )
                        .filter((entry) => entry.isFile())
                        .map((entry) =>
                            path
                                .relative(
                                    publicDirectory,
                                    path.join(entry.parentPath, entry.name),
                                )
                                .split(path.sep)
                                .join('/'),
                        )
                        .filter((name) => !populated.has(name))
                        .sort();
                    let bytes = 0;
                    for (const name of files) {
                        assert.match(name, publicPath);
                        bytes += (await stat(path.join(publicDirectory, name)))
                            .size;
                    }
                    if (files.length === 0) return;
                    assert.ok(bytes <= 4_294_967_291);
                    const clients = replicas.map((replica, position) =>
                        openPublicArchive(archiveRuntime, {
                            context: archiveContext,
                            faultBound: 0,
                            replicas: [
                                {
                                    baseUrl: replica.baseUrl,
                                    verificationKey:
                                        archivePolicy.verificationKeys[
                                            position
                                        ],
                                },
                            ],
                            maximumRecords: 65_536,
                            maximumTotalBytes: 4_294_967_291,
                        }),
                    );
                    const started = performance.now();
                    serviceTransfer = emptyParticipantTransfer();
                    try {
                        for (const name of files) {
                            const encoder = createTranscriptFileEncoder(
                                clients[0],
                                name,
                                async (record) => {
                                    await Promise.all(
                                        clients.map((client) =>
                                            client.store(
                                                record,
                                                AbortSignal.timeout(60_000),
                                            ),
                                        ),
                                    );
                                },
                            );
                            const file = await open(
                                path.join(publicDirectory, name),
                                'r',
                            );
                            try {
                                const chunk = Buffer.alloc(1 << 20);
                                for (;;) {
                                    const { bytesRead } =
                                        await file.read(chunk);
                                    if (bytesRead === 0) break;
                                    await encoder.write(
                                        chunk.subarray(0, bytesRead),
                                    );
                                }
                                await encoder.finish();
                                populated.add(name);
                            } finally {
                                await file.close();
                            }
                        }
                        const measurement = {
                            files: files.length,
                            sourceDiskReadBytes: bytes,
                            milliseconds: performance.now() - started,
                            transfers: serviceTransfer,
                        };
                        servicePrepopulation.push(measurement);
                        log.writeEvent({
                            eventType: 'service-archive-prepopulation',
                            details: measurement,
                        });
                    } finally {
                        serviceTransfer = undefined;
                    }
                };
                await prepopulate();
                return {
                    archiveContext,
                    archivePolicy,
                    archiveRuntime,
                    replicas,
                    prepopulate,
                };
            };
            let startedArchives: ReturnType<typeof createArchives> | undefined;
            const startArchives = () => (startedArchives ??= createArchives());
            let ordinaryArchive: Record<string, unknown> | undefined;
            const completeRoster = async (
                members: readonly Member[],
                recordIds: readonly string[],
                scores: readonly (readonly number[])[],
            ) => {
                const [organizing, ...accepting] = members;
                assert.equal(
                    (await act(organizing, 'propose-roster', { recordIds }))
                        .generation,
                    3,
                );
                await act(organizing, 'publish');
                for (const details of await Promise.all(
                    accepting.map((member) =>
                        act(member, 'accept-roster', { recordIds }),
                    ),
                ))
                    assert.equal(details.generation, 3);
                const contributing = members.slice(0, setupContributorCount);
                if (memoryPressure)
                    await pressure(contributing[1].origin, 'contribute');
                await Promise.all([
                    ...contributing.map(async (member) => {
                        assert.equal(
                            (await act(member, 'contribute')).generation,
                            7,
                        );
                        assert.equal(
                            (await act(member, 'confirm')).generation,
                            9,
                        );
                    }),
                    ...members
                        .slice(setupContributorCount)
                        .map(async (member) => {
                            assert.equal(
                                (await act(member, 'confirm')).generation,
                                9,
                            );
                        }),
                ]);
                await Promise.all(
                    contributing.map(async (member) => {
                        assert.equal(
                            (await act(member, 'open')).generation,
                            11,
                        );
                    }),
                );
                if (mode === 'plain') await startArchives();
                await Promise.all(
                    members.map(async (member) => {
                        const verified = await act(member, 'verify-setup');
                        assert.equal(verified.generation, 12);
                        assert.equal(verified.ballot, 'open');
                    }),
                );
                await Promise.all(
                    members.map(async (member, position) => {
                        assert.equal(
                            (
                                await act(member, 'ballot', {
                                    scores: scores[position],
                                })
                            ).generation,
                            17,
                        );
                    }),
                );
                const authors = members.map((_member, position) => position);
                await Promise.all(
                    accepting.map(async (member, index) => {
                        assert.equal(
                            (
                                await act(member, 'close', {
                                    deliver: authors.filter(
                                        (author) => author !== index + 1,
                                    ),
                                })
                            ).generation,
                            17,
                        );
                    }),
                );
                assert.equal(
                    (
                        await act(organizing, 'close', {
                            deliver: authors.slice(1),
                            announce: [],
                            closeTime: Date.now(),
                        })
                    ).generation,
                    19,
                );
                await Promise.all(
                    accepting.map(async (member) => {
                        assert.equal(
                            (await act(member, 'close')).generation,
                            21,
                        );
                    }),
                );
                assert.equal((await act(organizing, 'close')).generation, 22);
                await Promise.all(
                    members
                        .slice(0, bounds.close.quorum)
                        .map(async (member) => {
                            const voted = await act(member, 'target');
                            assert.equal(voted.generation, 24);
                            assert.equal(voted.ballotStatus, 'included');
                            assert.equal(voted.usableBallots, participantCount);
                            assert.equal(voted.validBallots, participantCount);
                        }),
                );
                const archiveStorage =
                    mode === 'plain' ? await startArchives() : undefined;
                await archiveStorage?.prepopulate();
                for (const details of await Promise.all(
                    members.map((member) => act(member, 'release')),
                )) {
                    assert.equal(details.generation, 29);
                    assert.equal(details.encrypted, true);
                }
                const combined = await act(
                    members[members.length - 1],
                    'result',
                );
                assert.equal(combined.encrypted, true);
                assert.deepEqual(
                    combined.identifiers,
                    rankedIdentifiers(scores),
                );
                if (mode === 'plain') {
                    await archiveStorage?.prepopulate();
                    ordinaryArchive = await act(
                        members[members.length - 1],
                        'archive',
                    );
                    assert.deepEqual(
                        ordinaryArchive.identifiers,
                        combined.identifiers,
                    );
                }
                return combined.identifiers as readonly string[];
            };
            if (mode === 'plain') {
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
                );
                // Before its signed opening no contributor published anything
                // derived from its contribution body but the committed
                // confirmation.
                assert.deepEqual(relay.earlyContributionRecords, []);
                await writeFile(
                    path.join(log.runDirectoryPath, 'result.json'),
                    JSON.stringify(
                        {
                            participantCount,
                            optionCount,
                            mode,
                            sequential,
                            servicePrepopulation,
                            poll: organizer.poll,
                            recordIds: plainRecordIds,
                            runtimeIdentity: runtime.identity.runtime,
                            peakProcessTreeBytes: peaks,
                            identifiers,
                            topCount,
                            profiled: profiling,
                            memoryPressures,
                            archive: ordinaryArchive,
                            transfers,
                            sampledResources,
                            unmeasured: [
                                'Exact productive-visit coalescence; stage groups are not visits, and a participant total is a conservative active-work upper bound for one visit',
                                'Exact transient browser and JavaScript memory peaks between samples',
                                'HTTP headers and link-layer transfer overhead',
                                'Human delays between visits',
                                'Physical-device performance and power use',
                            ],
                            workflow: memoryPressure
                                ? null
                                : summarizeParticipantWorkflow(
                                      ordinaryOperations,
                                      participantCount,
                                      sequential,
                                  ),
                            scope: [
                                'Browser registration, roster agreement, setup contribution and verification, signed ballots, close responses, target votes, release shares and the combined result of one roster of honest participants, each stage once with no crash, forgery or other roster, in the maintained participant runtime in external Chrome.',
                                ...(profiling
                                    ? [
                                          'Chrome recorded the CPU samples of every operation, which slows it.',
                                      ]
                                    : []),
                                ...(memoryPressure
                                    ? [
                                          'The second contributor first contributed in a browser that caps each WebAssembly memory below what its contribution needs, which left it pending, and its next visit completed the contribution.',
                                      ]
                                    : []),
                            ].join(' '),
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
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
                                    { status: 'pending', reason },
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
                // Before its signed opening no contributor of either roster
                // published anything derived from its contribution body but
                // the committed confirmation.
                assert.deepEqual(relay.earlyContributionRecords, []);
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
                        },
                        null,
                        2,
                    ) + '\n',
                    { flag: 'wx' },
                );
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
            // The organizer crashes with its proposal intent, and its next
            // visit verifies the records again and signs the locked proposal
            // with the retained coins. The last honest participant crashes
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
            // Only the first roster positions contribute setup key material,
            // as each participant reports once its roster is retained. Every
            // participant confirms the roster.
            const contributors = positions.slice(0, setupContributorCount);
            const confirmers = positions.slice(setupContributorCount);
            for (const position of positions) {
                const status = await run(position, 'status');
                assert.equal(status.generation, 3);
                assert.equal(status.poll, organizer.poll);
                assert.equal(
                    status.isSetupContributor,
                    position < setupContributorCount,
                );
            }
            // A participant outside the setup contributors contributes and
            // opens nothing, and verifies the setup only behind its own
            // signed confirmation.
            if (confirmers.length > 0)
                for (const operation of ['contribute', 'open', 'verify-setup'])
                    await expectStatus(confirmers[0], operation, 'refused');
            // Every setup contributor generates and retains its contribution
            // body and confirms it. No opening precedes the complete
            // confirmation inventory. The last honest contributor crashes
            // during its generation once checkpoint records are stored, with
            // its checkpoint retained, during its continuation once proof
            // records are stored, and with its confirmation and opening
            // intents. Each next visit discards what an interrupted operation
            // stored and continues from its retained seed, checkpoint or
            // coins.
            const setupReplay = [...contributors].reverse().find(honest);
            assert.notEqual(setupReplay, undefined);
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
                        await interrupt(position, 'contribute', {}, 5);
                        await interruptStaged(
                            position,
                            'contribute',
                            6,
                            'contribution',
                            bodyRecords + 1,
                        );
                    }
                    assert.equal(
                        (await run(position, 'contribute')).generation,
                        7,
                    );
                }),
            );
            await expectStatus(0, 'contribute', 'refused');
            if (setupReplay === 0) await interrupt(0, 'confirm', {}, 8);
            assert.equal((await run(0, 'confirm')).generation, 9);
            assert.deepEqual(await request(0, 'open'), {
                status: 'pending',
                reason: 'A public record is unavailable.',
            });
            assert.equal((await run(0, 'status')).generation, 9);
            await Promise.all(
                contributors.slice(1).map(async (position) => {
                    if (position === setupReplay)
                        await interrupt(position, 'confirm', {}, 8);
                    assert.equal(
                        (await run(position, 'confirm')).generation,
                        9,
                    );
                }),
            );
            // The opening waits for every participant's confirmation. The
            // last honest participant outside the setup contributors crashes
            // with its confirmation intent, and its next visit signs with
            // the locked coins.
            if (confirmers.length > 0) {
                assert.deepEqual(await request(0, 'open'), {
                    status: 'pending',
                    reason: 'A public record is unavailable.',
                });
                const confirmationReplay = [...confirmers]
                    .reverse()
                    .find(honest);
                await Promise.all(
                    confirmers.map(async (position) => {
                        if (position === confirmationReplay)
                            await interrupt(position, 'confirm', {}, 8);
                        assert.equal(
                            (await run(position, 'confirm')).generation,
                            9,
                        );
                    }),
                );
            }
            await Promise.all(
                contributors.map(async (position) => {
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
            // reference once, which opens its ballot: a setup contributor
            // behind its opening, any other participant behind its signed
            // confirmation. In an empty run the last participant's setup
            // arrives only after the organizer's close intent, below.
            // A ballot needs the verified setup.
            await expectStatus(0, 'ballot', 'refused', {
                scores: ballotScores(0),
            });
            const lateSetup =
                mode === 'empty' ? participantCount - 1 : undefined;
            // The first honest participant outside the setup contributors,
            // or the last honest contributor when every position contributes,
            // crashes while it verifies the setup, once the relay delivered it
            // the last contributor's opening, and again right after it
            // retains the verified setup. Its next visits verify the setup
            // again from the public records and then continue from the
            // retained setup.
            const verificationReplay = [
                ...confirmers,
                ...[...contributors].reverse(),
            ].find((position) => honest(position) && position !== lateSetup);
            assert.ok(verificationReplay !== undefined);
            await startArchives();
            await Promise.all(
                positions
                    .filter((position) => position !== lateSetup)
                    .map(async (position) => {
                        if (position === verificationReplay) {
                            await interruptDelivered(
                                position,
                                'verify-setup',
                                position < setupContributorCount ? 11 : 9,
                                `contribution-${String(setupContributorCount - 1)}/opening.bin`,
                            );
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
            await expectStatus(0, 'verify-setup', 'refused');
            // With its setup retained, a participant outside the setup
            // contributors still contributes and opens nothing, and only
            // delivers its signed confirmation again.
            const confirmer = confirmers.find(
                (position) => position !== lateSetup,
            );
            if (confirmer !== undefined) {
                for (const operation of ['contribute', 'open', 'verify-setup'])
                    await expectStatus(confirmer, operation, 'refused');
                assert.equal((await run(confirmer, 'confirm')).generation, 12);
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
            // The relay refuses the pointer to the equivocator's ballot until
            // every ballot is signed, so that the pointer it stores names the
            // original ballot.
            const pointerName = (author: number) =>
                'ballot-' + String(author) + '/submission.bin';
            if (equivocator !== undefined) {
                for (const copy of copyNames)
                    await copyState(equivocator, copy);
                refusedPublications.add(pointerName(equivocator));
            }
            const refusedDelivery = {
                status: 'pending',
                reason: 'Public delivery was refused.',
            };
            // The first honest authors halt between them at every ballot
            // generation: after the attempt lock, with the seed retained,
            // with the body retained, with the signature intent, and with the
            // signed ballot before its delivery.
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
            const signBallot = async (position: number) => {
                const scores = ballotScores(position);
                if (position === equivocator) {
                    assert.deepEqual(
                        await request(position, 'ballot', { scores }),
                        refusedDelivery,
                    );
                    return;
                }
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
                assert.deepEqual(
                    await request(
                        equivocator,
                        'ballot',
                        {
                            scores: ballotScores(
                                participantCount + copyNames.indexOf(copy),
                            ),
                        },
                        copy,
                    ),
                    refusedDelivery,
                );
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
            const ballotBounds = bounds.ballot;
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
            // The relay shows the omitted ballot to its author alone.
            const shown = (position: number, authors: readonly number[]) =>
                authors.filter(
                    (author) =>
                        author !== omittedVoter || position === omittedVoter,
                );
            const beforeClose = mode === 'empty' ? 12 : 17;
            const submissions = (kind: string, authors: readonly number[]) =>
                authors.map((position) => ({ kind, position }));
            // One honest verifier learns the other envelopes without their
            // bodies. Its later target checks must consume those bodies from
            // the public source even when other participants reuse custody.
            const publicBodyProbe =
                mode === 'empty'
                    ? undefined
                    : positions.find(
                          (position) =>
                              position !== 0 &&
                              honest(position) &&
                              !departed.has(position),
                      );
            // The relay serves every other participant none of the omitted
            // ballot's records until the target votes are published.
            const omission: string[] = [];
            if (omittedVoter !== undefined) {
                const directory = await submissionDirectory(omittedVoter);
                omission.push(
                    pointerName(omittedVoter),
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
                    .filter(
                        (position) =>
                            position !== lateSetup && !departed.has(position),
                    )
                    .map(async (position) => {
                        const announced = shown(
                            position,
                            cast(others(position)),
                        );
                        const delivered =
                            position === publicBodyProbe ? [] : announced;
                        const details = await run(position, 'close', {
                            deliver: delivered,
                            announce:
                                position === publicBodyProbe ? announced : [],
                        });
                        assert.equal(details.generation, beforeClose);
                        assert.deepEqual(details.closeEvents, [
                            ...submissions('own', cast([position])),
                            ...submissions('held', delivered),
                            ...submissions(
                                'known',
                                position === publicBodyProbe ? announced : [],
                            ),
                        ]);
                    }),
            );
            const equivocatorHeld =
                equivocation === undefined ? [] : [equivocation.position];
            if (equivocation !== undefined) {
                views[lastPosition].delete(pointerName(equivocation.position));
                views[0].set(
                    pointerName(equivocation.position),
                    pointerTo(equivocation.conflicting.identity),
                );
                const collected = await run(0, 'close', {
                    deliver: equivocatorHeld,
                });
                views[0].delete(pointerName(equivocation.position));
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
            const announced = shown(0, others(0)).find(
                (position) =>
                    onTime(position) &&
                    position !== equivocator &&
                    honest(position),
            );
            assert.equal(announced === undefined, mode === 'empty');
            const announcedList = announced === undefined ? [] : [announced];
            const organizerDeliveries = shown(0, cast(others(0))).filter(
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
                responders
                    .filter(honest)
                    .slice(0, 2)
                    .map((position, index) => [position, [19, 20][index]]),
            );
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
                            position === publicBodyProbe ? 'known' : 'held',
                            heldOnTime(position),
                        ),
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
                    ...submissions('response', responders),
                    ...submissions('held', announcedList),
                ].map(({ kind }) => ({ kind })),
            );
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
                        position === omittedVoter
                            ? 'omitted'
                            : onTime(position)
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
            // The three local archive replicas and a fourth that never answers
            // have run since setup verification, with fault bound one. Every
            // honest page configures them. A participant's first release archives
            // the certified target closure it read before it draws release
            // randomness.
            const { archiveContext, archivePolicy, archiveRuntime, replicas } =
                await startArchives();
            await (await startArchives()).prepopulate();
            type ArchivedTranscript = Readonly<{
                transcript: Readonly<{ identity: string; byteLength: number }>;
                parts: number;
                records: number;
                byteLength: number;
            }>;
            // The routes of an archived transcript, which the runner
            // retrieves from the replicas that still run.
            const transcriptRoutes = async (
                index: ArchivedTranscript['transcript'],
            ) => {
                const archive = openPublicArchive(archiveRuntime, {
                    context: archiveContext,
                    faultBound: archivePolicy.faultBound,
                    replicas: replicas.map((replica, replicaPosition) => ({
                        baseUrl: replica.baseUrl,
                        verificationKey:
                            archivePolicy.verificationKeys[replicaPosition],
                    })),
                    maximumRecords: 65_536,
                    maximumTotalBytes: 4_294_967_291,
                });
                const records = new Map<string, Uint8Array>();
                const store = {
                    get: (identity: string) =>
                        Promise.resolve(records.get(identity)),
                    put: (identity: string, bytes: Uint8Array) => {
                        records.set(identity, bytes);
                        return Promise.resolve();
                    },
                };
                await retrieveTranscript(archive, index, store);
                const { routes } = await readTranscript(
                    archive,
                    index,
                    store,
                    () =>
                        Promise.resolve({
                            write: () => Promise.resolve(),
                            close: () => Promise.resolve(),
                        }),
                );
                return new Set(routes);
            };
            // A participant archives, with the target closure and with its
            // outcome's transcript, every record a fresh reader verifies the
            // setup and the close from, whatever its own retained state
            // lets it skip: each roster registration's header, signature,
            // public key and proof, each setup contributor's opening, body
            // and proof, and the close intent and proposal.
            const assertClosureRoutes = async (
                index: ArchivedTranscript['transcript'],
            ) => {
                const routes = await transcriptRoutes(index);
                const expected = [
                    'poll-definition.bin',
                    'poll-signature.bin',
                    'proposal.bin',
                    'proposal-signature.bin',
                    ...recordIds.flatMap((id) =>
                        Object.values(registrationFile).map(
                            (file) => `registration/${id}/${file}`,
                        ),
                    ),
                    'close/intent.bin',
                    'close/proposal.bin',
                    'completion/target.bin',
                    ...positions.flatMap((position) => [
                        `contribution-${String(position)}/confirmation.bin`,
                        `contribution-${String(position)}/confirmation-signature.bin`,
                    ]),
                ];
                for (
                    let contributor = 0;
                    contributor < setupContributorCount;
                    contributor++
                ) {
                    const directory = `contribution-${String(contributor)}`;
                    for (const file of await readdir(
                        path.join(publicDirectory, directory),
                    ))
                        if (!file.startsWith('confirmation'))
                            expected.push(directory + '/' + file);
                }
                for (const route of expected)
                    assert.ok(
                        routes.has(route),
                        'The archived transcript lacks ' + route + '.',
                    );
            };
            // The certified target closures the first release visits
            // archived, by the position that archived each.
            const closures = new Map<number, ArchivedTranscript>();
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
            // The participant that released from an archived closure, and
            // that closure's index.
            let closureReader:
                | Readonly<{
                      reader: number;
                      transcript: Readonly<{
                          identity: string;
                          byteLength: number;
                      }>;
                  }>
                | undefined;
            if (noResult) {
                // The certified target carries no result, so each remaining
                // participant's release certifies it, archives its closure
                // and creates nothing. The corrupt client's page names no
                // archive, so its release archives nothing.
                for (const position of remaining) {
                    const details = await run(position, 'release');
                    assert.equal(details.generation, predecessor(position));
                    assert.equal(details.encrypted, false);
                    assert.equal(details.predecessor, undefined);
                    assert.equal(details.resumedFrom, undefined);
                    if (position === corrupt?.position) {
                        assert.equal(details.closure, undefined);
                        continue;
                    }
                    assert.ok(details.closure !== undefined);
                    closures.set(
                        position,
                        details.closure as ArchivedTranscript,
                    );
                }
                for (const archived of closures.values())
                    await assertClosureRoutes(archived.transcript);
            } else {
                // Every remaining participant certifies the target from the
                // published votes, archives the certified target closure it
                // read, retains the seed of its release randomness, and
                // generates and signs its release share. The first remaining
                // voter's browser closes while it generates its share from the
                // retained seed, and its next visit generates it again from
                // that seed.
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
                    // Its first visit archived the closure before the seed.
                    assert.equal(details.closure, undefined);
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
                                details.predecessor,
                                predecessor(position),
                            );
                            assert.ok(details.closure !== undefined);
                            closures.set(
                                position,
                                details.closure as ArchivedTranscript,
                            );
                        }),
                ]);
                interruption = { position: interruptedPosition, resumedFrom };
                for (const archived of closures.values())
                    await assertClosureRoutes(archived.transcript);
                // The combining participant, which the relay then serves no
                // public record and which has lost its public caches, finds
                // the archived closures among the archive's hints and
                // releases from the replicas alone, verifying the setup and
                // evaluating the target again from a closure. It halts at
                // every generation after its target lock, the last with its
                // signed release before delivery, which its next visit only
                // delivers.
                await discardPublicCaches(combiningPosition);
                let hint: Readonly<{ identity: string; byteLength: number }>;
                relay.withheld.add(combiningPosition);
                try {
                    await expectStatus(combiningPosition, 'release', 'pending');
                    const hints = (await run(combiningPosition, 'transcripts'))
                        .transcripts as readonly Readonly<{
                        identity: string;
                        byteLength: number;
                    }>[];
                    for (const archived of closures.values())
                        assert.ok(
                            hints.some(
                                (index) =>
                                    index.identity ===
                                    archived.transcript.identity,
                            ),
                        );
                    assert.ok(hints.length > 0);
                    const certifiedHints = new Set(
                        [...closures.values()].map(
                            (closure) => closure.transcript.identity,
                        ),
                    );
                    for (const index of hints.filter(
                        (candidate) => !certifiedHints.has(candidate.identity),
                    ))
                        await expectStatus(
                            combiningPosition,
                            'release',
                            'pending',
                            { transcript: index },
                        );
                    const candidate = hints.find((index) =>
                        certifiedHints.has(index.identity),
                    );
                    assert.ok(candidate !== undefined);
                    hint = candidate;
                    for (const generation of [26, 27, 28, 29])
                        await interrupt(
                            combiningPosition,
                            'release',
                            { transcript: hint },
                            generation,
                        );
                } finally {
                    relay.withheld.delete(combiningPosition);
                }
                const delivered = await run(combiningPosition, 'release');
                assert.equal(delivered.generation, 29);
                assert.equal(delivered.encrypted, undefined);
                closureReader = {
                    reader: combiningPosition,
                    transcript: hint,
                };
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
                        ]),
                        reason: 'A usable body was refused.',
                    },
                    {
                        forgery: 'withheld body',
                        forgeries: new Map<string, ViewedRecord>([
                            [ballotName('body.bin'), undefined],
                        ]),
                        reason: 'A public record is unavailable.',
                    },
                    {
                        forgery: 'replaced submission',
                        forgeries: new Map<string, ViewedRecord>(
                            ['envelope.bin', 'signature.bin', 'body.bin'].map(
                                (file) => [
                                    ballotName(file),
                                    { file: path.join(replacing, file) },
                                ],
                            ),
                        ),
                        reason: 'A listed envelope is unavailable.',
                    },
                    {
                        forgery: 'altered signature',
                        forgeries: new Map<string, ViewedRecord>([
                            [ballotName('signature.bin'), alteredSignature],
                        ]),
                        reason: 'A listed envelope was refused.',
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
                        await probe(
                            position,
                            view,
                            family === 'contributions'
                                ? 'An opening was refused.'
                                : 'The close intent was refused.',
                            'archive',
                        );
                        // Restore the cache from genuine inputs before testing
                        // another family's cached-result behavior.
                        await run(position, 'result');
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
                reason: string,
                operation: 'result' | 'archive' = 'result',
            ) => {
                if (operation === 'archive')
                    await discardPublicCaches(position);
                deliveredRecords[position].clear();
                for (const [name, bytes] of forgeries)
                    views[position].set(name, bytes);
                try {
                    assert.deepEqual(await request(position, operation), {
                        status: 'pending',
                        reason,
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
                operation: 'result' | 'archive' = 'result',
            ) => {
                deliveredRecords[position].clear();
                for (const [name, bytes] of forgeries)
                    views[position].set(name, bytes);
                try {
                    const result = await run(position, operation);
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
                            for (const { forgeries, reason } of ballotForgeries)
                                await probe(position, forgeries, reason);
                            await probe(
                                position,
                                registrationForgeries,
                                'A registration header was refused.',
                            );
                        }
                        if (position === shareProbe && !noResult)
                            await probe(
                                position,
                                shareForgeries,
                                'The release shares are incomplete.',
                            );
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
            // The archive path actually streams the held body through the
            // barrier verifier and recorder despite these wire substitutions.
            // The other probe above consumes the altered body and refuses it.
            for (const { forgeries } of ballotForgeries.slice(0, 2)) {
                const reused = await probeUnread(
                    combiningPosition,
                    forgeries,
                    'archive',
                );
                assert.equal(reused.encrypted, result.encrypted);
                assert.deepEqual(reused.identifiers, result.identifiers);
            }
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
            // A retained roster need not read an old proof. The archive
            // probe clears public caches to force owning verification of
            // the newly consumed proof instead of authenticated reuse.
            const changedProofName = `registration/${recordIds[0]}/${registrationFile.proof}`;
            const changedProof = await readFile(
                path.join(publicDirectory, changedProofName),
            );
            changedProof[0] ^= 1;
            const proofForgery = new Map([[changedProofName, changedProof]]);
            const cachedProofResult = await probeUnread(
                voteProbe,
                proofForgery,
            );
            assert.equal(cachedProofResult.encrypted, result.encrypted);
            assert.deepEqual(cachedProofResult.identifiers, result.identifiers);
            await probe(
                voteProbe,
                proofForgery,
                'The published registrations are not the retained roster.',
                'archive',
            );
            // The combining participant archives the transcript of its
            // verified outcome to three local replicas and a fourth that
            // never answers, with fault bound one. After one of the three
            // stops, the voter probe, served no public record by the relay,
            // finds the transcript among the archive's hints and reaches the
            // same outcome from the replicas alone.
            const archived = await run(combiningPosition, 'archive');
            assert.equal(archived.encrypted, result.encrypted);
            assert.deepEqual(archived.identifiers, result.identifiers);
            const transcript = archived.transcript as Readonly<{
                identity: string;
                byteLength: number;
            }>;
            await assertClosureRoutes(transcript);
            let listed:
                | readonly Readonly<{ identity: string; byteLength: number }>[]
                | undefined;
            await replicas[0].close();
            relay.withheld.add(voteProbe);
            // The voter probe has lost its public caches too, so it verifies
            // the setup and evaluates the target again from the transcript.
            await discardPublicCaches(voteProbe);
            try {
                await expectStatus(voteProbe, 'result', 'pending');
                listed = (await run(voteProbe, 'transcripts'))
                    .transcripts as NonNullable<typeof listed>;
                assert.ok(
                    listed.some(
                        (index) => index.identity === transcript.identity,
                    ),
                );
                // Every hint is tried until one verifies; a forged one
                // leaves the participant pending.
                let fromArchive: Record<string, unknown> | undefined;
                for (const index of listed) {
                    const attempt = await request(voteProbe, 'result', {
                        transcript: index,
                    });
                    if (attempt.status === 'completed') {
                        fromArchive = attempt.details;
                        break;
                    }
                    assert.equal(attempt.status, 'pending');
                }
                assert.ok(fromArchive !== undefined);
                assert.equal(fromArchive.encrypted, result.encrypted);
                assert.deepEqual(fromArchive.identifiers, result.identifiers);
            } finally {
                relay.withheld.delete(voteProbe);
            }
            relay.archive.configuration = undefined;
            assert.ok(listed !== undefined);
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
            // Browser fault checks are over. Remove every source-service
            // endpoint before the independent archive retrieval; only the
            // surviving archive replicas can supply these public records.
            for (const server of relay.servers) {
                server.closeAllConnections();
                await new Promise<void>((resolve, reject) =>
                    server.close((error) =>
                        error === undefined ? resolve() : reject(error),
                    ),
                );
            }
            // Keep exactly the participant-published records retrieved
            // after source-service and replica loss.
            // The independent reader materializes these content-bound
            // closures afresh and has no participant verification cache.
            const independentClosure = [...closures.values()][0].transcript;
            const independentArchive = openPublicArchive(archiveRuntime, {
                context: archiveContext,
                faultBound: archivePolicy.faultBound,
                replicas: replicas.map((replica, position) => ({
                    baseUrl: replica.baseUrl,
                    verificationKey: archivePolicy.verificationKeys[position],
                })),
                maximumRecords: 65_536,
                maximumTotalBytes: 4_294_967_291,
            });
            for (const [stage, index] of [
                ['closure', independentClosure],
                ['terminal', transcript],
            ] as const) {
                const started = performance.now();
                const parts = await retrieveTranscript(
                    independentArchive,
                    index,
                    await directoryArchiveStore(
                        path.join(
                            log.artifactDirectoryPath,
                            'archived-' + stage,
                        ),
                    ),
                );
                log.writeEvent({
                    eventType: 'independent-archive-retrieval',
                    details: {
                        stage,
                        index,
                        parts,
                        milliseconds: performance.now() - started,
                        unavailableReplica: 0,
                        sourceServiceUnavailable: true,
                    },
                });
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
                'Every participant confirms the roster, and only the setup contributors contribute and open; a contributor opens only once every participant confirmed. An honest setup contributor crashes during its contribution generation and during its continuation once it stored records ahead of its next root, with its retained checkpoint, and with its confirmation and opening intents, and an honest participant outside the setup contributors with its confirmation intent; each next visit discards what an interrupted operation stored and continues from its retained seed or state.',
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
                `Three local archive replicas and a fourth that never answers run with fault bound one from setup verification on. Successful setup verification archives its complete public inputs and binds that index into the participant's authenticated root. Each remaining participant's first release visit archives the certified target closure before any release randomness, reusing those authenticated setup dependencies${noResult ? '' : ', and the last remaining participant, served no public record by the relay, finds a closure among the archive hints and releases from the replicas alone'}. The last remaining participant then archives the transcript of its verified outcome; after one of the three replicas stops, another remaining participant that the relay serves no public record finds the transcript among the archive hints and reaches the same outcome from the replicas alone. Local replicas on one host are not independent fault domains.`,
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
                        closures: {
                            archived: Object.fromEntries(
                                [...closures].map(([position, closure]) => [
                                    position,
                                    closure.transcript,
                                ]),
                            ),
                            ...closureReader,
                        },
                        archive: {
                            archivist: combiningPosition,
                            transcript: archived.transcript,
                            parts: archived.parts,
                            records: archived.records,
                            byteLength: archived.byteLength,
                            unavailableReplica: 0,
                            silentReplica: 3,
                            reader: voteProbe,
                            hints: listed.length,
                            independentClosure,
                            verificationKeys: archivePolicy.verificationKeys
                                .slice(0, 3)
                                .map((key) => key.toString('hex')),
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
            completed = true;
            process.stdout.write(log.runDirectoryPath + '\n');
        } finally {
            sampling = false;
            await monitor;
            await browsers.closeAll();
            for (const server of archiveServers) await server.close();
            for (const server of relay?.servers ?? [])
                await new Promise((resolve) => server.close(resolve));
            log.writeEvent({
                eventType: 'participant-transfer-summary',
                details: { participants: transfers },
            });
            if (profiles !== undefined && completed && !preserveProfiles)
                await rm(profiles, { recursive: true, force: true });
            else if (profiles !== undefined)
                log.writeEvent({
                    eventType: 'participant-checkpoint-preserved',
                    details: {
                        directory: profiles,
                        runtimeBound: true,
                        completed,
                    },
                });
            await releaseLock();
        }
    },
);
