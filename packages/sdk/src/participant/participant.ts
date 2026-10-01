import type { ArchiveReference } from '@sealed-lattice/wasm';

import {
    foundationKernelSha256,
    foundationKernelUrl,
} from '../foundation-kernel.js';

import { hexadecimal } from './worker/bytes.js';
import type {
    ParticipantPendingCause,
    ParticipantRefusalReason,
} from './worker/outcome.js';
import {
    affordedHelpers,
    helperRole,
    helperStartMilliseconds,
} from './worker/parallel.js';
import { participantNamespacePattern } from './worker/storage.js';
import type { WorkerResult } from './worker/worker.js';

export type {
    ParticipantPendingCause,
    ParticipantRefusalReason,
} from './worker/outcome.js';

// The application page's side of the participant runtime. The SDK carries the
// packaged worker's source, so no server can alter it, and runs every request
// in a fresh worker. The worker fetches the packaged module, checks it against
// the digest this build recorded and recomputes the runtime identity before it
// opens the namespace's local state.

type PackagedParticipantRuntime = Readonly<{
    identity: Readonly<{
        runtime: string;
        source: string;
        module: string;
        worker: string;
    }>;
    worker: string;
}>;

declare const __SEALED_LATTICE_PARTICIPANT_RUNTIME__:
    PackagedParticipantRuntime | undefined;

const participantModuleUrl = new URL('./participant.wasm', import.meta.url);

export type ParticipantOptions = Readonly<{
    /**
     * Names the local state of one participant on this origin: 1 to 64
     * lower-case letters, digits and inner hyphens.
     */
    namespace: string;
    /**
     * The relay's absolute HTTP or HTTPS base URL, without credentials, a
     * query or a fragment. It serves each public record at `public/<name>`
     * and accepts its publication at `publish/<name>?offset=<offset>`.
     */
    relay: string;
    /**
     * The archive replicas that retain the poll's certified target closure,
     * which a participant archives before it releases its share, and its
     * transcript once a participant archives its verified result, with the
     * fault bound `b` the application trusts: at least `2b + 1` and at most
     * 32 replicas.
     */
    archive?: ParticipantArchive;
}>;

export type ParticipantArchive = Readonly<{
    faultBound: number;
    replicas: readonly Readonly<{
        /**
         * An HTTPS URL, or HTTP on a loopback address, without credentials, a
         * query or a fragment.
         */
        baseUrl: string;
        /** The replica's raw ML-DSA-65 verification key. */
        verificationKey: Uint8Array;
    }>[];
}>;

/** Creates a poll as its organizer, or joins a poll from its signed definition. Bytes are lower-case hexadecimal. */
export type ParticipantEnrollment = Readonly<
    | {
          role: 'creator';
          manifest: string;
          topCount: number;
          /** The largest roster the poll admits. */
          maximumParticipants: number;
          username: string;
      }
    | {
          role: 'join';
          poll: string;
          definition: string;
          definitionSignature: string;
          username: string;
      }
>;

/** A retained participant's operations refuse another poll's identity when `poll` names one. */
type PollBinding = Readonly<{ poll?: string }>;

export type ParticipantRequest = Readonly<
    | { operation: 'create'; parameters: ParticipantEnrollment }
    | {
          operation: 'propose-roster' | 'accept-roster';
          parameters: PollBinding & Readonly<{ recordIds: readonly string[] }>;
      }
    | {
          operation: 'ballot';
          parameters?: PollBinding & Readonly<{ scores?: readonly number[] }>;
      }
    | {
          operation: 'close';
          parameters?: PollBinding &
              Readonly<{
                  /** The organizer's close time in Unix milliseconds. */
                  closeTime?: number;
                  /**
                   * Roster positions whose published ballots to collect with
                   * their bodies. A request that names neither list collects
                   * every other position's published ballot.
                   */
                  deliver?: readonly number[];
                  /** Roster positions whose published envelopes alone to record. */
                  announce?: readonly number[];
              }>;
      }
    | {
          operation:
              | 'status'
              | 'publish'
              | 'contribute'
              | 'confirm'
              | 'open'
              | 'verify-setup'
              | 'target'
              | 'archive'
              | 'transcripts';
          parameters?: PollBinding;
      }
    | {
          operation: 'release' | 'result';
          parameters?: PollBinding &
              Readonly<{
                  /** An archived transcript's index to read instead of the relay. */
                  transcript?: ArchiveReference;
              }>;
      }
>;

/** What the participant retains, after every completed operation. */
export type ParticipantSummary = Readonly<{
    generation: number;
    rootHash: string;
    poll: string;
    bodyDigest: string;
    username: string;
    isOrganizer: boolean;
    /** Whether the participant contributes setup key material, once its roster is retained. */
    isSetupContributor: boolean | undefined;
    ballot: 'open' | 'in progress' | 'signed' | 'could not vote' | undefined;
    /**
     * The own ballot's status in the target the participant signs, once it
     * has evaluated that target. A participant that signs no target reads it
     * from the certified target in its release and result visits, and every
     * operation reports it again once its release is locked.
     */
    ballotStatus: 'not cast' | 'late' | 'included' | 'omitted' | undefined;
    /**
     * Whether the browser keeps the origin's storage under storage pressure.
     * It may evict best-effort storage, which stops the participant.
     */
    persistentStorage: boolean;
}>;

/**
 * A refused request changed nothing, and its reason says why; a pending one
 * waits for public input, storage or a device resource such as memory, or
 * follows a module or worker failure, as its cause names and its reason
 * describes, and a later visit continues from the participant's last
 * committed state; a stopped participant never acts again. A participant
 * that another runtime created is refused, naming that runtime when its
 * state records it, so the application can open it with the SDK of that
 * runtime.
 */
export type ParticipantResult = Readonly<
    | {
          status: 'completed';
          details: ParticipantSummary & Readonly<Record<string, unknown>>;
      }
    | {
          status: 'refused';
          reason: Exclude<ParticipantRefusalReason, 'another runtime'>;
      }
    | { status: 'refused'; reason: 'another runtime'; runtime?: string }
    | { status: 'pending'; cause: ParticipantPendingCause; reason: string }
    | {
          status: 'stopped';
          reason: string;
          stopPersistence: 'confirmed' | 'unconfirmed';
      }
>;

export type Participant = Readonly<{
    run: (request: ParticipantRequest) => Promise<ParticipantResult>;
}>;

// Starts the helpers this context affords from the worker source and waits
// until each listens on its port, whose other ends the operation's worker
// takes. A helper that fails to load or does not listen in time leaves the
// worker without helpers.
const openHelpers = async (url: string) => {
    const count = affordedHelpers();
    if (count === 0) return { workers: [], ports: [] };
    const workers: Worker[] = [];
    const ports: MessagePort[] = [];
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = new Promise<readonly boolean[]>((resolve) => {
        timer = setTimeout(() => {
            resolve([false]);
        }, helperStartMilliseconds);
    });
    const listening = await Promise.race([
        Promise.all(
            Array.from(
                { length: count },
                () =>
                    new Promise<boolean>((resolve) => {
                        const worker = new Worker(url, { type: 'module' });
                        const channel = new MessageChannel();
                        workers.push(worker);
                        ports.push(channel.port2);
                        worker.onmessage = () => {
                            resolve(true);
                        };
                        worker.onerror = () => {
                            resolve(false);
                        };
                        worker.postMessage(helperRole, [channel.port1]);
                    }),
            ),
        ),
        deadline,
    ]);
    clearTimeout(timer);
    for (const worker of workers) {
        worker.onmessage = null;
        worker.onerror = null;
    }
    if (!listening.every(Boolean)) {
        for (const worker of workers) worker.terminate();
        for (const port of ports) port.close();
        return { workers: [], ports: [] };
    }
    return { workers, ports };
};

// Runs the command in a worker of its own beside helpers of their own, and
// ends them all once the worker answers.
const runWorkerOnce = async (
    url: string,
    command: Readonly<Record<string, unknown>>,
) => {
    const helpers = await openHelpers(url);
    return new Promise<WorkerResult>((resolve) => {
        const worker = new Worker(url, { type: 'module' });
        let finished = false;
        const finish = (result: WorkerResult) => {
            if (finished) return;
            finished = true;
            worker.terminate();
            for (const helper of helpers.workers) helper.terminate();
            resolve(result);
        };
        worker.onmessage = (event: MessageEvent<WorkerResult>) => {
            finish(event.data);
        };
        worker.onerror = (event) => {
            finish({
                status: 'pending',
                cause: 'worker',
                reason: event.message || 'The participant worker failed.',
            });
        };
        // The worker would wait for a failed helper's jobs, so the operation
        // ends as pending, as when the browser closes.
        for (const helper of helpers.workers)
            helper.onerror = (event) => {
                finish({
                    status: 'pending',
                    cause: 'worker',
                    reason: event.message || 'A participant helper failed.',
                });
            };
        worker.postMessage(command, helpers.ports);
    });
};

// Runs the request's command. An instance's memory never shrinks and ends
// only with its worker, so a worker that retained the target it evaluated
// before the operation's other work ends with its helpers, and fresh ones
// run the operation again and restore the target; the result also reports
// the evaluating worker's memory.
const runWorker = async (
    source: string,
    command: Readonly<Record<string, unknown>>,
) => {
    const url = URL.createObjectURL(
        new Blob([source], { type: 'text/javascript' }),
    );
    try {
        const first = await runWorkerOnce(url, {
            ...command,
            separateEvaluation: true,
        });
        if (first.status !== 'evaluated') return first as ParticipantResult;
        const result = await runWorkerOnce(url, {
            ...command,
            separateEvaluation: false,
        });
        if (result.status === 'evaluated')
            return {
                status: 'pending',
                cause: 'worker',
                reason: 'The participant worker evaluated again.',
            } as const;
        return (
            result.status === 'completed'
                ? {
                      status: 'completed',
                      details: {
                          ...result.details,
                          evaluationMemory: first.memory,
                      },
                  }
                : result
        ) as ParticipantResult;
    } finally {
        URL.revokeObjectURL(url);
    }
};

// A base URL is absolute HTTP or HTTPS without credentials, a query or a
// fragment, and its path ends with a slash so that every name extends it.
const baseUrl = (value: unknown) => {
    const url =
        typeof value === 'string' && URL.canParse(value)
            ? new URL(value)
            : undefined;
    if (
        url === undefined ||
        (url.protocol !== 'https:' && url.protocol !== 'http:') ||
        url.username !== '' ||
        url.password !== '' ||
        url.search !== '' ||
        url.hash !== ''
    )
        return undefined;
    if (!url.pathname.endsWith('/')) url.pathname += '/';
    return url;
};

// Asks the browser to keep the origin's storage under storage pressure,
// which it grants by its own policy; a context that cannot ask reads whether
// it already does. A refused request means best-effort storage.
const persistStorage = async () => {
    if (typeof navigator.storage !== 'object') return false;
    const request =
        typeof navigator.storage.persist === 'function'
            ? navigator.storage.persist()
            : navigator.storage.persisted();
    return request.catch(() => false);
};

/**
 * Opens the participant whose local state the namespace names. The relay and
 * the archive replicas are untrusted: the participant verifies every record
 * it reads.
 */
export const openParticipant = (options: ParticipantOptions): Participant => {
    const runtime =
        typeof __SEALED_LATTICE_PARTICIPANT_RUNTIME__ === 'undefined'
            ? undefined
            : __SEALED_LATTICE_PARTICIPANT_RUNTIME__;
    if (runtime === undefined)
        throw new Error(
            'Build the SDK through its package script so the participant runtime is packaged.',
        );
    const { namespace } = options;
    if (
        typeof namespace !== 'string' ||
        !participantNamespacePattern.test(namespace)
    )
        throw new TypeError(
            'A participant namespace has 1 to 64 lower-case letters, digits and inner hyphens.',
        );
    const relay = baseUrl(options.relay)?.href;
    if (relay === undefined)
        throw new TypeError(
            'The relay is an absolute HTTP or HTTPS URL without credentials, a query or a fragment.',
        );
    const archive = options.archive;
    const kernelSha256 = foundationKernelSha256;
    if (archive !== undefined && kernelSha256 === undefined)
        throw new Error(
            'Build the SDK through its package script so the foundation kernel is pinned.',
        );
    // The archive client accepts HTTP only on a loopback address.
    const replicas = archive?.replicas.map((replica) => {
        const url = baseUrl(replica.baseUrl);
        if (
            url === undefined ||
            (url.protocol === 'http:' &&
                url.hostname !== '127.0.0.1' &&
                url.hostname !== 'localhost') ||
            !(replica.verificationKey instanceof Uint8Array) ||
            replica.verificationKey.length !== 1952
        )
            throw new TypeError(
                'An archive replica has an HTTPS or loopback HTTP base URL without credentials, a query or a fragment, and an ML-DSA-65 verification key.',
            );
        return {
            baseUrl: url.href,
            verificationKey: hexadecimal(replica.verificationKey),
        };
    });
    if (
        archive !== undefined &&
        (!Number.isSafeInteger(archive.faultBound) ||
            archive.faultBound < 0 ||
            replicas === undefined ||
            replicas.length < 2 * archive.faultBound + 1 ||
            replicas.length > 32 ||
            new Set(replicas.map((replica) => replica.baseUrl)).size !==
                replicas.length)
    )
        throw new TypeError(
            'An archive has 2b + 1 to 32 distinct replicas for its fault bound b.',
        );
    return {
        run: async (request) => {
            const persistentStorage = await persistStorage();
            const result = await runWorker(runtime.worker, {
                operation: request.operation,
                parameters: request.parameters ?? {},
                namespace,
                relay,
                module: participantModuleUrl.href,
                identity: runtime.identity,
                ...(archive === undefined
                    ? {}
                    : {
                          archive: {
                              faultBound: archive.faultBound,
                              replicas,
                              kernel: foundationKernelUrl.href,
                              kernelSha256,
                          },
                      }),
            });
            return result.status === 'completed'
                ? {
                      status: 'completed',
                      details: { ...result.details, persistentStorage },
                  }
                : result;
        },
    };
};
