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
     * The relay's absolute HTTP or HTTPS base URL, ending with a slash,
     * without credentials, a query or a fragment. The package README's relay
     * section lists the routes it serves.
     */
    relay: string;
}>;

/**
 * Creates a poll as its organizer from its question and option labels, or
 * joins a poll from its signed definition. Bytes are lower-case hexadecimal.
 */
export type ParticipantEnrollment = Readonly<
    | {
          role: 'creator';
          question: string;
          /** The option labels in order; the result names option `i` as `option-i`. */
          options: readonly string[];
          /** How many option identifiers the result lists. */
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
              }>;
      }
    | {
          operation:
              | 'status'
              | 'publish'
              | 'contribute'
              | 'confirm'
              | 'select-setup'
              | 'endorse-setup'
              | 'verify-setup'
              | 'target'
              | 'release'
              | 'result';
          parameters?: PollBinding;
      }
>;

/** What the participant retains, after every completed operation. */
export type ParticipantSummary = Readonly<{
    generation: number;
    poll: string;
    bodyDigest: string;
    username: string;
    isOrganizer: boolean;
    /** The poll's question, as the participant module verified it from the signed poll definition. */
    question: string;
    /** The poll's options in order, each with the identifier the result names it by. */
    options: readonly Readonly<{ identifier: string; label: string }>[];
    /** How many option identifiers the result lists. */
    topCount: number;
    /** Whether the participant may offer setup key material, once its roster is retained. */
    isEligibleContributor: boolean | undefined;
    /**
     * The current local ballot state. `could not vote` means submission is
     * closed without an own ballot; it does not identify the cause of absence.
     */
    ballot: 'open' | 'in progress' | 'signed' | 'could not vote' | undefined;
    /**
     * The own ballot's status in the target the participant signs, once it
     * has evaluated that target. A participant that signs no target reads it
     * from the certified target in its release and result operations, and
     * every operation reports it again once its release is locked.
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
 * follows a module or worker failure, as its cause names and its detail
 * describes, and a later operation continues from the participant's last
 * committed state; a stopped participant never acts again, as its detail
 * describes. Enrollment that ends after its intent is retained but before
 * its secrets are retained stops, since that intent cannot resume private
 * generation. A participant that another runtime created is refused, naming
 * that runtime, so the application can open it with the SDK of that runtime.
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
    | { status: 'refused'; reason: 'another runtime'; runtime: string }
    | { status: 'pending'; cause: ParticipantPendingCause; detail: string }
    | {
          status: 'stopped';
          detail: string;
          stopPersistence: 'confirmed' | 'unconfirmed';
      }
>;

export type Participant = Readonly<{
    run: (request: ParticipantRequest) => Promise<ParticipantResult>;
}>;

/** What the outcome verifier reads. */
export type OutcomeVerificationOptions = Readonly<{
    /** The poll's identity in lower-case hexadecimal. */
    poll: string;
    /**
     * The relay's absolute HTTP or HTTPS base URL, ending with a slash,
     * without credentials, a query or a fragment. The package README's relay
     * section lists the routes it serves.
     */
    relay: string;
}>;

/**
 * A completed verification names whether the certified target carries an
 * encrypted result, and the result's ordered option identifiers, none for a
 * certified no-result target. A refused request changed nothing, and its
 * reason says why; a pending one waits for public records that verify, or
 * ended on a device resource or a module or worker failure, as its cause
 * names and its detail describes.
 */
export type OutcomeVerification = Readonly<
    | {
          status: 'completed';
          details: Readonly<{
              poll: string;
              encrypted: boolean;
              identifiers: readonly string[];
          }> &
              Readonly<Record<string, unknown>>;
      }
    | {
          status: 'refused';
          reason: Extract<
              ParticipantRefusalReason,
              'unsupported browser' | 'invalid request'
          >;
      }
    | { status: 'pending'; cause: ParticipantPendingCause; detail: string }
>;

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
                detail: event.message || 'The participant worker failed.',
            });
        };
        // The worker would wait for a failed helper's jobs, so the operation
        // ends as pending, as when the browser closes.
        for (const helper of helpers.workers)
            helper.onerror = (event) => {
                finish({
                    status: 'pending',
                    cause: 'worker',
                    detail: event.message || 'A participant helper failed.',
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
                detail: 'The participant worker evaluated again.',
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

const packagedRuntime = () => {
    const runtime =
        typeof __SEALED_LATTICE_PARTICIPANT_RUNTIME__ === 'undefined'
            ? undefined
            : __SEALED_LATTICE_PARTICIPANT_RUNTIME__;
    if (runtime === undefined)
        throw new Error(
            'Build the SDK through its package script so the participant runtime is packaged.',
        );
    return runtime;
};

// The relay's base URL, which every request names.
const relayUrl = (value: unknown) => {
    const relay = baseUrl(value)?.href;
    if (relay === undefined)
        throw new TypeError(
            'The relay is an absolute HTTP or HTTPS URL without credentials, a query or a fragment.',
        );
    return relay;
};

/**
 * Opens the participant whose local state the namespace names. The relay is
 * untrusted: the participant verifies every record it reads.
 */
export const openParticipant = (options: ParticipantOptions): Participant => {
    const runtime = packagedRuntime();
    const { namespace } = options;
    if (
        typeof namespace !== 'string' ||
        !participantNamespacePattern.test(namespace)
    )
        throw new TypeError(
            'A participant namespace has 1 to 64 lower-case letters, digits and inner hyphens.',
        );
    const relay = relayUrl(options.relay);
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

/**
 * Verifies a poll's outcome from the relay's public records alone, without
 * participant state, so a participant whose state stopped, or any page that
 * holds the poll's identity and relay, checks the result. A fresh worker
 * holds no credential or randomness and runs every owning verifier from the
 * signed poll definition through the certified target and its release
 * shares. The relay is untrusted.
 */
export const verifyOutcome = async (
    options: OutcomeVerificationOptions,
): Promise<OutcomeVerification> => {
    const runtime = packagedRuntime();
    const { poll } = options;
    if (typeof poll !== 'string' || !/^[0-9a-f]{128}$/u.test(poll))
        throw new TypeError(
            'A poll identity is 64 bytes in lower-case hexadecimal.',
        );
    const relay = relayUrl(options.relay);
    const url = URL.createObjectURL(
        new Blob([runtime.worker], { type: 'text/javascript' }),
    );
    try {
        return (await runWorkerOnce(url, {
            operation: 'verify-outcome',
            poll,
            relay,
            module: participantModuleUrl.href,
            identity: runtime.identity,
        })) as OutcomeVerification;
    } finally {
        URL.revokeObjectURL(url);
    }
};
