import type {
    OutcomeVerification,
    OutcomeVerificationOptions,
    Participant,
    ParticipantOptions,
} from './participant-contract.js';
import { helperRole } from './worker/module/parallel-helper-instance.js';
import {
    affordedHelpers,
    allStartedInTime,
} from './worker/module/parallel-helpers.js';
import type {
    VerificationWorkerCommand,
    ParticipantWorkerCommand,
    WorkerResult,
    ParticipantWorkerResult,
    VerificationWorkerResult,
} from './worker/runtime/worker-messages.js';
import { isDigest } from './worker/shared/bytes.js';
import { participantNamespacePattern } from './worker/storage/database.js';

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

// Starts the helpers this context affords from the worker source and waits
// until each listens on its port, whose other ends the operation's worker
// takes. A helper that fails to load or does not listen in time leaves the
// worker without helpers.
const openHelpers = async (url: string) => {
    const count = affordedHelpers();
    const workers: Worker[] = [];
    const ports: MessagePort[] = [];
    const ownedPorts: MessagePort[] = [];
    const stop = () => {
        for (const worker of workers) {
            worker.onmessage = null;
            worker.onerror = null;
            worker.terminate();
        }
        for (const port of ownedPorts) port.close();
        workers.length = ports.length = ownedPorts.length = 0;
    };
    if (count === 0) return { workers, ports, stop };
    try {
        const listening = await allStartedInTime(
            Array.from(
                { length: count },
                () =>
                    new Promise<boolean>((resolve) => {
                        const worker = new Worker(url, { type: 'module' });
                        workers.push(worker);
                        const channel = new MessageChannel();
                        ownedPorts.push(channel.port1, channel.port2);
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
        );
        for (const worker of workers) {
            worker.onmessage = null;
            worker.onerror = null;
        }
        if (!listening) stop();
    } catch {
        // Optional helpers that cannot start leave the operation scalar.
        stop();
    }
    return { workers, ports, stop };
};

// Runs the command in a worker of its own beside helpers of their own, and
// ends them all once the worker answers.
function runWorkerOnce(
    url: string,
    command: ParticipantWorkerCommand,
): Promise<ParticipantWorkerResult>;
function runWorkerOnce(
    url: string,
    command: VerificationWorkerCommand,
): Promise<VerificationWorkerResult>;
async function runWorkerOnce(
    url: string,
    command: ParticipantWorkerCommand | VerificationWorkerCommand,
): Promise<WorkerResult> {
    const helpers = await openHelpers(url);
    let worker: Worker | undefined;
    const pending = (detail: string): WorkerResult => ({
        status: 'pending',
        cause: 'worker',
        detail,
    });
    try {
        return await new Promise<WorkerResult>((resolve) => {
            worker = new Worker(url, { type: 'module' });
            worker.onmessage = (event: MessageEvent<WorkerResult>) => {
                resolve(event.data);
            };
            worker.onerror = (event) => {
                resolve(
                    pending(event.message || 'The participant worker failed.'),
                );
            };
            worker.onmessageerror = () =>
                resolve(
                    pending(
                        'The participant worker message could not be read.',
                    ),
                );
            // The worker would wait for a failed helper's jobs, so the operation
            // ends as pending, as when the browser closes.
            for (const helper of helpers.workers)
                helper.onerror = (event) => {
                    resolve(
                        pending(
                            event.message || 'A participant helper failed.',
                        ),
                    );
                };
            worker.postMessage(command, helpers.ports);
        });
    } catch (error) {
        return pending(error instanceof Error ? error.message : String(error));
    } finally {
        worker?.terminate();
        helpers.stop();
    }
}

// Runs the request's command. An instance's memory never shrinks and ends
// only with its worker, so a worker that retained the target it evaluated
// before the operation's other work ends with its helpers, and fresh ones
// run the operation again and restore the target; the result also reports
// the evaluating worker's memory.
const runWorker = async (
    source: string,
    command: Omit<ParticipantWorkerCommand, 'separateEvaluation'>,
): Promise<Exclude<ParticipantWorkerResult, { status: 'evaluated' }>> => {
    const url = URL.createObjectURL(
        new Blob([source], { type: 'text/javascript' }),
    );
    try {
        const first = await runWorkerOnce(url, {
            ...command,
            separateEvaluation: true,
        });
        if (first.status !== 'evaluated') return first;
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
        return result.status === 'completed'
            ? {
                  status: 'completed',
                  details: {
                      ...result.details,
                      evaluationMemory: first.memory,
                  },
              }
            : result;
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
            const isStoragePersistent = await persistStorage();
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
                      details: { ...result.details, isStoragePersistent },
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
    if (!isDigest(poll))
        throw new TypeError(
            'A poll identity is 64 bytes in lower-case hexadecimal.',
        );
    const relay = relayUrl(options.relay);
    const url = URL.createObjectURL(
        new Blob([runtime.worker], { type: 'text/javascript' }),
    );
    try {
        return await runWorkerOnce(url, {
            operation: 'verify-outcome',
            poll,
            relay,
            module: participantModuleUrl.href,
            identity: runtime.identity,
        });
    } finally {
        URL.revokeObjectURL(url);
    }
};
