import { participantNamespacePattern } from './worker/storage.js';
import type { WorkerResult } from './worker/worker.js';

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
     * The relay's absolute HTTP or HTTPS base URL, without a query or
     * fragment. It serves each public record at `public/<name>` and accepts
     * its publication at `publish/<name>?offset=<offset>`.
     */
    relay: string;
}>;

/** Creates a poll as its organizer, or joins a poll from its signed definition. Bytes are lower-case hexadecimal. */
export type ParticipantEnrollment = Readonly<
    | {
          role: 'creator';
          manifest: string;
          topCount: number;
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
                  /** Roster positions whose published ballots to collect with their bodies. */
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
              | 'release'
              | 'result';
          parameters?: PollBinding;
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
    ballot: 'open' | 'in progress' | 'signed' | 'could not vote' | undefined;
}>;

/**
 * A refused request changed nothing; a pending one waits for public input or
 * storage; a stopped participant never acts again.
 */
export type ParticipantResult = Readonly<
    | {
          status: 'completed';
          details: ParticipantSummary & Readonly<Record<string, unknown>>;
      }
    | { status: 'refused' }
    | { status: 'pending'; reason: string }
    | {
          status: 'stopped';
          reason: string;
          stopPersistence: 'confirmed' | 'unconfirmed';
      }
>;

export type Participant = Readonly<{
    run: (request: ParticipantRequest) => Promise<ParticipantResult>;
}>;

const runWorker = (
    source: string,
    command: Readonly<Record<string, unknown>>,
) =>
    new Promise<ParticipantResult>((resolve) => {
        const url = URL.createObjectURL(
            new Blob([source], { type: 'text/javascript' }),
        );
        const worker = new Worker(url, { type: 'module' });
        const finish = (result: ParticipantResult) => {
            worker.terminate();
            URL.revokeObjectURL(url);
            resolve(result);
        };
        worker.onmessage = (event: MessageEvent<WorkerResult>) => {
            finish(event.data as ParticipantResult);
        };
        worker.onerror = (event) => {
            finish({
                status: 'pending',
                reason: event.message || 'The participant worker failed.',
            });
        };
        worker.postMessage(command);
    });

/**
 * Opens the participant whose local state the namespace names. The relay is
 * untrusted: the participant verifies every record it reads.
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
    const relay = URL.canParse(options.relay)
        ? new URL(options.relay)
        : undefined;
    if (
        relay === undefined ||
        (relay.protocol !== 'https:' && relay.protocol !== 'http:') ||
        relay.search !== '' ||
        relay.hash !== ''
    )
        throw new TypeError(
            'The relay is an absolute HTTP or HTTPS URL without a query or fragment.',
        );
    if (!relay.pathname.endsWith('/')) relay.pathname += '/';
    return {
        run: (request) =>
            runWorker(runtime.worker, {
                operation: request.operation,
                parameters: request.parameters ?? {},
                namespace,
                relay: relay.href,
                module: participantModuleUrl.href,
                identity: runtime.identity,
            }),
    };
};
