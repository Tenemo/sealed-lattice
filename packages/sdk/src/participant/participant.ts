import type { ArchiveReference } from '@sealed-lattice/wasm';

import {
    foundationKernelSha256,
    foundationKernelUrl,
} from '../foundation-kernel.js';

import { hexadecimal } from './worker/bytes.js';
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
     * The relay's absolute HTTP or HTTPS base URL, without credentials, a
     * query or a fragment. It serves each public record at `public/<name>`
     * and accepts its publication at `publish/<name>?offset=<offset>`.
     */
    relay: string;
    /**
     * The archive replicas that retain the poll's transcript once a
     * participant archives its verified result, with the fault bound `b`
     * the application trusts: at least `2b + 1` and at most 32 replicas.
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
              | 'archive'
              | 'transcripts';
          parameters?: PollBinding;
      }
    | {
          operation: 'result';
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
        run: (request) =>
            runWorker(runtime.worker, {
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
            }),
    };
};
