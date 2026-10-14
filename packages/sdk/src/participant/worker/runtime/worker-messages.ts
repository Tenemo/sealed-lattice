import type {
    OutcomeVerification,
    ParticipantRequest,
    ParticipantSummary,
    ParticipantReportedDetails,
} from '../../participant-contract.js';
import { isDigest } from '../shared/bytes.js';
import type {
    IncompleteOperation,
    ParticipantRefusalReason,
} from '../shared/operation-status.js';
import { participantNamespacePattern } from '../storage/database.js';

import type { OperationMemory } from './module-delivery.js';
import { isParticipantOperation } from './operation-availability.js';

// The application's SDK supplies the namespace of the participant's local
// state, the relay's base URL, the module's URL and the identities its build
// recorded; the worker fetches the module itself and recomputes the runtime
// identity that every retained root binds. Protocol bounds come from the
// verified module and retained state, never from the page. When the page
// separates evaluation, a worker that retains the target it evaluated before
// the operation's other work ends there, and the page runs the operation
// again in a fresh worker.
export type ParticipantWorkerCommand = Readonly<{
    operation: ParticipantRequest['operation'];
    namespace: string;
    relay: string;
    module: string;
    identity: Readonly<{
        source: string;
        module: string;
        worker: string;
    }>;
    parameters: Readonly<Record<string, unknown>>;
    separateEvaluation?: boolean;
}>;

// A verification of a poll's outcome from the relay's public records alone,
// in a fresh worker that holds no participant state. The page names the
// poll's identity, and the module refuses a poll of another runtime.
export type VerificationWorkerCommand = Readonly<{
    operation: 'verify-outcome';
    poll: string;
    relay: string;
    module: string;
    identity: ParticipantWorkerCommand['identity'];
}>;

// An evaluated result reports the memory of a worker that retained the
// target it evaluated, and is never an operation's result. A refused result
// says why, and a participant that another runtime created is refused with
// that runtime's identity, which its head names. A pending result names what
// the participant waits for.
export type ParticipantWorkerResult =
    | Readonly<{
          status: 'completed';
          details: Omit<ParticipantSummary, 'isStoragePersistent'> &
              ParticipantReportedDetails &
              Readonly<Record<string, unknown>>;
      }>
    | IncompleteOperation
    | Readonly<{ status: 'evaluated'; memory: OperationMemory }>;

export type VerificationWorkerResult = OutcomeVerification;
export type WorkerResult = ParticipantWorkerResult | VerificationWorkerResult;

// A refused request changed nothing.
export const refused = <
    Reason extends Exclude<ParticipantRefusalReason, 'another runtime'>,
>(
    reason: Reason,
) => ({ status: 'refused', reason }) as const;

// An absolute HTTP or HTTPS URL in its canonical form.
const httpUrl = (value: unknown) => {
    if (typeof value !== 'string' || !URL.canParse(value)) return undefined;
    const url = new URL(value);
    return (url.protocol === 'https:' || url.protocol === 'http:') &&
        url.href === value
        ? url
        : undefined;
};

// A base URL ends with a slash and has no query or fragment, so every
// record name extends its path.
const isBaseUrl = (value: unknown) => {
    const url = httpUrl(value);
    return (
        url !== undefined &&
        url.pathname.endsWith('/') &&
        url.search === '' &&
        url.hash === ''
    );
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

const hasRuntimeAndRelay = (command: Record<string, unknown>) =>
    isBaseUrl(command.relay) &&
    httpUrl(command.module) !== undefined &&
    isRecord(command.identity) &&
    isDigest(command.identity.source) &&
    isDigest(command.identity.module) &&
    isDigest(command.identity.worker);

export const isWellFormed = (
    command: unknown,
): command is ParticipantWorkerCommand =>
    isRecord(command) &&
    hasRuntimeAndRelay(command) &&
    isParticipantOperation(command.operation) &&
    isRecord(command.parameters) &&
    typeof command.namespace === 'string' &&
    participantNamespacePattern.test(command.namespace) &&
    (command.separateEvaluation === undefined ||
        typeof command.separateEvaluation === 'boolean');

export const isVerification = (command: unknown) =>
    isRecord(command) && command.operation === 'verify-outcome';

export const isWellFormedVerification = (
    command: unknown,
): command is VerificationWorkerCommand =>
    isRecord(command) &&
    hasRuntimeAndRelay(command) &&
    command.operation === 'verify-outcome' &&
    isDigest(command.poll);
