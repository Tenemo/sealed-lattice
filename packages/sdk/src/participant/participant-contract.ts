import type { OperationMemory } from './worker/runtime/module-delivery.js';
import type {
    IncompleteOperation,
    ParticipantPendingCause,
    ParticipantRefusalReason,
} from './worker/shared/operation-status.js';
export type {
    ParticipantPendingCause,
    ParticipantRefusalReason,
} from './worker/shared/operation-status.js';

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
          role: 'organizer';
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
          role: 'joiner';
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
          parameters: PollBinding &
              Readonly<{ registrationBodyDigests: readonly string[] }>;
      }
    | {
          operation: 'cast-ballot';
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
              | 'sign-target'
              | 'release'
              | 'compute-result';
          parameters?: PollBinding;
      }
>;

/** What the participant retains, after every completed operation. */
export type ParticipantSummary = Readonly<{
    generation: number;
    poll: string;
    registrationBodyDigest: string;
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
    ballotState:
        'open' | 'in progress' | 'signed' | 'could not vote' | undefined;
    /**
     * The own ballot's inclusion in the target the participant signs, once
     * it has evaluated that target. A participant that signs no target reads
     * it from the certified target in its release and result operations, and
     * every operation reports it again once its release is locked.
     */
    ballotInclusion: 'not cast' | 'late' | 'included' | 'omitted' | undefined;
    /**
     * Whether the browser keeps the origin's storage under storage pressure.
     * It may evict best-effort storage, which stops the participant.
     */
    isStoragePersistent: boolean;
}>;

/**
 * A refused request changed nothing, and its reason says why; a pending one
 * waits for public input, storage or a device resource such as memory, or
 * follows a module or worker failure, as its cause names and its detail
 * describes, and a later operation continues from the participant's last
 * committed state. A stopped one ended on missing or inconsistent local
 * state, as its detail describes; once its stop persistence is confirmed,
 * the participant never acts again, and after an unconfirmed stop a later
 * operation stops again unless the participant's last committed state reads
 * back intact, from which it continues. Enrollment that ends after its intent
 * is retained but before its secrets are retained stops, since that intent
 * cannot resume private generation. A participant that another runtime
 * created is refused, naming that runtime, so the application can open it
 * with the SDK of that runtime.
 */
export type ParticipantReportedDetails = Readonly<{
    rosterUsernames?: readonly string[];
    proofRandomBytes?: number;
    closeEvents?: readonly Readonly<{ kind: string; position?: number }>[];
    usableSubmissions?: number;
    acceptedBallots?: number;
    encrypted?: boolean;
    identifiers?: readonly string[];
    predecessor?: number;
    resumedFrom?: Readonly<{ generation: number }>;
    memory?: OperationMemory;
    evaluationMemory?: OperationMemory;
}>;

export type ParticipantResponse =
    | Readonly<{
          status: 'completed';
          details: ParticipantSummary &
              ParticipantReportedDetails &
              Readonly<Record<string, unknown>>;
      }>
    | IncompleteOperation;

export type Participant = Readonly<{
    run: (request: ParticipantRequest) => Promise<ParticipantResponse>;
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
