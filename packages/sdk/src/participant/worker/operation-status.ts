import type { StopPersistence } from './stop.js';

/**
 * Why a refused request changed nothing: the browser lacks a required
 * capability; the request is malformed or asks for something its parameters
 * cannot supply; the namespace holds no participant, or already holds one,
 * or holds a database this SDK does not recognize; the device lacks the
 * storage an enrollment needs; the participant belongs
 * to another poll or another runtime; or the operation is not available at
 * the participant's stage or role.
 */
export type ParticipantRefusalReason =
    | 'unsupported browser'
    | 'invalid request'
    | 'no participant'
    | 'participant exists'
    | 'unrecognized state'
    | 'insufficient storage'
    | 'another poll'
    | 'another runtime'
    | 'unavailable operation';

/**
 * What a pending participant waits for or what ended its operation early:
 * missing or refused public input, storage, a device resource such as
 * memory, a failed module call, or a worker or helper that ended or failed
 * before the participant's authority started.
 */
export type ParticipantPendingCause =
    'public input' | 'storage' | 'resource' | 'module' | 'worker';

// An operation that did not complete: a refusal that changed nothing, one of
// a participant that another runtime created, naming that runtime, a pending
// participant and a stopped one.
export type IncompleteOperation = Readonly<
    | {
          status: 'refused';
          reason: Exclude<ParticipantRefusalReason, 'another runtime'>;
      }
    | { status: 'refused'; reason: 'another runtime'; runtime: string }
    | { status: 'pending'; cause: ParticipantPendingCause; detail: string }
    | {
          status: 'stopped';
          detail: string;
          stopPersistence: StopPersistence;
      }
>;
