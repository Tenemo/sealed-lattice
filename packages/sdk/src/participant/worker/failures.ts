import type { ParticipantPendingCause } from './outcome.js';

// The failures that decide how an operation ends. Any other failure is a
// local fault.

// A request whose parameters are malformed is refused before the operation
// changes anything.
export class InvalidRequest extends Error {}

// A namespace whose participant database this SDK does not recognize is
// refused, and nothing is written to it.
export class UnrecognizedState extends Error {}

// A public input that is unavailable or refused leaves the participant
// pending; it never stops the participant or replaces retained state.
export class PublicInputFailure extends Error {}

// A failed write that leaves the participant's retained authority as it
// was, a transition whose exact predecessor still authenticates or staged
// records the origin had no room for, leaves the participant pending; any
// other failure is local state loss.
export class StoragePending extends Error {}

// A helper that failed, and an exhausted memory bound of the module instance
// or of the shared arena, end the operation as pending. The instance is not
// used again; a later operation starts a fresh one.
export class ResourceFailure extends Error {}

// A module call that ended without returning for any other reason, a trap or
// a host function's failure, also ends the operation as pending. The module
// reads the participant's local inputs only after their authentication, so
// such a call consumed public input or met a defect of its own, and the
// participant stays where its last commit left it.
export class ModuleFailure extends Error {}

export const pendingCause = (error: unknown): ParticipantPendingCause =>
    error instanceof PublicInputFailure
        ? 'public input'
        : error instanceof StoragePending
          ? 'storage'
          : error instanceof ResourceFailure
            ? 'resource'
            : error instanceof ModuleFailure
              ? 'module'
              : 'worker';

// How a failure ends an operation: a malformed request and an unrecognized
// participant database are refused; a failure with a cause of its own, and
// any failure before the participant's authority started, leaves the
// participant pending; any other failure after authority started stops it.
export const classifyFailure = (
    error: unknown,
    authorityStarted: boolean,
):
    | Readonly<{
          status: 'refused';
          reason: 'invalid request' | 'unrecognized state';
      }>
    | Readonly<{ status: 'pending'; cause: ParticipantPendingCause }>
    | Readonly<{ status: 'stopped' }> => {
    if (error instanceof InvalidRequest)
        return { status: 'refused', reason: 'invalid request' };
    if (error instanceof UnrecognizedState)
        return { status: 'refused', reason: 'unrecognized state' };
    const cause = pendingCause(error);
    return !authorityStarted || cause !== 'worker'
        ? { status: 'pending', cause }
        : { status: 'stopped' };
};
