import type { ParticipantLimits, ParticipantProfile } from './bounds.js';
import { writeInput, writeOwnRegistrationInput } from './kernel.js';
import type { KernelHandlers, ParticipantKernel } from './kernel.js';
import type { ParallelHelpers } from './parallel.js';

// What a verification of public records shares: the namespace that names
// its public working storage, the module instance with its current handlers
// and its helpers, the recomputed runtime identity and the module's shared
// bounds.
export type PublicContext = Readonly<{
    namespace: string;
    kernel: ParticipantKernel;
    handlers: KernelHandlers;
    parallel: ParallelHelpers;
    runtime: Uint8Array;
    limits: ParticipantLimits;
}>;

// A public verification once the verified roster names the poll's profile.
export type PublicProfileContext = PublicContext &
    Readonly<{ profile: ParticipantProfile }>;

// What one worker invocation shares across the participant's phases: also
// the participant's database, whether a target it evaluates before other
// work ends the worker once retained and, once the retained roster names
// the poll's profile, that profile's bounds and the participant's position
// in the roster.
export type ParticipantContext = PublicContext &
    Readonly<{
        database: IDBDatabase;
        separateEvaluation: boolean;
        profile?: ParticipantProfile;
    }>;

export type ProfileContext = ParticipantContext &
    Readonly<{ profile: ParticipantProfile; position: number }>;

// Only the first roster positions contribute setup key material.
export const isSetupContributor = (context: ProfileContext) =>
    context.position < context.profile.setupContributorCount;

export const sessionInput = (context: PublicContext, bytes: Uint8Array) =>
    writeInput(context.kernel, bytes);

export const ownRegistrationInput = (
    context: ParticipantContext,
    bytes: Uint8Array,
) => writeOwnRegistrationInput(context.kernel, bytes);

// A public input that is unavailable or refused leaves the participant
// pending; it never stops the participant or replaces retained state.
export class PublicInputFailure extends Error {}

// A request whose parameters are malformed is refused before the operation
// changes anything.
export class InvalidRequest extends Error {}

export const describe = (error: unknown) =>
    error instanceof Error ? error.message : String(error);
