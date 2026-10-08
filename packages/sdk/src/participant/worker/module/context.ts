import type { ParallelHelpers } from './parallel-helpers.js';
import { writeInput, writeOwnRegistrationInput } from './participant-module.js';
import type {
    ModuleHandlers,
    ParticipantModule,
} from './participant-module.js';
import type {
    ParticipantLimits,
    ParticipantProfile,
} from './runtime-bounds.js';

// What a verification of public records shares: the namespace that names
// its public working storage, the module instance with its current handlers
// and its helpers, the recomputed runtime identity and the module's shared
// bounds.
export type PublicContext = Readonly<{
    namespace: string;
    module: ParticipantModule;
    handlers: ModuleHandlers;
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

export type ParticipantProfileContext = ParticipantContext &
    Readonly<{ profile: ParticipantProfile; position: number }>;

// Only the first roster positions contribute setup key material.
export const isEligibleContributor = (context: ParticipantProfileContext) =>
    context.position < context.profile.eligibleContributorCount;

export const writeModuleInput = (context: PublicContext, bytes: Uint8Array) =>
    writeInput(context.module, bytes);

export const ownRegistrationInput = (
    context: ParticipantContext,
    bytes: Uint8Array,
) => writeOwnRegistrationInput(context.module, bytes);

export const errorMessage = (error: unknown) =>
    error instanceof Error ? error.message : String(error);
