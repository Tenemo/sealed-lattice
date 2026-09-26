import type { ParticipantLimits, ParticipantProfile } from './bounds.js';
import { writeInput, writeOwnRegistrationInput } from './kernel.js';
import type { KernelHandlers, ParticipantKernel } from './kernel.js';

// What one worker invocation shares across the participant's phases: the
// namespace and its database, the single module instance with its current
// handlers, the recomputed runtime identity, the module's shared bounds and,
// once the retained roster names the poll's profile, that profile's bounds
// and the participant's position in the roster.
export type ParticipantContext = Readonly<{
    namespace: string;
    database: IDBDatabase;
    kernel: ParticipantKernel;
    handlers: KernelHandlers;
    runtime: Uint8Array;
    limits: ParticipantLimits;
    profile?: ParticipantProfile;
}>;

export type ProfileContext = ParticipantContext &
    Readonly<{ profile: ParticipantProfile; position: number }>;

// Only the first roster positions contribute setup key material.
export const isSetupContributor = (context: ProfileContext) =>
    context.position < context.profile.setupContributorCount;

export const sessionInput = (context: ParticipantContext, bytes: Uint8Array) =>
    writeInput(context.kernel, bytes);

export const ownRegistrationInput = (
    context: ParticipantContext,
    bytes: Uint8Array,
) => writeOwnRegistrationInput(context.kernel, bytes);

// A public input that is unavailable or refused leaves the participant
// pending; it never stops the participant or replaces retained state.
export class PublicInputFailure extends Error {}

export const describe = (error: unknown) =>
    error instanceof Error ? error.message : String(error);
