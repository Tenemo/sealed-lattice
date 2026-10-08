import { completedClosePhase } from './close-state.js';
import { rootGeneration, targetPhase } from './root-generation.js';

// What a retained participant's operation availability depends on: its root
// generation, its role, whether its retained roster names its profile and
// makes it an eligible contributor, and whether a release spent its target
// signing purpose without a vote.
export type ParticipantStage = Readonly<{
    generation: number;
    isOrganizer: boolean;
    hasProfile: boolean;
    isEligibleContributor: boolean;
    spentTargetVote: boolean;
}>;

// The stages at which each operation of a retained participant may start.
// The roster operations decide from the retained proposal, and an
// operation's parameters can narrow its availability further.
const operationAvailability = new Map<
    string,
    (stage: ParticipantStage) => boolean
>(
    Object.entries({
        status: () => true,
        publish: () => true,
        'propose-roster': () => true,
        'accept-roster': () => true,
        confirm: ({ generation }: ParticipantStage) =>
            generation === rootGeneration.rosterSigned ||
            generation === rootGeneration.preparation,
        contribute: ({ generation, isEligibleContributor }: ParticipantStage) =>
            generation === rootGeneration.preparation && isEligibleContributor,
        'select-setup': ({ generation, isOrganizer }: ParticipantStage) =>
            generation === rootGeneration.preparation && isOrganizer,
        'endorse-setup': ({ generation }: ParticipantStage) =>
            generation === rootGeneration.preparation,
        // Any original member may activate the uniquely certified setup.
        'verify-setup': ({ generation, hasProfile }: ParticipantStage) =>
            hasProfile && generation === rootGeneration.preparation,
        'cast-ballot': ({ generation, hasProfile }: ParticipantStage) =>
            hasProfile && generation >= rootGeneration.setupRetained,
        close: ({ generation, hasProfile }: ParticipantStage) =>
            hasProfile && generation >= rootGeneration.setupRetained,
        // Target signing follows the completed close, unless a release that
        // followed it spent the target purpose without a vote.
        'sign-target': ({
            generation,
            isOrganizer,
            spentTargetVote,
        }: ParticipantStage) =>
            generation >= completedClosePhase(isOrganizer) && !spentTargetVote,
        // Release follows the participant's signed target, or its completed
        // close when it signs no target; a pending target vote cannot be
        // bypassed.
        release: ({ generation, isOrganizer }: ParticipantStage) =>
            generation === completedClosePhase(isOrganizer) ||
            generation >= targetPhase.signed,
        'compute-result': ({ generation, isOrganizer }: ParticipantStage) =>
            generation >= completedClosePhase(isOrganizer),
    }),
);

// Whether a retained participant at the stage may start the operation, or
// undefined for an operation a retained participant does not have.
export const isOperationAvailable = (
    operation: string,
    stage: ParticipantStage,
): boolean | undefined => operationAvailability.get(operation)?.(stage);
