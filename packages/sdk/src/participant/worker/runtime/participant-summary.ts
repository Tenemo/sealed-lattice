import { isEligibleContributor } from '../module/context.js';
import type { ParticipantProfileContext } from '../module/context.js';
import { hexadecimal } from '../shared/bytes.js';
import type { RestoredEnrollment } from '../stages/enrollment/enrollment.js';
import { decodeReleaseState } from '../stages/release/release-state.js';
import { decodeTargetState } from '../stages/target-vote/target-state.js';
import {
    ballotPhase,
    releasePhase,
    rootGeneration,
    targetPhase,
} from '../storage/root-generation.js';
import type { AuthenticatedRoot } from '../storage/root.js';

// What this participant's ballot is: open once the verified setup is
// retained, in progress from the attempt lock, signed, or impossible once the
// participant learned that ballot submission closed without a ballot of its
// own.
const ballotState = (root: AuthenticatedRoot) => {
    const { generation } = root.head;
    if (generation < rootGeneration.setupRetained) return undefined;
    if (generation === rootGeneration.setupRetained) return 'open';
    if (generation < ballotPhase.signed) return 'in progress';
    return (root.manifest.suffixes.ballot?.length ?? 0) > 0
        ? 'signed'
        : 'could not vote';
};

// The own ballot's status in the certified target, which the target
// signing state retains from the evaluation on, and the release state of a
// participant that signed no target from its lock on. A participant that
// signed no target and locked no release retains none.
const ballotInclusion = (
    root: AuthenticatedRoot,
    isOrganizer: boolean,
    profiled: ParticipantProfileContext | undefined,
) => {
    const { generation } = root.head;
    const { target, release } = root.manifest.suffixes;
    if (profiled === undefined) return undefined;
    if (
        generation >= targetPhase.intent &&
        target !== undefined &&
        target.length !== 0
    )
        return decodeTargetState(
            profiled.profile,
            generation,
            isOrganizer,
            target,
        ).ballotInclusion;
    return generation < releasePhase.locked || release === undefined
        ? undefined
        : decodeReleaseState(profiled.profile, generation, isOrganizer, release)
              .ballotInclusion;
};

// Whether the participant contributes setup key material is known once its
// roster is retained.
export const summary = (
    root: AuthenticatedRoot,
    enrollment: RestoredEnrollment,
    profiled: ParticipantProfileContext | undefined,
) => ({
    generation: root.head.generation,
    poll: hexadecimal(root.manifest.poll),
    registrationBodyDigest: hexadecimal(enrollment.registrationBodyDigest),
    username: enrollment.username,
    isOrganizer: enrollment.isOrganizer,
    question: enrollment.poll.question,
    options: enrollment.poll.options,
    topCount: enrollment.poll.topCount,
    isEligibleContributor:
        profiled === undefined ? undefined : isEligibleContributor(profiled),
    ballotState: ballotState(root),
    ballotInclusion: ballotInclusion(root, enrollment.isOrganizer, profiled),
});
