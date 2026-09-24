import { traceCommonMatrixPreparationVisits } from '#tests/participant-visit-dependency-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

export const fixedPublicationWitnesses = (participantCount: number) => {
    const profile = compileThresholdCompletionProfile(participantCount);
    // Unanimity of a fixed set needs at least one honest member under every
    // allowed static corruption set. This alone supplies neither publication
    // availability nor a closing protocol.
    const minimumWitnesses = profile.maximumCorruptParticipantCount + 1;
    const committees = Array.from({ length: participantCount }, (_, author) =>
        Array.from(
            { length: minimumWitnesses },
            (_unused, offset) => (author + offset) % participantCount,
        ),
    );
    const assignments = Array.from({ length: participantCount }, () => 0);
    for (const committee of committees)
        for (const member of committee) assignments[member]++;
    return { minimumWitnesses, committees, assignments };
};

// Optimistic completion-profile trace: one witness message per ballot, instant
// durable certificate assembly, and an ideal nonselective close. There is no
// READY wave or organizer proposal. Only actual newly enabled work is visited.
export const traceFixedPublicationWitnessVisits = () => {
    const participantCount = 10;
    const profile = compileThresholdCompletionProfile(participantCount);
    const { committees } = fixedPublicationWitnesses(participantCount);
    const visits = [
        ...traceCommonMatrixPreparationVisits(participantCount, []),
    ];
    const cast = new Set<number>();
    const witnessed = committees.map(() => new Set<number>());
    const closed = new Set<number>();
    const certified = new Set<number>();
    const released = new Set<number>();
    const retrieved = new Set<number>();
    let closeRequested = false;
    const visit = (participant: number, castBallot = false): void => {
        const actions: string[] = [];
        if (castBallot && !cast.has(participant)) {
            cast.add(participant);
            actions.push('ballot-origin');
        }
        for (const author of cast)
            if (
                committees[author].includes(participant) &&
                !witnessed[author].has(participant)
            ) {
                witnessed[author].add(participant);
                actions.push(`witness-ballot-${author}`);
            }
        if (closeRequested && !closed.has(participant)) {
            closed.add(participant);
            actions.push('close-evidence');
        }
        if (closed.size === participantCount && !certified.has(participant)) {
            certified.add(participant);
            actions.push('evaluate-and-certify-target');
        }
        if (
            certified.size >= profile.inventoryCertificateThreshold &&
            !released.has(participant)
        ) {
            released.add(participant);
            actions.push('release-share');
        }
        if (
            released.size >= profile.resultReleaseThreshold &&
            !retrieved.has(participant)
        ) {
            retrieved.add(participant);
            actions.push('verify-terminal');
        }
        if (actions.length) visits.push({ participant, actions });
    };
    // Finish each publication before the next author creates a ballot. This is
    // permitted sequential work, not a transport timeout or status-only visit.
    for (let author = 0; author < participantCount; author++) {
        visit(author, true);
        for (const member of committees[author]) visit(member);
    }
    closeRequested = true;
    // Participant zero acts first at each dependency boundary. The other
    // participants still coalesce all work enabled during their own visits.
    for (let wave = 0; wave < 4; wave++)
        for (
            let participant = 0;
            participant < participantCount;
            participant++
        ) {
            visit(participant);
            if (
                certified.size >= profile.inventoryCertificateThreshold &&
                !released.has(0)
            )
                visit(0);
        }
    return {
        visits,
        committees,
        witnessed: witnessed.map((members) => [...members]),
        closed: [...closed],
        certified: [...certified],
        released: [...released],
        retrieved: [...retrieved],
    };
};

export const compileFixedPublicationWitnessCensus = () => {
    const trace = traceFixedPublicationWitnessVisits();
    return {
        ...fixedPublicationWitnesses(trace.committees.length),
        participantVisits: trace.committees.map(
            (_, participant) =>
                trace.visits.filter(
                    (visit) => visit.participant === participant,
                ).length,
        ),
        firstParticipantActions: trace.visits
            .filter((visit) => visit.participant === 0)
            .map((visit) => visit.actions),
    };
};
