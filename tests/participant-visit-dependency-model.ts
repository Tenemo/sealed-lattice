import assert from 'node:assert/strict';

import { createPublicationCutModel } from '#tests/publication-cut-model.js';

const preferredVisitCount = 5;
const maximumVisitCount = 10;

// Each stage consumes every participant's preceding publication. Joining is
// included; the organizer is allowed to freeze registration without extra delay.
const preparationStages = [
    'registration',
    'roster-confirmation-and-seed-commitment',
    'seed-opening',
    'share-encryption-key',
    'setup-contribution',
    'setup-receipt',
] as const;

export type ParticipantVisit = Readonly<{
    participant: number;
    actions: readonly string[];
}>;

// A permitted sequential schedule, not a maximum over asynchronous deliveries.
// The first participant returns before the other participants complete each
// stage. Every visit still performs all work enabled by the shared transcript.
const tracePreparation = (
    participantCount: number,
    ballotAuthors: readonly number[],
    stages: readonly string[],
): readonly ParticipantVisit[] => {
    assert.ok(
        Number.isInteger(participantCount) &&
            participantCount >= 3 &&
            participantCount <= 20,
    );
    const authors = new Set(ballotAuthors);
    assert.equal(authors.size, ballotAuthors.length);
    for (const author of authors) {
        assert.ok(
            Number.isInteger(author) &&
                author >= 0 &&
                author < participantCount,
        );
    }
    const published = stages.map(() => new Set<number>());
    const ballots = new Set<number>();
    const visits: ParticipantVisit[] = [];
    const visit = (participant: number): void => {
        const actions: string[] = [];
        for (const [stage, id] of stages.entries()) {
            if (published[stage].has(participant)) continue;
            if (stage > 0 && published[stage - 1].size !== participantCount)
                break;
            published[stage].add(participant);
            actions.push(id);
        }
        if (
            published[published.length - 1].size === participantCount &&
            authors.has(participant) &&
            !ballots.has(participant)
        ) {
            ballots.add(participant);
            actions.push('ballot-publication-attempt');
        }
        if (actions.length > 0) visits.push({ participant, actions });
    };
    for (const completed of published) {
        for (
            let participant = 0;
            participant < participantCount;
            participant++
        ) {
            if (!completed.has(participant)) visit(participant);
        }
        assert.equal(completed.size, participantCount);
    }
    for (const participant of authors) {
        if (!ballots.has(participant)) visit(participant);
    }
    return visits;
};

export const tracePreparationVisits = (
    participantCount: number,
    ballotAuthors: readonly number[],
): readonly ParticipantVisit[] =>
    tracePreparation(participantCount, ballotAuthors, preparationStages);

export const traceCommonMatrixPreparationVisits = (
    participantCount: number,
    ballotAuthors: readonly number[],
): readonly ParticipantVisit[] =>
    tracePreparation(participantCount, ballotAuthors, [
        'registration-and-recipient-key',
        'roster-confirmation-and-setup-commitment',
        'setup-opening',
    ]);

export const tracePublicationCompletionVisits = (
    preparation: (
        participantCount: number,
        ballotAuthors: readonly number[],
    ) => readonly ParticipantVisit[] = tracePreparationVisits,
    revisitFirstAfterEachBallot = false,
): readonly ParticipantVisit[] => {
    const participantCount = 10;
    const corruptionBound = Math.floor((participantCount - 1) / 3);
    const quorum = participantCount - corruptionBound;
    const releaseThreshold = corruptionBound + 1;
    const honest = Array.from({ length: quorum }, (_, position) => position);
    // Corrupt parties finish required preparation, then withhold everything.
    const model = createPublicationCutModel(
        participantCount,
        Array.from(
            { length: corruptionBound },
            (_, position) => quorum + position,
        ),
    );
    const bodies: {
        slot: number;
        identity: string;
        validBallot: boolean;
    }[] = [];
    const visits: ParticipantVisit[] = [];
    const frozen = new Set<number>();
    const signed = new Set<number>();
    const released = new Set<number>();
    const retrieved = new Set<number>();
    let closeRequested = false;
    let targetProposed = false;
    const visit = (
        participant: number,
        priorActions: readonly string[] = [],
    ) => {
        const actions = [...priorActions];
        const before = model.messages().length;
        for (const body of bodies) model.echo(participant, body);
        // Immediate ledger delivery and every enabled action are favorable to
        // coalescing. Even this sequential execution can reject a visit bound.
        let consumed = 0;
        while (consumed < model.messages().length) {
            const messages = model.messages();
            while (consumed < messages.length)
                model.receive(participant, messages[consumed++]);
        }
        for (const message of model.messages().slice(before))
            actions.push(
                `${message.kind}/${String(message.certificates[0].body.slot)}`,
            );
        const ready = model.messages().filter(({ kind }) => kind === 'ready');
        if (
            participant === 0 &&
            !closeRequested &&
            bodies.length === honest.length &&
            bodies.every(
                ({ slot }) =>
                    ready.filter(
                        ({ certificates }) =>
                            certificates[0].body.slot === slot,
                    ).length >= quorum,
            )
        ) {
            closeRequested = true;
            actions.push('close-intent');
        }
        if (closeRequested && !frozen.has(participant)) {
            model.freeze(participant);
            frozen.add(participant);
            actions.push('close-report');
        }
        if (participant === 0 && !targetProposed && frozen.size >= quorum) {
            const reports = model
                .messages()
                .filter(({ kind }) => kind === 'freeze');
            assert.deepEqual(model.inventory(reports), bodies);
            targetProposed = true;
            actions.push('target-proposal');
        }
        if (targetProposed && !signed.has(participant)) {
            signed.add(participant);
            actions.push('target-signature');
        }
        if (signed.size >= quorum && !released.has(participant)) {
            released.add(participant);
            actions.push('release-share');
        }
        if (released.size >= releaseThreshold && !retrieved.has(participant)) {
            retrieved.add(participant);
            actions.push('terminal-retrieval');
        }
        if (actions.length > 0) visits.push({ participant, actions });
    };
    for (const entry of preparation(participantCount, honest)) {
        if (entry.actions.includes('ballot-publication-attempt')) {
            bodies.push({
                slot: entry.participant,
                identity: `ballot/${String(entry.participant)}`,
                validBallot: true,
            });
            visit(entry.participant, entry.actions);
            if (revisitFirstAfterEachBallot && entry.participant !== 0)
                visit(0);
        } else visits.push(entry);
    }
    let passes = 0;
    while (retrieved.size !== honest.length) {
        assert.ok(passes++ < 20, 'The candidate trace stopped progressing.');
        for (const participant of honest) visit(participant);
    }
    return visits;
};

export const compileParticipantVisitDependencyCensus = () => {
    const participantCount = 10;
    const countFirstParticipantVisits = (authors: readonly number[]): number =>
        tracePreparationVisits(participantCount, authors).filter(
            ({ participant }) => participant === 0,
        ).length;
    const preparationWitnessVisitCount = countFirstParticipantVisits([]);
    const ballotAuthorWitnessVisitCount = countFirstParticipantVisits([0]);
    const completionWitnessVisitCount =
        tracePublicationCompletionVisits().filter(
            ({ participant }) => participant === 0,
        ).length;
    const commonMatrixCompletionWitnessVisitCount =
        tracePublicationCompletionVisits(
            traceCommonMatrixPreparationVisits,
        ).filter(({ participant }) => participant === 0).length;
    const interleavedCommonMatrixWitnessVisitCount =
        tracePublicationCompletionVisits(
            traceCommonMatrixPreparationVisits,
            true,
        ).filter(({ participant }) => participant === 0).length;
    return {
        participantCount,
        preparationWitnessVisitCount,
        ballotAuthorWitnessVisitCount,
        preferredVisitCount,
        maximumPermittedVisitCount: maximumVisitCount,
        remainingVisitBudget: maximumVisitCount - ballotAuthorWitnessVisitCount,
        completionWitnessVisitCount,
        completionWitnessExcess:
            completionWitnessVisitCount - maximumVisitCount,
        commonMatrixCompletionWitnessVisitCount,
        interleavedCommonMatrixWitnessVisitCount,
    };
};
