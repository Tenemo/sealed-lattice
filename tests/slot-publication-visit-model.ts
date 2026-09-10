import { traceCommonMatrixPreparationVisits } from '#tests/participant-visit-dependency-model.js';
import { createSlotPublicationModel } from '#tests/slot-publication-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

// Conditional all-cooperating schedule for the slot model. A participant waits
// for every assigned source token, then witnesses its assigned slots in one
// batch. That guard is an actual extra input dependency. Missing corrupt source
// tokens can prevent this pre-boundary work; this is not quorum-only liveness.
export const traceSlotPublicationVisits = (
    ballotAuthors: readonly number[],
    participantOrder: readonly number[],
    invalidBallotAuthors: readonly number[] = [],
) => {
    const participantCount = 10;
    if (
        participantOrder.length !== participantCount ||
        new Set(participantOrder).size !== participantCount ||
        participantOrder.some(
            (value) =>
                !Number.isInteger(value) ||
                value < 0 ||
                value >= participantCount,
        ) ||
        new Set(ballotAuthors).size !== ballotAuthors.length ||
        ballotAuthors.some((value) => !participantOrder.includes(value)) ||
        new Set(invalidBallotAuthors).size !== invalidBallotAuthors.length ||
        invalidBallotAuthors.some((value) => !ballotAuthors.includes(value))
    )
        throw new Error('Invalid completion-profile schedule.');
    const profile = compileThresholdCompletionProfile(participantCount);
    const model = createSlotPublicationModel(
        participantCount,
        [],
        'visit-comparison',
    );
    const visits = [
        ...traceCommonMatrixPreparationVisits(participantCount, []),
    ];
    const tokens = new Map<
        number,
        NonNullable<ReturnType<typeof model.originate>>
    >();
    const witnessed = new Set<number>();
    const certified = new Set<number>();
    const released = new Set<number>();
    const retrieved = new Set<number>();
    const certificates = new Map<
        number,
        ReturnType<typeof model.certificate>
    >();
    const assigned = participantOrder.map((participant) =>
        model.committees.flatMap((members, author) =>
            members.includes(participant) ? [author] : [],
        ),
    );
    const assignments = new Map(
        participantOrder.map((participant, index) => [
            participant,
            assigned[index],
        ]),
    );
    let closeRequested = false;
    let encryptedResult = false;
    const visit = (participant: number, source?: 'ballot' | 'close') => {
        const actions: string[] = [];
        if (source === 'close') {
            if (participant !== 0 || closeRequested)
                throw new Error('Invalid organizer close.');
            model.requestClose(0);
            closeRequested = true;
            actions.push('request-close');
        }
        if (closeRequested) model.observeClose(participant);
        if (
            !tokens.has(participant) &&
            (source === 'ballot' || closeRequested)
        ) {
            const body = source === 'ballot' ? `ballot-${participant}` : null;
            if (body !== null)
                model.fixture(
                    body,
                    !invalidBallotAuthors.includes(participant),
                );
            const token = model.originate(participant, body);
            if (!token) throw new Error('Authorized source token was refused.');
            tokens.set(participant, token);
            actions.push(
                body === null ? 'publish-empty-slot' : 'publish-ballot',
            );
        }
        if (
            !witnessed.has(participant) &&
            assignments.get(participant)!.every((author) => tokens.has(author))
        ) {
            for (const author of assignments.get(participant)!) {
                const token = tokens.get(author)!;
                if (!model.witness(participant, token, token.body))
                    throw new Error('Honest batch was refused.');
            }
            witnessed.add(participant);
            actions.push('witness-assigned-slots');
        }
        for (const [author, token] of tokens) {
            const certificate = model.certificate(token);
            if (model.verifyCertificate(certificate)) {
                model.publish(certificate);
                certificates.set(author, certificate);
            }
        }
        const inventory = closeRequested
            ? model.close([...certificates.values()])
            : undefined;
        if (inventory)
            encryptedResult = inventory.some(
                (value) => value.classification === 'accepted',
            );
        if (inventory && !certified.has(participant)) {
            certified.add(participant);
            actions.push('evaluate-and-certify-target');
        }
        if (certified.size >= profile.inventoryCertificateThreshold) {
            if (!encryptedResult) {
                if (!retrieved.has(participant)) {
                    retrieved.add(participant);
                    actions.push('verify-no-result');
                }
            } else {
                if (!released.has(participant)) {
                    released.add(participant);
                    actions.push('release-share');
                }
                if (
                    released.size >= profile.resultReleaseThreshold &&
                    !retrieved.has(participant)
                ) {
                    retrieved.add(participant);
                    actions.push('verify-result');
                }
            }
        }
        if (actions.length) visits.push({ participant, actions });
    };
    for (const author of ballotAuthors) {
        visit(author, 'ballot');
        for (const participant of participantOrder) visit(participant);
    }
    visit(0, 'close');
    for (let wave = 0; wave < 7; wave++)
        for (const participant of participantOrder) {
            visit(participant);
            // Return as soon as release is newly enabled, before enough other
            // shares exist. Retrieval must then be a later productive visit.
            if (
                certified.size >= profile.inventoryCertificateThreshold &&
                !released.has(0) &&
                encryptedResult
            )
                visit(0);
        }
    return {
        visits,
        inventory: model.close([...certificates.values()]),
        retrieved: [...retrieved],
        released: [...released],
        participantVisits: participantOrder.map((participant) => ({
            participant,
            count: visits.filter((value) => value.participant === participant)
                .length,
        })),
    };
};

export const compileSlotPublicationVisitCensus = () => {
    const participants = Array.from({ length: 10 }, (_, index) => index);
    const preparation = traceCommonMatrixPreparationVisits(
        participants.length,
        [],
    );
    const preparationMaximum = Math.max(
        ...participants.map(
            (participant) =>
                preparation.filter((visit) => visit.participant === participant)
                    .length,
        ),
    );
    // Each remaining action is one-shot. The witness action waits for all of
    // its assigned inputs. This bounds the modeled honest productive actions,
    // not bytes, time, arbitrary invalid-input processing, or qualification.
    const continuationActions = [
        'source-token',
        'witness-batch',
        'target-certificate',
        'release-share',
        'terminal-retrieval',
    ];
    const cases = [
        { authors: [], invalidAuthors: [] },
        { authors: [0], invalidAuthors: [] },
        { authors: [1, 4], invalidAuthors: [] },
        { authors: participants, invalidAuthors: [] },
        { authors: [1, 4], invalidAuthors: [1] },
        { authors: participants, invalidAuthors: participants },
    ].map(({ authors, invalidAuthors }) => {
        const samples = participants.map((offset) =>
            traceSlotPublicationVisits(
                authors,
                [
                    ...participants.slice(offset),
                    ...participants.slice(0, offset),
                ],
                invalidAuthors,
            ),
        );
        if (
            samples.some(
                (sample) => sample.retrieved.length !== participants.length,
            )
        )
            throw new Error('A conditional visit schedule did not complete.');
        return {
            ballotAuthors: authors,
            invalidBallotAuthors: invalidAuthors,
            scheduleCount: samples.length,
            maximumObservedVisits: Math.max(
                ...samples.flatMap((sample) =>
                    sample.participantVisits.map((value) => value.count),
                ),
            ),
        };
    });
    return {
        preparationMaximum,
        continuationActions,
        ordinaryActionBound: preparationMaximum + continuationActions.length,
        organizerActionBound:
            preparationMaximum + continuationActions.length + 1,
        cases,
    };
};
