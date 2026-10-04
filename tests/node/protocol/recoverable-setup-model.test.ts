import { describe, expect, it } from 'vitest';

import {
    RecoverableSetupModel,
    makeRecoveryOffer,
    polynomialValue,
    reconstructOpeningKey,
    type RecoveryOffer,
    type SetupFailure,
    type SetupFailureStage,
    type SetupFrame,
} from '#tests/recoverable-setup-model.js';

const scope = { poll: 'poll-one', roster: 'fixed-roster-one' };
const fixture = (participantCount: number, candidateCount?: number) => {
    const faultBound = Math.floor((participantCount - 1) / 3);
    const threshold = Math.max(faultBound + 1, 2);
    return Array.from(
        { length: candidateCount ?? threshold + faultBound },
        (_, dealer) =>
            makeRecoveryOffer(
                participantCount,
                dealer,
                `seal-${String(dealer).padStart(2, '0')}`,
                Array.from({ length: threshold }, (_coefficient, degree) =>
                    degree === 0
                        ? BigInt(80 + dealer)
                        : BigInt((dealer + 3) * (degree % 2 ? -1 : 1)),
                ),
                [1, dealer, 17 + dealer],
            ),
    );
};

const confirmAll = (model: RecoverableSetupModel) => {
    for (let position = 0; position < model.participantCount; position++)
        expect(model.confirm(position, scope.roster)).toBe(true);
};

const completeOwnOffer = (
    model: RecoverableSetupModel,
    participant: number,
) => {
    while (model.produceOwnBodyRecord(participant)) {
        // Every successful step adds one retained payload record or stops
        // that actor. No public decision is delivered by this helper.
    }
};

const failureSets = (participantCount: number, maximum: number): number[][] => {
    const result: number[][] = [];
    const visit = (next: number, chosen: number[]) => {
        result.push(chosen);
        if (chosen.length === maximum) return;
        for (let position = next; position < participantCount; position++)
            visit(position + 1, [...chosen, position]);
    };
    visit(1, []);
    return result;
};

const verifyRecovery = (model: RecoverableSetupModel) => {
    const continuers = model.participants.filter(
        (participant) => participant.active,
    );
    const selections = new Set(
        continuers.map((participant) => JSON.stringify(participant.delivered)),
    );
    expect(selections.size).toBe(1);
    for (const participant of continuers) {
        expect(participant.delivered).toHaveLength(model.releaseThreshold);
        expect(participant.recovered.size).toBe(model.releaseThreshold);
        for (const [identity, bytes] of participant.recovered) {
            const dealer = Number(identity.slice('seal-'.length));
            expect(bytes).toEqual([1, dealer, 17 + dealer]);
        }
        // Recovery is productive work after opening shares arrive. A full
        // lifecycle graph must justify any coalescing with setup verification
        // or the ballot; this experiment does not establish a visit limit.
        expect(participant.stages.size).toBeLessThanOrEqual(5);
    }
};

const signed = (
    sender: number,
    kind: SetupFrame['kind'],
    selection: readonly string[],
    shares?: readonly bigint[],
): SetupFrame => ({ scope, sender, kind, selection, shares });

describe('recoverable setup availability candidate', () => {
    it('recovers integer opening keys from nonconsecutive points with negative coefficients', () => {
        const coefficients = [91n, -23n, 7n, -2n];
        for (const positions of [
            [0, 1, 2, 3],
            [0, 3, 6, 9],
            [2, 4, 5, 8],
        ]) {
            expect(
                reconstructOpeningKey(
                    positions.map((participant) => ({
                        participant,
                        value: polynomialValue(coefficients, participant),
                    })),
                ),
            ).toBe(91n);
        }
        expect(() =>
            reconstructOpeningKey([
                { participant: 0, value: 1n },
                { participant: 0, value: 1n },
            ]),
        ).toThrow('distinct');
        expect(() =>
            reconstructOpeningKey([
                { participant: 0, value: 0n },
                { participant: 2, value: 1n },
            ]),
        ).toThrow('integer');
    });

    it.each(Array.from({ length: 18 }, (_unused, index) => index + 3))(
        'completes the unchanged roster of %i through source broadcast thresholds',
        (participantCount) => {
            const model = new RecoverableSetupModel(
                participantCount,
                scope,
                fixture(participantCount),
            );
            confirmAll(model);
            model.drain();
            verifyRecovery(model);
            const faultBound = Math.floor((participantCount - 1) / 3);
            expect(model.echoThreshold).toBe(participantCount - faultBound);
            expect(model.deliveryThreshold).toBe(2 * faultBound + 1);
            expect(model.participants).toHaveLength(participantCount);
        },
    );

    it('survives every allowed unavailable set at each producer cut of the small and completion profiles', () => {
        const stages: SetupFailureStage[] = [
            'confirmation',
            'offer',
            'echo',
            'ready',
            'opening',
        ];
        for (const participantCount of [4, 10]) {
            const faultBound = Math.floor((participantCount - 1) / 3);
            for (const missing of failureSets(participantCount, faultBound)) {
                for (const before of stages) {
                    const failures = missing.map((participant) => ({
                        participant,
                        before,
                    }));
                    const model = new RecoverableSetupModel(
                        participantCount,
                        scope,
                        fixture(participantCount),
                        { failures },
                    );
                    for (
                        let participant = 0;
                        participant < participantCount;
                        participant++
                    )
                        expect(model.confirm(participant, scope.roster)).toBe(
                            before !== 'confirmation' ||
                                !missing.includes(participant),
                        );
                    model.drain(before === 'ready');
                    verifyRecovery(model);
                    expect(model.unavailable()).toEqual(missing);
                    for (const participant of missing) {
                        expect(model.participants[participant].confirmed).toBe(
                            before !== 'confirmation',
                        );
                        expect(model.confirm(participant, scope.roster)).toBe(
                            false,
                        );
                        const stopped = model.trace.indexOf(
                            `${participant}:stopped-before-${before}`,
                        );
                        expect(stopped).toBeGreaterThanOrEqual(0);
                        expect(
                            model.trace
                                .slice(stopped + 1)
                                .some((event) =>
                                    event.startsWith(`${participant}:`),
                                ),
                        ).toBe(false);
                    }
                }
            }
        }
    });

    it('spends one total failure budget across different preparation stages', () => {
        const failures: SetupFailure[] = [
            { participant: 1, before: 'offer' },
            { participant: 4, before: 'ready' },
            { participant: 8, before: 'opening' },
        ];
        const model = new RecoverableSetupModel(10, scope, fixture(10), {
            failures,
        });
        confirmAll(model);
        model.drain(true);
        verifyRecovery(model);
        expect(model.unavailable()).toEqual([1, 4, 8]);
        expect(
            () =>
                new RecoverableSetupModel(10, scope, fixture(10), {
                    failures: [
                        ...failures,
                        { participant: 9, before: 'offer' },
                    ],
                }),
        ).toThrow('scope');
        expect(
            () =>
                new RecoverableSetupModel(4, scope, fixture(4), {
                    failures: [{ participant: 0, before: 'opening' }],
                }),
        ).toThrow('scope');
    });

    it('rejects a candidate pool one below d plus f without changing the roster or threshold', () => {
        const model = new RecoverableSetupModel(10, scope, fixture(10, 6), {
            candidateCount: 6,
            failures: [1, 2, 3].map((participant) => ({
                participant,
                before: 'offer',
            })),
        });
        confirmAll(model);
        model.drain();
        expect(
            model.participants.filter((participant) => participant.active),
        ).toHaveLength(7);
        expect(
            model.participants.every(
                (participant) => participant.delivered === undefined,
            ),
        ).toBe(true);
        expect(model.releaseThreshold).toBe(4);
        expect(model.participants).toHaveLength(10);
    });

    it('does not move an earlier loss to a later stage when the same participant fails again', () => {
        const model = new RecoverableSetupModel(4, scope, fixture(4), {
            failures: [
                { participant: 1, before: 'offer' },
                { participant: 1, before: 'opening' },
            ],
        });
        confirmAll(model);
        model.drain();
        verifyRecovery(model);
        expect(model.unavailable()).toEqual([1]);
        expect(model.publications.some(({ author }) => author === 1)).toBe(
            false,
        );
    });

    it('charges actual refusers and stopped actors independently of cooperative corrupt actors', () => {
        expect(
            () =>
                new RecoverableSetupModel(4, scope, fixture(4), {
                    corrupt: [1],
                    failures: [{ participant: 2, before: 'offer' }],
                }),
        ).toThrow('scope');
        expect(
            () =>
                new RecoverableSetupModel(4, scope, fixture(4), {
                    corrupt: [1],
                    cooperativeCorrupt: [1],
                    failures: [{ participant: 2, before: 'offer' }],
                }),
        ).not.toThrow();
        expect(
            () =>
                new RecoverableSetupModel(4, scope, fixture(4), {
                    corrupt: [1],
                    failures: [{ participant: 1, before: 'offer' }],
                }),
        ).not.toThrow();
        for (const options of [
            { corrupt: [1, 2], cooperativeCorrupt: [1, 2] },
            { corrupt: [1], cooperativeCorrupt: [2] },
        ])
            expect(
                () => new RecoverableSetupModel(4, scope, fixture(4), options),
            ).toThrow('scope');
        expect(
            () =>
                new RecoverableSetupModel(4, scope, fixture(4), {
                    candidateCount: 2.5,
                }),
        ).toThrow('scope');
    });

    it.each([4, 10, 20])(
        'finishes with separate full corruption and honest-departure sets at %i participants',
        (participantCount) => {
            const faultBound = Math.floor((participantCount - 1) / 3);
            const corrupt = Array.from(
                { length: faultBound },
                (_unused, index) => index + 1,
            );
            const departed = corrupt.map((position) => position + faultBound);
            const offers = fixture(participantCount);
            for (const participant of corrupt) {
                const original = offers[participant];
                // Valid outer sharing, but an inner body outside the
                // fixture's version-one grammar. These actors still provide
                // the ECHO, READY and opening work needed by the continuers.
                offers[participant] = makeRecoveryOffer(
                    participantCount,
                    participant,
                    original.identity,
                    original.coefficients,
                    [0, participant, 17 + participant],
                );
            }
            const model = new RecoverableSetupModel(
                participantCount,
                scope,
                offers,
                {
                    corrupt,
                    cooperativeCorrupt: corrupt,
                    failures: departed.map((participant) => ({
                        participant,
                        before: 'offer',
                    })),
                },
            );
            confirmAll(model);
            model.drain();
            expect(model.unavailable()).toEqual(departed);
            const selected = offers
                .slice(0, faultBound + 1)
                .map(({ identity }) => identity);
            const continuers = model.participants.filter(
                (participant) => participant.active,
            );
            expect(continuers).toHaveLength(participantCount - faultBound);
            for (const participant of continuers) {
                expect(participant.delivered).toEqual(selected);
                expect([...participant.recovered.keys()]).toEqual(selected);
                // Classification consumes the recovered bytes. No dealer's
                // outer-proof verdict substitutes for the inner predicate.
                expect(
                    [...participant.recovered.entries()]
                        .filter(([, body]) => body[0] === 1)
                        .map(([identity]) => identity),
                ).toEqual(['seal-00']);
                for (const corruptParticipant of corrupt)
                    expect(
                        participant.recovered.get(
                            offers[corruptParticipant].identity,
                        ),
                    ).toEqual([0, corruptParticipant, 17 + corruptParticipant]);
            }
            for (const participant of corrupt)
                for (const kind of ['offer', 'echo', 'ready', 'opening'])
                    expect(
                        model.publications.some(
                            ({ author, frame }) =>
                                author === participant && frame.kind === kind,
                        ),
                    ).toBe(true);
            for (const participant of departed)
                expect(
                    model.publications.some(
                        ({ author }) => author === participant,
                    ),
                ).toBe(false);
            expect(model.participants).toHaveLength(participantCount);
            expect(model.releaseThreshold).toBe(faultBound + 1);
        },
    );

    it('ignores invalid corrupt work before the same actor supplies its original valid work', () => {
        const offers = fixture(4);
        const malformed = {
            ...offers[1],
            identity: 'invalid-seal-01',
            recipientShares: offers[1].recipientShares.map(
                (share, position) => share + (position === 3 ? 1n : 0n),
            ),
        };
        const model = new RecoverableSetupModel(
            4,
            scope,
            [...offers, malformed],
            {
                corrupt: [1],
                cooperativeCorrupt: [1],
                failures: [{ participant: 2, before: 'offer' }],
            },
        );
        confirmAll(model);
        completeOwnOffer(model, 0);
        model.inject(1, signed(1, 'offer', [malformed.identity]));
        for (const record of model.publications)
            model.deliver(record.ordinal, 0);
        expect(model.advance(0)).toBe(false);
        expect(model.participants[0].delivered).toBeUndefined();
        model.inject(
            1,
            signed(1, 'opening', ['seal-00', 'seal-01'], [999n, 999n]),
        );
        completeOwnOffer(model, 1);
        model.drain();
        verifyRecovery(model);
        expect(model.unavailable()).toEqual([2]);
        for (const participant of [0, 1, 3]) {
            expect(model.participants[participant].delivered).toEqual([
                'seal-00',
                'seal-01',
            ]);
            expect(
                model.participants[participant].recovered.get('seal-01'),
            ).toEqual([1, 1, 18]);
            expect(
                model.participants[participant].recovered.has(
                    malformed.identity,
                ),
            ).toBe(false);
        }
        expect(model.ownWorkView(1).identity).toBe('seal-01');
    });

    it('does not grant another loss allowance when retained work is damaged later', () => {
        const model = new RecoverableSetupModel(4, scope, fixture(4), {
            corrupt: [1],
            cooperativeCorrupt: [1],
            failures: [{ participant: 2, before: 'offer' }],
        });
        confirmAll(model);
        expect(model.produceOwnBodyRecord(1)).toBe(true);
        model.loseOwnBodyRecord(1, 0);
        expect(() => model.advance(1)).toThrow('total unavailable set');
    });

    it('does not require global roster confirmation before another participant offers', () => {
        const model = new RecoverableSetupModel(4, scope, fixture(4), {
            failures: [{ participant: 2, before: 'offer' }],
        });
        expect(model.confirm(0, 'different-roster')).toBe(false);
        expect(model.advance(0)).toBe(false);
        expect(model.confirm(0, scope.roster)).toBe(true);
        expect(model.advance(0)).toBe(true);
        expect(model.publications).toHaveLength(0);
        completeOwnOffer(model, 0);
        expect(model.publications).toHaveLength(1);
        expect(model.participants[1].confirmed).toBe(false);
        confirmAll(model);
        model.drain();
        verifyRecovery(model);
    });

    it('helps the selected set with an unfinished own body and retires it only after reliable delivery', () => {
        const model = new RecoverableSetupModel(4, scope, fixture(4), {
            failures: [{ participant: 3, before: 'offer' }],
        });
        confirmAll(model);
        completeOwnOffer(model, 0);
        completeOwnOffer(model, 1);
        expect(model.produceOwnBodyRecord(2)).toBe(true);
        const partial = model.ownWorkView(2);
        expect(partial.retainedPrefix).toHaveLength(1);
        expect(partial.records).toHaveLength(1);
        for (const record of [...model.publications])
            model.deliver(record.ordinal, 0);
        expect(model.advance(0)).toBe(true);
        for (const record of [...model.publications])
            model.deliver(record.ordinal, 2);
        expect(model.advance(2)).toBe(true);
        expect(model.participants[2].echo).toEqual(['seal-00', 'seal-01']);
        expect(model.participants[2].offered).toBe(false);
        expect(model.produceOwnBodyRecord(2)).toBe(false);
        expect(model.ownWorkView(2)).toEqual(partial);
        expect(model.participants[2].delivered).toBeUndefined();
        model.drain();
        verifyRecovery(model);
        expect(model.unavailable()).toEqual([3]);
        expect(model.ownWorkView(2)).toEqual({
            identity: 'seal-02',
            retainedPrefix: [],
            records: [],
            retiredFor: ['seal-00', 'seal-01'],
        });
        expect(
            model.trace.filter((event) => event.startsWith('2:own-record:')),
        ).toHaveLength(1);
        expect(
            model.publications.some(
                ({ author, frame }) => author === 2 && frame.kind === 'offer',
            ),
        ).toBe(false);
        expect(model.produceOwnBodyRecord(2)).toBe(false);
        expect(model.participants[2].confirmed).toBe(true);
    });

    it.each(['missing', 'changed', 'extra'] as const)(
        'stops on a %s required own record before retirement while the other continuers finish',
        (damage) => {
            const model = new RecoverableSetupModel(4, scope, fixture(4));
            confirmAll(model);
            completeOwnOffer(model, 0);
            completeOwnOffer(model, 1);
            expect(model.produceOwnBodyRecord(2)).toBe(true);
            const original = model.ownWorkView(2).retainedPrefix[0];
            if (damage === 'missing') model.loseOwnBodyRecord(2, 0);
            else if (damage === 'changed')
                model.changeOwnBodyRecord(2, 0, original + 1n);
            else model.changeOwnBodyRecord(2, 99, original);
            model.drain();
            verifyRecovery(model);
            expect(model.unavailable()).toEqual([2]);
            expect(model.participants[2].delivered).toBeUndefined();
            expect(model.participants[2].opened).toBe(false);
            expect(model.ownWorkView(2).retainedPrefix).toEqual([original]);
            expect(model.ownWorkView(2).retiredFor).toBeUndefined();
            expect(model.publications.some(({ author }) => author === 2)).toBe(
                false,
            );
            expect(model.produceOwnBodyRecord(2)).toBe(false);
            expect(model.advance(2)).toBe(false);
        },
    );

    it('retains published unselected offers after their private work is retired', () => {
        const model = new RecoverableSetupModel(4, scope, fixture(4));
        confirmAll(model);
        for (const participant of [0, 1, 2])
            completeOwnOffer(model, participant);
        const published = model.publications.find(({ author }) => author === 2);
        expect(published?.frame.selection).toEqual(['seal-02']);
        model.drain();
        verifyRecovery(model);
        expect(model.ownWorkView(2).retiredFor).toEqual(['seal-00', 'seal-01']);
        expect(model.publications).toContainEqual(published);
        expect(model.produceOwnBodyRecord(2)).toBe(false);
    });

    it('rejects inconsistent recoverability before selection and replaces no selected body', () => {
        const offers = fixture(4);
        const original = offers[1];
        const changed: RecoveryOffer = {
            ...original,
            recipientShares: original.recipientShares.map(
                (value, index) => value + (index === 2 ? 1n : 0n),
            ),
        };
        const model = new RecoverableSetupModel(
            4,
            scope,
            [offers[0], changed, offers[2]],
            { corrupt: [1] },
        );
        confirmAll(model);
        model.inject(1, signed(1, 'offer', [changed.identity]));
        model.drain();
        for (const participant of [0, 2, 3]) {
            expect(model.participants[participant].delivered).toEqual([
                'seal-00',
                'seal-02',
            ]);
            expect(model.participants[participant].recovered.size).toBe(2);
        }
    });

    it('recovers a selected corrupt body after its author refuses instead of choosing a replacement', () => {
        const offers = fixture(4);
        // The payload is intentionally outside the fixture application's
        // version-one grammar. Recoverability does not certify an FHE body.
        offers[1] = makeRecoveryOffer(4, 1, 'seal-01', [81n, -4n], [0, 1, 18]);
        const model = new RecoverableSetupModel(4, scope, offers, {
            corrupt: [1],
        });
        confirmAll(model);
        model.inject(1, signed(1, 'offer', ['seal-01']));
        model.inject(
            1,
            signed(1, 'opening', ['seal-00', 'seal-01'], [999n, 999n]),
        );
        model.drain();
        for (const position of [0, 2, 3]) {
            const participant = model.participants[position];
            expect(participant.delivered).toEqual(['seal-00', 'seal-01']);
            expect(participant.recovered.get('seal-01')).toEqual([0, 1, 18]);
            expect(
                [...participant.recovered.values()].filter(
                    (body) => body[0] === 1,
                ),
            ).toHaveLength(1);
            expect(participant.recovered.has('seal-02')).toBe(false);
        }
        expect(model.releaseThreshold).toBe(2);
    });

    it('amplifies the winning READY after an earlier ECHO for another organizer fork', () => {
        const offers = fixture(4);
        const model = new RecoverableSetupModel(4, scope, offers, {
            corrupt: [0],
        });
        confirmAll(model);
        model.inject(0, signed(0, 'offer', ['seal-00']));
        for (const position of [1, 2, 3]) completeOwnOffer(model, position);
        for (const record of [...model.publications])
            for (const position of [1, 2, 3])
                model.deliver(record.ordinal, position);
        const first = ['seal-00', 'seal-01'];
        const second = ['seal-01', 'seal-02'];
        const firstProposal = model.inject(0, signed(0, 'selection', first));
        const secondProposal = model.inject(0, signed(0, 'selection', second));
        model.deliver(firstProposal, 1);
        model.deliver(firstProposal, 2);
        model.deliver(secondProposal, 3);
        for (const position of [1, 2, 3]) model.advance(position);
        expect(model.participants[3].echo).toEqual(second);
        expect(
            model.participants.every((participant) => !participant.opened),
        ).toBe(true);
        model.inject(0, signed(0, 'echo', first));
        model.drain(true);
        for (const position of [1, 2, 3]) {
            expect(model.participants[position].delivered).toEqual(first);
            expect(model.participants[position].recovered.size).toBe(2);
        }
        expect(model.participants[3].ready).toEqual(first);
        expect(
            model.publications
                .filter(({ frame }) => frame.kind === 'opening')
                .every(
                    ({ frame }) =>
                        JSON.stringify(frame.selection) ===
                        JSON.stringify(first),
                ),
        ).toBe(true);
    });

    it('ignores wrong-context frames, relabelled authors and duplicate shares', () => {
        const offers = fixture(4);
        const model = new RecoverableSetupModel(4, scope, offers, {
            corrupt: [1],
        });
        confirmAll(model);
        const relabelled = model.inject(1, signed(2, 'offer', ['seal-02']));
        expect(model.deliver(relabelled, 0)).toBe(false);
        const replay = model.inject(1, {
            ...signed(1, 'offer', ['seal-01']),
            scope: { ...scope, poll: 'other-poll' },
        });
        expect(model.deliver(replay, 0)).toBe(false);
        expect(() =>
            model.inject(2, signed(2, 'echo', ['seal-00', 'seal-02'])),
        ).toThrow('honest');
        model.inject(1, signed(1, 'offer', ['seal-01']));
        const opening = signed(
            1,
            'opening',
            ['seal-00', 'seal-01'],
            [offers[0].recipientShares[1], offers[1].recipientShares[1]],
        );
        for (let copy = 0; copy < 4; copy++) model.inject(1, opening);
        // A single sender's repeated early shares cannot cause honest opening
        // or provide a threshold. Honest actions begin only in the drain.
        for (const record of model.publications)
            model.deliver(record.ordinal, 0);
        expect(model.participants[0].recovered.size).toBe(0);
        model.drain();
        for (const position of [0, 2, 3])
            expect(model.participants[position].recovered.size).toBe(2);
    });

    it('keeps totality and one opening set under every small two-fork ECHO split and corrupt vote choice', () => {
        const alternatives = [
            ['seal-00', 'seal-01'],
            ['seal-01', 'seal-02'],
        ];
        for (let firstViews = 0; firstViews < 8; firstViews++) {
            for (let corruptEchoes = 0; corruptEchoes < 4; corruptEchoes++) {
                for (
                    let corruptReadies = 0;
                    corruptReadies < 4;
                    corruptReadies++
                ) {
                    const model = new RecoverableSetupModel(
                        4,
                        scope,
                        fixture(4),
                        {
                            corrupt: [0],
                        },
                    );
                    confirmAll(model);
                    model.inject(0, signed(0, 'offer', ['seal-00']));
                    for (const position of [1, 2, 3])
                        completeOwnOffer(model, position);
                    for (const record of [...model.publications])
                        for (const position of [1, 2, 3])
                            model.deliver(record.ordinal, position);
                    const proposals = alternatives.map((selection) =>
                        model.inject(0, signed(0, 'selection', selection)),
                    );
                    for (const position of [1, 2, 3]) {
                        const first = (firstViews >> (position - 1)) & 1;
                        model.deliver(proposals[first], position);
                        model.advance(position);
                    }
                    for (const [index, selection] of alternatives.entries()) {
                        if ((corruptEchoes & (1 << index)) !== 0)
                            model.inject(0, signed(0, 'echo', selection));
                        if ((corruptReadies & (1 << index)) !== 0)
                            model.inject(0, signed(0, 'ready', selection));
                    }
                    model.drain((firstViews & 1) !== 0);
                    const honest = model.participants.slice(1);
                    const delivered = honest.filter((state) => state.delivered);
                    expect(
                        new Set(
                            delivered.map((state) =>
                                JSON.stringify(state.delivered),
                            ),
                        ).size,
                    ).toBeLessThanOrEqual(1);
                    expect([0, 3]).toContain(delivered.length);
                    expect(
                        honest.every((state) =>
                            delivered.length === 0
                                ? !state.opened
                                : state.recovered.size === 2,
                        ),
                    ).toBe(true);
                }
            }
        }
    });
});
