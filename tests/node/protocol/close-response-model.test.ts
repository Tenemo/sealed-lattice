import { describe, expect, it } from 'vitest';

import {
    bruteForceListerSets,
    closeInventory,
    compileCloseObligationCounterexamples,
    compileCloseVisitCensus,
    deriveCloseProfile,
    envelopeIdentity,
    exploreCompletionProfileExecutions,
    exploreJointCloseViews,
    listKnownEnvelopes,
    runCloseExecution,
    usableEnvelopes,
    verifyCloseProposal,
    verifyCloseResponse,
    type CloseEnvelope,
    type CloseIntent,
    type CloseResponse,
} from '#tests/close-response-model.js';

// Product goals, maintained independently of the model: at most
// f = floor((n - 1) / 3) participants are corrupt, closing needs n - f
// responses including the organizer, at most f ballots can be left out, a
// result needs f + 2 accepted ballots, release needs max(f + 1, 2) shares,
// and more than ten productive visits is a product failure.
const goalThresholds = (participantCount: number) => {
    const faultBound = Math.floor((participantCount - 1) / 3);
    return {
        participantCount,
        faultBound,
        quorum: participantCount - faultBound,
        minimumTurnout: faultBound + 2,
        releaseThreshold: Math.max(faultBound + 1, 2),
    };
};
const supportedParticipantCounts = Array.from(
    { length: 18 },
    (_unused, index) => index + 3,
);
const mandatoryVisitCeiling = 10;
const memberCount = (mask: number): number =>
    [...mask.toString(2)].filter((digit) => digit === '1').length;
const binomial = (n: number, k: number): number => {
    let value = 1;
    for (let index = 1; index <= k; index += 1)
        value = (value * (n - k + index)) / index;
    return value;
};

const envelope = (
    author: number,
    variant: number,
    time: number,
    options: Partial<Pick<CloseEnvelope, 'bodyAvailable' | 'validProof'>> = {},
): CloseEnvelope => ({
    author,
    variant,
    time,
    bodyAvailable: options.bodyAvailable ?? true,
    validProof: options.validProof ?? true,
});
const byIdentity = (values: readonly CloseEnvelope[]) =>
    new Map(
        values.map((value) => [
            envelopeIdentity(value.author, value.variant),
            value,
        ]),
    );

describe('close response model', () => {
    it('derives the close thresholds from the goal formulas', () => {
        for (const participantCount of supportedParticipantCounts)
            expect(deriveCloseProfile(participantCount)).toEqual(
                goalThresholds(participantCount),
            );
    });

    it('lists one on-time envelope with its body and two known ones without', () => {
        const intent: CloseIntent = { variant: 0, closeTime: 5 };
        const known = [
            envelope(4, 2, 5),
            envelope(4, 0, 1),
            envelope(4, 1, 2),
            envelope(1, 0, 6),
            envelope(2, 0, 3, { bodyAvailable: false }),
            envelope(3, 0, 5, { validProof: false }),
            envelope(3, 0, 5, { validProof: false }),
            envelope(5, 0, 4, { bodyAvailable: false }),
            envelope(5, 1, 5, { bodyAvailable: false }),
            envelope(6, 0, 2),
            envelope(6, 1, 7),
        ];
        const held = new Set(
            known
                .filter(({ bodyAvailable }) => bodyAvailable)
                .map(({ author, variant }) =>
                    envelopeIdentity(author, variant),
                ),
        );
        // Slot 1 is late; slot 2's only envelope has no body; slot 5 lists
        // two bodiless envelopes; slot 6's second envelope is late.
        expect(listKnownEnvelopes(known, held, intent)).toEqual([
            envelopeIdentity(3, 0),
            envelopeIdentity(4, 0),
            envelopeIdentity(4, 1),
            envelopeIdentity(5, 0),
            envelopeIdentity(5, 1),
            envelopeIdentity(6, 0),
        ]);
        expect(
            listKnownEnvelopes(known, held, intent, Number.POSITIVE_INFINITY),
        ).toHaveLength(7);
        // Without bodies only the slots with two known envelopes are listed.
        expect(listKnownEnvelopes(known, new Set(), intent)).toEqual([
            envelopeIdentity(4, 0),
            envelopeIdentity(4, 1),
            envelopeIdentity(5, 0),
            envelopeIdentity(5, 1),
        ]);
        expect(
            listKnownEnvelopes(known, held, { variant: 0, closeTime: 0 }),
        ).toEqual([]);
    });

    it('refuses late, unknown, unordered and overfull responses but not bodiless entries', () => {
        const intents = new Map([[0, { variant: 0, closeTime: 5 }]]);
        const envelopes = byIdentity([
            envelope(1, 0, 1),
            envelope(2, 0, 1),
            envelope(2, 1, 2),
            envelope(2, 2, 3),
            envelope(3, 0, 6),
            envelope(4, 0, 1, { bodyAvailable: false }),
        ]);
        const response = (
            listed: readonly string[],
            signer = 1,
            intent = 0,
        ): CloseResponse => ({ signer, intent, listed });
        const verify = (value: CloseResponse) =>
            verifyCloseResponse(value, intents, envelopes, 10);
        expect(
            verify(
                response([
                    envelopeIdentity(1, 0),
                    envelopeIdentity(2, 0),
                    envelopeIdentity(2, 1),
                ]),
            ),
        ).toBe(true);
        expect(verify(response([]))).toBe(true);
        // A response needs the listed envelope, not its body.
        expect(verify(response([envelopeIdentity(4, 0)]))).toBe(true);
        for (const listed of [
            [envelopeIdentity(3, 0)],
            [envelopeIdentity(5, 0)],
            [envelopeIdentity(2, 0), envelopeIdentity(1, 0)],
            [envelopeIdentity(1, 0), envelopeIdentity(1, 0)],
            [
                envelopeIdentity(2, 0),
                envelopeIdentity(2, 1),
                envelopeIdentity(2, 2),
            ],
        ])
            expect(verify(response(listed))).toBe(false);
        expect(verify(response([], 1, 1))).toBe(false);
        expect(verify(response([], 10))).toBe(false);
        expect(verify(response([], -1))).toBe(false);
    });

    it('requires exactly q ordered distinct responses naming one intent, including the organizer', () => {
        const profile = deriveCloseProfile(4);
        const intents = new Map([
            [0, { variant: 0, closeTime: 5 }],
            [1, { variant: 1, closeTime: 9 }],
        ]);
        const envelopes = byIdentity([envelope(1, 0, 7)]);
        const response = (
            signer: number,
            intent = 0,
            listed: readonly string[] = [],
        ): CloseResponse => ({ signer, intent, listed });
        const verify = (responses: readonly CloseResponse[], intent = 0) =>
            verifyCloseProposal(
                { intent, responses },
                intents,
                envelopes,
                profile,
            );
        expect(verify([response(0), response(1), response(3)])).toBe(true);
        expect(verify([response(0), response(1)])).toBe(false);
        expect(
            verify([response(0), response(1), response(2), response(3)]),
        ).toBe(false);
        expect(verify([response(1), response(2), response(3)])).toBe(false);
        expect(verify([response(0), response(1), response(1)])).toBe(false);
        expect(verify([response(0), response(3), response(1)])).toBe(false);
        expect(verify([response(0), response(1), response(2, 1)])).toBe(false);
        expect(
            verify([
                response(0),
                response(1),
                response(2, 0, [envelopeIdentity(1, 0)]),
            ]),
        ).toBe(false);
        expect(
            verify(
                [
                    response(0, 1),
                    response(1, 1),
                    response(2, 1, [envelopeIdentity(1, 0)]),
                ],
                1,
            ),
        ).toBe(true);
        expect(verify([response(0), response(1), response(2)], 2)).toBe(false);
    });

    it('requires the body of every usable slot and of no conflicting slot', () => {
        const profile = deriveCloseProfile(4);
        const intents = new Map([[0, { variant: 0, closeTime: 5 }]]);
        const withheld = envelope(3, 0, 1, { bodyAvailable: false });
        const other = envelope(3, 1, 1);
        const envelopes = byIdentity([envelope(1, 0, 1), withheld, other]);
        const response = (
            signer: number,
            listed: readonly string[],
        ): CloseResponse => ({ signer, intent: 0, listed });
        const verify = (responses: readonly CloseResponse[]) =>
            verifyCloseProposal(
                { intent: 0, responses },
                intents,
                envelopes,
                profile,
            );
        const usable = [envelopeIdentity(1, 0)];
        // The withheld envelope alone would make its slot usable.
        expect(
            verify([
                response(0, usable),
                response(1, [...usable, envelopeIdentity(3, 0)]),
                response(2, usable),
            ]),
        ).toBe(false);
        // Listed with a second envelope, the slot is conflicting.
        const conflicting = [
            response(0, usable),
            response(1, [...usable, envelopeIdentity(3, 0)]),
            response(2, [...usable, envelopeIdentity(3, 1)]),
        ];
        expect(verify(conflicting)).toBe(true);
        expect(
            usableEnvelopes(conflicting, envelopes).map(({ author }) => author),
        ).toEqual([1]);
        expect(
            closeInventory(
                { intent: 0, responses: conflicting },
                envelopes,
                profile,
            ).slots,
        ).toEqual(['absent', 'accepted', 'absent', 'conflicting']);
    });

    it('classifies the union and derives the turnout branch at its boundary', () => {
        const profile = deriveCloseProfile(10);
        const intent = 0;
        const values = [
            envelope(0, 0, 1),
            envelope(1, 0, 1),
            envelope(2, 0, 1),
            envelope(3, 0, 1),
            envelope(4, 0, 1, { validProof: false }),
            envelope(5, 0, 1),
            envelope(5, 1, 1),
            envelope(6, 0, 1),
        ];
        const envelopes = byIdentity(values);
        const listing = (authors: readonly number[]) =>
            values
                .filter(({ author }) => authors.includes(author))
                .map(({ author, variant }) =>
                    envelopeIdentity(author, variant),
                );
        const responses = (acceptedAuthors: readonly number[]) =>
            Array.from({ length: profile.quorum }, (_unused, signer) => ({
                signer,
                intent,
                listed: signer === 0 ? listing(acceptedAuthors) : [],
            }));
        const inventory = closeInventory(
            { intent, responses: responses([0, 1, 2, 3, 4, 5]) },
            envelopes,
            profile,
        );
        expect(inventory.slots).toEqual([
            'accepted',
            'accepted',
            'accepted',
            'accepted',
            'invalid',
            'conflicting',
            'absent',
            'absent',
            'absent',
            'absent',
        ]);
        expect(inventory.acceptedCount).toBe(profile.minimumTurnout - 1);
        expect(inventory.branch).toBe('no-result');
        const turnout = closeInventory(
            { intent, responses: responses([0, 1, 2, 3, 6]) },
            envelopes,
            profile,
        );
        expect(turnout.acceptedCount).toBe(profile.minimumTurnout);
        expect(turnout.branch).toBe('evaluation');
    });

    it('includes every ballot f + 1 honest participants list and leaves out at most f', () => {
        for (const participantCount of supportedParticipantCounts.filter(
            (value) => value <= 10,
        )) {
            const { faultBound } = goalThresholds(participantCount);
            const census = bruteForceListerSets(participantCount);
            expect(census.minimumInclusionMargin).toBe(1);
            expect(census.maximumOmittedAuthors).toBe(faultBound);
            expect(census.tightOmissionWitness).toBe(true);
            expect(census.corruptionSets).toBe(
                Array.from({ length: faultBound + 1 }, (_unused, size) =>
                    binomial(participantCount, size),
                ).reduce((sum, value) => sum + value, 0),
            );
        }
    });

    it('checks every observable delivery order for three and four participants', () => {
        const three = exploreJointCloseViews(3);
        const four = exploreJointCloseViews(4);
        for (const census of [three, four]) {
            expect(census.findings).toEqual([]);
            expect(census.maximumHonestOmission).toBe(
                goalThresholds(census.participantCount).faultBound,
            );
            expect(census.referenceCrossChecks).toBeGreaterThan(0);
            expect(census.noResultInventories).toBeGreaterThan(0);
        }
        expect(four.corruptionCases).toBe(3);
        expect(four.conflictingSlots).toBeGreaterThan(0);
    });

    it('keeps the contract in every completion-profile corruption set', () => {
        const census = exploreCompletionProfileExecutions();
        const { faultBound, participantCount } = goalThresholds(10);
        expect(census.corruptionSets).toBe(
            Array.from({ length: faultBound + 1 }, (_unused, size) =>
                binomial(participantCount, size),
            ).reduce((sum, value) => sum + value, 0),
        );
        expect(census.findings).toEqual([]);
        expect(census.maximumHonestOmission).toBe(faultBound);
        // Ten is 3f + 1, so omission with corrupt abstention forces no result.
        expect(census.forcedNoResultExecutions).toBeGreaterThan(0);
        expect(census.maximumListedEntries).toBeLessThanOrEqual(
            2 * participantCount,
        );
        expect(census.certifiedExecutions).toBeGreaterThan(
            census.executions / 2,
        );
        // Every honest organizer closes despite late bodies filling its slots
        // and a different envelope for every other honest participant.
        expect(census.targetedExecutions).toBeGreaterThan(0);
        expect(census.targetedCertifiedExecutions).toBe(
            census.targetedExecutions,
        );
        expect(census.maximumHeldPerSlot).toBe(2);
        expect(census.maximumReceivedPerHonestSlot).toBe(1);
        expect(census.maximumReceivedPerCorruptSlot).toBeLessThanOrEqual(4);
        expect(census.maximumOrganizerRequestsPerSlot).toBe(1);
    });

    it('closes when corrupt participants fill the organizer body slots and split the others', () => {
        for (const participantCount of [4, 7, 10, 13]) {
            const { faultBound, quorum } = goalThresholds(participantCount);
            const corrupt =
                ((1 << faultBound) - 1) << (participantCount - faultBound);
            const result = runCloseExecution({
                participantCount,
                corrupt,
                voters: ((1 << participantCount) - 1) & ~corrupt,
                departedBeforeClose: 0,
                departedAfterCertification: 0,
                isolated: 0,
                seed: participantCount,
                corruptVotes: false,
                corruptEquivocation: 0,
                corruptBackdating: false,
                corruptWithholdsBody: false,
                corruptSignTargets: false,
                corruptOmitsIsolated: false,
                refuseAfterOwnOmission: false,
                corruptTargetsOrganizer: true,
                corruptWithholdsResponses: true,
            });
            expect(result.findings).toEqual([]);
            expect(result.certifiedTargets).toBe(1);
            expect(result.omittedHonest).toBe(0);
            // Every corrupt slot is conflicting through the organizer's own
            // listing, and every honest ballot is accepted.
            expect(result.inventory!.slots).toEqual(
                Array.from({ length: participantCount }, (_unused, author) =>
                    author >= participantCount - faultBound
                        ? 'conflicting'
                        : 'accepted',
                ),
            );
            expect(memberCount(result.inventory!.responders)).toBe(quorum);
            // The organizer receives two late bodies, discarded at its lock,
            // and requests at most the one known body before a second
            // envelope for the slot is known.
            expect(result.maximumReceivedPerCorruptSlot).toBeLessThanOrEqual(3);
            expect(result.maximumOrganizerRequestsPerSlot).toBe(1);
        }
    });

    it('ignores replayed messages of another action', () => {
        const result = runCloseExecution({
            participantCount: 7,
            corrupt: 0b1000000,
            voters: 0b0111111,
            departedBeforeClose: 0,
            departedAfterCertification: 0,
            isolated: 0,
            seed: 3,
            corruptVotes: true,
            corruptEquivocation: 2,
            corruptBackdating: true,
            corruptWithholdsBody: true,
            corruptSignTargets: true,
            corruptOmitsIsolated: false,
            refuseAfterOwnOmission: false,
        });
        expect(result.findings).toEqual([]);
        expect(result.certifiedTargets).toBe(1);
        expect(result.ignoredMessages).toBeGreaterThanOrEqual(6);
    });

    it('demonstrates each review obligation with a counterexample', () => {
        const census = compileCloseObligationCounterexamples();
        expect(census.volatileRetentionFindings).toEqual([
            'inclusion',
            'omission-inside-proposal',
        ]);
        expect(census.durableRetentionFindings).toEqual([]);
        expect(census.refusalCertifiedTargets).toBe(0);
        expect(census.refusalHonestSigners).toBeLessThan(census.refusalQuorum);
        expect(census.omittedSignerCertifiedTargets).toBe(1);
        expect(census.omittedSignerHonestOmission).toBe(
            goalThresholds(10).faultBound,
        );
        expect(census.omittedSignerFindings).toEqual([]);
        expect(census.uncappedResponseEntries).toBe(census.equivocations);
        expect(census.cappedResponseEntries).toBe(2);
        expect(census.earlyOrganizerSelection).toBe(1);
        expect(census.lateOrganizerSelection).toBe(census.organizerStallQuorum);
        expect(census.lateOwnListing).toEqual([
            envelopeIdentity(9, 0),
            envelopeIdentity(9, 1),
        ]);
        expect(census.supportRuleIncludesEnvelope).toBe(false);
        expect(census.unionRuleIncludesEnvelope).toBe(true);
    });

    it('attains but never exceeds the eight-visit stage bound for every roster', () => {
        // Three preparation visits, then ballot, close response, target
        // signature, release and verification; a nonvoter has no ballot.
        for (const participantCount of supportedParticipantCounts) {
            const census = compileCloseVisitCensus(participantCount);
            expect(census.voterStageBound).toBe(8);
            expect(census.organizerStageBound).toBe(8);
            expect(census.nonvoterStageBound).toBe(7);
            expect(census.voterVisits).toBe(8);
            expect(census.organizerVisits).toBe(8);
            expect(census.nonvoterVisits).toBe(7);
            expect(census.maximumVisits).toBeLessThanOrEqual(
                mandatoryVisitCeiling,
            );
        }
    });
});
