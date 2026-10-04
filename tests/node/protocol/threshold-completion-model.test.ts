import { describe, expect, it } from 'vitest';

import {
    compileSupportedThresholdCompletionProfiles,
    compileThresholdCompletionProfile,
    deriveLifecycleAvailability,
    lifecycleAvailabilityStages,
    simulateFixedContributorMessageAvailability,
} from '#tests/threshold-completion-model.js';

// Product goals, maintained independently of the model: a poll has 3 to 20
// participants, at most f = floor((n - 1) / 3) of them are corrupt, and at
// most f ballots can be left out. Release needs shares from at least f + 1
// participants and never fewer than 2, a result needs at least f + 2 accepted
// ballots, and closing needs n - f participants. From roster fixing, a total
// of at most f participants may become unavailable; only the organizer is
// indispensable before closure, and no participant is indispensable after it.
const supportedParticipantCounts = Array.from(
    { length: 20 - 3 + 1 },
    (_unused, index) => 3 + index,
);

const goalThresholds = (participantCount: number) => {
    const maximumCorruptParticipantCount = Math.floor(
        (participantCount - 1) / 3,
    );
    return {
        maximumCorruptParticipantCount,
        resultReleaseThreshold: Math.max(maximumCorruptParticipantCount + 1, 2),
        minimumTurnout: maximumCorruptParticipantCount + 2,
        inventoryCertificateThreshold:
            participantCount - maximumCorruptParticipantCount,
    };
};

const memberCount = (participantSet: number): number => {
    let count = 0;
    for (
        let remaining = participantSet;
        remaining !== 0;
        remaining &= remaining - 1
    ) {
        count += 1;
    }
    return count;
};

// Every participant set, as a bit mask, whose size the predicate admits.
const participantSets = (
    participantCount: number,
    admitsSize: (size: number) => boolean,
): readonly number[] =>
    Array.from(
        { length: 2 ** participantCount },
        (_unused, participantSet) => participantSet,
    ).filter((participantSet) => admitsSize(memberCount(participantSet)));

describe('threshold completion model', () => {
    it('derives the thresholds and the current candidate post-setup census independently', () => {
        expect(compileThresholdCompletionProfile(10)).toMatchObject({
            participantCount: 10,
            maximumCorruptParticipantCount: 3,
            inventoryCertificateThreshold: 7,
            resultReleaseThreshold: 4,
            setupContributorCount: 4,
            minimumTurnout: 5,
            noResultForceableAtFullHonestTurnout: true,
            setupReceiptThreshold: 10,
            guaranteedHonestResponderCount: 4,
            minimumHonestVerifiedShareCountAfterDisappearance: 4,
            minimumHonestCertificateSignerCount: 4,
            minimumCertificateIntersection: 4,
            mandatoryReleaseParticipantCount: 0,
            certificateSetCount: 120n,
            orderedCertificatePairCount: 14_400n,
            bruteForceCrossChecked: true,
        });
    });

    it('derives release and turnout thresholds at the roster extremes', () => {
        expect(compileThresholdCompletionProfile(3)).toMatchObject({
            maximumCorruptParticipantCount: 0,
            inventoryCertificateThreshold: 3,
            resultReleaseThreshold: 2,
            setupContributorCount: 2,
            minimumTurnout: 2,
            noResultForceableAtFullHonestTurnout: false,
            mandatoryReleaseParticipantCount: 0,
        });
        expect(compileThresholdCompletionProfile(20)).toMatchObject({
            maximumCorruptParticipantCount: 6,
            resultReleaseThreshold: 7,
            setupContributorCount: 7,
            minimumTurnout: 8,
            noResultForceableAtFullHonestTurnout: false,
        });
    });

    it('matches the goal thresholds and their safety facts at every supported participant count', () => {
        const expectedProfiles = supportedParticipantCounts.map(
            (participantCount) => {
                const thresholds = goalThresholds(participantCount);
                const {
                    maximumCorruptParticipantCount,
                    minimumTurnout,
                    inventoryCertificateThreshold,
                } = thresholds;
                const honestParticipantCount =
                    participantCount - maximumCorruptParticipantCount;
                return {
                    participantCount,
                    ...thresholds,
                    // A closing certificate's n - f signers, less the f
                    // corrupt ones.
                    minimumHonestCertificateSignerCount:
                        inventoryCertificateThreshold -
                        maximumCorruptParticipantCount,
                    // Two sets of n - f participants share at least
                    // 2 * (n - f) - n of them.
                    minimumCertificateIntersection:
                        2 * inventoryCertificateThreshold - participantCount,
                    // With every honest participant voting, f honest ballots
                    // can be left out while every corrupt participant
                    // abstains.
                    noResultForceableAtFullHonestTurnout:
                        honestParticipantCount -
                            maximumCorruptParticipantCount <
                        minimumTurnout,
                    mandatoryReleaseParticipantCount: 0,
                };
            },
        );
        expect(compileSupportedThresholdCompletionProfiles()).toMatchObject(
            expectedProfiles,
        );
        for (const expected of expectedProfiles) {
            // Two closing certificates share an honest participant.
            expect(expected.minimumCertificateIntersection).toBeGreaterThan(
                expected.maximumCorruptParticipantCount,
            );
            // The corrupt participants cannot release on their own.
            expect(expected.maximumCorruptParticipantCount).toBeLessThan(
                expected.resultReleaseThreshold,
            );
            // Some release set omits any given participant.
            expect(expected.resultReleaseThreshold).toBeLessThan(
                expected.participantCount,
            );
        }
    });

    it('leaves an honest member in the fixed contributor set', () => {
        for (const profile of compileSupportedThresholdCompletionProfiles()) {
            // Only the first setupContributorCount positions contribute, and
            // the corrupt participants cannot fill them all.
            expect(profile.setupContributorCount).toBeGreaterThan(
                profile.maximumCorruptParticipantCount,
            );
            expect(profile.setupContributorCount).toBeGreaterThanOrEqual(2);
            expect(profile.setupContributorCount).toBeLessThanOrEqual(
                profile.participantCount,
            );
        }
        // Every corrupt set of at most f participants leaves an honest
        // contributor.
        for (
            let participantCount = 3;
            participantCount <= 12;
            participantCount += 1
        ) {
            const { maximumCorruptParticipantCount, setupContributorCount } =
                compileThresholdCompletionProfile(participantCount);
            const contributors = 2 ** setupContributorCount - 1;
            for (const corruptSet of participantSets(
                participantCount,
                (size) => size <= maximumCorruptParticipantCount,
            ))
                expect(
                    memberCount(contributors & ~corruptSet),
                ).toBeGreaterThanOrEqual(1);
        }
    });

    it('confirms certificate intersections and the separate post-setup stress census by enumeration', () => {
        // Up to 12 participants, each enumeration visits fewer than 100,000
        // set pairs.
        for (
            let participantCount = 3;
            participantCount <= 12;
            participantCount += 1
        ) {
            const {
                maximumCorruptParticipantCount,
                resultReleaseThreshold,
                inventoryCertificateThreshold,
            } = goalThresholds(participantCount);
            const profile = compileThresholdCompletionProfile(participantCount);

            const certificates = participantSets(
                participantCount,
                (size) => size === inventoryCertificateThreshold,
            );
            let minimumCertificateIntersection = participantCount;
            for (const left of certificates) {
                for (const right of certificates) {
                    minimumCertificateIntersection = Math.min(
                        minimumCertificateIntersection,
                        memberCount(left & right),
                    );
                }
            }
            expect(minimumCertificateIntersection).toBeGreaterThan(
                maximumCorruptParticipantCount,
            );
            expect(profile).toMatchObject({
                minimumCertificateIntersection,
                certificateSetCount: BigInt(certificates.length),
                orderedCertificatePairCount: BigInt(certificates.length) ** 2n,
            });

            // This stronger responder-count stress case starts after all
            // setup receipts exist. It cannot prove progress from roster
            // fixing, for which the unavailable union is bounded by f.
            const faultSets = participantSets(
                participantCount,
                (size) => size <= maximumCorruptParticipantCount,
            );
            const everyParticipant = 2 ** participantCount - 1;
            let minimumHonestResponderCount = participantCount;
            let corruptionDisappearanceRefusalCaseCount = 0;
            for (const corruptSet of faultSets) {
                for (const disappearedSet of faultSets) {
                    minimumHonestResponderCount = Math.min(
                        minimumHonestResponderCount,
                        memberCount(
                            everyParticipant & ~corruptSet & ~disappearedSet,
                        ),
                    );
                    corruptionDisappearanceRefusalCaseCount +=
                        2 ** memberCount(corruptSet & ~disappearedSet);
                }
            }
            expect(minimumHonestResponderCount).toBeGreaterThanOrEqual(
                resultReleaseThreshold,
            );
            expect(profile).toMatchObject({
                setupReceiptThreshold: participantCount,
                guaranteedHonestResponderCount: minimumHonestResponderCount,
                minimumHonestVerifiedShareCountAfterDisappearance:
                    minimumHonestResponderCount,
                corruptionDisappearanceRefusalCaseCount: BigInt(
                    corruptionDisappearanceRefusalCaseCount,
                ),
            });
        }
    });

    it('rejects participant counts outside the supported range', () => {
        for (const participantCount of [0, 1, 2, 21, 3.5, Number.NaN]) {
            expect(() =>
                compileThresholdCompletionProfile(participantCount),
            ).toThrow(/outside the supported range/u);
        }
    });
});

describe('availability from roster fixing', () => {
    it('keeps at least n - f participants at every cut in every permitted single-failure schedule', () => {
        for (const participantCount of supportedParticipantCounts) {
            const faultBound = Math.floor((participantCount - 1) / 3);
            const roster = Array.from(
                { length: participantCount },
                (_unused, participant) => participant,
            );
            const uninterrupted = deriveLifecycleAvailability(
                participantCount,
                0,
                [],
            );
            expect(uninterrupted.requiredContinuerCount).toBe(
                participantCount - faultBound,
            );
            for (const stage of uninterrupted.stages)
                expect(stage.availableParticipants).toEqual(roster);
            if (faultBound === 0) continue;
            for (const [cut, before] of lifecycleAvailabilityStages.entries()) {
                for (const participant of roster) {
                    if (participant === 0 && cut <= 5) continue;
                    const availability = deriveLifecycleAvailability(
                        participantCount,
                        0,
                        [{ participant, before }],
                    );
                    expect(availability.roster).toEqual(roster);
                    for (const [
                        index,
                        stage,
                    ] of availability.stages.entries()) {
                        expect(stage.availableParticipants).toEqual(
                            index < cut
                                ? roster
                                : roster.filter(
                                      (position) => position !== participant,
                                  ),
                        );
                        expect(
                            stage.availableParticipants.length,
                        ).toBeGreaterThanOrEqual(participantCount - faultBound);
                    }
                }
            }
        }
    });

    it('charges the union across stages and keeps the organizer until closure', () => {
        const availability = deriveLifecycleAvailability(10, 0, [
            { participant: 0, before: 'release' },
            { participant: 1, before: 'roster-fixed' },
            { participant: 7, before: 'closing' },
            { participant: 1, before: 'release' },
        ]);
        expect(
            availability.stages.map(
                (stage) => stage.availableParticipants.length,
            ),
        ).toEqual([9, 9, 9, 9, 8, 8, 7]);
        expect(availability.stages[5].availableParticipants).toContain(0);
        expect(availability.stages[6].availableParticipants).not.toContain(0);
        expect(() =>
            deriveLifecycleAvailability(4, 0, [
                { participant: 1, before: 'roster-fixed' },
                { participant: 2, before: 'release' },
            ]),
        ).toThrow('total unavailable set');
        for (const before of lifecycleAvailabilityStages.slice(0, 6))
            expect(() =>
                deriveLifecycleAvailability(4, 0, [{ participant: 0, before }]),
            ).toThrow('organizer is required');
        // The creator's identity, rather than a hard-coded position, owns
        // the closing exception.
        expect(() =>
            deriveLifecycleAvailability(4, 3, [
                { participant: 3, before: 'closing' },
            ]),
        ).toThrow('organizer is required');
        expect(
            deriveLifecycleAvailability(4, 3, [
                { participant: 0, before: 'closing' },
            ]).stages[4].availableParticipants,
        ).toEqual([1, 2, 3]);
    });

    it('refuses schedules outside the supported roster and failure envelope', () => {
        for (const participantCount of [2, 21, 3.5, Number.NaN])
            expect(() =>
                deriveLifecycleAvailability(participantCount, 0, []),
            ).toThrow('supported range');
        for (const participant of [-1, 4, 1.5, Number.NaN]) {
            expect(() =>
                deriveLifecycleAvailability(4, participant, []),
            ).toThrow('outside the roster');
            expect(() =>
                deriveLifecycleAvailability(4, 0, [
                    { participant, before: 'release' },
                ]),
            ).toThrow('outside the roster');
        }
        expect(() =>
            deriveLifecycleAvailability(3, 0, [
                { participant: 1, before: 'release' },
            ]),
        ).toThrow('total unavailable set');
    });
});

describe('fixed-contributor preparation dependency experiment', () => {
    it('exposes the minimal missing-confirmation and committed-but-unopened counterexamples', () => {
        const missingConfirmation = simulateFixedContributorMessageAvailability(
            4,
            0,
            [{ participant: 2, before: 'roster-confirmation' }],
        );
        expect(missingConfirmation.confirmationParticipants).toEqual([0, 1, 3]);
        expect(missingConfirmation.missingConfirmationParticipants).toEqual([
            2,
        ]);
        expect(missingConfirmation.openingParticipants).toEqual([]);
        expect(missingConfirmation.closeParticipants).toEqual([]);
        expect(missingConfirmation.releaseParticipants).toEqual([]);

        const missingOpening = simulateFixedContributorMessageAvailability(
            4,
            0,
            [{ participant: 1, before: 'setup-opening' }],
        );
        expect(missingOpening.confirmationParticipants).toEqual([0, 1, 2, 3]);
        expect(missingOpening.missingConfirmationParticipants).toEqual([]);
        expect(missingOpening.openingParticipants).toEqual([0]);
        expect(missingOpening.missingOpeningParticipants).toEqual([1]);
        expect(missingOpening.closeParticipants).toEqual([]);
        expect(missingOpening.releaseParticipants).toEqual([]);
    });

    it('finds the missing producer for every early single failure at every fault-tolerant size', () => {
        for (const participantCount of supportedParticipantCounts.filter(
            (count) => count >= 4,
        )) {
            const faultBound = Math.floor((participantCount - 1) / 3);
            const contributors = Array.from(
                { length: Math.max(faultBound + 1, 2) },
                (_unused, participant) => participant,
            );
            for (
                let participant = 1;
                participant < participantCount;
                participant++
            ) {
                for (const before of lifecycleAvailabilityStages.slice(0, 4)) {
                    const trace = simulateFixedContributorMessageAvailability(
                        participantCount,
                        0,
                        [{ participant, before }],
                    );
                    const contributor = contributors.includes(participant);
                    const confirmationMissing =
                        before === 'roster-fixed' ||
                        before === 'roster-confirmation' ||
                        (before === 'setup-commitment' && contributor);
                    expect(trace.missingConfirmationParticipants).toEqual(
                        confirmationMissing ? [participant] : [],
                    );
                    expect(trace.missingOpeningParticipants).toEqual(
                        confirmationMissing
                            ? contributors
                            : contributor
                              ? [participant]
                              : [],
                    );
                    expect(trace.releaseParticipants.length).toBe(
                        confirmationMissing || contributor
                            ? 0
                            : participantCount - 1,
                    );
                }
            }
        }
    });

    it('retains published setup messages and permits later quorum work without their departed senders', () => {
        for (const participantCount of supportedParticipantCounts) {
            const faultBound = Math.floor((participantCount - 1) / 3);
            const roster = Array.from(
                { length: participantCount },
                (_unused, participant) => participant,
            );
            const uninterrupted = simulateFixedContributorMessageAvailability(
                participantCount,
                0,
                [],
            );
            expect(uninterrupted.confirmationParticipants).toEqual(roster);
            expect(uninterrupted.openingParticipants).toEqual(
                roster.slice(0, Math.max(faultBound + 1, 2)),
            );
            expect(uninterrupted.releaseParticipants).toEqual(roster);
            if (faultBound === 0) continue;
            // Some participants leave before closing; the organizer leaves
            // after certification permanently closes the inventory. The total
            // is exactly f, not a renewed per-stage f.
            const failures = [
                ...roster.slice(1, faultBound).map((participant) => ({
                    participant,
                    before: 'closing' as const,
                })),
                { participant: 0, before: 'release' as const },
            ];
            const trace = simulateFixedContributorMessageAvailability(
                participantCount,
                0,
                failures,
            );
            expect(trace.confirmationParticipants).toEqual(roster);
            expect(trace.openingParticipants).toEqual(
                uninterrupted.openingParticipants,
            );
            expect(trace.closeParticipants).toEqual([
                0,
                ...roster.slice(faultBound),
            ]);
            expect(trace.certificateParticipants).toEqual([
                0,
                ...roster.slice(faultBound),
            ]);
            expect(trace.releaseParticipants).toEqual(roster.slice(faultBound));
            expect(trace.releaseParticipants.length).toBeGreaterThanOrEqual(
                Math.max(faultBound + 1, 2),
            );
        }
    });
});
