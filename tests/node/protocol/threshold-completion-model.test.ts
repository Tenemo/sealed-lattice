import { describe, expect, it } from 'vitest';

import {
    compileSupportedThresholdCompletionProfiles,
    compileThresholdCompletionProfile,
} from '#tests/threshold-completion-model.js';

// Product goals, maintained independently of the model: a poll has 3 to 20
// participants, at most f = floor((n - 1) / 3) of them are corrupt, and at
// most f ballots can be left out. Release needs shares from at least f + 1
// participants and never fewer than 2, a result needs at least f + 2 accepted
// ballots, closing needs n - f participants, and no stage may require a
// particular participant.
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
    it('derives the completion thresholds independently', () => {
        expect(compileThresholdCompletionProfile(10)).toMatchObject({
            participantCount: 10,
            maximumCorruptParticipantCount: 3,
            inventoryCertificateThreshold: 7,
            resultReleaseThreshold: 4,
            minimumTurnout: 5,
            noResultForceableAtFullHonestTurnout: true,
            setupReceiptThreshold: 10,
            guaranteedHonestResponderCount: 4,
            minimumHonestVerifiedShareCountAfterDisappearance: 4,
            minimumHonestPublicationSignerCount: 4,
            minimumCertificateIntersection: 4,
            maximumPostClosePublicationSignerCount: 6,
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
            minimumTurnout: 2,
            noResultForceableAtFullHonestTurnout: false,
            mandatoryReleaseParticipantCount: 0,
        });
        expect(compileThresholdCompletionProfile(20)).toMatchObject({
            maximumCorruptParticipantCount: 6,
            resultReleaseThreshold: 7,
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
                    // Every roster participant completes preparation.
                    setupReceiptThreshold: participantCount,
                    // Besides the f corrupt participants, up to f honest ones
                    // may disappear.
                    guaranteedHonestResponderCount:
                        honestParticipantCount - maximumCorruptParticipantCount,
                    // Every participant's verified setup share, less the f
                    // corrupt and f disappeared participants.
                    minimumHonestVerifiedShareCountAfterDisappearance:
                        participantCount - 2 * maximumCorruptParticipantCount,
                    // A closing certificate's n - f signers, less the f
                    // corrupt ones.
                    minimumHonestPublicationSignerCount:
                        inventoryCertificateThreshold -
                        maximumCorruptParticipantCount,
                    // Corruption and disappearance each remove at most f
                    // certificate holders.
                    maximumPostClosePublicationSignerCount:
                        2 * maximumCorruptParticipantCount,
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
            // The guaranteed honest responders can release on their own.
            expect(
                expected.guaranteedHonestResponderCount,
            ).toBeGreaterThanOrEqual(expected.resultReleaseThreshold);
            // The corrupt participants cannot release on their own.
            expect(expected.maximumCorruptParticipantCount).toBeLessThan(
                expected.resultReleaseThreshold,
            );
            // Enough verified setup shares survive disappearance to release.
            expect(
                expected.minimumHonestVerifiedShareCountAfterDisappearance,
            ).toBeGreaterThanOrEqual(expected.resultReleaseThreshold);
            // A closing certificate outnumbers every holder that can be lost.
            expect(
                expected.maximumPostClosePublicationSignerCount,
            ).toBeLessThan(expected.inventoryCertificateThreshold);
            // Some release set omits any given participant.
            expect(expected.resultReleaseThreshold).toBeLessThan(
                expected.participantCount,
            );
        }
    });

    it('confirms certificate intersections and honest responders by enumeration for small rosters', () => {
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

            // Corrupt and disappearing sets of at most f participants are
            // chosen independently, and any subset of the corrupt participants
            // that remain may refuse.
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
                guaranteedHonestResponderCount: minimumHonestResponderCount,
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
