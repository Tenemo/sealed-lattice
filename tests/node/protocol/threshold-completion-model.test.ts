import { describe, expect, it } from 'vitest';

import {
    compileSupportedThresholdCompletionProfiles,
    compileThresholdCompletionProfile,
} from '#tests/threshold-completion-model.js';

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

    it('covers every supported participant count', () => {
        const profiles = compileSupportedThresholdCompletionProfiles();
        expect(
            profiles.map(({ participantCount }) => participantCount),
        ).toEqual(Array.from({ length: 18 }, (_unused, index) => index + 3));
        for (const profile of profiles) {
            expect(profile.maximumCorruptParticipantCount).toBeLessThan(
                profile.resultReleaseThreshold,
            );
            expect(
                profile.guaranteedHonestResponderCount,
            ).toBeGreaterThanOrEqual(profile.resultReleaseThreshold);
            expect(
                profile.minimumHonestVerifiedShareCountAfterDisappearance,
            ).toBeGreaterThanOrEqual(profile.resultReleaseThreshold);
            expect(profile.minimumHonestPublicationSignerCount).toBe(
                profile.guaranteedHonestResponderCount,
            );
            expect(profile.maximumPostClosePublicationSignerCount).toBeLessThan(
                profile.inventoryCertificateThreshold,
            );
            expect(profile.minimumCertificateIntersection).toBeGreaterThan(
                profile.maximumCorruptParticipantCount,
            );
            expect(profile.mandatoryReleaseParticipantCount).toBe(0);
            expect(profile.resultReleaseThreshold).toBeGreaterThanOrEqual(2);
            expect(profile.resultReleaseThreshold).toBeLessThan(
                profile.participantCount,
            );
            expect(
                profile.minimumTurnout - profile.maximumCorruptParticipantCount,
            ).toBe(2);
            expect(profile.noResultForceableAtFullHonestTurnout).toBe(
                profile.participantCount ===
                    3 * profile.maximumCorruptParticipantCount + 1,
            );
        }
    });

    it('rejects participant counts outside the supported range', () => {
        expect(() => compileThresholdCompletionProfile(2)).toThrow(
            /outside the supported range/u,
        );
        expect(() => compileThresholdCompletionProfile(21)).toThrow(
            /outside the supported range/u,
        );
    });
});
