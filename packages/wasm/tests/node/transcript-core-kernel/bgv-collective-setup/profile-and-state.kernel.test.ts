import {
    configurableParticipantCountRange,
    deriveFoundationRosterParameters,
    foundationProfile,
} from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
    it('uses the selected ten-participant profile only when the participant count is omitted', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const selectedParameters =
            kernel.describeCollectiveBgvSetupParameters();
        const explicitPrototypeParameters =
            kernel.describeCollectiveBgvSetupParameters({
                participantCount: foundationProfile.participantCount,
            });

        expect(selectedParameters.participantCount).toBe(
            foundationProfile.participantCount,
        );
        expect(explicitPrototypeParameters).toEqual(selectedParameters);

        for (const malformedParticipantCount of [-1, 3.5]) {
            expect(() =>
                kernel.describeCollectiveBgvSetupParameters({
                    participantCount: malformedParticipantCount,
                }),
            ).toThrow('participantCount must be an unsigned integer');
        }
    });

    it('derives setup descriptions across the configurable range and rejects counts outside it', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setupParameterHashes = new Set<string>();

        for (
            let participantCount = configurableParticipantCountRange.minimum;
            participantCount <= configurableParticipantCountRange.maximum;
            participantCount += 1
        ) {
            const parameters = kernel.describeCollectiveBgvSetupParameters({
                participantCount,
            });
            const rosterParameters =
                deriveFoundationRosterParameters(participantCount);
            expect(parameters.participantCount).toBe(participantCount);
            expect(parameters.reconstructionThreshold).toBe(
                rosterParameters.reconstructionThreshold,
            );
            expect(parameters.setupParametersHash).toMatch(/^[0-9a-f]{128}$/u);
            setupParameterHashes.add(parameters.setupParametersHash);
        }
        expect(setupParameterHashes.size).toBe(
            configurableParticipantCountRange.maximum -
                configurableParticipantCountRange.minimum +
                1,
        );

        for (const participantCount of [2, 21]) {
            expect(() =>
                kernel.describeCollectiveBgvSetupParameters({
                    participantCount,
                }),
            ).toThrow('participantCount must be an integer from 3 through 20');
        }
    });

    it('exposes the canonical logical-slot rotation schedule', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const parameters = kernel.describeCollectiveBgvSetupParameters();
        const expectedRotations = [
            3, 9, 81, 385, 2657, 6561, 16001, 17153, 18609, 31233, 34305, 36409,
            43691, 47297, 48385, 55105,
        ];

        expect(
            parameters.evaluatorKeySchedule.requiredGaloisKeySchedule,
        ).toEqual(
            expectedRotations.map((rotation) => ({ rotation, level: 16 })),
        );
        expect(parameters.setupParametersHash).toBe(
            'faf7e7a20ec6c45c08aa0083a5c596ae45a06c703c22653cac5d1672cdcc8667e8e2da7def0edd14224747ac9842de7286043e83e92f86b899bed8a91605d9b7',
        );
    });
});
