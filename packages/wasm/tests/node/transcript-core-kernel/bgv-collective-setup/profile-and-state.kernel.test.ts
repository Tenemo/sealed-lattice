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
        expect(selectedParameters.qShare.primes).toEqual([
            '1953759233',
            '2256928769',
            '2408513537',
            '2610626561',
            '2661154817',
            '3014852609',
            '3031695361',
            '3368550401',
        ]);

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
        const expectedSchedule = [
            { rotation: 15, level: 14 },
            { rotation: 19, level: 14 },
            { rotation: 219, level: 14 },
            { rotation: 257, level: 18 },
            { rotation: 1025, level: 18 },
            { rotation: 8193, level: 18 },
        ];

        expect(
            parameters.evaluatorKeySchedule.requiredGaloisKeySchedule,
        ).toEqual(expectedSchedule);
        expect(parameters.setupParametersHash).toBe(
            '2f08fa04dce5ee8106ea47079012765fc7037dee77ab352ad1685c3983ca20a552bd148802ad49e5ae51d8a52307e086cbd2cce2255e4341cf52f7559453e8b4',
        );
    });
});
