import { describe, expect, it } from 'vitest';

import { loadTranscriptCoreKernel } from '#packages/wasm/src/index';

describe('collective BGV setup kernel commands', () => {
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
            '7f9ebdddb630b12e5aa3bef13381d862eaa5f66b9309692b9239b67069308058dd59b95565860d5c31de77b3a93852d694545e9343f4fb3eef9f21860d35f4dc',
        );
    });

});
