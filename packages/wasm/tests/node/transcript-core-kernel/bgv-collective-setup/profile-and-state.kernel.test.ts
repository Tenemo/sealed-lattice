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
            'faf7e7a20ec6c45c08aa0083a5c596ae45a06c703c22653cac5d1672cdcc8667e8e2da7def0edd14224747ac9842de7286043e83e92f86b899bed8a91605d9b7',
        );
    });
});
