import { describe, expect, it } from 'vitest';

import { compileFullTallyResourceModel } from '#tests/full-tally-resource-model.js';

describe('independent full-tally resource model', () => {
    it('derives every admitted result width from emitted object lengths', () => {
        for (let topCount = 1; topCount <= 10; topCount += 1) {
            const resource = compileFullTallyResourceModel(topCount, 8);
            expect(resource.activationChunkCorpusByteLength).toBeGreaterThan(0);
            expect(resource.activationInventoryByteLength).toBeGreaterThan(0);
            expect(resource.cleanVerifiedDownloadByteLength).toBeGreaterThan(
                resource.activationChunkCorpusByteLength,
            );
            expect(
                resource.maximumConstructionCommandRequestByteLength,
            ).toBeLessThanOrEqual(1_572_864);
        }
    });

    it('regenerates the maximum-width emitted download screen', () => {
        expect(compileFullTallyResourceModel(10, 8)).toEqual({
            activationChunkCorpusByteLength: 304_336_370,
            activationInventoryByteLength: 86_550,
            cleanVerifiedDownloadByteLength: 305_130_327,
            maximumConstructionCommandRequestByteLength: 1_200_505,
            maximumChunkEvaluationRequestByteLength: 1_200_505,
            maximumChunkGenerationRequestByteLength: 448_553,
            maximumPrivatePreparationRecipientByteLength: 181_467,
            preparationParentInventoryByteLength: 119_110,
            sourceInventoryByteLength: 37_438,
        });
    });

    it('refuses an impossible submission inventory', () => {
        expect(() => compileFullTallyResourceModel(10, -1)).toThrow(RangeError);
        expect(() => compileFullTallyResourceModel(10, 11)).toThrow(RangeError);
    });
});
