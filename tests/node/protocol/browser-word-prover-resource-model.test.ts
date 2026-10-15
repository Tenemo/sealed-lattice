import { describe, expect, it } from 'vitest';

import {
    compileBrowserWordProverResources,
    compileContributionGenerationResources,
} from '#tests/browser-word-prover-resource-model.js';
import { merkleTreeStorage } from '#tests/merkle-opening-work-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('browser word prover live-data schedule', () => {
    it('counts retained digest arrays and one seed per private tree', () => {
        expect(merkleTreeStorage(2, false)).toEqual({
            saltSeedBytes: 64n,
            leafDigestBytes: 128n,
            innerNodeBytes: 128n,
            residentBytes: 320n,
        });
        expect(merkleTreeStorage(262_144, false).residentBytes).toBe(
            17_825_856n,
        );
        expect(merkleTreeStorage(262_144, true).residentBytes).toBe(1_048_640n);
        expect(merkleTreeStorage(32, true).innerNodeBytes).toBe(128n);
        for (const length of [0, 1, 3, Number.POSITIVE_INFINITY])
            expect(() => merkleTreeStorage(length, false)).toThrow(RangeError);
        const result = compileBrowserWordProverResources(completionProfile());
        expect(result.retainedPrivateTreeBytes).toBe(17_825_856n);
        expect(result.forgottenPrivateTreeBytes).toBe(1_048_640n);
        // Fold lengths 131072 through 4 retain 262140 field elements,
        // inner arrays totalling 16388 digests and sixteen salt seeds.
        expect(result.retainedFoldingBytes).toBe(
            262_140n * 48n + 16_388n * 64n + 16n * 64n,
        );
    });
    it('bounds the combined private handoff and public working-store representation', () => {
        const result =
            compileContributionGenerationResources(completionProfile());
        expect(result.combinedAllowance).toBeLessThan(671_088_640n);
        expect(result.maximumPublicEmissionBatch).toBe(7n * 65536n * 109n);
        expect(result.regeneratedCommonBytes).toBe(
            18n * 65536n * 109n + 65536n * 21n,
        );
        expect(result.reusedRecipientBytes).toBe(10n * 65536n * 21n);
        expect(result.publicWorkingBytes).toBe(
            result.expandedPublicWorkingBytes -
                (18n * 65536n * 109n + 11n * 65536n * 21n),
        );
        expect(result.publicWorkingBytes).toBeLessThan(268_435_456n);
        expect(result.expandedPublicWorkingBytes).toBeGreaterThan(268_435_456n);
    });
    it('counts common adjoints beside the streamed public-polynomial schedule', () => {
        const result = compileBrowserWordProverResources(completionProfile());
        expect(result.fullDegreeCommonPolynomials).toBe(3n * 6n + 10n + 1n);
        expect(result.preparedAdjointBytes).toBe(29n * 65536n * 48n);
        expect(result.maximumLiveBytes).toBeLessThan(671_088_640n);
    });
});
