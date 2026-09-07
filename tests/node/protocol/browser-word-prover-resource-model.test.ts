import { describe, expect, it } from 'vitest';

import {
    compileBrowserWordProverResources,
    compileContributionGenerationResources,
} from '#tests/browser-word-prover-resource-model.js';

describe('browser word prover live-data schedule', () => {
    it('bounds the combined private handoff and public working-store representation', () => {
        const result = compileContributionGenerationResources();
        expect(result.combinedAllowance).toBeLessThan(671_088_640n);
        expect(result.maximumPublicEmissionBatch).toBe(7n * 65536n * 109n);
        expect(result.regeneratedCommonBytes).toBe(
            18n * 65536n * 109n + 65536n * 21n + 4096n * 6n,
        );
        expect(result.reusedRecipientBytes).toBe(10n * 65536n * 21n);
        expect(result.publicWorkingBytes).toBe(
            result.expandedPublicWorkingBytes -
                (18n * 65536n * 109n + 11n * 65536n * 21n + 4096n * 6n),
        );
        expect(result.publicWorkingBytes).toBeLessThan(268_435_456n);
        expect(result.expandedPublicWorkingBytes).toBeGreaterThan(268_435_456n);
    });
    it('retains common adjoints while streaming public polynomials and releases first-oracle state before second openings', () => {
        const result = compileBrowserWordProverResources();
        expect(result.fullDegreeCommonPolynomials).toBe(3n * 6n + 10n + 1n);
        expect(result.preparedAdjointBytes).toBe((29n * 65536n + 4096n) * 48n);
        const first = result.stages.find(
            (stage) => stage.stage === 'first openings',
        )!;
        const second = result.stages.find(
            (stage) => stage.stage === 'second openings',
        )!;
        expect(second.bytes).toBeLessThan(first.bytes);
        expect(result.maximumLiveBytes).toBeLessThan(671_088_640n);
    });
});
