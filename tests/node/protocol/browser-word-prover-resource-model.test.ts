import { describe, expect, it } from 'vitest';

import { compileBrowserWordProverResources } from '#tests/browser-word-prover-resource-model.js';

describe('browser word prover live-data schedule', () => {
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
