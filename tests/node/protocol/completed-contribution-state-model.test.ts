import { describe, expect, it } from 'vitest';

import { compileCompletedContributionStateCensus } from '#tests/completed-contribution-state-model.js';

describe('completed contribution retention', () => {
    it('bounds staged completion before private checkpoint retirement', () => {
        const model = compileCompletedContributionStateCensus();
        expect(model.maximumProofRecords).toBe(41n);
        expect(model.maximumPublicRecords).toBe(210n + 41n);
        expect(model.maximumRootPlaintextBytes).toBe(80n + 106n * 251n);
        expect(model.maximumStagedPayloadBytes).toBeLessThan(402_653_184n);
        expect(model.maximumRetainedPayloadBytes).toBeLessThan(268_435_456n);
        expect(model.maximumRetainedPayloadBytes).toBeLessThan(
            model.maximumStagedPayloadBytes,
        );
    });
});
