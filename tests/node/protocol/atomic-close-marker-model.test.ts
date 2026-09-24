import { describe, expect, it } from 'vitest';

import { atomicCloseMarkerTrace } from '#tests/atomic-close-marker-model.js';

describe('ordinary close markers in an ordered broadcast channel', () => {
    it.each([4, 10, 20])(
        'does not turn earlier invocation into earlier delivery for %i parties',
        (count) => {
            const trace = atomicCloseMarkerTrace(count);
            expect(trace.invocationOrder).toEqual(['ballot', 'close']);
            expect(trace.authenticatedPrefix).toHaveLength(count);
            expect(trace.bothProposalsValidate).toBe(true);
            expect(trace.delayedProposalValidates).toBe(true);
            expect(trace.staleRoundProposalAccepted).toBe(false);
            expect(trace.firstBatch).toEqual(['ballot', 'close']);
            expect(trace.completeAfterDelay).toEqual(['close', 'ballot']);
            expect(trace.ballotBeforeCloseWithIncludingProposal).toBe(true);
            expect(trace.ballotBeforeCloseWithExcludingProposal).toBe(false);
            expect(trace.invalidDuplicateProposalAccepted).toBe(false);
        },
    );

    it('refuses profiles outside the counterexample premise', () => {
        for (const count of [0, 3, 21, 4.5, Number.NaN])
            expect(() => atomicCloseMarkerTrace(count)).toThrow();
    });
});
