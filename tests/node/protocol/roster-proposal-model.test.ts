import { describe, expect, it } from 'vitest';

import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';

describe('verified registration roster proposal', () => {
    it('bounds the complete public record corpus and recipient key live set', () => {
        for (let count = 3; count <= 20; count++) {
            const value = compileRosterProposalCensus(count);
            expect(value.roleBytes).toBeLessThanOrEqual(1024n);
            expect(value.proposalBytes).toBeLessThan(2048n);
            expect(value.contributionControlBytes).toBeLessThan(2048n);
            expect(value.maximumPublicCorpusBytes).toBeLessThan(
                256n * 1024n ** 2n,
            );
        }
        const value = compileRosterProposalCensus(10);
        expect(value.retainedRecipientKeyBytes).toBe(13_762_560n);
        expect(value.maximumPublicCorpusBytes).toBeLessThan(128n * 1024n ** 2n);
    });
    it('refuses unsupported or nonintegral roster counts', () => {
        for (const count of [2, 21, 3.5, NaN])
            expect(() => compileRosterProposalCensus(count)).toThrow();
    });
});
