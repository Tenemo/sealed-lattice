import { describe, expect, it } from 'vitest';

import { validatePollSpec } from '../../src/lifecycle/poll-spec';
import {
    decodeSparseTopKTarget,
    derivePlaintextTopKOracle,
} from '../../src/plaintext-oracle/index';

describe('plaintext oracle in browsers', () => {
    it('derives and decodes a deterministic sparse top-k target without native helpers', () => {
        const pollSpec = validatePollSpec({
            pollId: 'browser-plaintext-oracle',
            question: 'Question',
            options: ['Alpha', 'Beta', 'Gamma'],
            topOptionCount: 2,
        });

        expect(pollSpec.ok).toBe(true);
        if (!pollSpec.ok) {
            throw new Error('Poll spec should validate.');
        }

        const oracle = derivePlaintextTopKOracle({
            ballots: [
                { scores: [10, 1, 1] },
                { scores: [1, 10, 1] },
                { scores: [10, 2, 1] },
            ],
            maximumRosterSize: 20,
            pollSpec: pollSpec.normalized,
        });
        const decoding = decodeSparseTopKTarget({
            expectedLayoutDigest: oracle.sparseTarget.layoutDigest,
            target: oracle.sparseTarget,
        });

        expect(oracle.ranking.map((entry) => entry.optionOrdinal)).toEqual([
            1, 2, 3,
        ]);
        expect(decoding.ok).toBe(true);
        expect(decoding.selectedOptionOrdinals).toEqual([1, 2]);
    });
});
