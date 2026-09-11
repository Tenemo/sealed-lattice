import { describe, expect, it } from 'vitest';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
describe('participant ballot custody layout', () => {
    it('counts the retained bytes before and after signed-message completion', () => {
        const value = compileParticipantBallotCustody(),
            body = compileBallotBodyCensus();
        expect(value.prefixBytes).toBe(13n);
        expect(value.maximumBodyRecords).toBe(25n);
        expect(value.phaseBytes.map((entry) => entry.bytes)).toEqual([
            13n + 20n + 32n * 146n,
            13n + 20n + 32n * 147n,
            13n + 20n + 32n * (147n + 25n) + 206n,
            13n + 20n + 32n * (147n + 25n) + 206n + 32n,
            13n + 32n * 25n + 206n + 3309n,
        ]);
        expect(value.maximumStateBytes).toBe(5775n);
        expect(value.maximumEncryptedBodyBytes).toBe(
            body.maximumBodyBytes + 25n * 16n,
        );
        expect(value.maximumJournalAndBodyBytes).toBeLessThan(268435456n);
    });
});
