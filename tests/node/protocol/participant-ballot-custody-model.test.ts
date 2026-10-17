import { describe, expect, it } from 'vitest';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';
describe('participant ballot custody layout', () => {
    it('retains the seed from the attempt lock until the body is retained', () => {
        const value = compileParticipantBallotCustody(completionProfile()),
            body = compileBallotBodyCensus(completionProfile());
        // The score count, body length and key count; at most 20 scores and
        // the 8-byte ballot time; the 512-bit seed; 32-byte keys,
        // the 210-byte envelope and the 8,642-byte signature.
        expect(value.prefixBytes).toBe(7n);
        expect(value.maximumBodyRecords).toBe(23n);
        expect(value.phaseBytes.map((entry) => entry.bytes)).toEqual([
            7n + 20n + 8n,
            7n + 20n + 8n + 64n,
            7n + 20n + 8n + 32n * 23n + 210n,
            7n + 32n * 23n + 210n + 8642n,
        ]);
        expect(value.maximumStateBytes).toBe(9595n);
        expect(value.maximumEncryptedBodyBytes).toBe(
            body.maximumBodyBytes + 23n * 16n,
        );
    });
});
