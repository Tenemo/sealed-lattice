import { describe, expect, it } from 'vitest';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';
describe('participant ballot custody layout', () => {
    it('retains the seed from the attempt lock until the body is retained', () => {
        const value = compileParticipantBallotCustody(completionProfile()),
            body = compileBallotBodyCensus(completionProfile());
        // The marker, score count, body length and key count; at most 20
        // scores and the 8-byte ballot time; the 512-bit seed; 32-byte keys,
        // the 214-byte envelope, 32 coin bytes and the 3,309-byte signature.
        expect(value.prefixBytes).toBe(11n);
        expect(value.maximumBodyRecords).toBe(25n);
        expect(value.phaseBytes.map((entry) => entry.bytes)).toEqual([
            11n + 20n + 8n,
            11n + 20n + 8n + 64n,
            11n + 20n + 8n + 32n * 25n + 214n,
            11n + 20n + 8n + 32n * 25n + 214n + 32n,
            11n + 32n * 25n + 214n + 3309n,
        ]);
        expect(value.maximumStateBytes).toBe(4334n);
        expect(value.maximumEncryptedBodyBytes).toBe(
            body.maximumBodyBytes + 25n * 16n,
        );
    });
});
