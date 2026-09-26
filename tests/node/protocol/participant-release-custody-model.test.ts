import { describe, expect, it } from 'vitest';

import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('participant release custody layout', () => {
    it('retains the seed only between the target lock and the body', () => {
        const value = compileParticipantReleaseCustody(completionProfile());
        // The marker, predecessor, target length, body length and key count;
        // the 2,048-byte largest target; the 512-bit seed; 32-byte keys; the
        // envelope of the release context, body length and body identity; 32
        // coin bytes and the 3,309-byte signature.
        const attempt = 13n + 2048n;
        const envelope = 4n + 3n * 64n + 2n + 8n + 64n;
        const records = value.maximumBodyRecords;
        expect(value.prefixBytes).toBe(13n);
        expect(value.envelopeBytes).toBe(envelope);
        expect(records).toBe(
            (value.maximumBodyBytes + (1n << 20n) - 1n) / (1n << 20n),
        );
        expect(value.phaseBytes).toEqual([
            { phase: 25, bytes: attempt },
            { phase: 26, bytes: attempt + 64n },
            { phase: 27, bytes: attempt + 32n * records + envelope },
            { phase: 28, bytes: attempt + 32n * records + envelope + 32n },
            { phase: 29, bytes: attempt + 32n * records + envelope + 3309n },
        ]);
        expect(value.maximumStateBytes).toBe(
            attempt + 32n * records + envelope + 3309n,
        );
        expect(value.maximumEncryptedBodyBytes).toBe(
            value.maximumBodyBytes + 16n * records,
        );
    });
});
