import { describe, expect, it } from 'vitest';

import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('participant release custody layout', () => {
    it('retains the seed only between the target lock and the body', () => {
        const value = compileParticipantReleaseCustody(completionProfile());
        // The marker, predecessor, target length, body length and key count;
        // the 2,048-byte largest target; the 512-bit seed; 32-byte keys; the
        // envelope of the release context, body length and body identity; 32
        // coin bytes and the 3,309-byte signature. The largest release body
        // fills 16 records of 1 MiB; the runtime bounds test checks its
        // length against the participant module's.
        const attempt = 13n + 2048n;
        const envelope = 4n + 3n * 64n + 2n + 8n + 64n;
        const records = 16n;
        expect(value.prefixBytes).toBe(13n);
        expect(value.envelopeBytes).toBe(envelope);
        expect(value.maximumBodyBytes).toBe(15_830_066n);
        expect(value.maximumBodyRecords).toBe(records);
        expect(value.phaseBytes).toEqual([
            { phase: 25, bytes: attempt },
            { phase: 26, bytes: attempt + 64n },
            { phase: 27, bytes: attempt + 32n * records + envelope },
            { phase: 28, bytes: attempt + 32n * records + envelope + 32n },
            { phase: 29, bytes: attempt + 32n * records + envelope + 3309n },
        ]);
        expect(value.maximumStateBytes).toBe(6152n);
        expect(value.maximumEncryptedBodyBytes).toBe(
            15_830_066n + 16n * records,
        );
    });
});
