import { describe, expect, it } from 'vitest';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileParticipantCloseCustody } from '#tests/participant-close-custody-model.js';
import {
    completionProfile,
    deriveSupportedProfile,
} from '#tests/supported-profile-model.js';

// FIPS 204 Table 2: an ML-DSA-65 signature has 3309 bytes.
const signatureBytes = 3309n;
const envelopeBytes = 214n;
const recordBytes = 1n << 20n;

describe('participant close custody layout', () => {
    it('counts the completion roster suffix by hand', () => {
        const value = compileParticipantCloseCustody(completionProfile());
        // Ten participants, three corrupt: thirteen known envelopes and held
        // bodies, nine other responders and twenty-five body records. An
        // event opens with an 11-byte header: kind, record count, serial and
        // payload length. The locked intent is one event without records.
        expect(value.maximumBodyRecords).toBe(25n);
        const delivery = 13n * (11n + 32n) + 13n * (11n + 32n * 26n);
        const events = delivery + 11n + 9n * (11n + 32n);
        const intent = 4n + 202n + signatureBytes;
        const response = 4n + (280n + 20n * 66n - 2n) + signatureBytes;
        const proposal = 4n + 732n + signatureBytes;
        expect(value.collectingBytes).toBe(8n + delivery);
        expect(value.phaseBytes).toEqual([
            { phase: 18, bytes: 8n + 202n + 32n + delivery },
            { phase: 19, bytes: 8n + intent + events },
            {
                phase: 20,
                bytes: 8n + intent + events + 4n + 1598n + 32n,
            },
            {
                phase: 21,
                bytes: 8n + intent + events + response + 732n + 32n,
            },
            { phase: 22, bytes: 8n + intent + events + response + proposal },
        ]);
        expect(value.maximumStateBytes).toBe(24_395n);
        expect(value.maximumEvents).toBe(13n + 13n + 1n + 9n);
        expect(value.maximumRecords).toBe(13n + 13n * 26n + 9n);
    });

    it('bounds the encrypted close records of every roster by its held bodies', () => {
        for (const [participants, options] of [
            [3, 2],
            [4, 2],
            [10, 10],
            [20, 20],
        ]) {
            const profile = deriveSupportedProfile(participants, options);
            const value = compileParticipantCloseCustody(profile);
            const body = compileBallotBodyCensus(profile);
            const faultBound = BigInt(Math.floor((participants - 1) / 3));
            const count = BigInt(participants);
            const bodyRecords =
                (body.maximumBodyBytes + recordBytes - 1n) / recordBytes;
            expect(value.maximumBodyRecords).toBe(bodyRecords);
            const held = count + faultBound;
            const organizerKnown = held + (count - 1n) * 2n * faultBound;
            const envelopeRecord = envelopeBytes + signatureBytes + 16n;
            const bodyBytes = body.maximumBodyBytes + 16n * bodyRecords;
            expect(value.maximumEncryptedRecordBytes).toBe(
                2n * held * envelopeRecord + held * bodyBytes,
            );
            const responsePacket =
                4n + 280n + 2n * count * 66n - 2n + signatureBytes;
            expect(value.maximumOrganizerEncryptedRecordBytes).toBe(
                (organizerKnown + held) * envelopeRecord +
                    held * bodyBytes +
                    (count - 1n) * (responsePacket + 16n),
            );
            // The suffix itself stays far below one copied buffer.
            expect(value.maximumStateBytes).toBeLessThan(1_572_864n);
        }
    });
});
