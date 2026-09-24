import { describe, expect, it } from 'vitest';

import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import {
    closeContexts,
    compileCloseWireCensus,
} from '#tests/close-wire-model.js';

// FIPS 204 Table 2: an ML-DSA-65 signature has 3309 bytes.
const signatureBytes = 3309n;
const supportedParticipantCounts = Array.from(
    { length: 18 },
    (_unused, index) => index + 3,
);

describe('close wire census', () => {
    it('matches hand-derived lengths at the smallest, completion and largest rosters', () => {
        // Header 8, purpose 6 + 4 + 30 or 32 ASCII bytes, and two identities
        // of 6 + 64 bytes open each message.
        expect(closeContexts.intent).toHaveLength(30);
        expect(closeContexts.response).toHaveLength(32);
        expect(closeContexts.proposal).toHaveLength(32);
        for (const [participants, quorum, response, proposal] of [
            [3, 3, 190 + 70 + 8 + 10 + 6 * 66, 190 + 70 + 10 + 3 * 66],
            [10, 7, 190 + 70 + 8 + 10 + 20 * 66, 190 + 70 + 10 + 7 * 66],
            [20, 14, 2918, 1194],
        ]) {
            const value = compileCloseWireCensus(participants);
            expect(value.closeQuorum).toBe(BigInt(quorum));
            expect(value.intentBodyBytes).toBe(188n + 14n);
            expect(value.maximumResponseBodyBytes).toBe(BigInt(response));
            expect(value.proposalBodyBytes).toBe(BigInt(proposal));
            expect(value.intentPacketBytes).toBe(4n + 202n + signatureBytes);
        }
        expect(compileCloseWireCensus(3).minimumResponseBodyBytes).toBe(
            190n + 70n + 8n + 10n,
        );
    });

    it('bounds the barrier closure by envelopes and usable bodies only', () => {
        const ballot = compileBallotBodyCensus();
        expect(ballot.envelopeBytes).toBe(214n);
        for (const participants of supportedParticipantCounts) {
            const value = compileCloseWireCensus(participants);
            const faultBound = BigInt(Math.floor((participants - 1) / 3));
            const quorum = BigInt(participants) - faultBound;
            expect(value.maximumResponseEntries).toBe(
                2n * BigInt(participants),
            );
            expect(value.maximumUnionEnvelopes).toBe(
                BigInt(participants) - faultBound + faultBound * 2n * quorum,
            );
            // The union never exceeds the q used responses' entries.
            expect(value.maximumUnionEnvelopes).toBeLessThanOrEqual(
                quorum * value.maximumResponseEntries,
            );
            expect(value.submissionBytes).toBe(214n + signatureBytes);
            expect(value.maximumRosterListedEnvelopes).toBe(
                BigInt(participants) -
                    faultBound +
                    faultBound * 2n * BigInt(participants),
            );
            expect(value.maximumRosterCloseMetadataBytes).toBe(
                value.intentPacketBytes +
                    BigInt(participants) * value.maximumResponsePacketBytes +
                    value.proposalPacketBytes +
                    value.maximumRosterListedEnvelopes * value.submissionBytes,
            );
            expect(value.maximumBarrierBodyBytes).toBe(
                BigInt(participants) * ballot.maximumBodyBytes,
            );
            expect(value.barrierSignatureVerifications).toBe(
                quorum + 2n + value.maximumUnionEnvelopes,
            );
            expect(value.maximumHeldBodies).toBe(
                BigInt(participants) + faultBound,
            );
            // One body per honest slot; two before and two after the intent
            // lock for each corrupt slot.
            expect(value.maximumReceivedBodies).toBe(
                BigInt(participants) - faultBound + 4n * faultBound,
            );
            expect(value.maximumReceivedBodyBytes).toBe(
                value.maximumReceivedBodies * ballot.maximumSignedBodyBytes,
            );
            expect(value.maximumParticipantStateBytes).toBe(
                6n +
                    (6n + 202n + signatureBytes) +
                    (6n + value.maximumResponseBodyBytes + signatureBytes) +
                    (6n + value.proposalBodyBytes + signatureBytes),
            );
        }
        // Conflicting corrupt envelopes add only envelope metadata: at the
        // completion roster, 3 * 2 * 7 of them cost far less than one body.
        const completion = compileCloseWireCensus(10);
        expect(completion.maximumUnionEnvelopes).toBe(7n + 42n);
        expect(42n * completion.submissionBytes).toBeLessThan(
            ballot.maximumBodyBytes,
        );
    });
});
