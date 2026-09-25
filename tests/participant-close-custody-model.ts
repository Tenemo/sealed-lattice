import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

// The close suffix retains the close inputs the participant's state machine
// accepted, in arrival order, so restoration replays them into the same
// state. Each event holds its kind, its record count, the serial that
// locates its records, its payload length and one key per encrypted record:
// a known envelope has one record, a held body its envelope record and its
// body records, and a response the organizer takes one record with the
// packet and the envelopes delivered with it. The participant's own ballot
// references the completed ballot suffix and adds no record, and neither
// does the locked intent, whose event fixes where replay applies it. Before
// an intent the suffix only collects, alongside every ballot phase.
export const compileParticipantCloseCustody = (profile: SupportedProfile) => {
    const wire = compileCloseWireCensus(profile);
    const ballot = compileBallotBodyCensus(profile);
    const { maximumBodyRecords } = compileParticipantBallotCustody(profile);
    const participants = wire.participantCount;
    const keyBytes = 32n;
    const tagBytes = 16n;
    const coinBytes = 32n;
    // Marker and event count.
    const prefixBytes = 4n + 4n;
    const eventBytes = (records: bigint) =>
        1n + 2n + 4n + 4n + keyBytes * records;
    // Delivery adds one event per new known envelope and per held body; only
    // the organizer takes responses, one retained event per other responder.
    const deliveryEventBytes =
        wire.maximumKnownEnvelopes * eventBytes(1n) +
        wire.maximumHeldBodies * eventBytes(1n + maximumBodyRecords);
    const maximumResponseEvents = participants - 1n;
    const organizerEventBytes =
        deliveryEventBytes +
        eventBytes(0n) +
        maximumResponseEvents * eventBytes(1n);
    const responseSigningBytes = 4n + wire.maximumResponseBodyBytes + coinBytes;
    const proposalSigningBytes = wire.proposalBodyBytes + coinBytes;
    const phaseBytes = [
        // The organizer's intent body and coins before its signature.
        {
            phase: 18,
            bytes:
                prefixBytes +
                wire.intentBodyBytes +
                coinBytes +
                deliveryEventBytes,
        },
        // The locked intent; responses arrive only after it.
        {
            phase: 19,
            bytes: prefixBytes + wire.intentPacketBytes + organizerEventBytes,
        },
        {
            phase: 20,
            bytes:
                prefixBytes +
                wire.intentPacketBytes +
                organizerEventBytes +
                responseSigningBytes,
        },
        // The completed response; the organizer's completion transaction also
        // retains its proposal body and coins.
        {
            phase: 21,
            bytes:
                prefixBytes +
                wire.intentPacketBytes +
                organizerEventBytes +
                wire.maximumResponsePacketBytes +
                proposalSigningBytes,
        },
        {
            phase: 22,
            bytes:
                prefixBytes +
                wire.intentPacketBytes +
                organizerEventBytes +
                wire.maximumResponsePacketBytes +
                wire.proposalPacketBytes,
        },
    ];
    const envelopeRecordBytes = wire.submissionBytes + tagBytes;
    const bodyRecordBytes =
        ballot.maximumBodyBytes + tagBytes * maximumBodyRecords;
    // Every retained envelope copy is one known envelope's record or the
    // envelope record of a held body.
    const maximumEncryptedRecordBytes =
        (wire.maximumKnownEnvelopes + wire.maximumHeldBodies) *
            envelopeRecordBytes +
        wire.maximumHeldBodies * bodyRecordBytes;
    const maximumOrganizerEncryptedRecordBytes =
        (wire.maximumOrganizerKnownEnvelopes + wire.maximumHeldBodies) *
            envelopeRecordBytes +
        wire.maximumHeldBodies * bodyRecordBytes +
        maximumResponseEvents * (wire.maximumResponsePacketBytes + tagBytes);
    return {
        prefixBytes,
        maximumBodyRecords,
        maximumEvents:
            wire.maximumKnownEnvelopes +
            wire.maximumHeldBodies +
            1n +
            maximumResponseEvents,
        maximumRecords:
            wire.maximumKnownEnvelopes +
            wire.maximumHeldBodies * (1n + maximumBodyRecords) +
            maximumResponseEvents,
        collectingBytes: prefixBytes + deliveryEventBytes,
        phaseBytes,
        maximumStateBytes: phaseBytes.reduce(
            (maximum, value) => (value.bytes > maximum ? value.bytes : maximum),
            prefixBytes + deliveryEventBytes,
        ),
        maximumEncryptedRecordBytes,
        maximumOrganizerEncryptedRecordBytes,
    };
};
