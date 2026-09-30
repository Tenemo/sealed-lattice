import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { deriveCloseProfile } from '#tests/close-response-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

// Canonical tuple framing: an eight-byte tuple header, then a two-byte type
// and a four-byte length for each item. ASCII and byte-string values also
// carry a four-byte inner length.
const tupleHeaderBytes = 8n;
const itemHeaderBytes = 6n;
const innerLengthBytes = 4n;
const identityBytes = 64n;
const identityItemBytes = itemHeaderBytes + identityBytes;
const asciiItemBytes = (value: string) =>
    itemHeaderBytes + innerLengthBytes + BigInt(Buffer.byteLength(value));
const unsignedItemBytes = (width: bigint) => itemHeaderBytes + width;
const byteStringItemBytes = (length: bigint) =>
    itemHeaderBytes + innerLengthBytes + length;

export const closeContexts = {
    intent: 'sealed-lattice/close-intent/v1',
    response: 'sealed-lattice/close-response/v1',
    proposal: 'sealed-lattice/close-proposal/v1',
} as const;

// A listed entry is a two-byte author position and an envelope identity; a
// proposal entry is a two-byte responder position and a response identity.
const entryBytes = 2n + identityBytes;
const maximumListedEnvelopesPerSlot = 2n;
export const compileCloseWireCensus = (supportedProfile: SupportedProfile) => {
    const participantCount = supportedProfile.participantCount;
    const profile = deriveCloseProfile(participantCount);
    const participants = BigInt(participantCount);
    const quorum = BigInt(profile.quorum);
    const faultBound = BigInt(profile.faultBound);
    const { signatureBytes } = compileRegistrationEnrollmentCensus();
    const ballot = compileBallotBodyCensus(supportedProfile);
    // Purpose, poll identity and inventory identity open every close message.
    const prefixBytes = (purpose: string) =>
        tupleHeaderBytes + asciiItemBytes(purpose) + 2n * identityItemBytes;
    const intentBodyBytes =
        prefixBytes(closeContexts.intent) + unsignedItemBytes(8n);
    const responseBodyBytes = (entries: bigint) =>
        prefixBytes(closeContexts.response) +
        identityItemBytes +
        unsignedItemBytes(2n) +
        byteStringItemBytes(entries * entryBytes);
    const maximumResponseEntries = maximumListedEnvelopesPerSlot * participants;
    const maximumResponseBodyBytes = responseBodyBytes(maximumResponseEntries);
    const proposalBodyBytes =
        prefixBytes(closeContexts.proposal) +
        identityItemBytes +
        byteStringItemBytes(quorum * entryBytes);
    const packetBytes = (body: bigint) => 4n + body + signatureBytes;
    // An honest author signs one envelope. Each of the q used responses lists
    // at most two envelopes for one corrupt slot.
    const maximumUnionEnvelopes =
        participants -
        faultBound +
        faultBound * maximumListedEnvelopesPerSlot * quorum;
    const submissionBytes = ballot.envelopeBytes + signatureBytes;
    // A participant holds at most two complete bodies for one slot. Its
    // intent lock discards late bodies and refuses later ones, so a corrupt
    // slot can deliver two before the lock and two on-time bodies after it;
    // an honest author's one body arrives once.
    const maximumHeldBodies =
        participants - faultBound + faultBound * maximumListedEnvelopesPerSlot;
    const maximumReceivedBodies =
        participants -
        faultBound +
        faultBound * 2n * maximumListedEnvelopesPerSlot;
    // Delivery adds a new envelope to a slot only while fewer than two are
    // known, and every held body is known. The organizer alone also learns
    // the envelopes listed by the first response of each other responder, at
    // most two for each corrupt slot.
    const maximumKnownEnvelopes = maximumHeldBodies;
    const maximumOrganizerKnownEnvelopes =
        maximumKnownEnvelopes +
        (participants - 1n) * faultBound * maximumListedEnvelopesPerSlot;
    // Every participant's response may list two envelopes for a corrupt slot.
    const maximumRosterListedEnvelopes =
        participants -
        faultBound +
        faultBound * maximumListedEnvelopesPerSlot * participants;
    return {
        participantCount: participants,
        closeQuorum: quorum,
        intentBodyBytes,
        minimumResponseBodyBytes: responseBodyBytes(0n),
        maximumResponseEntries,
        maximumResponseBodyBytes,
        proposalBodyBytes,
        intentPacketBytes: packetBytes(intentBodyBytes),
        maximumResponsePacketBytes: packetBytes(maximumResponseBodyBytes),
        proposalPacketBytes: packetBytes(proposalBodyBytes),
        submissionBytes,
        maximumUnionEnvelopes,
        maximumUsableBodies: participants,
        // The archived closure of one barrier: the intent, the used responses,
        // the proposal and every listed envelope. Only usable slots need
        // their bodies.
        maximumBarrierMetadataBytes:
            packetBytes(intentBodyBytes) +
            quorum * packetBytes(maximumResponseBodyBytes) +
            packetBytes(proposalBodyBytes) +
            maximumUnionEnvelopes * submissionBytes,
        maximumBarrierBodyBytes: participants * ballot.maximumBodyBytes,
        // Every participant's response and every envelope any of them lists.
        maximumRosterCloseMetadataBytes:
            packetBytes(intentBodyBytes) +
            participants * packetBytes(maximumResponseBodyBytes) +
            packetBytes(proposalBodyBytes) +
            maximumRosterListedEnvelopes * submissionBytes,
        maximumRosterListedEnvelopes,
        // One target signer checks the intent, each used response, the
        // proposal and each listed envelope.
        barrierSignatureVerifications: 1n + quorum + 1n + maximumUnionEnvelopes,
        maximumHeldBodies,
        maximumHeldBodyBytes: maximumHeldBodies * ballot.maximumSignedBodyBytes,
        maximumReceivedBodies,
        maximumReceivedBodyBytes:
            maximumReceivedBodies * ballot.maximumSignedBodyBytes,
        maximumKnownEnvelopes,
        maximumOrganizerKnownEnvelopes,
        // The organizer publishes with its intent the identities of the
        // bodies it held at its lock. Each other responder publishes with its
        // response a copy of every envelope it lists and forwards the body of
        // each other slot it lists alone that the held list lacks.
        maximumOrganizerHeldListBytes: maximumHeldBodies * identityBytes,
        maximumListedCopyBytes: maximumResponseEntries * submissionBytes,
        maximumForwardedBodies: participants - 1n,
        maximumForwardedBodyBytes:
            (participants - 1n) * ballot.maximumBodyBytes,
    };
};
