import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { deriveCloseProfile } from '#tests/close-response-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';

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
// The participant root prefixes each retained completed message, and the
// close state as a whole, with six bytes.
const entryPrefixBytes = 6n;
// The ballot body census does not depend on the roster.
let ballotBodyCensus: ReturnType<typeof compileBallotBodyCensus> | undefined;

export const compileCloseWireCensus = (participantCount: number) => {
    const profile = deriveCloseProfile(participantCount);
    const participants = BigInt(participantCount);
    const quorum = BigInt(profile.quorum);
    const faultBound = BigInt(profile.faultBound);
    const { signatureBytes } = compileRegistrationEnrollmentCensus();
    const ballot = (ballotBodyCensus ??= compileBallotBodyCensus());
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
        // The completed locked intent, the own response and, for the
        // organizer, the proposal. A signing intent keeps 32 coins instead of
        // its larger signature.
        maximumParticipantStateBytes:
            entryPrefixBytes +
            (entryPrefixBytes + intentBodyBytes + signatureBytes) +
            (entryPrefixBytes + maximumResponseBodyBytes + signatureBytes) +
            (entryPrefixBytes + proposalBodyBytes + signatureBytes),
    };
};
