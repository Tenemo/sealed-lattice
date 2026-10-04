import {
    ballotWorkInput,
    isSignedBallot,
    readBallotBody,
    resumeBallot,
    retainedBallotRecords,
    submissionDirectory,
    submissionPointer,
} from './ballot.js';
import type { BallotSession } from './ballot.js';
import type { ParticipantProfile } from './bounds.js';
import {
    concatenate,
    equalBytes,
    fromHexadecimal,
    hexadecimal,
    readUnsigned16,
    readUnsigned32,
    readUnsigned64,
    unsigned32,
    unsigned64,
} from './bytes.js';
import {
    closeEventKind,
    closePhase,
    closeRecordAssociatedData,
    closeRecordInventory,
    closeRecordLengths,
    collectingCloseState,
    completedClosePhase,
    decodeCloseState,
    encodeCloseState,
} from './close-state.js';
import type { CloseEvent, CloseState } from './close-state.js';
import { PublicInputFailure, sessionInput } from './context.js';
import type { ProfileContext, PublicProfileContext } from './context.js';
import { contributionRecords } from './contribution.js';
import type { ParticipantSession } from './contribution.js';
import { openDelivery } from './delivery.js';
import type { Delivery } from './delivery.js';
import { custodyIdentity, custodyPurpose } from './identity.js';
import { readKernel } from './kernel.js';
import {
    publishChunk,
    publishRecord,
    readPublic,
    streamPublic,
} from './public.js';
import type { PublicRelay } from './public.js';
import { openRecord, recordContext, sealRecord } from './records.js';
import type { RecordContext } from './records.js';
import { commitRoot, dataRecordInventory } from './root.js';
import { snapshotParticipant } from './storage.js';

// A participant's close work. Each visit restores the module's close state
// from the retained log, then accepts the deliveries it is given, locks the
// organizer's intent, responds, and for the organizer takes the other
// responses and proposes. Every accepted input commits its event, records and
// root together; a refused public input changes nothing and leaves the
// participant where it was.

const coinBytes = 32;
const identityBytes = 64;
const listedEntryBytes = 2 + identityBytes;
// The envelope's author position, ballot time and body length.
const envelopeAuthorOffset = 132;
const envelopeTimeOffset = 134;
const envelopeLengthOffset = 142;
// A response body ends with its responder and its listing: an unsigned item
// of six header bytes and two value bytes, then a byte-string item of six
// header bytes and a four-byte inner length before the entries.
const responderFromListing = 6 + 4 + 2;
export const closeDirectory = 'close/';
// The organizer's copies of the close records its proposal depends on, each
// under its own identity.
const closureDirectory = closeDirectory + 'closure/';
export const closureResponseRoute = (identity: Uint8Array) =>
    closureDirectory + 'response-' + hexadecimal(identity) + '.bin';
export const closureSubmissionRoute = (identity: Uint8Array) =>
    closureDirectory + 'submission-' + hexadecimal(identity) + '.bin';
export const closureBodyRoute = (identity: Uint8Array) =>
    closureDirectory + 'body-' + hexadecimal(identity) + '.bin';
// The identities of the bodies the organizer held when it locked its intent,
// published with the intent, and each responder's copies of the envelopes
// its response lists and of the bodies it forwards to the organizer.
const organizerHeldRoute = closeDirectory + 'held.bin';
const listedCopiesRoute = (position: number) =>
    closeDirectory + 'response-' + String(position) + '-submissions.bin';
const forwardedBodyRoute = (position: number, identity: Uint8Array) =>
    closeDirectory +
    'response-' +
    String(position) +
    '-body-' +
    hexadecimal(identity) +
    '.bin';

// The most entries a response lists, two envelopes for each slot, which also
// bounds the bodies the organizer can hold.
const maximumListedEntries = ({ close }: ParticipantProfile) =>
    (close.maximumResponseBodyBytes - close.minimumResponseBodyBytes) /
    listedEntryBytes;

export type CloseRequest = Readonly<{
    // The organizer's close time in Unix milliseconds, only before an intent.
    closeTime?: bigint;
}>;

// The close time a request supplies, or undefined when it is malformed.
export const parseCloseRequest = (
    parameters: Readonly<Record<string, unknown>>,
): CloseRequest | undefined => {
    const { closeTime } = parameters;
    if (closeTime === undefined) return {};
    return typeof closeTime === 'number' &&
        Number.isSafeInteger(closeTime) &&
        closeTime >= 0
        ? { closeTime: BigInt(closeTime) }
        : undefined;
};

// What replay and delivery learned of a retained submission.
type Submission = Readonly<{
    author: number;
    identity: Uint8Array;
    ballotTime: bigint;
}>;

export type CloseSession = {
    readonly participant: ParticipantSession;
    readonly records: RecordContext;
    readonly organizer: boolean;
    readonly ballot: BallotSession | undefined;
    state: CloseState;
    // The submission of each own or held event and the responder of each
    // taken response, by serial, and every envelope identity the module
    // knows.
    readonly submissions: Map<number, Submission>;
    readonly responders: Map<number, number>;
    readonly known: Set<string>;
};

type AddedRecord = Readonly<{
    serial: number;
    index: number;
    key: Uint8Array;
    ciphertext: Uint8Array;
}>;

const tryCloseCommand = (
    context: ProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const { kernel } = context;
    sessionInput(context, input);
    if (
        kernel.participant_close_command(operation, argument, input.length) !==
        0
    )
        return undefined;
    return readKernel(
        kernel,
        kernel.contribution_output_pointer(),
        kernel.contribution_output_length(),
    );
};

const closeCommand = (
    context: ProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const output = tryCloseCommand(context, operation, argument, input);
    if (output === undefined)
        throw new Error(
            'The close module refused operation ' + String(operation) + '.',
        );
    return output;
};

const packet = (body: Uint8Array, signature: Uint8Array) =>
    concatenate(unsigned32(body.length), body, signature);

const generationOf = (session: CloseSession) =>
    session.participant.root.head.generation;

const nextSerial = (state: CloseState) =>
    state.events.length === 0
        ? 0
        : state.events[state.events.length - 1].serial + 1;

const recordCount = (state: CloseState) =>
    state.events.reduce((total, event) => total + event.keys.length, 0);

// Decodes the retained close log and the signed ballot it may reference.
// Every listed record must be stored and nothing else.
export const resumeClose = async (
    participant: ParticipantSession,
    organizer: boolean,
): Promise<CloseSession> => {
    const { context, root } = participant;
    const bytes = root.manifest.suffixes.close;
    if (root.head.generation < 12 || bytes === undefined)
        throw new Error('No close log is retained.');
    const records = await recordContext(participant);
    const state = decodeCloseState(
        context.profile,
        root.head.generation,
        organizer,
        bytes,
    );
    const snapshot = await snapshotParticipant(context.database);
    if (snapshot.counts.close !== recordCount(state))
        throw new Error('The close records changed.');
    const ballot = await resumeBallot(participant);
    return {
        participant,
        records,
        organizer,
        ballot:
            ballot !== undefined && isSignedBallot(ballot) ? ballot : undefined,
        state,
        submissions: new Map(),
        responders: new Map(),
        known: new Set(),
    };
};

// Whether nothing remains for this participant's close.
export const isCloseComplete = (session: CloseSession) =>
    generationOf(session) >= completedClosePhase(session.organizer);

const openCloseRecord = (
    session: CloseSession,
    event: CloseEvent,
    index: number,
) => {
    const { context } = session.participant;
    const length = closeRecordLengths(context.profile, event)[index];
    return openRecord(
        context.database,
        'close',
        [event.serial, index],
        {
            key: event.keys[index],
            additionalData: closeRecordAssociatedData(
                session.records,
                event,
                index,
                length,
            ),
        },
        length,
    );
};

const sealCloseRecord = async (
    session: CloseSession,
    event: Readonly<{ kind: number; serial: number }>,
    index: number,
    bytes: Uint8Array,
): Promise<AddedRecord> => ({
    serial: event.serial,
    index,
    ...(await sealRecord(
        closeRecordAssociatedData(session.records, event, index, bytes.length),
        bytes,
    )),
});

type CloseTransition = Readonly<{
    generation: number;
    state: CloseState;
    added?: readonly AddedRecord[];
    // Serials whose records leave with the events that listed them.
    retired?: readonly number[];
}>;

const commitClose = async (
    session: CloseSession,
    transition: CloseTransition,
) => {
    const { participant } = session;
    const { context, root } = participant;
    const { profile } = context;
    const encoded = encodeCloseState(
        transition.generation,
        session.organizer,
        transition.state,
    );
    if (encoded.length > profile.close.maximumStateBytes)
        throw new Error('The close state exceeds its bound.');
    participant.root = await commitRoot(context, root, {
        generation: transition.generation,
        manifest: {
            ...root.manifest,
            suffixes: { ...root.manifest.suffixes, close: encoded },
        },
        predecessorRecords: [
            ...dataRecordInventory(root.manifest),
            ...contributionRecords(participant),
            ...retainedBallotRecords(participant, session.records),
            ...closeRecordInventory(profile, session.records, session.state),
        ],
        write: (transaction) => {
            const store = transaction.objectStore('close');
            for (const serial of transition.retired ?? [])
                store.delete(
                    IDBKeyRange.bound([serial], [serial + 1], false, true),
                );
            for (const record of transition.added ?? [])
                store.add(new Blob([new Uint8Array(record.ciphertext)]), [
                    record.serial,
                    record.index,
                ]);
        },
    });
    session.state = transition.state;
    for (const record of transition.added ?? []) {
        const event = transition.state.events.find(
            (value) => value.serial === record.serial,
        );
        if (event === undefined)
            throw new Error('An added close record has no event.');
        (await openCloseRecord(session, event, record.index)).fill(0);
    }
};

// The submission identity the module reports for an envelope, which
// listings and wanted bodies name; undefined for bytes that are not one.
const envelopeIdentity = (context: ProfileContext, submission: Uint8Array) =>
    tryCloseCommand(
        context,
        14,
        0,
        submission.subarray(0, context.profile.ballot.envelopeBytes),
    );

const namesEnvelope = (
    context: ProfileContext,
    submission: Uint8Array,
    identity: Uint8Array,
) => {
    const value = envelopeIdentity(context, submission);
    return value !== undefined && equalBytes(value, identity);
};

// The identity of the envelope a retained submission begins with, derived
// without the close module, so that a visit that restores no setup can name
// what its custody holds.
const custodyEnvelopeIdentity = (
    context: PublicProfileContext,
    submission: Uint8Array,
) =>
    custodyIdentity(
        context.kernel,
        custodyPurpose.envelope,
        submission.subarray(0, context.profile.ballot.envelopeBytes),
    );

// Whether a submission is the listed author's envelope with the listed
// identity, followed by a signature. Only the listed envelope's bytes have
// its identity, so a copy selected here is the one the barrier verifier then
// authenticates.
export const isListedSubmission = (
    context: PublicProfileContext,
    submission: Uint8Array,
    author: number,
    identity: Uint8Array,
) =>
    submission.length === context.profile.close.submissionBytes &&
    readUnsigned16(submission, envelopeAuthorOffset) === author &&
    equalBytes(custodyEnvelopeIdentity(context, submission), identity);

// Whether bytes frame one response packet of the profile.
export const isResponsePacket = (
    profile: ParticipantProfile,
    bytes: Uint8Array,
) => {
    if (bytes.length < 4) return false;
    const length = readUnsigned32(bytes, 0);
    return (
        length >= profile.close.minimumResponseBodyBytes &&
        length <= profile.close.maximumResponseBodyBytes &&
        bytes.length === 4 + length + profile.registration.signatureBytes
    );
};

// A response packet's identity, by which a proposal names it: the identity
// of its signed body.
export const responseIdentity = (
    context: PublicProfileContext,
    response: Uint8Array,
) =>
    custodyIdentity(
        context.kernel,
        custodyPurpose.closeResponse,
        response.subarray(4, 4 + readUnsigned32(response, 0)),
    );

// The author and envelope identity of each entry a response packet lists.
export const responseListing = (
    profile: ParticipantProfile,
    response: Uint8Array,
) => {
    const end = 4 + readUnsigned32(response, 0);
    const entries: { author: number; identity: Uint8Array }[] = [];
    for (
        let offset = 4 + profile.close.minimumResponseBodyBytes;
        offset + listedEntryBytes <= end;
        offset += listedEntryBytes
    )
        entries.push({
            author: readUnsigned16(response, offset),
            identity: response.slice(offset + 2, offset + listedEntryBytes),
        });
    return entries;
};

// The responders and response identities that end a proposal packet's body.
export const proposalResponses = (
    profile: ParticipantProfile,
    proposal: Uint8Array,
) => {
    const { proposalBodyBytes, quorum } = profile.close;
    return Array.from({ length: quorum }, (_unused, index) => {
        const offset =
            4 + proposalBodyBytes - (quorum - index) * listedEntryBytes;
        return {
            responder: readUnsigned16(proposal, offset),
            identity: proposal.slice(offset + 2, offset + listedEntryBytes),
        };
    });
};

// Supplies only a body named by this root's authenticated custody. The
// caller still runs its owning public verifiers. A missing listed record is
// state loss, never a reason to fetch a replacement from the relay.
export const heldBallotBody = async (
    session: CloseSession,
    author: number,
    identity: Uint8Array,
) => {
    const { context } = session.participant;
    const { ballot } = session;
    if (
        ballot !== undefined &&
        author === context.position &&
        equalBytes(
            custodyEnvelopeIdentity(context, ballot.state.envelope),
            identity,
        )
    )
        return async (consume: (bytes: Uint8Array) => void | Promise<void>) => {
            await readBallotBody(ballot, consume);
            return ballot.state.bodyLength;
        };
    for (const event of session.state.events) {
        if (event.kind !== closeEventKind.held) continue;
        const submission = await openCloseRecord(session, event, 0);
        const matches =
            readUnsigned16(submission, envelopeAuthorOffset) === author &&
            equalBytes(custodyEnvelopeIdentity(context, submission), identity);
        if (
            readUnsigned64(submission, envelopeLengthOffset) !==
            BigInt(event.length)
        )
            throw new Error('A held body changed its length.');
        if (!matches) continue;
        return async (consume: (bytes: Uint8Array) => void | Promise<void>) => {
            let length = 0;
            for (let index = 1; index < event.keys.length; index++) {
                const bytes = await openCloseRecord(session, event, index);
                try {
                    await consume(bytes);
                    length += bytes.length;
                } finally {
                    bytes.fill(0);
                }
            }
            if (length !== event.length)
                throw new Error('The held ballot body is incomplete.');
            return length;
        };
    }
    return undefined;
};

const learnSubmission = (
    session: CloseSession,
    serial: number,
    envelope: Uint8Array,
) => {
    const identity = envelopeIdentity(session.participant.context, envelope);
    if (identity === undefined)
        throw new Error('An accepted envelope has no identity.');
    session.submissions.set(serial, {
        author: readUnsigned16(envelope, envelopeAuthorOffset),
        identity,
        ballotTime: readUnsigned64(envelope, envelopeTimeOffset),
    });
    session.known.add(hexadecimal(identity));
};

// A taken response names its responder, and the envelopes delivered with it
// join the known ones.
const learnResponse = (
    session: CloseSession,
    serial: number,
    record: Uint8Array,
) => {
    const { context } = session.participant;
    const { close, registration } = context.profile;
    const length = readUnsigned32(record, 0);
    session.responders.set(
        serial,
        readUnsigned16(
            record,
            4 + close.minimumResponseBodyBytes - responderFromListing,
        ),
    );
    for (
        let offset = 4 + length + registration.signatureBytes;
        offset < record.length;
        offset += close.submissionBytes
    ) {
        const identity = envelopeIdentity(context, record.subarray(offset));
        if (identity === undefined)
            throw new Error('An accepted envelope has no identity.');
        session.known.add(hexadecimal(identity));
    }
};

const ownSubmission = (ballot: BallotSession) =>
    concatenate(ballot.state.envelope, ballot.state.signature);

// Every submission this root's custody holds, by envelope identity: the own
// signed ballot, each held envelope and each envelope delivered with a taken
// response.
export const heldSubmissions = async (session: CloseSession) => {
    const { context } = session.participant;
    const { close, registration } = context.profile;
    const held = new Map<string, Uint8Array>();
    const hold = (submission: Uint8Array) =>
        held.set(
            hexadecimal(custodyEnvelopeIdentity(context, submission)),
            submission,
        );
    if (session.ballot !== undefined) hold(ownSubmission(session.ballot));
    for (const event of session.state.events)
        if (event.kind === closeEventKind.held)
            hold(await openCloseRecord(session, event, 0));
        else if (event.kind === closeEventKind.response) {
            const record = await openCloseRecord(session, event, 0);
            for (
                let offset =
                    4 + readUnsigned32(record, 0) + registration.signatureBytes;
                offset < record.length;
                offset += close.submissionBytes
            )
                hold(record.slice(offset, offset + close.submissionBytes));
        }
    return held;
};

// Every response packet this root's custody holds, by responder: the own
// signed response and, for the organizer, each response it took.
export const heldResponses = async (session: CloseSession) => {
    const { profile } = session.participant.context;
    const held = new Map<number, Uint8Array>();
    if (generationOf(session) >= closePhase.responded)
        held.set(session.records.position, session.state.responsePacket);
    for (const event of session.state.events) {
        if (event.kind !== closeEventKind.response) continue;
        const record = await openCloseRecord(session, event, 0);
        held.set(
            readUnsigned16(
                record,
                4 +
                    profile.close.minimumResponseBodyBytes -
                    responderFromListing,
            ),
            record.slice(
                0,
                4 +
                    readUnsigned32(record, 0) +
                    profile.registration.signatureBytes,
            ),
        );
    }
    return held;
};

// Replays one retained event. It was accepted on arrival, so a refusal means
// the retained state changed.
const replayEvent = async (session: CloseSession, event: CloseEvent) => {
    const { context } = session.participant;
    switch (event.kind) {
        case closeEventKind.own: {
            const { ballot } = session;
            if (ballot === undefined)
                throw new Error('The close log names an unsigned ballot.');
            closeCommand(context, 3, 0, ownSubmission(ballot));
            await readBallotBody(ballot, (bytes) => {
                closeCommand(context, 4, 0, bytes);
            });
            closeCommand(context, 5);
            learnSubmission(session, event.serial, ballot.state.envelope);
            break;
        }
        case closeEventKind.held: {
            const submission = await openCloseRecord(session, event, 0);
            if (
                readUnsigned64(submission, envelopeLengthOffset) !==
                BigInt(event.length)
            )
                throw new Error('A held body changed its length.');
            closeCommand(context, 3, 0, submission);
            for (let index = 1; index < event.keys.length; index++) {
                const bytes = await openCloseRecord(session, event, index);
                try {
                    closeCommand(context, 4, 0, bytes);
                } finally {
                    bytes.fill(0);
                }
            }
            closeCommand(context, 5);
            learnSubmission(session, event.serial, submission);
            break;
        }
        case closeEventKind.lock:
            closeCommand(context, 2, 0, session.state.intentPacket);
            break;
        case closeEventKind.response: {
            const record = await openCloseRecord(session, event, 0);
            closeCommand(context, 7, 0, record);
            learnResponse(session, event.serial, record);
            break;
        }
        default:
            throw new Error('The close log names an unknown event.');
    }
};

// Starts the module's close work, restores the purposes the credential
// completed, and replays the log. The owning setup verifier must have
// verified the complete setup in this instance first. A completed proposal
// leaves no close work to start.
const startCloseWork = async (session: CloseSession) => {
    const { participant } = session;
    const { context } = participant;
    const generation = generationOf(session);
    closeCommand(
        context,
        0,
        0,
        await ballotWorkInput(participant, session.records.inventory),
    );
    if (session.ballot !== undefined)
        closeCommand(context, 11, 0, ownSubmission(session.ballot));
    if (session.organizer && generation >= closePhase.locked)
        closeCommand(context, 10, 0, session.state.intentPacket);
    for (const event of session.state.events) await replayEvent(session, event);
    if (generation >= closePhase.responded)
        closeCommand(context, 10, 1, session.state.responsePacket);
};

// Restores the authority a completed close retains without replaying its
// log: the own signed ballot, the organizer's intent, the locked intent, the
// signed response and the organizer's proposal. The owning setup verifier
// must have verified the complete setup in this instance first.
export const restoreCompletedClose = async (session: CloseSession) => {
    const { participant, state } = session;
    const { context } = participant;
    if (!isCloseComplete(session))
        throw new Error('The close is not complete.');
    closeCommand(
        context,
        0,
        0,
        await ballotWorkInput(participant, session.records.inventory),
    );
    if (session.ballot !== undefined)
        closeCommand(context, 11, 0, ownSubmission(session.ballot));
    if (session.organizer) closeCommand(context, 10, 0, state.intentPacket);
    closeCommand(context, 2, 0, state.intentPacket);
    closeCommand(context, 10, 1, state.responsePacket);
    if (session.organizer) closeCommand(context, 10, 2, state.proposalPacket);
};

// The close records the root lists.
export const completedCloseRecords = (session: CloseSession) =>
    closeRecordInventory(
        session.participant.context.profile,
        session.records,
        session.state,
    );

const appendEvent = (
    session: CloseSession,
    event: CloseEvent,
    added: readonly AddedRecord[] = [],
) =>
    commitClose(session, {
        generation: generationOf(session),
        state: { ...session.state, events: [...session.state.events, event] },
        added,
    });

// Delivers the own signed ballot once, from the ballot suffix.
const deliverOwnBallot = async (session: CloseSession) => {
    const { ballot } = session;
    if (
        ballot === undefined ||
        session.state.events.some((event) => event.kind === closeEventKind.own)
    )
        return;
    const { context } = session.participant;
    // A late own ballot after the lock is refused and never listed.
    if (tryCloseCommand(context, 3, 0, ownSubmission(ballot)) === undefined)
        return;
    await readBallotBody(ballot, (bytes) => {
        closeCommand(context, 4, 0, bytes);
    });
    closeCommand(context, 5);
    const serial = nextSerial(session.state);
    await appendEvent(session, {
        kind: closeEventKind.own,
        serial,
        length: 0,
        keys: [],
    });
    learnSubmission(session, serial, ballot.state.envelope);
};

// The envelope and signature published under an author and envelope
// identity, or undefined when the relay lacks them. The caller checks that
// the envelope has that identity.
export const readPublishedSubmission = async (
    profile: ParticipantProfile,
    relay: PublicRelay,
    author: number,
    identity: Uint8Array,
) => {
    const directory = submissionDirectory(author, identity);
    try {
        const submission = concatenate(
            await readPublic(
                relay,
                directory + 'envelope.bin',
                profile.ballot.envelopeBytes,
            ),
            await readPublic(
                relay,
                directory + 'signature.bin',
                profile.registration.signatureBytes,
            ),
        );
        return submission.length === profile.close.submissionBytes
            ? submission
            : undefined;
    } catch (error) {
        if (error instanceof PublicInputFailure) return undefined;
        throw error;
    }
};

// The submission an author's pointer names, or undefined when the relay lacks
// it or serves one that is not that author's envelope with that identity. The
// pointer only proposes an identity; the module authenticates what it names.
const readAnnouncedSubmission = async (
    context: ProfileContext,
    relay: PublicRelay,
    author: number,
) => {
    let identity: Uint8Array;
    try {
        identity = await readPublic(relay, submissionPointer(author), 64);
    } catch (error) {
        if (error instanceof PublicInputFailure) return undefined;
        throw error;
    }
    const submission =
        identity.length === 64
            ? await readPublishedSubmission(
                  context.profile,
                  relay,
                  author,
                  identity,
              )
            : undefined;
    return submission !== undefined &&
        readUnsigned16(submission, envelopeAuthorOffset) === author &&
        namesEnvelope(context, submission, identity)
        ? submission
        : undefined;
};

// Delivers a submission with its body from a route, sealing each body
// record as it passes the module. A refused, late or incomplete submission
// changes nothing. Returns whether the module accepted the body.
const deliverBody = async (
    session: CloseSession,
    relay: PublicRelay,
    submission: Uint8Array,
    route: string,
) => {
    const { context } = session.participant;
    const { profile } = context;
    if (tryCloseCommand(context, 3, 0, submission) === undefined) return false;
    const length = Number(readUnsigned64(submission, envelopeLengthOffset));
    const { recordBytes, minimumBodyBytes, maximumBodyBytes } = profile.ballot;
    const event = {
        kind: closeEventKind.held,
        serial: nextSerial(session.state),
    };
    const added = [await sealCloseRecord(session, event, 0, submission)];
    let accepted = length >= minimumBodyBytes && length <= maximumBodyBytes;
    const pending = new Uint8Array(recordBytes);
    let used = 0;
    const flush = async () => {
        const bytes = pending.slice(0, used);
        used = 0;
        try {
            if (tryCloseCommand(context, 4, 0, bytes) === undefined)
                accepted = false;
            else
                added.push(
                    await sealCloseRecord(session, event, added.length, bytes),
                );
        } finally {
            bytes.fill(0);
        }
    };
    try {
        if (accepted)
            await streamPublic(relay, route, length, async (bytes) => {
                for (let start = 0; start < bytes.length && accepted;) {
                    const count = Math.min(
                        bytes.length - start,
                        recordBytes - used,
                    );
                    pending.set(bytes.subarray(start, start + count), used);
                    start += count;
                    used += count;
                    if (used === recordBytes) await flush();
                }
            });
        if (used > 0 && accepted) await flush();
    } catch (error) {
        if (!(error instanceof PublicInputFailure)) throw error;
        accepted = false;
    } finally {
        pending.fill(0);
    }
    // Finishing also clears a refused or incomplete body's authentication.
    if (tryCloseCommand(context, 5) === undefined || !accepted) return false;
    await appendEvent(
        session,
        { ...event, length, keys: added.map((record) => record.key) },
        added,
    );
    learnSubmission(session, event.serial, submission);
    return true;
};

// Delivers a published ballot with its body from its author's route. An
// expected identity restricts delivery to that envelope; otherwise the
// author's pointer names it.
const deliverBallot = async (
    session: CloseSession,
    relay: PublicRelay,
    author: number,
    expected?: Uint8Array,
) => {
    const { context } = session.participant;
    const submission =
        expected === undefined
            ? await readAnnouncedSubmission(context, relay, author)
            : await readPublishedSubmission(
                  context.profile,
                  relay,
                  author,
                  expected,
              );
    const identity =
        submission === undefined
            ? undefined
            : envelopeIdentity(context, submission);
    if (
        submission === undefined ||
        identity === undefined ||
        (expected !== undefined && !equalBytes(identity, expected))
    )
        return;
    await deliverBody(
        session,
        relay,
        submission,
        submissionDirectory(author, identity) + 'body.bin',
    );
};

// The organizer's intent. Its body and fresh coins enter the root before the
// signature exists; an interrupted signing recomputes the same body from the
// retained close time, which ends the body.
const signIntent = async (session: CloseSession, closeTime?: bigint) => {
    const { context } = session.participant;
    let body: Uint8Array;
    if (generationOf(session) === closePhase.intent) {
        const retained = session.state.intentBody;
        body = closeCommand(context, 1, 0, retained.subarray(-8));
        if (!equalBytes(body, retained))
            throw new Error('The retained intent body changed.');
    } else {
        if (closeTime === undefined)
            throw new Error('No close time was requested.');
        body = closeCommand(context, 1, 0, unsigned64(closeTime));
        await commitClose(session, {
            generation: closePhase.intent,
            state: {
                ...session.state,
                intentBody: body,
                coins: crypto.getRandomValues(new Uint8Array(coinBytes)),
            },
        });
    }
    const signature = closeCommand(
        context,
        8,
        0,
        concatenate(body, session.state.coins),
    );
    return packet(body, signature);
};

// Locks the first authenticated intent. The lock's transaction retires the
// events of submissions timed after the close time, which no response can
// list, and appends the lock event, so replay applies it where it arrived.
const lockIntent = async (session: CloseSession, intentPacket: Uint8Array) => {
    const { context } = session.participant;
    if (tryCloseCommand(context, 2, 0, intentPacket) === undefined)
        throw new PublicInputFailure('The close intent was refused.');
    const { close } = session.participant.context.profile;
    const closeTime = readUnsigned64(
        intentPacket,
        4 + close.intentBodyBytes - 8,
    );
    const serial = nextSerial(session.state);
    const late = (event: CloseEvent) => {
        const submission = session.submissions.get(event.serial);
        return submission !== undefined && submission.ballotTime > closeTime;
    };
    const retired = session.state.events.filter(late);
    await commitClose(session, {
        generation: closePhase.locked,
        state: {
            ...collectingCloseState(),
            events: [
                ...session.state.events.filter((event) => !late(event)),
                { kind: closeEventKind.lock, serial, length: 0, keys: [] },
            ],
            intentPacket,
        },
        retired: retired.map((event) => event.serial),
    });
    for (const event of retired) {
        const submission = session.submissions.get(event.serial);
        if (submission !== undefined)
            session.known.delete(hexadecimal(submission.identity));
        session.submissions.delete(event.serial);
    }
};

// A responder's copies of the envelopes its response lists, or none when
// the relay lacks them.
const readListedCopies = async (
    profile: ParticipantProfile,
    relay: PublicRelay,
    responder: number,
) => {
    try {
        return await readPublic(
            relay,
            listedCopiesRoute(responder),
            maximumListedEntries(profile) * profile.close.submissionBytes,
        );
    } catch (error) {
        if (error instanceof PublicInputFailure) return new Uint8Array();
        throw error;
    }
};

// Takes each other published response not yet taken, with the listed
// envelopes the module does not know, each from its author's route or else
// from the responder's copies. A response the module refuses, or one whose
// envelopes the relay lacks, waits for a later visit.
const takeResponses = async (session: CloseSession, relay: PublicRelay) => {
    const { context } = session.participant;
    const { profile } = context;
    const { close, registration } = profile;
    const taken = new Set(session.responders.values());
    for (let responder = 0; responder < profile.participantCount; responder++) {
        if (responder === session.records.position || taken.has(responder))
            continue;
        let response: Uint8Array;
        try {
            response = await readPublic(
                relay,
                closeDirectory + 'response-' + String(responder) + '.bin',
                4 +
                    close.maximumResponseBodyBytes +
                    registration.signatureBytes,
            );
        } catch (error) {
            if (error instanceof PublicInputFailure) continue;
            throw error;
        }
        if (response.length < 4) continue;
        const length = readUnsigned32(response, 0);
        if (
            length < close.minimumResponseBodyBytes ||
            response.length !== 4 + length + registration.signatureBytes
        )
            continue;
        const supplied: Uint8Array[] = [];
        let copies: Uint8Array | undefined;
        for (
            let offset = 4 + close.minimumResponseBodyBytes, index = 0;
            offset + listedEntryBytes <= 4 + length;
            offset += listedEntryBytes, index++
        ) {
            const author = readUnsigned16(response, offset);
            const identity = response.subarray(
                offset + 2,
                offset + listedEntryBytes,
            );
            if (
                session.known.has(hexadecimal(identity)) ||
                supplied.some((value) =>
                    namesEnvelope(context, value, identity),
                )
            )
                continue;
            let submission: Uint8Array | undefined =
                await readPublishedSubmission(profile, relay, author, identity);
            if (
                submission === undefined ||
                !isListedSubmission(context, submission, author, identity)
            ) {
                copies ??= await readListedCopies(profile, relay, responder);
                submission = copies.subarray(
                    index * close.submissionBytes,
                    (index + 1) * close.submissionBytes,
                );
            }
            if (isListedSubmission(context, submission, author, identity))
                supplied.push(submission);
        }
        const record = concatenate(response, ...supplied);
        if (
            record.length > close.maximumResponseRecordBytes ||
            tryCloseCommand(context, 7, 0, record) === undefined
        )
            continue;
        const event = {
            kind: closeEventKind.response,
            serial: nextSerial(session.state),
        };
        const added = [await sealCloseRecord(session, event, 0, record)];
        await appendEvent(
            session,
            { ...event, length: record.length, keys: [added[0].key] },
            added,
        );
        learnResponse(session, event.serial, record);
    }
};

// Delivers the bodies the taken responses need and the organizer lacks,
// each from its author's route or else from the copy a responder that lists
// it forwarded. The envelope comes from this root's custody, where a taken
// response delivered it, or from its author's route.
const deliverWantedBodies = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const { context } = session.participant;
    const { profile } = context;
    const wanted = closeCommand(context, 13);
    if (wanted.length === 0) return;
    const submissions = await heldSubmissions(session);
    const responses = await heldResponses(session);
    for (let offset = 0; offset < wanted.length; offset += listedEntryBytes) {
        const author = readUnsigned16(wanted, offset);
        const identity = wanted.slice(offset + 2, offset + listedEntryBytes);
        const submission =
            submissions.get(hexadecimal(identity)) ??
            (await readPublishedSubmission(profile, relay, author, identity));
        if (
            submission === undefined ||
            !isListedSubmission(context, submission, author, identity)
        )
            continue;
        const routes = [submissionDirectory(author, identity) + 'body.bin'];
        for (const [responder, response] of responses)
            if (
                responder !== session.records.position &&
                responseListing(profile, response).some((entry) =>
                    equalBytes(entry.identity, identity),
                )
            )
                routes.push(forwardedBodyRoute(responder, identity));
        for (const route of routes)
            if (await deliverBody(session, relay, submission, route)) break;
    }
};

// This participant's one response. Its body and fresh coins enter the root
// before the signature exists; an interrupted signing must recompute the
// same body from the replayed log. The organizer then takes its own response
// and retains its proposal body and coins with it. Returns whether the
// organizer's proposal is prepared in this instance.
const respond = async (session: CloseSession) => {
    const { context } = session.participant;
    const resumed = generationOf(session) === closePhase.responding;
    const body = tryCloseCommand(context, 6);
    if (body === undefined) {
        if (resumed)
            throw new Error('The retained response can no longer be prepared.');
        return false;
    }
    if (resumed) {
        if (!equalBytes(body, session.state.responseBody))
            throw new Error(
                'The replayed response differs from the retained one.',
            );
    } else
        await commitClose(session, {
            generation: closePhase.responding,
            state: {
                ...session.state,
                responseBody: body,
                coins: crypto.getRandomValues(new Uint8Array(coinBytes)),
            },
        });
    const signature = closeCommand(
        context,
        8,
        0,
        concatenate(body, session.state.coins),
    );
    const responsePacket = packet(body, signature);
    let state: CloseState = {
        ...session.state,
        responseBody: new Uint8Array(),
        coins: new Uint8Array(),
        responsePacket,
    };
    if (session.organizer) {
        closeCommand(context, 7, 0, responsePacket);
        state = {
            ...state,
            proposalBody: closeCommand(context, 9),
            coins: crypto.getRandomValues(new Uint8Array(coinBytes)),
        };
    }
    await commitClose(session, { generation: closePhase.responded, state });
    return session.organizer;
};

// Signs the organizer's retained proposal. A restored organizer takes its
// own response again and must prepare the same proposal first.
const propose = async (session: CloseSession, prepared: boolean) => {
    const { context } = session.participant;
    if (!prepared) {
        closeCommand(context, 7, 0, session.state.responsePacket);
        if (!equalBytes(closeCommand(context, 9), session.state.proposalBody))
            throw new Error(
                'The replayed proposal differs from the retained one.',
            );
    }
    const signature = closeCommand(
        context,
        8,
        0,
        concatenate(session.state.proposalBody, session.state.coins),
    );
    await commitClose(session, {
        generation: closePhase.proposed,
        state: {
            ...session.state,
            proposalBody: new Uint8Array(),
            coins: new Uint8Array(),
            proposalPacket: packet(session.state.proposalBody, signature),
        },
    });
};

// The organizer's published intent, or undefined when the relay lacks it.
const readPublishedIntent = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const { close, registration } = session.participant.context.profile;
    try {
        return await readPublic(
            relay,
            closeDirectory + 'intent.bin',
            4 + close.intentBodyBytes + registration.signatureBytes,
        );
    } catch (error) {
        if (!(error instanceof PublicInputFailure)) throw error;
        return undefined;
    }
};

// A participant other than the organizer whose setup was just verified in
// this instance, before any ballot attempt, locks the organizer's published
// intent: it learned that ballot submission closed before it could vote, so
// it never starts a ballot. Returns whether it locked; without an authentic
// published intent it can still vote.
export const lockPublishedIntent = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    if (session.organizer || generationOf(session) !== 12) return false;
    const intent = await readPublishedIntent(session, relay);
    if (intent === undefined) return false;
    await startCloseWork(session);
    try {
        await lockIntent(session, intent);
    } catch (error) {
        if (!(error instanceof PublicInputFailure)) throw error;
        return false;
    }
    return true;
};

// One visit's close work after the complete setup verified in this instance.
export const advanceClose = async (
    session: CloseSession,
    relay: PublicRelay,
    request: CloseRequest,
) => {
    const generation = () => generationOf(session);
    const collecting = () =>
        generation() !== closePhase.intent &&
        generation() < closePhase.responding;
    await startCloseWork(session);
    if (collecting()) {
        // Every other roster position's published ballot, so that an honest
        // participant holds every ballot it can read before it responds.
        await deliverOwnBallot(session);
        for (
            let author = 0;
            author < session.participant.context.profile.participantCount;
            author++
        )
            if (author !== session.records.position)
                await deliverBallot(session, relay, author);
    }
    // A locked ballot attempt completes before any intent is locked.
    const unlocked = generation() === 12 || generation() === 17;
    if (session.organizer) {
        if (
            generation() === closePhase.intent ||
            (unlocked && request.closeTime !== undefined)
        )
            await lockIntent(
                session,
                await signIntent(session, request.closeTime),
            );
    } else if (unlocked) {
        const intent = await readPublishedIntent(session, relay);
        if (intent !== undefined) await lockIntent(session, intent);
    }
    if (session.organizer && generation() === closePhase.locked) {
        await takeResponses(session, relay);
        await deliverWantedBodies(session, relay);
    }
    let prepared = false;
    if (
        generation() === closePhase.locked ||
        generation() === closePhase.responding
    )
        prepared = await respond(session);
    if (session.organizer && generation() === closePhase.responded)
        await propose(session, prepared);
};

// Delivers the organizer's copy of every close record its proposal depends
// on, each under its own identity: the named responses, every envelope they
// list and the body of each slot they list one envelope for, but the
// organizer's own, which its ballot delivers. A participant whom the relay
// shows none of an author's or a responder's own records still finds them.
// Every copy comes from this root's custody, where the module accepted it
// before the proposal was prepared.
const publishClosure = async (
    session: CloseSession,
    relay: PublicRelay,
    delivery: Delivery,
) => {
    const { context } = session.participant;
    const { profile } = context;
    const responses = await heldResponses(session);
    const submissions = await heldSubmissions(session);
    // The distinct envelopes the named responses list for each slot.
    const slots = Array.from(
        { length: profile.participantCount },
        () => new Map<string, Uint8Array>(),
    );
    for (const { responder, identity } of proposalResponses(
        profile,
        session.state.proposalPacket,
    )) {
        const response = responses.get(responder);
        if (
            response === undefined ||
            !equalBytes(responseIdentity(context, response), identity)
        )
            throw new Error('The proposal names a response not held.');
        await delivery.transfer(() =>
            publishRecord(relay, closureResponseRoute(identity), response),
        );
        for (const entry of responseListing(profile, response)) {
            const key = hexadecimal(entry.identity);
            if (slots[entry.author].has(key)) continue;
            const submission = submissions.get(key);
            if (submission === undefined)
                throw new Error('The proposal lists an envelope not held.');
            slots[entry.author].set(key, entry.identity);
            await delivery.transfer(() =>
                publishRecord(
                    relay,
                    closureSubmissionRoute(entry.identity),
                    submission,
                ),
            );
        }
    }
    for (const [author, listed] of slots.entries()) {
        if (author === session.records.position || listed.size !== 1) continue;
        const [identity] = listed.values();
        const held = await heldBallotBody(session, author, identity);
        if (held === undefined)
            throw new Error('The proposal needs a body not held.');
        let offset = 0;
        await held(async (bytes) => {
            await delivery.transfer(
                () =>
                    publishChunk(
                        relay,
                        closureBodyRoute(identity),
                        offset,
                        bytes,
                    ),
                bytes,
            );
            offset += bytes.length;
        });
    }
};

// The identities of the bodies the organizer held when it locked its
// intent, in ascending order: its own ballot's and each held body retained
// before the lock event, whose transaction retired the late ones. Replay
// yields the same list, so every delivery publishes the same bytes.
const organizerHeldList = (session: CloseSession) => {
    const held: string[] = [];
    for (const event of session.state.events) {
        if (event.kind === closeEventKind.lock) break;
        if (
            event.kind !== closeEventKind.own &&
            event.kind !== closeEventKind.held
        )
            continue;
        const submission = session.submissions.get(event.serial);
        if (submission === undefined)
            throw new Error('A held body has no identity.');
        held.push(hexadecimal(submission.identity));
    }
    return concatenate(...held.sort().map(fromHexadecimal));
};

// The organizer's held list as a responder reads it; empty when the relay
// lacks it or serves a malformed one, so the responder then forwards every
// body it lists alone.
const readOrganizerHeld = async (
    profile: ParticipantProfile,
    relay: PublicRelay,
) => {
    const held = new Set<string>();
    let bytes: Uint8Array;
    try {
        bytes = await readPublic(
            relay,
            organizerHeldRoute,
            maximumListedEntries(profile) * identityBytes,
        );
    } catch (error) {
        if (error instanceof PublicInputFailure) return held;
        throw error;
    }
    if (bytes.length % identityBytes !== 0) return held;
    for (let offset = 0; offset < bytes.length; offset += identityBytes)
        held.add(hexadecimal(bytes.subarray(offset, offset + identityBytes)));
    return held;
};

// A copy of every envelope this participant's response lists, with its
// signature, in listing order, from this root's custody.
const listedCopies = async (session: CloseSession) => {
    const { profile } = session.participant.context;
    const held = await heldSubmissions(session);
    return concatenate(
        ...responseListing(profile, session.state.responsePacket).map(
            ({ identity }) => {
                const submission = held.get(hexadecimal(identity));
                if (submission === undefined)
                    throw new Error('The response lists an envelope not held.');
                return submission;
            },
        ),
    );
};

// Forwards the body of each slot this participant's response lists one
// envelope for, other than its own ballot's, that the organizer's held list
// lacks, so an organizer the relay shows no copy of that ballot still
// obtains it from a responder that lists it. Each body comes from this
// root's custody.
const forwardListedBodies = async (
    session: CloseSession,
    relay: PublicRelay,
    delivery: Delivery,
) => {
    const { profile } = session.participant.context;
    const { position } = session.records;
    const organizerHeld = await readOrganizerHeld(profile, relay);
    const listing = responseListing(profile, session.state.responsePacket);
    for (const { author, identity } of listing) {
        if (
            author === position ||
            organizerHeld.has(hexadecimal(identity)) ||
            listing.filter((entry) => entry.author === author).length !== 1
        )
            continue;
        const held = await heldBallotBody(session, author, identity);
        if (held === undefined)
            throw new Error('The response lists a body not held.');
        let offset = 0;
        await held(async (bytes) => {
            await delivery.transfer(
                () =>
                    publishChunk(
                        relay,
                        forwardedBodyRoute(position, identity),
                        offset,
                        bytes,
                    ),
                bytes,
            );
            offset += bytes.length;
        });
    }
};

// Retransmits the retained signed close messages, inspecting the retained
// authority around every transfer. The organizer's held list precedes its
// intent, and its proposal follows the closure it depends on. Another
// responder's response follows its copies of the envelopes it lists and
// precedes the bodies it forwards.
export const publishClose = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const generation = generationOf(session);
    const { state } = session;
    const { position } = session.records;
    const responder = !session.organizer && generation >= closePhase.responded;
    const messages: [string, Uint8Array][] = [];
    if (session.organizer && generation >= closePhase.locked)
        messages.push(
            [organizerHeldRoute, organizerHeldList(session)],
            [closeDirectory + 'intent.bin', state.intentPacket],
        );
    if (responder)
        messages.push([
            listedCopiesRoute(position),
            await listedCopies(session),
        ]);
    if (generation >= closePhase.responded)
        messages.push([
            closeDirectory + 'response-' + String(position) + '.bin',
            state.responsePacket,
        ]);
    if (messages.length === 0) return;
    const { context, root } = session.participant;
    const delivery = await openDelivery(context, root);
    for (const [route, message] of messages)
        await delivery.transfer(() => publishRecord(relay, route, message));
    if (responder) await forwardListedBodies(session, relay, delivery);
    if (generation === closePhase.proposed) {
        await publishClosure(session, relay, delivery);
        await delivery.transfer(() =>
            publishRecord(
                relay,
                closeDirectory + 'proposal.bin',
                state.proposalPacket,
            ),
        );
    }
};

const kindNames = ['own', 'held', 'lock', 'response'];

// The retained events in arrival order, with the author or responder each
// replay or delivery learned.
export const closeEvents = (session: CloseSession) =>
    session.state.events.map((event) => {
        const position =
            session.submissions.get(event.serial)?.author ??
            session.responders.get(event.serial);
        const kind = kindNames[event.kind];
        return position === undefined ? { kind } : { kind, position };
    });
