import { writeModuleInput } from '../../module/context.js';
import type { ParticipantProfileContext } from '../../module/context.js';
import { readParticipantOutput } from '../../module/participant-module.js';
import type { ParticipantProfile } from '../../module/runtime-bounds.js';
import type { CandidateView } from '../../relay/candidates.js';
import {
    candidateLists,
    readCandidateFile,
    readCandidates,
    scanCandidatesFairly,
    streamCandidateFile,
} from '../../relay/candidates.js';
import { createCandidatePublication } from '../../relay/publication.js';
import type { PublicRelay } from '../../relay/relay.js';
import {
    concatenate,
    equalBytes,
    hexadecimal,
    readUnsigned16,
    readUnsigned32,
    readUnsigned64,
    unsigned64,
} from '../../shared/bytes.js';
import { PublicInputFailure } from '../../shared/failures.js';
import { encodeSignedPacket } from '../../shared/signed-packet.js';
import { snapshotParticipant } from '../../storage/database.js';
import { openDelivery } from '../../storage/delivery.js';
import type {
    RecordContext,
    SealedRecord,
} from '../../storage/private-records.js';
import { openRecord, sealRecord } from '../../storage/private-records.js';
import {
    ballotPhase,
    closePhase,
    rootGeneration,
} from '../../storage/root-generation.js';
import { commitRoot, dataRecordInventory } from '../../storage/root.js';
import { ballotEnvelopeOffset } from '../ballot/ballot-state.js';
import type { BallotSession } from '../ballot/ballot.js';
import {
    ballotCandidateKey,
    ballotWorkInput,
    isSignedBallot,
    readBallotBody,
    resumeBallot,
    retainedBallotRecords,
} from '../ballot/ballot.js';
import type { ParticipantSession } from '../contribution/contribution.js';
import { retainedRecordContext } from '../setup/setup.js';

import {
    closeIntentCandidateKey,
    closeProposalCandidateKey,
    closeResponseCandidateKey,
    closureBodyFile,
    closureResponseFile,
    closureSubmissionFile,
    custodyEnvelopeIdentity,
    isListedSubmission,
    isResponsePacket,
    listedEntryBytes,
    proposalResponses,
    responseIdentity,
    responseListing,
} from './close-records.js';
import type { CloseEvent, CloseState } from './close-state.js';
import {
    closeEventKind,
    closeRecordAssociatedData,
    closeRecordInventory,
    closeRecordLengths,
    collectingCloseState,
    completedClosePhase,
    decodeCloseState,
    encodeCloseState,
} from './close-state.js';

// A participant's close work. Each operation restores the module's close state
// from the retained log, then accepts the deliveries it is given, locks the
// organizer's intent, responds, and for the organizer takes the other
// responses and proposes. Every accepted input commits its event, records and
// root together; a refused public input changes nothing and leaves the
// participant where it was.

// A response body ends with its responder and its listing: an unsigned item
// of six header bytes and two value bytes, then a byte-string item of six
// header bytes and a four-byte inner length before the entries.
const responderFromListing = 6 + 4 + 2;

// The most entries a response lists, two envelopes for each slot, which also
// bounds the bodies the organizer can hold.
const maximumListedEntries = ({ close }: ParticipantProfile) =>
    (close.maximumResponseBodyBytes - close.minimumResponseBodyBytes) /
    listedEntryBytes;

export type CloseParameters = Readonly<{
    // The organizer's close time in Unix milliseconds, only before an intent.
    closeTime?: bigint;
}>;

// The close time a request supplies, or undefined when it is malformed.
export const parseCloseParameters = (
    parameters: Readonly<Record<string, unknown>>,
): CloseParameters | undefined => {
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
    readonly isOrganizer: boolean;
    readonly ballot: BallotSession | undefined;
    state: CloseState;
    // The submission of each own or held event and the responder of each
    // taken response, by serial, and every envelope identity the module
    // knows.
    readonly submissions: Map<number, Submission>;
    readonly responders: Map<number, number>;
    readonly known: Set<string>;
};

// A close record also names the event that lists it.
type SealedCloseRecord = SealedRecord & Readonly<{ serial: number }>;

// The close work's operations, as the module's close command numbers them.
const closeOperation = {
    begin: 0,
    prepareIntent: 1,
    lockIntent: 2,
    // A held envelope and its complete body, transferred in chunks.
    beginHeldBody: 3,
    pushHeldBody: 4,
    finishHeldBody: 5,
    prepareResponse: 6,
    admitResponse: 7,
    sign: 8,
    prepareProposal: 9,
    restoreMessage: 10,
    restoreBallotSigning: 11,
    discardHeldBody: 12,
    wantedBodies: 13,
    envelopeIdentity: 14,
} as const;

// The completed close message that a restore names.
const closeMessage = { intent: 0, response: 1, proposal: 2 } as const;

const tryCloseCommand = (
    context: ParticipantProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => {
    const { module } = context;
    writeModuleInput(context, input);
    if (
        module.participant_close_command(operation, argument, input.length) !==
        0
    )
        return undefined;
    return readParticipantOutput(module);
};

const closeCommand = (
    context: ParticipantProfileContext,
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
    isOrganizer: boolean,
): Promise<CloseSession> => {
    const { context, root } = participant;
    const bytes = root.manifest.suffixes.close;
    if (
        root.head.generation < rootGeneration.setupRetained ||
        bytes === undefined
    )
        throw new Error('No close log is retained.');
    const records = await retainedRecordContext(participant);
    const state = decodeCloseState(
        context.profile,
        root.head.generation,
        isOrganizer,
        bytes,
    );
    const snapshot = await snapshotParticipant(context.database);
    if (snapshot.counts.close !== recordCount(state))
        throw new Error('The close records changed.');
    const ballot = await resumeBallot(participant);
    return {
        participant,
        records,
        isOrganizer,
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
    generationOf(session) >= completedClosePhase(session.isOrganizer);

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
): Promise<SealedCloseRecord> => ({
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
    added?: readonly SealedCloseRecord[];
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
        session.isOrganizer,
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
const envelopeIdentity = (
    context: ParticipantProfileContext,
    submission: Uint8Array,
) =>
    tryCloseCommand(
        context,
        closeOperation.envelopeIdentity,
        0,
        submission.subarray(0, context.profile.ballot.envelopeBytes),
    );

const namesEnvelope = (
    context: ParticipantProfileContext,
    submission: Uint8Array,
    identity: Uint8Array,
) => {
    const value = envelopeIdentity(context, submission);
    return value !== undefined && equalBytes(value, identity);
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
            readUnsigned16(submission, ballotEnvelopeOffset.author) ===
                author &&
            equalBytes(custodyEnvelopeIdentity(context, submission), identity);
        if (
            readUnsigned64(submission, ballotEnvelopeOffset.bodyLength) !==
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
        author: readUnsigned16(envelope, ballotEnvelopeOffset.author),
        identity,
        ballotTime: readUnsigned64(envelope, ballotEnvelopeOffset.ballotTime),
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
            closeCommand(
                context,
                closeOperation.beginHeldBody,
                0,
                ownSubmission(ballot),
            );
            await readBallotBody(ballot, (bytes) => {
                closeCommand(context, closeOperation.pushHeldBody, 0, bytes);
            });
            closeCommand(context, closeOperation.finishHeldBody);
            learnSubmission(session, event.serial, ballot.state.envelope);
            break;
        }
        case closeEventKind.held: {
            const submission = await openCloseRecord(session, event, 0);
            if (
                readUnsigned64(submission, ballotEnvelopeOffset.bodyLength) !==
                BigInt(event.length)
            )
                throw new Error('A held body changed its length.');
            closeCommand(context, closeOperation.beginHeldBody, 0, submission);
            for (let index = 1; index < event.keys.length; index++) {
                const bytes = await openCloseRecord(session, event, index);
                try {
                    closeCommand(
                        context,
                        closeOperation.pushHeldBody,
                        0,
                        bytes,
                    );
                } finally {
                    bytes.fill(0);
                }
            }
            closeCommand(context, closeOperation.finishHeldBody);
            learnSubmission(session, event.serial, submission);
            break;
        }
        case closeEventKind.lock:
            closeCommand(
                context,
                closeOperation.lockIntent,
                0,
                session.state.intentPacket,
            );
            break;
        case closeEventKind.response: {
            const record = await openCloseRecord(session, event, 0);
            closeCommand(context, closeOperation.admitResponse, 0, record);
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
        closeOperation.begin,
        0,
        await ballotWorkInput(participant, session.records.setupIdentity),
    );
    if (session.ballot !== undefined)
        closeCommand(
            context,
            closeOperation.restoreBallotSigning,
            0,
            ownSubmission(session.ballot),
        );
    if (session.isOrganizer && generation >= closePhase.locked)
        closeCommand(
            context,
            closeOperation.restoreMessage,
            closeMessage.intent,
            session.state.intentPacket,
        );
    for (const event of session.state.events) await replayEvent(session, event);
    if (generation >= closePhase.responded)
        closeCommand(
            context,
            closeOperation.restoreMessage,
            closeMessage.response,
            session.state.responsePacket,
        );
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
        closeOperation.begin,
        0,
        await ballotWorkInput(participant, session.records.setupIdentity),
    );
    if (session.ballot !== undefined)
        closeCommand(
            context,
            closeOperation.restoreBallotSigning,
            0,
            ownSubmission(session.ballot),
        );
    if (session.isOrganizer)
        closeCommand(
            context,
            closeOperation.restoreMessage,
            closeMessage.intent,
            state.intentPacket,
        );
    closeCommand(context, closeOperation.lockIntent, 0, state.intentPacket);
    closeCommand(
        context,
        closeOperation.restoreMessage,
        closeMessage.response,
        state.responsePacket,
    );
    if (session.isOrganizer)
        closeCommand(
            context,
            closeOperation.restoreMessage,
            closeMessage.proposal,
            state.proposalPacket,
        );
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
    added: readonly SealedCloseRecord[] = [],
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
    if (
        tryCloseCommand(
            context,
            closeOperation.beginHeldBody,
            0,
            ownSubmission(ballot),
        ) === undefined
    )
        return;
    await readBallotBody(ballot, (bytes) => {
        closeCommand(context, closeOperation.pushHeldBody, 0, bytes);
    });
    closeCommand(context, closeOperation.finishHeldBody);
    const serial = nextSerial(session.state);
    await appendEvent(session, {
        kind: closeEventKind.own,
        serial,
        length: 0,
        keys: [],
    });
    learnSubmission(session, serial, ballot.state.envelope);
};

// Read both parts from the same candidate; the owning close verifier decides
// authentication before it accepts any body or publishes a response.
const readSubmissionCandidate = async (
    profile: ParticipantProfile,
    relay: PublicRelay,
    candidate: CandidateView,
) => {
    try {
        const submission = concatenate(
            await readCandidateFile(
                relay,
                candidate,
                'envelope.bin',
                profile.ballot.envelopeBytes,
            ),
            await readCandidateFile(
                relay,
                candidate,
                'signature.bin',
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

// Delivers a submission with its body from a route, sealing each body
// record as it passes the module. A refused, late or incomplete submission
// changes nothing. Returns whether the module accepted the body.
const deliverBody = async (
    session: CloseSession,
    relay: PublicRelay,
    submission: Uint8Array,
    candidate: CandidateView,
    name: string,
) => {
    const { context } = session.participant;
    const { profile } = context;
    if (
        tryCloseCommand(
            context,
            closeOperation.beginHeldBody,
            0,
            submission,
        ) === undefined
    )
        return false;
    const length = Number(
        readUnsigned64(submission, ballotEnvelopeOffset.bodyLength),
    );
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
            if (
                tryCloseCommand(
                    context,
                    closeOperation.pushHeldBody,
                    0,
                    bytes,
                ) === undefined
            )
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
            await streamCandidateFile(
                relay,
                candidate,
                name,
                length,
                async (bytes) => {
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
                },
            );
        if (used > 0 && accepted) await flush();
    } catch (error) {
        if (!(error instanceof PublicInputFailure)) throw error;
        accepted = false;
    } finally {
        pending.fill(0);
    }
    // A stream may fail after its last payload byte. Cancel before finish so
    // that failed transport cannot install even a complete tentative body.
    if (!accepted) {
        closeCommand(context, closeOperation.discardHeldBody);
        return false;
    }
    if (tryCloseCommand(context, closeOperation.finishHeldBody) === undefined)
        return false;
    await appendEvent(
        session,
        { ...event, length, keys: added.map((record) => record.key) },
        added,
    );
    learnSubmission(session, event.serial, submission);
    return true;
};

// Tries every candidate in the author's finite published prefix. Exact
// duplicates and extra conflicting envelopes are refused by the close owner.
const deliverBallot = async (
    session: CloseSession,
    relay: PublicRelay,
    author: number,
) => {
    const { context } = session.participant;
    for await (const candidate of readCandidates(
        relay,
        ballotCandidateKey(author),
    )) {
        const submission = await readSubmissionCandidate(
            context.profile,
            relay,
            candidate,
        );
        if (
            submission === undefined ||
            readUnsigned16(submission, ballotEnvelopeOffset.author) !== author
        )
            continue;
        await deliverBody(session, relay, submission, candidate, 'body.bin');
    }
};

// The organizer's intent. Its exact body enters the root before the
// signature exists; an interrupted signing recomputes the same body from the
// retained close time, which ends the body.
const signIntent = async (session: CloseSession, closeTime?: bigint) => {
    const { context } = session.participant;
    let body: Uint8Array;
    if (generationOf(session) === closePhase.intent) {
        const retained = session.state.intentBody;
        body = closeCommand(
            context,
            closeOperation.prepareIntent,
            0,
            retained.subarray(-8),
        );
        if (!equalBytes(body, retained))
            throw new Error('The retained intent body changed.');
    } else {
        if (closeTime === undefined)
            throw new Error('No close time was requested.');
        body = closeCommand(
            context,
            closeOperation.prepareIntent,
            0,
            unsigned64(closeTime),
        );
        await commitClose(session, {
            generation: closePhase.intent,
            state: {
                ...session.state,
                intentBody: body,
            },
        });
    }
    const signature = closeCommand(context, closeOperation.sign, 0, body);
    return encodeSignedPacket({ body, signature });
};

// Locks the first authenticated intent. The lock's transaction retires the
// events of submissions timed after the close time, which no response can
// list, and appends the lock event, so replay applies it where it arrived.
const lockIntent = async (session: CloseSession, intentPacket: Uint8Array) => {
    const { context } = session.participant;
    if (
        tryCloseCommand(context, closeOperation.lockIntent, 0, intentPacket) ===
        undefined
    )
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

// Takes each other published response not yet taken, with the listed
// envelopes from the same complete candidate. A failed candidate cannot
// consume its responder's chance to supply a later valid response.
const takeResponses = async (session: CloseSession, relay: PublicRelay) => {
    const { context } = session.participant;
    const { profile } = context;
    const { close, registration } = profile;
    const taken = new Set(session.responders.values());
    // Authentication does not establish body availability. Only the owning
    // close machine may prepare the organizer's response from a ready quorum.
    const restored = tryCloseCommand(context, closeOperation.prepareResponse);
    if (restored !== undefined) return restored;
    await deliverWantedBodies(session, relay);
    const recovered = tryCloseCommand(context, closeOperation.prepareResponse);
    if (recovered !== undefined) return recovered;
    let prepared: ReturnType<typeof tryCloseCommand>;
    return scanCandidatesFairly(
        candidateLists(
            relay,
            profile.participantCount,
            closeResponseCandidateKey,
            (position) =>
                position !== session.records.position && !taken.has(position),
        ),
        async (responder, candidate) => {
            let response: Uint8Array;
            let copies: Uint8Array;
            try {
                response = await readCandidateFile(
                    relay,
                    candidate,
                    'response.bin',
                    4 +
                        close.maximumResponseBodyBytes +
                        registration.signatureBytes,
                );
                copies = await readCandidateFile(
                    relay,
                    candidate,
                    'submissions.bin',
                    maximumListedEntries(profile) * close.submissionBytes,
                );
            } catch (error) {
                if (error instanceof PublicInputFailure) return false;
                throw error;
            }
            if (
                !isResponsePacket(profile, response) ||
                readUnsigned16(
                    response,
                    4 + close.minimumResponseBodyBytes - responderFromListing,
                ) !== responder
            )
                return false;
            const length = readUnsigned32(response, 0);
            const supplied: Uint8Array[] = [];
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
                const submission = copies.subarray(
                    index * close.submissionBytes,
                    (index + 1) * close.submissionBytes,
                );
                if (isListedSubmission(context, submission, author, identity))
                    supplied.push(submission);
            }
            const record = concatenate(response, ...supplied);
            if (
                record.length > close.maximumResponseRecordBytes ||
                tryCloseCommand(
                    context,
                    closeOperation.admitResponse,
                    0,
                    record,
                ) === undefined
            )
                return false;
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
            prepared = tryCloseCommand(context, closeOperation.prepareResponse);
            return true;
        },
        () => prepared,
        async () => {
            await deliverWantedBodies(session, relay);
            prepared = tryCloseCommand(context, closeOperation.prepareResponse);
        },
    );
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
    const wanted = closeCommand(context, closeOperation.wantedBodies);
    if (wanted.length === 0) return;
    const submissions = await heldSubmissions(session);
    const responses = await heldResponses(session);
    for (let offset = 0; offset < wanted.length; offset += listedEntryBytes) {
        const author = readUnsigned16(wanted, offset);
        const identity = wanted.slice(offset + 2, offset + listedEntryBytes);
        const submission = submissions.get(hexadecimal(identity));
        if (
            submission === undefined ||
            !isListedSubmission(context, submission, author, identity)
        )
            continue;
        const sources: [string, string][] = [
            [ballotCandidateKey(author), 'body.bin'],
        ];
        for (const [responder, response] of responses)
            if (
                responder !== session.records.position &&
                responseListing(profile, response).some((entry) =>
                    equalBytes(entry.identity, identity),
                )
            )
                sources.push([
                    closeResponseCandidateKey(responder),
                    closureBodyFile(identity),
                ]);
        let delivered = false;
        for (const [key, name] of sources) {
            for await (const candidate of readCandidates(relay, key)) {
                if (
                    await deliverBody(
                        session,
                        relay,
                        submission,
                        candidate,
                        name,
                    )
                ) {
                    delivered = true;
                    break;
                }
            }
            if (delivered) break;
        }
    }
};

// This participant's one response. Its exact body enters the root
// before the signature exists; an interrupted signing must recompute the
// same body from the replayed log. The organizer then takes its own response
// and retains its proposal exact body with it. Returns whether the
// organizer's proposal is prepared in this instance.
const respond = async (session: CloseSession, preparedBody?: Uint8Array) => {
    const { context } = session.participant;
    const resumed = generationOf(session) === closePhase.responding;
    const body =
        preparedBody ??
        tryCloseCommand(context, closeOperation.prepareResponse);
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
            },
        });
    const signature = closeCommand(context, closeOperation.sign, 0, body);
    const responsePacket = encodeSignedPacket({ body, signature });
    let state: CloseState = {
        ...session.state,
        responseBody: new Uint8Array(),
        responsePacket,
    };
    if (session.isOrganizer) {
        closeCommand(context, closeOperation.admitResponse, 0, responsePacket);
        state = {
            ...state,
            proposalBody: closeCommand(context, closeOperation.prepareProposal),
        };
    }
    await commitClose(session, { generation: closePhase.responded, state });
    return session.isOrganizer;
};

// Signs the organizer's retained proposal. A restored organizer takes its
// own response again and must prepare the same proposal first.
const propose = async (session: CloseSession, prepared: boolean) => {
    const { context } = session.participant;
    if (!prepared) {
        closeCommand(
            context,
            closeOperation.admitResponse,
            0,
            session.state.responsePacket,
        );
        if (
            !equalBytes(
                closeCommand(context, closeOperation.prepareProposal),
                session.state.proposalBody,
            )
        )
            throw new Error(
                'The replayed proposal differs from the retained one.',
            );
    }
    const signature = closeCommand(
        context,
        closeOperation.sign,
        0,
        session.state.proposalBody,
    );
    await commitClose(session, {
        generation: closePhase.proposed,
        state: {
            ...session.state,
            proposalBody: new Uint8Array(),
            proposalPacket: encodeSignedPacket({
                body: session.state.proposalBody,
                signature,
            }),
        },
    });
};

// Only the owning lock may select an organizer's intent from discovery.
const lockAvailableIntent = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const { close, registration } = session.participant.context.profile;
    for await (const candidate of readCandidates(
        relay,
        closeIntentCandidateKey,
    )) {
        try {
            const intent = await readCandidateFile(
                relay,
                candidate,
                'intent.bin',
                4 + close.intentBodyBytes + registration.signatureBytes,
            );
            await lockIntent(session, intent);
            return true;
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
    }
    return false;
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
    if (session.isOrganizer || generationOf(session) !== 12) return false;
    await startCloseWork(session);
    return lockAvailableIntent(session, relay);
};

// One operation's close work after the complete setup verified in this instance.
export const advanceClose = async (
    session: CloseSession,
    relay: PublicRelay,
    request: CloseParameters,
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
    const unlocked =
        generation() === rootGeneration.setupRetained ||
        generation() === ballotPhase.signed;
    if (session.isOrganizer) {
        if (
            generation() === closePhase.intent ||
            (unlocked && request.closeTime !== undefined)
        )
            await lockIntent(
                session,
                await signIntent(session, request.closeTime),
            );
    } else if (unlocked) {
        await lockAvailableIntent(session, relay);
    }
    let responseBody: Uint8Array | undefined;
    if (session.isOrganizer && generation() === closePhase.locked)
        responseBody = await takeResponses(session, relay);
    let prepared = false;
    if (
        generation() === closePhase.locked ||
        generation() === closePhase.responding
    )
        prepared = await respond(session, responseBody);
    if (session.isOrganizer && generation() === closePhase.responded)
        await propose(session, prepared);
};

// Delivers the organizer's copy of every close record its proposal depends
// on, each under its own identity: the named responses, every envelope they
// list and the body of each slot they list one envelope for. A participant whom the relay
// shows none of an author's or a responder's own records still finds them.
// Every copy comes from this root's custody, where the module accepted it
// before the proposal was prepared.
const publishClosure = async (
    session: CloseSession,
    publication: ReturnType<typeof createCandidatePublication>,
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
        await publication.addBytes(closureResponseFile(identity), response);
        for (const entry of responseListing(profile, response)) {
            const key = hexadecimal(entry.identity);
            if (slots[entry.author].has(key)) continue;
            const submission = submissions.get(key);
            if (submission === undefined)
                throw new Error('The proposal lists an envelope not held.');
            slots[entry.author].set(key, entry.identity);
            await publication.addBytes(
                closureSubmissionFile(entry.identity),
                submission,
            );
        }
    }
    for (const [author, listed] of slots.entries()) {
        if (listed.size !== 1) continue;
        const [identity] = listed.values();
        const held = await heldBallotBody(session, author, identity);
        if (held === undefined)
            throw new Error('The proposal needs a body not held.');
        const submission = submissions.get(hexadecimal(identity))!;
        await publication.addRetainedFile(
            closureBodyFile(identity),
            Number(readUnsigned64(submission, ballotEnvelopeOffset.bodyLength)),
            async (accept) => {
                await held(accept);
            },
            ballotCandidateKey(author),
            'body.bin',
        );
    }
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
// envelope for, including its own if the original publication failed. An unsigned relay hint must not
// suppress required forwarding. Every copy comes from this root's custody.
const forwardListedBodies = async (
    session: CloseSession,
    publication: ReturnType<typeof createCandidatePublication>,
) => {
    const { profile } = session.participant.context;
    const submissions = await heldSubmissions(session);
    const listing = responseListing(profile, session.state.responsePacket);
    for (const { author, identity } of listing) {
        if (listing.filter((entry) => entry.author === author).length !== 1)
            continue;
        const held = await heldBallotBody(session, author, identity);
        if (held === undefined)
            throw new Error('The response lists a body not held.');
        const submission = submissions.get(hexadecimal(identity));
        if (submission === undefined)
            throw new Error('The response lists an envelope not held.');
        await publication.addRetainedFile(
            closureBodyFile(identity),
            Number(readUnsigned64(submission, ballotEnvelopeOffset.bodyLength)),
            async (accept) => {
                await held(accept);
            },
            ballotCandidateKey(author),
            'body.bin',
        );
    }
};

// Retransmits the retained signed close messages, inspecting the retained
// authority around every transfer. Each response and proposal is discovered
// only after its complete correlated dependency copies have been uploaded.
export const publishClose = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const generation = generationOf(session);
    const { state } = session;
    const { position } = session.records;
    const responder =
        !session.isOrganizer && generation >= closePhase.responded;
    if (generation < closePhase.locked) return;
    const { context, root } = session.participant;
    const delivery = await openDelivery(context, root);
    if (session.isOrganizer) {
        const publication = createCandidatePublication(
            relay,
            closeIntentCandidateKey,
            delivery,
        );
        await publication.addBytes('intent.bin', state.intentPacket);
        await publication.finish();
    }
    if (generation >= closePhase.responded) {
        const publication = createCandidatePublication(
            relay,
            closeResponseCandidateKey(position),
            delivery,
        );
        await publication.addBytes('response.bin', state.responsePacket);
        await publication.addBytes(
            'submissions.bin',
            await listedCopies(session),
        );
        if (responder) await forwardListedBodies(session, publication);
        await publication.finish();
    }
    if (generation === closePhase.proposed) {
        const publication = createCandidatePublication(
            relay,
            closeProposalCandidateKey,
            delivery,
        );
        await publication.addBytes('intent.bin', state.intentPacket);
        await publishClosure(session, publication);
        await publication.addBytes('proposal.bin', state.proposalPacket);
        await publication.finish();
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
