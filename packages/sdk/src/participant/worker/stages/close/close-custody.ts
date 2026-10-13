import type { ParticipantProfileContext } from '../../module/context.js';
import {
    moduleCommand,
    tryModuleCommand,
} from '../../module/participant-module.js';
import { ballotEnvelopeOffset } from '../../module/runtime-bounds.js';
import type { ParticipantSession } from '../../runtime/participant-session.js';
import {
    concatenate,
    equalBytes,
    hexadecimal,
    readUnsigned16,
    readUnsigned32,
    readUnsigned64,
} from '../../shared/bytes.js';
import { snapshotParticipant } from '../../storage/database.js';
import type {
    RecordContext,
    SealedRecord,
} from '../../storage/private-records.js';
import { openRecord, sealRecord } from '../../storage/private-records.js';
import { closePhase, rootGeneration } from '../../storage/root-generation.js';
import { commitRoot, dataRecordInventory } from '../../storage/root.js';
import type { BallotSession } from '../ballot/ballot.js';
import {
    ballotWorkInput,
    isSignedBallot,
    readBallotBody,
    resumeBallot,
    retainedBallotRecords,
} from '../ballot/ballot.js';
import { retainedRecordContext } from '../setup/setup.js';

import { custodyEnvelopeIdentity } from './close-records.js';
import type { CloseEvent, CloseState } from './close-state.js';
import {
    closeEventKind,
    closeRecordAssociatedData,
    closeRecordInventory,
    closeRecordLengths,
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
export const responderFromListing = 6 + 4 + 2;

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
export const closeOperation = {
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

export const tryCloseCommand = (
    context: ParticipantProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => tryModuleCommand(context.module, 'close', operation, { argument, input });

export const closeCommand = (
    context: ParticipantProfileContext,
    operation: number,
    argument = 0,
    input: Uint8Array = new Uint8Array(),
) => moduleCommand(context.module, 'close', operation, { argument, input });

export const generationOf = (session: CloseSession) =>
    session.participant.root.head.generation;

export const nextSerial = (state: CloseState) =>
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

export const sealCloseRecord = async (
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

export const commitClose = async (
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

export const namesEnvelope = (
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

export const learnSubmission = (
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
export const learnResponse = (
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

export const ownSubmission = (ballot: BallotSession) =>
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
export const startCloseWork = async (session: CloseSession) => {
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

export const appendEvent = (
    session: CloseSession,
    event: CloseEvent,
    added: readonly SealedCloseRecord[] = [],
) =>
    commitClose(session, {
        generation: generationOf(session),
        state: { ...session.state, events: [...session.state.events, event] },
        added,
    });

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
