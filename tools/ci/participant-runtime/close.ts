import {
    ballotDirectory,
    ballotWorkInput,
    isSignedBallot,
    readBallotBody,
    resumeBallot,
    retainedBallotRecords,
} from './ballot.js';
import type { BallotSession } from './ballot.js';
import {
    concatenate,
    equalBytes,
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
import type { ParticipantContext } from './context.js';
import { contributionRecords } from './contribution.js';
import type { ContributionSession } from './contribution.js';
import type { ParticipantDescriptor } from './descriptor.js';
import { readKernel } from './kernel.js';
import { publishRecord, readPublic, streamPublic } from './public.js';
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
const listedEntryBytes = 2 + 64;
// The envelope's author position, ballot time and body length.
const envelopeAuthorOffset = 132;
const envelopeTimeOffset = 134;
const envelopeLengthOffset = 142;
// A response body ends with its responder and its listing: an unsigned item
// of six header bytes and two value bytes, then a byte-string item of six
// header bytes and a four-byte inner length before the entries.
const responderFromListing = 6 + 4 + 2;
export const closeDirectory = 'close/';

export type CloseRequest = Readonly<{
    // Published ballots to deliver with their bodies, by author.
    deliver: readonly number[];
    // Published ballots to deliver as envelopes alone, by author.
    announce: readonly number[];
    // The organizer's close time in Unix milliseconds, only before an intent.
    closeTime?: bigint;
}>;

// Distinct roster positions, or undefined when the value lists anything else.
const parsePositions = (
    descriptor: ParticipantDescriptor,
    value: unknown,
): number[] | undefined => {
    if (value === undefined) return [];
    if (!Array.isArray(value)) return undefined;
    const positions: unknown[] = value;
    return positions.every(
        (position) =>
            typeof position === 'number' &&
            Number.isSafeInteger(position) &&
            position >= 0 &&
            position < descriptor.participantCount,
    ) && new Set(positions).size === positions.length
        ? (positions as number[])
        : undefined;
};

// The deliveries and close time a request supplies, or undefined when any
// is malformed.
export const parseCloseRequest = (
    descriptor: ParticipantDescriptor,
    parameters: Readonly<Record<string, unknown>>,
): CloseRequest | undefined => {
    const deliver = parsePositions(descriptor, parameters.deliver);
    const announce = parsePositions(descriptor, parameters.announce);
    const { closeTime } = parameters;
    if (
        deliver === undefined ||
        announce === undefined ||
        (closeTime !== undefined &&
            (typeof closeTime !== 'number' ||
                !Number.isSafeInteger(closeTime) ||
                closeTime < 0))
    )
        return undefined;
    return {
        deliver,
        announce,
        ...(closeTime === undefined ? {} : { closeTime: BigInt(closeTime) }),
    };
};

// What replay and delivery learned of a retained submission.
type Submission = Readonly<{
    author: number;
    identity: Uint8Array;
    ballotTime: bigint;
}>;

export type CloseSession = {
    readonly contribution: ContributionSession;
    readonly records: RecordContext;
    readonly organizer: boolean;
    readonly ballot: BallotSession | undefined;
    state: CloseState;
    // The submission of each own, known or held event and the responder of
    // each taken response, by serial, and every envelope identity the
    // module knows.
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
    context: ParticipantContext,
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
    context: ParticipantContext,
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
    session.contribution.root.head.generation;

const nextSerial = (state: CloseState) =>
    state.events.length === 0
        ? 0
        : state.events[state.events.length - 1].serial + 1;

const recordCount = (state: CloseState) =>
    state.events.reduce((total, event) => total + event.keys.length, 0);

// Decodes the retained close log and the signed ballot it may reference.
// Every listed record must be stored and nothing else.
export const resumeClose = async (
    contribution: ContributionSession,
    organizer: boolean,
): Promise<CloseSession> => {
    const { context, root } = contribution;
    const bytes = root.manifest.suffixes.close;
    if (root.head.generation < 12 || bytes === undefined)
        throw new Error('No close log is retained.');
    const records = await recordContext(contribution);
    const state = decodeCloseState(
        context.descriptor,
        root.head.generation,
        organizer,
        bytes,
    );
    const snapshot = await snapshotParticipant(context.database);
    if (snapshot.counts.close !== recordCount(state))
        throw new Error('The close records changed.');
    const ballot = await resumeBallot(contribution);
    return {
        contribution,
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
    const { context } = session.contribution;
    const length = closeRecordLengths(context.descriptor, event)[index];
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
    const { contribution } = session;
    const { context, root } = contribution;
    const { descriptor } = context;
    const encoded = encodeCloseState(
        transition.generation,
        session.organizer,
        transition.state,
    );
    if (encoded.length > descriptor.close.maximumStateBytes)
        throw new Error('The close state exceeds its bound.');
    contribution.root = await commitRoot(
        context.database,
        context.runtime,
        descriptor,
        root,
        {
            generation: transition.generation,
            manifest: {
                ...root.manifest,
                suffixes: { ...root.manifest.suffixes, close: encoded },
            },
            predecessorRecords: [
                ...dataRecordInventory(root.manifest),
                ...contributionRecords(contribution),
                ...retainedBallotRecords(contribution, session.records),
                ...closeRecordInventory(
                    descriptor,
                    session.records,
                    session.state,
                ),
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
        },
    );
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
export const envelopeIdentity = (
    context: ParticipantContext,
    submission: Uint8Array,
) =>
    tryCloseCommand(
        context,
        14,
        0,
        submission.subarray(0, context.descriptor.ballot.envelopeBytes),
    );

const namesEnvelope = (
    context: ParticipantContext,
    submission: Uint8Array,
    identity: Uint8Array,
) => {
    const value = envelopeIdentity(context, submission);
    return value !== undefined && equalBytes(value, identity);
};

const learnSubmission = (
    session: CloseSession,
    serial: number,
    envelope: Uint8Array,
) => {
    const identity = envelopeIdentity(session.contribution.context, envelope);
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
    const { context } = session.contribution;
    const { close, registration } = context.descriptor;
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

// Replays one retained event. It was accepted on arrival, so a refusal means
// the retained state changed.
const replayEvent = async (session: CloseSession, event: CloseEvent) => {
    const { context } = session.contribution;
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
        case closeEventKind.known: {
            const submission = await openCloseRecord(session, event, 0);
            closeCommand(context, 12, 0, submission);
            learnSubmission(session, event.serial, submission);
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
    const { contribution } = session;
    const { context } = contribution;
    const generation = generationOf(session);
    closeCommand(
        context,
        0,
        0,
        await ballotWorkInput(contribution, session.records.inventory),
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
    const { contribution, state } = session;
    const { context } = contribution;
    if (!isCloseComplete(session))
        throw new Error('The close is not complete.');
    closeCommand(
        context,
        0,
        0,
        await ballotWorkInput(contribution, session.records.inventory),
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
        session.contribution.context.descriptor,
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
    const { context } = session.contribution;
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

// A published ballot's envelope and signature, or undefined when the relay
// lacks them.
export const readPublishedSubmission = async (
    descriptor: ParticipantDescriptor,
    relay: PublicRelay,
    author: number,
) => {
    const directory = ballotDirectory(author);
    try {
        const submission = concatenate(
            await readPublic(
                relay,
                directory + 'envelope.bin',
                descriptor.ballot.envelopeBytes,
            ),
            await readPublic(
                relay,
                directory + 'signature.bin',
                descriptor.registration.signatureBytes,
            ),
        );
        return submission.length === descriptor.close.submissionBytes
            ? submission
            : undefined;
    } catch (error) {
        if (error instanceof PublicInputFailure) return undefined;
        throw error;
    }
};

// Delivers a published ballot with its body, sealing each body record as it
// passes the module. An expected identity restricts delivery to that
// envelope. A refused, late or incomplete submission changes nothing.
const deliverBallot = async (
    session: CloseSession,
    relay: PublicRelay,
    author: number,
    expected?: Uint8Array,
) => {
    const { context } = session.contribution;
    const { descriptor } = context;
    const submission = await readPublishedSubmission(descriptor, relay, author);
    if (
        submission === undefined ||
        (expected !== undefined &&
            !namesEnvelope(context, submission, expected)) ||
        tryCloseCommand(context, 3, 0, submission) === undefined
    )
        return;
    const length = Number(readUnsigned64(submission, envelopeLengthOffset));
    const { recordBytes, minimumBodyBytes, maximumBodyBytes } =
        descriptor.ballot;
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
            await streamPublic(
                relay,
                ballotDirectory(author) + 'body.bin',
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
    // Finishing also clears a refused or incomplete body's authentication.
    if (tryCloseCommand(context, 5) === undefined || !accepted) return;
    await appendEvent(
        session,
        { ...event, length, keys: added.map((record) => record.key) },
        added,
    );
    learnSubmission(session, event.serial, submission);
};

// Delivers a published envelope without its body.
const announceBallot = async (
    session: CloseSession,
    relay: PublicRelay,
    author: number,
) => {
    const { context } = session.contribution;
    const submission = await readPublishedSubmission(
        context.descriptor,
        relay,
        author,
    );
    if (
        submission === undefined ||
        tryCloseCommand(context, 12, 0, submission) === undefined
    )
        return;
    const event = {
        kind: closeEventKind.known,
        serial: nextSerial(session.state),
    };
    const added = [await sealCloseRecord(session, event, 0, submission)];
    await appendEvent(
        session,
        { ...event, length: submission.length, keys: [added[0].key] },
        added,
    );
    learnSubmission(session, event.serial, submission);
};

// The organizer's intent. Its body and fresh coins enter the root before the
// signature exists; an interrupted signing recomputes the same body from the
// retained close time, which ends the body.
const signIntent = async (session: CloseSession, closeTime?: bigint) => {
    const { context } = session.contribution;
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
    const { context } = session.contribution;
    if (tryCloseCommand(context, 2, 0, intentPacket) === undefined)
        throw new PublicInputFailure('The close intent was refused.');
    const { close } = session.contribution.context.descriptor;
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
// envelopes the module does not know. A response the module refuses, or one
// whose envelopes the relay lacks, waits for a later visit.
const takeResponses = async (session: CloseSession, relay: PublicRelay) => {
    const { context } = session.contribution;
    const { descriptor } = context;
    const { close, registration } = descriptor;
    const taken = new Set(session.responders.values());
    for (
        let responder = 0;
        responder < descriptor.participantCount;
        responder++
    ) {
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
        for (
            let offset = 4 + close.minimumResponseBodyBytes;
            offset + listedEntryBytes <= 4 + length;
            offset += listedEntryBytes
        ) {
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
            const submission = await readPublishedSubmission(
                descriptor,
                relay,
                readUnsigned16(response, offset),
            );
            if (
                submission !== undefined &&
                namesEnvelope(context, submission, identity)
            )
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

// Delivers the bodies the taken responses need and the organizer lacks.
const deliverWantedBodies = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const wanted = closeCommand(session.contribution.context, 13);
    for (let offset = 0; offset < wanted.length; offset += listedEntryBytes)
        await deliverBallot(
            session,
            relay,
            readUnsigned16(wanted, offset),
            wanted.slice(offset + 2, offset + listedEntryBytes),
        );
};

// This participant's one response. Its body and fresh coins enter the root
// before the signature exists; an interrupted signing must recompute the
// same body from the replayed log. The organizer then takes its own response
// and retains its proposal body and coins with it. Returns whether the
// organizer's proposal is prepared in this instance.
const respond = async (session: CloseSession) => {
    const { context } = session.contribution;
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
    const { context } = session.contribution;
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
        await deliverOwnBallot(session);
        for (const author of request.deliver)
            await deliverBallot(session, relay, author);
        for (const author of request.announce)
            await announceBallot(session, relay, author);
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
        const { close, registration } = session.contribution.context.descriptor;
        let intent: Uint8Array | undefined;
        try {
            intent = await readPublic(
                relay,
                closeDirectory + 'intent.bin',
                4 + close.intentBodyBytes + registration.signatureBytes,
            );
        } catch (error) {
            if (!(error instanceof PublicInputFailure)) throw error;
        }
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

// Retransmits the retained signed close messages.
export const publishClose = async (
    session: CloseSession,
    relay: PublicRelay,
) => {
    const generation = generationOf(session);
    const { state } = session;
    if (session.organizer && generation >= closePhase.locked)
        await publishRecord(
            relay,
            closeDirectory + 'intent.bin',
            state.intentPacket,
        );
    if (generation >= closePhase.responded)
        await publishRecord(
            relay,
            closeDirectory +
                'response-' +
                String(session.records.position) +
                '.bin',
            state.responsePacket,
        );
    if (generation === closePhase.proposed)
        await publishRecord(
            relay,
            closeDirectory + 'proposal.bin',
            state.proposalPacket,
        );
};

const kindNames = ['own', 'known', 'held', 'lock', 'response'];

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
