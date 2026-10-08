import type { ParticipantProfile } from '../../module/runtime-bounds.js';
import { recordKeyBytes } from '../../module/runtime-bounds.js';
import {
    concatenate,
    encodeText,
    equalBytes,
    readUnsigned16,
    readUnsigned32,
    unsigned16,
    unsigned32,
} from '../../shared/bytes.js';
import type { ParticipantStoredRecord } from '../../storage/predecessor.js';
import { sealedLength } from '../../storage/private-records.js';
import type { RecordContext } from '../../storage/private-records.js';
import { closePhase, rootGeneration } from '../../storage/root-generation.js';

// The close log beneath the authenticated root. It retains every close input
// the participant's state machine accepted, in arrival order, so restoration
// replays them into the same state. An event holds its kind, its record
// count, the serial its records are stored under, its payload length and one
// key per record. Before an intent the log only collects, alongside every
// ballot phase. Generation 18 retains the organizer's intent exact body,
// 19 the locked intent, 20 the response exact body, 21 the signed
// response and, for the organizer, its proposal exact body, and 22 the
// organizer's signed proposal. No event is added from generation 20 on, and
// later generations keep the completed close unchanged.

const marker = encodeText('CST2');

const eventHeaderBytes = 1 + 2 + 4 + 4;

// The participant's own signed ballot and the locked intent reference other
// retained state and add no record. A held body has one record with its
// envelope and signature and then its body records; a response the
// organizer takes one record with the packet and the envelopes delivered
// with it.
export const closeEventKind = {
    own: 0,
    held: 1,
    lock: 2,
    response: 3,
} as const;

export type CloseEvent = Readonly<{
    kind: number;
    serial: number;
    length: number;
    keys: readonly Uint8Array[];
}>;

export type CloseState = Readonly<{
    events: readonly CloseEvent[];
    intentBody: Uint8Array;
    intentPacket: Uint8Array;
    responseBody: Uint8Array;
    responsePacket: Uint8Array;
    proposalBody: Uint8Array;
    proposalPacket: Uint8Array;
}>;

export const collectingCloseState = (): CloseState => ({
    events: [],
    intentBody: new Uint8Array(),
    intentPacket: new Uint8Array(),
    responseBody: new Uint8Array(),
    responsePacket: new Uint8Array(),
    proposalBody: new Uint8Array(),
    proposalPacket: new Uint8Array(),
});

// The completed close of a participant: its signed response, and for the
// organizer its signed proposal.
export const completedClosePhase = (isOrganizer: boolean) =>
    isOrganizer ? closePhase.proposed : closePhase.responded;

// The close phase a root generation supplies: zero while the log collects,
// and the completed close after it.
const phaseOf = (generation: number, isOrganizer: boolean) => {
    if (generation > closePhase.proposed)
        return completedClosePhase(isOrganizer);
    return generation >= closePhase.intent ? generation : 0;
};

// The fields each phase retains after the events.
const phaseFields = (
    phase: number,
    isOrganizer: boolean,
    state: CloseState,
) => {
    switch (phase) {
        case closePhase.intent:
            return [state.intentBody];
        case closePhase.locked:
            return [state.intentPacket];
        case closePhase.responding:
            return [
                state.intentPacket,
                unsigned32(state.responseBody.length),
                state.responseBody,
            ];
        case closePhase.responded:
            return isOrganizer
                ? [state.intentPacket, state.responsePacket, state.proposalBody]
                : [state.intentPacket, state.responsePacket];
        case closePhase.proposed:
            return [
                state.intentPacket,
                state.responsePacket,
                state.proposalPacket,
            ];
        default:
            return [];
    }
};

export const encodeCloseState = (
    generation: number,
    isOrganizer: boolean,
    state: CloseState,
) =>
    concatenate(
        marker,
        unsigned32(state.events.length),
        ...state.events.flatMap((event) => [
            Uint8Array.of(event.kind),
            unsigned16(event.keys.length),
            unsigned32(event.serial),
            unsigned32(event.length),
            ...event.keys,
        ]),
        ...phaseFields(phaseOf(generation, isOrganizer), isOrganizer, state),
    );

// The plaintext length of each record of an event, in record order.
export const closeRecordLengths = (
    profile: ParticipantProfile,
    event: CloseEvent,
) => {
    const { submissionBytes } = profile.close;
    const { recordBytes } = profile.ballot;
    if (event.kind === closeEventKind.held)
        return [
            submissionBytes,
            ...Array.from({ length: event.keys.length - 1 }, (_unused, index) =>
                Math.min(recordBytes, event.length - index * recordBytes),
            ),
        ];
    if (event.kind === closeEventKind.response) return [event.length];
    return [];
};

const validEvent = (profile: ParticipantProfile, event: CloseEvent) => {
    const { close, ballot, registration } = profile;
    const count = event.keys.length;
    switch (event.kind) {
        case closeEventKind.own:
        case closeEventKind.lock:
            return count === 0 && event.length === 0;
        case closeEventKind.held:
            return (
                event.length >= ballot.minimumBodyBytes &&
                event.length <= ballot.maximumBodyBytes &&
                count === 1 + Math.ceil(event.length / ballot.recordBytes)
            );
        case closeEventKind.response:
            return (
                count === 1 &&
                event.length >=
                    4 +
                        close.minimumResponseBodyBytes +
                        registration.signatureBytes &&
                event.length <= close.maximumResponseRecordBytes
            );
        default:
            return false;
    }
};

// A length-prefixed signed packet whose body length lies in the bounds.
const packetLength = (
    bytes: Uint8Array,
    offset: number,
    minimum: number,
    maximum: number,
    signatureBytes: number,
) => {
    if (bytes.length - offset < 4)
        throw new Error('The close state is truncated.');
    const length = readUnsigned32(bytes, offset);
    if (length < minimum || length > maximum)
        throw new Error('A retained close packet has another length.');
    return 4 + length + signatureBytes;
};

// Decodes the close log under the phase its root generation supplies. The
// events must keep their serials ascending, the lock must be present exactly
// from generation 19, only the organizer may take responses and only after
// the lock, and only the organizer's phases may carry its intent signing and
// proposal.
export const decodeCloseState = (
    profile: ParticipantProfile,
    generation: number,
    isOrganizer: boolean,
    bytes: Uint8Array,
): CloseState => {
    const { close, registration } = profile;
    const phase = phaseOf(generation, isOrganizer);
    if (
        generation < rootGeneration.setupRetained ||
        (!isOrganizer &&
            (phase === closePhase.intent || phase === closePhase.proposed)) ||
        bytes.length > close.maximumStateBytes ||
        !equalBytes(bytes.subarray(0, marker.length), marker)
    )
        throw new Error('The close state is malformed.');
    let offset = marker.length;
    const take = (length: number) => {
        if (length > bytes.length - offset)
            throw new Error('The close state is truncated.');
        const value = bytes.slice(offset, offset + length);
        offset += length;
        return value;
    };
    const eventCount = readUnsigned32(take(4), 0);
    if (eventCount > close.maximumEvents)
        throw new Error('The close log has too many events.');
    const events: CloseEvent[] = [];
    let records = 0;
    let locked = false;
    for (let index = 0; index < eventCount; index++) {
        const header = take(eventHeaderBytes);
        const kind = header[0];
        const count = readUnsigned16(header, 1);
        const serial = readUnsigned32(header, 3);
        const length = readUnsigned32(header, 7);
        records += count;
        if (records > close.maximumRecords)
            throw new Error('The close log has too many records.');
        const event = {
            kind,
            serial,
            length,
            keys: Array.from({ length: count }, () => take(recordKeyBytes)),
        };
        if (
            !validEvent(profile, event) ||
            (events.length > 0 && serial <= events[events.length - 1].serial) ||
            (kind === closeEventKind.lock && locked) ||
            (kind === closeEventKind.response && (!isOrganizer || !locked))
        )
            throw new Error('The close log is inconsistent.');
        if (kind === closeEventKind.lock) locked = true;
        events.push(event);
    }
    if (locked !== phase >= closePhase.locked)
        throw new Error('The close log disagrees with its intent lock.');
    const signature = registration.signatureBytes;
    const intentPacketBytes = 4 + close.intentBodyBytes + signature;
    const state = { ...collectingCloseState(), events };
    let result: CloseState = state;
    if (phase === closePhase.intent)
        result = {
            ...state,
            intentBody: take(close.intentBodyBytes),
        };
    else if (phase >= closePhase.locked) {
        const intentPacket = take(intentPacketBytes);
        if (readUnsigned32(intentPacket, 0) !== close.intentBodyBytes)
            throw new Error('The locked intent has another length.');
        result = { ...state, intentPacket };
        if (phase === closePhase.responding) {
            const length = readUnsigned32(take(4), 0);
            if (
                length < close.minimumResponseBodyBytes ||
                length > close.maximumResponseBodyBytes
            )
                throw new Error('The response body has another length.');
            result = {
                ...result,
                responseBody: take(length),
            };
        } else if (phase >= closePhase.responded) {
            const responsePacket = take(
                packetLength(
                    bytes,
                    offset,
                    close.minimumResponseBodyBytes,
                    close.maximumResponseBodyBytes,
                    signature,
                ),
            );
            result = { ...result, responsePacket };
            if (isOrganizer && phase === closePhase.responded)
                result = {
                    ...result,
                    proposalBody: take(close.proposalBodyBytes),
                };
            else if (phase === closePhase.proposed) {
                const proposalPacket = take(
                    4 + close.proposalBodyBytes + signature,
                );
                if (
                    readUnsigned32(proposalPacket, 0) !==
                    close.proposalBodyBytes
                )
                    throw new Error('The proposal has another length.');
                result = { ...result, proposalPacket };
            }
        }
    }
    if (offset !== bytes.length)
        throw new Error('The close state has extra bytes.');
    return result;
};

export const closeRecordAssociatedData = (
    context: RecordContext,
    event: Readonly<{ kind: number; serial: number }>,
    index: number,
    length: number,
) =>
    concatenate(
        encodeText('sealed-lattice/participant-close-record/v1'),
        context.poll,
        context.runtime,
        context.setupIdentity,
        unsigned16(context.position),
        Uint8Array.of(event.kind),
        unsigned32(event.serial),
        unsigned16(index),
        unsigned32(length),
    );

// The close records a log lists, each at [serial, index]; the predecessor
// check opens each under its own key.
export const closeRecordInventory = (
    profile: ParticipantProfile,
    context: RecordContext,
    state: CloseState,
): ParticipantStoredRecord[] =>
    state.events.flatMap((event) =>
        closeRecordLengths(profile, event).map((length, index) => ({
            store: 'close',
            key: [event.serial, index],
            byteLength: sealedLength(length),
            encryption: {
                key: event.keys[index],
                additionalData: closeRecordAssociatedData(
                    context,
                    event,
                    index,
                    length,
                ),
            },
        })),
    );
