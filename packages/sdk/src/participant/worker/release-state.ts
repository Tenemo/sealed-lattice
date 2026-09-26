import {
    concatenate,
    encodeText,
    equalBytes,
    readUnsigned16,
    readUnsigned32,
    unsigned16,
    unsigned32,
} from './bytes.js';
import { completedClosePhase } from './close-state.js';
import type { ParticipantDescriptor } from './descriptor.js';
import type { ParticipantStoredRecord } from './predecessor.js';
import { recordKeyBytes, sealedLength } from './records.js';
import type { RecordContext } from './records.js';
import { targetPhase } from './target-state.js';

// The release suffix follows the signed target, or the completed close when
// the participant signed no target and a certificate already exists; the
// target field then stays empty. Generation 25 appends the
// journal of original random bytes one encrypted record per transition, and
// the append of its final record enters generation 26. Generation 27 retains
// the generated body's records and its envelope, 28 also the signing coins
// before the signature exists, and 29 the signature, retiring the journal.

export const releasePhase = {
    journal: 25,
    ready: 26,
    body: 27,
    intent: 28,
    signed: 29,
} as const;

// The release store holds journal records under kind zero and body records
// under kind one, each at [kind, index].
export const releaseRecordKind = { journal: 0, body: 1 } as const;

const marker = encodeText('RST1');
const prefixBytes = marker.length + 1 + 2 + 2 + 4 + 2;
const coinBytes = 32;

export type ReleaseState = Readonly<{
    // The signed-target or completed-close generation the release follows.
    predecessor: number;
    // The certified target body.
    target: Uint8Array;
    journalKeys: readonly Uint8Array[];
    bodyLength: number;
    bodyKeys: readonly Uint8Array[];
    envelope: Uint8Array;
    coins: Uint8Array;
    signature: Uint8Array;
}>;

const phaseOf = (generation: number) =>
    Math.min(generation, releasePhase.signed);

export const encodeReleaseState = (generation: number, state: ReleaseState) => {
    const phase = phaseOf(generation);
    return concatenate(
        marker,
        Uint8Array.of(state.predecessor),
        unsigned16(state.target.length),
        unsigned16(state.journalKeys.length),
        unsigned32(state.bodyLength),
        unsigned16(state.bodyKeys.length),
        state.target,
        ...state.journalKeys,
        ...state.bodyKeys,
        ...(phase >= releasePhase.body ? [state.envelope] : []),
        ...(phase === releasePhase.intent ? [state.coins] : []),
        ...(phase === releasePhase.signed ? [state.signature] : []),
    );
};

// The byte length of each record of one kind: whole records of the record
// size and a final partial one.
export const releaseRecordLengths = (
    descriptor: ParticipantDescriptor,
    totalBytes: number,
) => {
    const { recordBytes } = descriptor.release;
    return Array.from(
        { length: Math.ceil(totalBytes / recordBytes) },
        (_unused, index) =>
            Math.min(recordBytes, totalBytes - index * recordBytes),
    );
};

export const decodeReleaseState = (
    descriptor: ParticipantDescriptor,
    generation: number,
    organizer: boolean,
    bytes: Uint8Array,
): ReleaseState => {
    const bounds = descriptor.release;
    const phase = phaseOf(generation);
    if (
        generation < releasePhase.journal ||
        bytes.length < prefixBytes ||
        bytes.length > bounds.maximumStateBytes ||
        !equalBytes(bytes.subarray(0, marker.length), marker) ||
        (bytes[marker.length] !== targetPhase.signed &&
            bytes[marker.length] !== completedClosePhase(organizer))
    )
        throw new Error('The release state is malformed.');
    const targetLength = readUnsigned16(bytes, marker.length + 1);
    const journalCount = readUnsigned16(bytes, marker.length + 3);
    const bodyLength = readUnsigned32(bytes, marker.length + 5);
    const bodyCount = readUnsigned16(bytes, marker.length + 9);
    const journalExpected =
        phase === releasePhase.journal
            ? journalCount >= 1 && journalCount < bounds.journalRecords
            : journalCount ===
              (phase === releasePhase.signed ? 0 : bounds.journalRecords);
    const withBody = phase >= releasePhase.body;
    if (
        targetLength === 0 ||
        targetLength > descriptor.target.maximumBodyBytes ||
        !journalExpected ||
        (withBody
            ? bodyLength < bounds.minimumBodyBytes ||
              bodyLength > bounds.maximumBodyBytes ||
              bodyCount !== Math.ceil(bodyLength / bounds.recordBytes)
            : bodyLength !== 0 || bodyCount !== 0)
    )
        throw new Error('The release state has other counts.');
    const tail =
        (withBody ? bounds.envelopeBytes : 0) +
        (phase === releasePhase.intent ? coinBytes : 0) +
        (phase === releasePhase.signed
            ? descriptor.registration.signatureBytes
            : 0);
    const keysStart = prefixBytes + targetLength;
    const tailStart = keysStart + recordKeyBytes * (journalCount + bodyCount);
    if (bytes.length !== tailStart + tail)
        throw new Error('The release state has another length.');
    const keys = (start: number, count: number) =>
        Array.from({ length: count }, (_unused, index) =>
            bytes.slice(
                start + recordKeyBytes * index,
                start + recordKeyBytes * (index + 1),
            ),
        );
    const envelopeEnd = tailStart + (withBody ? bounds.envelopeBytes : 0);
    return {
        predecessor: bytes[marker.length],
        target: bytes.slice(prefixBytes, keysStart),
        journalKeys: keys(keysStart, journalCount),
        bodyLength,
        bodyKeys: keys(keysStart + recordKeyBytes * journalCount, bodyCount),
        envelope: bytes.slice(tailStart, envelopeEnd),
        coins:
            phase === releasePhase.intent
                ? bytes.slice(envelopeEnd)
                : new Uint8Array(),
        signature:
            phase === releasePhase.signed
                ? bytes.slice(envelopeEnd)
                : new Uint8Array(),
    };
};

// The associated data of one release record binds the participant's record
// context, the certified target's digest and the record's coordinates.
export const releaseRecordAssociatedData = (
    context: RecordContext,
    targetDigest: Uint8Array,
    kind: number,
    index: number,
    length: number,
) =>
    concatenate(
        encodeText('sealed-lattice/participant-release-record/v1'),
        context.poll,
        context.runtime,
        context.inventory,
        unsigned16(context.position),
        targetDigest,
        Uint8Array.of(kind),
        unsigned16(index),
        unsigned32(length),
    );

// The release records a state lists; the predecessor check opens each under
// its own key.
export const releaseRecordInventory = (
    descriptor: ParticipantDescriptor,
    context: RecordContext,
    targetDigest: Uint8Array,
    state: ReleaseState,
): ParticipantStoredRecord[] => {
    const kinds = [
        {
            kind: releaseRecordKind.journal,
            keys: state.journalKeys,
            lengths: releaseRecordLengths(
                descriptor,
                descriptor.release.journalBytes,
            ),
        },
        {
            kind: releaseRecordKind.body,
            keys: state.bodyKeys,
            lengths: releaseRecordLengths(descriptor, state.bodyLength),
        },
    ];
    return kinds.flatMap(({ kind, keys, lengths }) =>
        keys.map((key, index) => ({
            store: 'release',
            key: [kind, index],
            byteLength: sealedLength(lengths[index]),
            encryption: {
                key,
                additionalData: releaseRecordAssociatedData(
                    context,
                    targetDigest,
                    kind,
                    index,
                    lengths[index],
                ),
            },
        })),
    );
};
