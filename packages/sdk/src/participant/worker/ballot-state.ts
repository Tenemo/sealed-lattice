import {
    concatenate,
    encodeText,
    equalBytes,
    readUnsigned16,
    readUnsigned32,
    readUnsigned64,
    unsigned16,
    unsigned32,
    unsigned64,
} from './bytes.js';
import { operationSeedBytes } from './participant-module.js';
import type { ParticipantStoredRecord } from './predecessor.js';
import { recordKeyBytes, sealedLength } from './private-records.js';
import type { RecordContext } from './private-records.js';
import { ballotPhase, isRootGeneration } from './root-generation.js';
import type { ParticipantProfile } from './runtime-bounds.js';

// A participant's ballot beneath its authenticated root. Generation 13 locks
// the attempt's scores and ballot time; generation 14 adds the seed of all
// the ballot's randomness before the module draws any. Generation 15 retains
// the envelope and every body record with one root, retiring the seed;
// that same transaction locks signing. Generation 17 retains the signature, retiring the
// scores. An interruption before the body is retained draws the same bytes
// from the seed again. Every root is sealed under a fresh key. A signed
// ballot stays retained unchanged through the later generations, and a
// participant without a ballot keeps an empty suffix.

const marker = encodeText('BST3');
const envelopeMarker = encodeText('LBE2');

export type BallotState = Readonly<{
    scores: Uint8Array;
    ballotTime: bigint;
    seed: Uint8Array;
    bodyLength: number;
    bodyKeys: readonly Uint8Array[];
    envelope: Uint8Array;

    signature: Uint8Array;
}>;

// Whether the scores are one valid score per option.
export const validBallotScores = (
    profile: ParticipantProfile,
    scores: Uint8Array,
) =>
    scores.length === profile.optionCount &&
    scores.every(
        (score) =>
            score >= profile.ballot.minimumScore &&
            score <= profile.ballot.maximumScore,
    );

// The length of the body record at the index.
export const ballotRecordLength = (
    profile: ParticipantProfile,
    state: BallotState,
    index: number,
) =>
    Math.min(
        profile.ballot.recordBytes,
        state.bodyLength - index * profile.ballot.recordBytes,
    );

export const encodeBallotState = (generation: number, state: BallotState) =>
    concatenate(
        marker,
        Uint8Array.of(state.scores.length),
        state.scores,
        generation < ballotPhase.signed
            ? unsigned64(state.ballotTime)
            : new Uint8Array(),
        state.seed,
        unsigned32(state.bodyLength),
        unsigned16(state.bodyKeys.length),
        ...state.bodyKeys,
        state.envelope,

        state.signature,
    );

// The envelope's context fields at their offsets: the poll, the setup
// identity, the author's position, the ballot time and the body length.
export const ballotEnvelopeMatches = (
    envelope: Uint8Array,
    context: RecordContext,
    bodyLength: number,
    ballotTime?: bigint,
) =>
    equalBytes(envelope.subarray(0, 4), envelopeMarker) &&
    equalBytes(envelope.subarray(4, 68), context.poll) &&
    equalBytes(envelope.subarray(68, 132), context.setupIdentity) &&
    readUnsigned16(envelope, 132) === context.position &&
    (ballotTime === undefined ||
        readUnsigned64(envelope, 134) === ballotTime) &&
    readUnsigned64(envelope, 142) === BigInt(bodyLength);

// Decodes the ballot suffix under the phase its root generation supplies;
// each phase has exactly one shape.
export const decodeBallotState = (
    profile: ParticipantProfile,
    context: RecordContext,
    generation: number,
    bytes: Uint8Array,
): BallotState => {
    const bounds = profile.ballot;
    if (
        generation < ballotPhase.locked ||
        generation > ballotPhase.signed ||
        !isRootGeneration(generation) ||
        bytes.length > bounds.maximumStateBytes ||
        !equalBytes(bytes.subarray(0, marker.length), marker)
    )
        throw new Error('The ballot state is malformed.');
    let offset = marker.length;
    const take = (length: number) => {
        if (length > bytes.length - offset)
            throw new Error('The ballot state is truncated.');
        const value = bytes.slice(offset, offset + length);
        offset += length;
        return value;
    };
    const scores = take(take(1)[0]);
    if (
        generation === ballotPhase.signed
            ? scores.length !== 0
            : !validBallotScores(profile, scores)
    )
        throw new Error('The locked scores changed.');
    const ballotTime =
        generation === ballotPhase.signed ? 0n : readUnsigned64(take(8), 0);
    const seed = take(
        generation === ballotPhase.ready ? operationSeedBytes : 0,
    );
    const bodyLength = readUnsigned32(take(4), 0);
    const bodyCount = readUnsigned16(take(2), 0);
    const bodyRecords = Math.ceil(bodyLength / bounds.recordBytes);
    if (
        generation < ballotPhase.body
            ? bodyLength !== 0 || bodyCount !== 0
            : bodyLength < bounds.minimumBodyBytes ||
              bodyLength > bounds.maximumBodyBytes ||
              bodyCount !== bodyRecords
    )
        throw new Error('The retained ballot body is inconsistent.');
    const bodyKeys = Array.from({ length: bodyCount }, () =>
        take(recordKeyBytes),
    );
    const envelope =
        generation >= ballotPhase.body
            ? take(bounds.envelopeBytes)
            : new Uint8Array();
    const signature =
        generation === ballotPhase.signed
            ? take(profile.registration.signatureBytes)
            : new Uint8Array();
    if (offset !== bytes.length)
        throw new Error('The ballot state has extra bytes.');
    if (
        generation >= ballotPhase.body &&
        !ballotEnvelopeMatches(
            envelope,
            context,
            bodyLength,
            generation === ballotPhase.signed ? undefined : ballotTime,
        )
    )
        throw new Error('The retained envelope changed its context.');
    return {
        scores,
        ballotTime,
        seed,
        bodyLength,
        bodyKeys,
        envelope,

        signature,
    };
};

// A body record is stored under its index and bound to its length.
export const ballotRecordAssociatedData = (
    context: RecordContext,
    index: number,
    length: number,
) =>
    concatenate(
        encodeText('sealed-lattice/participant-ballot-record/v2'),
        context.poll,
        context.runtime,
        context.setupIdentity,
        unsigned16(context.position),
        unsigned16(index),
        unsigned32(length),
    );

// The ballot records a state lists; the predecessor check opens each under
// its own key.
export const ballotRecordInventory = (
    profile: ParticipantProfile,
    records: RecordContext,
    state: BallotState,
): ParticipantStoredRecord[] =>
    state.bodyKeys.map((key, index) => {
        const length = ballotRecordLength(profile, state, index);
        return {
            store: 'ballot',
            key: index,
            byteLength: sealedLength(length),
            encryption: {
                key,
                additionalData: ballotRecordAssociatedData(
                    records,
                    index,
                    length,
                ),
            },
        };
    });
