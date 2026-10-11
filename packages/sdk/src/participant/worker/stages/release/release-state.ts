import { operationSeedBytes } from '../../module/participant-module.js';
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
import {
    isRootGeneration,
    releasePhase,
    targetPhase,
} from '../../storage/root-generation.js';
import { completedClosePhase } from '../close/close-state.js';
import { ballotInclusions } from '../target-vote/target-state.js';
import type { BallotInclusion } from '../target-vote/target-state.js';

// The release suffix follows the signed target, or the completed close when
// the participant signed no target and a certificate already exists; the
// target field then stays empty. Generation 25 locks the certified target
// and the own ballot's status in it, and generation 26 adds the seed of all
// the release's randomness before any private generation. Generation 27
// retains the generated body's records and its envelope, retiring the seed;
// that same transaction locks signing, and generation 29 retains the
// signature.

const marker = encodeText('RST4');
const prefixBytes = marker.length + 2 + 2 + 4 + 2;

export type ReleaseState = Readonly<{
    // The signed-target or completed-close generation the release follows.
    predecessor: number;
    // The own ballot's status in the certified target.
    ballotInclusion: BallotInclusion;
    // The certified target body.
    target: Uint8Array;
    // The randomness seed, retained only until the body is.
    seed: Uint8Array;
    bodyLength: number;
    bodyKeys: readonly Uint8Array[];
    envelope: Uint8Array;

    signature: Uint8Array;
}>;

const phaseOf = (generation: number) =>
    Math.min(generation, releasePhase.signed);

export const encodeReleaseState = (generation: number, state: ReleaseState) => {
    const phase = phaseOf(generation);
    return concatenate(
        marker,
        Uint8Array.of(
            state.predecessor,
            ballotInclusions.indexOf(state.ballotInclusion),
        ),
        unsigned16(state.target.length),
        unsigned32(state.bodyLength),
        unsigned16(state.bodyKeys.length),
        state.target,
        state.seed,
        ...state.bodyKeys,
        ...(phase >= releasePhase.body ? [state.envelope] : []),
        ...(phase === releasePhase.signed ? [state.signature] : []),
    );
};

// The byte length of each body record: whole records of the record size and
// a final partial one.
export const releaseRecordLengths = (
    profile: ParticipantProfile,
    totalBytes: number,
) => {
    const { recordBytes } = profile.release;
    return Array.from(
        { length: Math.ceil(totalBytes / recordBytes) },
        (_unused, index) =>
            Math.min(recordBytes, totalBytes - index * recordBytes),
    );
};

export const decodeReleaseState = (
    profile: ParticipantProfile,
    generation: number,
    isOrganizer: boolean,
    bytes: Uint8Array,
): ReleaseState => {
    const bounds = profile.release;
    const phase = phaseOf(generation);
    if (
        generation < releasePhase.locked ||
        !isRootGeneration(generation) ||
        bytes.length < prefixBytes ||
        bytes.length > bounds.maximumStateBytes ||
        !equalBytes(bytes.subarray(0, marker.length), marker) ||
        (bytes[marker.length] !== targetPhase.signed &&
            bytes[marker.length] !== completedClosePhase(isOrganizer)) ||
        bytes[marker.length + 1] >= ballotInclusions.length
    )
        throw new Error('The release state is malformed.');
    const targetLength = readUnsigned16(bytes, marker.length + 2);
    const bodyLength = readUnsigned32(bytes, marker.length + 4);
    const bodyCount = readUnsigned16(bytes, marker.length + 8);
    const seedLength = phase === releasePhase.ready ? operationSeedBytes : 0;
    const withBody = phase >= releasePhase.body;
    if (
        targetLength === 0 ||
        targetLength > profile.target.maximumBodyBytes ||
        (withBody
            ? bodyLength < bounds.minimumBodyBytes ||
              bodyLength > bounds.maximumBodyBytes ||
              bodyCount !== Math.ceil(bodyLength / bounds.recordBytes)
            : bodyLength !== 0 || bodyCount !== 0)
    )
        throw new Error('The release state has other counts.');
    const tail =
        (withBody ? bounds.envelopeBytes : 0) +
        (phase === releasePhase.signed
            ? profile.registration.signatureBytes
            : 0);
    const seedStart = prefixBytes + targetLength;
    const keysStart = seedStart + seedLength;
    const tailStart = keysStart + recordKeyBytes * bodyCount;
    if (bytes.length !== tailStart + tail)
        throw new Error('The release state has another length.');
    const envelopeEnd = tailStart + (withBody ? bounds.envelopeBytes : 0);
    return {
        predecessor: bytes[marker.length],
        ballotInclusion: ballotInclusions[bytes[marker.length + 1]],
        target: bytes.slice(prefixBytes, seedStart),
        seed: bytes.slice(seedStart, keysStart),
        bodyLength,
        bodyKeys: Array.from({ length: bodyCount }, (_unused, index) =>
            bytes.slice(
                keysStart + recordKeyBytes * index,
                keysStart + recordKeyBytes * (index + 1),
            ),
        ),
        envelope: bytes.slice(tailStart, envelopeEnd),
        signature:
            phase === releasePhase.signed
                ? bytes.slice(envelopeEnd)
                : new Uint8Array(),
    };
};

// The associated data of one body record, stored under its index, binds the
// participant's record context, the certified target's digest and the
// record's index and length.
export const releaseRecordAssociatedData = (
    context: RecordContext,
    targetDigest: Uint8Array,
    index: number,
    length: number,
) =>
    concatenate(
        encodeText('sealed-lattice/participant-release-record/v3'),
        context.poll,
        context.setupIdentity,
        unsigned16(context.position),
        targetDigest,
        unsigned16(index),
        unsigned32(length),
    );

// The release records a state lists; the predecessor check opens each under
// its own key.
export const releaseRecordInventory = (
    profile: ParticipantProfile,
    context: RecordContext,
    targetDigest: Uint8Array,
    state: ReleaseState,
): ParticipantStoredRecord[] => {
    const lengths = releaseRecordLengths(profile, state.bodyLength);
    return state.bodyKeys.map((key, index) => ({
        store: 'release',
        key: index,
        byteLength: sealedLength(lengths[index]),
        encryption: {
            key,
            additionalData: releaseRecordAssociatedData(
                context,
                targetDigest,
                index,
                lengths[index],
            ),
        },
    }));
};
