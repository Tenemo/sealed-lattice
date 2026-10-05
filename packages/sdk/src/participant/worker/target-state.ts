import type { ParticipantProfile } from './bounds.js';
import {
    concatenate,
    encodeText,
    equalBytes,
    readUnsigned16,
    unsigned16,
} from './bytes.js';
import { completedClosePhase } from './close-state.js';

// The target signing suffix follows the completed close: the participant's
// signed response, and for the organizer its signed proposal. Generation 23
// retains the exact evaluated target body, the own ballot's status in it and
// its signing intent before the signature exists; generation 24 retains the
// body, the status and the completed vote, which later generations keep
// unchanged.

export const targetPhase = { intent: 23, signed: 24 } as const;
const marker = encodeText('TST3');

// The own ballot's status in the target, by the finality work's code.
export const ballotStatuses = [
    'not cast',
    'late',
    'included',
    'omitted',
] as const;
export type BallotStatus = (typeof ballotStatuses)[number];

export type TargetState = Readonly<{
    // The close generation the target signing follows.
    predecessor: number;
    ballotStatus: BallotStatus;
    body: Uint8Array;

    vote: Uint8Array;
}>;

export const encodeTargetState = (generation: number, state: TargetState) =>
    concatenate(
        marker,
        Uint8Array.of(
            state.predecessor,
            ballotStatuses.indexOf(state.ballotStatus),
        ),
        unsigned16(state.body.length),
        state.body,
        generation === targetPhase.intent ? new Uint8Array() : state.vote,
    );

export const decodeTargetState = (
    profile: ParticipantProfile,
    generation: number,
    organizer: boolean,
    bytes: Uint8Array,
): TargetState => {
    const { maximumBodyBytes, votePacketBytes } = profile.target;
    const signed = generation >= targetPhase.signed;
    if (
        generation < targetPhase.intent ||
        bytes.length < marker.length + 4 ||
        !equalBytes(bytes.subarray(0, marker.length), marker) ||
        bytes[marker.length] !== completedClosePhase(organizer) ||
        bytes[marker.length + 1] >= ballotStatuses.length
    )
        throw new Error('The target state is malformed.');
    const length = readUnsigned16(bytes, marker.length + 2);
    const start = marker.length + 4;
    const tail = signed ? votePacketBytes : 0;
    if (
        length === 0 ||
        length > maximumBodyBytes ||
        bytes.length !== start + length + tail
    )
        throw new Error('The target state has another length.');
    const rest = bytes.slice(start + length);
    return {
        predecessor: bytes[marker.length],
        ballotStatus: ballotStatuses[bytes[marker.length + 1]],
        body: bytes.slice(start, start + length),
        vote: signed ? rest : new Uint8Array(),
    };
};
