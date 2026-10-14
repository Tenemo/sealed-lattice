import type { ParticipantProfile } from '../../module/runtime-bounds.js';
import { targetPrefixBytes } from '../../module/runtime-bounds.js';
import { concatenate, readUnsigned16, unsigned16 } from '../../shared/bytes.js';
import {
    completedClosePhase,
    targetPhase,
} from '../../storage/root-generation.js';

// The target signing suffix follows the completed close: the participant's
// signed response, and for the organizer its signed proposal. Generation 23
// retains the exact evaluated target body, the own ballot's status in it and
// its signing intent before the signature exists; generation 24 retains the
// body, the status and the completed vote, which later generations keep
// unchanged.

// The own ballot's status in the target, by the finality work's code.
export const ballotInclusions = [
    'not cast',
    'late',
    'included',
    'omitted',
] as const;
export type BallotInclusion = (typeof ballotInclusions)[number];

export type TargetState = Readonly<{
    // The close generation the target signing follows.
    predecessor: number;
    ballotInclusion: BallotInclusion;
    body: Uint8Array;

    vote: Uint8Array;
}>;

export const encodeTargetState = (generation: number, state: TargetState) =>
    concatenate(
        Uint8Array.of(
            state.predecessor,
            ballotInclusions.indexOf(state.ballotInclusion),
        ),
        unsigned16(state.body.length),
        state.body,
        generation === targetPhase.locked ? new Uint8Array() : state.vote,
    );

export const decodeTargetState = (
    profile: ParticipantProfile,
    generation: number,
    isOrganizer: boolean,
    bytes: Uint8Array,
): TargetState => {
    const { maximumBodyBytes, votePacketBytes } = profile.target;
    const signed = generation >= targetPhase.signed;
    if (
        generation < targetPhase.locked ||
        bytes.length < targetPrefixBytes ||
        bytes[0] !== completedClosePhase(isOrganizer) ||
        bytes[1] >= ballotInclusions.length
    )
        throw new Error('The target state is malformed.');
    const length = readUnsigned16(bytes, 2);
    const start = targetPrefixBytes;
    const tail = signed ? votePacketBytes : 0;
    if (
        length === 0 ||
        length > maximumBodyBytes ||
        bytes.length !== start + length + tail
    )
        throw new Error('The target state has another length.');
    const rest = bytes.slice(start + length);
    return {
        predecessor: bytes[0],
        ballotInclusion: ballotInclusions[bytes[1]],
        body: bytes.slice(start, start + length),
        vote: signed ? rest : new Uint8Array(),
    };
};
