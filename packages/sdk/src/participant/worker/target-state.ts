import {
    concatenate,
    encodeText,
    equalBytes,
    readUnsigned16,
    unsigned16,
} from './bytes.js';
import { completedClosePhase } from './close-state.js';
import type { ParticipantDescriptor } from './descriptor.js';

// The target signing suffix follows the completed close: the participant's
// signed response, and for the organizer its signed proposal. Generation 23
// retains the exact evaluated target body and the signing coins before the
// signature exists; generation 24 retains the body and the completed vote,
// which later generations keep unchanged.

export const targetPhase = { intent: 23, signed: 24 } as const;
const marker = encodeText('TST1');
const coinBytes = 32;

export type TargetState = Readonly<{
    // The close generation the target signing follows.
    predecessor: number;
    body: Uint8Array;
    coins: Uint8Array;
    vote: Uint8Array;
}>;

export const encodeTargetState = (generation: number, state: TargetState) =>
    concatenate(
        marker,
        Uint8Array.of(state.predecessor),
        unsigned16(state.body.length),
        state.body,
        generation === targetPhase.intent ? state.coins : state.vote,
    );

export const decodeTargetState = (
    descriptor: ParticipantDescriptor,
    generation: number,
    organizer: boolean,
    bytes: Uint8Array,
): TargetState => {
    const { maximumBodyBytes, votePacketBytes } = descriptor.target;
    const signed = generation >= targetPhase.signed;
    if (
        generation < targetPhase.intent ||
        bytes.length < marker.length + 3 ||
        !equalBytes(bytes.subarray(0, marker.length), marker) ||
        bytes[marker.length] !== completedClosePhase(organizer)
    )
        throw new Error('The target state is malformed.');
    const length = readUnsigned16(bytes, marker.length + 1);
    const start = marker.length + 3;
    const tail = signed ? votePacketBytes : coinBytes;
    if (
        length === 0 ||
        length > maximumBodyBytes ||
        bytes.length !== start + length + tail
    )
        throw new Error('The target state has another length.');
    const rest = bytes.slice(start + length);
    return {
        predecessor: bytes[marker.length],
        body: bytes.slice(start, start + length),
        coins: signed ? new Uint8Array() : rest,
        vote: signed ? rest : new Uint8Array(),
    };
};
