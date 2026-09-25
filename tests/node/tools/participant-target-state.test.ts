import { describe, expect, it } from 'vitest';

import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';
import { completedClosePhase } from '#tools/ci/participant-runtime/close-state.js';
import {
    decodeTargetState,
    encodeTargetState,
    targetPhase,
} from '#tools/ci/participant-runtime/target-state.js';
import { deriveParticipantDescriptor } from '#tools/ci/participant-runtime-assembly.js';

const descriptor = deriveParticipantDescriptor(3, 2);
const census = compileTargetSigningStateCensus();

const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);

const state = (organizer: boolean, bodyLength: number) => ({
    predecessor: completedClosePhase(organizer),
    body: filled(bodyLength, 7),
    coins: filled(32, 9),
    vote: filled(descriptor.target.votePacketBytes, 11),
});

describe('participant target signing state', () => {
    it('round-trips both phases for both roles at the body bounds', () => {
        for (const organizer of [false, true])
            for (const bodyLength of [1, descriptor.target.maximumBodyBytes]) {
                const value = state(organizer, bodyLength);
                const intent = encodeTargetState(targetPhase.intent, value);
                expect(intent.length).toBe(
                    Number(census.prefixBytes) + bodyLength + 32,
                );
                expect(
                    decodeTargetState(
                        descriptor,
                        targetPhase.intent,
                        organizer,
                        intent,
                    ),
                ).toEqual({ ...value, vote: new Uint8Array() });
                const signed = encodeTargetState(targetPhase.signed, value);
                expect(signed.length).toBe(
                    Number(census.prefixBytes) +
                        bodyLength +
                        Number(census.packetBytes),
                );
                expect(
                    decodeTargetState(
                        descriptor,
                        targetPhase.signed,
                        organizer,
                        signed,
                    ),
                ).toEqual({ ...value, coins: new Uint8Array() });
            }
    });

    it('bounds the complete state by the census', () => {
        const largest = encodeTargetState(
            targetPhase.signed,
            state(true, descriptor.target.maximumBodyBytes),
        );
        expect(largest.length).toBe(descriptor.target.maximumStateBytes);
        expect(BigInt(descriptor.target.maximumStateBytes)).toBe(
            census.maximumStateBytes,
        );
    });

    it('refuses a state of another shape, role or phase', () => {
        const value = state(false, 40);
        const intent = encodeTargetState(targetPhase.intent, value);
        const signed = encodeTargetState(targetPhase.signed, value);
        const refused = (
            generation: number,
            organizer: boolean,
            bytes: Uint8Array,
        ) =>
            expect(() =>
                decodeTargetState(descriptor, generation, organizer, bytes),
            ).toThrow();
        // Each phase carries its own tail.
        refused(targetPhase.signed, false, intent);
        refused(targetPhase.intent, false, signed);
        // The organizer follows its signed proposal, not a response.
        refused(targetPhase.intent, true, intent);
        refused(targetPhase.intent - 1, false, intent);
        refused(targetPhase.intent, false, intent.subarray(0, -1));
        refused(targetPhase.intent, false, Uint8Array.of(...intent, 0));
        const marker = intent.slice();
        marker[0] ^= 1;
        refused(targetPhase.intent, false, marker);
        const empty = encodeTargetState(targetPhase.intent, state(false, 0));
        refused(targetPhase.intent, false, empty);
        const oversized = encodeTargetState(
            targetPhase.intent,
            state(false, descriptor.target.maximumBodyBytes + 1),
        );
        refused(targetPhase.intent, false, oversized);
    });
});
