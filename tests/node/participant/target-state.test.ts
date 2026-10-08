import { describe, expect, it } from 'vitest';

import { completedClosePhase } from '#packages/sdk/src/participant/worker/close-state.js';
import { targetPhase } from '#packages/sdk/src/participant/worker/root-generation.js';
import {
    ballotStatuses,
    decodeTargetState,
    encodeTargetState,
} from '#packages/sdk/src/participant/worker/target-state.js';
import type { BallotStatus } from '#packages/sdk/src/participant/worker/target-state.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';

const profile = compileParticipantRuntimeProfile(3, 2);
const census = compileTargetSigningStateCensus();

const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);

const state = (
    organizer: boolean,
    bodyLength: number,
    ballotStatus: BallotStatus = 'included',
) => ({
    predecessor: completedClosePhase(organizer),
    ballotStatus,
    body: filled(bodyLength, 7),

    vote: filled(profile.target.votePacketBytes, 11),
});

describe('participant target signing state', () => {
    it('round-trips both phases for both roles at the body bounds', () => {
        for (const organizer of [false, true])
            for (const bodyLength of [1, profile.target.maximumBodyBytes]) {
                const value = state(organizer, bodyLength);
                const intent = encodeTargetState(targetPhase.intent, value);
                expect(intent.length).toBe(
                    Number(census.prefixBytes) + bodyLength,
                );
                expect(
                    decodeTargetState(
                        profile,
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
                        profile,
                        targetPhase.signed,
                        organizer,
                        signed,
                    ),
                ).toEqual(value);
                // Later generations keep the completed vote unchanged.
                expect(
                    decodeTargetState(
                        profile,
                        targetPhase.signed + 5,
                        organizer,
                        signed,
                    ),
                ).toEqual(value);
            }
    });

    it('retains every own ballot status through both phases', () => {
        for (const ballotStatus of ballotStatuses) {
            const value = state(false, 40, ballotStatus);
            for (const generation of [
                targetPhase.intent,
                targetPhase.signed,
                targetPhase.signed + 5,
            ])
                expect(
                    decodeTargetState(
                        profile,
                        generation,
                        false,
                        encodeTargetState(generation, value),
                    ).ballotStatus,
                ).toBe(ballotStatus);
        }
    });

    it('bounds the complete state by the census', () => {
        const largest = encodeTargetState(
            targetPhase.signed,
            state(true, profile.target.maximumBodyBytes),
        );
        expect(largest.length).toBe(profile.target.maximumStateBytes);
        expect(BigInt(profile.target.maximumStateBytes)).toBe(
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
                decodeTargetState(profile, generation, organizer, bytes),
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
        // The state before the retained status is another shape.
        const unversioned = intent.slice();
        unversioned[3] = '1'.charCodeAt(0);
        refused(targetPhase.intent, false, unversioned);
        const unknownStatus = intent.slice();
        unknownStatus[5] = ballotStatuses.length;
        refused(targetPhase.intent, false, unknownStatus);
        const empty = encodeTargetState(targetPhase.intent, state(false, 0));
        refused(targetPhase.intent, false, empty);
        const oversized = encodeTargetState(
            targetPhase.intent,
            state(false, profile.target.maximumBodyBytes + 1),
        );
        refused(targetPhase.intent, false, oversized);
    });
});
