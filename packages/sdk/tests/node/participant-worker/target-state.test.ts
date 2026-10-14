import { describe, expect, it } from 'vitest';

import {
    ballotInclusions,
    decodeTargetState,
    encodeTargetState,
} from '#packages/sdk/src/participant/worker/stages/target-vote/target-state.js';
import type { BallotInclusion } from '#packages/sdk/src/participant/worker/stages/target-vote/target-state.js';
import {
    completedClosePhase,
    targetPhase,
} from '#packages/sdk/src/participant/worker/storage/root-generation.js';
import { targetStateLayout } from '#packages/sdk/tests/node/participant-worker/stored-layouts.js';
import { expectEveryTruncationStops } from '#packages/sdk/tests/node/participant-worker/stored-state-refusal.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';

const profile = compileParticipantRuntimeProfile(3, 2);
const census = compileTargetSigningStateCensus();

const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);

const state = (
    isOrganizer: boolean,
    bodyLength: number,
    ballotInclusion: BallotInclusion = 'included',
) => ({
    predecessor: completedClosePhase(isOrganizer),
    ballotInclusion,
    body: filled(bodyLength, 7),

    vote: filled(profile.target.votePacketBytes, 11),
});

describe('participant target signing state', () => {
    it('round-trips both phases for both roles at the body bounds', () => {
        for (const isOrganizer of [false, true])
            for (const bodyLength of [1, profile.target.maximumBodyBytes]) {
                const value = state(isOrganizer, bodyLength);
                const intent = encodeTargetState(targetPhase.locked, value);
                expect(intent.length).toBe(
                    Number(census.prefixBytes) + bodyLength,
                );
                expect(
                    decodeTargetState(
                        profile,
                        targetPhase.locked,
                        isOrganizer,
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
                        isOrganizer,
                        signed,
                    ),
                ).toEqual(value);
                // Later generations keep the completed vote unchanged.
                expect(
                    decodeTargetState(
                        profile,
                        targetPhase.signed + 5,
                        isOrganizer,
                        signed,
                    ),
                ).toEqual(value);
            }
    });

    it('stops on every truncation of both phases', () => {
        for (const isOrganizer of [false, true])
            for (const phase of [targetPhase.locked, targetPhase.signed])
                expectEveryTruncationStops(
                    encodeTargetState(phase, state(isOrganizer, 1)),
                    (prefix) =>
                        decodeTargetState(profile, phase, isOrganizer, prefix),
                );
    });

    it('retains every own ballot inclusion through both phases', () => {
        for (const ballotInclusion of ballotInclusions) {
            const value = state(false, 40, ballotInclusion);
            for (const generation of [
                targetPhase.locked,
                targetPhase.signed,
                targetPhase.signed + 5,
            ])
                expect(
                    decodeTargetState(
                        profile,
                        generation,
                        false,
                        encodeTargetState(generation, value),
                    ).ballotInclusion,
                ).toBe(ballotInclusion);
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
        const intent = encodeTargetState(targetPhase.locked, value);
        const signed = encodeTargetState(targetPhase.signed, value);
        const refused = (
            generation: number,
            isOrganizer: boolean,
            bytes: Uint8Array,
        ) =>
            expect(() =>
                decodeTargetState(profile, generation, isOrganizer, bytes),
            ).toThrow();
        // Each phase carries its own tail.
        refused(targetPhase.signed, false, intent);
        refused(targetPhase.locked, false, signed);
        // The organizer follows its signed proposal, not a response.
        refused(targetPhase.locked, true, intent);
        refused(targetPhase.locked - 1, false, intent);
        refused(targetPhase.locked, false, intent.subarray(0, -1));
        refused(targetPhase.locked, false, Uint8Array.of(...intent, 0));
        const marker = intent.slice();
        marker[0] ^= 1;
        refused(targetPhase.locked, false, marker);
        // The state before the retained status is another shape.
        const unversioned = intent.slice();
        unversioned[3] = '1'.charCodeAt(0);
        refused(targetPhase.locked, false, unversioned);
        const unknownStatus = intent.slice();
        unknownStatus[5] = ballotInclusions.length;
        refused(targetPhase.locked, false, unknownStatus);
        const empty = encodeTargetState(targetPhase.locked, state(false, 0));
        refused(targetPhase.locked, false, empty);
        const oversized = encodeTargetState(
            targetPhase.locked,
            state(false, profile.target.maximumBodyBytes + 1),
        );
        refused(targetPhase.locked, false, oversized);
    });

    it('stores both phases for both roles and every status in its layout', () => {
        for (const isOrganizer of [false, true])
            for (const ballotInclusion of ballotInclusions) {
                const value = state(isOrganizer, 1, ballotInclusion);
                expect(
                    Buffer.from(encodeTargetState(targetPhase.locked, value)),
                ).toEqual(targetStateLayout({ ...value, vote: undefined }));
                expect(
                    Buffer.from(encodeTargetState(targetPhase.signed, value)),
                ).toEqual(targetStateLayout(value));
            }
    });
});
