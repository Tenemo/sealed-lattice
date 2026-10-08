import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { completedClosePhase } from '#packages/sdk/src/participant/worker/close-state.js';
import { targetPhase } from '#packages/sdk/src/participant/worker/root-generation.js';
import {
    ballotInclusions,
    decodeTargetState,
    encodeTargetState,
} from '#packages/sdk/src/participant/worker/target-state.js';
import type { BallotInclusion } from '#packages/sdk/src/participant/worker/target-state.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import { compileTargetSigningStateCensus } from '#tests/target-signing-state-model.js';

// The SHA-256 digest of stored bytes, which pins their exact format.
const storedDigest = (bytes: Uint8Array) =>
    createHash('sha256').update(bytes).digest('hex');

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
                const intent = encodeTargetState(targetPhase.intent, value);
                expect(intent.length).toBe(
                    Number(census.prefixBytes) + bodyLength,
                );
                expect(
                    decodeTargetState(
                        profile,
                        targetPhase.intent,
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

    it('retains every own ballot status through both phases', () => {
        for (const ballotInclusion of ballotInclusions) {
            const value = state(false, 40, ballotInclusion);
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
        const intent = encodeTargetState(targetPhase.intent, value);
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
        unknownStatus[5] = ballotInclusions.length;
        refused(targetPhase.intent, false, unknownStatus);
        const empty = encodeTargetState(targetPhase.intent, state(false, 0));
        refused(targetPhase.intent, false, empty);
        const oversized = encodeTargetState(
            targetPhase.intent,
            state(false, profile.target.maximumBodyBytes + 1),
        );
        refused(targetPhase.intent, false, oversized);
    });

    it('pins the bytes both phases store for both roles', () => {
        expect(
            [false, true].flatMap((isOrganizer) =>
                [targetPhase.intent, targetPhase.signed].map((phase) =>
                    storedDigest(
                        encodeTargetState(phase, state(isOrganizer, 1)),
                    ),
                ),
            ),
        ).toEqual([
            '53e4ef42312e6eec3c33fe66ccbe9b0e62c26f60f3d22c80bd8bb75c4052590d',
            '30757a8897523115fee6c082ee25cbe0e6a8a12fbec4321c6a59c21e52876a08',
            '8ea12efe2c1d3334de605952118a524717c6fdf075f9c3e182428d96f72fe0e9',
            '8c3594d5bedc1000449b42a45cdc047d3f93b2e4dbc870599ce89d2da05aba7b',
        ]);
    });
});
