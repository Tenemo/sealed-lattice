import { describe, expect, it } from 'vitest';

import {
    ballotRecordInventory,
    decodeBallotState,
    encodeBallotState,
} from '#packages/sdk/src/participant/worker/ballot-state.js';
import type { BallotState } from '#packages/sdk/src/participant/worker/ballot-state.js';
import {
    concatenate,
    encodeText,
    unsigned16,
    unsigned64,
} from '#packages/sdk/src/participant/worker/bytes.js';
import type { RecordContext } from '#packages/sdk/src/participant/worker/private-records.js';
import { ballotPhase } from '#packages/sdk/src/participant/worker/root-generation.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

const runtimeProfile = (participants: number, options: number) => {
    const profile = compileParticipantRuntimeProfile(participants, options);
    if (profile === undefined) throw new Error('Unsupported profile.');
    return profile;
};
const profile = runtimeProfile(3, 2);
const bounds = profile.ballot;

const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);
const keys = (count: number, first: number) =>
    Array.from({ length: count }, (_unused, index) =>
        filled(32, (first + index) % 256),
    );

const context: RecordContext = {
    poll: filled(64, 1),
    runtime: filled(64, 2),
    inventory: filled(64, 3),
    position: 2,
};
const ballotTime = 1_790_000_000_000n;

// An envelope whose context fields name the record context, the ballot time
// and the body length.
const envelopeFor = (
    envelopeBytes: number,
    records: RecordContext,
    bodyLength: number,
    time = ballotTime,
) => {
    const fields = concatenate(
        encodeText('LBE2'),
        records.poll,
        records.inventory,
        unsigned16(records.position),
        unsigned64(time),
        unsigned64(BigInt(bodyLength)),
    );
    return concatenate(fields, filled(envelopeBytes - fields.length, 9));
};

const bodyRecords = (recordBytes: number, length: number) =>
    Math.ceil(length / recordBytes);

// The state each phase retains for a body of the given length.
const stateAt = (
    phase: number,
    bodyLength: number,
    scores: Uint8Array = Uint8Array.of(
        bounds.minimumScore,
        bounds.maximumScore,
    ),
    ballot = bounds,
    signatureBytes = profile.registration.signatureBytes,
): BallotState => {
    const retained = phase >= ballotPhase.body;
    return {
        scores: phase === ballotPhase.signed ? new Uint8Array() : scores,
        ballotTime: phase === ballotPhase.signed ? 0n : ballotTime,
        seed: phase === ballotPhase.ready ? filled(64, 6) : new Uint8Array(),
        bodyLength: retained ? bodyLength : 0,
        bodyKeys: retained
            ? keys(bodyRecords(ballot.recordBytes, bodyLength), 200)
            : [],
        envelope: retained
            ? envelopeFor(ballot.envelopeBytes, context, bodyLength)
            : new Uint8Array(),

        signature:
            phase === ballotPhase.signed
                ? filled(signatureBytes, 4)
                : new Uint8Array(),
    };
};

const phases = Object.values(ballotPhase);
const decode = (generation: number, bytes: Uint8Array) =>
    decodeBallotState(profile, context, generation, bytes);

describe('participant ballot state', () => {
    it('round-trips every phase', () => {
        for (const phase of phases)
            for (const bodyLength of [
                bounds.minimumBodyBytes,
                bounds.maximumBodyBytes,
            ]) {
                const state = stateAt(phase, bodyLength);
                expect(decode(phase, encodeBallotState(phase, state))).toEqual(
                    state,
                );
            }
    });

    it('bounds each phase by the census', () => {
        // The census bounds every profile by twenty scores.
        const largest = runtimeProfile(20, 20);
        const custody = compileParticipantBallotCustody(
            deriveSupportedProfile(20, 20),
        );
        const { ballot } = largest;
        for (const { phase, bytes } of custody.phaseBytes)
            expect(
                encodeBallotState(
                    phase,
                    stateAt(
                        phase,
                        ballot.maximumBodyBytes,
                        filled(20, ballot.maximumScore),
                        ballot,
                        largest.registration.signatureBytes,
                    ),
                ).length,
            ).toBe(Number(bytes));
        expect(BigInt(ballot.maximumStateBytes)).toBe(
            custody.maximumStateBytes,
        );
    });

    it('refuses a state of another phase, shape or context', () => {
        const refused = (generation: number, bytes: Uint8Array) =>
            expect(() => decode(generation, bytes)).toThrow();
        const body = encodeBallotState(
            ballotPhase.body,
            stateAt(ballotPhase.body, bounds.minimumBodyBytes),
        );
        // Each phase carries its own fields.
        for (const phase of phases)
            if (phase !== ballotPhase.body) refused(phase, body);
        refused(ballotPhase.locked - 1, body);
        refused(ballotPhase.signed + 1, body);
        refused(ballotPhase.body, body.subarray(0, -1));
        refused(ballotPhase.body, Uint8Array.of(...body, 0));
        const marker = body.slice();
        marker[0] ^= 1;
        refused(ballotPhase.body, marker);
        // Scores are one valid score per option until the signed ballot
        // retires them.
        for (const scores of [
            Uint8Array.of(bounds.minimumScore),
            Uint8Array.of(bounds.minimumScore, bounds.maximumScore, 0),
            Uint8Array.of(bounds.minimumScore - 1, bounds.maximumScore),
            Uint8Array.of(bounds.minimumScore, bounds.maximumScore + 1),
        ])
            refused(
                ballotPhase.locked,
                encodeBallotState(ballotPhase.locked, {
                    ...stateAt(ballotPhase.locked, 0),
                    scores,
                }),
            );
        refused(
            ballotPhase.signed,
            encodeBallotState(ballotPhase.signed, {
                ...stateAt(ballotPhase.signed, bounds.minimumBodyBytes),
                scores: Uint8Array.of(bounds.minimumScore, bounds.minimumScore),
            }),
        );
        // Only the ready phase retains the seed, and it retains all of it.
        for (const phase of phases)
            refused(
                phase,
                encodeBallotState(phase, {
                    ...stateAt(phase, bounds.minimumBodyBytes),
                    seed:
                        phase === ballotPhase.ready
                            ? filled(63, 6)
                            : filled(64, 6),
                }),
            );
        // The body must fit its bounds and its record count.
        for (const bodyLength of [
            bounds.minimumBodyBytes - 1,
            bounds.maximumBodyBytes + 1,
        ])
            refused(
                ballotPhase.body,
                encodeBallotState(
                    ballotPhase.body,
                    stateAt(ballotPhase.body, bodyLength),
                ),
            );
        refused(
            ballotPhase.body,
            encodeBallotState(ballotPhase.body, {
                ...stateAt(ballotPhase.body, bounds.maximumBodyBytes),
                bodyKeys: keys(
                    bodyRecords(bounds.recordBytes, bounds.maximumBodyBytes) -
                        1,
                    9,
                ),
            }),
        );
        // The retained envelope names this poll, setup inventory, author,
        // ballot time and body length.
        const length = bounds.minimumBodyBytes;
        for (const envelope of [
            envelopeFor(
                bounds.envelopeBytes,
                {
                    ...context,
                    poll: filled(64, 7),
                },
                length,
            ),
            envelopeFor(
                bounds.envelopeBytes,
                {
                    ...context,
                    inventory: filled(64, 7),
                },
                length,
            ),
            envelopeFor(
                bounds.envelopeBytes,
                {
                    ...context,
                    position: 1,
                },
                length,
            ),
            envelopeFor(bounds.envelopeBytes, context, length, ballotTime + 1n),
            envelopeFor(bounds.envelopeBytes, context, length + 1),
        ])
            refused(
                ballotPhase.body,
                encodeBallotState(ballotPhase.body, {
                    ...stateAt(ballotPhase.body, length),
                    envelope,
                }),
            );
    });

    it('lists every body record under its own index, length and binding', () => {
        const state = stateAt(ballotPhase.body, bounds.maximumBodyBytes);
        const records = ballotRecordInventory(profile, context, state);
        expect(records.map((record) => record.key)).toEqual(
            state.bodyKeys.map((_key, index) => index),
        );
        const lengths = records.map((record) => record.byteLength - 16);
        expect(lengths.reduce((a, b) => a + b)).toBe(bounds.maximumBodyBytes);
        expect(
            lengths.slice(0, -1).every((value) => value === bounds.recordBytes),
        ).toBe(true);
        const binding = (listed: ReturnType<typeof ballotRecordInventory>) =>
            listed.map((record) =>
                Buffer.from(record.encryption!.additionalData).toString('hex'),
            );
        expect(new Set(binding(records)).size).toBe(records.length);
        // Another author's records are bound to its own position.
        const other = binding(
            ballotRecordInventory(profile, { ...context, position: 1 }, state),
        );
        for (const [index, value] of other.entries())
            expect(value).not.toBe(binding(records)[index]);
    });
});
