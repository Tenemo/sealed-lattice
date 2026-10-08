import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { completedClosePhase } from '#packages/sdk/src/participant/worker/stages/close/close-state.js';
import {
    decodeReleaseState,
    encodeReleaseState,
    releaseRecordInventory,
    releaseRecordLengths,
} from '#packages/sdk/src/participant/worker/stages/release/release-state.js';
import type { ReleaseState } from '#packages/sdk/src/participant/worker/stages/release/release-state.js';
import { ballotInclusions } from '#packages/sdk/src/participant/worker/stages/target-vote/target-state.js';
import type { BallotInclusion } from '#packages/sdk/src/participant/worker/stages/target-vote/target-state.js';
import {
    releasePhase,
    targetPhase,
} from '#packages/sdk/src/participant/worker/storage/root-generation.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileParticipantRuntimeProfile } from '#tests/participant-runtime-bounds-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

// The SHA-256 digest of stored bytes, which pins their exact format.
const storedDigest = (bytes: Uint8Array) =>
    createHash('sha256').update(bytes).digest('hex');

const profile = compileParticipantRuntimeProfile(3, 2);
const bounds = profile.release;
const custody = compileParticipantReleaseCustody(deriveSupportedProfile(3, 2));

const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);
const keys = (count: number, first: number) =>
    Array.from({ length: count }, (_unused, index) =>
        filled(32, (first + index) % 256),
    );

const bodyRecords = (length: number) => Math.ceil(length / bounds.recordBytes);

// The state each phase retains for a target and body of the given lengths.
const stateAt = (
    phase: number,
    targetLength: number,
    bodyLength: number,
    predecessor: number = targetPhase.signed,
    ballotInclusion: BallotInclusion = 'included',
): ReleaseState => ({
    predecessor,
    ballotInclusion,
    target: filled(targetLength, 5),
    seed: phase === releasePhase.ready ? filled(64, 6) : new Uint8Array(),
    bodyLength: phase >= releasePhase.body ? bodyLength : 0,
    bodyKeys:
        phase >= releasePhase.body ? keys(bodyRecords(bodyLength), 200) : [],
    envelope:
        phase >= releasePhase.body
            ? filled(bounds.envelopeBytes, 9)
            : new Uint8Array(),

    signature:
        phase === releasePhase.signed
            ? filled(profile.registration.signatureBytes, 4)
            : new Uint8Array(),
});

const phases = Object.values(releasePhase);

describe('participant release state', () => {
    it('round-trips every phase and status after a signed target or a completed close', () => {
        for (const isOrganizer of [false, true])
            for (const predecessor of [
                targetPhase.signed,
                completedClosePhase(isOrganizer),
            ])
                for (const phase of phases)
                    for (const ballotInclusion of ballotInclusions)
                        for (const bodyLength of [
                            bounds.minimumBodyBytes,
                            bounds.maximumBodyBytes,
                        ]) {
                            const state = stateAt(
                                phase,
                                7,
                                bodyLength,
                                predecessor,
                                ballotInclusion,
                            );
                            expect(
                                decodeReleaseState(
                                    profile,
                                    phase,
                                    isOrganizer,
                                    encodeReleaseState(phase, state),
                                ),
                            ).toEqual(state);
                        }
    });

    it('bounds each phase by the census', () => {
        for (const { phase, bytes } of custody.phaseBytes)
            expect(
                encodeReleaseState(
                    phase,
                    stateAt(
                        phase,
                        profile.target.maximumBodyBytes,
                        bounds.maximumBodyBytes,
                    ),
                ).length,
            ).toBe(Number(bytes));
        expect(BigInt(bounds.maximumStateBytes)).toBe(
            custody.maximumStateBytes,
        );
    });

    it('refuses a state of another phase, count or length', () => {
        const refused = (
            generation: number,
            bytes: Uint8Array,
            isOrganizer = false,
        ) =>
            expect(() =>
                decodeReleaseState(profile, generation, isOrganizer, bytes),
            ).toThrow();
        const body = encodeReleaseState(
            releasePhase.body,
            stateAt(releasePhase.body, 7, bounds.minimumBodyBytes),
        );
        // Each phase carries its own counts and tail.
        for (const phase of phases)
            if (phase !== releasePhase.body) refused(phase, body);
        refused(targetPhase.signed, body);
        refused(releasePhase.body, body.subarray(0, -1));
        refused(releasePhase.body, Uint8Array.of(...body, 0));
        const marker = body.slice();
        marker[0] ^= 1;
        refused(releasePhase.body, marker);
        // The state before the retained status is another shape.
        const unversioned = body.slice();
        unversioned[3] = '2'.charCodeAt(0);
        refused(releasePhase.body, unversioned);
        const unknownStatus = body.slice();
        unknownStatus[5] = ballotInclusions.length;
        refused(releasePhase.body, unknownStatus);
        // A release follows a signed target or the participant's own
        // completed close, never a pending signature or another role's close.
        const predecessor = body.slice();
        predecessor[4] = targetPhase.intent;
        refused(releasePhase.body, predecessor);
        for (const isOrganizer of [false, true]) {
            predecessor[4] = completedClosePhase(!isOrganizer);
            refused(releasePhase.body, predecessor, isOrganizer);
        }
        // The body must fit its bounds and its record count.
        refused(
            releasePhase.body,
            encodeReleaseState(
                releasePhase.body,
                stateAt(releasePhase.body, 7, bounds.minimumBodyBytes - 1),
            ),
        );
        refused(
            releasePhase.body,
            encodeReleaseState(releasePhase.body, {
                ...stateAt(releasePhase.body, 7, bounds.maximumBodyBytes),
                bodyKeys: keys(bodyRecords(bounds.maximumBodyBytes) - 1, 9),
            }),
        );
        // Only the ready phase retains the seed, and it retains all of it.
        for (const phase of phases)
            refused(
                phase,
                encodeReleaseState(phase, {
                    ...stateAt(phase, 7, bounds.minimumBodyBytes),
                    seed:
                        phase === releasePhase.ready
                            ? filled(63, 6)
                            : filled(64, 6),
                }),
            );
        // Every phase names a target.
        refused(
            releasePhase.locked,
            encodeReleaseState(
                releasePhase.locked,
                stateAt(releasePhase.locked, 0, 0),
            ),
        );
    });

    it('lists every record under its own coordinates, length and binding', () => {
        const context = {
            poll: filled(64, 1),
            runtime: filled(64, 2),
            setupIdentity: filled(64, 3),
            position: 2,
        };
        const digest = filled(64, 8);
        const state = stateAt(releasePhase.body, 7, bounds.maximumBodyBytes);
        const records = releaseRecordInventory(profile, context, digest, state);
        expect(records.map((record) => record.key)).toEqual(
            state.bodyKeys.map((_key, index) => index),
        );
        const lengths = releaseRecordLengths(profile, bounds.maximumBodyBytes);
        expect(records.map((record) => record.byteLength)).toEqual(
            lengths.map((length) => length + 16),
        );
        expect(lengths.reduce((a, b) => a + b)).toBe(bounds.maximumBodyBytes);
        const bindings = new Set(
            records.map((record) =>
                Buffer.from(record.encryption!.additionalData).toString('hex'),
            ),
        );
        expect(bindings.size).toBe(records.length);
        const otherTarget = releaseRecordInventory(
            profile,
            context,
            filled(64, 9),
            state,
        );
        expect(
            otherTarget.every(
                (record, index) =>
                    Buffer.from(record.encryption!.additionalData).toString(
                        'hex',
                    ) !==
                    Buffer.from(
                        records[index].encryption!.additionalData,
                    ).toString('hex'),
            ),
        ).toBe(true);
    });

    it('pins the bytes every phase stores', () => {
        expect(
            phases.map((phase) =>
                storedDigest(
                    encodeReleaseState(
                        phase,
                        stateAt(phase, 7, bounds.minimumBodyBytes),
                    ),
                ),
            ),
        ).toEqual([
            '3f739df5c7ffa666889e9b76279d2f9ee36260068ddefdc7924dc50c2b79c28f',
            '8638dc2d021cd817c12d50ef257a74c4070fb37bfc3f89ee3f9f661a41c50f9b',
            'fee866accfcb9c0a48553edc3168841287cc8eba5323168ebd1c0336161dd5f6',
            'c6e70668345a9bcac2f4bd5772c78c8a3420bb2116d88da56cd85ed783b1bf40',
        ]);
    });
});
