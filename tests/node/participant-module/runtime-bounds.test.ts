import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import { noParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import {
    instantiateParticipantModule,
    requireInputCapacities,
} from '#packages/sdk/src/participant/worker/module/participant-module.js';
import {
    chunkBytes,
    readParticipantLimits,
    readParticipantProfile,
} from '#packages/sdk/src/participant/worker/module/runtime-bounds.js';
import { ModuleFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';
import { largestBufferInputBytes } from '#packages/sdk/src/participant/worker/stages/target-vote/target.js';
import {
    compileParticipantRuntimeLimits,
    compileParticipantRuntimeProfile,
} from '#tests/participant-runtime-bounds-model.js';

// The packaged participant module reports its sizes and budgets; the worker
// derives its bounds from them. Both must equal the independent models'.
const participantModule = await WebAssembly.compile(
    await readFile(
        new URL('../../../packages/sdk/dist/participant.wasm', import.meta.url),
    ),
);
const { module } = await instantiateParticipantModule(
    participantModule,
    noParallelHelpers,
);
const limits = readParticipantLimits(module);
const counts = (range: Readonly<{ minimum: number; maximum: number }>) =>
    Array.from(
        { length: range.maximum - range.minimum + 1 },
        (_unused, index) => range.minimum + index,
    );
const participantCounts = counts(limits.participants);
const optionCounts = counts(limits.options);

describe('participant runtime bounds', () => {
    it('reports the shared bounds the models derive', () => {
        expect(limits).toEqual(compileParticipantRuntimeLimits());
    });

    it('derives every supported profile as the models do, within the shared limits', () => {
        for (const participants of participantCounts)
            for (const options of optionCounts) {
                const profile = readParticipantProfile(
                    module,
                    limits,
                    participants,
                    options,
                );
                expect(profile).toEqual(
                    compileParticipantRuntimeProfile(participants, options),
                );
                if (profile === undefined) continue;
                expect(profile.proposalBytes).toBeLessThanOrEqual(
                    limits.registration.maximumProposalBytes,
                );
                expect(profile.root.maximumRootBytes).toBeLessThanOrEqual(
                    limits.root.maximumRootBytes,
                );
                expect(profile.root.setupReferenceBytes).toBeLessThanOrEqual(
                    limits.root.maximumSetupReferenceBytes,
                );
                expect(profile.root.retainedRosterBytes).toBeLessThanOrEqual(
                    limits.root.maximumRetainedRosterBytes,
                );
            }
    });

    it('refuses every unsupported profile', () => {
        for (const [participants, options] of [
            [limits.participants.minimum - 1, limits.options.minimum],
            [limits.participants.maximum + 1, limits.options.maximum],
            [limits.participants.minimum, limits.options.minimum - 1],
            [limits.participants.maximum, limits.options.maximum + 1],
            [0, 0],
        ])
            expect(
                readParticipantProfile(module, limits, participants, options),
            ).toBeUndefined();
    });
});

describe('participant module input buffers', () => {
    it('take the largest input the worker writes into them at every supported profile, and a buffer that holds less refuses the module', () => {
        // A relay transfer chunk, a retained record chunk and an evaluation
        // store chunk are a mebibyte each, a cached aggregate chunk half one.
        const largest = largestBufferInputBytes(module);
        expect(largest).toBe(1 << 20);
        expect(() => requireInputCapacities(module, largest)).not.toThrow();
        // Restoring a retained target streams retained record chunks into
        // the session input.
        expect(module.input_capacity()).toBeGreaterThanOrEqual(chunkBytes);
        for (const participants of participantCounts)
            for (const options of optionCounts) {
                const profile = readParticipantProfile(
                    module,
                    limits,
                    participants,
                    options,
                );
                if (profile === undefined) continue;
                const { ballot, close, registration, release, target } =
                    profile;
                const { signatureBytes } = registration;
                // The whole records and concatenations the worker writes
                // into the certificate, close and classifier buffers.
                for (const bytes of [
                    target.votePacketBytes,
                    release.envelopeBytes + signatureBytes,
                    release.bodyHeaderBytes,
                    4 + close.intentBodyBytes + signatureBytes,
                    close.submissionBytes,
                    4 + close.maximumResponseBodyBytes + signatureBytes,
                    4 + close.proposalBodyBytes + signatureBytes,
                    close.submissionBytes + ballot.headerBytes,
                ])
                    expect(bytes).toBeLessThanOrEqual(largest);
            }
        expect(() => requireInputCapacities(module, largest + 1)).toThrow(
            new ModuleFailure(
                'The participant module cannot take the largest input in its completion buffer.',
            ),
        );
    });
});

describe('participant memory plan', () => {
    const absoluteBytes = 671_088_640;
    const pageBytes = 65_536;
    const instantiate = async () =>
        (
            await instantiateParticipantModule(
                participantModule,
                noParallelHelpers,
            )
        ).module;

    it('divides the absolute linear-memory bound between the worker and up to eight helpers', () => {
        for (const evaluation of [0, 1]) {
            expect(module.helper_memory_bound(0, evaluation) >>> 0).toBe(0);
            expect(module.worker_memory_bound(0, evaluation) >>> 0).toBe(
                absoluteBytes,
            );
            for (let helpers = 1; helpers <= 8; helpers++) {
                const helper =
                    module.helper_memory_bound(helpers, evaluation) >>> 0;
                const worker =
                    module.worker_memory_bound(helpers, evaluation) >>> 0;
                expect(helper).toBeGreaterThan(0);
                expect(helper % pageBytes).toBe(0);
                expect(worker % pageBytes).toBe(0);
                expect(helpers * helper + worker).toBe(absoluteBytes);
            }
            expect(module.helper_memory_bound(9, evaluation) >>> 0).toBe(0);
            expect(module.worker_memory_bound(9, evaluation) >>> 0).toBe(0);
        }
        expect(module.helper_memory_bound(1, 2) >>> 0).toBe(0);
        expect(module.worker_memory_bound(1, 2) >>> 0).toBe(0);
    });

    it("admits the worker's first allocations within its share of every plan", async () => {
        for (const evaluation of [0, 1])
            for (let helpers = 1; helpers <= 8; helpers++) {
                const fresh = await instantiate();
                expect(fresh.worker_reserve(helpers, evaluation) >>> 0).toBe(0);
                expect(readParticipantLimits(fresh)).toEqual(limits);
            }
    });

    it("bounds the worker's instance only before its first allocation and only within a plan", async () => {
        const fresh = await instantiate();
        expect(fresh.worker_reserve(9, 0) >>> 0).toBe(1);
        expect(fresh.worker_reserve(8, 2) >>> 0).toBe(1);
        expect(fresh.worker_reserve(8, 1) >>> 0).toBe(0);
        expect(readParticipantLimits(fresh)).toEqual(limits);
        expect(fresh.worker_reserve(8, 1) >>> 0).toBe(1);
        expect(module.worker_reserve(0, 0) >>> 0).toBe(1);
    });
});
