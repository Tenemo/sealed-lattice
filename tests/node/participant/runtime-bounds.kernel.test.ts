import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    readParticipantLimits,
    readParticipantProfile,
} from '#packages/sdk/src/participant/worker/bounds.js';
import { instantiateParticipantKernel } from '#packages/sdk/src/participant/worker/kernel.js';
import { noParallelHelpers } from '#packages/sdk/src/participant/worker/parallel.js';
import {
    compileParticipantRuntimeLimits,
    compileParticipantRuntimeProfile,
} from '#tests/participant-runtime-bounds-model.js';

// The packaged participant module reports its sizes and budgets; the worker
// derives its bounds from them. Both must equal the independent models'.
const { kernel } = await instantiateParticipantKernel(
    await WebAssembly.compile(
        await readFile(
            new URL(
                '../../../packages/sdk/dist/participant.wasm',
                import.meta.url,
            ),
        ),
    ),
    noParallelHelpers,
);
const limits = readParticipantLimits(kernel);
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
                    kernel,
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
                readParticipantProfile(kernel, limits, participants, options),
            ).toBeUndefined();
    });
});
