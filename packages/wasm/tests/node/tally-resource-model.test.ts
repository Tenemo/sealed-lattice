import { describe, expect, it } from 'vitest';

import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import { openTallyActivationRuntime } from '../../src/tally-activation-runtime.js';
import {
    modelParticipantActivationByteLength,
    modelTallyScalarWork,
} from '../../src/tally-resource-model.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const expectedOperationCounts = [
    [1, 2153, 2098, 250],
    [2, 2515, 2290, 364],
    [3, 2837, 2458, 462],
    [4, 3113, 2602, 546],
    [5, 3343, 2722, 616],
    [6, 3527, 2818, 672],
    [7, 3665, 2890, 714],
    [8, 3757, 2938, 742],
    [9, 3803, 2962, 756],
    [10, 3803, 2962, 756],
] as const;

describe('completion tally resource model', () => {
    it('derives every admitted output width and scalar activation ledger from the emitted plan', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const runtime = openTallyActivationRuntime(kernel);
        const profiles = expectedOperationCounts.map(
            ([
                topCount,
                exclusiveOrOperationCount,
                conjunctionCount,
                negationOperationCount,
            ]) => {
                const plan = runtime.plan(topCount);
                expect(plan).toMatchObject({
                    constantOperationCount: 2,
                    exclusiveOrOperationCount,
                    conjunctionCount,
                    negationOperationCount,
                    outputBitCount: 11 + 4 * topCount,
                });
                const counts = {
                    operationCount: plan.operationCount,
                    constantOperationCount: plan.constantOperationCount,
                    exclusiveOrOperationCount: plan.exclusiveOrOperationCount,
                    conjunctionCount: plan.conjunctionCount,
                    negationOperationCount: plan.negationOperationCount,
                    outputBitCount: plan.outputBitCount,
                    rangeCount: plan.ranges.length,
                };
                return {
                    topCount,
                    operationCount: plan.operationCount,
                    outputBitCount: plan.outputBitCount,
                    rangeCount: plan.ranges.length,
                    participantActivationByteLength:
                        modelParticipantActivationByteLength(counts),
                    scalarWork: modelTallyScalarWork(counts),
                };
            },
        );
        expect(profiles).toHaveLength(10);
        expect(profiles[9]).toMatchObject({
            topCount: 10,
            outputBitCount: 51,
        });
        expect(
            Math.max(
                ...profiles.map(
                    (profile) => profile.participantActivationByteLength,
                ),
            ) * 10,
        ).toBeLessThanOrEqual(2_147_483_648);
        console.info(
            `All-topCount resource evidence ${JSON.stringify(profiles)}`,
        );
    });
});
