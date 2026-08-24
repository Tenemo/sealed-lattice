import { beforeEach, describe, expect, it } from 'vitest';

import {
    loadFreshTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { resolveCommonProofKernelContext } from '#packages/wasm/src/transcript-core-bridge/common-proof-kernel-context';

describe('Accepted-setup package construction real-WASM boundary', () => {
    let kernel: TranscriptCoreKernel;

    beforeEach(async () => {
        kernel = await loadFreshTranscriptCoreKernel();
    });

    it('refuses package and collective-key construction without verifier-owned authorities', () => {
        const context = resolveCommonProofKernelContext(kernel);
        expect(context).toBeDefined();
        if (context === undefined) {
            throw new Error('The real WASM kernel context is unavailable.');
        }

        const beginPackageBuilder =
            context.wasmExports
                .sealed_lattice_accepted_setup_package_builder_begin;
        const beginCollectivePublicKey =
            context.wasmExports
                .sealed_lattice_collective_public_key_aggregate_begin;
        const contributeCollectivePublicKey =
            context.wasmExports
                .sealed_lattice_collective_public_key_aggregate_contribute_package;
        const contributeEvaluatorAggregate =
            context.wasmExports
                .sealed_lattice_evaluator_aggregate_contribute_package;
        expect(beginPackageBuilder).toBeTypeOf('function');
        expect(beginCollectivePublicKey).toBeTypeOf('function');
        expect(contributeCollectivePublicKey).toBeTypeOf('function');
        expect(contributeEvaluatorAggregate).toBeTypeOf('function');
        if (
            beginPackageBuilder === undefined ||
            beginCollectivePublicKey === undefined ||
            contributeCollectivePublicKey === undefined ||
            contributeEvaluatorAggregate === undefined
        ) {
            throw new Error(
                'The accepted-setup construction exports are unavailable.',
            );
        }

        const statusPointer = context.allocate(Uint32Array.BYTES_PER_ELEMENT);
        const materialRootPointer = context.allocate(64);
        try {
            new Uint8Array(context.memory.buffer, materialRootPointer, 64).fill(
                0,
            );

            new DataView(context.memory.buffer).setUint32(
                statusPointer,
                0,
                true,
            );
            expect(
                beginPackageBuilder(
                    0,
                    0,
                    materialRootPointer,
                    64,
                    statusPointer,
                ),
            ).toBe(0);
            expect(
                new DataView(context.memory.buffer).getUint32(
                    statusPointer,
                    true,
                ),
            ).not.toBe(0);

            new DataView(context.memory.buffer).setUint32(
                statusPointer,
                0,
                true,
            );
            expect(beginCollectivePublicKey(0, statusPointer)).toBe(0);
            expect(
                new DataView(context.memory.buffer).getUint32(
                    statusPointer,
                    true,
                ),
            ).not.toBe(0);
        } finally {
            context.deallocate(materialRootPointer, 64);
            context.deallocate(statusPointer, Uint32Array.BYTES_PER_ELEMENT);
        }
    });
});
