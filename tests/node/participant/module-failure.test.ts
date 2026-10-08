import binaryen from 'binaryen';
import { describe, expect, it } from 'vitest';

import {
    ModuleFailure,
    ResourceFailure,
} from '#packages/sdk/src/participant/worker/failures.js';
import {
    instantiateParticipantKernel,
    kernelFunctions,
} from '#packages/sdk/src/participant/worker/kernel.js';
import type { ParallelHelpers } from '#packages/sdk/src/participant/worker/parallel.js';

// A stand-in participant module that exports every function the worker
// calls. One export traps, one reports an exhausted memory bound through the
// allocator's import and one draws randomness through the witness import.
const trapping = 'restore';
const exhausting = 'check_retained';
const drawing = 'prepare_organizer';
const standInModule = () => {
    const text = [
        '(module',
        '  (import "allocator" "exhausted" (func $exhausted (param i32)))',
        '  (import "setup_witness" "fill_random" (func $random (param i32 i32) (result i32)))',
        '  (memory (export "memory") 1)',
        ...kernelFunctions.map((name) =>
            name === trapping
                ? `  (func (export "${name}") (result i32) unreachable)`
                : name === exhausting
                  ? `  (func (export "${name}") (result i32) (call $exhausted (i32.const 4096)) (i32.const 0))`
                  : name === drawing
                    ? `  (func (export "${name}") (result i32) (call $random (i32.const 0) (i32.const 16)))`
                    : `  (func (export "${name}") (result i32) (i32.const 0))`,
        ),
        ')',
    ].join('\n');
    const parsed = binaryen.parseText(text);
    try {
        return new WebAssembly.Module(new Uint8Array(parsed.emitBinary()));
    } finally {
        parsed.dispose();
    }
};
// No helper runs; the stand-in module imports nothing from the helpers.
const noHelpers = {
    count: 0,
    imports: () => ({}),
} as unknown as ParallelHelpers;

describe('participant module failures', () => {
    it('reports a trap as a module failure and never enters the instance again', async () => {
        const { kernel } = await instantiateParticipantKernel(
            standInModule(),
            noHelpers,
        );
        expect(kernel.input_capacity()).toBe(0);
        let failure: unknown;
        try {
            kernel.restore();
        } catch (error) {
            failure = error;
        }
        expect(failure).toBeInstanceOf(ModuleFailure);
        expect((failure as Error).message).toMatch(
            /^The participant module failed in restore: /u,
        );
        // Every later call ends with the same failure, whichever export it
        // names, because the instance's state is unknown.
        for (const call of [
            () => kernel.input_capacity(),
            () => kernel.restore(),
        ])
            expect(call).toThrow(failure);
    });

    it('keeps an exhausted memory bound a resource failure', async () => {
        const { kernel } = await instantiateParticipantKernel(
            standInModule(),
            noHelpers,
        );
        let failure: unknown;
        try {
            kernel.check_retained();
        } catch (error) {
            failure = error;
        }
        expect(failure).toBeInstanceOf(ResourceFailure);
        expect(failure).not.toBeInstanceOf(ModuleFailure);
        expect(() => kernel.input_capacity()).toThrow(failure);
    });

    it('reports a host function that refused its call as a module failure', async () => {
        const { kernel, handlers } = await instantiateParticipantKernel(
            standInModule(),
            noHelpers,
        );
        // No operation installed a randomness handler, so the import refuses.
        expect(() => kernel.prepare_organizer()).toThrow(ModuleFailure);
        // With a handler, a fresh instance draws and returns.
        const fresh = await instantiateParticipantKernel(
            standInModule(),
            noHelpers,
        );
        let drawn = 0;
        fresh.handlers.random = (target) => {
            drawn += target.length;
        };
        expect(fresh.kernel.prepare_organizer()).toBe(0);
        expect(drawn).toBe(16);
        expect(handlers.random).toBeUndefined();
    });
});
