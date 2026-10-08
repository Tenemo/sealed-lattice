import binaryen from 'binaryen';
import { describe, expect, it } from 'vitest';

import type { ParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import {
    instantiateParticipantModule,
    moduleFunctions,
} from '#packages/sdk/src/participant/worker/module/participant-module.js';
import {
    ModuleFailure,
    ResourceFailure,
} from '#packages/sdk/src/participant/worker/shared/failures.js';

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
        ...moduleFunctions.map((name) =>
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
        const { module } = await instantiateParticipantModule(
            standInModule(),
            noHelpers,
        );
        expect(module.input_capacity()).toBe(0);
        let failure: unknown;
        try {
            module.restore();
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
            () => module.input_capacity(),
            () => module.restore(),
        ])
            expect(call).toThrow(failure);
    });

    it('keeps an exhausted memory bound a resource failure', async () => {
        const { module } = await instantiateParticipantModule(
            standInModule(),
            noHelpers,
        );
        let failure: unknown;
        try {
            module.check_retained();
        } catch (error) {
            failure = error;
        }
        expect(failure).toBeInstanceOf(ResourceFailure);
        expect(failure).not.toBeInstanceOf(ModuleFailure);
        expect(() => module.input_capacity()).toThrow(failure);
    });

    it('reports a host function that refused its call as a module failure', async () => {
        const { module, handlers } = await instantiateParticipantModule(
            standInModule(),
            noHelpers,
        );
        // No operation installed a randomness handler, so the import refuses.
        expect(() => module.prepare_organizer()).toThrow(ModuleFailure);
        // With a handler, a fresh instance draws and returns.
        const fresh = await instantiateParticipantModule(
            standInModule(),
            noHelpers,
        );
        let drawn = 0;
        fresh.handlers.random = (target) => {
            drawn += target.length;
        };
        expect(fresh.module.prepare_organizer()).toBe(0);
        expect(drawn).toBe(16);
        expect(handlers.random).toBeUndefined();
    });
});
