import binaryen from 'binaryen';
import { describe, expect, it } from 'vitest';

import type { ParallelHelpers } from '#packages/sdk/src/participant/worker/module/parallel-helpers.js';
import {
    instantiateParticipantModule,
    moduleArity,
    moduleFunctions,
} from '#packages/sdk/src/participant/worker/module/participant-module.js';
import {
    ModuleFailure,
    ResourceFailure,
} from '#packages/sdk/src/participant/worker/shared/failures.js';

// A stand-in participant module that exports every function the worker
// calls with its parameter count, or one export with an extra parameter. One
// export traps, one reports an exhausted memory bound through the
// allocator's import and one draws randomness through the witness import.
const trapping = 'restore';
const exhausting = 'retain_proposal';
const drawing = 'prepare_organizer';
const standInModule = (extraParameter?: string) => {
    const signature = (name: (typeof moduleFunctions)[number]) => {
        const count = moduleArity[name] + (name === extraParameter ? 1 : 0);
        return `(export "${name}")${
            count === 0 ? '' : ` (param${' i32'.repeat(count)})`
        } (result i32)`;
    };
    const text = [
        '(module',
        '  (import "allocator" "exhausted" (func $exhausted (param i32)))',
        '  (import "setup_witness" "fill_random" (func $random (param i32 i32) (result i32)))',
        '  (memory (export "memory") 1)',
        ...moduleFunctions.map((name) =>
            name === trapping
                ? `  (func ${signature(name)} unreachable)`
                : name === exhausting
                  ? `  (func ${signature(name)} (call $exhausted (i32.const 4096)) (i32.const 0))`
                  : name === drawing
                    ? `  (func ${signature(name)} (call $random (i32.const 0) (i32.const 16)))`
                    : `  (func ${signature(name)} (i32.const 0))`,
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
    it('refuses a module whose export takes other parameters than the worker passes', async () => {
        await expect(
            instantiateParticipantModule(
                standInModule('roster_record'),
                noHelpers,
            ),
        ).rejects.toThrow(
            'The participant module export roster_record takes 4 parameters, not 3.',
        );
    });

    it('reports a trap as a module failure and never enters the instance again', async () => {
        const { module } = await instantiateParticipantModule(
            standInModule(),
            noHelpers,
        );
        expect(module.input_capacity()).toBe(0);
        let failure: unknown;
        try {
            module.restore(0);
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
            () => module.restore(0),
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
            module.retain_proposal(0);
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
        expect(() => module.prepare_organizer(0)).toThrow(ModuleFailure);
        // With a handler, a fresh instance draws and returns.
        const fresh = await instantiateParticipantModule(
            standInModule(),
            noHelpers,
        );
        let drawn = 0;
        fresh.handlers.random = (target) => {
            drawn += target.length;
        };
        expect(fresh.module.prepare_organizer(0)).toBe(0);
        expect(drawn).toBe(16);
        expect(handlers.random).toBeUndefined();
    });
});
