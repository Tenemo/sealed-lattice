import { describe, expect, it } from 'vitest';

import type { PublicProfileContext } from '#packages/sdk/src/participant/worker/context.js';
import {
    classifyFailure,
    InvalidRequest,
    ModuleFailure,
    pendingCause,
    PublicInputFailure,
    ResourceFailure,
    StorageFailure,
    UnrecognizedState,
} from '#packages/sdk/src/participant/worker/failures.js';
import { authenticateSelection } from '#packages/sdk/src/participant/worker/setup.js';

describe('participant failures', () => {
    it('name what a pending participant waits for by the failure that ended its operation', () => {
        expect(pendingCause(new PublicInputFailure('missing'))).toBe(
            'public input',
        );
        expect(pendingCause(new StorageFailure('quota'))).toBe('storage');
        expect(pendingCause(new ResourceFailure('memory'))).toBe('resource');
        expect(pendingCause(new ModuleFailure('trap'))).toBe('module');
        // Any other failure ended the worker before authority started.
        for (const error of [
            new Error('database'),
            new TypeError('fetch'),
            'thrown text',
            undefined,
        ])
            expect(pendingCause(error)).toBe('worker');
    });

    it('refuse a malformed request and an unrecognized database, leave a participant pending on a failure with its own cause or before its authority started, and stop it on any other failure after', () => {
        const pending = (cause: string) => ({ status: 'pending', cause });
        const stopped = { status: 'stopped' };
        for (const [error, before, after] of [
            [
                new InvalidRequest('labels'),
                { status: 'refused', reason: 'invalid request' },
                { status: 'refused', reason: 'invalid request' },
            ],
            [
                new UnrecognizedState('stores'),
                { status: 'refused', reason: 'unrecognized state' },
                { status: 'refused', reason: 'unrecognized state' },
            ],
            [
                new PublicInputFailure('missing'),
                pending('public input'),
                pending('public input'),
            ],
            [
                new StorageFailure('quota'),
                pending('storage'),
                pending('storage'),
            ],
            [
                new ResourceFailure('memory'),
                pending('resource'),
                pending('resource'),
            ],
            [new ModuleFailure('trap'), pending('module'), pending('module')],
            [new Error('database'), pending('worker'), stopped],
            [new TypeError('fetch'), pending('worker'), stopped],
            ['thrown text', pending('worker'), stopped],
            [undefined, pending('worker'), stopped],
        ] as const) {
            expect(classifyFailure(error, false)).toEqual(before);
            expect(classifyFailure(error, true)).toEqual(after);
        }
    });

    it('stop a participant whose own retained selection the module refuses, and leave one pending whose published selection it refuses', () => {
        const context = {
            module: {
                memory: new WebAssembly.Memory({ initial: 1 }),
                setup_input_pointer: () => 0,
                setup_input_capacity: () => 64,
                setup_selection_begin: () => 1,
            },
        } as unknown as PublicProfileContext;
        const refusal = (retained: boolean) => {
            try {
                authenticateSelection(
                    context,
                    { body: Uint8Array.of(1, 2), signature: Uint8Array.of(3) },
                    retained,
                );
            } catch (error) {
                return error;
            }
            throw new Error('The refusing module accepted a selection.');
        };
        expect(classifyFailure(refusal(false), true)).toEqual({
            status: 'pending',
            cause: 'public input',
        });
        expect(classifyFailure(refusal(true), true)).toEqual({
            status: 'stopped',
        });
    });
});
