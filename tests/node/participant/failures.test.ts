import { describe, expect, it } from 'vitest';

import {
    classifyFailure,
    InvalidRequest,
    ModuleFailure,
    pendingCause,
    PublicInputFailure,
    ResourceFailure,
    StoragePending,
} from '#packages/sdk/src/participant/worker/failures.js';

describe('participant failures', () => {
    it('name what a pending participant waits for by the failure that ended its operation', () => {
        expect(pendingCause(new PublicInputFailure('missing'))).toBe(
            'public input',
        );
        expect(pendingCause(new StoragePending('quota'))).toBe('storage');
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

    it('refuse a malformed request, leave a participant pending on a failure with its own cause or before its authority started, and stop it on any other failure after', () => {
        const pending = (cause: string) => ({ status: 'pending', cause });
        const stopped = { status: 'stopped' };
        for (const [error, before, after] of [
            [
                new InvalidRequest('labels'),
                { status: 'refused' },
                { status: 'refused' },
            ],
            [
                new PublicInputFailure('missing'),
                pending('public input'),
                pending('public input'),
            ],
            [
                new StoragePending('quota'),
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
});
