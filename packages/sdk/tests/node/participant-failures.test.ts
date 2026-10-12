import { describe, expect, it } from 'vitest';

import {
    classifyFailure,
    InvalidRequest,
    ModuleFailure,
    PublicInputFailure,
    ResourceFailure,
    StorageFailure,
    UnrecognizedState,
} from '#packages/sdk/src/participant/worker/shared/failures.js';

describe('participant failure classification', () => {
    it('refuses a malformed request and an unrecognized database whenever they occur', () => {
        for (const authorityStarted of [false, true]) {
            expect(
                classifyFailure(
                    new InvalidRequest('Malformed byte parameter.'),
                    authorityStarted,
                ),
            ).toEqual({ status: 'refused', reason: 'invalid request' });
            expect(
                classifyFailure(
                    new UnrecognizedState(
                        'The participant database has another version.',
                    ),
                    authorityStarted,
                ),
            ).toEqual({ status: 'refused', reason: 'unrecognized state' });
        }
    });

    it('leaves the participant pending after a failure with a cause of its own, also once authority started', () => {
        for (const [error, cause] of [
            [
                new PublicInputFailure('A public record is unavailable.'),
                'public input',
            ],
            [
                new StorageFailure('Local storage failed: Quota exceeded.'),
                'storage',
            ],
            [new ResourceFailure('The shared arena is exhausted.'), 'resource'],
            [new RangeError('Array buffer allocation failed'), 'resource'],
            [new ModuleFailure('The participant module failed.'), 'module'],
        ] as const)
            for (const authorityStarted of [false, true])
                expect(classifyFailure(error, authorityStarted)).toEqual({
                    status: 'pending',
                    cause,
                });
    });

    it('stops the participant on any other failure once authority started, and leaves it pending before', () => {
        for (const error of [
            new Error('Participant root readback differs.'),
            // WebCrypto reports a root that fails authentication this way.
            new DOMException(
                'The operation failed for an operation-specific reason',
                'OperationError',
            ),
            new TypeError('Cannot read properties of undefined'),
            'A thrown value that is not an error.',
        ]) {
            expect(classifyFailure(error, true)).toEqual({ status: 'stopped' });
            expect(classifyFailure(error, false)).toEqual({
                status: 'pending',
                cause: 'worker',
            });
        }
    });
});
