import { describe, expect, it } from 'vitest';

import {
    isWellFormed,
    isWellFormedVerification,
} from '#packages/sdk/src/participant/worker/runtime/worker-messages.js';

const runtime = {
    relay: 'https://relay.invalid/',
    module: 'https://application.invalid/participant.wasm',
    identity: {
        source: 'ab'.repeat(64),
        module: 'cd'.repeat(64),
        worker: 'ef'.repeat(64),
    },
};
const participant = {
    ...runtime,
    operation: 'status',
    namespace: 'participant',
    parameters: {},
};
const verification = {
    ...runtime,
    operation: 'verify-outcome',
    poll: '12'.repeat(64),
};

describe('worker message boundary', () => {
    it.each([
        'https://user@relay.invalid/',
        'https://user:pass@relay.invalid/',
        'https://:pass@relay.invalid/',
        'https://%75ser:p%40ss@relay.invalid/',
        'http://%40@127.0.0.1:43123/records/',
    ])('refuses relay credentials in both message types: %s', (relay) => {
        expect(isWellFormed({ ...participant, relay })).toBe(false);
        expect(isWellFormedVerification({ ...verification, relay })).toBe(
            false,
        );
    });

    it.each([
        'https://relay.invalid/',
        'https://relay.invalid/user@room/',
        'http://127.0.0.1:43123/records/',
        'http://[::1]:43123/records/',
    ])(
        'accepts credential-free relay bases in both message types: %s',
        (relay) => {
            expect(isWellFormed({ ...participant, relay })).toBe(true);
            expect(isWellFormedVerification({ ...verification, relay })).toBe(
                true,
            );
        },
    );

    it('recognizes participant and independent-verification envelopes separately', () => {
        expect(isWellFormed(participant)).toBe(true);
        expect(
            isWellFormed({
                ...participant,
                operation: 'release',
                separateEvaluation: true,
            }),
        ).toBe(true);
        expect(isWellFormedVerification(verification)).toBe(true);
        expect(isWellFormed(verification)).toBe(false);
        expect(isWellFormedVerification(participant)).toBe(false);
    });

    it('refuses malformed required fields without dereferencing untrusted shapes', () => {
        for (const value of [null, undefined, [], {}, false, 'status']) {
            expect(isWellFormed(value)).toBe(false);
            expect(isWellFormedVerification(value)).toBe(false);
        }
        for (const changed of [
            { operation: 'constructor' },
            { operation: '__proto__' },
            { operation: 1 },
            { namespace: 'Invalid namespace' },
            { parameters: undefined },
            { parameters: null },
            { parameters: [] },
            { separateEvaluation: 1 },
        ])
            expect(isWellFormed({ ...participant, ...changed })).toBe(false);
        for (const changed of [
            { identity: undefined },
            { identity: [] },
            { identity: { ...runtime.identity, worker: 1 } },
            { identity: { ...runtime.identity, source: 'AB'.repeat(64) } },
            { identity: { ...runtime.identity, module: 'cd'.repeat(63) } },
            { identity: { ...runtime.identity, worker: 'ef'.repeat(65) } },
            { relay: 'https://relay.invalid/?poll=1' },
            { module: 'file:///participant.wasm' },
        ]) {
            expect(isWellFormed({ ...participant, ...changed })).toBe(false);
            expect(
                isWellFormedVerification({ ...verification, ...changed }),
            ).toBe(false);
        }
        for (const poll of ['', '12'.repeat(63), 'gg'.repeat(64)])
            expect(isWellFormedVerification({ ...verification, poll })).toBe(
                false,
            );
    });
});
