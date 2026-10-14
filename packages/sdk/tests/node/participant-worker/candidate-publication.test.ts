import { afterEach, expect, it, vi } from 'vitest';

import { encodeCandidatePage } from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import { createCandidatePublication } from '#packages/sdk/src/participant/worker/relay/publication.js';
import { PublicInputFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';
import { guardDelivery } from '#packages/sdk/src/participant/worker/storage/delivery.js';
import { participantRelayFixture } from '#packages/sdk/tests/participant-relay-fixture.js';

afterEach(() => vi.unstubAllGlobals());

it.each(['absent', 'different', 'truncated'] as const)(
    'refuses an acknowledged manifest with %s discovery readback and permits exact retry',
    async (fault) => {
        const relay = participantRelayFixture();
        let changed = true;
        vi.stubGlobal(
            'fetch',
            async (url: string, options: RequestInit = {}) => {
                if (
                    changed &&
                    options.method !== 'POST' &&
                    new URL(url).pathname === '/candidates/selection'
                ) {
                    const bytes =
                        fault === 'truncated'
                            ? new Uint8Array(11)
                            : encodeCandidatePage(
                                  fault === 'absent'
                                      ? { total: 0, locators: [] }
                                      : {
                                            total: 1,
                                            locators: ['fe'.repeat(16)],
                                        },
                              );
                    return new Response(new Uint8Array(bytes));
                }
                return relay.fetch(url, options);
            },
        );
        const publication = createCandidatePublication(
            { base: 'https://relay.invalid/' },
            'selection',
            await guardDelivery(() => Promise.resolve()),
        );
        const original = Uint8Array.of(7, 11, 13);
        await publication.addBytes('selection.bin', original);
        const refusal = await publication
            .finish()
            .catch((error: unknown) => error);
        expect(refusal).toBeInstanceOf(PublicInputFailure);
        expect((refusal as Error).message).toContain('discovery');
        expect(original).toEqual(Uint8Array.of(7, 11, 13));
        changed = false;
        await expect(publication.finish()).resolves.toBeUndefined();
    },
);

it('refuses a malformed publication receipt as public input and permits exact retry', async () => {
    const relay = participantRelayFixture();
    let changed = true;
    vi.stubGlobal('fetch', async (url: string, options: RequestInit = {}) =>
        changed &&
        options.method === 'POST' &&
        new URL(url).pathname === '/candidates/selection'
            ? new Response(Uint8Array.of(1, 2, 3))
            : relay.fetch(url, options),
    );
    const publication = createCandidatePublication(
        { base: 'https://relay.invalid/' },
        'selection',
        await guardDelivery(() => Promise.resolve()),
    );
    await publication.addBytes('selection.bin', Uint8Array.of(7, 11, 13));
    await expect(publication.finish()).rejects.toBeInstanceOf(
        PublicInputFailure,
    );
    changed = false;
    await expect(publication.finish()).resolves.toBeUndefined();
});
