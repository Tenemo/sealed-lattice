import { afterEach, expect, it, vi } from 'vitest';

import { encodeCandidatePage } from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import { createCandidatePublication } from '#packages/sdk/src/participant/worker/relay/relay.js';
import { guardDelivery } from '#packages/sdk/src/participant/worker/storage/delivery.js';
import { participantRelayFixture } from '#tests/participant-relay-fixture.js';

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
                                      ? { total: 0, ids: [] }
                                      : { total: 1, ids: ['fe'.repeat(16)] },
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
        await expect(publication.finish()).rejects.toThrow('discovery');
        expect(original).toEqual(Uint8Array.of(7, 11, 13));
        changed = false;
        await expect(publication.finish()).resolves.toBeUndefined();
    },
);
