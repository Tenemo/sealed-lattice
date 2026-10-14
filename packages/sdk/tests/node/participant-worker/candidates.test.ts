import { afterEach, expect, it, vi } from 'vitest';

import { encodeCandidatePage } from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import {
    readCandidates,
    type CandidateView,
} from '#packages/sdk/src/participant/worker/relay/candidates.js';
import { PublicInputFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';

const relay = { base: 'https://relay.invalid/' };

afterEach(() => vi.unstubAllGlobals());

it('ends discovery at a malformed page and refuses a malformed manifest as public input', async () => {
    vi.stubGlobal('fetch', (url: string) => {
        const { pathname } = new URL(url);
        return Promise.resolve(
            new Response(
                pathname === '/candidates/malformed'
                    ? new Uint8Array(11)
                    : pathname === '/candidates/listed'
                      ? encodeCandidatePage({
                            total: 1,
                            locators: ['0f'.repeat(16)],
                        })
                      : Uint8Array.of(1, 2, 3),
            ),
        );
    });
    const read = async (key: string) => {
        const views: CandidateView[] = [];
        for await (const view of readCandidates(relay, key)) views.push(view);
        return views;
    };
    expect(await read('malformed')).toEqual([]);
    const [view, ...rest] = await read('listed');
    expect(rest).toEqual([]);
    await expect(view.manifest()).rejects.toBeInstanceOf(PublicInputFailure);
});
