import { afterEach, describe, expect, it, vi } from 'vitest';

import { candidateChunkBytes } from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import {
    streamCandidateFile,
    type CandidateView,
} from '#packages/sdk/src/participant/worker/relay/candidates.js';
import { PublicInputFailure } from '#packages/sdk/src/participant/worker/shared/failures.js';

afterEach(() => vi.unstubAllGlobals());
const relay = { base: 'https://relay.invalid/' };
const length = candidateChunkBytes * 2 + 79;
const original = Uint8Array.from({ length }, (_unused, index) => index % 251);
const locators = ['01', '02', '03'].map((value) => value.repeat(16));
const candidate = {
    manifest: () =>
        Promise.resolve({
            files: [
                { name: 'source-ciphertexts.bin', length, chunks: locators },
            ],
        }),
} as CandidateView;
const fixture = () => {
    const reads: number[] = [];
    const fetch = vi.fn((url: string) => {
        const index = locators.indexOf(
            new URL(url).pathname.slice('/chunk/'.length),
        );
        expect(index).toBeGreaterThanOrEqual(0);
        reads.push(index);
        return Promise.resolve(
            new Response(
                original.slice(
                    index * candidateChunkBytes,
                    Math.min(length, (index + 1) * candidateChunkBytes),
                ),
            ),
        );
    });
    vi.stubGlobal('fetch', fetch);
    return { reads, fetch };
};

describe('registered source range reads', () => {
    it.each([
        { start: 0, length: 0 },
        { start: 0, length: 1 },
        { start: candidateChunkBytes - 7, length: 31 },
        { start: candidateChunkBytes, length: candidateChunkBytes },
        { start: length - 9, length: 9 },
        { start: length, length: 0 },
    ])(
        'reads exactly the bounded source interval $start + $length',
        async (range) => {
            const state = fixture();
            const received: Uint8Array[] = [];
            const actual = await streamCandidateFile(
                relay,
                candidate,
                'source-ciphertexts.bin',
                length,
                (bytes) => {
                    received.push(bytes.slice());
                },
                range,
            );
            expect(actual).toBe(range.length);
            expect(Buffer.concat(received)).toEqual(
                Buffer.from(
                    original.subarray(range.start, range.start + range.length),
                ),
            );
            expect(
                received.every((bytes) => bytes.length <= candidateChunkBytes),
            ).toBe(true);
            const first = Math.floor(range.start / candidateChunkBytes);
            const count =
                range.length === 0
                    ? 0
                    : Math.ceil(
                          (range.start + range.length) / candidateChunkBytes,
                      ) - first;
            expect(state.reads).toEqual(
                Array.from(
                    { length: count },
                    (_unused, index) => first + index,
                ),
            );
        },
    );

    it.each([
        { start: -1, length: 1 },
        { start: 1.5, length: 1 },
        { start: 0, length: -1 },
        { start: 0, length: Number.NaN },
        { start: length, length: 1 },
        { start: length + 1, length: 0 },
        { start: Number.MAX_SAFE_INTEGER + 1, length: 0 },
        { start: 0, length: Number.MAX_SAFE_INTEGER + 1 },
    ])(
        'refuses invalid range $start + $length without a request',
        async (range) => {
            const state = fixture();
            const accept = vi.fn();
            await expect(
                streamCandidateFile(
                    relay,
                    candidate,
                    'source-ciphertexts.bin',
                    length,
                    accept,
                    range,
                ),
            ).rejects.toBeInstanceOf(PublicInputFailure);
            expect(accept).not.toHaveBeenCalled();
            expect(state.fetch).not.toHaveBeenCalled();
        },
    );

    it('refuses a truncated transport chunk before exposing a selected prefix', async () => {
        fixture().fetch.mockResolvedValueOnce(
            new Response(original.slice(0, candidateChunkBytes - 1)),
        );
        const accept = vi.fn();
        await expect(
            streamCandidateFile(
                relay,
                candidate,
                'source-ciphertexts.bin',
                length,
                accept,
                { start: 7, length: 13 },
            ),
        ).rejects.toThrow('A candidate chunk is incomplete.');
        expect(accept).not.toHaveBeenCalled();
    });

    it('refuses an oversized source object even when its requested interval fits', async () => {
        const state = fixture();
        await expect(
            streamCandidateFile(
                relay,
                candidate,
                'source-ciphertexts.bin',
                length - 1,
                () => undefined,
                { start: 0, length: 1 },
            ),
        ).rejects.toBeInstanceOf(PublicInputFailure);
        expect(state.fetch).not.toHaveBeenCalled();
    });
});
