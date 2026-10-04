import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

import { seedSharingChunkBytes } from '#tools/ci/seed-sharing-browser-input.mjs';
import { createSeedSharingProofSink } from '#tools/ci/seed-sharing-proof-sink.mjs';

// Invalid HTTP envelopes are refused before the shared writer consumes work.
// A valid chunk receives a receipt only after that writer's durable write.
export const createBrowserProofSink = async (
    file: string,
    expectedBytes: number,
    expectedSha512: string,
) => {
    const sink = await createSeedSharingProofSink(
        file,
        expectedBytes,
        expectedSha512,
    );
    let busy = false;
    return {
        receive: async (
            index: number,
            offset: number,
            length: number,
            sha512: string,
            body: AsyncIterable<unknown>,
        ) => {
            assert.ok(!busy, 'The proof sink already has a pending chunk.');
            const state = sink.state();
            assert.equal(
                index,
                state.chunks,
                'The proof chunk index is out of order.',
            );
            assert.equal(
                offset,
                state.bytes,
                'The proof chunk offset is out of order.',
            );
            assert.ok(
                Number.isSafeInteger(length) &&
                    length > 0 &&
                    length <= seedSharingChunkBytes &&
                    length <= expectedBytes - state.bytes,
                'The proof chunk exceeds its bound.',
            );
            assert.match(
                sha512,
                /^[0-9a-f]{128}$/u,
                'The proof chunk digest is malformed.',
            );
            busy = true;
            try {
                const buffer = new Uint8Array(length);
                let received = 0;
                for await (const chunk of body) {
                    assert.ok(
                        chunk instanceof Uint8Array,
                        'The proof chunk is not binary.',
                    );
                    assert.ok(
                        chunk.length <= length - received,
                        'The proof chunk exceeds its declared length.',
                    );
                    buffer.set(chunk, received);
                    received += chunk.length;
                }
                assert.equal(received, length, 'The proof chunk ended early.');
                assert.equal(
                    createHash('sha512').update(buffer).digest('hex'),
                    sha512,
                    'The proof chunk digest differs.',
                );
                return await sink.write(index, offset, buffer);
            } finally {
                busy = false;
            }
        },
        result: () => {
            assert.ok(!busy, 'The proof sink has a pending chunk.');
            return sink.finish();
        },
        close: () => sink.close(),
    };
};
