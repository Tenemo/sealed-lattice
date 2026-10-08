import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { encodeManifest } from '#packages/sdk/src/participant/worker/root.js';

// The SHA-256 digest of stored bytes, which pins their exact format.
const storedDigest = (bytes: Uint8Array) =>
    createHash('sha256').update(bytes).digest('hex');

const filled = (length: number, value: number) =>
    new Uint8Array(length).fill(value);
const references = [
    { kind: 0, offset: 0, length: 17, hash: filled(64, 5) },
    { kind: 1, offset: 0, length: 9, hash: filled(64, 6) },
];

describe('participant root manifest', () => {
    it('pins the bytes of an enrollment root and of a root with every suffix', () => {
        const enrollment = encodeManifest(
            {
                dataKeys: filled(96, 1),
                poll: filled(64, 2),
                references,
                suffixes: {},
            },
            1,
        );
        const complete = encodeManifest(
            {
                dataKeys: filled(64, 1),
                poll: filled(64, 2),
                references,
                suffixes: {
                    preparation: filled(3, 7),
                    ballot: filled(5, 8),
                    close: filled(2, 9),
                    target: filled(4, 10),
                    release: filled(6, 11),
                },
            },
            29,
        );
        expect([enrollment, complete].map(storedDigest)).toEqual([
            '5313d98cf0458953c71e98f836cda4ff7a6ef9d6258b0691d5ee672de5048e17',
            'ef16caa3d2f1242b87c69cd577f43474934503b47fb88559f65e00995a4e5782',
        ]);
    });
});
