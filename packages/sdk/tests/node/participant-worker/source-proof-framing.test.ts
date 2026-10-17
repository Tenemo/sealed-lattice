import { describe, expect, it } from 'vitest';

import {
    proofLength,
    proofRecordLayout,
} from '#packages/sdk/src/participant/worker/stages/contribution/contribution-proof.js';

const bounds = {
    bodyHeaderBytes: 8,
    minimumProofBytes: 97,
    maximumProofBytes: 2 ** 20 + 31,
};
const header = (length: number) => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, BigInt(length), true);
    return bytes;
};

describe('source-linked compact proof framing', () => {
    it.each([97, 2 ** 20 - 1, 2 ** 20, 2 ** 20 + 31])(
        'uses the authenticated eight-byte length for a %s-byte proof',
        (length) => {
            expect(proofLength(bounds, header(length))).toBe(length);
            const layout = proofRecordLayout(bounds, length);
            expect(layout.reduce((sum, record) => sum + record.length, 0)).toBe(
                length,
            );
            expect(
                layout.every(
                    (record) => record.length > 0 && record.length <= 2 ** 20,
                ),
            ).toBe(true);
        },
    );

    it('refuses truncated and oversized body headers', () => {
        const valid = header(97);
        for (let length = 0; length < valid.length; length++)
            expect(() => proofLength(bounds, valid.slice(0, length))).toThrow();
        for (const length of [
            bounds.bodyHeaderBytes + 1,
            bounds.bodyHeaderBytes + 2,
            bounds.bodyHeaderBytes * 2,
            bounds.bodyHeaderBytes * 4,
        ]) {
            const bytes = new Uint8Array(length);
            bytes.set(valid);
            expect(() => proofLength(bounds, bytes)).toThrow(
                'The contribution body header is malformed.',
            );
        }
    });

    it.each([96, 2 ** 20 + 32])(
        'refuses a proof length outside the profile at %s',
        (length) => {
            expect(() => proofLength(bounds, header(length))).toThrow(
                'The retained proof has an invalid length.',
            );
            expect(() => proofRecordLayout(bounds, length)).toThrow(
                'The contribution proof has an invalid length.',
            );
        },
    );
});
