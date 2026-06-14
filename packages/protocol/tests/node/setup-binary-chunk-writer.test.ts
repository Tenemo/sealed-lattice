import { describe, expect, it } from 'vitest';

import { BinaryChunkWriter } from '#packages/protocol/src/setup/binary-chunk-writer';

const flattenChunks = (chunks: readonly Uint8Array[]): readonly number[] =>
    chunks.flatMap((chunk) => Array.from(chunk));

const expectedVaruintBytes = (value: number): readonly number[] => {
    let remainingValue = BigInt(value);
    const bytes: number[] = [];

    do {
        let byte = Number(remainingValue % 128n);
        remainingValue /= 128n;
        if (remainingValue !== 0n) {
            byte |= 0x80;
        }
        bytes.push(byte);
    } while (remainingValue !== 0n);

    return bytes;
};

describe('BinaryChunkWriter', () => {
    it('streams chunks without retaining bytes and reports the encoded length', () => {
        const capturedChunks: {
            readonly chunkIndex: number;
            readonly bytes: readonly number[];
        }[] = [];
        const writer = new BinaryChunkWriter({
            chunkSizeBytes: 3,
            emptyErrorMessage: 'test writer requires bytes.',
            expectedTotalByteLength: 6,
            retainChunks: false,
            consumeChunk: (chunkIndex, chunk) => {
                capturedChunks.push({
                    chunkIndex,
                    bytes: Array.from(chunk),
                });
            },
        });

        writer.writeBytes(new Uint8Array([1, 2, 3, 4, 5]));
        writer.writeByte(6);
        const summary = writer.finishWithSummary();

        expect(summary).toEqual({
            chunks: [],
            chunkCount: 2,
            totalByteLength: 6,
        });
        expect(capturedChunks).toEqual([
            { chunkIndex: 0, bytes: [1, 2, 3] },
            { chunkIndex: 1, bytes: [4, 5, 6] },
        ]);
        expect(writer.finish()).toEqual([]);
        expect(() => writer.writeByte(7)).toThrow(/after finish/u);
    });

    it('rejects an expected byte length mismatch at finish', () => {
        const writer = new BinaryChunkWriter({
            chunkSizeBytes: 2,
            emptyErrorMessage: 'test writer requires bytes.',
            expectedTotalByteLength: 4,
        });

        writer.writeBytes(new Uint8Array([1, 2, 3]));

        expect(() => writer.finishWithSummary()).toThrow(
            /expectedTotalByteLength/u,
        );
    });

    it('encodes safe-integer varuint values across chunk boundaries', () => {
        const value = 2 ** 40 + 127;
        const writer = new BinaryChunkWriter({
            chunkSizeBytes: 2,
            emptyErrorMessage: 'test writer requires bytes.',
        });

        writer.writeVaruint(value);
        const summary = writer.finishWithSummary();

        expect(flattenChunks(summary.chunks)).toEqual(
            expectedVaruintBytes(value),
        );
        expect(summary.chunkCount).toBeGreaterThan(1);
        expect(summary.totalByteLength).toBe(
            expectedVaruintBytes(value).length,
        );
    });
});
