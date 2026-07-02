export class ChunkedBinaryReader {
    private chunkIndex = 0;

    private chunkOffset = 0;

    private consumedByteLength = 0;

    private readonly totalByteLength: number;

    public constructor(
        private readonly chunks: readonly Uint8Array[],
        input: { readonly emptyChunksMessage?: string } = {},
    ) {
        if (chunks.length === 0 && input.emptyChunksMessage !== undefined) {
            throw new Error(input.emptyChunksMessage);
        }
        this.totalByteLength = chunks.reduce(
            (accumulatedLength, chunk) => accumulatedLength + chunk.byteLength,
            0,
        );
    }

    public isFinished(): boolean {
        return this.consumedByteLength === this.totalByteLength;
    }

    public readBytes(byteLength: number, fieldName: string): Uint8Array {
        if (
            byteLength < 0 ||
            this.consumedByteLength + byteLength > this.totalByteLength
        ) {
            throw new Error(
                `${fieldName} ended before the binary object was complete.`,
            );
        }

        const outputBytes = new Uint8Array(byteLength);
        let outputOffset = 0;
        while (outputOffset < byteLength) {
            const chunk = this.chunks[this.chunkIndex];
            if (chunk === undefined) {
                throw new Error(
                    `${fieldName} ended before the binary object was complete.`,
                );
            }
            const availableLength = chunk.byteLength - this.chunkOffset;
            if (availableLength === 0) {
                this.chunkIndex += 1;
                this.chunkOffset = 0;
                continue;
            }
            const copyLength = Math.min(
                byteLength - outputOffset,
                availableLength,
            );
            outputBytes.set(
                chunk.subarray(this.chunkOffset, this.chunkOffset + copyLength),
                outputOffset,
            );
            outputOffset += copyLength;
            this.chunkOffset += copyLength;
            this.consumedByteLength += copyLength;
        }

        return outputBytes;
    }
}
