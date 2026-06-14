type BinaryChunkWriterInput = Readonly<{
    readonly chunkSizeBytes: number;
    readonly emptyErrorMessage: string;
    readonly expectedTotalByteLength?: number;
    readonly retainChunks?: boolean;
    readonly consumeChunk?: (chunkIndex: number, chunk: Uint8Array) => void;
}>;

export type BinaryChunkWriterFinishResult = Readonly<{
    readonly chunks: readonly Uint8Array[];
    readonly chunkCount: number;
    readonly totalByteLength: number;
}>;

export class BinaryChunkWriter {
    private readonly chunkSizeBytes: number;
    private readonly emptyErrorMessage: string;
    private readonly expectedTotalByteLength?: number;
    private readonly retainChunks: boolean;
    private readonly consumeChunk?: (
        chunkIndex: number,
        chunk: Uint8Array,
    ) => void;
    private readonly chunks: Uint8Array[] = [];
    private currentChunk: Uint8Array;
    private currentChunkLength = 0;
    private flushedChunkCount = 0;
    private totalByteLength = 0;
    private finishResult?: BinaryChunkWriterFinishResult;

    public constructor(input: BinaryChunkWriterInput) {
        if (
            !Number.isSafeInteger(input.chunkSizeBytes) ||
            input.chunkSizeBytes <= 0
        ) {
            throw new TypeError(
                'binary chunk writer chunkSizeBytes must be a positive safe integer.',
            );
        }
        this.chunkSizeBytes = input.chunkSizeBytes;
        this.emptyErrorMessage = input.emptyErrorMessage;
        this.expectedTotalByteLength = input.expectedTotalByteLength;
        this.retainChunks = input.retainChunks ?? true;
        this.consumeChunk = input.consumeChunk;
        this.currentChunk = new Uint8Array(input.chunkSizeBytes);
    }

    public writeByte(value: number): void {
        this.assertWritable();
        if (!Number.isInteger(value) || value < 0 || value > 255) {
            throw new TypeError(
                'binary chunk writer byte values must be integers in [0, 255].',
            );
        }
        if (this.currentChunkLength === this.chunkSizeBytes) {
            this.flushFullChunk();
        }
        this.currentChunk[this.currentChunkLength] = value;
        this.currentChunkLength += 1;
    }

    public writeBytes(bytes: Uint8Array): void {
        this.assertWritable();
        let byteOffset = 0;
        while (byteOffset < bytes.byteLength) {
            if (this.currentChunkLength === this.chunkSizeBytes) {
                this.flushFullChunk();
            }
            const writableByteCount = Math.min(
                this.chunkSizeBytes - this.currentChunkLength,
                bytes.byteLength - byteOffset,
            );
            this.currentChunk.set(
                bytes.subarray(byteOffset, byteOffset + writableByteCount),
                this.currentChunkLength,
            );
            this.currentChunkLength += writableByteCount;
            byteOffset += writableByteCount;
        }
    }

    public writeVaruint(value: number): void {
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new TypeError(
                'binary varuint value must be a non-negative safe integer.',
            );
        }
        let remainingValue = value;
        do {
            let byte = remainingValue % 128;
            remainingValue = Math.floor(remainingValue / 128);
            if (remainingValue !== 0) {
                byte |= 0x80;
            }
            this.writeByte(byte);
        } while (remainingValue !== 0);
    }

    public writeU64LittleEndian(value: number, fieldName: string): void {
        if (!Number.isSafeInteger(value) || value < 0) {
            throw new TypeError(
                `${fieldName} must be a non-negative safe integer.`,
            );
        }
        let remainingValue = BigInt(value);
        for (let byteIndex = 0; byteIndex < 8; byteIndex += 1) {
            this.writeByte(Number(remainingValue & 0xffn));
            remainingValue >>= 8n;
        }
    }

    public finish(): readonly Uint8Array[] {
        return this.finishWithSummary().chunks;
    }

    public finishWithSummary(): BinaryChunkWriterFinishResult {
        if (this.finishResult !== undefined) {
            return this.finishResult;
        }
        if (this.currentChunkLength > 0) {
            this.flushFullChunk();
        }
        if (this.flushedChunkCount === 0) {
            throw new Error(this.emptyErrorMessage);
        }
        if (
            this.expectedTotalByteLength !== undefined &&
            this.totalByteLength !== this.expectedTotalByteLength
        ) {
            throw new Error(
                'binary chunk writer totalByteLength must match expectedTotalByteLength.',
            );
        }

        this.finishResult = {
            chunks: this.chunks.slice(),
            chunkCount: this.flushedChunkCount,
            totalByteLength: this.totalByteLength,
        };

        return this.finishResult;
    }

    private assertWritable(): void {
        if (this.finishResult !== undefined) {
            throw new Error(
                'binary chunk writer cannot be written after finish.',
            );
        }
    }

    private flushFullChunk(): void {
        const chunk = this.currentChunk.slice(0, this.currentChunkLength);
        const chunkIndex = this.flushedChunkCount;
        this.flushedChunkCount += 1;
        this.totalByteLength += chunk.byteLength;
        if (this.retainChunks) {
            this.chunks.push(chunk);
        }
        this.consumeChunk?.(chunkIndex, chunk);
        this.currentChunk = new Uint8Array(this.chunkSizeBytes);
        this.currentChunkLength = 0;
    }
}
