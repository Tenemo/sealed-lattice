type BinaryChunkWriterInput = Readonly<{
    readonly chunkSizeBytes: number;
    readonly emptyErrorMessage: string;
}>;

export class BinaryChunkWriter {
    private readonly chunkSizeBytes: number;
    private readonly emptyErrorMessage: string;
    private readonly chunks: Uint8Array[] = [];
    private currentChunk: Uint8Array;
    private currentChunkLength = 0;

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
        this.currentChunk = new Uint8Array(input.chunkSizeBytes);
    }

    public writeByte(value: number): void {
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
            let byte = remainingValue & 0x7f;
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
        if (this.currentChunkLength > 0) {
            this.chunks.push(
                this.currentChunk.slice(0, this.currentChunkLength),
            );
            this.currentChunk = new Uint8Array(this.chunkSizeBytes);
            this.currentChunkLength = 0;
        }
        if (this.chunks.length === 0) {
            throw new Error(this.emptyErrorMessage);
        }

        return this.chunks;
    }

    private flushFullChunk(): void {
        this.chunks.push(this.currentChunk);
        this.currentChunk = new Uint8Array(this.chunkSizeBytes);
        this.currentChunkLength = 0;
    }
}
