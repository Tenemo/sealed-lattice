import { appendVaruint } from './varuint-encoding.js';

export class ChunkedBinaryReader {
    private chunkIndex = 0;

    private chunkOffset = 0;

    private consumedByteLength = 0;

    private readonly totalByteLength: number;

    public constructor(private readonly chunks: readonly Uint8Array[]) {
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

    public readVaruint(fieldName: string): number {
        let shift = 0n;
        let value = 0n;
        const consumed: number[] = [];
        for (let byteIndex = 0; byteIndex < 10; byteIndex += 1) {
            const byte = this.readBytes(1, fieldName)[0];
            consumed.push(byte);
            value |= BigInt(byte & 0x7f) << shift;
            if ((byte & 0x80) === 0) {
                if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
                    throw new Error(
                        `${fieldName} does not fit a safe integer.`,
                    );
                }
                const numericValue = Number(value);
                const canonical: number[] = [];
                appendVaruint(canonical, numericValue);
                if (
                    canonical.length !== consumed.length ||
                    canonical.some(
                        (canonicalByte, index) =>
                            canonicalByte !== consumed[index],
                    )
                ) {
                    throw new Error(
                        `${fieldName} binary varuint is not minimally encoded.`,
                    );
                }

                return numericValue;
            }
            shift += 7n;
        }

        throw new Error(`${fieldName} binary varuint is too long.`);
    }

    public readU64(fieldName: string): number {
        const bytes = this.readBytes(8, fieldName);
        let value = 0n;
        for (let byteIndex = 7; byteIndex >= 0; byteIndex -= 1) {
            value <<= 8n;
            value |= BigInt(bytes[byteIndex] ?? 0);
        }
        if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
            throw new Error(`${fieldName} does not fit a safe integer.`);
        }

        return Number(value);
    }
}
