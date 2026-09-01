import { maximumFoundationCopiedBufferByteLength } from './foundation-contract.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';

type ConstructionErrorCode =
    | 'InvalidEnum'
    | 'InvalidProtocolObject'
    | 'InvalidUtf8'
    | 'MalformedLength'
    | 'TrailingBytes';

export class ConstructionKernelCommandError extends Error {
    readonly code: ConstructionErrorCode;

    constructor(code: ConstructionErrorCode, message: string) {
        super(`${code}: ${message}`);
        this.name = 'ConstructionKernelCommandError';
        this.code = code;
    }
}

export class ConstructionCommandWriter {
    readonly #chunks: Uint8Array[] = [];
    #length = 0;

    #write(bytes: Uint8Array): void {
        const requiredLength = this.#length + bytes.byteLength;
        if (
            !Number.isSafeInteger(requiredLength) ||
            requiredLength > maximumFoundationCopiedBufferByteLength
        ) {
            throw new RangeError(
                'The construction command exceeds the copied-buffer limit.',
            );
        }
        this.#chunks.push(bytes);
        this.#length = requiredLength;
    }

    writeU8(value: number): void {
        this.#write(Uint8Array.of(value));
    }

    writeU16(value: number): void {
        const bytes = new Uint8Array(2);
        new DataView(bytes.buffer).setUint16(0, value, true);
        this.#write(bytes);
    }

    writeFixed(bytes: Uint8Array): void {
        this.#write(bytes);
    }

    writeBytes(bytes: Uint8Array): void {
        const length = new Uint8Array(4);
        new DataView(length.buffer).setUint32(0, bytes.byteLength, true);
        this.#write(length);
        this.#write(bytes);
    }

    finish(): Uint8Array {
        const output = new Uint8Array(this.#length);
        let offset = 0;
        for (const chunk of this.#chunks) {
            output.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return output;
    }
}

class ConstructionCommandReader {
    #offset = 0;

    constructor(private readonly bytes: Uint8Array) {}

    readU8(): number {
        return this.readFixed(1)[0] ?? 0;
    }

    readU16(): number {
        const bytes = this.readFixed(2);
        return new DataView(
            bytes.buffer,
            bytes.byteOffset,
            bytes.byteLength,
        ).getUint16(0, true);
    }

    readFixed(length: number): Uint8Array {
        const end = this.#offset + length;
        if (length < 0 || end > this.bytes.byteLength) {
            throw new Error(
                'The construction kernel returned a truncated response.',
            );
        }
        const value = this.bytes.subarray(this.#offset, end);
        this.#offset = end;
        return value;
    }

    readBytes(): Uint8Array {
        const lengthBytes = this.readFixed(4);
        const length = new DataView(
            lengthBytes.buffer,
            lengthBytes.byteOffset,
            lengthBytes.byteLength,
        ).getUint32(0, true);
        return this.readFixed(length);
    }

    readString(): string {
        return new TextDecoder('utf-8', { fatal: true }).decode(
            this.readBytes(),
        );
    }

    finish(): void {
        if (this.#offset !== this.bytes.byteLength) {
            throw new Error(
                'The construction kernel returned trailing response bytes.',
            );
        }
    }
}

const constructionErrorCodes = new Set<ConstructionErrorCode>([
    'InvalidEnum',
    'InvalidProtocolObject',
    'InvalidUtf8',
    'MalformedLength',
    'TrailingBytes',
]);

export const executeConstructionCommand = <Result>(
    kernel: ConstructionKernelCommandRuntime,
    request: ConstructionCommandWriter,
    decodeResult: (reader: ConstructionCommandReader) => Result,
): Result => {
    const requestBytes = request.finish();
    let responseBytes: Uint8Array | undefined;
    try {
        responseBytes = kernel.executeCommand(requestBytes);
        const reader = new ConstructionCommandReader(responseBytes);
        const status = reader.readU8();
        if (status === 1) {
            const code = reader.readString();
            const message = reader.readString();
            reader.finish();
            if (!constructionErrorCodes.has(code as ConstructionErrorCode)) {
                throw new Error(
                    'The construction kernel returned an unknown error code.',
                );
            }
            throw new ConstructionKernelCommandError(
                code as ConstructionErrorCode,
                message,
            );
        }
        if (status !== 0) {
            throw new Error(
                'The construction kernel returned an invalid command status.',
            );
        }
        const result = decodeResult(reader);
        reader.finish();
        return result;
    } finally {
        requestBytes.fill(0);
        responseBytes?.fill(0);
    }
};

export const requireExactConstructionBytes = (
    bytes: Uint8Array,
    expectedLength: number,
    name: string,
): void => {
    if (!(bytes instanceof Uint8Array) || bytes.byteLength !== expectedLength) {
        throw new TypeError(
            `${name} must be a ${String(expectedLength)}-byte Uint8Array.`,
        );
    }
};
