export const wasm32UsizeByteLength = 4;

export const sha256HexPattern = /^[a-f0-9]{64}$/u;

export const textDecoder = new TextDecoder('utf-8', { fatal: true });

export const textEncoder = new TextEncoder();

const hexadecimalByteStrings = Object.freeze(
    Array.from({ length: 256 }, (_, byte) =>
        byte.toString(16).padStart(2, '0'),
    ),
);
const hexadecimalEncodingChunkByteLength = 8_192;

export const bytesToHex = (bytes: Uint8Array): string => {
    const chunks: string[] = [];
    for (
        let chunkStart = 0;
        chunkStart < bytes.byteLength;
        chunkStart += hexadecimalEncodingChunkByteLength
    ) {
        const chunkEnd = Math.min(
            bytes.byteLength,
            chunkStart + hexadecimalEncodingChunkByteLength,
        );
        const encodedBytes = new Array<string>(chunkEnd - chunkStart);
        for (let byteIndex = chunkStart; byteIndex < chunkEnd; byteIndex += 1) {
            encodedBytes[byteIndex - chunkStart] =
                hexadecimalByteStrings[bytes[byteIndex]] ?? '';
        }
        chunks.push(encodedBytes.join(''));
    }

    return chunks.join('');
};
