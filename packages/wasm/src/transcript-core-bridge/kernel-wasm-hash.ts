// wasm32 `usize` is 4 bytes; used to read/allocate the LE u32 output-length cell.
export const wasm32UsizeByteLength = 4;

// 8 bytes = the `\0asm` magic (4) plus the version word (4) at the module start.
export const wasmHeaderByteLength = 8;

// Section id 0 is the WASM custom-section id (debug / producers / name sections).
export const wasmCustomSectionId = 0;

export const sha256HexPattern = /^[a-f0-9]{64}$/u;

export const textDecoder = new TextDecoder('utf-8', { fatal: true });

export const textEncoder = new TextEncoder();

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const isPrintableAscii = (byte: number): boolean =>
    byte >= 0x20 && byte <= 0x7e;

// Neutralizes machine-specific absolute paths baked into the WASM so the integrity
// hash is reproducible across build hosts (mirrors --remap-path-prefix in
// build-wasm-kernel.ts).
const normalizeRustSourcePathForHash = (sourcePath: string): string => {
    const forwardSlashSourcePath = sourcePath.replace(/\\/gu, '/');
    const cargoRegistrySourcePath = forwardSlashSourcePath.replace(
        /^(?:[A-Za-z]:)?\/.*?\/\.cargo\/registry\/src\//u,
        '/cargo/registry/src/',
    );

    return cargoRegistrySourcePath.replace(
        /^.*?\/crates\/sealed-lattice-kernel\//u,
        'crates/sealed-lattice-kernel/',
    );
};

// Only normalizes NUL-delimited printable-ASCII chunks containing `.rs`; any chunk
// with non-printable bytes (i.e. binary) is returned untouched so normalization can
// never corrupt the module's executable sections.
const normalizeHashChunk = (chunk: Uint8Array): Uint8Array => {
    if (chunk.length === 0) {
        return chunk;
    }
    // 0x2e is '.'; skip chunks with no dot since they cannot contain a `.rs` path.
    if (!chunk.includes(0x2e)) {
        return chunk;
    }
    for (const byte of chunk) {
        if (!isPrintableAscii(byte)) {
            return chunk;
        }
    }

    const text = textDecoder.decode(chunk);
    if (!text.includes('.rs')) {
        return chunk;
    }

    const normalizedText = normalizeRustSourcePathForHash(text);
    if (normalizedText === text) {
        return chunk;
    }

    return textEncoder.encode(normalizedText);
};

export const normalizeRustSourcePathsForHash = (
    bytes: Uint8Array,
): Uint8Array => {
    const normalizedChunks: Uint8Array[] = [];
    let totalByteLength = 0;
    let chunkStart = 0;

    for (let byteIndex = 0; byteIndex <= bytes.length; byteIndex += 1) {
        if (byteIndex !== bytes.length && bytes[byteIndex] !== 0) {
            continue;
        }

        const normalizedChunk = normalizeHashChunk(
            bytes.subarray(chunkStart, byteIndex),
        );
        normalizedChunks.push(normalizedChunk);
        totalByteLength += normalizedChunk.length;

        if (byteIndex !== bytes.length) {
            normalizedChunks.push(Uint8Array.of(0));
            totalByteLength += 1;
        }
        chunkStart = byteIndex + 1;
    }

    const normalizedBytes = new Uint8Array(totalByteLength);
    let writeOffset = 0;
    for (const chunk of normalizedChunks) {
        normalizedBytes.set(chunk, writeOffset);
        writeOffset += chunk.length;
    }

    return normalizedBytes;
};

export const hasWasmHeader = (bytes: Uint8Array): boolean =>
    bytes.length >= wasmHeaderByteLength &&
    bytes[0] === 0x00 &&
    bytes[1] === 0x61 &&
    bytes[2] === 0x73 &&
    bytes[3] === 0x6d &&
    bytes[4] === 0x01 &&
    bytes[5] === 0x00 &&
    bytes[6] === 0x00 &&
    bytes[7] === 0x00;

// Canonical LEB128 reader for WASM section lengths: rejects encodings longer than
// 5 bytes, a 5th byte with bits above bit 32 set, or any value exceeding 2^32-1, so
// overlong / overflowing section lengths cannot be accepted.
export const readWasmVarUint32 = (
    bytes: Uint8Array,
    startOffset: number,
): { readonly nextOffset: number; readonly value: number } => {
    let value = 0;
    let multiplier = 1;

    for (
        let byteOffset = startOffset;
        byteOffset < bytes.length;
        byteOffset += 1
    ) {
        const byte = bytes[byteOffset];
        const groupIndex = byteOffset - startOffset;
        if (groupIndex >= 5 || (groupIndex === 4 && byte > 0x0f)) {
            throw new Error(
                'The transcript-core kernel contains an invalid WASM section length.',
            );
        }
        value += (byte & 0x7f) * multiplier;
        if (value > 0xffff_ffff) {
            throw new Error(
                'The transcript-core kernel contains an invalid WASM section length.',
            );
        }
        if (byte < 0x80) {
            return {
                nextOffset: byteOffset + 1,
                value,
            };
        }
        multiplier *= 0x80;
        if (multiplier > 0x1_0000_0000) {
            throw new Error(
                'The transcript-core kernel contains an invalid WASM section length.',
            );
        }
    }

    throw new Error(
        'The transcript-core kernel contains a truncated WASM section length.',
    );
};

export const concatenateByteChunks = (
    chunks: readonly Uint8Array[],
    totalByteLength: number,
): Uint8Array => {
    const output = new Uint8Array(totalByteLength);
    let writeOffset = 0;

    for (const chunk of chunks) {
        output.set(chunk, writeOffset);
        writeOffset += chunk.length;
    }

    return output;
};
