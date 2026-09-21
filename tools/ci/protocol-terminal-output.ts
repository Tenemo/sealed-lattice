// This decodes the owning kernel's output. It creates no verification
// capability and must never replace the kernel's successful terminal check.
export function decodeTerminalOutput(encoded: Uint8Array): string[] {
    if (encoded.length < 4 || encoded.length > 1_048_576)
        throw new Error('Invalid terminal output length.');
    const view = new DataView(
        encoded.buffer,
        encoded.byteOffset,
        encoded.byteLength,
    );
    const count = view.getUint32(0, true);
    if (count > Math.floor((encoded.length - 4) / 5))
        throw new Error('Incomplete terminal identifiers.');
    const identifiers: string[] = [];
    const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    let offset = 4;
    for (let index = 0; index < count; index++) {
        if (offset + 4 > encoded.length)
            throw new Error('Truncated result identifier.');
        const length = view.getUint32(offset, true);
        offset += 4;
        if (length === 0 || length > encoded.length - offset)
            throw new Error('Invalid result identifier length.');
        identifiers.push(
            decoder.decode(encoded.subarray(offset, offset + length)),
        );
        offset += length;
    }
    if (offset !== encoded.length) throw new Error('Trailing terminal data.');
    return identifiers;
}
