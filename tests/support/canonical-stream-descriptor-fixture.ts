const canonicalChunkByteLength = 1_048_576;
const canonicalHashByteLength = 64;

export const canonicalStreamDescriptorFixture = (
    totalByteLength: number,
    chunkHashByte = 0x41,
    fullObjectDigestByte = 0x42,
): Uint8Array => {
    if (!Number.isSafeInteger(totalByteLength) || totalByteLength <= 0) {
        throw new TypeError('totalByteLength must be a positive safe integer.');
    }
    const chunkCount = Math.ceil(totalByteLength / canonicalChunkByteLength);
    const descriptorBytes = new Uint8Array(
        104 + canonicalHashByteLength * chunkCount,
    );
    const view = new DataView(descriptorBytes.buffer);
    view.setUint16(0, 0x1800, true);
    view.setUint16(2, 1, true);
    view.setUint32(4, 3, true);

    let byteOffset = 8;
    view.setUint16(byteOffset, 0x05, true);
    view.setUint32(byteOffset + 2, 8, true);
    view.setBigUint64(byteOffset + 6, BigInt(totalByteLength), true);
    byteOffset += 14;

    view.setUint16(byteOffset, 0x0e, true);
    view.setUint32(
        byteOffset + 2,
        6 + canonicalHashByteLength * chunkCount,
        true,
    );
    view.setUint16(byteOffset + 6, 0x06, true);
    view.setUint32(byteOffset + 8, chunkCount, true);
    byteOffset += 12;
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        descriptorBytes.fill(
            (chunkHashByte + chunkIndex) & 0xff,
            byteOffset,
            byteOffset + canonicalHashByteLength,
        );
        byteOffset += canonicalHashByteLength;
    }

    view.setUint16(byteOffset, 0x06, true);
    view.setUint32(byteOffset + 2, canonicalHashByteLength, true);
    descriptorBytes.fill(
        fullObjectDigestByte,
        byteOffset + 6,
        byteOffset + 6 + canonicalHashByteLength,
    );

    return descriptorBytes;
};
