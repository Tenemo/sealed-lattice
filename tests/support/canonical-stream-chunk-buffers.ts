import { foundationProfile } from '#packages/types/src/foundation-contract';

export const canonicalStreamChunkBuffers = (
    bytes: Uint8Array,
): readonly ArrayBuffer[] => {
    const chunks: ArrayBuffer[] = [];
    for (
        let byteOffset = 0;
        byteOffset < bytes.byteLength;
        byteOffset += foundationProfile.streamChunkByteLength
    ) {
        chunks.push(
            bytes.slice(
                byteOffset,
                byteOffset + foundationProfile.streamChunkByteLength,
            ).buffer,
        );
    }
    return chunks;
};
