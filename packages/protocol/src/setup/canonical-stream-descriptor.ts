import { foundationProfile } from '@sealed-lattice/types';

const maximumCanonicalStreamByteLength = 2_147_483_648;
const canonicalHashByteLength = 64;
const maximumCanonicalStreamChunkCount = Math.ceil(
    maximumCanonicalStreamByteLength / foundationProfile.streamChunkByteLength,
);
const maximumCanonicalStreamDescriptorByteLength =
    34 + canonicalHashByteLength * maximumCanonicalStreamChunkCount;

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

export const copyCanonicalStreamDescriptor = (
    descriptorValue: unknown,
    fieldPath: string,
): Uint8Array => {
    if (!isUint8Array(descriptorValue) || descriptorValue.byteLength === 0) {
        throw new TypeError(`${fieldPath} must be a non-empty Uint8Array.`);
    }
    if (
        descriptorValue.byteLength > maximumCanonicalStreamDescriptorByteLength
    ) {
        throw new TypeError(
            `${fieldPath} exceeds the canonical stream descriptor bound.`,
        );
    }

    const descriptorCopy = new Uint8Array(descriptorValue.byteLength);
    Uint8Array.prototype.set.call(descriptorCopy, descriptorValue);
    return descriptorCopy;
};
