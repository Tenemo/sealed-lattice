import { BrowserActionStorageCustodyError } from '../browser-action-storage-custody.js';

export const mutationIdentifierByteLength = 32;
export const storageRootCommitmentByteLength = 64;
export const maximumCheckpointCollectionLength = 4096;
export const maximumCheckpointDescriptorByteLength = 1_048_576;

export const copyBytes = (
    value: unknown,
    byteLength: number,
    label: string,
): Uint8Array => {
    if (!(value instanceof Uint8Array) || value.byteLength !== byteLength) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must contain exactly ${byteLength} bytes.`,
        );
    }

    return value.slice();
};

export const copyBoundedBytes = (
    value: unknown,
    maximumByteLength: number,
    label: string,
): Uint8Array => {
    if (
        !(value instanceof Uint8Array) ||
        value.byteLength > maximumByteLength
    ) {
        throw new BrowserActionStorageCustodyError(
            'InvalidInput',
            `${label} must be a byte array within the worker-channel copy bound.`,
        );
    }
    return value.slice();
};

export const bytesEqual = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.byteLength !== right.byteLength) {
        return false;
    }
    let difference = 0;
    for (let byteIndex = 0; byteIndex < left.byteLength; byteIndex += 1) {
        difference |= (left[byteIndex] ?? 0) ^ (right[byteIndex] ?? 0);
    }
    return difference === 0;
};
