import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import {
    canonicalItemTypes,
    foundationProfile,
    foundationSchemaIdentifiers,
    type ProtocolHash,
} from '@sealed-lattice/types';

import { setupTransportStorageQuotaBytes } from './setup-certificates/constants.js';

const canonicalFoundationSchemaVersion = 1;
const canonicalTupleHeaderByteLength = 8;
const canonicalItemHeaderByteLength = 6;
const canonicalHashByteLength = 64;
const canonicalStreamDescriptorItemCount = 3;
const homogeneousListHeaderByteLength = 6;
const maximumCanonicalStreamChunkCount = Math.ceil(
    setupTransportStorageQuotaBytes / foundationProfile.streamChunkByteLength,
);
const maximumCanonicalStreamDescriptorByteLength =
    104 + canonicalHashByteLength * maximumCanonicalStreamChunkCount;

type DecodedCanonicalStreamDescriptor = Readonly<{
    readonly totalByteLength: number;
    readonly chunkHashes: readonly ProtocolHash[];
    readonly fullObjectHash: ProtocolHash;
}>;

export type CanonicalStreamTransportAccounting = Readonly<{
    readonly totalByteLength: number;
    readonly fullObjectHash: ProtocolHash;
    readonly chunkRoot: ProtocolHash;
    readonly chunkHashes: readonly ProtocolHash[];
}>;

const isUint8Array = (value: unknown): value is Uint8Array =>
    ArrayBuffer.isView(value) &&
    Object.prototype.toString.call(value) === '[object Uint8Array]';

const lowercaseHash = (bytes: Uint8Array): ProtocolHash =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const requireAvailableBytes = (
    availableByteLength: number,
    requiredEndOffset: number,
    fieldPath: string,
): void => {
    if (requiredEndOffset > availableByteLength) {
        throw new TypeError(`${fieldPath} is truncated.`);
    }
};

const requireItemHeader = (
    view: DataView,
    descriptorByteLength: number,
    byteOffset: number,
    expectedItemType: number,
    itemPath: string,
): Readonly<{ readonly byteLength: number; readonly valueOffset: number }> => {
    requireAvailableBytes(
        descriptorByteLength,
        byteOffset + canonicalItemHeaderByteLength,
        itemPath,
    );
    const itemType = view.getUint16(byteOffset, true);
    if (itemType !== expectedItemType) {
        throw new TypeError(`${itemPath} has the wrong canonical item type.`);
    }
    const byteLength = view.getUint32(byteOffset + 2, true);
    const valueOffset = byteOffset + canonicalItemHeaderByteLength;
    requireAvailableBytes(
        descriptorByteLength,
        valueOffset + byteLength,
        itemPath,
    );

    return { byteLength, valueOffset };
};

const decodeCanonicalStreamDescriptor = (
    descriptorValue: unknown,
    fieldPath: string,
): DecodedCanonicalStreamDescriptor => {
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
    requireAvailableBytes(
        descriptorValue.byteLength,
        canonicalTupleHeaderByteLength,
        fieldPath,
    );

    const view = new DataView(
        descriptorValue.buffer,
        descriptorValue.byteOffset,
        descriptorValue.byteLength,
    );
    if (
        view.getUint16(0, true) !== foundationSchemaIdentifiers.streamDescriptor
    ) {
        throw new TypeError(
            `${fieldPath} must use the canonical stream descriptor schema.`,
        );
    }
    if (view.getUint16(2, true) !== canonicalFoundationSchemaVersion) {
        throw new TypeError(
            `${fieldPath} must use canonical stream descriptor version 1.`,
        );
    }
    if (view.getUint32(4, true) !== canonicalStreamDescriptorItemCount) {
        throw new TypeError(
            `${fieldPath} must contain exactly three canonical items.`,
        );
    }

    let byteOffset = canonicalTupleHeaderByteLength;
    const totalByteLengthItem = requireItemHeader(
        view,
        descriptorValue.byteLength,
        byteOffset,
        canonicalItemTypes.unsigned64,
        `${fieldPath}.totalByteLength`,
    );
    if (totalByteLengthItem.byteLength !== 8) {
        throw new TypeError(
            `${fieldPath}.totalByteLength must use the canonical eight-byte length.`,
        );
    }
    const totalByteLengthValue = view.getBigUint64(
        totalByteLengthItem.valueOffset,
        true,
    );
    if (
        totalByteLengthValue === 0n ||
        totalByteLengthValue > BigInt(setupTransportStorageQuotaBytes)
    ) {
        throw new TypeError(
            `${fieldPath}.totalByteLength is outside the canonical stream bound.`,
        );
    }
    const totalByteLength = Number(totalByteLengthValue);
    byteOffset =
        totalByteLengthItem.valueOffset + totalByteLengthItem.byteLength;

    const chunkHashesItem = requireItemHeader(
        view,
        descriptorValue.byteLength,
        byteOffset,
        canonicalItemTypes.homogeneousList,
        `${fieldPath}.chunkHashes`,
    );
    if (chunkHashesItem.byteLength < homogeneousListHeaderByteLength) {
        throw new TypeError(
            `${fieldPath}.chunkHashes has a truncated canonical list header.`,
        );
    }
    if (
        view.getUint16(chunkHashesItem.valueOffset, true) !==
        canonicalItemTypes.hash512
    ) {
        throw new TypeError(
            `${fieldPath}.chunkHashes must be a homogeneous hash512 list.`,
        );
    }
    const chunkCount = view.getUint32(chunkHashesItem.valueOffset + 2, true);
    if (chunkCount === 0 || chunkCount > maximumCanonicalStreamChunkCount) {
        throw new TypeError(
            `${fieldPath}.chunkHashes count is outside the canonical stream bound.`,
        );
    }
    const expectedChunkHashesItemByteLength =
        homogeneousListHeaderByteLength + canonicalHashByteLength * chunkCount;
    if (chunkHashesItem.byteLength !== expectedChunkHashesItemByteLength) {
        throw new TypeError(
            `${fieldPath}.chunkHashes does not use the canonical list length.`,
        );
    }
    const expectedChunkCount = Math.ceil(
        totalByteLength / foundationProfile.streamChunkByteLength,
    );
    if (chunkCount !== expectedChunkCount) {
        throw new TypeError(
            `${fieldPath}.chunkHashes count does not match totalByteLength.`,
        );
    }
    const chunkHashes: ProtocolHash[] = [];
    let chunkHashOffset =
        chunkHashesItem.valueOffset + homogeneousListHeaderByteLength;
    for (let chunkIndex = 0; chunkIndex < chunkCount; chunkIndex += 1) {
        const chunkHashEndOffset = chunkHashOffset + canonicalHashByteLength;
        chunkHashes.push(
            lowercaseHash(
                descriptorValue.subarray(chunkHashOffset, chunkHashEndOffset),
            ),
        );
        chunkHashOffset = chunkHashEndOffset;
    }
    byteOffset = chunkHashesItem.valueOffset + chunkHashesItem.byteLength;

    const fullObjectHashItem = requireItemHeader(
        view,
        descriptorValue.byteLength,
        byteOffset,
        canonicalItemTypes.hash512,
        `${fieldPath}.fullObjectHash`,
    );
    if (fullObjectHashItem.byteLength !== canonicalHashByteLength) {
        throw new TypeError(
            `${fieldPath}.fullObjectHash must use the canonical hash512 length.`,
        );
    }
    const descriptorEndOffset =
        fullObjectHashItem.valueOffset + fullObjectHashItem.byteLength;
    if (descriptorEndOffset !== descriptorValue.byteLength) {
        throw new TypeError(`${fieldPath} contains trailing bytes.`);
    }

    return {
        totalByteLength,
        chunkHashes,
        fullObjectHash: lowercaseHash(
            descriptorValue.subarray(
                fullObjectHashItem.valueOffset,
                descriptorEndOffset,
            ),
        ),
    };
};

export const canonicalStreamTransportAccountingFromDescriptor = (
    descriptorValue: unknown,
    fieldPath: string,
): CanonicalStreamTransportAccounting => {
    const descriptor = decodeCanonicalStreamDescriptor(
        descriptorValue,
        fieldPath,
    );

    return {
        totalByteLength: descriptor.totalByteLength,
        fullObjectHash: descriptor.fullObjectHash,
        chunkRoot: deriveCanonicalObjectHash({
            objectType: 'SetupTransportChunkManifest',
            chunkCount: descriptor.chunkHashes.length,
            totalByteLength: descriptor.totalByteLength,
            chunkHashes: descriptor.chunkHashes,
            fullObjectHash: descriptor.fullObjectHash,
        }),
        chunkHashes: descriptor.chunkHashes,
    };
};

export const copyCanonicalStreamDescriptor = (
    descriptorValue: unknown,
    fieldPath: string,
): Uint8Array => {
    decodeCanonicalStreamDescriptor(descriptorValue, fieldPath);
    const descriptorBytes = descriptorValue as Uint8Array;
    const descriptorCopy = new Uint8Array(descriptorBytes.byteLength);
    Uint8Array.prototype.set.call(descriptorCopy, descriptorBytes);

    return descriptorCopy;
};
