import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import { isProtocolHash, type ProtocolHash } from '@sealed-lattice/types';

import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

export type JsonRecord = Record<string, unknown>;

export const assertProtocolHash = (
    value: unknown,
    fieldName: string,
): ProtocolHash => {
    if (!isProtocolHash(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }

    return value;
};

export const assertNonEmptyString = (
    value: unknown,
    fieldName: string,
): string => {
    if (typeof value !== 'string' || value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }

    return value;
};

export const assertPositiveSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value <= 0
    ) {
        throw new TypeError(`${fieldName} must be a positive safe integer.`);
    }

    return value;
};

export const assertNonNegativeSafeInteger = (
    value: unknown,
    fieldName: string,
): number => {
    if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0
    ) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }

    return value;
};

export const assertJsonRecord = (
    value: unknown,
    fieldName: string,
): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const lowercaseHexBytesPattern = /^(?:[0-9a-f]{2})*$/u;

const assertLowercaseHexBytes = (value: string, fieldName: string): void => {
    if (!lowercaseHexBytesPattern.test(value)) {
        throw new TypeError(`${fieldName} must be lowercase hex bytes.`);
    }
};

export const bytesFromHex = (hex: string, fieldName: string): Uint8Array => {
    assertLowercaseHexBytes(hex, fieldName);
    const bytes = new Uint8Array(hex.length / 2);
    for (let byteIndex = 0; byteIndex < bytes.length; byteIndex += 1) {
        bytes[byteIndex] = Number.parseInt(
            hex.slice(byteIndex * 2, byteIndex * 2 + 2),
            16,
        );
    }

    return bytes;
};

export const bytesToHex = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

export const deriveCollectiveBgvSetupContextHash = (
    setupContext: CollectiveBgvSetupContext,
): ProtocolHash =>
    deriveCanonicalObjectHash({
        objectType: 'CollectiveBgvSetupContext',
        ceremonyId: setupContext.ceremonyId,
        manifestHash: setupContext.manifestHash,
        rosterHash: setupContext.rosterHash,
        setupParametersHash: setupContext.setupParametersHash,
        setupEpoch: setupContext.setupEpoch,
        participantCount: setupContext.participantCount,
    });

export const assertSetupContextHashMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    objectPath: string,
): void => {
    if (
        value.setupContextHash !==
        deriveCollectiveBgvSetupContextHash(setupContext)
    ) {
        throw new Error(
            `${objectPath}.setupContextHash must match the authoritative setup context.`,
        );
    }
};
