import {
    configurableParticipantCountRange,
    deriveFoundationRosterParameters,
    isProtocolHash,
    type FoundationRosterParameters,
    type ProtocolHash,
} from '@sealed-lattice/types';

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

export const requireFoundationRosterParameters = (
    value: unknown,
    fieldName: string,
): FoundationRosterParameters => {
    if (typeof value !== 'number' || !Number.isSafeInteger(value)) {
        throw new TypeError(`${fieldName} must be an integer.`);
    }
    try {
        return deriveFoundationRosterParameters(value);
    } catch {
        throw new RangeError(
            `${fieldName} must be from ${String(configurableParticipantCountRange.minimum)} through ${String(configurableParticipantCountRange.maximum)}.`,
        );
    }
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
