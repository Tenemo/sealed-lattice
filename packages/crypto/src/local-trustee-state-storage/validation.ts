import type { ProtocolHash } from '@sealed-lattice/types';

export { decodeFixedHex } from '../web-crypto.js';

import { protocolHashPattern, type JsonRecord } from './constants-and-types.js';

export const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

export const assertNonNegativeSafeInteger = (
    value: number,
    fieldName: string,
): void => {
    if (!Number.isSafeInteger(value) || value < 0) {
        throw new TypeError(
            `${fieldName} must be a non-negative safe integer.`,
        );
    }
};

export const assertNonEmptyString = (
    value: string,
    fieldName: string,
): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const isJsonRecord = (value: unknown): value is JsonRecord =>
    typeof value === 'object' && value !== null && !Array.isArray(value);

export const assertJsonRecord = (
    value: unknown,
    fieldName: string,
): JsonRecord => {
    if (!isJsonRecord(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value;
};

export const assertRequiredFields = (
    value: JsonRecord,
    requiredFieldNames: readonly string[],
    objectPath: string,
): void => {
    for (const fieldName of requiredFieldNames) {
        if (!(fieldName in value)) {
            throw new TypeError(
                `${objectPath}.${fieldName} is required by the local trustee state schema.`,
            );
        }
    }
};

export const stringField = (
    value: JsonRecord,
    fieldName: string,
    displayName = fieldName,
): string => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'string') {
        throw new TypeError(`${displayName} must be a string.`);
    }

    return fieldValue;
};

export const numberField = (value: JsonRecord, fieldName: string): number => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'number') {
        throw new TypeError(`${fieldName} must be a number.`);
    }

    return fieldValue;
};

export const protocolHashArrayField = (
    value: JsonRecord,
    fieldName: string,
): ProtocolHash[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(
            `${fieldName} must be an array of protocol hashes.`,
        );
    }

    return fieldValue.map((item, itemIndex) => {
        if (typeof item !== 'string') {
            throw new TypeError(
                `${fieldName}.${String(itemIndex)} must be a protocol hash.`,
            );
        }
        assertProtocolHash(item, `${fieldName}.${String(itemIndex)}`);

        return item;
    });
};
