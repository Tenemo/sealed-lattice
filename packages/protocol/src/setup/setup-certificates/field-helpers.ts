import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
import type { ProtocolHash } from '@sealed-lattice/types';

import { protocolHashPattern } from './constants.js';
import type {
    CollectiveBgvSetupParametersForCertificates,
    JsonRecord,
    SetupCertificateTransportedObjectInput,
} from './types.js';

export const assertObjectRecord = (
    value: unknown,
    fieldName: string,
): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

const cloneJsonRecord = (value: JsonRecord): JsonRecord =>
    JSON.parse(JSON.stringify(value)) as JsonRecord;

export const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const stringField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): string => {
    const fieldValue = value[fieldName];
    if (typeof fieldValue !== 'string' || fieldValue.length === 0) {
        throw new TypeError(`${objectPath}.${fieldName} must be non-empty.`);
    }

    return fieldValue;
};

export const hashField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): ProtocolHash => {
    const fieldValue = stringField(value, fieldName, objectPath);
    assertProtocolHash(fieldValue, `${objectPath}.${fieldName}`);

    return fieldValue;
};

export const acceptedCertificateTemplate = (
    setupParameters: CollectiveBgvSetupParametersForCertificates,
    templateFieldName: string,
    objectType: string,
    hashFieldName: string,
): JsonRecord | null => {
    const templates = setupParameters.acceptedCertificateTemplates;
    if (templates === undefined) {
        return null;
    }
    const certificate = assertObjectRecord(
        templates[templateFieldName],
        `setupParameters.acceptedCertificateTemplates.${templateFieldName}`,
    );
    if (certificate.objectType !== objectType) {
        throw new Error(
            `setupParameters.acceptedCertificateTemplates.${templateFieldName}.objectType must be ${objectType}.`,
        );
    }
    const certificateHash = stringField(
        certificate,
        hashFieldName,
        `setupParameters.acceptedCertificateTemplates.${templateFieldName}`,
    );
    assertProtocolHash(
        certificateHash,
        `setupParameters.acceptedCertificateTemplates.${templateFieldName}.${hashFieldName}`,
    );
    const hashInput = cloneJsonRecord(certificate);
    delete hashInput[hashFieldName];
    if (deriveCanonicalObjectHash(hashInput) !== certificateHash) {
        throw new Error(
            `setupParameters.acceptedCertificateTemplates.${templateFieldName}.${hashFieldName} must match the certificate body.`,
        );
    }

    return cloneJsonRecord(certificate);
};

export const numberField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = value[fieldName];
    if (
        typeof fieldValue !== 'number' ||
        !Number.isSafeInteger(fieldValue) ||
        fieldValue < 0
    ) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a non-negative safe integer.`,
        );
    }

    return fieldValue;
};

export const positiveNumberField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number => {
    const fieldValue = numberField(value, fieldName, objectPath);
    if (fieldValue <= 0) {
        throw new TypeError(
            `${objectPath}.${fieldName} must be a positive safe integer.`,
        );
    }

    return fieldValue;
};

export const objectField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): JsonRecord =>
    assertObjectRecord(value[fieldName], `${objectPath}.${fieldName}`);

export const hashArrayField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): ProtocolHash[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(`${objectPath}.${fieldName} must be an array.`);
    }

    return fieldValue.map((item, itemIndex) => {
        if (typeof item !== 'string') {
            throw new TypeError(
                `${objectPath}.${fieldName}.${String(itemIndex)} must be a protocol hash.`,
            );
        }
        assertProtocolHash(
            item,
            `${objectPath}.${fieldName}.${String(itemIndex)}`,
        );

        return item;
    });
};

export const setupCertificateTransportedObjectInputs = (
    transport: Readonly<Record<string, unknown>>,
): readonly SetupCertificateTransportedObjectInput[] => {
    const transportedObjects = transport.transportedObjects;
    if (transportedObjects === undefined) {
        return [];
    }
    if (!Array.isArray(transportedObjects)) {
        throw new TypeError('transport.transportedObjects must be an array.');
    }

    return transportedObjects.map((transportedObjectValue, objectIndex) => {
        const objectPath = `transport.transportedObjects.${String(objectIndex)}`;
        const transportedObject = assertObjectRecord(
            transportedObjectValue,
            objectPath,
        );

        return {
            objectName: stringField(
                transportedObject,
                'objectName',
                objectPath,
            ),
            objectRole: stringField(
                transportedObject,
                'objectRole',
                objectPath,
            ),
            objectRoot: hashField(transportedObject, 'objectRoot', objectPath),
            byteLength: positiveNumberField(
                transportedObject,
                'byteLength',
                objectPath,
            ),
            fullObjectHash: hashField(
                transportedObject,
                'fullObjectHash',
                objectPath,
            ),
            chunkRoot: hashField(transportedObject, 'chunkRoot', objectPath),
            chunkHashes: hashArrayField(
                transportedObject,
                'chunkHashes',
                objectPath,
            ),
        };
    });
};

export const numberArrayField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): number[] => {
    const fieldValue = value[fieldName];
    if (!Array.isArray(fieldValue)) {
        throw new TypeError(`${objectPath}.${fieldName} must be an array.`);
    }

    return fieldValue.map((item, itemIndex) => {
        if (
            typeof item !== 'number' ||
            !Number.isSafeInteger(item) ||
            item <= 0
        ) {
            throw new TypeError(
                `${objectPath}.${fieldName}.${String(itemIndex)} must be a positive safe integer.`,
            );
        }

        return item;
    });
};

export const scalarPowerSum = (
    coefficientCount: number,
    trusteePoint: number,
): bigint => {
    let scalarSum = 0n;
    let trusteePower = 1n;
    const trusteePointWide = BigInt(trusteePoint);
    for (
        let coefficientIndex = 0;
        coefficientIndex < coefficientCount;
        coefficientIndex += 1
    ) {
        scalarSum += trusteePower;
        if (coefficientIndex + 1 < coefficientCount) {
            trusteePower *= trusteePointWide;
        }
    }

    return scalarSum;
};

export const ceilLog2Bigint = (value: bigint): number => {
    if (value <= 1n) {
        return 0;
    }

    return (value - 1n).toString(2).length;
};

export const modulusProductDecimal = (moduli: readonly number[]): string =>
    moduli
        .reduce((product, modulus) => product * BigInt(modulus), 1n)
        .toString();

export const moduliBitLengthSum = (moduli: readonly number[]): number =>
    moduli.reduce(
        (bitLengthSum, modulus) => bitLengthSum + modulus.toString(2).length,
        0,
    );

export const keySwitchComponentPolynomialCount = (
    entries: readonly Readonly<{ readonly level: number }>[],
): number =>
    entries.reduce((total, entry) => {
        if (!Number.isSafeInteger(entry.level) || entry.level < 0) {
            throw new TypeError(
                'evaluatorKeySchedule levels must be non-negative safe integers.',
            );
        }
        const digitCount = entry.level + 1;

        return total + digitCount * digitCount;
    }, 0);
