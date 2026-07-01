import type { ProtocolHash } from '@sealed-lattice/types';

import {
    assertContextFieldPathsMatch,
    setupContextFieldNames,
} from '../common-fields.js';
import type { CollectiveBgvSetupContext } from '../vss-share-verification-records.js';

import type { JsonRecord } from './types.js';

const protocolHashPattern = /^[0-9a-f]{128}$/u;
const setupContextTokenPattern = /^[A-Za-z0-9._:/@+-]{1,128}$/u;
export const requiredSetupPhases = [
    ['rosterFreeze', 1],
    ['setupIntent', 2],
    ['commonRandomnessCommit', 3],
    ['commonRandomnessReveal', 4],
    ['vssCoefficientCommitments', 5],
    ['privateVssEnvelopeDelivery', 6],
    ['recipientVssVerification', 7],
    ['vssAcceptanceOrComplaint', 8],
    ['publicKeyShareProofs', 9],
    ['relinearizationRoundOne', 10],
    ['relinearizationRoundTwo', 11],
    ['galoisKeyShareBatches', 12],
    ['trusteeEvaluationKeyProofs', 13],
    ['setupPackageAssembly', 14],
    ['setupPackageVerification', 15],
] as const;

export const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

const assertNonEmptyString = (value: string, fieldName: string): void => {
    if (value.length === 0) {
        throw new TypeError(`${fieldName} must be non-empty.`);
    }
};

const assertSetupContextToken = (value: string, fieldName: string): void => {
    if (!setupContextTokenPattern.test(value)) {
        throw new TypeError(
            `${fieldName} must be a bounded setup context token.`,
        );
    }
};

export const assertObjectRecord = (
    value: unknown,
    fieldName: string,
): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new TypeError(`${fieldName} must be an object.`);
    }

    return value as JsonRecord;
};

export const assertContext = (
    setupContext: CollectiveBgvSetupContext,
): void => {
    for (const fieldName of setupContextFieldNames) {
        assertNonEmptyString(
            setupContext[fieldName],
            `setupContext.${fieldName}`,
        );
    }
    for (const fieldName of ['ceremonyId', 'setupEpoch'] as const) {
        assertSetupContextToken(
            setupContext[fieldName],
            `setupContext.${fieldName}`,
        );
    }
    for (const fieldName of [
        'manifestHash',
        'rosterHash',
        'setupParametersHash',
    ] as const) {
        assertProtocolHash(
            setupContext[fieldName],
            `setupContext.${fieldName}`,
        );
    }
};

export const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    objectPath: string,
): void => assertContextFieldPathsMatch(setupContext, value, objectPath);

const objectTypeAt = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
): string => {
    const objectType = value.objectType;
    if (typeof objectType !== 'string' || objectType.length === 0) {
        throw new TypeError(`${fieldName}.objectType must be non-empty.`);
    }

    return objectType;
};

export const assertObjectType = (
    value: unknown,
    fieldName: string,
    expectedObjectType: string,
): void => {
    const objectRecord = assertObjectRecord(value, fieldName);
    const objectType = objectTypeAt(objectRecord, fieldName);
    if (objectType !== expectedObjectType) {
        throw new Error(
            `${fieldName}.objectType must be ${expectedObjectType}.`,
        );
    }
    if (objectRecord.objectVersion !== 1) {
        throw new Error(`${fieldName}.objectVersion must be 1.`);
    }
};

export const hashField = (
    value: Readonly<Record<string, unknown>>,
    fieldName: string,
    objectPath: string,
): ProtocolHash => {
    const hashValue = value[fieldName];
    if (typeof hashValue !== 'string') {
        throw new TypeError(`${objectPath}.${fieldName} must be a string.`);
    }
    assertProtocolHash(hashValue, `${objectPath}.${fieldName}`);

    return hashValue;
};

export const cloneJsonLike = (value: unknown): unknown => {
    if (Array.isArray(value)) {
        return value.map(cloneJsonLike);
    }
    if (typeof value !== 'object' || value === null) {
        return value;
    }

    return Object.fromEntries(
        Object.entries(value as JsonRecord).map(([fieldName, fieldValue]) => [
            fieldName,
            cloneJsonLike(fieldValue),
        ]),
    );
};
