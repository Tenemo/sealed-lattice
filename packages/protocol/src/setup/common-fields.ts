import type { CollectiveBgvSetupContext } from './vss-share-verification-records.js';

export const protocolHashPattern = /^[0-9a-f]{128}$/u;

const setupContextFieldNames = [
    'ceremonyId',
    'manifestHash',
    'rosterHash',
    'setupParametersHash',
    'setupEpoch',
] as const;

type SetupContextFieldName = (typeof setupContextFieldNames)[number];

export const assertProtocolHash = (value: string, fieldName: string): void => {
    if (!protocolHashPattern.test(value)) {
        throw new TypeError(`${fieldName} must be a protocol hash.`);
    }
};

export const contextFields = (
    setupContext: CollectiveBgvSetupContext,
): Pick<CollectiveBgvSetupContext, SetupContextFieldName> => ({
    ceremonyId: setupContext.ceremonyId,
    manifestHash: setupContext.manifestHash,
    rosterHash: setupContext.rosterHash,
    setupParametersHash: setupContext.setupParametersHash,
    setupEpoch: setupContext.setupEpoch,
});

export const assertContextMatches = (
    setupContext: CollectiveBgvSetupContext,
    value: Readonly<Record<string, unknown>>,
    valueName: string,
): void => {
    for (const fieldName of setupContextFieldNames) {
        if (value[fieldName] !== setupContext[fieldName]) {
            throw new Error(
                `${valueName}.${fieldName} must match setupContext.`,
            );
        }
    }
};
