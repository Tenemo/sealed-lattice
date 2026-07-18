type ProductionDesktopBrowserMeasurementIdentityRecord = Readonly<{
    actionContextHash: string;
    inputCorpusHash: string;
    manifestHash: string;
    packagedWasmSha256: string;
    runtimeBuildManifestHash: string;
    suiteIdentifier: string;
}>;

export type ProductionDesktopBrowserMeasurementIdentity =
    ProductionDesktopBrowserMeasurementIdentityRecord;

const lowercaseSha256Pattern = /^[a-f0-9]{64}$/u;
const lowercaseSha512Pattern = /^[a-f0-9]{128}$/u;

const requirePlainRecord = (
    value: unknown,
    fieldName: string,
): Record<string, unknown> => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(
            `Production desktop-browser measurement ${fieldName} must be an object.`,
        );
    }
    return value as Record<string, unknown>;
};

const requireLowercaseHex = (
    value: unknown,
    fieldName: string,
    pattern: RegExp,
    algorithmName: string,
): string => {
    if (typeof value !== 'string' || !pattern.test(value)) {
        throw new Error(
            `Production desktop-browser measurement ${fieldName} must be one lowercase ${algorithmName} hexadecimal digest.`,
        );
    }
    return value;
};

export const requireProductionDesktopBrowserMeasurementSha512 = (
    value: unknown,
    fieldName: string,
): string =>
    requireLowercaseHex(value, fieldName, lowercaseSha512Pattern, 'SHA-512');

export const requireProductionDesktopBrowserMeasurementIdentity = (
    value: unknown,
): ProductionDesktopBrowserMeasurementIdentity => {
    const record = requirePlainRecord(value, 'identity');
    return Object.freeze({
        actionContextHash: requireLowercaseHex(
            record.actionContextHash,
            'identity.actionContextHash',
            lowercaseSha512Pattern,
            'Hash512',
        ),
        inputCorpusHash: requireLowercaseHex(
            record.inputCorpusHash,
            'identity.inputCorpusHash',
            lowercaseSha512Pattern,
            'Hash512',
        ),
        manifestHash: requireLowercaseHex(
            record.manifestHash,
            'identity.manifestHash',
            lowercaseSha512Pattern,
            'Hash512',
        ),
        packagedWasmSha256: requireLowercaseHex(
            record.packagedWasmSha256,
            'identity.packagedWasmSha256',
            lowercaseSha256Pattern,
            'SHA-256',
        ),
        runtimeBuildManifestHash: requireLowercaseHex(
            record.runtimeBuildManifestHash,
            'identity.runtimeBuildManifestHash',
            lowercaseSha512Pattern,
            'Hash512',
        ),
        suiteIdentifier: requireLowercaseHex(
            record.suiteIdentifier,
            'identity.suiteIdentifier',
            lowercaseSha512Pattern,
            'Hash512',
        ),
    });
};
