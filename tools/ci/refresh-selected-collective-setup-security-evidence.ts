import { readFile, writeFile } from 'node:fs/promises';

import {
    buildSelectedCollectiveSetupSecurityEvidence,
    canonicalJsonText,
    parseJsonValue,
    selectedCollectiveSetupSecurityEvidencePath,
    validateSelectedCollectiveSetupSecurityEvidence,
    type JsonValue,
} from './selected-collective-setup-security-evidence.js';

const requireRecord = (value: JsonValue): Record<string, JsonValue> => {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) {
        throw new Error(
            'The checked collective-setup evidence must be an object.',
        );
    }
    return value as Record<string, JsonValue>;
};

export const refreshSelectedCollectiveSetupSecurityEvidence =
    async (): Promise<void> => {
        const checkedEvidence = parseJsonValue(
            await readFile(selectedCollectiveSetupSecurityEvidencePath, 'utf8'),
        );
        const productionAuthority =
            requireRecord(checkedEvidence).productionAuthority;
        if (productionAuthority === undefined) {
            throw new Error(
                'The checked collective-setup production authority is missing.',
            );
        }
        const freshEvidence =
            await buildSelectedCollectiveSetupSecurityEvidence(
                productionAuthority,
            );
        validateSelectedCollectiveSetupSecurityEvidence(
            freshEvidence,
            freshEvidence,
        );
        await writeFile(
            selectedCollectiveSetupSecurityEvidencePath,
            `${canonicalJsonText(freshEvidence)}\n`,
            'utf8',
        );
    };

if (import.meta.main) {
    void refreshSelectedCollectiveSetupSecurityEvidence();
}
