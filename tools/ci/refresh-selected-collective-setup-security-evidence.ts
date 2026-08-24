import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { resolvePackageManagerRunner } from './package-manager-runner.js';
import { runPackageManagerAndCaptureOutput } from './run-command.js';
import {
    buildSelectedCollectiveSetupSecurityEvidence,
    canonicalJsonText,
    parseJsonValue,
    selectedCollectiveSetupSecurityEvidencePath,
    validateSelectedCollectiveSetupSecurityEvidence,
    type JsonValue,
} from './selected-collective-setup-security-evidence.js';

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));
const productionAuthorityExportPathEnvironmentVariable =
    'SEALED_LATTICE_COLLECTIVE_SETUP_AUTHORITY_EXPORT_PATH';
const productionAuthorityExportTestName =
    'collective_setup_security_production_authority_exports_for_refresh';

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
        const temporaryDirectoryPath = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-collective-setup-authority-'),
        );
        const productionAuthorityPath = path.join(
            temporaryDirectoryPath,
            'production-authority.json',
        );

        try {
            const packageManagerRunner = resolvePackageManagerRunner();
            runPackageManagerAndCaptureOutput(
                packageManagerRunner,
                [
                    'run',
                    'test:rust:kernel:full-profile-evidence',
                    '--',
                    productionAuthorityExportTestName,
                ],
                repositoryRoot,
                {
                    environment: {
                        ...process.env,
                        [productionAuthorityExportPathEnvironmentVariable]:
                            productionAuthorityPath,
                    },
                },
            );
            const productionAuthority = parseJsonValue(
                await readFile(productionAuthorityPath, 'utf8'),
            );
            requireRecord(productionAuthority);
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
        } finally {
            await rm(temporaryDirectoryPath, {
                force: true,
                recursive: true,
            });
        }
    };

if (import.meta.main) {
    void refreshSelectedCollectiveSetupSecurityEvidence();
}
