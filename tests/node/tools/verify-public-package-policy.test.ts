import { describe, expect, it } from 'vitest';

import {
    publicPackagePolicy,
    type VendoredProtocolRuntimeEntryExport,
} from '#tools/ci/public-package-policy';
import { validatePublicPackagePolicy } from '#tools/ci/verify-public-package-policy';

const emptyPackagePolicy = {
    vendoredCryptoRuntimeModules:
        publicPackagePolicy.vendoredCryptoRuntimeModules,
    vendoredProtocolRuntimeEntryExports: [],
    vendoredProtocolRuntimeModules: [],
} as const satisfies Parameters<typeof validatePublicPackagePolicy>[0];

const runtimeFacadeExportNamesForPolicyEntry = (
    entry: VendoredProtocolRuntimeEntryExport,
): readonly string[] => entry.runtimeFacadeExports ?? entry.exports;

describe('public package policy', () => {
    it('rejects missing protocol runtime entry exports from the SDK facade', async () => {
        const requiredRuntimeExports =
            publicPackagePolicy.vendoredProtocolRuntimeEntryExports.flatMap(
                runtimeFacadeExportNamesForPolicyEntry,
            );
        const failures = await validatePublicPackagePolicy(
            publicPackagePolicy,
            requiredRuntimeExports.filter(
                (exportName) => exportName !== 'verifyBoardConsistency',
            ),
        );

        expect(failures).toEqual([
            'vendoredProtocolRuntimeEntryExports board/index.js exposes "verifyBoardConsistency" outside the SDK runtime facade',
        ]);
    });

    it('rejects unreachable vendored protocol runtime modules', async () => {
        const requiredRuntimeExports =
            publicPackagePolicy.vendoredProtocolRuntimeEntryExports.flatMap(
                runtimeFacadeExportNamesForPolicyEntry,
            );
        const failures = await validatePublicPackagePolicy(
            {
                ...publicPackagePolicy,
                vendoredProtocolRuntimeModules: [
                    ...publicPackagePolicy.vendoredProtocolRuntimeModules,
                    'setup/local-trustee-setup-state.ts',
                ],
            },
            requiredRuntimeExports,
        );

        expect(failures).toEqual([
            'vendoredProtocolRuntimeModules includes unreachable source "setup/local-trustee-setup-state.ts"',
        ]);
    });

    it('rejects missing transitive crypto runtime modules', async () => {
        const failures = await validatePublicPackagePolicy(
            {
                ...emptyPackagePolicy,
                vendoredCryptoRuntimeModules: ['index.ts'],
            },
            [],
        );

        expect(failures).toEqual([
            'vendoredCryptoRuntimeModules is missing reachable source "canonical-json.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "hashes.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "local-trustee-state-storage.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "private-vss-mailbox.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "signatures.ts"',
        ]);
    });
});
