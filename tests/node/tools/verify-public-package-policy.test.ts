import { describe, expect, it } from 'vitest';

import { publicPackagePolicy } from '#tools/ci/public-package-policy';
import { validatePublicPackagePolicy } from '#tools/ci/verify-public-package-policy';

const emptyPackagePolicy = {
    vendoredCryptoRuntimeModules:
        publicPackagePolicy.vendoredCryptoRuntimeModules,
    vendoredProtocolRuntimeEntryExports: [],
    vendoredProtocolRuntimeModules: [],
} as const satisfies Parameters<typeof validatePublicPackagePolicy>[0];

describe('public package policy', () => {
    it('rejects missing protocol runtime entry exports from the SDK facade', async () => {
        const requiredRuntimeExports =
            publicPackagePolicy.vendoredProtocolRuntimeEntryExports.flatMap(
                (entry) =>
                    entry.runtimeVisibility === 'public' ? entry.exports : [],
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

    it('rejects an internal protocol helper exposed from the SDK facade', async () => {
        const publicRuntimeExports =
            publicPackagePolicy.vendoredProtocolRuntimeEntryExports.flatMap(
                (entry) =>
                    entry.runtimeVisibility === 'public' ? entry.exports : [],
            );
        const failures = await validatePublicPackagePolicy(
            publicPackagePolicy,
            [
                ...publicRuntimeExports,
                'createBgvTargetDecryptionShareCanonicalProofMaterialTransport',
            ],
        );

        expect(failures).toEqual([
            'vendoredProtocolRuntimeEntryExports target-decryption/proof-material-transport.js marks "createBgvTargetDecryptionShareCanonicalProofMaterialTransport" internal but the SDK runtime exports it',
        ]);
    });

    it('rejects unreachable vendored protocol runtime modules', async () => {
        const requiredRuntimeExports =
            publicPackagePolicy.vendoredProtocolRuntimeEntryExports.flatMap(
                (entry) =>
                    entry.runtimeVisibility === 'public' ? entry.exports : [],
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
            'vendoredCryptoRuntimeModules is missing reachable source "local-trustee-state-storage/aes-gcm.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "local-trustee-state-storage/constants-and-types.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "local-trustee-state-storage/envelope-validation.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "local-trustee-state-storage/operations.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "local-trustee-state-storage/validation.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "private-vss-mailbox.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "signatures.ts"',
        ]);
    });
});
