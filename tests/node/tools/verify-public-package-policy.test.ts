import { describe, expect, it } from 'vitest';

import {
    collectEntryPointTypeExportNames,
    validatePublicPackagePolicy,
} from '#tools/ci/verify-public-package-policy';

const emptyPackagePolicy = {
    forbiddenRuntimeExports: [],
    forbiddenTypeExports: [],
    vendoredProtocolRuntimeEntryExports: [],
    vendoredProtocolRuntimeModules: [],
} as const satisfies Parameters<typeof validatePublicPackagePolicy>[0];

describe('public package policy', () => {
    it('collects direct type exports from the package entry declaration', () => {
        const typeExports = collectEntryPointTypeExportNames(`
            export type { SafeType, UnsafeType as RenamedUnsafeType } from './internal/types.js';
            export type InlineType = { readonly value: string };
            export declare interface InlineInterface {
                readonly value: string;
            }
        `);

        expect(typeExports).toEqual([
            'InlineInterface',
            'InlineType',
            'SafeType',
            'UnsafeType',
        ]);
    });

    it('rejects forbidden type exports as public package drift', async () => {
        const failures = await validatePublicPackagePolicy(
            {
                ...emptyPackagePolicy,
                forbiddenTypeExports: [
                    'BgvPassiveSetupPackage',
                    'TopKEvaluatorEncryptedAggregateInput',
                ],
            },
            [],
            [
                'BgvPassiveSetupPackage',
                'SafeVerificationInput',
                'TopKEvaluatorEncryptedAggregateInput',
            ],
        );

        expect(failures).toEqual([
            'Forbidden type export is public: BgvPassiveSetupPackage',
            'Forbidden type export is public: TopKEvaluatorEncryptedAggregateInput',
        ]);
    });

    it('keeps verification input types and runtime exports on separate gates', async () => {
        const failures = await validatePublicPackagePolicy(
            {
                ...emptyPackagePolicy,
                forbiddenRuntimeExports: ['decryptIntermediateWire'],
                forbiddenTypeExports: ['BridgeProofRecord'],
            },
            ['decryptIntermediateWire', 'verifyBridgeProof'],
            [
                'BridgeProofVerificationInput',
                'ReceiverKeyProofVerificationInput',
            ],
        );

        expect(failures).toEqual([
            'Forbidden runtime export is public: decryptIntermediateWire',
        ]);
    });
});
