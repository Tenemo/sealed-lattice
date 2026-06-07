import { describe, expect, it } from 'vitest';

import { publicPackagePolicy } from '#tools/ci/public-package-policy';
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
                    'TopKEvaluatorDirectAggregateInput',
                ],
            },
            [],
            [
                'BgvPassiveSetupPackage',
                'SafeVerificationInput',
                'TopKEvaluatorDirectAggregateInput',
            ],
        );

        expect(failures).toEqual([
            'Forbidden type export is public: BgvPassiveSetupPackage',
            'Forbidden type export is public: TopKEvaluatorDirectAggregateInput',
        ]);
    });

    it('keeps verification input types and runtime exports on separate gates', async () => {
        const failures = await validatePublicPackagePolicy(
            {
                ...emptyPackagePolicy,
                forbiddenRuntimeExports: ['decryptIntermediateWire'],
                forbiddenTypeExports: ['DirectEncryptedBallotWitness'],
            },
            ['decryptIntermediateWire', 'verifyDirectEncryptedBallotProof'],
            [
                'DirectEncryptedBallotVerificationInput',
                'EvaluatorReplayVerificationInput',
            ],
        );

        expect(failures).toEqual([
            'Forbidden runtime export is public: decryptIntermediateWire',
        ]);
    });

    it('rejects target-decryption implementation exports if they reach the SDK facade', async () => {
        const requiredRuntimeExports =
            publicPackagePolicy.vendoredProtocolRuntimeEntryExports.flatMap(
                (entry) =>
                    'runtimeFacadeExports' in entry
                        ? entry.runtimeFacadeExports
                        : entry.exports,
            );
        const failures = await validatePublicPackagePolicy(
            publicPackagePolicy,
            [
                ...requiredRuntimeExports,
                'verifyTargetAcceptedRecord',
                'verifyTopKDecryptionShareShell',
            ],
            [],
        );

        expect(failures).toEqual([
            'Forbidden runtime export is public: verifyTargetAcceptedRecord',
            'Forbidden runtime export is public: verifyTopKDecryptionShareShell',
        ]);
    });
});
