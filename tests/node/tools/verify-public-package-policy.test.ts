import { describe, expect, it } from 'vitest';

import {
    publicPackagePolicy,
    type VendoredProtocolRuntimeEntryExport,
} from '#tools/ci/public-package-policy';
import {
    collectEntryPointTypeExportNames,
    validateGeneratedInternalBridgeArtifactTexts,
    validatePublicPackagePolicy,
    validateSdkKernelCommandStrings,
} from '#tools/ci/verify-public-package-policy';

const emptyPackagePolicy = {
    forbiddenGeneratedInternalBridgeMembers: [],
    forbiddenProtocolRootExports: [],
    forbiddenSdkKernelCommandStrings: [],
    forbiddenSdkVendoredInternalBridgeMembers: [],
    forbiddenRuntimeExports: [],
    forbiddenTypeExports: [],
    sdkVendoredBridgeRemovedMembers: [],
    vendoredCryptoRuntimeModules:
        publicPackagePolicy.vendoredCryptoRuntimeModules,
    vendoredProtocolRuntimeEntryExports: [],
    vendoredProtocolRuntimeModules: [],
} as const satisfies Parameters<typeof validatePublicPackagePolicy>[0];

const runtimeFacadeExportNamesForPolicyEntry = (
    entry: VendoredProtocolRuntimeEntryExport,
): readonly string[] => entry.runtimeFacadeExports ?? entry.exports;

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

    it('rejects exact forbidden generated bridge members without matching longer helpers', () => {
        const failures = validateGeneratedInternalBridgeArtifactTexts(
            {
                ...emptyPackagePolicy,
                forbiddenGeneratedInternalBridgeMembers: [
                    'GenerateBgvTargetDecryptionShare',
                    'generateBgvTargetDecryptionShare',
                ],
            },
            [
                {
                    relativePath: 'generated/current-bridge.js',
                    text: `
                        generateBgvTargetDecryptionShareFromLocalShare: (input) => input;
                        command: 'GenerateBgvTargetDecryptionShareFromLocalShare';
                    `,
                },
                {
                    relativePath: 'generated/stale-bridge.js',
                    text: `
                        generateBgvTargetDecryptionShare: (input) => input;
                        command: 'GenerateBgvTargetDecryptionShare';
                    `,
                },
            ],
        );

        expect(failures).toEqual(
            [
                'generated internal bridge artifact contains forbidden member "GenerateBgvTargetDecryptionShare": generated/stale-bridge.js',
                'generated internal bridge artifact contains forbidden member "generateBgvTargetDecryptionShare": generated/stale-bridge.js',
            ].sort((left, right) => left.localeCompare(right)),
        );
    });

    it('rejects target-decryption development bridge members only in the SDK vendored loader', () => {
        const failures = validateGeneratedInternalBridgeArtifactTexts(
            {
                ...emptyPackagePolicy,
                forbiddenSdkVendoredInternalBridgeMembers: [
                    'GenerateBgvTargetDecryptionShareFromLocalShare',
                    'generateBgvTargetDecryptionShareFromLocalShare',
                ],
            },
            [
                {
                    relativePath:
                        'packages/wasm/dist/transcript-core-bridge/kernel-loader.js',
                    text: `
                        generateBgvTargetDecryptionShareFromLocalShare: (input) => input;
                        command: 'GenerateBgvTargetDecryptionShareFromLocalShare';
                    `,
                },
                {
                    relativePath:
                        'packages/sdk/dist/internal/transcript-core-bridge/kernel-loader.js',
                    text: `
                        generateBgvTargetDecryptionShareFromLocalShare: (input) => input;
                        command: 'GenerateBgvTargetDecryptionShareFromLocalShare';
                    `,
                },
            ],
        );

        expect(failures).toEqual(
            [
                'SDK vendored internal bridge artifact contains forbidden member "GenerateBgvTargetDecryptionShareFromLocalShare": packages/sdk/dist/internal/transcript-core-bridge/kernel-loader.js',
                'SDK vendored internal bridge artifact contains forbidden member "generateBgvTargetDecryptionShareFromLocalShare": packages/sdk/dist/internal/transcript-core-bridge/kernel-loader.js',
            ].sort((left, right) => left.localeCompare(right)),
        );
    });

    it('requires stripped SDK bridge members to stay forbidden from the vendored artifact', () => {
        const failures = validateGeneratedInternalBridgeArtifactTexts(
            {
                ...emptyPackagePolicy,
                sdkVendoredBridgeRemovedMembers: [
                    'generateBgvTargetDecryptionShareFromLocalShare',
                ],
            },
            [],
        );

        expect(failures).toEqual([
            'sdkVendoredBridgeRemovedMembers member "generateBgvTargetDecryptionShareFromLocalShare" is not listed in forbiddenSdkVendoredInternalBridgeMembers',
        ]);
    });

    it('rejects target-decryption development commands in the SDK kernel artifact', () => {
        const failures = validateSdkKernelCommandStrings(
            {
                ...emptyPackagePolicy,
                forbiddenSdkKernelCommandStrings: [
                    'GenerateBgvTargetDecryptionShareFromLocalShare',
                ],
            },
            Buffer.from(
                '...GenerateBgvTargetDecryptionShareFromLocalShare...',
                'utf8',
            ),
            'packages/sdk/dist/sealed-lattice-kernel.wasm',
        );

        expect(failures).toEqual([
            'SDK kernel WASM contains forbidden command string "GenerateBgvTargetDecryptionShareFromLocalShare": packages/sdk/dist/sealed-lattice-kernel.wasm',
        ]);
    });

    it('rejects target-decryption implementation exports if they reach the SDK facade', async () => {
        const requiredRuntimeExports =
            publicPackagePolicy.vendoredProtocolRuntimeEntryExports.flatMap(
                runtimeFacadeExportNamesForPolicyEntry,
            );
        const failures = await validatePublicPackagePolicy(
            {
                ...publicPackagePolicy,
                forbiddenSdkKernelCommandStrings: [],
            },
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

    it('rejects forbidden protocol root exports', async () => {
        const failures = await validatePublicPackagePolicy(
            {
                ...emptyPackagePolicy,
                forbiddenProtocolRootExports: [
                    'validatePollSpec',
                    'verifyFoundationTranscript',
                ],
            },
            [],
            [],
        );

        expect(failures).toEqual([
            'Forbidden protocol root export is public: validatePollSpec',
            'Forbidden protocol root export is public: verifyFoundationTranscript',
        ]);
    });

    it('rejects missing transitive crypto runtime modules', async () => {
        const failures = await validatePublicPackagePolicy(
            {
                ...emptyPackagePolicy,
                vendoredCryptoRuntimeModules: ['index.ts'],
            },
            [],
            [],
        );

        expect(failures).toEqual([
            'vendoredCryptoRuntimeModules is missing reachable source "canonical-base64.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "canonical-json.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "hashes.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "local-trustee-state-storage.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "private-vss-mailbox.ts"',
            'vendoredCryptoRuntimeModules is missing reachable source "signatures.ts"',
        ]);
    });
});
