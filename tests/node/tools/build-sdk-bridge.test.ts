import { readFile } from 'node:fs/promises';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    computeRelativeTypesSpecifier,
    sdkCryptoRuntimeSourceRelativePaths,
    rewriteTypesImports,
    sdkProtocolRuntimeSourceRelativePaths,
    stripSdkExcludedTypesPackageExports,
    stripSdkVendoredBridgeMembers,
    transpileBridgeSource,
    transpileSdkInternalSource,
} from '#tools/ci/build-sdk-bridge';
import { sdkVendoredBridgeRemovedMembers } from '#tools/ci/public-package-policy';

const distRoot = path.resolve('/fake-repo/packages/sdk/dist');
const typesRuntime = path.resolve(distRoot, 'internal/types.js');

describe('SDK bridge build helpers', () => {
    it('removes type-only workspace imports from the published bridge copy', () => {
        const outputText = transpileBridgeSource(`
            import type { TranscriptCoreFixture } from '@sealed-lattice/types';

            export const acceptsFixture = (_fixture: TranscriptCoreFixture): boolean => true;
        `);

        expect(outputText).toContain('export const acceptsFixture');
        expect(outputText).not.toContain('@sealed-lattice/types');
    });

    it('transpiles selected protocol runtime modules for SDK vendoring', () => {
        const outputText = transpileSdkInternalSource(
            `
                import type { ThresholdProfile } from '@sealed-lattice/types';

                export const isSupportedSafeRange = (profile: ThresholdProfile): boolean =>
                    profile.rosterProfileKind === 'SupportedRosterRange';
            `,
            'packages/protocol/src/lifecycle/thresholds.ts',
        );

        expect(outputText).toContain('export const isSupportedSafeRange');
        expect(outputText).not.toContain('ThresholdProfile');
    });

    it('rewrites @sealed-lattice/types imports to a relative dist path', () => {
        const declarationFilePath = path.resolve(distRoot, 'index.d.ts');
        const original =
            "import type { Foo } from '@sealed-lattice/types';\nexport type * from '@sealed-lattice/types';\n";
        const rewritten = rewriteTypesImports(
            declarationFilePath,
            original,
            typesRuntime,
        );

        expect(rewritten).toContain("from './internal/types.js'");
        expect(rewritten).not.toContain('@sealed-lattice/types');
    });

    it('strips test-only plaintext oracle type exports from the SDK copy', () => {
        expect(
            stripSdkExcludedTypesPackageExports(
                [
                    "export * from './board-target.js';",
                    "export * from './plaintext-oracle.js';",
                    "export * from './target-result.js';",
                    '',
                ].join('\n'),
            ),
        ).toBe(
            [
                "export * from './board-target.js';",
                "export * from './target-result.js';",
                '',
            ].join('\n'),
        );
    });

    it('computes a relative specifier from nested dist files', () => {
        const nestedDeclarationFilePath = path.resolve(
            distRoot,
            'internal/election-foundation/index.d.ts',
        );
        const specifier = computeRelativeTypesSpecifier(
            nestedDeclarationFilePath,
            typesRuntime,
        );

        expect(specifier).toBe('../types.js');
    });

    it('vendors only SDK-safe protocol runtime modules', () => {
        expect(new Set(sdkProtocolRuntimeSourceRelativePaths).size).toBe(
            sdkProtocolRuntimeSourceRelativePaths.length,
        );
        expect(sdkProtocolRuntimeSourceRelativePaths).toContain(
            'board/consistency.ts',
        );
        expect(sdkProtocolRuntimeSourceRelativePaths).toContain(
            'board/index.ts',
        );
        expect(sdkProtocolRuntimeSourceRelativePaths).toContain(
            'roster/index.ts',
        );
        expect(sdkProtocolRuntimeSourceRelativePaths).not.toContain(
            'plaintext-oracle/index.ts',
        );
        expect(sdkProtocolRuntimeSourceRelativePaths).not.toContain(
            'plaintext-oracle/top-k.ts',
        );
    });

    it('vendors only reviewed crypto runtime modules', () => {
        expect(new Set(sdkCryptoRuntimeSourceRelativePaths).size).toBe(
            sdkCryptoRuntimeSourceRelativePaths.length,
        );
        expect(sdkCryptoRuntimeSourceRelativePaths).toContain('index.ts');
        expect(sdkCryptoRuntimeSourceRelativePaths).toContain(
            'canonical-json.ts',
        );
        expect(sdkCryptoRuntimeSourceRelativePaths).toContain(
            'private-vss-mailbox.ts',
        );
        expect(sdkCryptoRuntimeSourceRelativePaths).not.toContain(
            'tests/support/protocol-signature-fixtures.ts',
        );
    });

    it('strips development target-decryption members from the SDK bridge copy', async () => {
        const loaderSource = await readFile(
            path.resolve(
                'packages/wasm/src/transcript-core-bridge/kernel-loader.ts',
            ),
            'utf8',
        );
        const strippedSource = stripSdkVendoredBridgeMembers(
            loaderSource,
            sdkVendoredBridgeRemovedMembers,
        );
        const outputText = transpileSdkInternalSource(
            strippedSource,
            'packages/wasm/src/transcript-core-bridge/kernel-loader.ts',
        );

        for (const memberName of sdkVendoredBridgeRemovedMembers) {
            expect(outputText).not.toContain(memberName);
        }
        expect(outputText).toContain('verifyTargetDecryptionResult');
        expect(outputText).toContain('VerifyTargetDecryptionResult');
    });
});
