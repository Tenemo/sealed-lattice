import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    computeRelativeTypesSpecifier,
    sdkCryptoRuntimeSourceRelativePaths,
    rewriteTypesImports,
    sdkProtocolRuntimeSourceRelativePaths,
    stripSdkExcludedTypesPackageExports,
    transpileBridgeSource,
    transpileSdkInternalSource,
} from '#tools/ci/build-sdk-bridge';
import {
    filesystemMaximumRetries,
    withTransientFilesystemRetries,
} from '#tools/internal/files';

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
                import type { ThresholdParameters } from '@sealed-lattice/types';

                export const isSupportedSafeRange = (parameters: ThresholdParameters): boolean =>
                    parameters.rosterParametersKind === 'SupportedRosterRange';
            `,
            'packages/protocol/src/lifecycle/thresholds.ts',
        );

        expect(outputText).toContain('export const isSupportedSafeRange');
        expect(outputText).not.toContain('ThresholdParameters');
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
});

describe('transient filesystem retry helper', () => {
    // The retry helper guards the in-place rm -rf and recreate-and-write steps
    // of the SDK runtime vendoring against the Windows delete-pending race that
    // surfaces under load as transient ENOENT/EPERM/EBUSY/ENOTEMPTY failures.
    const noDelay = (): Promise<void> => Promise.resolve();

    const transientError = (code: string): NodeJS.ErrnoException =>
        Object.assign(new Error(`transient ${code}`), { code });

    it('retries transient filesystem errors until the operation succeeds', async () => {
        let attempts = 0;
        const result = await withTransientFilesystemRetries(
            (): Promise<string> => {
                attempts += 1;
                if (attempts === 1) {
                    return Promise.reject(transientError('ENOTEMPTY'));
                }
                if (attempts === 2) {
                    return Promise.reject(transientError('ENOENT'));
                }

                return Promise.resolve('written');
            },
            noDelay,
        );

        expect(result).toBe('written');
        expect(attempts).toBe(3);
    });

    it('rethrows non-transient errors immediately without retrying', async () => {
        let attempts = 0;
        await expect(
            withTransientFilesystemRetries((): Promise<never> => {
                attempts += 1;

                return Promise.reject(transientError('ENOSPC'));
            }, noDelay),
        ).rejects.toMatchObject({ code: 'ENOSPC' });

        expect(attempts).toBe(1);
    });

    it('gives up after the maximum number of retries on a persistent transient error', async () => {
        let attempts = 0;
        await expect(
            withTransientFilesystemRetries((): Promise<never> => {
                attempts += 1;

                return Promise.reject(transientError('EPERM'));
            }, noDelay),
        ).rejects.toMatchObject({ code: 'EPERM' });

        expect(attempts).toBe(filesystemMaximumRetries);
    });
});
