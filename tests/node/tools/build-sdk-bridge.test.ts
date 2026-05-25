import path from 'node:path';

import { describe, expect, it } from 'vitest';

import publicSurface from '#packages/sdk/public-surface.json' with { type: 'json' };
import {
    computeRelativeTypesSpecifier,
    rewriteTypesImports,
    sdkProtocolRuntimeSourceRelativePaths,
    transpileBridgeSource,
    transpileSdkInternalSource,
} from '#tools/ci/build-sdk-bridge';

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
        expect(sdkProtocolRuntimeSourceRelativePaths).toEqual(
            publicSurface.vendoredProtocolRuntimeModules,
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
            'target-acceptance/index.ts',
        );
    });
});
