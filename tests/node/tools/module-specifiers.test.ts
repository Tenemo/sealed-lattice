import { describe, expect, it } from 'vitest';

import {
    collectModuleSpecifierLiterals,
    extractModuleSpecifiers,
    rewriteModuleSpecifiers,
} from '#tools/internal/module-specifiers';

describe('module specifier helpers', () => {
    it('collects static, side-effect, dynamic, and import type specifiers', () => {
        const sourceText = `
            import 'sealed-lattice';
            import { loadKernel } from "@sealed-lattice/wasm";
            export { verifyBallotProof } from '@sealed-lattice/protocol';
            const loaded = await import('@sealed-lattice/testkit');
            type TranscriptKernel = import("@sealed-lattice/types").TranscriptKernel;
        `;

        expect(extractModuleSpecifiers(sourceText).sort()).toEqual([
            '@sealed-lattice/protocol',
            '@sealed-lattice/testkit',
            '@sealed-lattice/types',
            '@sealed-lattice/wasm',
            'sealed-lattice',
        ]);
    });

    it('deduplicates repeated specifiers without hiding separate literal positions', () => {
        const sourceText = `
            import type { TranscriptCoreFixture } from '@sealed-lattice/types';
            export type { TranscriptCoreFixture } from '@sealed-lattice/types';
        `;

        expect(extractModuleSpecifiers(sourceText)).toEqual([
            '@sealed-lattice/types',
        ]);
        expect(collectModuleSpecifierLiterals(sourceText)).toHaveLength(2);
    });

    it('ignores import-like syntax whose target is not a string literal', () => {
        const sourceText = `
            const packageName = '@sealed-lattice/wasm';
            void import(packageName);
            type PackageName = '@sealed-lattice/types';
            type TranscriptKernel = import(PackageName).TranscriptKernel;
        `;

        expect(extractModuleSpecifiers(sourceText)).toEqual([]);
    });

    it('rewrites every supported module specifier while preserving quote style', () => {
        const sourceText = [
            "import type { Foo } from '@sealed-lattice/types';",
            'export { verify } from "@sealed-lattice/protocol";',
            "const loaded = await import('@sealed-lattice/wasm');",
            'type Kernel = import("@sealed-lattice/wasm").TranscriptCoreKernel;',
        ].join('\n');
        const rewritten = rewriteModuleSpecifiers(
            'sdk/index.d.ts',
            sourceText,
            (specifier) => {
                if (specifier === '@sealed-lattice/types') {
                    return './internal/types.js';
                }
                if (specifier === '@sealed-lattice/protocol') {
                    return './internal/election-foundation/index.js';
                }
                if (specifier === '@sealed-lattice/wasm') {
                    return './internal/transcript-core-bridge.js';
                }

                return undefined;
            },
        );

        expect(rewritten).toBe(
            [
                "import type { Foo } from './internal/types.js';",
                'export { verify } from "./internal/election-foundation/index.js";',
                "const loaded = await import('./internal/transcript-core-bridge.js');",
                'type Kernel = import("./internal/transcript-core-bridge.js").TranscriptCoreKernel;',
            ].join('\n'),
        );
    });

    it('escapes rewritten specifiers for the original quote delimiter', () => {
        const sourceText =
            'const loaded = await import("@sealed-lattice/wasm");';
        const rewritten = rewriteModuleSpecifiers(
            'sdk/index.js',
            sourceText,
            () => './internal/"quoted".js',
        );

        expect(rewritten).toBe(
            'const loaded = await import("./internal/\\"quoted\\".js");',
        );
    });
});
