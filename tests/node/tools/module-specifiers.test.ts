import { describe, expect, it } from 'vitest';

import { extractModuleSpecifiers } from '#tools/internal/module-specifiers';

describe('module specifier helpers', () => {
    it('collects static, side-effect, dynamic, and import type specifiers', () => {
        const sourceText = `
            import 'sealed-lattice';
            import { loadKernel } from "@sealed-lattice/wasm";
            export { verifyBallotProof } from '@sealed-lattice/protocol';
            const loaded = await import('@sealed-lattice/crypto');
            type TranscriptKernel = import("@sealed-lattice/types").TranscriptKernel;
        `;

        expect(extractModuleSpecifiers(sourceText).sort()).toEqual([
            '@sealed-lattice/crypto',
            '@sealed-lattice/protocol',
            '@sealed-lattice/types',
            '@sealed-lattice/wasm',
            'sealed-lattice',
        ]);
    });

    it('deduplicates repeated specifiers', () => {
        const sourceText = `
            import type { ThresholdParameters } from '@sealed-lattice/types';
            export type { ThresholdParameters } from '@sealed-lattice/types';
        `;

        expect(extractModuleSpecifiers(sourceText)).toEqual([
            '@sealed-lattice/types',
        ]);
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
});
