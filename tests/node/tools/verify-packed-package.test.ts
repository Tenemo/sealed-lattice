import { describe, expect, it } from 'vitest';

import {
    validatePublishedPackageBundle,
    validatePublishedPackageFilePaths,
} from '#tools/ci/verify-packed-package';

describe('packed package policy checks', () => {
    it('requires the exact public package file set', () => {
        const expectedFilePaths = [
            'LICENSE',
            'README.md',
            'dist/index.d.ts',
            'dist/index.js',
            'dist/index.js.map',
            'dist/sealed-lattice-kernel.wasm',
            'package.json',
        ];

        expect(validatePublishedPackageFilePaths(expectedFilePaths)).toEqual(
            [],
        );
        expect(
            validatePublishedPackageFilePaths([
                ...expectedFilePaths.slice(1),
                'unexpected.txt',
            ]),
        ).toEqual([
            expect.stringContaining('Published package file set mismatch'),
        ]);
    });

    it('requires self-contained output with a resolved kernel token', () => {
        expect(
            validatePublishedPackageBundle({
                declarationSourceText:
                    "import type { Hash } from '@noble/hashes/utils.js';\nexport type Digest = Hash;",
                runtimeSourceText:
                    "import { sha256 } from '@noble/hashes/sha2.js';\nexport { sha256 };",
            }),
        ).toEqual([]);
        expect(
            validatePublishedPackageBundle({
                declarationSourceText:
                    "export type { VerificationResult } from '@sealed-lattice/types';",
                runtimeSourceText:
                    "import { validatePollSpec } from '@sealed-lattice/protocol';\nconst hash = __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;",
            }),
        ).toEqual(
            expect.arrayContaining([
                'Published declaration output must bundle internal workspace import "@sealed-lattice/types"',
                'Published runtime output must bundle internal workspace import "@sealed-lattice/protocol"',
                'Published runtime output contains the unresolved WASM integrity token',
            ]),
        );
    });
});
