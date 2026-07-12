import { describe, expect, it } from 'vitest';

import { validatePublicPackageBundle } from '#tools/ci/verify-public-package-policy';

describe('public package bundle policy', () => {
    it('accepts a self-contained runtime and declaration entry', () => {
        expect(
            validatePublicPackageBundle({
                declarationSourceText:
                    "import type { Hash } from '@noble/hashes/utils.js';\nexport type Digest = Hash;",
                runtimeSourceText:
                    "import { sha256 } from '@noble/hashes/sha2.js';\nexport { sha256 };",
            }),
        ).toEqual([]);
    });

    it('rejects internal workspace imports in either public output', () => {
        expect(
            validatePublicPackageBundle({
                declarationSourceText:
                    "export type { VerificationResult } from '@sealed-lattice/types';",
                runtimeSourceText:
                    "import { validatePollSpec } from '@sealed-lattice/protocol';",
            }),
        ).toEqual([
            'Published declaration output must bundle internal workspace import "@sealed-lattice/types"',
            'Published runtime output must bundle internal workspace import "@sealed-lattice/protocol"',
        ]);
    });

    it('rejects an unresolved WASM integrity token', () => {
        expect(
            validatePublicPackageBundle({
                declarationSourceText: 'export type Value = string;',
                runtimeSourceText:
                    'const expectedHash = __SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__;',
            }),
        ).toEqual([
            'Published runtime output contains the unresolved WASM integrity token',
        ]);
    });
});
