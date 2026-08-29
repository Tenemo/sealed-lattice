import { readFileSync } from 'node:fs';

import { foundationProfile } from '@sealed-lattice/wasm/published-sdk';
import { describe, expect, it } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';

type CreateCanonicalManifest = (input: {
    readonly options: readonly string[];
    readonly question: string;
}) => Promise<{
    readonly canonicalBytes: Uint8Array;
    readonly manifestHash: string;
}>;
type VerifyCanonicalManifest = (canonicalBytes: Uint8Array) => Promise<
    | Readonly<{
          readonly isValid: true;
          readonly value: Readonly<{ readonly manifestHash: string }>;
      }>
    | Readonly<{ readonly isValid: false; readonly refusalReason: string }>
>;
const publicApiRuntimeRecord = publicApiRuntime as Record<string, unknown>;
const createCanonicalManifest =
    publicApiRuntimeRecord.createCanonicalManifest as CreateCanonicalManifest;
const verifyCanonicalManifest =
    publicApiRuntimeRecord.verifyCanonicalManifest as VerifyCanonicalManifest;
const expectedPublicRuntimeExportNames = [
    'createCanonicalActionDefinition',
    'createCanonicalBoardPolicy',
    'createCanonicalManifest',
    'validatePollSpec',
    'verifyCanonicalActionContext',
    'verifyCanonicalActionDefinition',
    'verifyCanonicalBoardPolicy',
    'verifyCanonicalCeremonyContext',
    'verifyCanonicalManifest',
] as const;

describe('election foundation public package API in Node', () => {
    it('exposes safe runtime functions and keeps runtime exports callable', () => {
        const runtimeExportNames = Object.keys(publicApiRuntimeRecord).sort();

        expect(runtimeExportNames).toEqual(expectedPublicRuntimeExportNames);
        for (const publicFunctionName of runtimeExportNames) {
            expect(
                typeof publicApiRuntimeRecord[publicFunctionName],
                publicFunctionName,
            ).toBe('function');
        }
    });

    it('creates and verifies canonical manifest bytes through the packaged kernel', async () => {
        const manifest = await createCanonicalManifest({
            options: Array.from(
                { length: foundationProfile.optionCount },
                (_value, optionIndex) => `Option ${String(optionIndex)}`,
            ),
            question: 'Choose priorities',
        });

        expect(manifest.canonicalBytes.byteLength).toBeGreaterThan(0);
        expect(await verifyCanonicalManifest(manifest.canonicalBytes)).toEqual({
            isValid: true,
            value: { manifestHash: manifest.manifestHash },
        });
    });

    it('emits declarations for the foundation verification result', () => {
        const declarations = readFileSync(
            new URL('../../dist/index.d.ts', import.meta.url),
            'utf8',
        );

        expect(declarations).toContain(
            'declare const verifyCanonicalManifest:',
        );
        expect(declarations).toContain(
            'Promise<FoundationManifestVerification>',
        );
    });
});
