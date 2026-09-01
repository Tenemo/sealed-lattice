import { readFileSync } from 'node:fs';

import { describe, expect, it, vi } from 'vitest';

import * as publicApiRuntime from '../../dist/index.js';
import {
    createMaximumAcceptedPollSpec,
    maximumCanonicalManifestFixtureByteLength,
} from '../maximum-manifest-fixture.js';

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
const expectedPublicWasmExportNames = [
    '__data_end',
    '__heap_base',
    'memory',
    'sealed_lattice_allocate',
    'sealed_lattice_deallocate',
    'sealed_lattice_foundation_command_with_length',
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

    it('ships a foundation-only WebAssembly export inventory', () => {
        const module = new WebAssembly.Module(
            readFileSync(
                new URL(
                    '../../dist/sealed-lattice-kernel.wasm',
                    import.meta.url,
                ),
            ),
        );
        const exportNames = WebAssembly.Module.exports(module)
            .map((entry) => entry.name)
            .sort();

        expect(exportNames).toEqual(expectedPublicWasmExportNames);
        expect(exportNames).not.toContain(
            'sealed_lattice_construction_command_with_length',
        );
    });

    it('creates and verifies canonical manifest bytes through one packaged kernel instance', async () => {
        const instantiate = vi.spyOn(WebAssembly, 'instantiate');
        try {
            const manifest = await createCanonicalManifest({
                options: Array.from(
                    { length: 10 },
                    (_value, optionIndex) => `Option ${String(optionIndex)}`,
                ),
                question: 'Choose priorities',
            });

            expect(manifest.canonicalBytes.byteLength).toBeGreaterThan(0);
            expect(
                await verifyCanonicalManifest(manifest.canonicalBytes),
            ).toEqual({
                isValid: true,
                value: { manifestHash: manifest.manifestHash },
            });
            expect(instantiate).toHaveBeenCalledTimes(1);
        } finally {
            instantiate.mockRestore();
        }
    });

    it('creates and verifies the largest manifest admitted by poll validation', async () => {
        const manifest = await createCanonicalManifest(
            createMaximumAcceptedPollSpec(),
        );

        expect(manifest.canonicalBytes).toHaveLength(
            maximumCanonicalManifestFixtureByteLength,
        );
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
