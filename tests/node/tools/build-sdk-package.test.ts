import { describe, expect, it } from 'vitest';

import {
    hashWasmKernel,
    normalizeSdkDeclarationSourceMarkers,
} from '#tools/ci/build-sdk-package';

const wasmHeader = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00] as const;

describe('SDK package build', () => {
    it('binds the package hash to every shipped WASM byte', () => {
        const firstCustomSection = Uint8Array.from([
            ...wasmHeader,
            0x00,
            0x02,
            0x01,
            0x61,
        ]);
        const secondCustomSection = Uint8Array.from([
            ...wasmHeader,
            0x00,
            0x02,
            0x01,
            0x62,
        ]);
        const executableSection = Uint8Array.from([
            ...wasmHeader,
            0x01,
            0x01,
            0x00,
        ]);

        expect(hashWasmKernel(firstCustomSection)).not.toBe(
            hashWasmKernel(secondCustomSection),
        );
        expect(hashWasmKernel(firstCustomSection)).not.toBe(
            hashWasmKernel(executableSection),
        );
    });

    it('removes the random declaration scratch directory from every bundled source marker', () => {
        const declarationBundlePath =
            'C:/repository/packages/sdk/dist/index.d.ts';
        const firstDeclarationEntryPath =
            'C:/repository/temp/build-scratch/sdk-package-declarations/build-first/index.d.ts';
        const secondDeclarationEntryPath =
            'C:/repository/temp/build-scratch/sdk-package-declarations/build-second/index.d.ts';
        const declarationSource = (buildName: string): string =>
            [
                `//#region ../../temp/build-scratch/sdk-package-declarations/${buildName}/setup-verification-input.d.ts`,
                'type VerifySetupPackageInput = object;',
                `//#region ../../temp/build-scratch/sdk-package-declarations/${buildName}/index.d.ts`,
                'export type { VerifySetupPackageInput };',
            ].join('\n');

        const firstNormalizedSource = normalizeSdkDeclarationSourceMarkers({
            declarationBundlePath,
            declarationEntryPath: firstDeclarationEntryPath,
            declarationSourceText: declarationSource('build-first'),
        });
        const secondNormalizedSource = normalizeSdkDeclarationSourceMarkers({
            declarationBundlePath,
            declarationEntryPath: secondDeclarationEntryPath,
            declarationSourceText: declarationSource('build-second'),
        });

        expect(firstNormalizedSource).toBe(secondNormalizedSource);
        expect(firstNormalizedSource).toContain(
            '//#region src/setup-verification-input.d.ts',
        );
        expect(firstNormalizedSource).toContain('//#region src/index.ts');
        expect(firstNormalizedSource).not.toContain('build-first');
        expect(firstNormalizedSource).not.toContain('build-second');
    });
});
