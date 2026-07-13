import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    hashNormalizedWasmKernel,
    normalizeSdkDeclarationEntryMarker,
} from '#tools/ci/build-sdk-package';

const wasmHeader = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00] as const;

describe('SDK package build', () => {
    it('binds the package hash to executable WASM while ignoring custom metadata sections', () => {
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

        expect(hashNormalizedWasmKernel(firstCustomSection)).toBe(
            hashNormalizedWasmKernel(secondCustomSection),
        );
        expect(hashNormalizedWasmKernel(firstCustomSection)).not.toBe(
            hashNormalizedWasmKernel(executableSection),
        );
    });

    it('removes the random declaration scratch path from bundled output', () => {
        const declarationBundlePath = path.resolve(
            'packages',
            'sdk',
            'dist',
            'index.d.ts',
        );
        const declarationEntryPath = path.resolve(
            'temp',
            'build-scratch',
            'sdk-package-declarations',
            'build-random',
            'index.d.ts',
        );
        const declarationEntryMarkerPath = path
            .relative(
                path.dirname(path.dirname(declarationBundlePath)),
                declarationEntryPath,
            )
            .split(path.sep)
            .join('/');
        const declarationSourceText = [
            '//#region ../types/dist/index.d.ts',
            'type ProtocolHash = string;',
            '//#endregion',
            `//#region ${declarationEntryMarkerPath}`,
            'export { ProtocolHash };',
            '//#endregion',
            '',
        ].join('\n');

        expect(
            normalizeSdkDeclarationEntryMarker({
                declarationBundlePath,
                declarationEntryPath,
                declarationSourceText,
            }),
        ).toBe(
            declarationSourceText.replace(
                `//#region ${declarationEntryMarkerPath}`,
                '//#region src/index.ts',
            ),
        );
    });
});
