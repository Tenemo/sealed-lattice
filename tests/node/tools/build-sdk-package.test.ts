import { describe, expect, it } from 'vitest';

import { hashNormalizedWasmKernel } from '#tools/ci/build-sdk-package';

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
});
