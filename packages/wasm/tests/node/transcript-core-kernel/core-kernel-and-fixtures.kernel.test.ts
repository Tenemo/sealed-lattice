import { describe, expect, it } from 'vitest';

import { textDecoder, textEncoder, wasmHeader } from './shared.js';

import { normalizeTranscriptCoreKernelBytesForHash } from '#packages/wasm/src/transcript-core-bridge';

describe('transcript-core kernel integrity normalization', () => {
    it('normalizes host-specific Rust source paths before hashing', () => {
        const windowsBytes = textEncoder.encode(
            [
                'prefix',
                'C:\\Users\\Piotr\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\serde_json-1.0.149\\src\\error.rs',
                'crates\\sealed-lattice-kernel\\src\\lib.rs',
                'suffix',
            ].join('\0'),
        );
        const linuxBytes = textEncoder.encode(
            [
                'prefix',
                '/home/runner/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.149/src/error.rs',
                'crates/sealed-lattice-kernel/src/lib.rs',
                'suffix',
            ].join('\0'),
        );

        const normalizedWindowsBytes =
            normalizeTranscriptCoreKernelBytesForHash(windowsBytes);
        const normalizedLinuxBytes =
            normalizeTranscriptCoreKernelBytesForHash(linuxBytes);

        expect(Array.from(normalizedWindowsBytes)).toEqual(
            Array.from(normalizedLinuxBytes),
        );
        expect(textDecoder.decode(normalizedWindowsBytes)).toBe(
            [
                'prefix',
                '/cargo/registry/src/index.crates.io-1949cf8c6b5b557f/serde_json-1.0.149/src/error.rs',
                'crates/sealed-lattice-kernel/src/lib.rs',
                'suffix',
            ].join('\0'),
        );
    });

    it('excludes WASM custom sections from the integrity hash', () => {
        const leftCustomSection = Uint8Array.from([0, 4, 3, 111, 110, 101]);
        const rightCustomSection = Uint8Array.from([0, 4, 3, 116, 119, 111]);
        const emptyTypeSection = Uint8Array.from([1, 1, 0]);
        const leftBytes = Uint8Array.from([
            ...wasmHeader,
            ...leftCustomSection,
            ...emptyTypeSection,
        ]);
        const rightBytes = Uint8Array.from([
            ...wasmHeader,
            ...rightCustomSection,
            ...emptyTypeSection,
        ]);

        expect(
            Array.from(normalizeTranscriptCoreKernelBytesForHash(leftBytes)),
        ).toEqual(
            Array.from(normalizeTranscriptCoreKernelBytesForHash(rightBytes)),
        );
        expect(
            Array.from(normalizeTranscriptCoreKernelBytesForHash(leftBytes)),
        ).toEqual(
            Array.from(Uint8Array.from([...wasmHeader, ...emptyTypeSection])),
        );
    });

    it('rejects malformed WASM sections before hashing', () => {
        const malformedModules = [
            Uint8Array.from([...wasmHeader, 1, 0x80, 0x80, 0x80, 0x80, 0x80]),
            Uint8Array.from([...wasmHeader, 1, 0x80, 0x80, 0x80, 0x80, 0x10]),
            Uint8Array.from([...wasmHeader, 1, 0x80]),
            Uint8Array.from([...wasmHeader, 1, 2, 0]),
        ];

        for (const malformedModule of malformedModules) {
            expect(() =>
                normalizeTranscriptCoreKernelBytesForHash(malformedModule),
            ).toThrow();
        }
    });
});
