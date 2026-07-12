import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';

import { describe, expect, it } from 'vitest';

import {
    copyWasmKernelByteIdentically,
    hashNormalizedWasmKernel,
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

    it('copies the internal WASM artifact byte-for-byte on repeated SDK builds', async () => {
        const temporaryDirectoryPath = await mkdtemp(
            path.join(tmpdir(), 'sealed-lattice-sdk-wasm-copy-'),
        );
        const sourcePath = path.join(temporaryDirectoryPath, 'internal.wasm');
        const destinationPath = path.join(
            temporaryDirectoryPath,
            'sdk',
            'kernel.wasm',
        );
        const sourceBytes = Uint8Array.from([
            ...wasmHeader,
            0x01,
            0x02,
            0x03,
            0x04,
        ]);

        try {
            await writeFile(sourcePath, sourceBytes);
            await copyWasmKernelByteIdentically({
                destinationPath,
                sourceBytes,
                sourcePath,
            });
            await copyWasmKernelByteIdentically({
                destinationPath,
                sourceBytes,
                sourcePath,
            });
            expect(await readFile(destinationPath)).toEqual(
                Buffer.from(sourceBytes),
            );
        } finally {
            await rm(temporaryDirectoryPath, { force: true, recursive: true });
        }
    });

    it('keeps Cargo and wasm-opt production in the internal WASM package only', async () => {
        const repositoryRoot = new URL('../../../', import.meta.url);
        const wasmManifest = JSON.parse(
            await readFile(
                new URL('packages/wasm/package.json', repositoryRoot),
                'utf8',
            ),
        ) as { readonly scripts: Readonly<Record<string, string>> };
        const sdkManifest = JSON.parse(
            await readFile(
                new URL('packages/sdk/package.json', repositoryRoot),
                'utf8',
            ),
        ) as { readonly scripts: Readonly<Record<string, string>> };
        const sdkBuilder = await readFile(
            new URL('tools/ci/build-sdk-package.ts', repositoryRoot),
            'utf8',
        );

        expect(wasmManifest.scripts['build:wasm']).toContain(
            'build-wasm-kernel.ts',
        );
        expect(sdkManifest.scripts.build).toContain('build-sdk-package.ts');
        expect(sdkBuilder).not.toMatch(/command:\s*['"]cargo['"]/u);
        expect(sdkBuilder).not.toContain('wasm-opt');
        expect(sdkBuilder).not.toContain('mkdtemp');
        expect(sdkBuilder).toContain("'sdk-package-declarations'");
    });
});
