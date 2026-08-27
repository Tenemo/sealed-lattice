import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { describe, expect, it, vi } from 'vitest';

import { openFoundationCeremonyRuntime } from '../../src/foundation-ceremony-runtime.js';
import { normalizeTranscriptCoreKernelBytesForHash } from '../../src/transcript-core-bridge/kernel-runtime.js';
import { createPublishedSdkKernelLoader } from '../../src/transcript-core-bridge/published-sdk-kernel-loader.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);

const loadRuntime = async () =>
    openFoundationCeremonyRuntime(
        await createPublishedSdkKernelLoader(kernelUrl, {
            allowUnpinnedKernel: true,
        })(),
    );

const currentKernelSha256Hex = async (): Promise<string> =>
    createHash('sha256')
        .update(
            normalizeTranscriptCoreKernelBytesForHash(
                new Uint8Array(await readFile(kernelUrl)),
            ),
        )
        .digest('hex');

const manifestInput = (optionCount: number) => ({
    displayTitle: 'Choose priorities',
    optionDefinitions: Array.from(
        { length: optionCount },
        (_unused, optionIndex) => ({
            displayLabel: `Option ${String(optionIndex)}`,
            optionIdentifier: `option-${String(optionIndex)}`,
            optionIndex,
        }),
    ),
});

describe('foundation ceremony runtime with the scalar WASM kernel', () => {
    it('exports only the active command and joined-custody ABI with standard WASM globals', async () => {
        const module = await WebAssembly.compile(await readFile(kernelUrl));
        expect(WebAssembly.Module.exports(module)).toEqual([
            { kind: 'memory', name: 'memory' },
            { kind: 'function', name: 'sealed_lattice_allocate' },
            { kind: 'function', name: 'sealed_lattice_deallocate' },
            { kind: 'function', name: 'sealed_lattice_deallocate_secret' },
            {
                kind: 'function',
                name: 'sealed_lattice_transcript_core_command_with_length',
            },
            {
                kind: 'function',
                name: 'sealed_lattice_join_seed_masters_320_with_length',
            },
            {
                kind: 'function',
                name: 'sealed_lattice_validate_joined_seed_masters_320_with_length',
            },
            { kind: 'global', name: '__data_end' },
            { kind: 'global', name: '__heap_base' },
        ]);
    });

    it('loads only an integrity-pinned joined-custody kernel and preserves typed Rust refusals', async () => {
        const expectedKernelSha256Hex = await currentKernelSha256Hex();
        const integrityBindingName =
            '__SEALED_LATTICE_KERNEL_NORMALIZED_SHA256_HEX__';
        const globalBindings = globalThis as Record<string, unknown>;
        const priorBinding = Object.getOwnPropertyDescriptor(
            globalBindings,
            integrityBindingName,
        );
        try {
            Object.defineProperty(globalBindings, integrityBindingName, {
                configurable: true,
                value: '00'.repeat(32),
            });
            vi.resetModules();
            const wrongIdentityModule =
                await import('../../src/joined-seed-master-custody-kernel.js');
            await expect(
                wrongIdentityModule.openProductionJoinedSeedMasterCustodyKernel(
                    kernelUrl,
                ),
            ).rejects.toThrow('failed integrity verification');

            Object.defineProperty(globalBindings, integrityBindingName, {
                configurable: true,
                value: expectedKernelSha256Hex,
            });
            vi.resetModules();
            const joinedKernelModule =
                await import('../../src/joined-seed-master-custody-kernel.js');
            const kernel =
                await joinedKernelModule.openProductionJoinedSeedMasterCustodyKernel(
                    kernelUrl,
                );
            expect(
                joinedKernelModule.isProductionJoinedSeedMasterCustodyKernel(
                    kernel,
                ),
            ).toBe(true);
            expect(
                joinedKernelModule.isProductionJoinedSeedMasterCustodyKernel({
                    joinAndEncode: () => new Uint8Array(),
                    validateRetained: () => undefined,
                }),
            ).toBe(false);

            const malformedRequest = Uint8Array.of(0x53, 0x4c, 0x4a);
            expect(() => kernel.joinAndEncode(malformedRequest)).toThrowError(
                expect.objectContaining({ code: 'MalformedRequest' }),
            );
            expect(() =>
                kernel.validateRetained(malformedRequest),
            ).toThrowError(
                expect.objectContaining({ code: 'MalformedRequest' }),
            );
            expect(malformedRequest).toEqual(Uint8Array.of(0x53, 0x4c, 0x4a));
        } finally {
            if (priorBinding === undefined) {
                Reflect.deleteProperty(globalBindings, integrityBindingName);
            } else {
                Object.defineProperty(
                    globalBindings,
                    integrityBindingName,
                    priorBinding,
                );
            }
            vi.resetModules();
        }
    });

    it.each([2, 10, 20])(
        'roundtrips a canonical %i-option manifest through the exact kernel bytes',
        async (optionCount) => {
            const runtime = await loadRuntime();
            const encoded = runtime.encodeManifest(manifestInput(optionCount));

            expect(encoded.canonicalBytes.byteLength).toBeGreaterThan(0);
            expect(runtime.verifyManifest(encoded.canonicalBytes)).toEqual({
                isValid: true,
                value: { manifestHash: encoded.manifestHash },
            });
            expect(
                runtime.verifyManifest(encoded.canonicalBytes.slice(0, -1)),
            ).toEqual({
                isValid: false,
                refusalReason: 'malformedEncoding',
            });
        },
    );

    it('refuses duplicate option indexes and trailing canonical bytes', async () => {
        const runtime = await loadRuntime();
        const duplicateIndexInput = manifestInput(2);
        duplicateIndexInput.optionDefinitions[1] = {
            ...duplicateIndexInput.optionDefinitions[1],
            optionIndex: 0,
        };
        expect(() => runtime.encodeManifest(duplicateIndexInput)).toThrow();

        const encoded = runtime.encodeManifest(manifestInput(2));
        const trailing = new Uint8Array(encoded.canonicalBytes.length + 1);
        trailing.set(encoded.canonicalBytes);
        expect(runtime.verifyManifest(trailing)).toEqual({
            isValid: false,
            refusalReason: 'malformedEncoding',
        });
    });
});
