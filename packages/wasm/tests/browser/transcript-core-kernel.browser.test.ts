import { describe, expect, it } from 'vitest';

import {
    invalidFoundationDisplayTextVectors,
    validFoundationDisplayTextVectors,
} from '../foundation-canonical-test-vectors.js';

import {
    TranscriptCoreKernelCommandError,
    loadTranscriptCoreKernel,
} from '#packages/wasm/src/index';

const hash512Pattern = /^[a-f0-9]{128}$/u;

const storageRootCommitmentPayload = (): Uint8Array => {
    const bytes = new Uint8Array(78);
    const view = new DataView(bytes.buffer);
    view.setUint16(0, 0x0303, true);
    view.setUint16(2, 1, true);
    view.setUint32(4, 1, true);
    view.setUint16(8, 0x06, true);
    view.setUint32(10, 64, true);
    bytes.fill(0x5a, 14);
    return bytes;
};

describe('transcript-core kernel in browsers', () => {
    it('loads the transcript-core module and runs a command through browser WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(kernel.exportedFunctionNames).toEqual(
            expect.arrayContaining([
                'memory',
                'sealed_lattice_allocate',
                'sealed_lattice_deallocate',
                'sealed_lattice_transcript_core_command_with_length',
            ]),
        );

        const pollSpecHash = kernel.deriveCanonicalObjectHash({
            value: { objectType: 'PollSpec', poll: 'main' },
        });

        expect(pollSpecHash).toMatch(hash512Pattern);
    });

    it('validates an independently encoded foundation schema without returning its bytes', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const canonicalBytes = storageRootCommitmentPayload();

        const result = kernel.validateFoundationSchemaObject({
            canonicalBytes,
        });
        expect(result).toEqual({
            schemaIdentifier: 0x0303,
            schemaVersion: 1,
            canonicalByteLength: canonicalBytes.byteLength,
        });
        expect(result).not.toHaveProperty('canonicalBytes');
        expect(result).not.toHaveProperty('canonicalObjectHex');
    });

    it('enforces the same pinned Unicode 17 corpus as Node', async () => {
        const kernel = await loadTranscriptCoreKernel();

        for (const vector of validFoundationDisplayTextVectors) {
            expect(
                kernel.validateFoundationSchemaObject({
                    canonicalBytes: vector.canonicalBytes,
                }),
                vector.name,
            ).toMatchObject({
                schemaIdentifier: 0x0111,
                schemaVersion: 1,
                canonicalByteLength: vector.canonicalBytes.byteLength,
            });
        }

        for (const vector of invalidFoundationDisplayTextVectors) {
            let observedError: unknown;
            try {
                kernel.validateFoundationSchemaObject({
                    canonicalBytes: vector.canonicalBytes,
                });
            } catch (error) {
                observedError = error;
            }
            expect(observedError, vector.name).toBeInstanceOf(
                TranscriptCoreKernelCommandError,
            );
            expect(
                (observedError as TranscriptCoreKernelCommandError).code,
                vector.name,
            ).toBe('InvalidProtocolObject');
        }
    });
});
