import { describe, expect, it } from 'vitest';

import {
    foundationHashContractVector,
    invalidFoundationSchemaObjectVectors,
    invalidFoundationDisplayTextVectors,
    participantIdentityContractVector,
    validFoundationSchemaObjectVectors,
    validFoundationDisplayTextVectors,
} from '../foundation-canonical-test-vectors.js';

import {
    TranscriptCoreKernelCommandError,
    loadTranscriptCoreKernel,
} from '#packages/wasm/src/index';

const hash512Pattern = /^[a-f0-9]{128}$/u;

const hexadecimal = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

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

    it('re-encodes every accepted foundation schema without returning producer bytes', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(validFoundationSchemaObjectVectors).toHaveLength(45);
        expect(
            new Set(
                validFoundationSchemaObjectVectors.map(
                    (vector) => vector.schemaIdentifier,
                ),
            ).size,
        ).toBe(45);
        for (const vector of validFoundationSchemaObjectVectors) {
            const result = kernel.validateFoundationSchemaObject({
                canonicalBytes: vector.canonicalBytes,
            });
            expect(result, vector.name).toEqual({
                schemaIdentifier: vector.schemaIdentifier,
                schemaVersion: 1,
                canonicalByteLength: vector.canonicalBytes.byteLength,
            });
        }
    });

    it('matches independent foundation hash and participant-identity vectors', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(
            kernel.computeFoundationHash512({
                domain: foundationHashContractVector.domain,
                canonicalItemsTupleHex: hexadecimal(
                    foundationHashContractVector.canonicalItemsTupleBytes,
                ),
            }),
        ).toBe(foundationHashContractVector.expectedHash);
        expect(
            kernel.deriveFoundationParticipantIdentity({
                signingVerificationKeyHex: hexadecimal(
                    participantIdentityContractVector.signingVerificationKey,
                ),
            }),
        ).toBe(participantIdentityContractVector.expectedParticipantIdentity);
    });

    it('returns the same stable refusal codes as Node for invalid schema objects', async () => {
        const kernel = await loadTranscriptCoreKernel();

        for (const vector of invalidFoundationSchemaObjectVectors) {
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
            ).toBe(vector.expectedCode);
        }
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
