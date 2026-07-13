import { foundationProfile } from '@sealed-lattice/types';
import { describe, expect, expectTypeOf, it } from 'vitest';

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
    type FoundationSchemaObjectValidation,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const hexadecimal = (bytes: Uint8Array): string =>
    Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');

const validate = (
    kernel: TranscriptCoreKernel,
    canonicalBytes: Uint8Array,
): FoundationSchemaObjectValidation =>
    kernel.validateFoundationSchemaObject({ canonicalBytes });

const expectCommandErrorCode = (
    operation: () => unknown,
    expectedCode: string,
): void => {
    let observedError: unknown;
    try {
        operation();
    } catch (error) {
        observedError = error;
    }
    expect(observedError).toBeInstanceOf(TranscriptCoreKernelCommandError);
    expect((observedError as TranscriptCoreKernelCommandError).code).toBe(
        expectedCode,
    );
};

describe('Foundation schema object WASM boundary', () => {
    it('derives schema identity and re-encodes every accepted schema byte-identically', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(validFoundationSchemaObjectVectors).toHaveLength(46);
        expect(
            new Set(
                validFoundationSchemaObjectVectors.map(
                    (vector) => vector.schemaIdentifier,
                ),
            ).size,
        ).toBe(46);
        for (const vector of validFoundationSchemaObjectVectors) {
            const canonicalBytes = vector.canonicalBytes;
            const result = validate(kernel, canonicalBytes);
            expect(result, vector.name).toEqual({
                schemaIdentifier: vector.schemaIdentifier,
                schemaVersion: 1,
                canonicalByteLength: canonicalBytes.byteLength,
            });
            expectTypeOf(
                result,
            ).toEqualTypeOf<FoundationSchemaObjectValidation>();
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

    it('enforces the pinned Unicode 17 canonical-text corpus', async () => {
        const kernel = await loadTranscriptCoreKernel();

        for (const vector of validFoundationDisplayTextVectors) {
            expect(
                validate(kernel, vector.canonicalBytes),
                vector.name,
            ).toMatchObject({
                schemaIdentifier: 0x0111,
                schemaVersion: 1,
                canonicalByteLength: vector.canonicalBytes.byteLength,
            });
        }

        for (const vector of invalidFoundationDisplayTextVectors) {
            expectCommandErrorCode(
                () => validate(kernel, vector.canonicalBytes),
                'InvalidProtocolObject',
            );
        }
    });

    it('refuses unknown, unsupported-version, trailing, malformed, oversized, and invalid runtime inputs', async () => {
        const kernel = await loadTranscriptCoreKernel();
        for (const vector of invalidFoundationSchemaObjectVectors) {
            expectCommandErrorCode(
                () => validate(kernel, vector.canonicalBytes),
                vector.expectedCode,
            );
        }
        expectCommandErrorCode(
            () =>
                validate(
                    kernel,
                    new Uint8Array(
                        foundationProfile.maximumCopiedBufferByteLength + 1,
                    ),
                ),
            'MalformedLength',
        );
        expectCommandErrorCode(
            () =>
                kernel.validateFoundationSchemaObject({
                    canonicalBytes: {
                        byteLength: 0,
                        length:
                            foundationProfile.maximumCopiedBufferByteLength + 1,
                    } as unknown as Uint8Array,
                }),
            'InvalidProtocolObject',
        );
        const disguisedUnsigned16Array = new Uint16Array([0x0303, 1]);
        Object.defineProperty(disguisedUnsigned16Array, Symbol.toStringTag, {
            value: 'Uint8Array',
        });
        expectCommandErrorCode(
            () =>
                kernel.validateFoundationSchemaObject({
                    canonicalBytes:
                        disguisedUnsigned16Array as unknown as Uint8Array,
                }),
            'InvalidProtocolObject',
        );
    });
});
