import { createHash } from 'node:crypto';

import {
    isParticipantIdentity,
    type ParticipantIdentity,
} from '@sealed-lattice/types';
import { describe, expect, expectTypeOf, it } from 'vitest';

import {
    TranscriptCoreKernelCommandError,
    loadTranscriptCoreKernel,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const unsigned16LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(2);
    new DataView(bytes.buffer).setUint16(0, value, true);

    return bytes;
};

const unsigned32LittleEndian = (value: number): Uint8Array => {
    const bytes = new Uint8Array(4);
    new DataView(bytes.buffer).setUint32(0, value, true);

    return bytes;
};

const concatenateBytes = (...chunks: readonly Uint8Array[]): Uint8Array => {
    const totalByteLength = chunks.reduce(
        (byteLength, chunk) => byteLength + chunk.byteLength,
        0,
    );
    const output = new Uint8Array(totalByteLength);
    let byteOffset = 0;
    for (const chunk of chunks) {
        output.set(chunk, byteOffset);
        byteOffset += chunk.byteLength;
    }

    return output;
};

const canonicalItem = (
    itemType: number,
    canonicalBytes: Uint8Array,
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(itemType),
        unsigned32LittleEndian(canonicalBytes.byteLength),
        canonicalBytes,
    );

const canonicalTuple = (
    schemaIdentifier: number,
    schemaVersion: number,
    ...items: readonly Uint8Array[]
): Uint8Array =>
    concatenateBytes(
        unsigned16LittleEndian(schemaIdentifier),
        unsigned16LittleEndian(schemaVersion),
        unsigned32LittleEndian(items.length),
        ...items,
    );

const hexadecimal = (bytes: Uint8Array): string =>
    Buffer.from(bytes).toString('hex');

const textEncoder = new TextEncoder();

const variableValue = (value: Uint8Array): Uint8Array =>
    concatenateBytes(unsigned32LittleEndian(value.byteLength), value);

const itemTuple = canonicalTuple(
    0x0001,
    1,
    canonicalItem(0x03, unsigned16LittleEndian(0x0201)),
    canonicalItem(0x01, variableValue(Uint8Array.from([7, 8, 9]))),
);

const foundationHash512 = (
    domain: string,
    ...items: readonly Uint8Array[]
): string => {
    const hashFrame = canonicalTuple(
        0x0001,
        1,
        canonicalItem(0x02, variableValue(textEncoder.encode(domain))),
        ...items,
    );

    return createHash('shake256', { outputLength: 64 })
        .update(hashFrame)
        .digest('hex');
};

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

const validateTuple = (
    kernel: TranscriptCoreKernel,
    bytes: Uint8Array,
): unknown =>
    kernel.validateFoundationCanonicalTuple({
        canonicalTupleHex: hexadecimal(bytes),
    });

describe('Foundation canonical binary contract', () => {
    it('validates and re-encodes a typed tuple byte identically', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const canonicalTupleHex = hexadecimal(itemTuple);

        expect(
            kernel.validateFoundationCanonicalTuple({ canonicalTupleHex }),
        ).toEqual({
            canonicalTupleHex,
            schemaIdentifier: 0x0001,
            schemaVersion: 1,
            itemCount: 2,
        });
    });

    it('computes the exact typed SHAKE256 foundation framing', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const domain = 'sealed-lattice/test/hash/v1';
        const expected = foundationHash512(
            domain,
            canonicalItem(0x03, unsigned16LittleEndian(0x0201)),
            canonicalItem(0x01, variableValue(Uint8Array.from([7, 8, 9]))),
        );

        expect(
            kernel.computeFoundationHash512({
                domain,
                canonicalItemsTupleHex: hexadecimal(itemTuple),
            }),
        ).toBe(expected);
        expectCommandErrorCode(
            () =>
                kernel.computeFoundationHash512({
                    domain: '',
                    canonicalItemsTupleHex: hexadecimal(itemTuple),
                }),
            'InvalidProtocolObject',
        );
        expectCommandErrorCode(
            () =>
                kernel.computeFoundationHash512({
                    domain: 'sealed-lattice/test\n',
                    canonicalItemsTupleHex: hexadecimal(itemTuple),
                }),
            'InvalidProtocolObject',
        );
        expectCommandErrorCode(
            () =>
                kernel.computeFoundationHash512({
                    domain,
                    canonicalItemsTupleHex: hexadecimal(
                        canonicalTuple(0x0100, 1),
                    ),
                }),
            'InvalidProtocolObject',
        );
    });

    it('derives participant identity from exactly one ML-DSA-65 public key', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const signingVerificationKey = new Uint8Array(1_952);
        const expected = foundationHash512(
            'sealed-lattice/foundation/participant-id/v1',
            canonicalItem(0x01, signingVerificationKey),
        );

        const participantIdentity = kernel.deriveFoundationParticipantIdentity({
            signingVerificationKeyHex: hexadecimal(signingVerificationKey),
        });
        expect(participantIdentity).toBe(expected);
        expect(isParticipantIdentity(participantIdentity)).toBe(true);
        expectTypeOf(participantIdentity).toEqualTypeOf<ParticipantIdentity>();

        for (const invalidByteLength of [0, 1_951, 1_953]) {
            expectCommandErrorCode(
                () =>
                    kernel.deriveFoundationParticipantIdentity({
                        signingVerificationKeyHex: '00'.repeat(
                            invalidByteLength,
                        ),
                    }),
                'MalformedLength',
            );
        }
    });

    it('rejects truncated, trailing, unknown, and hostile tuple encodings', async () => {
        const kernel = await loadTranscriptCoreKernel();
        expectCommandErrorCode(
            () => validateTuple(kernel, itemTuple.slice(0, -1)),
            'MalformedLength',
        );
        expectCommandErrorCode(
            () =>
                validateTuple(
                    kernel,
                    concatenateBytes(itemTuple, Uint8Array.of(0)),
                ),
            'TrailingBytes',
        );
        expectCommandErrorCode(
            () =>
                validateTuple(
                    kernel,
                    canonicalTuple(
                        0x0001,
                        1,
                        canonicalItem(0xffff, new Uint8Array()),
                    ),
                ),
            'InvalidEnum',
        );
        expectCommandErrorCode(
            () =>
                validateTuple(
                    kernel,
                    canonicalTuple(
                        0x0001,
                        1,
                        canonicalItem(0x03, Uint8Array.of(1)),
                    ),
                ),
            'InvalidProtocolObject',
        );

        const hostileItemCount = concatenateBytes(
            unsigned16LittleEndian(0x0001),
            unsigned16LittleEndian(1),
            unsigned32LittleEndian(0xffff_ffff),
        );
        expectCommandErrorCode(
            () => validateTuple(kernel, hostileItemCount),
            'MalformedLength',
        );

        const hostileItemLength = concatenateBytes(
            unsigned16LittleEndian(0x0001),
            unsigned16LittleEndian(1),
            unsigned32LittleEndian(1),
            unsigned16LittleEndian(0x01),
            unsigned32LittleEndian(0xffff_ffff),
        );
        expectCommandErrorCode(
            () => validateTuple(kernel, hostileItemLength),
            'MalformedLength',
        );
        expectCommandErrorCode(
            () =>
                kernel.validateFoundationCanonicalTuple({
                    canonicalTupleHex: hexadecimal(
                        canonicalTuple(
                            0x0001,
                            1,
                            canonicalItem(
                                0x01,
                                variableValue(Uint8Array.of(0xab)),
                            ),
                        ),
                    ).toUpperCase(),
                }),
            'InvalidHex',
        );
    });
});
