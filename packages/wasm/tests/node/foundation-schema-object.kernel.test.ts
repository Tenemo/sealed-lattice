import { foundationProfile } from '@sealed-lattice/types';
import { describe, expect, expectTypeOf, it } from 'vitest';

import {
    invalidFoundationDisplayTextVectors,
    validFoundationDisplayTextVectors,
} from '../foundation-canonical-test-vectors.js';

import {
    TranscriptCoreKernelCommandError,
    loadTranscriptCoreKernel,
    type FoundationSchemaObjectValidation,
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

const unsigned64LittleEndian = (value: bigint): Uint8Array => {
    const bytes = new Uint8Array(8);
    new DataView(bytes.buffer).setBigUint64(0, value, true);
    return bytes;
};

const concatenateBytes = (...chunks: readonly Uint8Array[]): Uint8Array => {
    const byteLength = chunks.reduce(
        (total, chunk) => total + chunk.byteLength,
        0,
    );
    const bytes = new Uint8Array(byteLength);
    let offset = 0;
    for (const chunk of chunks) {
        bytes.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return bytes;
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

const textEncoder = new TextEncoder();
const variableBytes = (bytes: Uint8Array): Uint8Array =>
    concatenateBytes(unsigned32LittleEndian(bytes.byteLength), bytes);
const ascii = (value: string): Uint8Array =>
    canonicalItem(0x02, variableBytes(textEncoder.encode(value)));
const displayText = (value: string): Uint8Array =>
    canonicalItem(0x0c, variableBytes(textEncoder.encode(value)));
const hash = (byte: number): Uint8Array =>
    canonicalItem(0x06, new Uint8Array(64).fill(byte));
const participantIdentity = (byte: number): Uint8Array =>
    canonicalItem(0x07, new Uint8Array(64).fill(byte));
const unsigned16 = (value: number): Uint8Array =>
    canonicalItem(0x03, unsigned16LittleEndian(value));
const unsigned32 = (value: number): Uint8Array =>
    canonicalItem(0x04, unsigned32LittleEndian(value));
const unsigned64 = (value: bigint): Uint8Array =>
    canonicalItem(0x05, unsigned64LittleEndian(value));
const fixedBytes = (byteLength: number, byte: number): Uint8Array =>
    canonicalItem(0x01, new Uint8Array(byteLength).fill(byte));
const emptyHashList = (): Uint8Array =>
    canonicalItem(
        0x0e,
        concatenateBytes(
            unsigned16LittleEndian(0x06),
            unsigned32LittleEndian(0),
        ),
    );

const mailboxKeyScheduleInput = canonicalTuple(
    0x0200,
    1,
    ascii('sealed-lattice/mailbox/key-schedule/v1'),
    unsigned16(1),
    hash(1),
    hash(2),
    hash(3),
    hash(4),
    participantIdentity(5),
    participantIdentity(6),
    unsigned64(7n),
    fixedBytes(32, 8),
    ascii('source-to-recipient'),
    unsigned16(1),
    unsigned16(1),
    hash(9),
    emptyHashList(),
    hash(10),
);

const representativeObjects = [
    canonicalTuple(
        0x0111,
        1,
        unsigned16(0),
        ascii('option-1'),
        displayText('Option 1'),
    ),
    mailboxKeyScheduleInput,
    canonicalTuple(0x0303, 1, hash(11)),
    canonicalTuple(0x1610, 1, unsigned16(1), hash(12)),
    canonicalTuple(0x1806, 1, unsigned16(1), unsigned16(2)),
    canonicalTuple(0x0106, 1, unsigned32(3), unsigned64(4n), hash(13)),
    canonicalTuple(
        0x2203,
        1,
        unsigned16(0),
        unsigned32(4),
        unsigned64(3n),
        unsigned16(2),
        unsigned32(8),
        unsigned32(4),
        unsigned16(2),
    ),
] as const;

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
    it('derives schema identity and re-encodes representative families byte-identically', async () => {
        const kernel = await loadTranscriptCoreKernel();

        for (const canonicalBytes of representativeObjects) {
            const result = validate(kernel, canonicalBytes);
            expect(result).toEqual({
                schemaIdentifier: new DataView(
                    canonicalBytes.buffer,
                    canonicalBytes.byteOffset,
                    canonicalBytes.byteLength,
                ).getUint16(0, true),
                schemaVersion: 1,
                canonicalByteLength: canonicalBytes.byteLength,
            });
            expectTypeOf(
                result,
            ).toEqualTypeOf<FoundationSchemaObjectValidation>();
        }
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
        expectCommandErrorCode(
            () => validate(kernel, canonicalTuple(0xffff, 1)),
            'UnsupportedObjectType',
        );
        expectCommandErrorCode(
            () => validate(kernel, canonicalTuple(0x0303, 2, hash(1))),
            'UnsupportedObjectVersion',
        );
        expectCommandErrorCode(
            () =>
                validate(
                    kernel,
                    concatenateBytes(
                        canonicalTuple(0x0303, 1, hash(1)),
                        Uint8Array.of(0),
                    ),
                ),
            'InvalidProtocolObject',
        );
        expectCommandErrorCode(
            () => validate(kernel, canonicalTuple(0x0303, 1, unsigned16(1))),
            'InvalidProtocolObject',
        );
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
