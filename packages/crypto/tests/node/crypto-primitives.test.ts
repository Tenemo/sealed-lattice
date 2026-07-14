import type { CanonicalSignedRootObject } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    canonicalJson,
    deriveCanonicalObjectHash,
    hash512Hex,
    openCanonicalJsonByteSource,
    verifySignedObjectSignature,
} from '#packages/crypto/src/index';
import {
    createMlDsaKeyPairFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';

const contextHash = deriveCanonicalObjectHash({
    objectType: 'ActionContextHash',
    context: 'crypto-test',
});
const manifestHash = deriveCanonicalObjectHash({
    objectType: 'ManifestHash',
    manifest: 'crypto-test',
});

const textDecoder = new TextDecoder();
const textEncoder = new TextEncoder();

const concatenateBytes = (chunks: readonly Uint8Array[]): Uint8Array => {
    const result = new Uint8Array(
        chunks.reduce((byteLength, chunk) => byteLength + chunk.byteLength, 0),
    );
    let byteOffset = 0;
    for (const chunk of chunks) {
        result.set(chunk, byteOffset);
        byteOffset += chunk.byteLength;
    }

    return result;
};

const streamCanonicalJson = (
    value: unknown,
    maximumChunkByteLength: number,
): Uint8Array => {
    const source = openCanonicalJsonByteSource(value);
    const chunks: Uint8Array[] = [];
    let consumedByteLength = 0;
    let chunkIndex = 0;
    try {
        while (consumedByteLength < source.byteLength) {
            const expectedByteLength = Math.min(
                maximumChunkByteLength,
                source.byteLength - consumedByteLength,
            );
            const chunk = source.pullChunk({
                chunkIndex,
                expectedByteLength,
            });
            if (chunk === undefined) {
                throw new Error(
                    'Canonical JSON ended before its exact length.',
                );
            }
            chunks.push(new Uint8Array(chunk));
            consumedByteLength += chunk.byteLength;
            chunkIndex += 1;
        }
        expect(
            source.pullChunk({ chunkIndex, expectedByteLength: 0 }),
        ).toBeUndefined();

        return concatenateBytes(chunks);
    } finally {
        source.cancel();
    }
};

const createSignedRoot = (
    objectRoot = deriveCanonicalObjectHash({
        objectType: 'VssShareAcceptanceHash',
        object: 'root',
    }),
): CanonicalSignedRootObject => ({
    objectType: 'VssShareAcceptance',
    ceremonyId: 'ceremony',
    manifestHash,
    objectRoot,
    signerRole: 'Trustee',
    signerIdentity: 'trustee',
    recoveryEpoch: 0,
    deviceEpoch: 0,
    contextHash,
});

describe('crypto primitive boundary', () => {
    it('hashes large byte parts without argument spreading', () => {
        const largeCanonicalPart = new Uint8Array(200_000);

        largeCanonicalPart.fill(7);

        expect(
            hash512Hex('sealed-lattice-root/plaintext-root', [
                largeCanonicalPart,
            ]),
        ).toHaveLength(128);
    });

    it('canonicalizes JSON deterministically and rejects hostile values without executing them', () => {
        expect(canonicalJson({ b: [2, 1], a: { z: true } })).toBe(
            '{"a":{"z":true},"b":[2,1]}',
        );
        expect(canonicalJson({ '10': 'a', '2': 'b' })).toBe(
            '{"10":"a","2":"b"}',
        );

        let accessorReadCount = 0;
        const accessorBackedValue: Record<string, unknown> = {};
        Object.defineProperty(accessorBackedValue, 'value', {
            enumerable: true,
            get: () => {
                accessorReadCount += 1;
                return 'executed';
            },
        });
        const cyclicValue: Record<string, unknown> = {};
        cyclicValue.self = cyclicValue;

        for (const rejectedValue of [
            { value: '\u00e9' },
            { missing: undefined },
            { value: Number.MAX_SAFE_INTEGER + 1 },
            accessorBackedValue,
            cyclicValue,
        ]) {
            expect(() => canonicalJson(rejectedValue)).toThrow();
        }
        expect(accessorReadCount).toBe(0);
    });

    it('streams byte-exact canonical JSON across small and internal-fragment boundaries', () => {
        const longEscapedValue = `${'a'.repeat(4_091)}\u0000"\\${'z'.repeat(
            4_109,
        )}`;
        const value = {
            z: [
                null,
                true,
                false,
                -9_007_199_254_740_991,
                { nested: ['line\nfeed', 'tab\tvalue', longEscapedValue] },
            ],
            a: {
                '\u0001key': 'quote"backslash\\carriage\rreturn',
                empty: '',
            },
        };
        const expectedJson = canonicalJson(value);
        const expectedBytes = textEncoder.encode(expectedJson);

        for (const maximumChunkByteLength of [
            1, 2, 3, 5, 7, 16, 31, 127, 4_095, 4_096, 4_097, 16_384,
        ]) {
            const streamedBytes = streamCanonicalJson(
                value,
                maximumChunkByteLength,
            );
            expect(streamedBytes).toEqual(expectedBytes);
            expect(textDecoder.decode(streamedBytes)).toBe(expectedJson);
            expect(
                hash512Hex('sealed-lattice-test/canonical-stream', [
                    streamedBytes,
                ]),
            ).toBe(
                hash512Hex('sealed-lattice-test/canonical-stream', [
                    expectedBytes,
                ]),
            );
        }
    });

    it('reports the exact escaped byte length and enforces ordered exhaustion', () => {
        const value = {
            objectType: 'CanonicalJsonBoundaryFixture',
            controls: '\u0000\b\t\n\f\r"\\\u001f\u007f',
            values: [0, -1, Number.MAX_SAFE_INTEGER],
        };
        const expectedJson =
            '{"controls":"\\u0000\\b\\t\\n\\f\\r\\"\\\\\\u001f\u007f",' +
            '"objectType":"CanonicalJsonBoundaryFixture",' +
            '"values":[0,-1,9007199254740991]}';
        const source = openCanonicalJsonByteSource(value);
        try {
            expect(source.byteLength).toBe(
                textEncoder.encode(expectedJson).byteLength,
            );
            expect(() =>
                source.pullChunk({ chunkIndex: 1, expectedByteLength: 1 }),
            ).toThrow(/in order/u);
            expect(() =>
                source.pullChunk({ chunkIndex: 0, expectedByteLength: 0 }),
            ).toThrow(/exact length/u);

            const bytes = source.pullChunk({
                chunkIndex: 0,
                expectedByteLength: source.byteLength,
            });
            expect(bytes).toBeInstanceOf(ArrayBuffer);
            expect(textDecoder.decode(bytes)).toBe(expectedJson);
            expect(
                source.pullChunk({ chunkIndex: 1, expectedByteLength: 0 }),
            ).toBeUndefined();
            expect(() =>
                source.pullChunk({ chunkIndex: 2, expectedByteLength: 0 }),
            ).toThrow(/exhausted/u);
        } finally {
            source.cancel();
        }
    });

    it('fails closed when an unread value changes after length measurement', () => {
        for (const replacement of ['bravo', 'longer-than-bravo']) {
            const mutableValue = {
                first: 'a'.repeat(5_000),
                last: { value: 'delta' },
            };
            const source = openCanonicalJsonByteSource(mutableValue);
            const firstChunk = source.pullChunk({
                chunkIndex: 0,
                expectedByteLength: 1,
            });
            expect(textDecoder.decode(firstChunk)).toBe('{');
            mutableValue.last.value = replacement;

            expect(() =>
                source.pullChunk({
                    chunkIndex: 1,
                    expectedByteLength: source.byteLength - 1,
                }),
            ).toThrow(/changed while it was streamed/u);
            expect(() =>
                source.pullChunk({ chunkIndex: 2, expectedByteLength: 0 }),
            ).toThrow(/has failed/u);
            source.cancel();
        }
    });

    it('releases a partially consumed source and preserves canonical rejection limits', () => {
        const source = openCanonicalJsonByteSource({
            payload: ['first', { second: 'value' }],
        });
        const firstChunk = source.pullChunk({
            chunkIndex: 0,
            expectedByteLength: 3,
        });
        expect(firstChunk).toBeInstanceOf(ArrayBuffer);
        source.cancel();
        source.cancel();
        expect(() =>
            source.pullChunk({ chunkIndex: 1, expectedByteLength: 1 }),
        ).toThrow(/cancelled/u);

        let accessorReadCount = 0;
        const accessorValue: Record<string, unknown> = {};
        Object.defineProperty(accessorValue, 'secret', {
            enumerable: true,
            get: () => {
                accessorReadCount += 1;
                return 'must-not-run';
            },
        });
        const cyclicValue: Record<string, unknown> = {};
        cyclicValue.self = cyclicValue;
        let maximumDepthValue: unknown = null;
        for (let containerIndex = 0; containerIndex < 64; containerIndex += 1) {
            maximumDepthValue = { nested: maximumDepthValue };
        }
        expect(streamCanonicalJson(maximumDepthValue, 13).byteLength).toBe(
            textEncoder.encode(canonicalJson(maximumDepthValue)).byteLength,
        );
        let excessivelyNestedValue: unknown = null;
        for (let containerIndex = 0; containerIndex < 65; containerIndex += 1) {
            excessivelyNestedValue = { nested: excessivelyNestedValue };
        }
        const excessiveValueCount = new Array(1_000_000);
        for (const rejectedValue of [
            { value: '\u0080' },
            { value: '\ud800' },
            { missing: undefined },
            { number: -0 },
            accessorValue,
            cyclicValue,
            excessivelyNestedValue,
            excessiveValueCount,
        ]) {
            expect(() => openCanonicalJsonByteSource(rejectedValue)).toThrow();
        }
        expect(accessorReadCount).toBe(0);
    });

    it('creates deterministic ML-DSA fixtures and verifies signed roots', () => {
        const keyPair = createMlDsaKeyPairFixture('crypto-test-board');
        const signedRoot = createSignedRoot();
        const signature = createProtocolSignatureFixture({
            publicKeyBytesHex: keyPair.publicKeyBytesHex,
            publicKeyHash: keyPair.publicKeyHash,
            secretKeyBytesHex: keyPair.secretKeyBytesHex,
            signedRoot,
        });

        expect(keyPair.publicKeyHash).toBe(
            deriveCanonicalObjectHash({
                objectType: 'MlDsa65PublicKeyHash',
                publicKeyBytesHex: keyPair.publicKeyBytesHex,
            }),
        );
        expect(
            createProtocolSignatureFixture({
                publicKeyBytesHex: keyPair.publicKeyBytesHex,
                publicKeyHash: keyPair.publicKeyHash,
                secretKeyBytesHex: keyPair.secretKeyBytesHex,
                signedRoot,
            }),
        ).toEqual(signature);
        expect(
            verifySignedObjectSignature(signature, {
                ...signedRoot,
                publicKeyHash: keyPair.publicKeyHash,
            }),
        ).toEqual({ isValid: true, value: signature });
        expect(
            verifySignedObjectSignature(signature, {
                ...signedRoot,
                publicKeyHash: deriveCanonicalObjectHash({
                    objectType: 'PublicKeyHash',
                    key: 'wrong',
                }),
            }),
        ).toEqual({ isValid: false, refusalReason: 'wrongContext' });
    });

    it('rejects tampered signed roots and non-canonical hex encodings', () => {
        const keyPair = createMlDsaKeyPairFixture('crypto-test-metadata');
        const signedRoot = createSignedRoot();
        const signature = createProtocolSignatureFixture({
            publicKeyBytesHex: keyPair.publicKeyBytesHex,
            publicKeyHash: keyPair.publicKeyHash,
            secretKeyBytesHex: keyPair.secretKeyBytesHex,
            signedRoot,
        });
        const tamperedSignedRoot = {
            ...signature.signedRoot,
            recoveryEpoch: 999,
        };
        const tamperedSignedRootSignature = {
            ...signature,
            signedRoot: tamperedSignedRoot,
        };
        const uppercaseHexSignature = {
            ...signature,
            publicKeyBytesHex: signature.publicKeyBytesHex.toUpperCase(),
            signatureBytesHex: signature.signatureBytesHex.toUpperCase(),
        };

        expect(
            verifySignedObjectSignature(tamperedSignedRootSignature, {
                ...tamperedSignedRoot,
                publicKeyHash: keyPair.publicKeyHash,
            }),
        ).toEqual({ isValid: false, refusalReason: 'invalidSignature' });
        expect(
            verifySignedObjectSignature(uppercaseHexSignature, {
                ...signedRoot,
                publicKeyHash: keyPair.publicKeyHash,
            }),
        ).toEqual({ isValid: false, refusalReason: 'invalidSignature' });
    });

    it('rejects signatures over malformed signed-root hash bindings', () => {
        const keyPair = createMlDsaKeyPairFixture('crypto-test-bad-root');
        const {
            objectRoot: omittedObjectRoot,
            ...signedRootWithoutObjectRoot
        } = createSignedRoot();
        void omittedObjectRoot;
        const malformedRoots: CanonicalSignedRootObject[] = [
            {
                ...createSignedRoot(),
                manifestHash: 'not-a-hash',
            },
            {
                ...createSignedRoot(),
                objectRoot: 'not-a-hash',
            },
            {
                ...createSignedRoot(),
                contextHash: 'not-a-hash',
            },
        ];

        for (const signedRoot of malformedRoots) {
            const signature = createProtocolSignatureFixture({
                publicKeyBytesHex: keyPair.publicKeyBytesHex,
                publicKeyHash: keyPair.publicKeyHash,
                secretKeyBytesHex: keyPair.secretKeyBytesHex,
                signedRoot,
            });

            expect(
                verifySignedObjectSignature(signature, {
                    ...signedRoot,
                    publicKeyHash: keyPair.publicKeyHash,
                }),
            ).toMatchObject({
                isValid: false,
                refusalReason: 'wrongTypeOrLength',
            });
        }

        const validSignature = createProtocolSignatureFixture({
            publicKeyBytesHex: keyPair.publicKeyBytesHex,
            publicKeyHash: keyPair.publicKeyHash,
            secretKeyBytesHex: keyPair.secretKeyBytesHex,
            signedRoot: createSignedRoot(),
        });
        const signedRootMissingObjectRoot = {
            ...signedRootWithoutObjectRoot,
        } as CanonicalSignedRootObject;
        expect(
            verifySignedObjectSignature(
                {
                    ...validSignature,
                    signedRoot: signedRootMissingObjectRoot,
                },
                {
                    ...signedRootMissingObjectRoot,
                    publicKeyHash: keyPair.publicKeyHash,
                },
            ),
        ).toEqual({
            isValid: false,
            refusalReason: 'wrongTypeOrLength',
        });
    });
});
