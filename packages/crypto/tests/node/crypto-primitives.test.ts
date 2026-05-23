import type { CanonicalSignedRootObject } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    canonicalJson,
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveMlDsaPublicKeyDigest,
    deriveProtocolDigest,
    deriveProtocolHash,
    deriveProtocolSignatureDigest,
    hash512,
    hash512Hex,
    protocolDigestNamespaceByHashAlias,
    protocolHashAliasByDigestNamespace,
    resolveProtocolDigestDomain,
    resolveProtocolHashNamespace,
    verifySignedObjectSignature,
} from '../../src/index';

const contextDigest = deriveProtocolDigest('ActionContextDigest', {
    context: 'crypto-test',
});

const createSignedRoot = (
    objectRoot = deriveProtocolDigest('BoardHeadDigest', { object: 'root' }),
): CanonicalSignedRootObject => ({
    objectType: 'BoardHead',
    objectVersion: 1,
    ceremonyId: 'ceremony',
    manifestDigest: null,
    boardHeadDigest: null,
    objectRoot,
    chunkMerkleRoot: null,
    byteLength: 64,
    signerRole: 'Board',
    signerIdentity: 'board',
    recoveryEpoch: 0,
    deviceEpoch: 0,
    contextDigest,
});

describe('crypto primitive boundary', () => {
    it('uses the Rust Hash512 framing for protocol digest namespaces', () => {
        const canonicalBytes = new TextEncoder().encode(
            canonicalJson({ poll: 'main' }),
        );

        expect(resolveProtocolDigestDomain('PollSpecDigest')).toBe(
            'sealed-lattice-root/poll-spec-digest-v1',
        );
        expect(
            hash512Hex('sealed-lattice-root/poll-spec-digest-v1', [
                canonicalBytes,
            ]),
        ).toBe(
            '423c71de65abadb5adc05d9b6b704252420bb738af888c62614c8afc53a2be808662585305e76738b23e4f20154f8779e3827c0c8f313455d84675924f4a2c83',
        );
        expect(deriveProtocolDigest('PollSpecDigest', { poll: 'main' })).toBe(
            '423c71de65abadb5adc05d9b6b704252420bb738af888c62614c8afc53a2be808662585305e76738b23e4f20154f8779e3827c0c8f313455d84675924f4a2c83',
        );
    });

    it('hashes large byte parts without argument spreading', () => {
        const largeCanonicalPart = new Uint8Array(200_000);

        largeCanonicalPart.fill(7);

        expect(
            hash512('sealed-lattice-root/plaintext-root-v1', [
                largeCanonicalPart,
            ]),
        ).toHaveLength(64);
    });

    it('rejects unreserved protocol digest namespaces', () => {
        expect(() =>
            resolveProtocolDigestDomain('AuxiliaryBridgeModulusDigest'),
        ).toThrow('reserved');
        expect(() =>
            resolveProtocolDigestDomain(
                'sealed-lattice-root/auxiliary-bridge-modulus-digest-v1',
            ),
        ).toThrow('reserved');
        expect(() =>
            deriveProtocolDigest('ReceiverKeyRoot', {
                receiver: 'fixture',
            }),
        ).toThrow('reserved');
    });

    it('maps document-facing Hash names onto reserved v1 namespaces', () => {
        const targetProposal = { target: 'proposal' };

        expect(resolveProtocolHashNamespace('TargetProposalHash')).toBe(
            'TargetProposalDigest',
        );
        expect(protocolDigestNamespaceByHashAlias.ManifestHash).toBe(
            'ElectionManifestDigest',
        );
        expect(
            protocolHashAliasByDigestNamespace.KllpsTargetDecryptionProfileDigest,
        ).toBe('KllpsTargetDecryptionProfileHash');
        expect(deriveProtocolHash('TargetProposalHash', targetProposal)).toBe(
            deriveProtocolDigest('TargetProposalDigest', targetProposal),
        );
    });

    it('canonicalizes JSON deterministically and rejects unsupported values', () => {
        const objectWithPrototypeKey: Record<string, unknown> = {
            safe: true,
        };
        Object.defineProperty(objectWithPrototypeKey, '__proto__', {
            value: { polluted: true },
            enumerable: true,
            configurable: true,
            writable: true,
        });
        const objectWithEquivalentUnicodeKeys: Record<string, unknown> = {};
        Object.defineProperty(objectWithEquivalentUnicodeKeys, '\u0065\u0301', {
            value: 'first',
            enumerable: true,
            configurable: true,
            writable: true,
        });
        Object.defineProperty(objectWithEquivalentUnicodeKeys, '\u00e9', {
            value: 'second',
            enumerable: true,
            configurable: true,
            writable: true,
        });
        const sparseArray = new Array<unknown>(1);

        expect(canonicalJson({ b: [2, 1], a: { z: true } })).toBe(
            '{"a":{"z":true},"b":[2,1]}',
        );
        expect(canonicalJson({ '10': 'a', '2': 'b' })).toBe(
            '{"10":"a","2":"b"}',
        );
        expect(canonicalJson({ '\u0065\u0301': 1, z: 2 })).toBe(
            '{"z":2,"é":1}',
        );
        expect(canonicalJson({ '\u0061\u0303': 1, z: 2 })).toBe(
            `{"z":2,"${'\u00e3'}":1}`,
        );
        expect(canonicalJson({ '\u00e4': 1, '\u00e3': 2 })).toBe(
            `{"${'\u00e3'}":2,"${'\u00e4'}":1}`,
        );
        expect(canonicalJson({ value: '\u0065\u0301' })).toBe(
            '{"value":"\u00e9"}',
        );
        expect(() => canonicalJson(objectWithEquivalentUnicodeKeys)).toThrow(
            'NFC normalization',
        );
        expect(() => canonicalJson({ value: '\ud800' })).toThrow(
            'lone UTF-16 surrogates',
        );
        expect(() => canonicalJson({ '\udc00': true })).toThrow(
            'lone UTF-16 surrogates',
        );
        expect(canonicalJson(objectWithPrototypeKey)).toBe(
            '{"__proto__":{"polluted":true},"safe":true}',
        );
        expect(() => canonicalJson({ missing: undefined })).toThrow(
            'Canonical objects cannot contain undefined.',
        );
        expect(() => canonicalJson(sparseArray)).toThrow(
            'Canonical arrays cannot be sparse.',
        );
        expect(() => canonicalJson(1.5)).toThrow(
            'Canonical numeric fields must be safe integers.',
        );
        expect(() =>
            canonicalJson({ value: Number.MAX_SAFE_INTEGER + 1 }),
        ).toThrow('Canonical numeric fields must be safe integers.');
        expect(() => canonicalJson({ value: -0 })).toThrow(
            'Canonical numeric fields must be safe integers.',
        );
    });

    it('creates deterministic ML-DSA fixtures and verifies signed roots', () => {
        const profile = createMlDsaSignatureProfileFixture();
        const keyPair = createMlDsaKeyPairFixture('crypto-test-board');
        const signedRoot = createSignedRoot();
        const signature = createProtocolSignatureFixture({
            profile,
            publicKeyBytesHex: keyPair.publicKeyBytesHex,
            publicKeyDigest: keyPair.publicKeyDigest,
            secretKeyBytesHex: keyPair.secretKeyBytesHex,
            signedRoot,
        });

        expect(deriveMlDsaPublicKeyDigest(keyPair.publicKeyBytesHex)).toBe(
            keyPair.publicKeyDigest,
        );
        expect(signature.signatureDigest).toMatch(/^[0-9a-f]{128}$/u);
        expect(
            verifySignedObjectSignature(signature, {
                objectType: 'BoardHead',
                objectVersion: 1,
                signerRole: 'Board',
                signerIdentity: 'board',
                ceremonyId: 'ceremony',
                publicKeyDigest: keyPair.publicKeyDigest,
                objectRoot: signedRoot.objectRoot,
                boardHeadDigest: null,
                manifestDigest: null,
                contextDigest,
            }).ok,
        ).toBe(true);
        expect(
            verifySignedObjectSignature(signature, {
                objectType: 'BoardHead',
                objectVersion: 1,
                signerRole: 'Board',
                signerIdentity: 'board',
                ceremonyId: 'ceremony',
                publicKeyDigest: deriveProtocolDigest('PublicKeyDigest', {
                    key: 'wrong',
                }),
                objectRoot: signedRoot.objectRoot,
                boardHeadDigest: null,
                manifestDigest: null,
                contextDigest,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
    });

    it('rejects unsigned signature metadata and non-canonical hex encodings', () => {
        const profile = createMlDsaSignatureProfileFixture();
        const keyPair = createMlDsaKeyPairFixture('crypto-test-metadata');
        const signedRoot = createSignedRoot();
        const signature = createProtocolSignatureFixture({
            profile,
            publicKeyBytesHex: keyPair.publicKeyBytesHex,
            publicKeyDigest: keyPair.publicKeyDigest,
            secretKeyBytesHex: keyPair.secretKeyBytesHex,
            signedRoot,
        });
        const tamperedProfilePayload = {
            profile: {
                ...signature.profile,
                providerName: 'forged-provider',
                providerVersion: '999',
                providerBuildDigest: deriveProtocolDigest(
                    'ProviderBuildDigest',
                    {
                        forged: true,
                    },
                ),
            },
            publicKeyBytesHex: signature.publicKeyBytesHex,
            publicKeyDigest: signature.publicKeyDigest,
            signatureBytesHex: signature.signatureBytesHex,
            signedRoot: signature.signedRoot,
        };
        const tamperedProfileSignature = {
            ...tamperedProfilePayload,
            signatureDigest: deriveProtocolSignatureDigest(
                tamperedProfilePayload,
            ),
        };
        const uppercaseHexSignature = {
            ...signature,
            publicKeyBytesHex: signature.publicKeyBytesHex.toUpperCase(),
            signatureBytesHex: signature.signatureBytesHex.toUpperCase(),
        };

        for (const rejectedSignature of [
            tamperedProfileSignature,
            uppercaseHexSignature,
        ]) {
            expect(
                verifySignedObjectSignature(rejectedSignature, {
                    objectType: 'BoardHead',
                    objectVersion: 1,
                    signerRole: 'Board',
                    signerIdentity: 'board',
                    ceremonyId: 'ceremony',
                    publicKeyDigest: keyPair.publicKeyDigest,
                    objectRoot: signedRoot.objectRoot,
                    boardHeadDigest: null,
                    manifestDigest: null,
                    contextDigest,
                }).refusedObjects,
            ).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({ code: 'InvalidSignature' }),
                ]),
            );
        }
    });

    it('rejects signatures over malformed signed-root digest bindings', () => {
        const profile = createMlDsaSignatureProfileFixture();
        const keyPair = createMlDsaKeyPairFixture('crypto-test-bad-root');
        const malformedRoots: CanonicalSignedRootObject[] = [
            {
                ...createSignedRoot(),
                objectRoot: 'not-a-digest',
            } as CanonicalSignedRootObject,
            {
                ...createSignedRoot(),
                objectRoot: null,
                chunkMerkleRoot: 'A'.repeat(128),
            } as CanonicalSignedRootObject,
            {
                ...createSignedRoot(),
                contextDigest: 'not-a-digest',
            } as CanonicalSignedRootObject,
        ];

        for (const signedRoot of malformedRoots) {
            const signature = createProtocolSignatureFixture({
                profile,
                publicKeyBytesHex: keyPair.publicKeyBytesHex,
                publicKeyDigest: keyPair.publicKeyDigest,
                secretKeyBytesHex: keyPair.secretKeyBytesHex,
                signedRoot,
            });

            expect(verifySignedObjectSignature(signature)).toMatchObject({
                ok: false,
                refusedObjects: [
                    expect.objectContaining({ code: 'InvalidSignedRoot' }),
                ],
            });
        }
    });
});
