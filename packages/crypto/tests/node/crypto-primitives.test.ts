import type { CanonicalSignedRootObject } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    canonicalJson,
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveMlDsaPublicKeyHash,
    deriveProtocolHash,
    deriveProtocolSignatureHash,
    hash512,
    hash512Hex,
    resolveProtocolHashDomain,
    verifySignedObjectSignature,
} from '#packages/crypto/src/index';

const contextHash = deriveProtocolHash('ActionContextHash', {
    context: 'crypto-test',
});

const createSignedRoot = (
    objectRoot = deriveProtocolHash('BoardHeadHash', { object: 'root' }),
): CanonicalSignedRootObject => ({
    objectType: 'BoardHead',
    objectVersion: 1,
    ceremonyId: 'ceremony',
    manifestHash: null,
    boardHeadHash: null,
    objectRoot,
    chunkMerkleRoot: null,
    byteLength: 64,
    signerRole: 'Board',
    signerIdentity: 'board',
    recoveryEpoch: 0,
    deviceEpoch: 0,
    contextHash,
});

describe('crypto primitive boundary', () => {
    it('uses the Rust Hash512 framing for protocol hash namespaces', () => {
        const canonicalBytes = new TextEncoder().encode(
            canonicalJson({ poll: 'main' }),
        );

        expect(resolveProtocolHashDomain('PollSpecHash')).toBe(
            'sealed-lattice-root/poll-spec-hash-v1',
        );
        expect(
            hash512Hex('sealed-lattice-root/poll-spec-hash-v1', [
                canonicalBytes,
            ]),
        ).toBe(
            '43b28c9a3dcb3e34d75c9936a9930b68fb9f2010b87d43a6a61cbaa85d343d9fd0be2b312a90f404367b9c68793b0dcf02c4dae7351f6e96ded894b92f898cb4',
        );
        expect(deriveProtocolHash('PollSpecHash', { poll: 'main' })).toBe(
            '43b28c9a3dcb3e34d75c9936a9930b68fb9f2010b87d43a6a61cbaa85d343d9fd0be2b312a90f404367b9c68793b0dcf02c4dae7351f6e96ded894b92f898cb4',
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

    it('rejects unreserved protocol hash namespaces', () => {
        expect(() =>
            resolveProtocolHashDomain('UnreservedInternalModulusHash'),
        ).toThrow('reserved');
        expect(() =>
            resolveProtocolHashDomain(
                'sealed-lattice-root/unreserved-internal-modulus-hash-v1',
            ),
        ).toThrow('reserved');
        expect(() =>
            deriveProtocolHash('UnreservedInternalRoot', {
                fixture: 'rejected',
            }),
        ).toThrow('reserved');
    });

    it('uses only reserved hash namespaces without aliases', () => {
        const targetProposal = { target: 'proposal' };
        const targetProposalHash = deriveProtocolHash(
            'TargetProposalHash',
            targetProposal,
        );

        expect(resolveProtocolHashDomain('TargetProposalHash')).toBe(
            'sealed-lattice-root/target-proposal-hash-v1',
        );
        expect(() => resolveProtocolHashDomain('ManifestHash')).toThrow(
            'reserved',
        );
        expect(targetProposalHash).toMatch(/^[0-9a-f]{128}$/u);
        expect(targetProposalHash).toBe(
            deriveProtocolHash('TargetProposalHash', targetProposal),
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
            publicKeyHash: keyPair.publicKeyHash,
            secretKeyBytesHex: keyPair.secretKeyBytesHex,
            signedRoot,
        });

        expect(deriveMlDsaPublicKeyHash(keyPair.publicKeyBytesHex)).toBe(
            keyPair.publicKeyHash,
        );
        expect(signature.signatureHash).toMatch(/^[0-9a-f]{128}$/u);
        expect(
            verifySignedObjectSignature(signature, {
                objectType: 'BoardHead',
                objectVersion: 1,
                signerRole: 'Board',
                signerIdentity: 'board',
                ceremonyId: 'ceremony',
                publicKeyHash: keyPair.publicKeyHash,
                objectRoot: signedRoot.objectRoot,
                boardHeadHash: null,
                manifestHash: null,
                contextHash,
            }).ok,
        ).toBe(true);
        expect(
            verifySignedObjectSignature(signature, {
                objectType: 'BoardHead',
                objectVersion: 1,
                signerRole: 'Board',
                signerIdentity: 'board',
                ceremonyId: 'ceremony',
                publicKeyHash: deriveProtocolHash('PublicKeyHash', {
                    key: 'wrong',
                }),
                objectRoot: signedRoot.objectRoot,
                boardHeadHash: null,
                manifestHash: null,
                contextHash,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
    });

    it('requires explicit signature expectation bindings unless unbound verification is requested', () => {
        const profile = createMlDsaSignatureProfileFixture();
        const keyPair = createMlDsaKeyPairFixture('crypto-test-boundary');
        const signedRoot = createSignedRoot();
        const signature = createProtocolSignatureFixture({
            profile,
            publicKeyBytesHex: keyPair.publicKeyBytesHex,
            publicKeyHash: keyPair.publicKeyHash,
            secretKeyBytesHex: keyPair.secretKeyBytesHex,
            signedRoot,
        });

        expect(verifySignedObjectSignature(signature)).toMatchObject({
            ok: false,
            refusedObjects: [
                expect.objectContaining({ code: 'InvalidSignedRoot' }),
            ],
        });
        expect(
            verifySignedObjectSignature(signature, {
                allowUnboundVerification: true,
            }),
        ).toMatchObject({
            ok: true,
        });
    });

    it('rejects unsigned signature metadata and non-canonical hex encodings', () => {
        const profile = createMlDsaSignatureProfileFixture();
        const keyPair = createMlDsaKeyPairFixture('crypto-test-metadata');
        const signedRoot = createSignedRoot();
        const signature = createProtocolSignatureFixture({
            profile,
            publicKeyBytesHex: keyPair.publicKeyBytesHex,
            publicKeyHash: keyPair.publicKeyHash,
            secretKeyBytesHex: keyPair.secretKeyBytesHex,
            signedRoot,
        });
        const tamperedProfilePayload = {
            profile: {
                ...signature.profile,
                providerName: 'forged-provider',
                providerVersion: '999',
                providerBuildHash: deriveProtocolHash('ProviderBuildHash', {
                    forged: true,
                }),
            },
            publicKeyBytesHex: signature.publicKeyBytesHex,
            publicKeyHash: signature.publicKeyHash,
            signatureBytesHex: signature.signatureBytesHex,
            signedRoot: signature.signedRoot,
        };
        const tamperedProfileSignature = {
            ...tamperedProfilePayload,
            signatureHash: deriveProtocolSignatureHash(tamperedProfilePayload),
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
                    publicKeyHash: keyPair.publicKeyHash,
                    objectRoot: signedRoot.objectRoot,
                    boardHeadHash: null,
                    manifestHash: null,
                    contextHash,
                }).refusedObjects,
            ).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({ code: 'InvalidSignature' }),
                ]),
            );
        }
    });

    it('rejects signatures over malformed signed-root hash bindings', () => {
        const profile = createMlDsaSignatureProfileFixture();
        const keyPair = createMlDsaKeyPairFixture('crypto-test-bad-root');
        const malformedRoots: CanonicalSignedRootObject[] = [
            {
                ...createSignedRoot(),
                objectRoot: 'not-a-hash',
            },
            {
                ...createSignedRoot(),
                objectRoot: null,
                chunkMerkleRoot: 'A'.repeat(128),
            },
            {
                ...createSignedRoot(),
                contextHash: 'not-a-hash',
            },
        ];

        for (const signedRoot of malformedRoots) {
            const signature = createProtocolSignatureFixture({
                profile,
                publicKeyBytesHex: keyPair.publicKeyBytesHex,
                publicKeyHash: keyPair.publicKeyHash,
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
