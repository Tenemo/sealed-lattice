import type { CanonicalSignedRootObject } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    canonicalJson,
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveMlDsaPublicKeyDigest,
    deriveProtocolDigest,
    deriveProtocolSignatureDigest,
    hash512Hex,
    resolveProtocolDigestDomain,
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

    it('canonicalizes JSON deterministically and rejects unsupported values', () => {
        expect(canonicalJson({ b: [2, 1], a: { z: true } })).toBe(
            '{"a":{"z":true},"b":[2,1]}',
        );
        expect(() => canonicalJson({ missing: undefined })).toThrow(
            'Canonical objects cannot contain undefined.',
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
                providerBuildHash: deriveProtocolDigest('ProviderBuildDigest', {
                    forged: true,
                }),
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
});
