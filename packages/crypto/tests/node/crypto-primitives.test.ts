import type { CanonicalSignedRootObject } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    canonicalJson,
    createPrivateVssMailboxKeyPair,
    decryptLocalTrusteeSetupSealedMaterial,
    decryptLocalTrusteeState,
    decryptPrivateVssMailboxEnvelope,
    deriveCanonicalObjectHash,
    deriveLocalTrusteeSetupStateCommitmentRoot,
    deriveMlDsaPublicKeyHash,
    encryptLocalTrusteeSetupSealedMaterial,
    encryptLocalTrusteeState,
    encryptPrivateVssMailboxEnvelope,
    hash512Hex,
    verifySignedObjectSignature,
} from '#packages/crypto/src/index';
import {
    createMlDsaKeyPairFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import { withDeterministicWebCryptoRandomness } from '#tests/support/deterministic-web-crypto-randomness';

const contextHash = deriveCanonicalObjectHash({
    objectType: 'ActionContextHash',
    context: 'crypto-test',
});

const changeLastHexByte = (hexEncodedBytes: string): string =>
    `${hexEncodedBytes.slice(0, -2)}${
        hexEncodedBytes.endsWith('00') ? '01' : '00'
    }`;

const createSignedRoot = (
    objectRoot = deriveCanonicalObjectHash({
        objectType: 'BoardHeadHash',
        object: 'root',
    }),
): CanonicalSignedRootObject => ({
    objectType: 'BoardHead',
    ceremonyId: 'ceremony',
    manifestHash: null,
    boardHeadHash: null,
    objectRoot,
    chunkMerkleRoot: null,
    signerRole: 'Board',
    signerIdentity: 'board',
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

    it('creates deterministic ML-DSA fixtures and verifies signed roots', () => {
        const keyPair = createMlDsaKeyPairFixture('crypto-test-board');
        const signedRoot = createSignedRoot();
        const signature = createProtocolSignatureFixture({
            publicKeyBytesHex: keyPair.publicKeyBytesHex,
            publicKeyHash: keyPair.publicKeyHash,
            secretKeyBytesHex: keyPair.secretKeyBytesHex,
            signedRoot,
        });

        expect(deriveMlDsaPublicKeyHash(keyPair.publicKeyBytesHex)).toBe(
            keyPair.publicKeyHash,
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
            }).isValid,
        ).toBe(true);
        expect(
            verifySignedObjectSignature(signature, {
                ...signedRoot,
                publicKeyHash: deriveCanonicalObjectHash({
                    objectType: 'PublicKeyHash',
                    key: 'wrong',
                }),
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
    });

    it('encrypts private VSS mailbox envelopes and rejects tampered delivery material', async () => {
        const mailboxKeySeed = hash512Hex('test/private-vss-mailbox-key', [
            new TextEncoder().encode('recipient-trustee-3'),
        ]);
        const encapsulationRandomnessBytesHex = hash512Hex(
            'test/private-vss-mailbox-encapsulation',
            [new TextEncoder().encode('source-trustee-2-to-recipient-3')],
        ).slice(0, 64);
        const aeadNonceBytesHex = hash512Hex('test/private-vss-mailbox-nonce', [
            new TextEncoder().encode('source-trustee-2-to-recipient-3'),
        ]).slice(0, 24);
        const recipientMailboxKeyPair =
            createPrivateVssMailboxKeyPair(mailboxKeySeed);
        const privateEnvelopeAad = {
            objectType: 'PrivateVssEnvelopeAad',
            ceremonyId: 'ceremony',
            manifestHash: deriveCanonicalObjectHash({
                objectType: 'ElectionManifestHash',
                manifest: 'mailbox-test',
            }),
            rosterHash: deriveCanonicalObjectHash({
                objectType: 'RosterHash',
                roster: 'mailbox-test',
            }),
            sourceTrusteeIdentity: 'trustee-2',
            recipientIdentity: 'trustee-3',
            envelopeSequenceNumber: 23,
        };
        const privateEnvelope = {
            objectType: 'PrivateVssShareEnvelope',
            privateEnvelopeAadHash:
                deriveCanonicalObjectHash(privateEnvelopeAad),
            sourceTrusteeIdentity: 'trustee-2',
            recipientIdentity: 'trustee-3',
            rnsShareOpenings: [
                {
                    rnsLimbIndex: 0,
                    shareValues: [1, 2, 3],
                    privateVssShareProof: {
                        objectType: 'PrivateVssShareProof',
                        proofId: 'sealed-lattice-private-vss-share-proof-lnp',
                        proofMaterialRoot: deriveCanonicalObjectHash({
                            objectType: 'PrivateVssShareEnvelopeHash',
                            proof: 'material-root',
                        }),
                        proofBytesHash: deriveCanonicalObjectHash({
                            objectType: 'PrivateVssShareEnvelopeHash',
                            proof: 'bytes-hash',
                        }),
                        proofStatementRoot: deriveCanonicalObjectHash({
                            objectType: 'PrivateVssShareEnvelopeHash',
                            proof: 'statement-root',
                        }),
                    },
                },
            ],
        };

        const encrypted = await withDeterministicWebCryptoRandomness(
            [encapsulationRandomnessBytesHex, aeadNonceBytesHex],
            () =>
                encryptPrivateVssMailboxEnvelope({
                    privateEnvelope,
                    privateEnvelopeAad,
                    recipientMailboxPublicKeyBytesHex:
                        recipientMailboxKeyPair.publicKeyBytesHex,
                }),
        );

        expect(encrypted.encryptedEnvelope).toMatchObject({
            objectType: 'EncryptedPrivateVssShareEnvelope',
            recipientMailboxPublicKeyHash:
                recipientMailboxKeyPair.publicKeyHash,
            aeadNonceHex: aeadNonceBytesHex,
        });
        expect(encrypted.encryptedEnvelopeHash).toMatch(/^[0-9a-f]{128}$/u);
        const privateEnvelopeHash = deriveCanonicalObjectHash(privateEnvelope);
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: encrypted.encryptedEnvelope,
                expectedPrivateEnvelopeHash: privateEnvelopeHash,
                expectedEncryptedEnvelopeHash: encrypted.encryptedEnvelopeHash,
                recipientMailboxSecretKeyBytesHex:
                    recipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).resolves.toEqual(privateEnvelope);
        const wrongRecipientMailboxKeyPair = createPrivateVssMailboxKeyPair(
            hash512Hex('test/private-vss-mailbox-key', [
                new TextEncoder().encode('recipient-trustee-4'),
            ]),
        );
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: encrypted.encryptedEnvelope,
                expectedPrivateEnvelopeHash: privateEnvelopeHash,
                expectedEncryptedEnvelopeHash: encrypted.encryptedEnvelopeHash,
                recipientMailboxSecretKeyBytesHex:
                    wrongRecipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).rejects.toThrow();

        const tamperedCiphertext = {
            ...encrypted.encryptedEnvelope,
            ciphertextBytesHex: changeLastHexByte(
                encrypted.encryptedEnvelope.ciphertextBytesHex,
            ),
        } as typeof encrypted.encryptedEnvelope;
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: tamperedCiphertext,
                expectedPrivateEnvelopeHash: privateEnvelopeHash,
                expectedEncryptedEnvelopeHash:
                    deriveCanonicalObjectHash(tamperedCiphertext),
                recipientMailboxSecretKeyBytesHex:
                    recipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).rejects.toThrow();

        const reboundAad = {
            ...encrypted.encryptedEnvelope,
            privateEnvelopeAad: {
                ...privateEnvelopeAad,
                recipientIdentity: 'trustee-4',
            },
        };
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: reboundAad,
                expectedPrivateEnvelopeHash: privateEnvelopeHash,
                expectedEncryptedEnvelopeHash:
                    deriveCanonicalObjectHash(reboundAad),
                recipientMailboxSecretKeyBytesHex:
                    recipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).rejects.toThrow();
    });

    it('encrypts local trustee setup state and rejects raw or rebound state', async () => {
        const setupContext = {
            ceremonyId: 'ceremony',
            manifestHash: deriveCanonicalObjectHash({
                objectType: 'ElectionManifestHash',
                manifest: 'local-state-storage-test',
            }),
            rosterHash: deriveCanonicalObjectHash({
                objectType: 'RosterHash',
                roster: 'local-state-storage-test',
            }),
            setupParametersHash: deriveCanonicalObjectHash({
                objectType: 'SetupParametersHash',
                parameters: 'local-state-storage-test',
            }),
            setupEpoch: 'setup-epoch-1',
        };
        const thresholdShareCommitmentRecipientRoot = deriveCanonicalObjectHash(
            {
                objectType: 'ActionContextHash',
                commitment: 'threshold-share-commitment-recipient',
            },
        );
        const storageKeyBytesHex = '11'.repeat(32);
        const aeadNonceBytesHex = '22'.repeat(12);
        const sealedAggregateThresholdShare =
            await withDeterministicWebCryptoRandomness(['33'.repeat(12)], () =>
                encryptLocalTrusteeSetupSealedMaterial({
                    materialPlaintext: {
                        objectType:
                            'LocalTrusteeAggregateThresholdShareMaterial',
                        trusteeIdentity: 'trustee-3',
                        trusteeRosterPosition: 3,
                        thresholdShareCommitmentRecipientRoot,
                        shareValues: [1, 2, 3],
                    },
                    setupContext,
                    trusteeIdentity: 'trustee-3',
                    trusteeRosterPosition: 3,
                    thresholdShareCommitmentRecipientRoot,
                    storageKeyBytesHex,
                }),
            );
        const aggregateThresholdShareRoot =
            sealedAggregateThresholdShare.materialRoot;
        const localStateCommitmentWithoutRoot = {
            objectType: 'LocalTrusteeSetupStateCommitment',
            ceremonyId: setupContext.ceremonyId,
            manifestHash: setupContext.manifestHash,
            rosterHash: setupContext.rosterHash,
            setupParametersHash: setupContext.setupParametersHash,
            setupEpoch: setupContext.setupEpoch,
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            thresholdShareCommitmentRecipientRoot,
            aggregateThresholdShareRoot,
        } as const;
        const localStateCommitment = {
            ...localStateCommitmentWithoutRoot,
            localStateRoot: deriveLocalTrusteeSetupStateCommitmentRoot(
                localStateCommitmentWithoutRoot,
            ),
        } as const;
        const localStatePlaintext = {
            objectType: 'LocalTrusteeSetupStateSealedPayload',
            sealedAggregateThresholdShare,
        } as const;

        const encrypted = await withDeterministicWebCryptoRandomness(
            [aeadNonceBytesHex],
            () =>
                encryptLocalTrusteeState({
                    localStatePlaintext,
                    localStateCommitment,
                    setupContext,
                    storageKeyBytesHex,
                }),
        );

        expect(encrypted).toMatchObject({
            objectType: 'EncryptedLocalTrusteeSetupState',
            aeadNonceHex: aeadNonceBytesHex,
        });
        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: encrypted,
                expectedLocalStateRoot: localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex,
            }),
        ).resolves.toEqual(localStatePlaintext);
        await expect(
            decryptLocalTrusteeSetupSealedMaterial({
                sealedMaterial: sealedAggregateThresholdShare,
                expectedMaterialRoot: aggregateThresholdShareRoot,
                localStateCommitment,
                setupContext,
                storageKeyBytesHex,
            }),
        ).resolves.toMatchObject({
            objectType: 'LocalTrusteeAggregateThresholdShareMaterial',
            shareValues: [1, 2, 3],
        });

        const tamperedSealedCiphertextBytesHex = changeLastHexByte(
            sealedAggregateThresholdShare.ciphertextBytesHex,
        );
        const tamperedSealedMaterial = {
            ...sealedAggregateThresholdShare,
            ciphertextBytesHex: tamperedSealedCiphertextBytesHex,
        } as typeof sealedAggregateThresholdShare;
        await expect(
            decryptLocalTrusteeSetupSealedMaterial({
                sealedMaterial: tamperedSealedMaterial,
                expectedMaterialRoot: aggregateThresholdShareRoot,
                localStateCommitment,
                setupContext,
                storageKeyBytesHex,
            }),
        ).rejects.toThrow();

        const tamperedLocalStateCiphertextBytesHex = changeLastHexByte(
            encrypted.ciphertextBytesHex,
        );
        const tamperedLocalState = {
            ...encrypted,
            ciphertextBytesHex: tamperedLocalStateCiphertextBytesHex,
        } as typeof encrypted;
        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: tamperedLocalState,
                expectedLocalStateRoot: localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex,
            }),
        ).rejects.toThrow();

        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: encrypted,
                expectedLocalStateRoot: localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex: '44'.repeat(32),
            }),
        ).rejects.toThrow();

        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: encrypted,
                expectedLocalStateRoot: deriveCanonicalObjectHash({
                    objectType: 'LocalTrusteeSetupStateRoot',
                    trustee: 'wrong',
                }),
                setupContext,
                storageKeyBytesHex,
            }),
        ).rejects.toThrow(/expectedLocalStateRoot/u);
        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: {
                    ...encrypted,
                    storageAad: {
                        ...encrypted.storageAad,
                        localStateCommitment: {
                            ...localStateCommitment,
                            aggregateThresholdShareRoot:
                                thresholdShareCommitmentRecipientRoot,
                        },
                    },
                },
                expectedLocalStateRoot: localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex,
            }),
        ).rejects.toThrow(/canonical local state commitment/u);
        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: encrypted,
                expectedLocalStateRoot: localStateCommitment.localStateRoot,
                setupContext: {
                    ...setupContext,
                    setupEpoch: 'setup-epoch-2',
                },
                storageKeyBytesHex,
            }),
        ).rejects.toThrow(/storageAad/u);
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
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidSignature' }),
            ]),
        );
        expect(
            verifySignedObjectSignature(uppercaseHexSignature, {
                ...signedRoot,
                publicKeyHash: keyPair.publicKeyHash,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidSignature' }),
            ]),
        );
    });

    it('rejects signatures over malformed signed-root hash bindings', () => {
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
                refusedObjects: [
                    expect.objectContaining({ code: 'InvalidSignedRoot' }),
                ],
            });
        }
    });
});
