import type { CanonicalSignedRootObject } from '@sealed-lattice/types';
import { describe, expect, it } from 'vitest';

import {
    canonicalJson,
    createPrivateVssMailboxKeyPair,
    decryptLocalTrusteeSetupSealedMaterial,
    decryptLocalTrusteeState,
    decryptPrivateVssMailboxEnvelope,
    deriveMlDsaPublicKeyHash,
    deriveProtocolHash,
    deriveProtocolSignatureHash,
    encryptLocalTrusteeSetupSealedMaterial,
    encryptLocalTrusteeState,
    encryptPrivateVssMailboxEnvelope,
    hash512Hex,
    resolveProtocolHashDomain,
    verifySignedObjectSignature,
} from '#packages/crypto/src/index';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';

const contextHash = deriveProtocolHash('ActionContextHash', {
    context: 'crypto-test',
});
const testTextEncoder = new TextEncoder();

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
            hash512Hex('sealed-lattice-root/plaintext-root-v1', [
                largeCanonicalPart,
            ]),
        ).toHaveLength(128);
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
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            mailboxEncryptionProfileId:
                'sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1',
            ceremonyId: 'ceremony',
            manifestHash: deriveProtocolHash('ElectionManifestHash', {
                manifest: 'mailbox-test',
            }),
            rosterHash: deriveProtocolHash('RosterHash', {
                roster: 'mailbox-test',
            }),
            sourceTrusteeIdentity: 'trustee-2',
            recipientIdentity: 'trustee-3',
            envelopeSequenceNumber: 23,
        };
        const privateEnvelope = {
            objectType: 'PrivateVssShareEnvelope',
            objectVersion: 1,
            privateEnvelopeAadHash: deriveProtocolHash(
                'PrivateVssEnvelopeAadHash',
                privateEnvelopeAad,
            ),
            sourceTrusteeIdentity: 'trustee-2',
            recipientIdentity: 'trustee-3',
            rnsShareOpenings: [
                {
                    rnsLimbIndex: 0,
                    shareValuesLittleEndian48Hex:
                        '010000000000020000000000030000000000',
                    privateVssShareProof: {
                        objectType: 'PrivateVssShareProof',
                        objectVersion: 1,
                        proofProfileId:
                            'sealed-lattice-private-vss-share-proof-lnp-v1',
                        proofMaterialRoot: deriveProtocolHash(
                            'PrivateVssShareEnvelopeHash',
                            { proof: 'material-root' },
                        ),
                        proofBytesHash: deriveProtocolHash(
                            'PrivateVssShareEnvelopeHash',
                            { proof: 'bytes-hash' },
                        ),
                        proofStatementRoot: deriveProtocolHash(
                            'PrivateVssShareEnvelopeHash',
                            { proof: 'statement-root' },
                        ),
                        proofVerificationStatus:
                            'verifier-required-not-implemented',
                    },
                },
            ],
        };

        const encrypted = await encryptPrivateVssMailboxEnvelope({
            privateEnvelope,
            privateEnvelopeAad,
            recipientMailboxPublicKeyBytesHex:
                recipientMailboxKeyPair.publicKeyBytesHex,
            encapsulationRandomnessBytesHex,
            aeadNonceBytesHex,
        });

        expect(encrypted.encryptedEnvelope).toMatchObject({
            objectType: 'EncryptedPrivateVssShareEnvelope',
            objectVersion: 1,
            recipientMailboxPublicKeyHash:
                recipientMailboxKeyPair.publicKeyHash,
            aeadNonceHex: aeadNonceBytesHex,
            aeadTagLength: 128,
        });
        expect(encrypted.encryptedEnvelope.encryptedEnvelopeHash).toMatch(
            /^[0-9a-f]{128}$/u,
        );
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: encrypted.encryptedEnvelope,
                recipientMailboxSecretKeyBytesHex:
                    recipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).resolves.toMatchObject({
            privateEnvelope,
            privateEnvelopeHash: encrypted.privateEnvelopeHash,
            privateEnvelopeAadHash: encrypted.privateEnvelopeAadHash,
        });

        const originalPrivateMailboxCiphertext =
            encrypted.encryptedEnvelope.ciphertextBytesBase64;
        if (typeof originalPrivateMailboxCiphertext !== 'string') {
            throw new TypeError(
                'encrypted private VSS envelope ciphertext must be base64 text.',
            );
        }
        const tamperedCiphertext = {
            ...encrypted.encryptedEnvelope,
            ciphertextBytesBase64: `${
                originalPrivateMailboxCiphertext.startsWith('A') ? 'B' : 'A'
            }${originalPrivateMailboxCiphertext.slice(1)}`,
        };
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: tamperedCiphertext,
                recipientMailboxSecretKeyBytesHex:
                    recipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).rejects.toThrow(/ciphertextBytesHash/u);

        const wrongKemCiphertextHash = {
            ...encrypted.encryptedEnvelope,
            kemCiphertextHash: deriveProtocolHash(
                'PrivateVssEncryptedEnvelopeHash',
                {
                    fixture: 'wrong-kem-ciphertext-hash',
                },
            ),
        };
        const wrongKemCiphertextHashWithoutHash = Object.fromEntries(
            Object.entries(wrongKemCiphertextHash).filter(
                ([fieldName]) => fieldName !== 'encryptedEnvelopeHash',
            ),
        );
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: {
                    ...wrongKemCiphertextHash,
                    encryptedEnvelopeHash: deriveProtocolHash(
                        'PrivateVssEncryptedEnvelopeHash',
                        wrongKemCiphertextHashWithoutHash,
                    ),
                },
                recipientMailboxSecretKeyBytesHex:
                    recipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).rejects.toThrow(/kemCiphertextHash/u);

        const wrongCiphertextBytesHash = {
            ...encrypted.encryptedEnvelope,
            ciphertextBytesHash: deriveProtocolHash(
                'PrivateVssEncryptedEnvelopeHash',
                {
                    fixture: 'wrong-ciphertext-bytes-hash',
                },
            ),
        };
        const wrongCiphertextBytesHashWithoutHash = Object.fromEntries(
            Object.entries(wrongCiphertextBytesHash).filter(
                ([fieldName]) => fieldName !== 'encryptedEnvelopeHash',
            ),
        );
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: {
                    ...wrongCiphertextBytesHash,
                    encryptedEnvelopeHash: deriveProtocolHash(
                        'PrivateVssEncryptedEnvelopeHash',
                        wrongCiphertextBytesHashWithoutHash,
                    ),
                },
                recipientMailboxSecretKeyBytesHex:
                    recipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).rejects.toThrow(/ciphertextBytesHash/u);

        const wrongPrivateEnvelopeAadHash = {
            ...encrypted.encryptedEnvelope,
            privateEnvelopeAadHash: deriveProtocolHash(
                'PrivateVssEnvelopeAadHash',
                {
                    fixture: 'wrong-private-envelope-aad-hash',
                },
            ),
        };
        const wrongPrivateEnvelopeAadHashWithoutHash = Object.fromEntries(
            Object.entries(wrongPrivateEnvelopeAadHash).filter(
                ([fieldName]) => fieldName !== 'encryptedEnvelopeHash',
            ),
        );
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: {
                    ...wrongPrivateEnvelopeAadHash,
                    encryptedEnvelopeHash: deriveProtocolHash(
                        'PrivateVssEncryptedEnvelopeHash',
                        wrongPrivateEnvelopeAadHashWithoutHash,
                    ),
                },
                recipientMailboxSecretKeyBytesHex:
                    recipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).rejects.toThrow(/AAD hash/u);

        const reboundAad = {
            ...encrypted.encryptedEnvelope,
            privateEnvelopeAad: {
                ...privateEnvelopeAad,
                recipientIdentity: 'trustee-4',
            },
        };
        const reboundAadWithoutHash = Object.fromEntries(
            Object.entries(reboundAad).filter(
                ([fieldName]) => fieldName !== 'encryptedEnvelopeHash',
            ),
        );
        await expect(
            decryptPrivateVssMailboxEnvelope({
                encryptedEnvelope: {
                    ...reboundAad,
                    encryptedEnvelopeHash: deriveProtocolHash(
                        'PrivateVssEncryptedEnvelopeHash',
                        reboundAadWithoutHash,
                    ),
                },
                recipientMailboxSecretKeyBytesHex:
                    recipientMailboxKeyPair.secretKeyBytesHex,
            }),
        ).rejects.toThrow();
    });

    it('encrypts local trustee setup state and rejects raw or rebound state', async () => {
        const setupContext = {
            ceremonyId: 'ceremony',
            manifestHash: deriveProtocolHash('ElectionManifestHash', {
                manifest: 'local-state-storage-test',
            }),
            rosterHash: deriveProtocolHash('RosterHash', {
                roster: 'local-state-storage-test',
            }),
            setupProfileHash: deriveProtocolHash(
                'CollectiveBgvSetupProfileHash',
                {
                    profile: 'local-state-storage-test',
                },
            ),
            qShareHash: deriveProtocolHash('QSharePrimeListHash', {
                qShare: 'local-state-storage-test',
            }),
            carryAwareVssShareRelationProfileHash: deriveProtocolHash(
                'CarryAwareVssShareRelationProfileHash',
                { relation: 'local-state-storage-test' },
            ),
            commitmentProfileHash: deriveProtocolHash(
                'SetupCommitmentProfileHash',
                { commitment: 'local-state-storage-test' },
            ),
            setupEpoch: 'setup-epoch-1',
        };
        const thresholdShareCommitmentRecipientRoot = deriveProtocolHash(
            'ActionContextHash',
            {
                commitment: 'threshold-share-commitment-recipient',
            },
        );
        const issuedVssAcceptanceRoot = deriveProtocolHash(
            'VssShareAcceptanceRoot',
            {
                accepted: 'source-trustee-1',
            },
        );
        const issuedVssComplaintRoots = [
            deriveProtocolHash('VssComplaintRoot', {
                complaint: 'source-trustee-2',
            }),
        ];
        const storageKeyBytesHex = '11'.repeat(32);
        const aeadNonceBytesHex = '22'.repeat(12);
        const sealedAggregateThresholdShare =
            await encryptLocalTrusteeSetupSealedMaterial({
                materialClass: 'aggregate-threshold-share-sealed',
                materialPlaintext: {
                    objectType: 'LocalTrusteeAggregateThresholdShareMaterial',
                    objectVersion: 1,
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
                aeadNonceBytesHex: '33'.repeat(12),
            });
        const aggregateThresholdShareRoot =
            sealedAggregateThresholdShare.materialRoot;
        const sealedTargetDecryptionProofWitness =
            await encryptLocalTrusteeSetupSealedMaterial({
                materialClass: 'target-decryption-proof-witness-sealed',
                materialPlaintext: {
                    objectType:
                        'LocalTrusteeTargetDecryptionProofWitnessMaterial',
                    objectVersion: 1,
                    trusteeIdentity: 'trustee-3',
                    trusteeRosterPosition: 3,
                    thresholdShareCommitmentRecipientRoot,
                    aggregateThresholdShareRoot,
                },
                setupContext,
                trusteeIdentity: 'trustee-3',
                trusteeRosterPosition: 3,
                thresholdShareCommitmentRecipientRoot,
                storageKeyBytesHex,
                aeadNonceBytesHex: '44'.repeat(12),
            });
        const targetDecryptionProofWitnessRoot =
            sealedTargetDecryptionProofWitness.materialRoot;
        const localStateCommitment = {
            objectType: 'LocalTrusteeSetupStateCommitment',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            ceremonyId: setupContext.ceremonyId,
            manifestHash: setupContext.manifestHash,
            rosterHash: setupContext.rosterHash,
            setupEpoch: setupContext.setupEpoch,
            localStateRoot: deriveProtocolHash('LocalTrusteeSetupStateRoot', {
                trustee: 'trustee-3',
            }),
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            thresholdShareCommitmentRecipientRoot,
            aggregateThresholdShareRoot,
            targetDecryptionProofWitnessRoot,
            issuedVssAcceptanceRoot,
            issuedVssComplaintRoots,
        } as const;
        const localStatePlaintext = {
            objectType: 'LocalTrusteeSetupStateSealedPayload',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            ceremonyId: setupContext.ceremonyId,
            manifestHash: setupContext.manifestHash,
            rosterHash: setupContext.rosterHash,
            setupEpoch: setupContext.setupEpoch,
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            deviceEpoch: 0,
            thresholdShareCommitmentRecipientRoot,
            sealedAggregateThresholdShare: {
                ...sealedAggregateThresholdShare.sealedMaterial,
            },
            sealedTargetDecryptionProofWitness: {
                ...sealedTargetDecryptionProofWitness.sealedMaterial,
            },
            issuedVssAcceptanceRoots: [issuedVssAcceptanceRoot],
            issuedVssComplaintRoots,
        } as const;

        const encrypted = await encryptLocalTrusteeState({
            localStatePlaintext,
            localStateCommitment,
            setupContext,
            storageKeyBytesHex,
            aeadNonceBytesHex,
        });

        expect(encrypted.encryptedLocalState).toMatchObject({
            objectType: 'EncryptedLocalTrusteeSetupState',
            objectVersion: 1,
            localStateRoot: localStateCommitment.localStateRoot,
            aeadNonceHex: aeadNonceBytesHex,
            aeadTagLength: 128,
            sealedAggregateThresholdShareReference: {
                objectType: 'LocalTrusteeSetupStateSealedMaterialReference',
                objectVersion: 1,
                materialClass: 'aggregate-threshold-share-sealed',
                materialRoot: aggregateThresholdShareRoot,
                ciphertextReference:
                    sealedAggregateThresholdShare.sealedMaterial
                        .ciphertextReference,
            },
            sealedTargetDecryptionProofWitnessReference: {
                objectType: 'LocalTrusteeSetupStateSealedMaterialReference',
                objectVersion: 1,
                materialClass: 'target-decryption-proof-witness-sealed',
                materialRoot: targetDecryptionProofWitnessRoot,
                ciphertextReference:
                    sealedTargetDecryptionProofWitness.sealedMaterial
                        .ciphertextReference,
            },
        });
        expect(encrypted.encryptedLocalState.plaintextByteLength).toBeLessThan(
            testTextEncoder.encode(canonicalJson(localStatePlaintext))
                .byteLength,
        );
        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: encrypted.encryptedLocalState,
                sealedAggregateThresholdShare:
                    localStatePlaintext.sealedAggregateThresholdShare,
                sealedTargetDecryptionProofWitness:
                    localStatePlaintext.sealedTargetDecryptionProofWitness,
                expectedLocalStateRoot: localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex,
            }),
        ).resolves.toMatchObject({
            localStatePlaintext,
            localStatePlaintextHash: encrypted.localStatePlaintextHash,
            storageAadHash: encrypted.storageAadHash,
        });
        await expect(
            decryptLocalTrusteeSetupSealedMaterial({
                sealedMaterial:
                    localStatePlaintext.sealedTargetDecryptionProofWitness,
                expectedMaterialClass: 'target-decryption-proof-witness-sealed',
                expectedMaterialRoot: targetDecryptionProofWitnessRoot,
                setupContext,
                localStateCommitment,
                storageKeyBytesHex,
            }),
        ).resolves.toMatchObject({
            materialPlaintext: {
                objectType: 'LocalTrusteeTargetDecryptionProofWitnessMaterial',
                objectVersion: 1,
                trusteeIdentity: 'trustee-3',
                trusteeRosterPosition: 3,
                thresholdShareCommitmentRecipientRoot,
                aggregateThresholdShareRoot,
            },
            materialPlaintextHash:
                sealedTargetDecryptionProofWitness.materialPlaintextHash,
            materialAadHash: sealedTargetDecryptionProofWitness.materialAadHash,
        });
        await expect(
            decryptLocalTrusteeSetupSealedMaterial({
                sealedMaterial:
                    localStatePlaintext.sealedTargetDecryptionProofWitness,
                expectedMaterialClass: 'target-decryption-proof-witness-sealed',
                expectedMaterialRoot: aggregateThresholdShareRoot,
                setupContext,
                localStateCommitment,
                storageKeyBytesHex,
            }),
        ).rejects.toThrow(/materialRoot/u);

        await expect(
            encryptLocalTrusteeState({
                localStatePlaintext: {
                    ...localStatePlaintext,
                    hiddenAggregateShareCopy: [1, 2, 3],
                },
                localStateCommitment,
                setupContext,
                storageKeyBytesHex,
                aeadNonceBytesHex,
            }),
        ).rejects.toThrow(/not allowed by the local trustee state schema/u);
        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: encrypted.encryptedLocalState,
                sealedAggregateThresholdShare:
                    localStatePlaintext.sealedAggregateThresholdShare,
                sealedTargetDecryptionProofWitness:
                    localStatePlaintext.sealedTargetDecryptionProofWitness,
                expectedLocalStateRoot: deriveProtocolHash(
                    'LocalTrusteeSetupStateRoot',
                    { trustee: 'wrong' },
                ),
                setupContext,
                storageKeyBytesHex,
            }),
        ).rejects.toThrow(/expectedLocalStateRoot/u);
        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: encrypted.encryptedLocalState,
                sealedAggregateThresholdShare:
                    localStatePlaintext.sealedAggregateThresholdShare,
                sealedTargetDecryptionProofWitness:
                    localStatePlaintext.sealedTargetDecryptionProofWitness,
                expectedLocalStateRoot: localStateCommitment.localStateRoot,
                setupContext: {
                    ...setupContext,
                    setupEpoch: 'setup-epoch-2',
                },
                storageKeyBytesHex,
            }),
        ).rejects.toThrow(/storageAad/u);

        const originalTargetCiphertext =
            localStatePlaintext.sealedTargetDecryptionProofWitness
                .encryptedMaterial.ciphertextBytesBase64;
        if (typeof originalTargetCiphertext !== 'string') {
            throw new TypeError(
                'sealed target witness ciphertext must be base64 text.',
            );
        }
        const tamperedTargetDecryptionProofWitness = {
            ...localStatePlaintext.sealedTargetDecryptionProofWitness,
            encryptedMaterial: {
                ...localStatePlaintext.sealedTargetDecryptionProofWitness
                    .encryptedMaterial,
                ciphertextBytesBase64: `${
                    originalTargetCiphertext.startsWith('A') ? 'B' : 'A'
                }${originalTargetCiphertext.slice(1)}`,
            },
        };
        await expect(
            decryptLocalTrusteeState({
                encryptedLocalState: encrypted.encryptedLocalState,
                sealedAggregateThresholdShare:
                    localStatePlaintext.sealedAggregateThresholdShare,
                sealedTargetDecryptionProofWitness:
                    tamperedTargetDecryptionProofWitness,
                expectedLocalStateRoot: localStateCommitment.localStateRoot,
                setupContext,
                storageKeyBytesHex,
            }),
        ).rejects.toThrow(/ciphertextBytesHash/u);
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
