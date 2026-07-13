import {
    canonicalJson,
    deriveCanonicalObjectHash,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createVssComplaintSet,
    createVssShareAcceptanceRecord,
    createVssShareAcceptanceSet,
    createVssShareComplaintRecord,
    createVssShareComplaintRecordFromLocalVerification,
    type PrivateVssLocalVerificationFailure,
    type PrivateVssEnvelopeVerificationReference,
    type ProtocolRootSigner,
} from '#packages/protocol/src/setup/vss-share-verification-records';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#tests/support/protocol-signature-fixtures';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const textEncoder = new TextEncoder();

const fixtureHash = makeSetupFixtureHash(
    'setup-vss-share-verification-records',
);

const setupContext = makeSetupContext(fixtureHash);

const envelopeReference = (
    sourceTrusteeRosterPosition: number,
    recipientRosterPosition: number,
): PrivateVssEnvelopeVerificationReference =>
    ({
        objectType: 'PrivateVssEnvelopeCommitment',
        ...setupContext,
        sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
        sourceTrusteeRosterPosition,
        recipientIdentity: `trustee-${String(recipientRosterPosition)}`,
        recipientRosterPosition,
        sourceTrusteeCommitmentRoot: fixtureHash(
            `source-trustee-commitment-${String(sourceTrusteeRosterPosition)}`,
        ),
        privateEnvelopeHash: fixtureHash(
            `private-envelope-${String(sourceTrusteeRosterPosition)}-${String(
                recipientRosterPosition,
            )}`,
        ),
        encryptedEnvelopeHash: fixtureHash(
            `encrypted-envelope-${String(sourceTrusteeRosterPosition)}-${String(
                recipientRosterPosition,
            )}`,
        ),
        privateEnvelopeAad: {},
        privateEnvelopeAadHash: fixtureHash(
            `private-envelope-aad-${String(sourceTrusteeRosterPosition)}-${String(
                recipientRosterPosition,
            )}`,
        ),
        encryptedEnvelope: {},
        recipientMailboxPublicKeyHash: fixtureHash(
            `recipient-mailbox-${String(recipientRosterPosition)}`,
        ),
        localVerificationRoot: fixtureHash(
            `local-verification-${String(sourceTrusteeRosterPosition)}-${String(
                recipientRosterPosition,
            )}`,
        ),
        privateEnvelopeCommitmentRoot: fixtureHash(
            `private-envelope-commitment-${String(
                sourceTrusteeRosterPosition,
            )}-${String(recipientRosterPosition)}`,
        ),
    }) as unknown as PrivateVssEnvelopeVerificationReference;

const createSigner = (
    keySeedLabel: string,
): {
    readonly publicKeyHash: string;
    readonly signRoot: ProtocolRootSigner;
} => {
    const keyFixture = createMlDsaKeyPairFixture(keySeedLabel);

    return {
        publicKeyHash: keyFixture.publicKeyHash,
        signRoot: (signedRoot) =>
            createProtocolSignatureFixture({
                profile: createMlDsaSignatureProfileFixture(),
                publicKeyBytesHex: keyFixture.publicKeyBytesHex,
                publicKeyHash: keyFixture.publicKeyHash,
                secretKeyBytesHex: keyFixture.secretKeyBytesHex,
                signedRoot,
            }),
    };
};

describe('VSS share verification record builders', () => {
    it('creates a signed acceptance record and deterministic acceptance set', async () => {
        const signer = createSigner('recipient-acceptance-1');
        const firstRecord = await createVssShareAcceptanceRecord({
            setupContext,
            privateVssEnvelopeCommitmentRoot: fixtureHash(
                'private-envelope-set',
            ),
            envelopeReference: envelopeReference(1, 0),
            recoveryEpoch: 2,
            deviceEpoch: 3,
            signingPublicKeyHash: signer.publicKeyHash,
            signRoot: signer.signRoot,
        });
        const secondRecord = await createVssShareAcceptanceRecord({
            setupContext,
            privateVssEnvelopeCommitmentRoot: fixtureHash(
                'private-envelope-set',
            ),
            envelopeReference: envelopeReference(0, 0),
            recoveryEpoch: 2,
            deviceEpoch: 3,
            signingPublicKeyHash: signer.publicKeyHash,
            signRoot: signer.signRoot,
        });

        expect(firstRecord.acceptanceByteLength).toBe(
            textEncoder.encode(
                canonicalJson({
                    objectType: 'VssShareAcceptance',
                    ceremonyId: setupContext.ceremonyId,
                    manifestHash: setupContext.manifestHash,
                    rosterHash: setupContext.rosterHash,
                    setupParametersHash: setupContext.setupParametersHash,
                    setupEpoch: setupContext.setupEpoch,
                    sourceTrusteeIdentity: 'trustee-1',
                    sourceTrusteeRosterPosition: 1,
                    recipientIdentity: 'trustee-0',
                    recipientRosterPosition: 0,
                    sourceTrusteeCommitmentRoot: fixtureHash(
                        'source-trustee-commitment-1',
                    ),
                    privateVssEnvelopeCommitmentRoot: fixtureHash(
                        'private-envelope-set',
                    ),
                    privateEnvelopeHash: fixtureHash('private-envelope-1-0'),
                    localVerificationRoot: fixtureHash(
                        'local-verification-1-0',
                    ),
                    recoveryEpoch: 2,
                    deviceEpoch: 3,
                    signingPublicKeyHash: signer.publicKeyHash,
                }),
            ).byteLength,
        );
        expect(firstRecord.signatureEnvelope.signedRoot).toMatchObject({
            objectType: 'VssShareAcceptance',
            objectRoot: firstRecord.acceptanceRoot,
            contextHash: firstRecord.acceptanceContextHash,
            signerIdentity: 'trustee-0',
        });
        expect(
            verifySignedObjectSignature(firstRecord.signatureEnvelope, {
                objectType: 'VssShareAcceptance',
                signerRole: 'Trustee',
                signerIdentity: 'trustee-0',
                ceremonyId: setupContext.ceremonyId,
                publicKeyHash: signer.publicKeyHash,
                manifestHash: setupContext.manifestHash,
                objectRoot: firstRecord.acceptanceRoot,
                chunkMerkleRoot: null,
                boardHeadHash: null,
                contextHash: firstRecord.acceptanceContextHash,
                recoveryEpoch: 2,
                deviceEpoch: 3,
            }).isValid,
        ).toBe(true);

        const acceptanceSet = createVssShareAcceptanceSet({
            setupContext,
            privateVssEnvelopeCommitmentRoot: fixtureHash(
                'private-envelope-set',
            ),
            acceptanceRecords: [firstRecord, secondRecord],
        });
        expect(
            acceptanceSet.acceptanceRecords.map(
                (record) => record.sourceTrusteeRosterPosition,
            ),
        ).toEqual([0, 1]);
        expect(acceptanceSet.vssShareAcceptanceRoot).toBe(
            deriveCanonicalObjectHash({
                objectType: 'VssShareAcceptanceSet',
                ceremonyId: setupContext.ceremonyId,
                manifestHash: setupContext.manifestHash,
                rosterHash: setupContext.rosterHash,
                setupParametersHash: setupContext.setupParametersHash,
                setupEpoch: setupContext.setupEpoch,
                privateVssEnvelopeCommitmentRoot: fixtureHash(
                    'private-envelope-set',
                ),
                acceptanceRecords: acceptanceSet.acceptanceRecords,
            }),
        );
    });

    it('rejects mixed context, duplicate acceptance pairs, and bad signature roots', async () => {
        const signer = createSigner('recipient-acceptance-2');
        const acceptedRecord = await createVssShareAcceptanceRecord({
            setupContext,
            privateVssEnvelopeCommitmentRoot: fixtureHash(
                'private-envelope-set',
            ),
            envelopeReference: envelopeReference(0, 0),
            recoveryEpoch: 0,
            deviceEpoch: 0,
            signingPublicKeyHash: signer.publicKeyHash,
            signRoot: signer.signRoot,
        });
        expect(() =>
            createVssShareAcceptanceSet({
                setupContext,
                privateVssEnvelopeCommitmentRoot: fixtureHash(
                    'private-envelope-set',
                ),
                acceptanceRecords: [acceptedRecord, acceptedRecord],
            }),
        ).toThrow(/distinct source-trustee-recipient pairs/u);
        await expect(
            createVssShareAcceptanceRecord({
                setupContext,
                privateVssEnvelopeCommitmentRoot: fixtureHash(
                    'private-envelope-set',
                ),
                envelopeReference: {
                    ...envelopeReference(0, 0),
                    rosterHash: fixtureHash('wrong-roster'),
                },
                recoveryEpoch: 0,
                deviceEpoch: 0,
                signingPublicKeyHash: signer.publicKeyHash,
                signRoot: signer.signRoot,
            }),
        ).rejects.toThrow(/must match setupContext/u);

        await expect(
            createVssShareAcceptanceRecord({
                setupContext,
                privateVssEnvelopeCommitmentRoot: fixtureHash(
                    'private-envelope-set',
                ),
                envelopeReference: envelopeReference(0, 0),
                recoveryEpoch: 0,
                deviceEpoch: 0,
                signingPublicKeyHash: signer.publicKeyHash,
                signRoot: (signedRoot) =>
                    signer.signRoot({
                        ...signedRoot,
                        objectRoot: fixtureHash('wrong-acceptance-root'),
                    }),
            }),
        ).rejects.toThrow(/signature envelope failed verification/u);
    });

    it('creates signed complaint records with the complaint root type', async () => {
        const signer = createSigner('recipient-complaint-1');
        const complaintRecord = await createVssShareComplaintRecord({
            setupContext,
            privateVssEnvelopeCommitmentRoot: fixtureHash(
                'private-envelope-set',
            ),
            envelopeReference: envelopeReference(0, 1),
            complaintEvidenceRoot: fixtureHash('complaint-evidence'),
            complaintReasonCode: 'privateVssEnvelopeInvalidOpening',
            recoveryEpoch: 4,
            deviceEpoch: 5,
            signingPublicKeyHash: signer.publicKeyHash,
            signRoot: signer.signRoot,
        });

        expect(complaintRecord.signatureEnvelope.signedRoot).toMatchObject({
            objectType: 'VssShareComplaint',
            objectRoot: complaintRecord.complaintRoot,
            contextHash: complaintRecord.complaintContextHash,
            signerIdentity: 'trustee-1',
        });
        expect(
            verifySignedObjectSignature(complaintRecord.signatureEnvelope, {
                objectType: 'VssShareComplaint',
                signerRole: 'Trustee',
                signerIdentity: 'trustee-1',
                ceremonyId: setupContext.ceremonyId,
                publicKeyHash: signer.publicKeyHash,
                manifestHash: setupContext.manifestHash,
                objectRoot: complaintRecord.complaintRoot,
                chunkMerkleRoot: null,
                boardHeadHash: null,
                contextHash: complaintRecord.complaintContextHash,
                recoveryEpoch: 4,
                deviceEpoch: 5,
            }).isValid,
        ).toBe(true);

        const complaintSet = createVssComplaintSet({
            setupContext,
            privateVssEnvelopeCommitmentRoot: fixtureHash(
                'private-envelope-set',
            ),
            complaintRecords: [complaintRecord],
        });
        expect(complaintSet.vssComplaintRoot).toBe(
            deriveCanonicalObjectHash({
                objectType: 'VssComplaintSet',
                ceremonyId: setupContext.ceremonyId,
                manifestHash: setupContext.manifestHash,
                rosterHash: setupContext.rosterHash,
                setupParametersHash: setupContext.setupParametersHash,
                setupEpoch: setupContext.setupEpoch,
                privateVssEnvelopeCommitmentRoot: fixtureHash(
                    'private-envelope-set',
                ),
                complaintRecords: [complaintRecord],
            }),
        );
        await expect(
            createVssShareComplaintRecord({
                setupContext,
                privateVssEnvelopeCommitmentRoot: fixtureHash(
                    'private-envelope-set',
                ),
                envelopeReference: envelopeReference(0, 1),
                complaintEvidenceRoot: fixtureHash('complaint-evidence'),
                complaintReasonCode: '',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                signingPublicKeyHash: signer.publicKeyHash,
                signRoot: signer.signRoot,
            }),
        ).rejects.toThrow(/complaintReasonCode must be non-empty/u);
    });

    it('creates complaint evidence from failed local private VSS verification', async () => {
        const signer = createSigner('recipient-complaint-local-failure');
        const privateVssEnvelopeCommitmentRoot = fixtureHash(
            'private-envelope-set',
        );
        const failedEnvelopeReference = envelopeReference(1, 2);
        const localVerification = {
            isValid: false,
            privateEnvelopeHash: failedEnvelopeReference.privateEnvelopeHash,
            localVerificationRoot: null,
            refusedObjects: [
                {
                    reasonCode: 'private-vss-opening-verification-failed',
                    message: 'carry-aware private VSS opening did not verify',
                    objectPath: 'privateEnvelope.rnsShareOpenings.0',
                },
            ],
        } satisfies PrivateVssLocalVerificationFailure;
        const complaintRecord =
            await createVssShareComplaintRecordFromLocalVerification({
                setupContext,
                privateVssEnvelopeCommitmentRoot,
                envelopeReference: failedEnvelopeReference,
                localVerification,
                recoveryEpoch: 0,
                deviceEpoch: 0,
                signingPublicKeyHash: signer.publicKeyHash,
                signRoot: signer.signRoot,
            });

        expect(complaintRecord.complaintReasonCode).toBe(
            'private-vss-opening-verification-failed',
        );
        expect(complaintRecord.complaintEvidenceRoot).toBe(
            deriveCanonicalObjectHash({
                objectType: 'VssShareComplaintEvidence',
                ceremonyId: setupContext.ceremonyId,
                manifestHash: setupContext.manifestHash,
                rosterHash: setupContext.rosterHash,
                setupParametersHash: setupContext.setupParametersHash,
                setupEpoch: setupContext.setupEpoch,
                sourceTrusteeIdentity:
                    failedEnvelopeReference.sourceTrusteeIdentity,
                sourceTrusteeRosterPosition:
                    failedEnvelopeReference.sourceTrusteeRosterPosition,
                recipientIdentity: failedEnvelopeReference.recipientIdentity,
                recipientRosterPosition:
                    failedEnvelopeReference.recipientRosterPosition,
                sourceTrusteeCommitmentRoot:
                    failedEnvelopeReference.sourceTrusteeCommitmentRoot,
                privateVssEnvelopeCommitmentRoot,
                privateEnvelopeHash:
                    failedEnvelopeReference.privateEnvelopeHash,
                privateEnvelopeHashFromLocalVerification:
                    failedEnvelopeReference.privateEnvelopeHash,
                localVerificationRoot: null,
                refusedObjects: localVerification.refusedObjects,
            }),
        );

        await expect(
            createVssShareComplaintRecordFromLocalVerification({
                setupContext,
                privateVssEnvelopeCommitmentRoot,
                envelopeReference: failedEnvelopeReference,
                localVerification: {
                    ...localVerification,
                    refusedObjects: [],
                },
                recoveryEpoch: 0,
                deviceEpoch: 0,
                signingPublicKeyHash: signer.publicKeyHash,
                signRoot: signer.signRoot,
            }),
        ).rejects.toThrow(/refusedObjects/u);
        await expect(
            createVssShareComplaintRecordFromLocalVerification({
                setupContext,
                privateVssEnvelopeCommitmentRoot,
                envelopeReference: failedEnvelopeReference,
                localVerification: {
                    ...localVerification,
                    privateEnvelopeHash: fixtureHash('wrong-private-envelope'),
                },
                recoveryEpoch: 0,
                deviceEpoch: 0,
                signingPublicKeyHash: signer.publicKeyHash,
                signRoot: signer.signRoot,
            }),
        ).rejects.toThrow(/privateEnvelopeHash/u);
    });
});
