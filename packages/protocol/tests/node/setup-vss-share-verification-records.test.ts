import {
    deriveCanonicalObjectHash,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createMlDsaKeyPairFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import {
    createVssShareAcceptanceRecord,
    createVssShareAcceptanceSet,
    createVssShareComplaintRecord,
    createVssShareComplaintRecordFromLocalVerification,
    type PrivateVssLocalVerificationFailure,
    type PrivateVssEnvelopeVerificationReference,
    type ProtocolRootSigner,
} from '#packages/protocol/src/setup/vss-share-verification-records';
import {
    makeSetupContext,
    makeSetupFixtureHash,
} from '#tests/support/setup-fixtures';

const fixtureHash = makeSetupFixtureHash(
    'setup-vss-share-verification-records',
);
const setupContext = makeSetupContext(fixtureHash);
const privateVssEnvelopeCommitmentRoot = fixtureHash('private-envelope-set');

const envelopeReference = (
    sourceTrusteeRosterPosition: number,
    recipientRosterPosition: number,
): PrivateVssEnvelopeVerificationReference => {
    const sourceTrusteeIdentity = `trustee-${String(sourceTrusteeRosterPosition)}`;
    const recipientIdentity = `trustee-${String(recipientRosterPosition)}`;
    const trusteePairLabel = `${String(sourceTrusteeRosterPosition)}-${String(
        recipientRosterPosition,
    )}`;

    return {
        objectType: 'PrivateVssEnvelopeCommitment',
        ...setupContext,
        sourceTrusteeIdentity,
        sourceTrusteeRosterPosition,
        recipientIdentity,
        recipientRosterPosition,
        sourceTrusteeCommitmentRoot: fixtureHash(
            `source-trustee-commitment-${String(sourceTrusteeRosterPosition)}`,
        ),
        privateEnvelopeHash: fixtureHash(
            `private-envelope-${trusteePairLabel}`,
        ),
        encryptedEnvelopeHash: fixtureHash(
            `encrypted-envelope-${trusteePairLabel}`,
        ),
        privateEnvelopeAad: {},
        privateEnvelopeAadHash: fixtureHash(
            `private-envelope-aad-${trusteePairLabel}`,
        ),
        encryptedEnvelope: {},
        recipientMailboxPublicKeyHash: fixtureHash(
            `recipient-mailbox-${String(recipientRosterPosition)}`,
        ),
        localVerificationRoot: fixtureHash(
            `local-verification-${trusteePairLabel}`,
        ),
        privateEnvelopeCommitmentRoot: fixtureHash(
            `private-envelope-commitment-${trusteePairLabel}`,
        ),
    } as unknown as PrivateVssEnvelopeVerificationReference;
};

type FixtureSigner = Readonly<{
    publicKeyHash: string;
    signRoot: ProtocolRootSigner;
}>;

const createSigner = (keySeedLabel: string): FixtureSigner => {
    const keyFixture = createMlDsaKeyPairFixture(keySeedLabel);

    return {
        publicKeyHash: keyFixture.publicKeyHash,
        signRoot: (signedRoot) =>
            createProtocolSignatureFixture({
                publicKeyBytesHex: keyFixture.publicKeyBytesHex,
                publicKeyHash: keyFixture.publicKeyHash,
                secretKeyBytesHex: keyFixture.secretKeyBytesHex,
                signedRoot,
            }),
    };
};

type AcceptanceRecordInput = Parameters<
    typeof createVssShareAcceptanceRecord
>[0];
type ComplaintRecordInput = Parameters<typeof createVssShareComplaintRecord>[0];
type LocalComplaintRecordInput = Parameters<
    typeof createVssShareComplaintRecordFromLocalVerification
>[0];
type VerificationRecord =
    | Awaited<ReturnType<typeof createVssShareAcceptanceRecord>>
    | Awaited<ReturnType<typeof createVssShareComplaintRecord>>;

const acceptanceRecordInput = (
    signer: FixtureSigner,
    sourceTrusteeRosterPosition = 0,
    recipientRosterPosition = 0,
    recoveryEpoch = 0,
    deviceEpoch = 0,
): AcceptanceRecordInput => ({
    setupContext,
    privateVssEnvelopeCommitmentRoot,
    envelopeReference: envelopeReference(
        sourceTrusteeRosterPosition,
        recipientRosterPosition,
    ),
    recoveryEpoch,
    deviceEpoch,
    signingPublicKeyHash: signer.publicKeyHash,
    signRoot: signer.signRoot,
});

const complaintRecordInput = (
    signer: FixtureSigner,
    sourceTrusteeRosterPosition = 0,
    recipientRosterPosition = 1,
    recoveryEpoch = 0,
    deviceEpoch = 0,
): ComplaintRecordInput => ({
    ...acceptanceRecordInput(
        signer,
        sourceTrusteeRosterPosition,
        recipientRosterPosition,
        recoveryEpoch,
        deviceEpoch,
    ),
    complaintEvidenceRoot: fixtureHash('complaint-evidence'),
    complaintReasonCode: 'privateVssEnvelopeInvalidOpening',
});

const localVerificationFailure = (
    reference: PrivateVssEnvelopeVerificationReference,
): PrivateVssLocalVerificationFailure => ({
    isValid: false,
    privateEnvelopeHash: reference.privateEnvelopeHash,
    localVerificationRoot: null,
    refusedObjects: [
        {
            reasonCode: 'private-vss-opening-verification-failed',
            message: 'carry-aware private VSS opening did not verify',
            objectPath: 'privateEnvelope.rnsShareOpenings.0',
        },
    ],
});

const localComplaintRecordInput = (
    signer: FixtureSigner,
): LocalComplaintRecordInput => {
    const sharedInput = acceptanceRecordInput(signer, 1, 2);

    return {
        ...sharedInput,
        localVerification: localVerificationFailure(
            sharedInput.envelopeReference,
        ),
    };
};

const signatureContextFields = (record: VerificationRecord) => ({
    ceremonyId: record.ceremonyId,
    manifestHash: record.manifestHash,
    rosterHash: record.rosterHash,
    setupParametersHash: record.setupParametersHash,
    setupEpoch: record.setupEpoch,
    sourceTrusteeIdentity: record.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition: record.sourceTrusteeRosterPosition,
    recipientIdentity: record.recipientIdentity,
    recipientRosterPosition: record.recipientRosterPosition,
    sourceTrusteeCommitmentRoot: record.sourceTrusteeCommitmentRoot,
    privateVssEnvelopeCommitmentRoot: record.privateVssEnvelopeCommitmentRoot,
    privateEnvelopeHash: record.privateEnvelopeHash,
});

const expectValidTrusteeSignature = (
    record: VerificationRecord,
    signer: FixtureSigner,
    contextHash: string,
): void => {
    const objectRoot =
        record.objectType === 'VssShareAcceptance'
            ? record.acceptanceRoot
            : record.complaintRoot;
    expect(
        verifySignedObjectSignature(record.signatureEnvelope, {
            objectType: record.objectType,
            signerRole: 'Trustee',
            signerIdentity: record.recipientIdentity,
            ceremonyId: record.ceremonyId,
            publicKeyHash: signer.publicKeyHash,
            manifestHash: record.manifestHash,
            objectRoot,
            chunkMerkleRoot: null,
            boardHeadHash: null,
            contextHash,
            recoveryEpoch: record.recoveryEpoch,
            deviceEpoch: record.deviceEpoch,
        }).isValid,
    ).toBe(true);
};

type AsyncRejectionCase = Readonly<{
    label: string;
    expectedMessage: RegExp;
    run: (signer: FixtureSigner) => Promise<unknown>;
}>;

const rejectionCases = [
    {
        label: 'an envelope with a mismatched setup context',
        expectedMessage: /must match setupContext/u,
        run: (signer) => {
            const input = acceptanceRecordInput(signer);
            return createVssShareAcceptanceRecord({
                ...input,
                envelopeReference: {
                    ...input.envelopeReference,
                    rosterHash: fixtureHash('wrong-roster'),
                },
            });
        },
    },
    {
        label: 'an acceptance signature forged over the wrong root',
        expectedMessage: /signature envelope failed verification/u,
        run: (signer) =>
            createVssShareAcceptanceRecord({
                ...acceptanceRecordInput(signer),
                signRoot: (signedRoot) =>
                    signer.signRoot({
                        ...signedRoot,
                        objectRoot: fixtureHash('wrong-acceptance-root'),
                    }),
            }),
    },
    {
        label: 'an empty complaint reason code',
        expectedMessage: /complaintReasonCode must be non-empty/u,
        run: (signer) =>
            createVssShareComplaintRecord({
                ...complaintRecordInput(signer),
                complaintReasonCode: '',
            }),
    },
    {
        label: 'local verification without a refusal',
        expectedMessage: /refusedObjects/u,
        run: (signer) => {
            const input = localComplaintRecordInput(signer);
            return createVssShareComplaintRecordFromLocalVerification({
                ...input,
                localVerification: {
                    ...input.localVerification,
                    refusedObjects: [],
                },
            });
        },
    },
    {
        label: 'a mismatched locally verified private-envelope hash',
        expectedMessage: /privateEnvelopeHash/u,
        run: (signer) => {
            const input = localComplaintRecordInput(signer);
            return createVssShareComplaintRecordFromLocalVerification({
                ...input,
                localVerification: {
                    ...input.localVerification,
                    privateEnvelopeHash: fixtureHash('wrong-private-envelope'),
                },
            });
        },
    },
] as const satisfies readonly AsyncRejectionCase[];

describe('VSS share verification record builders', () => {
    it('creates a signed acceptance record and deterministic acceptance set', async () => {
        const signer = createSigner('recipient-acceptance-positive');
        const firstRecord = await createVssShareAcceptanceRecord(
            acceptanceRecordInput(signer, 1, 0, 2, 3),
        );
        const secondRecord = await createVssShareAcceptanceRecord(
            acceptanceRecordInput(signer, 0, 0, 2, 3),
        );
        const expectedContextHash = deriveCanonicalObjectHash({
            objectType: 'VssShareAcceptanceSignatureContext',
            ...signatureContextFields(firstRecord),
            localVerificationRoot: firstRecord.localVerificationRoot,
            acceptanceRoot: firstRecord.acceptanceRoot,
        });

        expectValidTrusteeSignature(firstRecord, signer, expectedContextHash);

        const acceptanceSet = createVssShareAcceptanceSet({
            acceptanceRecords: [firstRecord, secondRecord],
        });
        expect(
            acceptanceSet.acceptanceRecords.map(
                (record) => record.sourceTrusteeRosterPosition,
            ),
        ).toEqual([0, 1]);
    });

    it('rejects duplicate acceptance pairs', async () => {
        const signer = createSigner('recipient-acceptance-duplicate');
        const acceptedRecord = await createVssShareAcceptanceRecord(
            acceptanceRecordInput(signer),
        );

        expect(() =>
            createVssShareAcceptanceSet({
                acceptanceRecords: [acceptedRecord, acceptedRecord],
            }),
        ).toThrow(/distinct source-trustee-recipient pairs/u);
    });

    it('creates signed complaint records with the complaint root type', async () => {
        const signer = createSigner('recipient-complaint-positive');
        const complaintRecord = await createVssShareComplaintRecord(
            complaintRecordInput(signer, 0, 1, 4, 5),
        );
        const expectedContextHash = deriveCanonicalObjectHash({
            objectType: 'VssShareComplaintSignatureContext',
            ...signatureContextFields(complaintRecord),
            complaintEvidenceRoot: complaintRecord.complaintEvidenceRoot,
            complaintReasonCode: complaintRecord.complaintReasonCode,
            complaintRoot: complaintRecord.complaintRoot,
        });

        expectValidTrusteeSignature(
            complaintRecord,
            signer,
            expectedContextHash,
        );
    });

    it('creates complaint evidence from failed local private VSS verification', async () => {
        const signer = createSigner('recipient-complaint-local-failure');
        const input = localComplaintRecordInput(signer);
        const complaintRecord =
            await createVssShareComplaintRecordFromLocalVerification(input);

        expect(complaintRecord.complaintReasonCode).toBe(
            'private-vss-opening-verification-failed',
        );
        expect(complaintRecord.complaintEvidenceRoot).toBe(
            deriveCanonicalObjectHash({
                objectType: 'VssShareComplaintEvidence',
                ...signatureContextFields(complaintRecord),
                privateEnvelopeHashFromLocalVerification:
                    input.localVerification.privateEnvelopeHash,
                localVerificationRoot:
                    input.localVerification.localVerificationRoot,
                refusedObjects: input.localVerification.refusedObjects,
            }),
        );
    });

    it.each(rejectionCases)(
        'rejects $label',
        async ({ label, expectedMessage, run }) => {
            const signer = createSigner(
                `vss-share-verification-rejection-${label}`,
            );
            await expect(run(signer)).rejects.toThrow(expectedMessage);
        },
    );
});
