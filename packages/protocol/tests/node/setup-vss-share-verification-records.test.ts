import {
    deriveCanonicalObjectHash,
    verifySignedObjectSignature,
} from '@sealed-lattice/crypto';
import { describe, expect, it } from 'vitest';

import {
    createMlDsaKeyPairFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import { deriveCollectiveBgvSetupContextHash } from '#packages/protocol/src/setup/common-fields';
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
const setupContext = makeSetupContext(fixtureHash, 2);
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
        localVerificationRoot: fixtureHash(
            `local-verification-${trusteePairLabel}`,
        ),
    } satisfies PrivateVssEnvelopeVerificationReference;
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

const shareVerificationPayloadFields = (input: AcceptanceRecordInput) => ({
    setupContextHash: deriveCollectiveBgvSetupContextHash(input.setupContext),
    sourceTrusteeIdentity: input.envelopeReference.sourceTrusteeIdentity,
    sourceTrusteeRosterPosition:
        input.envelopeReference.sourceTrusteeRosterPosition,
    recipientIdentity: input.envelopeReference.recipientIdentity,
    recipientRosterPosition: input.envelopeReference.recipientRosterPosition,
    sourceTrusteeCommitmentRoot:
        input.envelopeReference.sourceTrusteeCommitmentRoot,
    privateVssEnvelopeCommitmentRoot: input.privateVssEnvelopeCommitmentRoot,
    privateEnvelopeHash: input.envelopeReference.privateEnvelopeHash,
});

const expectValidTrusteeSignature = (
    record: VerificationRecord,
    signer: FixtureSigner,
    expectedObjectRoot: string,
    expectedRecipientIdentity: string,
    recoveryEpoch: number,
    deviceEpoch: number,
): void => {
    const contextHash = deriveCanonicalObjectHash({
        objectType: `${record.objectType}SignatureContext`,
        payloadRoot: expectedObjectRoot,
    });
    expect(record.signatureEnvelope.signedRoot.objectRoot).toBe(
        expectedObjectRoot,
    );
    expect(
        verifySignedObjectSignature(record.signatureEnvelope, {
            objectType: record.objectType,
            signerRole: 'Trustee',
            signerIdentity: expectedRecipientIdentity,
            ceremonyId: setupContext.ceremonyId,
            publicKeyHash: signer.publicKeyHash,
            manifestHash: setupContext.manifestHash,
            objectRoot: expectedObjectRoot,
            contextHash,
            recoveryEpoch,
            deviceEpoch,
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
        label: 'a negative recovery epoch',
        expectedMessage: /recoveryEpoch must be a non-negative safe integer/u,
        run: (signer) =>
            createVssShareAcceptanceRecord({
                ...acceptanceRecordInput(signer),
                recoveryEpoch: -1,
            }),
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
        const firstInput = acceptanceRecordInput(signer, 1, 0, 2, 3);
        const firstRecord = await createVssShareAcceptanceRecord(firstInput);
        const secondRecord = await createVssShareAcceptanceRecord(
            acceptanceRecordInput(signer, 0, 0, 2, 3),
        );
        const expectedAcceptanceRoot = deriveCanonicalObjectHash({
            objectType: 'VssShareAcceptance',
            ...shareVerificationPayloadFields(firstInput),
            localVerificationRoot:
                firstInput.envelopeReference.localVerificationRoot,
            recoveryEpoch: firstInput.recoveryEpoch,
            deviceEpoch: firstInput.deviceEpoch,
        });

        expectValidTrusteeSignature(
            firstRecord,
            signer,
            expectedAcceptanceRoot,
            firstInput.envelopeReference.recipientIdentity,
            firstInput.recoveryEpoch,
            firstInput.deviceEpoch,
        );

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
        const input = complaintRecordInput(signer, 0, 1, 4, 5);
        const complaintRecord = await createVssShareComplaintRecord(input);
        const expectedComplaintRoot = deriveCanonicalObjectHash({
            objectType: 'VssShareComplaint',
            ...shareVerificationPayloadFields(input),
            complaintEvidenceRoot: input.complaintEvidenceRoot,
            complaintReasonCode: input.complaintReasonCode,
            recoveryEpoch: input.recoveryEpoch,
            deviceEpoch: input.deviceEpoch,
        });

        expectValidTrusteeSignature(
            complaintRecord,
            signer,
            expectedComplaintRoot,
            input.envelopeReference.recipientIdentity,
            input.recoveryEpoch,
            input.deviceEpoch,
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
                ...shareVerificationPayloadFields(input),
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
