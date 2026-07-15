import { deriveCanonicalObjectHash } from '@sealed-lattice/crypto';
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
    const trusteePairLabel = `${String(sourceTrusteeRosterPosition)}-${String(
        recipientRosterPosition,
    )}`;

    return {
        objectType: 'PrivateVssEnvelopeCommitment',
        sourceTrusteeRosterPosition,
        recipientRosterPosition,
        privateEnvelopeHash: fixtureHash(
            `private-envelope-${trusteePairLabel}`,
        ),
        encryptedEnvelopeHash: fixtureHash(
            `encrypted-envelope-${trusteePairLabel}`,
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
type VerificationRecord =
    | Awaited<ReturnType<typeof createVssShareAcceptanceRecord>>
    | Awaited<ReturnType<typeof createVssShareComplaintRecord>>;

const setupIntent = (
    recipientRosterPosition: number,
    recoveryEpoch: number,
    deviceEpoch: number,
): AcceptanceRecordInput['setupIntent'] => ({
    objectType: 'CollectiveBgvSetupIntent',
    trusteeRegistrations: [0, 1].map((rosterPosition) => ({
        objectType: 'CollectiveBgvSetupIntentTrusteeRegistration' as const,
        trusteeIdentity: `trustee-${String(rosterPosition)}`,
        recoveryEpoch:
            rosterPosition === recipientRosterPosition ? recoveryEpoch : 0,
        deviceEpoch:
            rosterPosition === recipientRosterPosition ? deviceEpoch : 0,
        privateVssMailboxPublicKeyHash: fixtureHash(
            `mailbox-key-${String(rosterPosition)}`,
        ),
        signatureEnvelope: {
            publicKeyHash: fixtureHash(
                `registration-key-${String(rosterPosition)}`,
            ),
            publicKeyBytesHex: '',
            signedRoot: {
                objectType:
                    'CollectiveBgvSetupIntentTrusteeRegistration' as const,
                objectRoot: fixtureHash(
                    `registration-root-${String(rosterPosition)}`,
                ),
            },
            signatureBytesHex: '',
        },
    })),
});

const vssPublicCoefficientCommitmentSet =
    (): AcceptanceRecordInput['vssPublicCoefficientCommitmentSet'] => ({
        objectType: 'VssPublicCoefficientCommitmentSet',
        publicMatrixSeedHash: fixtureHash('public-matrix-seed'),
        sourceTrusteeRecords: [0, 1].map(() => ({
            objectType: 'VssPublicSourceCoefficientCommitments' as const,
            coefficientCommitments: [],
        })),
    });

const acceptanceRecordInput = (
    signer: FixtureSigner,
    sourceTrusteeRosterPosition = 0,
    recipientRosterPosition = 0,
    recoveryEpoch = 0,
    deviceEpoch = 0,
): AcceptanceRecordInput => ({
    setupContext,
    setupIntent: setupIntent(
        recipientRosterPosition,
        recoveryEpoch,
        deviceEpoch,
    ),
    vssPublicCoefficientCommitmentSet: vssPublicCoefficientCommitmentSet(),
    privateVssEnvelopeCommitmentRoot,
    envelopeReference: envelopeReference(
        sourceTrusteeRosterPosition,
        recipientRosterPosition,
    ),
    signRoot: signer.signRoot,
});

const shareVerificationPayloadFields = (input: AcceptanceRecordInput) => {
    const sourceRegistration =
        input.setupIntent.trusteeRegistrations[
            input.envelopeReference.sourceTrusteeRosterPosition
        ];
    const recipientRegistration =
        input.setupIntent.trusteeRegistrations[
            input.envelopeReference.recipientRosterPosition
        ];
    if (
        sourceRegistration === undefined ||
        recipientRegistration === undefined
    ) {
        throw new Error('The fixture must contain both trustee registrations.');
    }

    return {
        setupContextHash: deriveCollectiveBgvSetupContextHash(
            input.setupContext,
        ),
        sourceTrusteeIdentity: sourceRegistration.trusteeIdentity,
        sourceTrusteeRosterPosition:
            input.envelopeReference.sourceTrusteeRosterPosition,
        recipientIdentity: recipientRegistration.trusteeIdentity,
        recipientRosterPosition:
            input.envelopeReference.recipientRosterPosition,
        sourceTrusteeCommitmentRoot: deriveCanonicalObjectHash({
            ...input.vssPublicCoefficientCommitmentSet.sourceTrusteeRecords[
                input.envelopeReference.sourceTrusteeRosterPosition
            ],
            sourceTrusteeIdentity: sourceRegistration.trusteeIdentity,
        }),
        privateVssEnvelopeCommitmentRoot:
            input.privateVssEnvelopeCommitmentRoot,
        privateEnvelopeHash: input.envelopeReference.privateEnvelopeHash,
        recoveryEpoch: recipientRegistration.recoveryEpoch,
        deviceEpoch: recipientRegistration.deviceEpoch,
    };
};

const expectReturnedTrusteeSignature = (
    record: VerificationRecord,
    signer: FixtureSigner,
    expectedObjectRoot: string,
): void => {
    expect(record.signatureEnvelope).toMatchObject({
        publicKeyHash: signer.publicKeyHash,
        signedRoot: {
            objectType: record.objectType,
            objectRoot: expectedObjectRoot,
        },
    });
};

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
        });

        expectReturnedTrusteeSignature(
            firstRecord,
            signer,
            expectedAcceptanceRoot,
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

    it('creates a recipient-signed complaint bound to the share context', async () => {
        const signer = createSigner('recipient-complaint-positive');
        const input = acceptanceRecordInput(signer, 0, 1, 4, 5);
        const complaintRecord = await createVssShareComplaintRecord(input);
        const expectedComplaintRoot = deriveCanonicalObjectHash({
            objectType: 'VssShareComplaint',
            ...shareVerificationPayloadFields(input),
        });

        expectReturnedTrusteeSignature(
            complaintRecord,
            signer,
            expectedComplaintRoot,
        );
    });

    it('rejects a negative recovery epoch before signing', async () => {
        const signer = createSigner('negative-recovery-epoch');
        await expect(
            createVssShareAcceptanceRecord({
                ...acceptanceRecordInput(signer, 0, 0, -1),
            }),
        ).rejects.toThrow(
            /recipientRegistration.recoveryEpoch must be a non-negative safe integer/u,
        );
    });
});
