import { expect } from 'vitest';

import {
    firstProfileParticipantCount,
    minimumSuccinctProofFixtureRingDegree,
    privateVssMailboxKeyPairForRosterPosition,
    setupTrusteeSignatureSeedLabel,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import { privateVssMailboxEncryptionProfileId } from '#packages/crypto/src/index';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import {
    createPrivateVssMailboxDeliverySetFromReferences,
    createPrivateVssMailboxSourceTrusteeDeliveryReferences,
    type PrivateVssEnvelopeCommitment,
    type PrivateVssMailboxDeliverySetInput,
} from '#packages/protocol/src/setup/private-vss-mailbox-delivery';
import { type VssSourceTrusteeOpeningMaterial } from '#packages/protocol/src/setup/vss-coefficient-commitments';
import {
    createVssComplaintSet,
    createVssShareAcceptanceRecord,
    createVssShareAcceptanceSet,
    createVssShareComplaintRecordFromLocalVerification,
    type CollectiveBgvSetupContext,
    type PrivateVssLocalVerificationFailure,
    type PrivateVssEnvelopeVerificationReference,
    type ProtocolRootSigner,
    type VssShareAcceptanceRecord,
    type VssShareComplaintRecord,
} from '#packages/protocol/src/setup/vss-share-verification-records';
import type {
    BgvCollectiveSetupProfileDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';

function collectForbiddenPrivateVssDeliveryFieldPaths(
    value: unknown,
    objectPath = 'privateVssEnvelopeCommitments',
): string[] {
    const forbiddenFieldNames = new Set([
        'privateEnvelope',
        'coefficientMessage',
        'randomnessByColumn',
        'shareValues',
        'aggregateOpening',
        'aggregateOpeningColumns',
        'carryWitnessesDecimal',
    ]);
    if (Array.isArray(value)) {
        return value.flatMap((item, itemIndex) =>
            collectForbiddenPrivateVssDeliveryFieldPaths(
                item,
                `${objectPath}.${String(itemIndex)}`,
            ),
        );
    }
    if (typeof value !== 'object' || value === null) {
        return [];
    }

    return Object.entries(value).flatMap(([fieldName, fieldValue]) => {
        const fieldPath = `${objectPath}.${fieldName}`;
        if (forbiddenFieldNames.has(fieldName)) {
            return [fieldPath];
        }

        return collectForbiddenPrivateVssDeliveryFieldPaths(
            fieldValue,
            fieldPath,
        );
    });
}

function collectiveSetupPhaseOrderHash(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): string {
    return kernel.deriveProtocolHash({
        namespace: 'CollectiveBgvSetupPhaseOrderHash',
        value: profile.phaseOrder.map(
            (phase: {
                readonly phaseId: string;
                readonly phaseNumber: number;
            }) => ({
                phaseId: phase.phaseId,
                phaseNumber: phase.phaseNumber,
            }),
        ),
    });
}

function privateVssSourceTrusteeContributionState(
    sourceTrusteeOpeningMaterial: VssSourceTrusteeOpeningMaterial,
    sourceTrusteeRecords: readonly JsonRecord[],
): PrivateVssMailboxDeliverySetInput['sourceTrusteeContributionStates'][number] {
    const sourceTrusteeRecord =
        sourceTrusteeRecords[
            sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition
        ];
    if (sourceTrusteeRecord === undefined) {
        throw new Error(
            'Missing VSS coefficient commitment source trustee record.',
        );
    }

    return {
        sourceTrusteeIdentity: `trustee-${String(
            sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition,
        )}`,
        sourceTrusteeRosterPosition:
            sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition,
        sourceTrusteeCommitmentRoot: String(
            sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
        ),
        sourceTrusteeCoefficientCommitmentRecord: sourceTrusteeRecord,
        sourceTrusteeCoefficientCommitmentMaterialRecords:
            sourceTrusteeOpeningMaterial.sourceTrusteeCoefficientCommitmentMaterialRecords,
        coefficientOpenings: sourceTrusteeOpeningMaterial.coefficientOpenings,
    };
}

function packageShapePrivateVssEnvelopeAad(input: {
    readonly setupContext: JsonRecord;
    readonly phaseOrderHash: string;
    readonly publicMatrixSeedHash: string;
    readonly vssCoefficientCommitmentRoot: string;
    readonly sourceTrusteeIdentity: string;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientIdentity: string;
    readonly recipientRosterPosition: number;
    readonly sourceTrusteeCommitmentRoot: string;
    readonly envelopeSequenceNumber: number;
}): JsonRecord {
    return {
        objectType: 'PrivateVssEnvelopeAad',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        mailboxEncryptionProfileId: privateVssMailboxEncryptionProfileId,
        privateEnvelopeObjectType: 'PrivateVssShareEnvelope',
        ciphertextContentType: 'private-vss-share-envelope',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        phaseOrderHash: input.phaseOrderHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        sourceTrusteeIdentity: input.sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        recipientIdentity: input.recipientIdentity,
        recipientRosterPosition: input.recipientRosterPosition,
        sourceTrusteeCommitmentRoot: input.sourceTrusteeCommitmentRoot,
        envelopeSequenceNumber: input.envelopeSequenceNumber,
        deliveryPhaseNumber: 6,
        verificationPhaseNumber: 7,
    };
}

function packageShapePrivateVssEnvelopeReference(input: {
    readonly kernel: TranscriptCoreKernel;
    readonly setupContext: JsonRecord;
    readonly phaseOrderHash: string;
    readonly publicMatrixSeedHash: string;
    readonly vssCoefficientCommitmentRoot: string;
    readonly sourceTrusteeRecord: JsonRecord;
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
}): PrivateVssEnvelopeCommitment {
    const sourceTrusteeIdentity = `trustee-${String(
        input.sourceTrusteeRosterPosition,
    )}`;
    const recipientIdentity = `trustee-${String(input.recipientRosterPosition)}`;
    const recipientMailboxKeyPair = privateVssMailboxKeyPairForRosterPosition(
        input.recipientRosterPosition,
    );
    const sourceTrusteeCommitmentRoot = String(
        input.sourceTrusteeRecord.sourceTrusteeCommitmentRoot,
    );
    const envelopeSequenceNumber =
        input.sourceTrusteeRosterPosition * firstProfileParticipantCount +
        input.recipientRosterPosition;
    const privateEnvelopeAad = packageShapePrivateVssEnvelopeAad({
        setupContext: input.setupContext,
        phaseOrderHash: input.phaseOrderHash,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        recipientIdentity,
        recipientRosterPosition: input.recipientRosterPosition,
        sourceTrusteeCommitmentRoot,
        envelopeSequenceNumber,
    });
    const privateEnvelopeAadHash = input.kernel.deriveProtocolHash({
        namespace: 'PrivateVssEnvelopeAadHash',
        value: privateEnvelopeAad,
    });
    const privateEnvelopeHash = input.kernel.deriveProtocolHash({
        namespace: 'PrivateVssShareEnvelopeHash',
        value: {
            fixture: 'package-shape-private-vss-envelope-reference',
            sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
            recipientRosterPosition: input.recipientRosterPosition,
        },
    });
    const encryptedEnvelopeHash = input.kernel.deriveProtocolHash({
        namespace: 'PrivateVssEncryptedEnvelopeHash',
        value: {
            fixture: 'package-shape-private-vss-envelope-reference',
            sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
            recipientRosterPosition: input.recipientRosterPosition,
            privateEnvelopeHash,
            privateEnvelopeAadHash,
        },
    });
    const localVerificationRoot = input.kernel.deriveProtocolHash({
        namespace: 'PrivateVssLocalVerificationRoot',
        value: {
            fixture: 'package-shape-private-vss-envelope-reference',
            sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
            recipientRosterPosition: input.recipientRosterPosition,
            privateEnvelopeHash,
        },
    });
    const referenceWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitment',
        objectVersion: 1,
        mailboxEncryptionProfileId: privateVssMailboxEncryptionProfileId,
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupProfileHash: input.setupContext.setupProfileHash,
        qShareHash: input.setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            input.setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: input.setupContext.commitmentProfileHash,
        setupEpoch: input.setupContext.setupEpoch,
        publicMatrixSeedHash: input.publicMatrixSeedHash,
        vssCoefficientCommitmentRoot: input.vssCoefficientCommitmentRoot,
        sourceTrusteeIdentity,
        sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
        recipientIdentity,
        recipientRosterPosition: input.recipientRosterPosition,
        sourceTrusteeCommitmentRoot,
        envelopeSequenceNumber,
        deliveryPhaseNumber: 6,
        verificationPhaseNumber: 7,
        privateEnvelopeHash,
        encryptedEnvelopeHash,
        privateEnvelopeAad,
        privateEnvelopeAadHash,
        recipientMailboxPublicKeyHash: recipientMailboxKeyPair.publicKeyHash,
        localVerificationRoot,
    } as const satisfies Omit<
        PrivateVssEnvelopeCommitment,
        'privateEnvelopeCommitmentRoot'
    >;

    return {
        ...referenceWithoutRoot,
        privateEnvelopeCommitmentRoot: input.kernel.deriveProtocolHash({
            namespace: 'PrivateVssEnvelopeCommitmentRoot',
            value: referenceWithoutRoot,
        }),
    } as const satisfies PrivateVssEnvelopeCommitment;
}

export function packageShapePrivateVssEnvelopeCommitments(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
    setupContext: JsonRecord,
    commonRandomness: JsonRecord,
    vssCoefficientCommitments: JsonRecord,
): JsonRecord {
    const sourceTrusteeRecords =
        vssCoefficientCommitments.sourceTrusteeRecords as JsonRecord[];
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const vssCoefficientCommitmentRoot = String(
        vssCoefficientCommitments.vssCoefficientCommitmentRoot,
    );
    const phaseOrderHash = collectiveSetupPhaseOrderHash(kernel, profile);
    const envelopeReferences = sourceTrusteeRecords.flatMap(
        (sourceTrusteeRecord, sourceTrusteeRosterPosition) =>
            Array.from(
                { length: firstProfileParticipantCount },
                (_unusedRecipient, recipientRosterPosition) =>
                    packageShapePrivateVssEnvelopeReference({
                        kernel,
                        setupContext,
                        phaseOrderHash,
                        publicMatrixSeedHash,
                        vssCoefficientCommitmentRoot,
                        sourceTrusteeRecord,
                        sourceTrusteeRosterPosition,
                        recipientRosterPosition,
                    }),
            ),
    );

    const privateVssEnvelopeCommitmentSet =
        createPrivateVssMailboxDeliverySetFromReferences({
            kernel: {
                deriveProtocolHash: (input) => kernel.deriveProtocolHash(input),
                verifyPrivateVssShareEnvelope: (input) =>
                    kernel.verifyPrivateVssShareEnvelope(input),
            },
            setupContext:
                setupContext as PrivateVssMailboxDeliverySetInput['setupContext'],
            publicMatrixSeedHash,
            vssCoefficientCommitmentRoot,
            participantCount: firstProfileParticipantCount,
            deliveryPhaseNumber: 6,
            verificationPhaseNumber: 7,
            envelopeReferences,
        });

    expect(
        collectForbiddenPrivateVssDeliveryFieldPaths(
            privateVssEnvelopeCommitmentSet,
        ),
    ).toEqual([]);

    return privateVssEnvelopeCommitmentSet;
}

export async function focusedPrivateVssSourceDeliveryReferences(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
    setupContext: JsonRecord,
    commonRandomness: JsonRecord,
    vssCoefficientCommitments: JsonRecord,
    privateOpeningMaterialBySourceTrustee: readonly VssSourceTrusteeOpeningMaterial[],
): Promise<readonly JsonRecord[]> {
    const sourceTrusteeRecords =
        vssCoefficientCommitments.sourceTrusteeRecords as JsonRecord[];
    const sourceTrusteeOpeningMaterial =
        privateOpeningMaterialBySourceTrustee[0];
    if (sourceTrusteeOpeningMaterial === undefined) {
        throw new Error('Missing focused private VSS source trustee state.');
    }
    const sourceTrusteeContributionState =
        privateVssSourceTrusteeContributionState(
            sourceTrusteeOpeningMaterial,
            sourceTrusteeRecords,
        );
    const recipientMailboxKeyPair =
        privateVssMailboxKeyPairForRosterPosition(0);

    return createPrivateVssMailboxSourceTrusteeDeliveryReferences({
        kernel: {
            deriveProtocolHash: (input) => kernel.deriveProtocolHash(input),
            generatePrivateVssShareProof: (input) =>
                kernel.generatePrivateVssShareProof(input),
            verifyPrivateVssShareEnvelope: (input) =>
                kernel.verifyPrivateVssShareEnvelope(input),
        },
        setupContext:
            setupContext as PrivateVssMailboxDeliverySetInput['setupContext'],
        phaseOrderHash: collectiveSetupPhaseOrderHash(kernel, profile),
        publicMatrixSeedHash: String(commonRandomness.publicMatrixSeedHash),
        vssCoefficientCommitmentRoot: String(
            vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        ),
        qSharePrimes: profile.qShare.primes,
        ringDegree: minimumSuccinctProofFixtureRingDegree,
        participantCount: 1,
        deliveryPhaseNumber: 6,
        verificationPhaseNumber: 7,
        privateVssShareProofMaterialEncoding: 'binary-chunked-proof-bytes',
        sourceTrusteeContributionState,
        recipients: [
            {
                recipientIdentity: 'trustee-0',
                recipientRosterPosition: 0,
                mailboxPublicKeyBytesHex:
                    recipientMailboxKeyPair.publicKeyBytesHex,
            },
        ],
    });
}

export async function acceptedVssShareAcceptances(
    setupContext: JsonRecord,
    privateVssEnvelopeCommitments: JsonRecord,
): Promise<JsonRecord> {
    const privateVssEnvelopeCommitmentRoot = String(
        privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot,
    );
    const envelopeReferences =
        privateVssEnvelopeCommitments.envelopeReferences as JsonRecord[];
    const acceptanceRecords: VssShareAcceptanceRecord[] = [];
    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < 10;
        sourceTrusteeRosterPosition += 1
    ) {
        for (
            let recipientRosterPosition = 0;
            recipientRosterPosition < 10;
            recipientRosterPosition += 1
        ) {
            const recipientIdentity = `trustee-${String(recipientRosterPosition)}`;
            const signatureSeedLabel =
                setupTrusteeSignatureSeedLabel(recipientIdentity);
            const keyFixture = createMlDsaKeyPairFixture(signatureSeedLabel);
            const envelopeReference =
                envelopeReferences[
                    sourceTrusteeRosterPosition * 10 + recipientRosterPosition
                ];
            if (envelopeReference === undefined) {
                throw new Error(
                    'Missing private VSS envelope reference for acceptance.',
                );
            }
            const signRoot: ProtocolRootSigner = (signedRoot) =>
                createProtocolSignatureFixture({
                    profile: createMlDsaSignatureProfileFixture(),
                    publicKeyBytesHex: keyFixture.publicKeyBytesHex,
                    publicKeyHash: keyFixture.publicKeyHash,
                    secretKeyBytesHex: keyFixture.secretKeyBytesHex,
                    signedRoot,
                });
            acceptanceRecords.push(
                await createVssShareAcceptanceRecord({
                    setupContext: setupContext as CollectiveBgvSetupContext,
                    privateVssEnvelopeCommitmentRoot,
                    envelopeReference:
                        envelopeReference as PrivateVssEnvelopeVerificationReference,
                    recoveryEpoch: 0,
                    deviceEpoch: 0,
                    signingPublicKeyHash: keyFixture.publicKeyHash,
                    signRoot,
                }),
            );
        }
    }

    return createVssShareAcceptanceSet({
        setupContext: setupContext as CollectiveBgvSetupContext,
        privateVssEnvelopeCommitmentRoot,
        acceptanceRecords,
    });
}

export async function acceptedVssComplaintSet(
    setupContext: JsonRecord,
    privateVssEnvelopeCommitments: JsonRecord,
): Promise<JsonRecord> {
    const privateVssEnvelopeCommitmentRoot = String(
        privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot,
    );
    const envelopeReferences =
        privateVssEnvelopeCommitments.envelopeReferences as JsonRecord[];
    const envelopeReference = envelopeReferences[0];
    if (envelopeReference === undefined) {
        throw new Error(
            'Missing private VSS envelope reference for complaint.',
        );
    }
    const keyFixture = createMlDsaKeyPairFixture(
        setupTrusteeSignatureSeedLabel('trustee-0'),
    );
    const signRoot: ProtocolRootSigner = (signedRoot) =>
        createProtocolSignatureFixture({
            profile: createMlDsaSignatureProfileFixture(),
            publicKeyBytesHex: keyFixture.publicKeyBytesHex,
            publicKeyHash: keyFixture.publicKeyHash,
            secretKeyBytesHex: keyFixture.secretKeyBytesHex,
            signedRoot,
        });
    const complaintRecord: VssShareComplaintRecord =
        await createVssShareComplaintRecordFromLocalVerification({
            setupContext: setupContext as CollectiveBgvSetupContext,
            privateVssEnvelopeCommitmentRoot,
            envelopeReference:
                envelopeReference as PrivateVssEnvelopeVerificationReference,
            localVerification: {
                ok: false,
                privateEnvelopeHash: String(
                    envelopeReference.privateEnvelopeHash,
                ),
                localVerificationRoot: null,
                refusedObjects: [
                    {
                        reasonCode: 'private-vss-opening-verification-failed',
                        message:
                            'recipient local private VSS opening verification failed',
                        objectPath: 'privateEnvelope.rnsShareOpenings.0',
                    },
                ],
            } satisfies PrivateVssLocalVerificationFailure,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            signingPublicKeyHash: keyFixture.publicKeyHash,
            signRoot,
        });

    return createVssComplaintSet({
        setupContext: setupContext as CollectiveBgvSetupContext,
        privateVssEnvelopeCommitmentRoot,
        complaintRecords: [complaintRecord],
    });
}
