import {
    minimumSuccinctProofFixtureRingDegree,
    privateVssMailboxKeyPairForRosterPosition,
    setupTrusteeSignatureSeedLabel,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

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
import { type VssPublicCoefficientCommitmentSet } from '#packages/protocol/src/setup/vss-commitments';
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
    BgvCollectiveSetupParametersDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    bgvCanonicalStreamFamilies,
    openBgvCanonicalStreamRuntime,
} from '#packages/wasm/src/index';

function collectiveSetupPhaseOrderHash(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
): string {
    return kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'CollectiveBgvSetupPhaseOrder',
            phaseOrder: setupParameters.phaseOrder.map(
                (phase: {
                    readonly phaseId: string;
                    readonly phaseNumber: number;
                }) => ({
                    phaseId: phase.phaseId,
                    phaseNumber: phase.phaseNumber,
                }),
            ),
        },
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
        privateEnvelopeObjectType: 'PrivateVssShareEnvelope',
        ciphertextContentType: 'private-vss-share-envelope',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
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
    readonly sourceTrusteeRecord: VssPublicCoefficientCommitmentSet['sourceTrusteeRecords'][number];
    readonly sourceTrusteeRosterPosition: number;
    readonly recipientRosterPosition: number;
    readonly participantCount: number;
}): PrivateVssEnvelopeCommitment {
    const sourceTrusteeIdentity = `trustee-${String(
        input.sourceTrusteeRosterPosition,
    )}`;
    const recipientIdentity = `trustee-${String(input.recipientRosterPosition)}`;
    const recipientMailboxKeyPair = privateVssMailboxKeyPairForRosterPosition(
        input.recipientRosterPosition,
    );
    const sourceTrusteeCommitmentRoot = String(
        input.sourceTrusteeRecord.sourceCoefficientCommitmentRoot,
    );
    const envelopeSequenceNumber =
        input.sourceTrusteeRosterPosition * input.participantCount +
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
    const privateEnvelopeAadHash = input.kernel.deriveCanonicalObjectHash({
        value: privateEnvelopeAad,
    });
    const privateEnvelopeHash = input.kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'PrivateVssShareEnvelopeHash',
            fixture: 'package-shape-private-vss-envelope-reference',
            sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
            recipientRosterPosition: input.recipientRosterPosition,
        },
    });
    const encryptedEnvelopeHash = input.kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'PrivateVssEncryptedEnvelopeHash',
            fixture: 'package-shape-private-vss-envelope-reference',
            sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
            recipientRosterPosition: input.recipientRosterPosition,
            privateEnvelopeHash,
            privateEnvelopeAadHash,
        },
    });
    const localVerificationRoot = input.kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'PrivateVssLocalVerificationRoot',
            fixture: 'package-shape-private-vss-envelope-reference',
            sourceTrusteeRosterPosition: input.sourceTrusteeRosterPosition,
            recipientRosterPosition: input.recipientRosterPosition,
            privateEnvelopeHash,
        },
    });
    const referenceWithoutRoot = {
        objectType: 'PrivateVssEnvelopeCommitment',
        ceremonyId: input.setupContext.ceremonyId,
        manifestHash: input.setupContext.manifestHash,
        rosterHash: input.setupContext.rosterHash,
        setupParametersHash: input.setupContext.setupParametersHash,
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
        privateEnvelopeCommitmentRoot: input.kernel.deriveCanonicalObjectHash({
            value: referenceWithoutRoot,
        }),
    } as const satisfies PrivateVssEnvelopeCommitment;
}

export function packageShapePrivateVssEnvelopeCommitments(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
    setupContext: JsonRecord,
    commonRandomness: JsonRecord,
    vssPublicCoefficientCommitmentSet: VssPublicCoefficientCommitmentSet,
): JsonRecord {
    const sourceTrusteeRecords =
        vssPublicCoefficientCommitmentSet.sourceTrusteeRecords;
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const vssCoefficientCommitmentRoot = String(
        vssPublicCoefficientCommitmentSet.coefficientCommitmentRoot,
    );
    const phaseOrderHash = collectiveSetupPhaseOrderHash(
        kernel,
        setupParameters,
    );
    const envelopeReferences = sourceTrusteeRecords.flatMap(
        (sourceTrusteeRecord, sourceTrusteeRosterPosition) =>
            Array.from(
                { length: setupParameters.participantCount },
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
                        participantCount: setupParameters.participantCount,
                    }),
            ),
    );

    const privateVssEnvelopeCommitmentSet =
        createPrivateVssMailboxDeliverySetFromReferences({
            kernel: {
                deriveCanonicalObjectHash: (input) =>
                    kernel.deriveCanonicalObjectHash(input),
                verifyPrivateVssShareEnvelope: (input) =>
                    kernel.verifyPrivateVssShareEnvelope(input),
            },
            setupContext:
                setupContext as PrivateVssMailboxDeliverySetInput['setupContext'],
            publicMatrixSeedHash,
            vssCoefficientCommitmentRoot,
            participantCount: setupParameters.participantCount,
            deliveryPhaseNumber: 6,
            verificationPhaseNumber: 7,
            envelopeReferences,
        });

    return privateVssEnvelopeCommitmentSet;
}

export async function focusedPrivateVssSourceDeliveryReferences(
    kernel: TranscriptCoreKernel,
    setupParameters: BgvCollectiveSetupParametersDescription,
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
    const canonicalStreamRuntime = openBgvCanonicalStreamRuntime({ kernel });

    return createPrivateVssMailboxSourceTrusteeDeliveryReferences({
        kernel: {
            deriveCanonicalObjectHash: (input) =>
                kernel.deriveCanonicalObjectHash(input),
            generatePrivateVssShareProof: (input) =>
                kernel.generatePrivateVssShareProof(input),
            exportCanonicalProofMaterial: async ({ proofMaterialRoot }) => {
                const storedChunks: ArrayBuffer[] = [];
                const descriptorBytes =
                    await canonicalStreamRuntime.writeMaterial({
                        emitChunk: ({ bytes, chunkIndex }) => {
                            storedChunks[chunkIndex] = bytes.slice(0);

                            return Promise.resolve();
                        },
                        family: bgvCanonicalStreamFamilies.vssOpeningCarry,
                        materialRoot: proofMaterialRoot,
                    });
                await canonicalStreamRuntime.readMaterial({
                    descriptorBytes,
                    family: bgvCanonicalStreamFamilies.vssOpeningCarry,
                    materialRoot: proofMaterialRoot,
                    pullChunk: ({ chunkIndex }) =>
                        Promise.resolve(storedChunks[chunkIndex]?.slice(0)),
                });

                return { descriptorBytes };
            },
            verifyPrivateVssShareEnvelope: (input) =>
                kernel.verifyPrivateVssShareEnvelope(input),
        },
        setupContext:
            setupContext as PrivateVssMailboxDeliverySetInput['setupContext'],
        phaseOrderHash: collectiveSetupPhaseOrderHash(kernel, setupParameters),
        publicMatrixSeedHash: String(commonRandomness.publicMatrixSeedHash),
        vssCoefficientCommitmentRoot: String(
            vssCoefficientCommitments.vssCoefficientCommitmentRoot,
        ),
        qSharePrimes: setupParameters.qShare.primes,
        ringDegree: minimumSuccinctProofFixtureRingDegree,
        participantCount: 1,
        deliveryPhaseNumber: 6,
        verificationPhaseNumber: 7,
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
    const participantCount = Number(setupContext.participantCount);
    const envelopeReferences =
        privateVssEnvelopeCommitments.envelopeReferences as JsonRecord[];
    const acceptanceRecords: VssShareAcceptanceRecord[] = [];
    for (
        let sourceTrusteeRosterPosition = 0;
        sourceTrusteeRosterPosition < participantCount;
        sourceTrusteeRosterPosition += 1
    ) {
        for (
            let recipientRosterPosition = 0;
            recipientRosterPosition < participantCount;
            recipientRosterPosition += 1
        ) {
            const recipientIdentity = `trustee-${String(recipientRosterPosition)}`;
            const signatureSeedLabel =
                setupTrusteeSignatureSeedLabel(recipientIdentity);
            const keyFixture = createMlDsaKeyPairFixture(signatureSeedLabel);
            const envelopeReference =
                envelopeReferences[
                    sourceTrusteeRosterPosition * participantCount +
                        recipientRosterPosition
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
                isValid: false,
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
