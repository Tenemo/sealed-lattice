import { describe, expect, it } from 'vitest';

import { setupRequest, validHash } from './bgv-passive-setup-fixtures.js';

import {
    createPrivateVssMailboxKeyPair,
    hash512Hex,
} from '#packages/crypto/src/index';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#packages/crypto/tests/support/protocol-signature-fixtures';
import {
    createEvaluatorKeySchedule,
    type EvaluatorKeySchedule,
} from '#packages/protocol/src/setup/evaluator-key-schedule';
import {
    collectForbiddenLocalTrusteeSetupStateFieldPaths,
    createLocalTrusteeSetupStateCommitment,
} from '#packages/protocol/src/setup/local-trustee-setup-state';
import {
    createPrivateVssMailboxDeliverySet,
    type PrivateVssMailboxDeliverySetInput,
} from '#packages/protocol/src/setup/private-vss-mailbox-delivery';
import {
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
} from '#packages/protocol/src/setup/public-key-share-records';
import { createSameSecretConsistencyStatementSet } from '#packages/protocol/src/setup/same-secret-consistency-records';
import type { SameSecretConsistencyStatementSet } from '#packages/protocol/src/setup/same-secret-consistency-records';
import {
    createSetupPhaseParticipantObject,
    createSetupPhaseRecord,
} from '#packages/protocol/src/setup/setup-phase-records';
import {
    createVssCoefficientCommitmentBundle,
    createVssSourceTrusteeCoefficientOpeningState,
    type VssCoefficientCommitmentBundle,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeOpeningMaterial,
    type VssOpeningRandomByteSource,
} from '#packages/protocol/src/setup/vss-coefficient-commitments';
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
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';
import type {
    BgvCollectiveSetupProfileDescription,
    BgvRnsProfileDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';

type JsonRecord = Record<string, unknown>;

const jsonRecord = (value: unknown, label: string): JsonRecord => {
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        throw new Error(`${label} must be a JSON object.`);
    }

    return value as JsonRecord;
};

const optionalJsonRecord = (
    value: unknown,
    label: string,
): JsonRecord | undefined =>
    value === undefined ? undefined : jsonRecord(value, label);

const cloneJsonRecord = (value: JsonRecord): JsonRecord =>
    JSON.parse(JSON.stringify(value)) as JsonRecord;

const textEncoder = new TextEncoder();
const acceptedDevelopmentRingDegree = 8;
const firstProfileParticipantCount = 10;
const firstProfileDecryptionThreshold = 4;
const protocolHashPattern = /^[0-9a-f]{128}$/u;
const setupTransportChunkSizeBytes = 1_048_576;
const setupTransportTotalByteLength = 1_604_321_280;
const setupTransportChunkCount =
    setupTransportTotalByteLength / setupTransportChunkSizeBytes;
const setupProofFamilies = [
    'vss-opening-carry',
    'same-secret-consistency',
    'public-key-share',
    'relinearization-key-share',
    'galois-key-share',
] as const;
const setupProofChallengeDomain =
    'sealed-lattice/collective-bgv-setup/lnp-challenge-v1';
const setupProofChallengeSampler =
    'sealed-lattice-shake256-lazer-autostable-rejection-v1';
const setupProofChallengeSpace =
    'fixed-lnp-small-coefficient-polynomial-challenge-set';
const setupProofChallengeSeedDomain =
    'sealed-lattice/collective-bgv-setup/lnp-challenge-seed-v1';
const setupProofChallengeStreamDomain =
    'sealed-lattice/collective-bgv-setup/lnp-challenge-stream-v1';
const setupProofBytesDomain =
    'sealed-lattice/collective-bgv-setup/lnp-proof-bytes-v1';
const setupProofSerialization = 'binary';
const setupProofByteDecoder = 'sealed-lattice-lnp-tbox-proof-byte-decoder-v1';
const setupProofChallengeSpaceAuditHashNamespace =
    'SetupProofChallengeSpaceAuditHash';

const hexToBytes = (hexValue: string): Uint8Array =>
    Uint8Array.from(
        Array.from({ length: hexValue.length / 2 }, (_unused, byteIndex) =>
            Number.parseInt(
                hexValue.slice(byteIndex * 2, byteIndex * 2 + 2),
                16,
            ),
        ),
    );

const privateVssMailboxKeyPairForRosterPosition = (
    rosterPosition: number,
): ReturnType<typeof createPrivateVssMailboxKeyPair> =>
    createPrivateVssMailboxKeyPair(
        hash512Hex('sealed-lattice-test/private-vss-mailbox-key', [
            textEncoder.encode(String(rosterPosition)),
        ]),
    );

const privateVssMailboxPublicKeyBytesHash = (
    publicKeyBytesHex: string,
): string =>
    hash512Hex('sealed-lattice-private-vss-mailbox/ml-kem-768-public-key-v1', [
        hexToBytes(publicKeyBytesHex),
    ]);

const deterministicRandomBytes = (
    seedLabel: string,
): VssOpeningRandomByteSource => {
    let blockIndex = 0;
    let bufferedBytes = new Uint8Array(0);
    let bufferedOffset = 0;

    return (byteLength) => {
        const outputBytes = new Uint8Array(byteLength);
        let outputOffset = 0;
        while (outputOffset < byteLength) {
            if (bufferedOffset >= bufferedBytes.byteLength) {
                const blockHex = hash512Hex(
                    'sealed-lattice-test/vss-opening-randomness',
                    [
                        textEncoder.encode(seedLabel),
                        textEncoder.encode(String(blockIndex)),
                    ],
                );
                bufferedBytes = Uint8Array.from(
                    blockHex
                        .match(/../gu)
                        ?.map((byteHex) => Number.parseInt(byteHex, 16)) ?? [],
                );
                bufferedOffset = 0;
                blockIndex += 1;
            }
            const copyLength = Math.min(
                byteLength - outputOffset,
                bufferedBytes.byteLength - bufferedOffset,
            );
            outputBytes.set(
                bufferedBytes.subarray(
                    bufferedOffset,
                    bufferedOffset + copyLength,
                ),
                outputOffset,
            );
            bufferedOffset += copyLength;
            outputOffset += copyLength;
        }

        return outputBytes;
    };
};

function acceptedVssCoefficientCommitments(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    publicMatrixSeedHash: string,
): VssCoefficientCommitmentBundle {
    return createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash,
        qSharePrimes: profile.qShare.primes,
        ringDegree: acceptedDevelopmentRingDegree,
        participantCount: firstProfileParticipantCount,
        thresholdDegree: firstProfileDecryptionThreshold,
        sourceTrusteeOpeningStates: Array.from(
            { length: firstProfileParticipantCount },
            (_unusedSourceTrustee, sourceTrusteeRosterPosition) =>
                createVssSourceTrusteeCoefficientOpeningState({
                    sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
                    sourceTrusteeRosterPosition,
                    participantCount: firstProfileParticipantCount,
                    qSharePrimes: profile.qShare.primes,
                    ringDegree: acceptedDevelopmentRingDegree,
                    thresholdDegree: firstProfileDecryptionThreshold,
                    randomBytes: deterministicRandomBytes(
                        `trustee-${String(sourceTrusteeRosterPosition)}`,
                    ),
                }),
        ),
    });
}

function acceptedSameSecretConsistency(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    vssCoefficientCommitments: VssCoefficientCommitmentSet,
): SameSecretConsistencyStatementSet {
    return createSameSecretConsistencyStatementSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        thresholdDegree: firstProfileDecryptionThreshold,
        vssCoefficientCommitments,
    });
}

function acceptedPublicKeyShares(
    kernel: TranscriptCoreKernel,
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    commonRandomness: JsonRecord,
    sameSecretConsistency: SameSecretConsistencyStatementSet,
): PublicKeyShareSet {
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;
    const publicKeyCrpRoot = String(crpRoots.publicKeyCrpRoot);
    const publicAPolynomialRoot = String(publicA.publicPolynomialRoot);

    return createPublicKeyShareSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        publicMatrixSeedHash,
        publicKeyCrpRoot,
        publicAPolynomialRoot,
        sameSecretConsistency,
        shareContributions: Array.from(
            { length: firstProfileParticipantCount },
            (_unused, trusteeRosterPosition) => ({
                trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
                trusteeRosterPosition,
                shareCoefficientVectorHash512ByLimb: profile.qShare.primes.map(
                    (rnsPrime, rnsLimbIndex) => ({
                        rnsLimbIndex,
                        rnsPrime,
                        component: 'b_i',
                        coefficientVectorHash512: kernel.deriveProtocolHash({
                            namespace: 'PublicKeyShareRoot',
                            value: {
                                fixture: 'public-key-share-coefficient-vector',
                                trusteeRosterPosition,
                                rnsLimbIndex,
                            },
                        }),
                    }),
                ),
            }),
        ),
    });
}

function acceptedPublicKeyShareProofs(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    commonRandomness: JsonRecord,
    sameSecretConsistency: SameSecretConsistencyStatementSet,
    publicKeyShares: PublicKeyShareSet,
): PublicKeyShareProofSet {
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;
    const publicKeyCrpRoot = String(crpRoots.publicKeyCrpRoot);
    const publicAPolynomialRoot = String(publicA.publicPolynomialRoot);

    return createPublicKeyShareProofSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        publicMatrixSeedHash,
        publicKeyCrpRoot,
        publicAPolynomialRoot,
        sameSecretConsistency,
        publicKeyShares,
    });
}

function acceptedEvaluatorKeySchedule(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    commonRandomness: JsonRecord,
    sameSecretConsistency: SameSecretConsistencyStatementSet,
    publicKeyShares: PublicKeyShareSet,
    publicKeyShareProofs: PublicKeyShareProofSet,
): EvaluatorKeySchedule {
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;

    return createEvaluatorKeySchedule({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        publicMatrixSeedHash,
        relinearizationCrpRoot: String(crpRoots.relinearizationCrpRoot),
        galoisKeyCrpRoot: String(crpRoots.galoisKeyCrpRoot),
        sameSecretConsistency,
        publicKeyShares,
        publicKeyShareProofs,
        requiredGaloisKeySchedule:
            profile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule,
    });
}

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

async function acceptedPrivateVssEnvelopeCommitments(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
    setupContext: JsonRecord,
    commonRandomness: JsonRecord,
    vssCoefficientCommitments: JsonRecord,
    privateOpeningMaterialBySourceTrustee: readonly VssSourceTrusteeOpeningMaterial[],
): Promise<JsonRecord> {
    const sourceTrusteeRecords =
        vssCoefficientCommitments.sourceTrusteeRecords as JsonRecord[];
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const vssCoefficientCommitmentRoot = String(
        vssCoefficientCommitments.vssCoefficientCommitmentRoot,
    );
    const phaseOrderHash = kernel.deriveProtocolHash({
        namespace: 'CollectiveBgvSetupPhaseOrderHash',
        value: profile.phaseOrder.map((phase) => ({
            phaseId: phase.phaseId,
            phaseNumber: phase.phaseNumber,
        })),
    });
    const mailboxRecipients = Array.from(
        { length: firstProfileParticipantCount },
        (_unusedSlot, recipientRosterPosition) => {
            const mailboxKeyPair = privateVssMailboxKeyPairForRosterPosition(
                recipientRosterPosition,
            );

            return {
                recipientIdentity: `trustee-${String(recipientRosterPosition)}`,
                recipientRosterPosition,
                mailboxPublicKeyBytesHex: mailboxKeyPair.publicKeyBytesHex,
            };
        },
    );
    const privateVssEnvelopeCommitmentSet =
        await createPrivateVssMailboxDeliverySet({
            kernel: {
                deriveProtocolHash: (input) => kernel.deriveProtocolHash(input),
                generatePrivateVssShareProof: (input) =>
                    kernel.generatePrivateVssShareProof(input),
                verifyPrivateVssShareEnvelope: (input) =>
                    kernel.verifyPrivateVssShareEnvelope(input),
            },
            setupContext:
                setupContext as PrivateVssMailboxDeliverySetInput['setupContext'],
            phaseOrderHash,
            publicMatrixSeedHash,
            vssCoefficientCommitmentRoot,
            qSharePrimes: profile.qShare.primes,
            ringDegree: acceptedDevelopmentRingDegree,
            participantCount: firstProfileParticipantCount,
            deliveryPhaseNumber: 6,
            verificationPhaseNumber: 7,
            privateVssShareProofMaterialEncoding: 'binary-chunked-proof-bytes',
            sourceTrusteeContributionStates:
                privateOpeningMaterialBySourceTrustee.map(
                    (sourceTrusteeOpeningMaterial) => {
                        const sourceTrusteeRecord =
                            sourceTrusteeRecords[
                                sourceTrusteeOpeningMaterial
                                    .sourceTrusteeRosterPosition
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
                            sourceTrusteeCoefficientCommitmentRecord:
                                sourceTrusteeRecord,
                            sourceTrusteeCoefficientCommitmentMaterialRecords:
                                sourceTrusteeOpeningMaterial.sourceTrusteeCoefficientCommitmentMaterialRecords,
                            coefficientOpenings:
                                sourceTrusteeOpeningMaterial.coefficientOpenings,
                        };
                    },
                ),
            privateVssShareProofRandomnessFactory: ({
                rnsLimbIndex,
                rnsPrime,
                recipient,
                coefficientCommitmentRoots,
            }) => ({
                source: 'development-deterministic-fixture',
                seedHex: kernel.deriveProtocolHash({
                    namespace: 'PrivateVssLocalVerificationRoot',
                    value: {
                        fixture: 'private-vss-share-proof-randomness',
                        rnsLimbIndex,
                        rnsPrime,
                        recipientRosterPosition:
                            recipient.recipientRosterPosition,
                        coefficientCommitmentRoots,
                    },
                }),
            }),
            recipients: mailboxRecipients,
        });

    expect(
        collectForbiddenPrivateVssDeliveryFieldPaths(
            privateVssEnvelopeCommitmentSet,
        ),
    ).toEqual([]);
    const firstEnvelopeReference = (
        privateVssEnvelopeCommitmentSet.envelopeReferences as readonly JsonRecord[]
    )[0];
    if (firstEnvelopeReference === undefined) {
        throw new Error('Missing private VSS envelope reference.');
    }
    expect(
        firstEnvelopeReference.transportedPrivateVssShareProofMaterial,
    ).toMatchObject({
        objectType: 'SetupTransportedPrivateVssShareProofMaterialSet',
        proofFamily: 'vss-opening-carry',
    });

    return privateVssEnvelopeCommitmentSet;
}

async function acceptedVssShareAcceptances(
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
        const sourceTrusteeIdentity = `trustee-${String(sourceTrusteeRosterPosition)}`;
        for (
            let recipientRosterPosition = 0;
            recipientRosterPosition < 10;
            recipientRosterPosition += 1
        ) {
            const recipientIdentity = `trustee-${String(recipientRosterPosition)}`;
            const signatureSeedLabel = `${recipientIdentity}-accepts-${sourceTrusteeIdentity}`;
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

async function acceptedVssComplaintSet(
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
        'trustee-0-complains-trustee-0',
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

function acceptedCommonRandomness(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const commitRecords: JsonRecord[] = [];
    const revealRecords: JsonRecord[] = [];
    const orderedRevealHashes: string[] = [];
    for (let rosterPosition = 0; rosterPosition < 10; rosterPosition += 1) {
        const trusteeIdentity = `trustee-${String(rosterPosition)}`;
        const revealHex = kernel
            .deriveProtocolHash({
                namespace: 'CommonRandomnessRevealHash',
                value: {
                    fixture: 'common-randomness-reveal',
                    rosterPosition,
                },
            })
            .slice(0, 64);
        const signatureEnvelopeHash = kernel.deriveProtocolHash({
            namespace: 'ProtocolSignatureEnvelopeHash',
            value: {
                fixture: 'common-randomness-signature',
                rosterPosition,
            },
        });
        const revealRecord: JsonRecord = {
            objectType: 'CommonRandomnessReveal',
            objectVersion: 1,
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash: setupRequest.rosterHash,
            setupProfileHash: profile.setupProfileHash,
            setupEpoch: 'setup-epoch-1',
            signerRole: 'Trustee',
            trusteeIdentity,
            rosterPosition,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            revealHex,
            signatureEnvelopeHash,
        };
        const revealHash = kernel.deriveProtocolHash({
            namespace: 'CommonRandomnessRevealHash',
            value: revealRecord,
        });
        revealRecord.revealHash = revealHash;
        revealRecords.push(revealRecord);
        orderedRevealHashes.push(revealHash);

        const commitRecord: JsonRecord = {
            objectType: 'CommonRandomnessCommit',
            objectVersion: 1,
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash: setupRequest.rosterHash,
            setupProfileHash: profile.setupProfileHash,
            setupEpoch: 'setup-epoch-1',
            signerRole: 'Trustee',
            trusteeIdentity,
            rosterPosition,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            revealHash,
            signatureEnvelopeHash,
        };
        commitRecord.commitHash = kernel.deriveProtocolHash({
            namespace: 'CommonRandomnessCommitHash',
            value: commitRecord,
        });
        commitRecords.push(commitRecord);
    }

    const publicMatrixSeedHash = kernel.deriveProtocolHash({
        namespace: 'SetupPublicMatrixSeedHash',
        value: {
            setupProfileId: 'CollectiveBgvSetup-v1',
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash: setupRequest.rosterHash,
            setupProfileHash: String(profile.setupProfileHash),
            setupEpoch: 'setup-epoch-1',
            orderedRevealHashes,
        },
    });
    const publicDerivations = kernel.deriveCollectiveBgvSetupPublicDerivations({
        publicMatrixSeedHash,
    });
    expect(
        publicDerivations.publicMatrices.commitmentMatrix.profileStatus,
    ).toBe('commitment-profile-bound');
    expect(
        publicDerivations.publicMatrices.setupProofMatrix.profileStatus,
    ).toBe('setup-proof-profile-bound');
    expect(
        publicDerivations.publicMatrices.setupProofMatrix.setupProofProfileHash,
    ).toEqual(expect.any(String));
    expect(
        publicDerivations.publicMatrices.setupProofMatrix.challengeDomainHash,
    ).toEqual(expect.any(String));
    expect(
        publicDerivations.publicMatrices.commitmentMatrix.sampledEntries[0]
            ?.coefficientValue,
    ).toEqual(expect.any(Number));
    expect(
        publicDerivations.publicMatrices.setupProofMatrix.sampledEntries[0]
            ?.coefficientValue,
    ).toEqual(expect.any(Number));
    const commonRandomness: JsonRecord = {
        objectType: 'SetupCommonRandomness',
        objectVersion: 1,
        ceremonyId: setupRequest.ceremonyId,
        manifestHash: setupRequest.manifestHash,
        rosterHash: setupRequest.rosterHash,
        setupProfileHash: profile.setupProfileHash,
        setupEpoch: 'setup-epoch-1',
        commitRecords,
        revealRecords,
        publicMatrixSeedHash,
        publicDerivations,
    };
    commonRandomness.commonRandomnessRoot = kernel.deriveProtocolHash({
        namespace: 'SetupCommonRandomnessRoot',
        value: commonRandomness,
    });

    return commonRandomness;
}

function publicPrivateVssEnvelopeCommitmentReference(
    envelopeReference: JsonRecord,
): JsonRecord {
    const {
        encryptedEnvelope: encryptedEnvelopeForRecipientTransport,
        transportedPrivateVssShareProofMaterial:
            transportedPrivateVssShareProofMaterialForRecipientTransport,
        ...publicReference
    } = envelopeReference;
    void encryptedEnvelopeForRecipientTransport;
    void transportedPrivateVssShareProofMaterialForRecipientTransport;

    return publicReference;
}

function publicPrivateVssEnvelopeCommitmentSet(
    privateVssEnvelopeCommitments: JsonRecord,
): JsonRecord {
    return {
        ...privateVssEnvelopeCommitments,
        envelopeReferences: (
            privateVssEnvelopeCommitments.envelopeReferences as JsonRecord[]
        ).map(publicPrivateVssEnvelopeCommitmentReference),
    };
}

function setupPackageHashInput(setupPackage: JsonRecord): JsonRecord {
    const hashInput: JsonRecord = { ...setupPackage };
    delete hashInput.setupPackageHash;
    hashInput.privateVssEnvelopeCommitments =
        publicPrivateVssEnvelopeCommitmentSet(
            hashInput.privateVssEnvelopeCommitments as JsonRecord,
        );

    return hashInput;
}

function rebindCollectiveSetupPackageHash(
    kernel: TranscriptCoreKernel,
    setupPackage: JsonRecord,
): void {
    delete setupPackage.setupPackageHash;
    setupPackage.setupPackageHash = kernel.deriveProtocolHash({
        namespace: 'SetupPackageHash',
        value: setupPackageHashInput(setupPackage),
    });
}

function scalarPowerSum(
    coefficientCount: number,
    trusteePoint: number,
): bigint {
    let scalarSum = 0n;
    let trusteePower = 1n;
    const trusteePointWide = BigInt(trusteePoint);
    for (
        let coefficientIndex = 0;
        coefficientIndex < coefficientCount;
        coefficientIndex += 1
    ) {
        scalarSum += trusteePower;
        if (coefficientIndex + 1 < coefficientCount) {
            trusteePower *= trusteePointWide;
        }
    }

    return scalarSum;
}

function ceilLog2Bigint(value: bigint): number {
    if (value <= 1n) {
        return 0;
    }

    return (value - 1n).toString(2).length;
}

function moduliProductDecimal(moduli: readonly number[]): string {
    return moduli
        .reduce((product, modulus) => product * BigInt(modulus), 1n)
        .toString();
}

function moduliBitLengthSum(moduli: readonly number[]): number {
    return moduli.reduce(
        (bitLengthSum, modulus) => bitLengthSum + modulus.toString(2).length,
        0,
    );
}

function keySwitchComponentPolynomialCount(
    entries: readonly { readonly level: number }[],
): number {
    return entries.reduce((total, entry) => {
        const digitCount = entry.level + 1;

        return total + digitCount * digitCount;
    }, 0);
}

function fallbackAcceptedSetupCommitmentSecurityCertificate(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const sourceRnsPrimes = profile.qShare.primes;
    const maxSourceMessageModulus = Math.max(...sourceRnsPrimes);
    const recipientScalarSum = scalarPowerSum(
        firstProfileDecryptionThreshold,
        10,
    );
    const thresholdScalarSum =
        recipientScalarSum * BigInt(firstProfileParticipantCount);
    const commitmentModulusLimbs = (
        profile.commitmentProfile.messageEncoding as JsonRecord
    ).commitmentModulusLimbs as readonly unknown[];
    const commitmentModulusProduct = commitmentModulusLimbs.reduce<bigint>(
        (product, limb, limbIndex) => {
            if (typeof limb === 'number') {
                return product * BigInt(limb);
            }
            const limbRecord = limb as JsonRecord;
            const modulus = limbRecord.modulus;
            if (typeof modulus !== 'number' || !Number.isSafeInteger(modulus)) {
                throw new TypeError(
                    `commitmentModulusLimbs.${String(limbIndex)}.modulus must be a safe integer.`,
                );
            }

            return product * BigInt(modulus);
        },
        1n,
    );
    const maxRecipientLiftedCoefficient =
        BigInt(maxSourceMessageModulus - 1) * recipientScalarSum;
    const maxThresholdLiftedCoefficient =
        BigInt(maxSourceMessageModulus - 1) * thresholdScalarSum;
    const commitmentModulusProductBits = ceilLog2Bigint(
        commitmentModulusProduct,
    );
    const certificate = {
        objectType: 'SetupCommitmentSecurityCertificate',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProfileHash: profile.setupProfileHash,
        commitmentProfileId: 'SealedLattice-BDLOP-LNP-Commitment-v1',
        commitmentProfileHash: profile.commitmentProfileHash,
        qShareHash: profile.qShareHash,
        carryAwareVssShareRelationProfileHash:
            profile.carryAwareVssShareRelationProfileHash,
        certificateScope:
            'first-profile-BDLOP-LNP-commitment-parameters-and-opening-bounds',
        acceptedUse: [
            'VSS coefficient commitment records',
            'recipient-local private VSS proof witness checks',
            'verifier-derived threshold-share commitment roots',
            'same-secret trustee commitment roots',
        ],
        nonClosure: [
            'public evaluation-key assembly and setup-package terminal acceptance remain separate from this commitment parameter certificate',
            'profile-scale binary streaming evidence remains separate from this commitment parameter certificate',
            'future target-decryption readiness remains outside this commitment parameter certificate',
        ],
        ringAndMatrixParameters: {
            coefficientRing: 'Z_q[X]/(X^N+1)',
            ringDegree: 32_768,
            sourceRnsLimbCount: sourceRnsPrimes.length,
            sourceRnsPrimes,
            commitmentModulusLimbs,
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            commitmentModulusProductCeilBits: commitmentModulusProductBits,
            moduleRank: 2,
            randomnessWidth: 5,
            commitmentRowCount: 3,
            publicMatrixSource:
                'full-roster-common-randomness-XOF-unbiased-residue-stream',
            matrixHashBound: true,
        },
        freshOpeningDistribution: {
            distribution: 'coefficientwise-centered-ternary',
            coefficientSet: [-1, 0, 1],
            infinityNormBound: 1,
            randomnessWidth: 5,
            rawOpeningExported: false,
            perCoefficientOpeningExported: false,
        },
        fullWidthMessageBound: {
            messageSource: 'per-RNS-prime-Shamir-coefficient-ring-element',
            maxSourceMessageModulus,
            maxFreshMessageCoefficientDecimal: String(
                maxSourceMessageModulus - 1,
            ),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            freshMessageNoWrap:
                BigInt(maxSourceMessageModulus - 1) < commitmentModulusProduct,
            status: 'claim-accounting-full-width-per-rns-message-bound-recorded',
        },
        aggregateOpeningBounds: {
            shamirCoefficientCount: firstProfileDecryptionThreshold,
            maximumTrusteePoint: 10,
            recipientScalarPowerSumDecimal: recipientScalarSum.toString(),
            recipientAggregateOpeningInfinityBound: Number(recipientScalarSum),
            maxRecipientLiftedCoefficientDecimal:
                maxRecipientLiftedCoefficient.toString(),
            sourceTrusteeCountForThresholdAggregation:
                firstProfileParticipantCount,
            thresholdScalarPowerSumDecimal: thresholdScalarSum.toString(),
            thresholdShareOpeningInfinityBound: Number(thresholdScalarSum),
            maxThresholdLiftedCoefficientDecimal:
                maxThresholdLiftedCoefficient.toString(),
            commitmentModulusProductDecimal:
                commitmentModulusProduct.toString(),
            recipientAndThresholdNoWrap: true,
            boundStatus:
                'claim-accounting-first-profile-homomorphic-opening-bounds-recorded',
        },
        multiOpeningLeakage: {
            recipientAggregateOpeningsArePublic: false,
            recipientAggregateOpeningsAreMailboxPlaintext: false,
            maxCorruptRecipientsBeforeThreshold:
                firstProfileDecryptionThreshold - 1,
            shamirPolynomialDegree: firstProfileDecryptionThreshold - 1,
            rawCoefficientOpeningsExported: false,
            perCoefficientRandomnessExported: false,
            thresholdBoundary:
                'recipient-aggregate-openings-and-carry-witnesses-are-private-proof-witnesses',
            status: 'claim-accounting-active-static-threshold-leakage-bound-recorded',
        },
        bindingAssumption: {
            assumption: 'Module-SIS',
            boundTarget:
                'two-valid-openings-to-one-commitment-yield-short-module-SIS-solution',
            moduleRank: 2,
            randomnessWidth: 5,
            commitmentModulusProductCeilBits: commitmentModulusProductBits,
            extractedOpeningInfinityBound: Number(thresholdScalarSum),
            referenceRows: [
                {
                    document:
                        'LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General',
                    localReferencePath:
                        'reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt',
                    sections: [
                        'Commitment schemes',
                        'Module-SIS and Module-LWE problems',
                        'ABDLOP commitment scheme and proofs of linear relations',
                    ],
                },
                {
                    document:
                        'FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting',
                    localReferencePath:
                        'reference-documents/FPS25_Lattice-Based Zero-Knowledge Proofs in Action Applications to Electronic Voting.txt',
                    sections: [
                        'BDLOP commitment background',
                        'Module-LWE and Module-SIS definitions',
                    ],
                },
            ],
            estimatorStatus:
                'repo-owned-module-sis-parameter-accounting-accepted',
        },
        hidingAssumption: {
            assumption:
                'Module-LWE with recipient-hidden proof-witness opening leakage boundary',
            openingDistribution: 'coefficientwise-centered-ternary',
            publicMatrixDistribution: 'hash-derived-uniform-residue-stream',
            lowEntropySecretHiding: true,
            statisticalLeakageStatus:
                'repo-owned-recipient-hidden-aggregate-opening-proof-witness-accounting-accepted',
            estimatorStatus:
                'repo-owned-module-lwe-parameter-accounting-accepted',
        },
        estimatorRows: [
            {
                rowId: 'first-profile-module-sis-binding-row',
                problem: 'Module-SIS',
                targetSecurityBits: 128,
                ringDegree: 32_768,
                moduleRank: 2,
                modulusCeilBits: commitmentModulusProductBits,
                shortVectorInfinityBoundDecimal: thresholdScalarSum.toString(),
                status: 'claim-accounting-accepted',
                accountingBasis:
                    'accepted Module-SIS binding row under LNP22/FPS25 commitment references and no-wrap threshold-opening bounds',
            },
            {
                rowId: 'first-profile-module-lwe-hiding-row',
                problem: 'Module-LWE',
                targetSecurityBits: 128,
                ringDegree: 32_768,
                moduleRank: 2,
                secretDistribution: 'centered-ternary-opening',
                modulusCeilBits: commitmentModulusProductBits,
                status: 'claim-accounting-accepted',
                accountingBasis:
                    'accepted Module-LWE hiding row under LNP22/FPS25/ACC18 references and recipient-hidden opening leakage boundary',
            },
        ],
        certificateStatus:
            'claim-bearing-setup-commitment-parameter-accounting-accepted',
    };

    return {
        ...certificate,
        setupCommitmentSecurityCertificateHash: kernel.deriveProtocolHash({
            namespace: 'SetupCommitmentSecurityCertificateHash',
            value: certificate,
        }),
    };
}

function acceptedSetupCommitmentSecurityCertificate(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const acceptedCertificateTemplates = optionalJsonRecord(
        (profile as unknown as JsonRecord).acceptedCertificateTemplates,
        'profile.acceptedCertificateTemplates',
    );
    const template =
        acceptedCertificateTemplates?.setupCommitmentSecurityCertificate;
    if (template !== undefined) {
        return cloneJsonRecord(
            jsonRecord(
                template,
                'profile.acceptedCertificateTemplates.setupCommitmentSecurityCertificate',
            ),
        );
    }

    return fallbackAcceptedSetupCommitmentSecurityCertificate(kernel, profile);
}

function setupProofRecordBindingForCertificate(
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const setupProofProfile = profile.setupProofProfile as JsonRecord;
    const challengeBinding = setupProofProfile.challengeBinding as JsonRecord;
    const relationModel = setupProofProfile.relationModel as JsonRecord;
    const verificationPolicy =
        setupProofProfile.verificationPolicy as JsonRecord;

    return {
        objectType: 'SetupProofRecordBinding',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProofProfileId: setupProofProfile.profileId,
        setupProofProfileHash: profile.setupProofProfileHash,
        proofSystem: setupProofProfile.proofSystem,
        challengeDomain: challengeBinding.challengeDomain,
        challengeDomainHash: challengeBinding.challengeDomainHash,
        challengeBits: challengeBinding.challengeBits,
        challengeCount: challengeBinding.challengeCount,
        challengeCoefficientBound: challengeBinding.challengeCoefficientBound,
        applicationRingDegree: relationModel.applicationRingDegree,
        lnpTboxProofRingDegree: challengeBinding.lnpTboxProofRingDegree,
        lnpTboxChallengeLog2Range: challengeBinding.lnpTboxChallengeLog2Range,
        lnpTboxChallengeEncodedBits:
            challengeBinding.lnpTboxChallengeEncodedBits,
        lnpTboxChallengeSpaceBits: challengeBinding.lnpTboxChallengeSpaceBits,
        challengeSpace: challengeBinding.challengeSpace,
        challengeSampler: challengeBinding.challengeSampler,
        challengeSeedDomain: setupProofChallengeSeedDomain,
        challengeStreamDomain: setupProofChallengeStreamDomain,
        challengeDifferenceInvertibilityStatus:
            challengeBinding.challengeDifferenceInvertibilityStatus,
        challengeDifferenceInvertibilityAccounting:
            challengeBinding.challengeDifferenceInvertibilityAccounting,
        proofBytesDomain: setupProofBytesDomain,
        proofSerialization: setupProofSerialization,
        proofByteDecoder: setupProofByteDecoder,
        privateVssShareTboxParameterProfileHash:
            setupProofProfile.privateVssShareTboxParameterProfileHash,
        sameSecretTboxParameterProfileHash:
            setupProofProfile.sameSecretTboxParameterProfileHash,
        publicKeyShareTboxParameterProfileHash:
            setupProofProfile.publicKeyShareTboxParameterProfileHash,
        relinearizationKeyShareTboxParameterProfileHash:
            setupProofProfile.relinearizationKeyShareTboxParameterProfileHash,
        galoisKeyShareTboxParameterProfileHash:
            setupProofProfile.galoisKeyShareTboxParameterProfileHash,
        proofBytesAcceptedStatus: verificationPolicy.proofBytesAcceptedStatus,
    };
}

function fallbackAcceptedSetupProofAccountingCertificate(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const setupProofRecordBinding =
        setupProofRecordBindingForCertificate(profile);
    const setupProofProfile = profile.setupProofProfile as JsonRecord;
    const challengeBinding = setupProofProfile.challengeBinding as JsonRecord;
    const challengeSpaceAudit =
        setupProofProfile.challengeSpaceAudit as JsonRecord;
    const certificate = {
        objectType: 'SetupProofAccountingCertificate',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupProfileHash: profile.setupProfileHash,
        setupProofProfileId: 'SealedLattice-LNP-SetupProof-v1',
        setupProofProfileHash: profile.setupProofProfileHash,
        setupProofRecordBinding,
        setupProofRecordBindingHash: kernel.deriveProtocolHash({
            namespace: 'SetupProofRecordBindingHash',
            value: setupProofRecordBinding,
        }),
        proofFamilies: setupProofFamilies,
        proofFamilyAccounting: [
            {
                proofFamily: 'vss-opening-carry',
                claimScope:
                    'recipient-local private VSS share proof relation over accepted Q_share limbs',
                verifierClosedStatus:
                    'relation-transcript-and-bound-checks-verifier-closed',
                accountingStatus:
                    'repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted',
            },
            {
                proofFamily: 'same-secret-consistency',
                claimScope:
                    'same trustee secret across accepted VSS constant commitments',
                verifierClosedStatus:
                    'relation-transcript-and-bound-checks-verifier-closed',
                accountingStatus:
                    'repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted',
            },
            {
                proofFamily: 'public-key-share',
                claimScope:
                    'public-key share relation bound to the accepted same-secret proof and public-key material roots',
                verifierClosedStatus:
                    'relation-transcript-and-bound-checks-verifier-closed',
                accountingStatus:
                    'repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted',
            },
            {
                proofFamily: 'relinearization-key-share',
                claimScope:
                    'relinearization key-share relation bound to the same secret, round-one aggregate, and key-switch component roots',
                verifierClosedStatus:
                    'relation-transcript-and-bound-checks-verifier-closed',
                accountingStatus:
                    'repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted',
            },
            {
                proofFamily: 'galois-key-share',
                claimScope:
                    'Galois key-share relation bound to the required automorphism schedule and key-switch component roots',
                verifierClosedStatus:
                    'relation-transcript-and-bound-checks-verifier-closed',
                accountingStatus:
                    'repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted',
            },
        ],
        challengeAccounting: {
            transform: 'Fiat-Shamir',
            challengeDomain: setupProofChallengeDomain,
            challengeDomainHash: challengeBinding.challengeDomainHash,
            challengeSampler: setupProofChallengeSampler,
            challengeSpace: setupProofChallengeSpace,
            challengeDifferenceInvertibilityStatus:
                challengeBinding.challengeDifferenceInvertibilityStatus,
            challengeDifferenceInvertibilityAccounting:
                challengeBinding.challengeDifferenceInvertibilityAccounting,
            challengeSpaceAudit,
            challengeSpaceAuditHash: kernel.deriveProtocolHash({
                namespace: setupProofChallengeSpaceAuditHashNamespace,
                value: challengeSpaceAudit,
            }),
            randomOracleModel:
                'repo-owned Fiat-Shamir/QROM accounting accepted for claim-bearing proof acceptance',
            qromStatus: 'qrom-reduction-theorem-accepted-for-setup-proof-claim',
            transcriptBinding: challengeBinding.transcriptBinding,
        },
        tboxAccounting: {
            tboxProfileHashBinding:
                'all-required-setup-proof-tbox-profile-hashes-bound',
            requiredFamilies: setupProofFamilies,
            accountingStatus:
                'generated-lower-protocol-tbox-profile-verifier-and-prover-closed',
            status: 'generated lower-protocol tbox suffix is verifier-enforced across quadratic, range, z3/z4 challenge-equation, norm-proof, hint, and Gaussian checks',
        },
        completionBoundary:
            'claim-bearing accepted setup is a repo-owned library claim and does not require external validation or a third-party review gate',
        certificateStatus: 'claim-bearing-setup-proof-accounting-accepted',
    };

    return {
        ...certificate,
        setupProofAccountingCertificateHash: kernel.deriveProtocolHash({
            namespace: 'SetupProofAccountingCertificateHash',
            value: certificate,
        }),
    };
}

function acceptedSetupProofAccountingCertificate(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const acceptedCertificateTemplates = optionalJsonRecord(
        (profile as unknown as JsonRecord).acceptedCertificateTemplates,
        'profile.acceptedCertificateTemplates',
    );
    const template =
        acceptedCertificateTemplates?.setupProofAccountingCertificate;
    if (template !== undefined) {
        return cloneJsonRecord(
            jsonRecord(
                template,
                'profile.acceptedCertificateTemplates.setupProofAccountingCertificate',
            ),
        );
    }

    return fallbackAcceptedSetupProofAccountingCertificate(kernel, profile);
}

function fallbackAcceptedHeSecurityCertificate(
    kernel: TranscriptCoreKernel,
    setupProfile: BgvCollectiveSetupProfileDescription,
    bgvProfile: BgvRnsProfileDescription,
): JsonRecord {
    const dataPrimes = bgvProfile.profile.dataPrimes;
    const dataPrimeProductDecimal = moduliProductDecimal(dataPrimes);
    const largestExposedModulusBits = moduliBitLengthSum(dataPrimes);
    const extendedUtilityCeilLog2Product = moduliBitLengthSum([
        ...dataPrimes,
        bgvProfile.profile.specialPrime,
    ]);
    const postQuantumMaximumLogQ = 827;
    const classicalMaximumLogQ = 881;
    const postQuantumAccepted =
        largestExposedModulusBits <= postQuantumMaximumLogQ;
    const classicalAccepted = largestExposedModulusBits <= classicalMaximumLogQ;
    const acceptedForDirectEvaluatorReplay =
        postQuantumAccepted && classicalAccepted;
    const acceptedRelinearizationKeyPolynomials =
        keySwitchComponentPolynomialCount(
            setupProfile.evaluatorKeyScheduleProfile
                .relinearizationLevelSchedule,
        );
    const acceptedGaloisKeyPolynomials = keySwitchComponentPolynomialCount(
        setupProfile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule,
    );
    const certificate = {
        objectType: 'BgvHeSecurityCertificate',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        profileId: bgvProfile.profile.profileId,
        backendProfileId: bgvProfile.profile.backendProfileId,
        setupProfileHash: setupProfile.setupProfileHash,
        qShareHash: setupProfile.qShareHash,
        setupProofProfileHash: setupProfile.setupProofProfileHash,
        evaluatorKeyScheduleProfileHash:
            setupProfile.evaluatorKeyScheduleProfileHash,
        certificateScope:
            'first-profile-accepted-setup-direct-evaluator-replay-Q-data-boundary',
        reference: {
            document: 'ACC18 Homomorphic Encryption Standard',
            localReferencePath:
                'reference-documents/ACC18_Homomorphic Encryption Standard.txt',
            sections: [
                'Section 2.1.3 secret key distribution',
                'Table 1 BKZ.sieve ternary n=32768 row',
                'Table 2 BKZ.qsieve ternary n=32768 row',
            ],
            tableScope: 'power-of-two cyclotomic RLWE parameter table',
        },
        assessedRing: {
            polynomialDegree: bgvProfile.profile.polynomialDegree,
            plaintextModulus: bgvProfile.profile.plaintextModulus,
            dataBasisId: bgvProfile.profile.dataBasisId,
            dataPrimeCount: dataPrimes.length,
            dataPrimeProductDecimal,
            dataPrimeCeilLog2Product: largestExposedModulusBits,
            qSharePrimeCount: dataPrimes.length,
            qSharePrimeProductDecimal: dataPrimeProductDecimal,
            qShareCeilLog2Product: largestExposedModulusBits,
            specialPrime: bgvProfile.profile.specialPrime,
            extendedUtilityCeilLog2Product,
            extendedUtilityExposureStatus:
                'not-exposed-by-current-accepted-direct-evaluator-replay-material',
            largestExposedBasisClass: 'Q_data',
            largestExposedModulusBits,
        },
        secretDistribution: {
            distributionKind: 'standard-ternary-collective-secret',
            support: [-1, 0, 1],
            isPlainDenseTernary: true,
            estimatorModel: 'HE-standard-ternary',
            source: 'recipient-verified-VSS same-secret commitments',
        },
        errorDistribution: {
            distributionKind: 'centered-binomial-eta2',
            support: [-2, -1, 0, 1, 2],
            keySwitchNoiseDistribution: 'centered-binomial-eta2',
            certificateStatus:
                'accepted-support-recorded-proof-family-checks-still-required',
        },
        publicSampleAccounting: {
            publicKeyCrpPolynomials: 1,
            publicKeyShareCount: firstProfileParticipantCount,
            acceptedRelinearizationKeyPolynomials,
            acceptedGaloisKeyPolynomials,
            scheduledRelinearizationLevelCount:
                setupProfile.evaluatorKeyScheduleProfile
                    .relinearizationLevelSchedule.length,
            scheduledGaloisKeyCount:
                setupProfile.evaluatorKeyScheduleProfile
                    .requiredGaloisKeySchedule.length,
            evaluationKeyExposureStatus:
                'root-bound-relinearization-and-galois-key-material-counted-for-direct-evaluator-replay-HE-boundary',
            commitmentAndSetupProofPublicMatrices:
                'covered-by-setup-commitment-and-setup-proof profiles, not counted as HE RLWE public-key samples',
        },
        standardRows: {
            postQuantumTernary128: {
                status: postQuantumAccepted
                    ? 'accepted'
                    : 'rejected-largest-exposed-modulus-exceeds-row',
                costModel: 'BKZ.qsieve',
                secretDistribution: 'ternary',
                polynomialDegree: 32_768,
                securityLevelBits: 128,
                maximumLogQ: postQuantumMaximumLogQ,
                largestExposedModulusBits,
                marginBits: Math.max(
                    postQuantumMaximumLogQ - largestExposedModulusBits,
                    0,
                ),
                uSVPBits: '128.1',
                decodingBits: '128.7',
                dualBits: '128.4',
            },
            classicalTernary128: {
                status: classicalAccepted
                    ? 'accepted'
                    : 'rejected-largest-exposed-modulus-exceeds-row',
                costModel: 'BKZ.sieve',
                secretDistribution: 'ternary',
                polynomialDegree: 32_768,
                securityLevelBits: 128,
                maximumLogQ: classicalMaximumLogQ,
                largestExposedModulusBits,
                marginBits: Math.max(
                    classicalMaximumLogQ - largestExposedModulusBits,
                    0,
                ),
                uSVPBits: '128.5',
                decodingBits: '129.1',
                dualBits: '128.5',
            },
        },
        estimatorBinding: {
            status: acceptedForDirectEvaluatorReplay
                ? 'accepted-by-local-HE-standard-table-row'
                : 'rejected-by-local-HE-standard-table-row',
            tool: 'HE-standard published parameter table',
            toolVersion: 'ACC18 local text reference',
            securityEstimatorInputHash: bgvProfile.securityEstimatorInputHash,
            secretModel: 'standard-ternary',
            errorModel: 'centered-binomial-eta2',
            largestExposedModulusBits,
            publicSamplesBound: true,
        },
        targetDecryptionStatus: {
            targetDecryptionProfileId: 'BGV-RNS-AsyncTargetDecryption-v1',
            qTargetKnown: false,
            qTargetCoveredByCertificate: false,
            targetC1ThroughC4Covered: false,
            targetDecryptionReadiness:
                'refused-until-q-target-certificate-closes',
        },
        acceptedForDirectEvaluatorReplay,
        acceptedForTargetDecryption: false,
        statusLabels: acceptedForDirectEvaluatorReplay
            ? [
                  'HEStandardPostQuantum128Accepted',
                  'HEStandardClassical128Accepted',
                  'DataBasisLargestExposedModulusAccepted',
                  'SpecialPrimeNotPubliclyExposedOnAcceptedPath',
                  'TargetDecryptionReadinessRefusedUntilQTargetCertificate',
              ]
            : [
                  'HEStandardSecurityRejected',
                  'DataBasisLargestExposedModulusRejected',
              ],
    };

    return {
        ...certificate,
        heSecurityCertificateHash: kernel.deriveProtocolHash({
            namespace: 'BGVHeSecurityCertificateHash',
            value: certificate,
        }),
    };
}

function acceptedHeSecurityCertificate(
    kernel: TranscriptCoreKernel,
    setupProfile: BgvCollectiveSetupProfileDescription,
    bgvProfile: BgvRnsProfileDescription,
): JsonRecord {
    const acceptedCertificateTemplates = optionalJsonRecord(
        (setupProfile as unknown as JsonRecord).acceptedCertificateTemplates,
        'setupProfile.acceptedCertificateTemplates',
    );
    const template = acceptedCertificateTemplates?.heSecurityCertificate;
    if (template !== undefined) {
        return cloneJsonRecord(
            jsonRecord(
                template,
                'setupProfile.acceptedCertificateTemplates.heSecurityCertificate',
            ),
        );
    }

    return fallbackAcceptedHeSecurityCertificate(
        kernel,
        setupProfile,
        bgvProfile,
    );
}

function acceptedSetupTransportCertificate(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
    vssCoefficientCommitmentMaterial: JsonRecord,
): JsonRecord {
    const fullObjectHash = kernel.deriveProtocolHash({
        namespace: 'SetupTransportChunkManifestRoot',
        value: {
            fixture: 'setup-transport-full-object-hash',
            totalByteLength: setupTransportTotalByteLength,
        },
    });
    const chunkHashes = Array.from(
        { length: setupTransportChunkCount },
        (_unused, chunkIndex) =>
            kernel.deriveProtocolHash({
                namespace: 'SetupTransportChunkManifestRoot',
                value: {
                    fixture: 'setup-transport-chunk-hash',
                    chunkIndex,
                },
            }),
    );
    const chunkRoot = kernel.deriveProtocolHash({
        namespace: 'SetupTransportChunkManifestRoot',
        value: {
            objectType: 'SetupTransportChunkManifest',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
            chunkSizeBytes: setupTransportChunkSizeBytes,
            chunkCount: setupTransportChunkCount,
            totalByteLength: setupTransportTotalByteLength,
            chunkHashes,
            fullObjectHash,
        },
    });
    const certificate = {
        objectType: 'SetupTransportCertificate',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        transportProfileId: 'sealed-lattice-setup-binary-chunked-transport-v1',
        setupTransportProfileHash: profile.setupTransportProfileHash,
        largeObjectEncoding: 'binary',
        chunking: 'required',
        chunkSizeBytes: setupTransportChunkSizeBytes,
        chunkCount: setupTransportChunkCount,
        totalByteLength: setupTransportTotalByteLength,
        storageQuotaBytes: 2_147_483_648,
        largestSingleBufferBytes: 1_572_864,
        copyCountLimit: 2,
        streamVerificationOrder: 'ascending-chunk-index',
        resumePolicy: 'chunk-index-checkpointed-by-hash',
        lazyLoadingPolicy: 'root-addressed-large-object-loading',
        transportedObjects: [
            {
                objectType: 'SetupTransportedObject',
                objectVersion: 1,
                objectName: 'vssCoefficientCommitmentMaterial',
                objectRole: 'public-vss-coefficient-commitment-material',
                objectRoot: String(
                    vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot,
                ),
                byteLength: setupTransportTotalByteLength,
                chunkStartIndex: 0,
                chunkCount: setupTransportChunkCount,
                chunkRoot,
                fullObjectHash,
                encoding: 'binary',
                loadingPolicy: 'stream-verified-before-object-use',
            },
        ],
        chunkHashes,
        chunkRoot,
        fullObjectHash,
    };

    return {
        ...certificate,
        setupTransportCertificateHash: kernel.deriveProtocolHash({
            namespace: 'SetupTransportCertificateHash',
            value: certificate,
        }),
    };
}

const acceptedShapedSetupPackageCacheByProfileKey = new Map<
    string,
    Promise<string>
>();

function acceptedShapedSetupPackageCacheKey(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): string {
    const bgvProfile = kernel.describeBgvRnsProfile();

    return [
        profile.setupProfileId,
        profile.setupProfileHash,
        profile.qShareHash,
        profile.carryAwareVssShareRelationProfileHash,
        profile.commitmentProfileHash,
        bgvProfile.profileHash,
        bgvProfile.backendProfileHash,
    ].join('|');
}

function optionalHashFromRecord(
    record: JsonRecord,
    fieldName: string,
): string | null {
    const value = record[fieldName];
    if (value === undefined) {
        return null;
    }
    if (typeof value !== 'string' || !protocolHashPattern.test(value)) {
        throw new Error(`${fieldName} must be a protocol hash.`);
    }

    return value;
}

function optionalNestedHashFromRecord(
    record: JsonRecord,
    objectFieldName: string,
    hashFieldName: string,
): string | null {
    const objectValue = record[objectFieldName];
    if (
        typeof objectValue !== 'object' ||
        objectValue === null ||
        Array.isArray(objectValue)
    ) {
        return null;
    }

    return optionalHashFromRecord(objectValue as JsonRecord, hashFieldName);
}

function acceptedActiveStaticSetupTheoremCertificate(
    kernel: TranscriptCoreKernel,
    setupPackage: JsonRecord,
): JsonRecord {
    const setupContext = setupPackage.setupContext as JsonRecord;
    const evaluationKeys = setupPackage.evaluationKeys;
    const evaluationKeysDeclared =
        typeof evaluationKeys === 'object' &&
        evaluationKeys !== null &&
        !Array.isArray(evaluationKeys) &&
        Object.keys(evaluationKeys).length > 0;
    const certificate = {
        objectType: 'ActiveStaticSetupTheoremCertificate',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        ceremonyId: setupContext.ceremonyId,
        manifestHash: setupContext.manifestHash,
        rosterHash: setupContext.rosterHash,
        setupProfileHash: setupContext.setupProfileHash,
        qShareHash: setupContext.qShareHash,
        carryAwareVssShareRelationProfileHash:
            setupContext.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: setupContext.commitmentProfileHash,
        setupEpoch: setupContext.setupEpoch,
        adversaryModel: {
            corruptionTiming: 'active-static',
            maliciousBehavior:
                'arbitrary-invalid-public-setup-artifacts-and-abort',
            secretConfidentialityCorruptTrusteeBound:
                firstProfileDecryptionThreshold - 1,
            fullRosterSetupCompletionRequired: true,
        },
        livenessModel: {
            model: 'secure-with-abort',
            setupCompletionQuorum: firstProfileParticipantCount,
            participantCount: firstProfileParticipantCount,
            acceptedAbortEvents: [
                'missing required setup phase object',
                'malformed public setup object',
                'invalid private VSS acceptance state',
                'invalid setup proof or proof material root',
                'invalid collective public-key or evaluation-key root',
                'unsupported target-decryption readiness claim',
            ],
            notClaimed: [
                'guaranteed output delivery',
                'identifiable abort',
                'post-setup target decryption',
                'production audit readiness',
            ],
        },
        verifiedSetupGates: [
            'setup context and package hash bind the ceremony, roster, manifest, profile, Q_share, commitment profile, and setup epoch',
            'full-roster common randomness commit/reveal records derive public setup matrices before proof and key verification',
            'public VSS coefficient commitments and recipient-local signed acceptances are checked before threshold-share commitment derivation',
            'threshold-share commitment roots are verifier-derived from public VSS commitments, not source-trustee supplied',
            'same-secret, public-key share, relinearization, and Galois proof records are verified before key roots are accepted',
            'collective public-key coefficients and public evaluation-key roots are verifier-recomputed from proof-bearing setup records',
            'setup commitment, proof-accounting, transport, HE, and key-correctness certificates are root-bound package objects',
            'generic key-switch material, unscheduled Galois keys, raw setup witnesses, raw shares, external aggregate public-key material, and premature target-decryption readiness are refused',
        ],
        dependencyHashes: {
            setupCommitmentSecurityCertificateHash:
                setupPackage.setupCommitmentSecurityCertificateHash,
            setupTransportCertificateHash:
                setupPackage.setupTransportCertificateHash,
            setupProofAccountingCertificateHash:
                setupPackage.setupProofAccountingCertificateHash,
            heSecurityCertificateHash: setupPackage.heSecurityCertificateHash,
            setupKeyCorrectnessCertificateHash: optionalHashFromRecord(
                setupPackage,
                'setupKeyCorrectnessCertificateHash',
            ),
        },
        terminalRoots: {
            thresholdShareCommitmentRoot: optionalHashFromRecord(
                setupPackage,
                'thresholdShareCommitmentRoot',
            ),
            sameSecretProofSetRoot: optionalNestedHashFromRecord(
                setupPackage,
                'sameSecretProofs',
                'sameSecretProofSetRoot',
            ),
            publicKeyShareMaterialSetRoot: optionalNestedHashFromRecord(
                setupPackage,
                'publicKeyShareMaterial',
                'publicKeyShareMaterialSetRoot',
            ),
            publicKeyShareLnpProofSetRoot: optionalNestedHashFromRecord(
                setupPackage,
                'publicKeyShareLnpProofs',
                'publicKeyShareLnpProofSetRoot',
            ),
            collectivePublicKeyRoot: optionalNestedHashFromRecord(
                setupPackage,
                'collectivePublicKey',
                'collectivePublicKeyRoot',
            ),
            evaluatorKeyScheduleRoot: optionalNestedHashFromRecord(
                setupPackage,
                'evaluatorKeySchedule',
                'evaluatorKeyScheduleRoot',
            ),
            evaluationKeySetHash: optionalNestedHashFromRecord(
                setupPackage,
                'evaluationKeys',
                'evaluationKeySetHash',
            ),
            publicEvaluationKeyMaterialRoot: optionalNestedHashFromRecord(
                setupPackage,
                'evaluationKeys',
                'publicEvaluationKeyMaterialRoot',
            ),
        },
        referenceRows: [
            {
                document: 'BCD25_Threshold (Fully) Homomorphic Encryption',
                localReferencePath:
                    'reference-documents/BCD25_Threshold (Fully) Homomorphic Encryption.txt',
                sections: [
                    'active-with-abort security model',
                    'static malicious adversaries',
                    'threshold FHE setup and abort boundaries',
                ],
            },
            {
                document:
                    'LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General',
                localReferencePath:
                    'reference-documents/LNP22_Lattice-Based Zero-Knowledge Proofs and Applications Shorter, Simpler, and More General.txt',
                sections: [
                    'Fiat-Shamir with aborts',
                    'commit-and-prove simulatability',
                    'knowledge soundness',
                ],
            },
            {
                document:
                    'BFM25_Threshold FHE with Efficient Asynchronous Decryption',
                localReferencePath:
                    'reference-documents/BFM25_Threshold FHE with Efficient Asynchronous Decryption.txt',
                sections: [
                    'malicious participant detection',
                    'setup preprocessing',
                    'abort behavior',
                ],
            },
        ],
        claimBoundary: {
            certificateStatus:
                'active-static-secure-with-abort-theorem-accepted',
            evaluationKeyCorrectnessStatus: evaluationKeysDeclared
                ? 'requires-setup-key-correctness-certificate'
                : 'no-public-evaluation-key-runtime-material-declared',
            remainingDependencies: [],
            integrationDependencies: [],
            completionBoundary:
                'external validation, independent audit, and third-party proof review are not setup completion prerequisites',
        },
    };

    return {
        ...certificate,
        activeStaticSetupTheoremCertificateHash: kernel.deriveProtocolHash({
            namespace: 'ActiveStaticSetupTheoremCertificateHash',
            value: certificate,
        }),
    };
}

async function buildAcceptedShapedSetupPackage(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): Promise<JsonRecord> {
    const bgvProfile = kernel.describeBgvRnsProfile();
    let previousPhaseRoot: string | null = null;
    const setupContext = {
        ceremonyId: setupRequest.ceremonyId,
        manifestHash: setupRequest.manifestHash,
        rosterHash: setupRequest.rosterHash,
        setupProfileHash: profile.setupProfileHash,
        qShareHash: profile.qShareHash,
        carryAwareVssShareRelationProfileHash:
            profile.carryAwareVssShareRelationProfileHash,
        commitmentProfileHash: profile.commitmentProfileHash,
        setupEpoch: 'setup-epoch-1',
        participantCount: firstProfileParticipantCount,
        qSetupComplete: 10,
        qBallotRelease: 10,
        qFinal: 10,
        qDec: firstProfileDecryptionThreshold,
    } satisfies CollectiveBgvSetupContext;
    const phaseTranscript: JsonRecord[] = [];
    for (const phase of profile.phaseOrder) {
        const participantPhaseObjects = await Promise.all(
            Array.from({ length: 10 }, async (_unusedSlot, rosterPosition) => {
                const trusteeIdentity = `trustee-${String(rosterPosition)}`;
                const signatureSeedLabel = `${trusteeIdentity}-${phase.phaseId}`;
                const keyFixture =
                    createMlDsaKeyPairFixture(signatureSeedLabel);
                const mailboxKeyPair =
                    privateVssMailboxKeyPairForRosterPosition(rosterPosition);
                const signRoot: ProtocolRootSigner = (signedRoot) =>
                    createProtocolSignatureFixture({
                        profile: createMlDsaSignatureProfileFixture(),
                        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
                        publicKeyHash: keyFixture.publicKeyHash,
                        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
                        signedRoot,
                    });

                return createSetupPhaseParticipantObject({
                    setupContext,
                    phaseId: phase.phaseId,
                    phaseNumber: phase.phaseNumber,
                    trusteeIdentity,
                    rosterPosition,
                    recoveryEpoch: 0,
                    deviceEpoch: 0,
                    signingPublicKeyHash: keyFixture.publicKeyHash,
                    ...(phase.phaseId === 'setupIntent'
                        ? {
                              privateVssMailboxPublicKeyHash:
                                  mailboxKeyPair.publicKeyHash,
                              privateVssMailboxPublicKeyBytesHash:
                                  privateVssMailboxPublicKeyBytesHash(
                                      mailboxKeyPair.publicKeyBytesHex,
                                  ),
                          }
                        : {}),
                    signRoot,
                });
            }),
        );
        const phaseRecord = createSetupPhaseRecord({
            setupContext,
            phaseId: phase.phaseId,
            phaseNumber: phase.phaseNumber,
            previousPhaseRoot,
            participantPhaseObjects,
        });
        phaseTranscript.push(phaseRecord);
        previousPhaseRoot = phaseRecord.phaseRoot;
    }
    const commonRandomness = acceptedCommonRandomness(kernel, profile);
    const vssCoefficientCommitmentBundle = acceptedVssCoefficientCommitments(
        setupContext,
        profile,
        String(commonRandomness.publicMatrixSeedHash),
    );
    const vssCoefficientCommitments =
        vssCoefficientCommitmentBundle.commitmentSet;
    const vssCoefficientCommitmentMaterial =
        vssCoefficientCommitmentBundle.materialSet;
    const thresholdShareCommitments = kernel.deriveThresholdShareCommitments({
        setupContext,
        publicMatrixSeedHash: String(commonRandomness.publicMatrixSeedHash),
        sourceTrusteeCoefficientCommitmentRecords:
            vssCoefficientCommitments.sourceTrusteeRecords.map(
                (sourceTrusteeRecord) => sourceTrusteeRecord as JsonRecord,
            ),
        coefficientCommitments:
            vssCoefficientCommitmentMaterial.coefficientCommitments.map(
                (coefficientCommitment) => coefficientCommitment as JsonRecord,
            ),
    }).thresholdShareCommitments;
    const privateVssEnvelopeCommitments =
        await acceptedPrivateVssEnvelopeCommitments(
            kernel,
            profile,
            setupContext,
            commonRandomness,
            vssCoefficientCommitments,
            vssCoefficientCommitmentBundle.privateOpeningMaterialBySourceTrustee,
        );
    const publicPrivateVssEnvelopeCommitments =
        publicPrivateVssEnvelopeCommitmentSet(privateVssEnvelopeCommitments);
    const privateVssEnvelopeCommitmentRoot = String(
        privateVssEnvelopeCommitments.privateVssEnvelopeCommitmentRoot,
    );
    const vssShareAcceptances = await acceptedVssShareAcceptances(
        setupContext,
        publicPrivateVssEnvelopeCommitments,
    );
    const sameSecretConsistency = acceptedSameSecretConsistency(
        setupContext,
        profile,
        vssCoefficientCommitments,
    );
    const publicKeyShares = acceptedPublicKeyShares(
        kernel,
        setupContext,
        profile,
        commonRandomness,
        sameSecretConsistency,
    );
    const publicKeyShareProofs = acceptedPublicKeyShareProofs(
        setupContext,
        profile,
        commonRandomness,
        sameSecretConsistency,
        publicKeyShares,
    );
    const evaluatorKeySchedule = acceptedEvaluatorKeySchedule(
        setupContext,
        profile,
        commonRandomness,
        sameSecretConsistency,
        publicKeyShares,
        publicKeyShareProofs,
    );
    const setupCommitmentSecurityCertificate =
        acceptedSetupCommitmentSecurityCertificate(kernel, profile);
    const setupProofAccountingCertificate =
        acceptedSetupProofAccountingCertificate(kernel, profile);
    const heSecurityCertificate = acceptedHeSecurityCertificate(
        kernel,
        profile,
        bgvProfile,
    );
    const setupTransportCertificate = acceptedSetupTransportCertificate(
        kernel,
        profile,
        vssCoefficientCommitmentMaterial,
    );
    const setupPackage: JsonRecord = {
        objectType: 'SetupPackage',
        objectVersion: 1,
        setupProfileId: 'CollectiveBgvSetup-v1',
        setupContext,
        qShare: profile.qShare,
        phaseTranscript,
        commonRandomness,
        vssCoefficientCommitments,
        vssCoefficientCommitmentMaterial,
        privateVssEnvelopeCommitments: publicPrivateVssEnvelopeCommitments,
        privateVssEnvelopeCommitmentRoot,
        vssShareAcceptances,
        thresholdShareCommitments,
        sameSecretConsistency,
        publicKeyShares,
        publicKeyShareProofs,
        evaluatorKeySchedule,
        relinearizationKeyShareRounds: {},
        galoisKeyShareBatches: [],
        trusteeEvaluationKeyProofs: {},
        evaluationKeys: {},
        setupCommitmentSecurityCertificate,
        setupCommitmentSecurityCertificateHash:
            setupCommitmentSecurityCertificate.setupCommitmentSecurityCertificateHash,
        setupTransportCertificate,
        setupTransportCertificateHash:
            setupTransportCertificate.setupTransportCertificateHash,
        setupProofAccountingCertificate,
        setupProofAccountingCertificateHash:
            setupProofAccountingCertificate.setupProofAccountingCertificateHash,
        heSecurityCertificate,
        heSecurityCertificateHash:
            heSecurityCertificate.heSecurityCertificateHash,
    };
    const activeStaticSetupTheoremCertificate =
        acceptedActiveStaticSetupTheoremCertificate(kernel, setupPackage);
    setupPackage.activeStaticSetupTheoremCertificate =
        activeStaticSetupTheoremCertificate;
    setupPackage.activeStaticSetupTheoremCertificateHash =
        activeStaticSetupTheoremCertificate.activeStaticSetupTheoremCertificateHash;
    rebindCollectiveSetupPackageHash(kernel, setupPackage);

    return setupPackage;
}

async function acceptedShapedSetupPackage(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): Promise<JsonRecord> {
    const cacheKey = acceptedShapedSetupPackageCacheKey(kernel, profile);
    let acceptedShapedSetupPackageJson =
        acceptedShapedSetupPackageCacheByProfileKey.get(cacheKey);
    if (acceptedShapedSetupPackageJson === undefined) {
        acceptedShapedSetupPackageJson = buildAcceptedShapedSetupPackage(
            kernel,
            profile,
        ).then((setupPackage) => JSON.stringify(setupPackage));
        acceptedShapedSetupPackageCacheByProfileKey.set(
            cacheKey,
            acceptedShapedSetupPackageJson,
        );
    }

    const setupPackage: unknown = JSON.parse(
        await acceptedShapedSetupPackageJson,
    );
    if (
        typeof setupPackage !== 'object' ||
        setupPackage === null ||
        Array.isArray(setupPackage)
    ) {
        throw new Error('Cached accepted setup package must be a JSON object.');
    }

    return setupPackage as JsonRecord;
}

describe('collective BGV setup kernel commands', () => {
    it('describes the accepted setup profile and compact verifier states', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();

        expect(profile).toMatchObject({
            setupProfileId: 'CollectiveBgvSetup-v1',
            objectType: 'SetupPackage',
            adversaryModel: 'active-static',
            livenessModel: 'secure-with-abort',
            sharingModel: 'recipient-verified-vss',
            sharingDomain: 'per-rns-prime',
            participantCount: 10,
            qSetupComplete: 10,
            qBallotRelease: 10,
            qFinal: 10,
            qDec: 4,
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
        });
        expect(profile.qShare).toMatchObject({
            objectType: 'QSharePrimeList',
            sharingDomain: 'per-rns-prime',
            primeOrder: 'profile-order',
        });
        expect(profile.qShare.primes.length).toBeGreaterThan(0);
        expect(profile.qShareHash).toHaveLength(128);
        expect(
            profile.commitmentProfile.assumptions.parameterAcceptanceStatus,
        ).toBe('claim-bearing-setup-commitment-parameter-accounting-accepted');
        expect(profile.publicVssCommitmentMaterialSizeProfile).toMatchObject({
            objectType: 'PublicVssCommitmentMaterialSizeProfile',
            ringDegree: 32768,
            ringDegreeStatus: 'profile-ring',
            fullMaterialCoefficientBytes: 1_604_321_280,
            fullMaterialCoefficientMebibytes: 1530,
            streamingRequirement:
                'binary-chunked-stream-verification-with-one-commitment-resident',
        });
        expect(profile.publicVssCommitmentMaterialSizeProfileHash).toHaveLength(
            128,
        );
        expect(profile.setupTransportProfile).toMatchObject({
            objectType: 'SetupTransportProfile',
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
            chunkSizeBytes: setupTransportChunkSizeBytes,
            storageQuotaBytes: 2_147_483_648,
            largestSingleBufferBytes: 1_572_864,
            streamVerificationOrder: 'ascending-chunk-index',
            lazyLoadingPolicy: 'root-addressed-large-object-loading',
        });
        expect(profile.setupTransportProfileHash).toHaveLength(128);
        expect(profile.carryAwareVssShareRelationProfile).toMatchObject({
            objectType: 'CarryAwareVssShareRelationProfile',
            sharingDomain: 'per-rns-prime',
            carryWitnessDomain: 'non-negative-bounded-integer',
        });
        expect(profile.carryAwareVssShareRelationProfileHash).toHaveLength(128);
        expect(profile.commitmentProfile).toMatchObject({
            objectType: 'BdlopLnpCommitmentProfile',
        });
        expect(profile.commitmentProfile.messageEncoding).toMatchObject({
            integerEncoding: 'crt-lifted-integer-coefficients',
        });
        expect(profile.commitmentProfileHash).toHaveLength(128);
        expect(profile.evaluatorKeyScheduleProfile).toMatchObject({
            objectType: 'EvaluatorKeyScheduleProfile',
            genericKeySwitchPolicy: 'refused-unless-explicitly-required',
            genericKeySwitchProofStatus: 'not-required-for-first-profile',
        });
        expect(
            profile.evaluatorKeyScheduleProfile.relinearizationLevelSchedule,
        ).not.toHaveLength(0);
        expect(
            profile.evaluatorKeyScheduleProfile.requiredGaloisKeySchedule,
        ).not.toHaveLength(0);
        expect(
            profile.evaluatorKeyScheduleProfile.requiredGaloisSetHash,
        ).toHaveLength(128);
        expect(profile.evaluatorKeyScheduleProfileHash).toHaveLength(128);
        expect(profile.verifierStatuses).toEqual([
            'accepted',
            'pending',
            'refused',
            'aborted',
            'forkDetected',
            'outsideProfile',
        ]);
        expect(profile.phaseOrder).toHaveLength(14);
        expect(profile.requiredFinalObjects).toContain(
            'setupTransportCertificate',
        );
    });

    it('classifies passive setup packages as outside profile', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const passiveSetup = kernel.generateBgvPassiveSetup(setupRequest);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage: passiveSetup,
        });

        expect(result).toMatchObject({
            ok: false,
            operation: 'verifyCollectiveBgvSetupPackage',
            setupProfileId: 'CollectiveBgvSetup-v1',
            verifierStatus: 'outsideProfile',
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'outsideCollectiveBgvSetupProfile',
        );
        expect(result.acceptedSetupHandoff).toBeUndefined();
    });

    it('maps malformed accepted setup command errors to neutral protocol errors', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() => {
            kernel.verifyCollectiveBgvSetup({
                setupPackage: undefined,
            });
        }).toThrow(TranscriptCoreKernelCommandError);

        let thrownError: unknown;
        try {
            kernel.verifyCollectiveBgvSetup({
                setupPackage: undefined,
            });
            throw new Error('verifyCollectiveBgvSetup should have failed.');
        } catch (error) {
            thrownError = error;
        }
        expect(thrownError).toBeInstanceOf(TranscriptCoreKernelCommandError);
        const commandError = thrownError as TranscriptCoreKernelCommandError;
        expect(commandError.code).toBe('InvalidProtocolObject');
        expect(commandError.message).not.toContain('InvalidFixture');
        expect(commandError.message).toContain('setupPackage is required');
    });

    it('reports accepted-shaped setup as pending before reduced-ring public VSS profile checks', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupPackage = await acceptedShapedSetupPackage(kernel, profile);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: setupRequest.rosterHash,
        });

        expect(result).toMatchObject({
            ok: false,
            verifierStatus: 'pending',
            currentPhase: 'setupPackageVerification',
            missingObjects: [
                'sameSecretProofs',
                'publicKeyShareMaterial',
                'publicKeyShareLnpProofs',
                'collectivePublicKey',
                'collectivePublicKeyRoot',
            ],
            refusedObjects: [],
        });
    });

    it('aborts accepted-shaped setup on a protocol-built VSS complaint', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupPackage = await acceptedShapedSetupPackage(kernel, profile);
        setupPackage.vssComplaints = await acceptedVssComplaintSet(
            setupPackage.setupContext as JsonRecord,
            setupPackage.privateVssEnvelopeCommitments as JsonRecord,
        );
        rebindCollectiveSetupPackageHash(kernel, setupPackage);

        const result = kernel.verifyCollectiveBgvSetup({
            setupPackage,
            expectedManifestHash: setupRequest.manifestHash,
            expectedRosterHash: setupRequest.rosterHash,
        });

        expect(result).toMatchObject({
            ok: false,
            verifierStatus: 'aborted',
            currentPhase: 'vssAcceptanceOrComplaint',
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'vssComplaintAcceptedAbort',
        );
        expect(result.acceptedHashes).toContain(
            (setupPackage.vssComplaints as JsonRecord).vssComplaintRoot,
        );
    });

    it('refuses undeclared generic key-switch material', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            profile,
        );
        const genericKeySwitchPackage = cloneJsonRecord(baseSetupPackage);
        genericKeySwitchPackage.genericKeySwitchKeys = {
            keyRoot: validHash('8'),
        };
        rebindCollectiveSetupPackageHash(kernel, genericKeySwitchPackage);

        const genericKeySwitchResult = kernel.verifyCollectiveBgvSetup({
            setupPackage: genericKeySwitchPackage,
        });

        expect(genericKeySwitchResult.verifierStatus).toBe('refused');
        expect(genericKeySwitchResult.refusedObjects[0]?.reasonCode).toBe(
            'genericKeySwitchOutsideProfile',
        );
    });

    it('refuses malformed commitment security certificates', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            profile,
        );
        const malformedCommitmentCertificatePackage =
            cloneJsonRecord(baseSetupPackage);
        const malformedCommitmentCertificate =
            malformedCommitmentCertificatePackage.setupCommitmentSecurityCertificate as JsonRecord;
        (
            malformedCommitmentCertificate.aggregateOpeningBounds as JsonRecord
        ).thresholdShareOpeningInfinityBound = 11_109;
        rebindCollectiveSetupPackageHash(
            kernel,
            malformedCommitmentCertificatePackage,
        );

        const malformedCommitmentCertificateResult =
            kernel.verifyCollectiveBgvSetup({
                setupPackage: malformedCommitmentCertificatePackage,
            });

        expect(malformedCommitmentCertificateResult.verifierStatus).toBe(
            'refused',
        );
        expect(
            malformedCommitmentCertificateResult.refusedObjects[0]?.reasonCode,
        ).toBe('commitmentSecurityCertificatePayloadMismatch');
    });

    it('refuses JSON setup transport certificates', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            profile,
        );
        const jsonTransportPackage = cloneJsonRecord(baseSetupPackage);
        (
            jsonTransportPackage.setupTransportCertificate as JsonRecord
        ).largeObjectEncoding = 'json';
        rebindCollectiveSetupPackageHash(kernel, jsonTransportPackage);

        const jsonTransportResult = kernel.verifyCollectiveBgvSetup({
            setupPackage: jsonTransportPackage,
        });

        expect(jsonTransportResult.verifierStatus).toBe('refused');
        expect(jsonTransportResult.refusedObjects[0]?.reasonCode).toBe(
            'transportEncodingMismatch',
        );
    });

    it('refuses setup transport chunk hash count mismatches', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const baseSetupPackage = await acceptedShapedSetupPackage(
            kernel,
            profile,
        );
        const malformedTransportPackage = cloneJsonRecord(baseSetupPackage);
        const malformedTransportCertificate =
            malformedTransportPackage.setupTransportCertificate as JsonRecord;
        (malformedTransportCertificate.chunkHashes as string[]).pop();
        rebindCollectiveSetupPackageHash(kernel, malformedTransportPackage);

        const malformedTransportResult = kernel.verifyCollectiveBgvSetup({
            setupPackage: malformedTransportPackage,
        });

        expect(malformedTransportResult.verifierStatus).toBe('refused');
        expect(malformedTransportResult.refusedObjects[0]?.reasonCode).toBe(
            'transportChunkHashCountMismatch',
        );
    });

    it('routes private VSS share envelope verification refusals', async () => {
        const kernel = await loadTranscriptCoreKernel();

        const result = kernel.verifyPrivateVssShareEnvelope({
            setupContext: {},
            publicMatrixSeedHash: validHash('1'),
            sourceTrusteeCoefficientCommitmentRecord: {},
            sourceTrusteeCoefficientCommitmentMaterialRecords: [],
            privateEnvelope: {},
        });

        expect(result).toMatchObject({
            ok: false,
            operation: 'verifyPrivateVssShareEnvelope',
            setupProfileId: 'CollectiveBgvSetup-v1',
            verifierStatus: 'refused',
        });
        expect(result.refusedObjects[0]?.reasonCode).toBe(
            'setupContextFieldMissing',
        );
    });

    it('routes threshold share commitment derivation errors', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() => {
            kernel.deriveThresholdShareCommitments({
                setupContext: {},
                publicMatrixSeedHash: validHash('1'),
                sourceTrusteeCoefficientCommitmentRecords: [],
                coefficientCommitments: [],
            });
        }).toThrow(TranscriptCoreKernelCommandError);
        expect(() => {
            kernel.deriveThresholdShareCommitments({
                setupContext: {},
                publicMatrixSeedHash: validHash('1'),
                sourceTrusteeCoefficientCommitmentRecords: [],
                coefficientCommitments: [],
            });
        }).toThrow(/setupContext\.ceremonyId is required/);
    });

    it('verifies protocol-built local trustee setup state commitments', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupContext = {
            ceremonyId: setupRequest.ceremonyId,
            manifestHash: setupRequest.manifestHash,
            rosterHash: setupRequest.rosterHash,
            setupProfileHash: profile.setupProfileHash,
            qShareHash: profile.qShareHash,
            carryAwareVssShareRelationProfileHash:
                profile.carryAwareVssShareRelationProfileHash,
            commitmentProfileHash: profile.commitmentProfileHash,
            setupEpoch: 'setup-epoch-1',
        } satisfies CollectiveBgvSetupContext;
        const localStateCommitment = createLocalTrusteeSetupStateCommitment({
            setupContext,
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            thresholdShareCommitmentRecipientRoot: validHash('1'),
            aggregateThresholdShareRoot: validHash('2'),
            issuedVssAcceptanceRoot: validHash('4'),
            issuedVssComplaintRoots: [validHash('5'), validHash('6')],
        });

        expect(
            collectForbiddenLocalTrusteeSetupStateFieldPaths(
                localStateCommitment,
            ),
        ).toEqual([]);
        expect(
            kernel.verifyLocalTrusteeSetupState({
                setupContext,
                localStateCommitment,
            }),
        ).toMatchObject({
            ok: true,
            operation: 'verifyLocalTrusteeSetupState',
            trusteeIdentity: 'trustee-3',
            trusteeRosterPosition: 3,
            trusteePoint: 4,
            localStateRoot: localStateCommitment.localStateRoot,
            deletionReceiptRoot: localStateCommitment.deletionReceiptRoot,
        });
    });

    it('binds generated proof-shaped private VSS envelope references without embedded ciphertext', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeCollectiveBgvSetupProfile();
        const setupPackage = await acceptedShapedSetupPackage(kernel, profile);
        const trusteeRosterPosition = 3;
        const privateVssEnvelopeCommitments =
            setupPackage.privateVssEnvelopeCommitments as JsonRecord;
        const envelopeReferences = (
            privateVssEnvelopeCommitments.envelopeReferences as JsonRecord[]
        ).filter(
            (envelopeReference) =>
                envelopeReference.recipientRosterPosition ===
                trusteeRosterPosition,
        );
        const envelopeReference = envelopeReferences[0];
        if (envelopeReference === undefined) {
            throw new Error(
                'Missing generated private VSS envelope reference.',
            );
        }

        expect(envelopeReference.encryptedEnvelope).toBeUndefined();
        expect(
            envelopeReference.transportedPrivateVssShareProofMaterial,
        ).toBeUndefined();
        expect(envelopeReference.openingVerificationStatus).toBe(
            'accepted-local-private-vss-opening',
        );
        expect(String(envelopeReference.privateEnvelopeHash)).toMatch(
            protocolHashPattern,
        );
        expect(String(envelopeReference.encryptedEnvelopeHash)).toMatch(
            protocolHashPattern,
        );
        expect(String(envelopeReference.localVerificationRoot)).toMatch(
            protocolHashPattern,
        );
        expect(String(envelopeReference.privateEnvelopeCommitmentRoot)).toMatch(
            protocolHashPattern,
        );
    });

    it('routes local trustee setup state verification errors', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() => {
            kernel.verifyLocalTrusteeSetupState({
                setupContext: {},
                localStateCommitment: {},
            });
        }).toThrow(TranscriptCoreKernelCommandError);
        expect(() => {
            kernel.verifyLocalTrusteeSetupState({
                setupContext: {},
                localStateCommitment: {},
            });
        }).toThrow(/setupContext\.ceremonyId is required/);
    });
});
