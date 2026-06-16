import { expect } from 'vitest';

import { setupRequest, validHash } from '../bgv-passive-setup-fixtures.js';

import {
    cloneJsonRecord,
    coefficientVectorLittleEndianHex,
    deterministicRandomBytes,
    firstProfileDecryptionThreshold,
    firstProfileParticipantCount,
    hexToBytes,
    jsonRecord,
    minimumSuccinctProofFixtureRingDegree,
    privateVssMailboxKeyPairForRosterPosition,
    privateVssMailboxPublicKeyBytesHash,
    protocolHashPattern,
    publicKeyShareCoefficientVectorHash,
    setupTransportChunkCount,
    setupTransportChunkSizeBytes,
    setupTransportTotalByteLength,
    textEncoder,
    type JsonRecord,
} from './setup-fixture-primitives.js';

import {
    hash512Hex,
    privateVssMailboxEncryptionProfileId,
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
    createPrivateVssMailboxDeliverySetFromReferences,
    createPrivateVssMailboxSourceTrusteeDeliveryReferences,
    type PrivateVssEnvelopeCommitment,
    type PrivateVssMailboxDeliverySetInput,
} from '#packages/protocol/src/setup/private-vss-mailbox-delivery';
import {
    createPublicKeyShareMaterialSet,
    createPublicKeyShareProofSet,
    createPublicKeyShareSet,
    createPublicKeyShareSuccinctProofSet,
    publicKeyShareProofFamily,
    type PublicKeyShareContributionInput,
    type PublicKeyShareMaterialContributionInput,
    type PublicKeyShareMaterialSet,
    type PublicKeyShareProofSet,
    type PublicKeyShareSet,
    type PublicKeyShareSuccinctProofMaterial,
    type PublicKeyShareSuccinctProofSet,
} from '#packages/protocol/src/setup/public-key-share-records';
import {
    createSameSecretConsistencyStatementSet,
    createSameSecretProofSet,
    sameSecretProofFamily,
    setupProofProfileId,
    type SameSecretConsistencyStatementSet,
    type SameSecretProofMaterial,
    type SameSecretProofSet,
} from '#packages/protocol/src/setup/same-secret-consistency-records';
import {
    createSetupPhaseParticipantObject,
    createSetupPhaseRecord,
} from '#packages/protocol/src/setup/setup-phase-records';
import {
    createVssCoefficientCommitmentBundle,
    createVssSourceTrusteeCoefficientOpeningState,
    type SetupPackageVssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentBundle,
    type VssCoefficientOpeningMaterial,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeOpeningMaterial,
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
import type {
    BgvCollectiveSetupProfileDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { setupCommitmentComputer } from '#tests/support/setup-commitment-computer';

export function acceptedVssCoefficientCommitments(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    publicMatrixSeedHash: string,
): VssCoefficientCommitmentBundle {
    return createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash,
        setupCommitmentComputer,
        qSharePrimes: profile.qShare.primes,
        ringDegree: minimumSuccinctProofFixtureRingDegree,
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
                    ringDegree: minimumSuccinctProofFixtureRingDegree,
                    thresholdDegree: firstProfileDecryptionThreshold,
                    randomBytes: deterministicRandomBytes(
                        `trustee-${String(sourceTrusteeRosterPosition)}`,
                    ),
                }),
        ),
    });
}

export function acceptedSameSecretConsistency(
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

const sameSecretProofBytesHash = (proofBytesHex: string): string =>
    hash512Hex(
        'sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1',
        [hexToBytes(proofBytesHex)],
    );

export function sameSecretProofsWithDriftedStatementHashes(
    profile: BgvCollectiveSetupProfileDescription,
    setupPackage: JsonRecord,
): SameSecretProofSet {
    const sameSecretConsistency =
        setupPackage.sameSecretConsistency as SameSecretConsistencyStatementSet;
    const setupProofAccountingCertificate = jsonRecord(
        setupPackage.setupProofAccountingCertificate,
        'setupPackage.setupProofAccountingCertificate',
    );
    const proofBytesHex = '00';
    const proofMaterials: SameSecretProofMaterial[] =
        sameSecretConsistency.statementRecords.map((statementRecord) => ({
            setupProofProfileId,
            proofFamily: sameSecretProofFamily,
            trusteeIdentity: statementRecord.trusteeIdentity,
            trusteeRosterPosition: statementRecord.trusteeRosterPosition,
            statementHash: validHash('7'),
            proofSizeBytes: 1,
            proofBytesHash: sameSecretProofBytesHash(proofBytesHex),
            proofBytesHex,
        }));

    return createSameSecretProofSet({
        setupContext: setupPackage.setupContext as CollectiveBgvSetupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        sameSecretConsistency,
        vssCoefficientCommitmentMaterial:
            setupPackage.vssCoefficientCommitmentMaterial as SetupPackageVssCoefficientCommitmentMaterialSet,
        proofAccountingHash: String(
            setupProofAccountingCertificate.sameSecretLinkageAnchorProofAccountingHash,
        ),
        proofMaterials,
    });
}

function requiredVssOpening(
    sourceTrusteeOpeningMaterial: VssSourceTrusteeOpeningMaterial,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
): VssCoefficientOpeningMaterial {
    const opening = sourceTrusteeOpeningMaterial.coefficientOpenings.find(
        (candidateOpening) =>
            candidateOpening.rnsLimbIndex === rnsLimbIndex &&
            candidateOpening.shamirCoefficientIndex === shamirCoefficientIndex,
    );
    if (opening === undefined) {
        throw new Error('VSS opening material is missing a required limb.');
    }

    return opening;
}

const centeredTernaryFromResidue = (
    residue: number,
    modulus: number,
): number => {
    const centeredValue =
        residue > Math.floor(modulus / 2) ? residue - modulus : residue;
    if (![-1, 0, 1].includes(centeredValue)) {
        throw new Error('same-secret fixture coefficient must be ternary.');
    }

    return centeredValue;
};

export function sameSecretProofsWithGeneratedProofs(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
    setupPackage: JsonRecord,
    vssCoefficientCommitmentBundle: VssCoefficientCommitmentBundle,
): SameSecretProofSet {
    const setupContext = setupPackage.setupContext as CollectiveBgvSetupContext;
    const setupProofAccountingCertificate = jsonRecord(
        setupPackage.setupProofAccountingCertificate,
        'setupPackage.setupProofAccountingCertificate',
    );
    const vssCoefficientCommitmentMaterial = jsonRecord(
        setupPackage.vssCoefficientCommitmentMaterial,
        'setupPackage.vssCoefficientCommitmentMaterial',
    );
    const vssCoefficientCommitmentMaterialRoot = String(
        vssCoefficientCommitmentMaterial.vssCoefficientCommitmentMaterialRoot,
    );
    if (
        vssCoefficientCommitmentMaterialRoot !==
        vssCoefficientCommitmentBundle.materialSet
            .vssCoefficientCommitmentMaterialRoot
    ) {
        throw new Error('recomputed VSS material must match setup package.');
    }
    const proofMaterials: SameSecretProofMaterial[] =
        vssCoefficientCommitmentBundle.privateOpeningMaterialBySourceTrustee.map(
            (sourceTrusteeOpeningMaterial) => {
                const firstLimbOpening = requiredVssOpening(
                    sourceTrusteeOpeningMaterial,
                    0,
                    0,
                );
                const secretCoefficients =
                    firstLimbOpening.coefficientMessage.map((residue) =>
                        centeredTernaryFromResidue(
                            residue,
                            firstLimbOpening.rnsPrime,
                        ),
                    );
                const constantCommitments = profile.qShare.primes.map(
                    (_rnsPrime, rnsLimbIndex) => {
                        const materialRecord =
                            sourceTrusteeOpeningMaterial.sourceTrusteeCoefficientCommitmentMaterialRecords.find(
                                (candidateRecord) =>
                                    candidateRecord.rnsLimbIndex ===
                                        rnsLimbIndex &&
                                    candidateRecord.shamirCoefficientIndex ===
                                        0,
                            );
                        if (materialRecord === undefined) {
                            throw new Error(
                                'VSS material is missing a constant commitment.',
                            );
                        }

                        return materialRecord.commitment;
                    },
                );
                const openingRandomnessByLimb = profile.qShare.primes.map(
                    (_rnsPrime, rnsLimbIndex) =>
                        requiredVssOpening(
                            sourceTrusteeOpeningMaterial,
                            rnsLimbIndex,
                            0,
                        ).randomnessByColumn,
                );
                const proofRandomnessLabel = String(
                    sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition,
                );
                const generatedProof = kernel.generateTrusteeEvaluationKeyProof(
                    {
                        context: {
                            ceremonyId: setupContext.ceremonyId,
                            manifestHash: setupContext.manifestHash,
                            rosterHash: setupContext.rosterHash,
                            trusteeIdentity:
                                sourceTrusteeOpeningMaterial.sourceTrusteeIdentity,
                            trusteeRosterPosition:
                                sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition,
                            setupEpoch: setupContext.setupEpoch,
                            vssCoefficientCommitmentMaterialRoot,
                        },
                        ringDegree:
                            vssCoefficientCommitmentBundle.materialSet
                                .ringDegree,
                        keys: [],
                        sameSecretLinkage: {
                            publicMatrixSeedHash:
                                vssCoefficientCommitmentBundle.materialSet
                                    .publicMatrixSeedHash,
                            commitments: constantCommitments,
                        },
                        secretCoefficients,
                        errorCoefficientsByKey: [],
                        negativeIndicatorCoefficients: secretCoefficients.map(
                            (secretCoefficient) =>
                                secretCoefficient < 0 ? 1 : 0,
                        ),
                        openingRandomnessByLimb,
                        proofRandomnessSource:
                            'development-deterministic-fixture',
                        proofRandomnessSeedHex: hash512Hex(
                            'sealed-lattice-test/same-secret-proof-seed-v1',
                            [textEncoder.encode(proofRandomnessLabel)],
                        ),
                        proofRandomnessNonceHex: hash512Hex(
                            'sealed-lattice-test/same-secret-proof-nonce-v1',
                            [textEncoder.encode(proofRandomnessLabel)],
                        ),
                    },
                );
                if (generatedProof.proofFamily !== sameSecretProofFamily) {
                    throw new Error(
                        'generated proof must be a same-secret proof.',
                    );
                }

                return {
                    setupProofProfileId,
                    proofFamily: sameSecretProofFamily,
                    trusteeIdentity:
                        sourceTrusteeOpeningMaterial.sourceTrusteeIdentity,
                    trusteeRosterPosition:
                        sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition,
                    statementHash: generatedProof.statementHash,
                    proofSizeBytes: generatedProof.proofByteLength,
                    proofBytesHash: sameSecretProofBytesHash(
                        generatedProof.proofBytesHex,
                    ),
                    proofBytesHex: generatedProof.proofBytesHex,
                };
            },
        );

    return createSameSecretProofSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        sameSecretConsistency:
            setupPackage.sameSecretConsistency as SameSecretConsistencyStatementSet,
        vssCoefficientCommitmentMaterial:
            setupPackage.vssCoefficientCommitmentMaterial as SetupPackageVssCoefficientCommitmentMaterialSet,
        proofAccountingHash: String(
            setupProofAccountingCertificate.sameSecretLinkageAnchorProofAccountingHash,
        ),
        proofMaterials,
    });
}

const publicKeyShareCoefficients = (
    trusteeRosterPosition: number,
    rnsLimbIndex: number,
    rnsPrime: number,
): readonly number[] =>
    Array.from(
        { length: minimumSuccinctProofFixtureRingDegree },
        (_unusedCoefficient, coefficientIndex) => {
            const value =
                (trusteeRosterPosition + 1) * 101 +
                (rnsLimbIndex + 1) * 29 +
                coefficientIndex * 13;

            return value % rnsPrime;
        },
    );

const acceptedPublicKeyShareMaterialContributions = (
    profile: BgvCollectiveSetupProfileDescription,
): PublicKeyShareMaterialContributionInput[] =>
    Array.from(
        { length: firstProfileParticipantCount },
        (_unusedTrustee, trusteeRosterPosition) => ({
            trusteeIdentity: `trustee-${String(trusteeRosterPosition)}`,
            trusteeRosterPosition,
            shareCoefficientVectorsByLimb: profile.qShare.primes.map(
                (rnsPrime, rnsLimbIndex) => {
                    const coefficients = publicKeyShareCoefficients(
                        trusteeRosterPosition,
                        rnsLimbIndex,
                        rnsPrime,
                    );

                    return {
                        rnsLimbIndex,
                        rnsPrime,
                        component: 'b_i',
                        coefficientByteLength:
                            minimumSuccinctProofFixtureRingDegree * 8,
                        coefficientVectorHash512:
                            publicKeyShareCoefficientVectorHash(coefficients),
                        coefficientsLeHex:
                            coefficientVectorLittleEndianHex(coefficients),
                    };
                },
            ),
        }),
    );

const publicKeyShareContributionsFromMaterial = (
    materialContributions: readonly PublicKeyShareMaterialContributionInput[],
): PublicKeyShareContributionInput[] =>
    materialContributions.map((materialContribution) => ({
        trusteeIdentity: materialContribution.trusteeIdentity,
        trusteeRosterPosition: materialContribution.trusteeRosterPosition,
        shareCoefficientVectorHash512ByLimb:
            materialContribution.shareCoefficientVectorsByLimb.map(
                (coefficientVector) => ({
                    rnsLimbIndex: coefficientVector.rnsLimbIndex,
                    rnsPrime: coefficientVector.rnsPrime,
                    component: coefficientVector.component,
                    coefficientVectorHash512:
                        coefficientVector.coefficientVectorHash512,
                }),
            ),
    }));

export function acceptedPublicKeyShares(
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
        shareContributions: publicKeyShareContributionsFromMaterial(
            acceptedPublicKeyShareMaterialContributions(profile),
        ),
    });
}

export function acceptedPublicKeyShareMaterial(
    setupContext: CollectiveBgvSetupContext,
    profile: BgvCollectiveSetupProfileDescription,
    commonRandomness: JsonRecord,
    publicKeyShares: PublicKeyShareSet,
): PublicKeyShareMaterialSet {
    const publicMatrixSeedHash = String(commonRandomness.publicMatrixSeedHash);
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;

    return createPublicKeyShareMaterialSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        ringDegree: minimumSuccinctProofFixtureRingDegree,
        publicMatrixSeedHash,
        publicKeyCrpRoot: String(crpRoots.publicKeyCrpRoot),
        publicAPolynomialRoot: String(publicA.publicPolynomialRoot),
        publicKeyShares,
        materialContributions:
            acceptedPublicKeyShareMaterialContributions(profile),
    });
}

export function acceptedPublicKeyShareProofs(
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

const publicKeyShareSuccinctProofBytesHash = (proofBytesHex: string): string =>
    hash512Hex(
        'sealed-lattice/setup/public-key-share/succinct-proof-bytes-v1',
        [hexToBytes(proofBytesHex)],
    );

export function publicKeyShareSuccinctProofsWithDriftedStatementHashes(
    profile: BgvCollectiveSetupProfileDescription,
    setupPackage: JsonRecord,
): PublicKeyShareSuccinctProofSet {
    const setupContext = setupPackage.setupContext as CollectiveBgvSetupContext;
    const commonRandomness = setupPackage.commonRandomness as JsonRecord;
    const publicDerivations = commonRandomness.publicDerivations as JsonRecord;
    const crpRoots = publicDerivations.crpRoots as JsonRecord;
    const publicA = publicDerivations.bgvPublicA as JsonRecord;
    const setupProofAccountingCertificate = jsonRecord(
        setupPackage.setupProofAccountingCertificate,
        'setupPackage.setupProofAccountingCertificate',
    );
    const publicKeyShares = setupPackage.publicKeyShares as PublicKeyShareSet;
    const proofBytesHex = '00';
    const proofMaterials: PublicKeyShareSuccinctProofMaterial[] =
        publicKeyShares.shareRecords.map((shareRecord) => ({
            setupProofProfileId,
            proofFamily: publicKeyShareProofFamily,
            trusteeIdentity: shareRecord.trusteeIdentity,
            trusteeRosterPosition: shareRecord.trusteeRosterPosition,
            statementHash: validHash('8'),
            proofSizeBytes: 1,
            proofBytesHash: publicKeyShareSuccinctProofBytesHash(proofBytesHex),
            proofBytesHex,
        }));

    return createPublicKeyShareSuccinctProofSet({
        setupContext,
        qSharePrimes: profile.qShare.primes,
        participantCount: firstProfileParticipantCount,
        publicMatrixSeedHash: String(commonRandomness.publicMatrixSeedHash),
        publicKeyCrpRoot: String(crpRoots.publicKeyCrpRoot),
        publicAPolynomialRoot: String(publicA.publicPolynomialRoot),
        sameSecretConsistency:
            setupPackage.sameSecretConsistency as SameSecretConsistencyStatementSet,
        sameSecretProofs: setupPackage.sameSecretProofs as SameSecretProofSet,
        publicKeyShares,
        publicKeyShareProofs:
            setupPackage.publicKeyShareProofs as PublicKeyShareProofSet,
        publicKeyShareMaterial:
            setupPackage.publicKeyShareMaterial as PublicKeyShareMaterialSet,
        proofAccountingHash: String(
            setupProofAccountingCertificate.publicKeyShareProofAccountingHash,
        ),
        proofMaterials,
    });
}

export function acceptedEvaluatorKeySchedule(
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
        recipientVerificationRequirement:
            'recipient-verifies-private-vss-opening-before-acceptance',
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
        openingVerificationStatus: 'accepted-local-private-vss-opening',
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

export function acceptedCommonRandomness(
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
        publicDerivations.publicMatrices.commitmentMatrix.sampledEntries[0]
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

export { publicPrivateVssEnvelopeCommitmentReference };

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

export function rebindCollectiveSetupPackageHash(
    kernel: TranscriptCoreKernel,
    setupPackage: JsonRecord,
): void {
    delete setupPackage.setupPackageHash;
    setupPackage.setupPackageHash = kernel.deriveProtocolHash({
        namespace: 'SetupPackageHash',
        value: setupPackageHashInput(setupPackage),
    });
}

function acceptedSetupCommitmentSecurityCertificate(
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const acceptedCertificateTemplates = jsonRecord(
        (profile as unknown as JsonRecord).acceptedCertificateTemplates,
        'profile.acceptedCertificateTemplates',
    );

    return cloneJsonRecord(
        jsonRecord(
            acceptedCertificateTemplates.setupCommitmentSecurityCertificate,
            'profile.acceptedCertificateTemplates.setupCommitmentSecurityCertificate',
        ),
    );
}

function acceptedSetupProofAccountingCertificate(
    profile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const acceptedCertificateTemplates = jsonRecord(
        (profile as unknown as JsonRecord).acceptedCertificateTemplates,
        'profile.acceptedCertificateTemplates',
    );

    return cloneJsonRecord(
        jsonRecord(
            acceptedCertificateTemplates.setupProofAccountingCertificate,
            'profile.acceptedCertificateTemplates.setupProofAccountingCertificate',
        ),
    );
}

function acceptedHeSecurityCertificate(
    setupProfile: BgvCollectiveSetupProfileDescription,
): JsonRecord {
    const acceptedCertificateTemplates = jsonRecord(
        (setupProfile as unknown as JsonRecord).acceptedCertificateTemplates,
        'setupProfile.acceptedCertificateTemplates',
    );

    return cloneJsonRecord(
        jsonRecord(
            acceptedCertificateTemplates.heSecurityCertificate,
            'setupProfile.acceptedCertificateTemplates.heSecurityCertificate',
        ),
    );
}

function acceptedSetupTransportCertificate(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
    vssCoefficientCommitmentMaterial: JsonRecord,
): JsonRecord {
    const vssObjectFullObjectHash = kernel.deriveProtocolHash({
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
    const vssObjectChunkRoot = kernel.deriveProtocolHash({
        namespace: 'SetupTransportChunkManifestRoot',
        value: {
            fixture: 'setup-transport-vss-object-chunk-root',
            totalByteLength: setupTransportTotalByteLength,
        },
    });
    const transportedVssObject = {
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
        chunkRoot: vssObjectChunkRoot,
        chunkHashes,
        fullObjectHash: vssObjectFullObjectHash,
        encoding: 'binary',
        loadingPolicy: 'stream-verified-before-object-use',
    };
    // The certificate-level hashes are the verifier-recomputed aggregates over
    // the transported-object set.
    const fullObjectHash = kernel.deriveProtocolHash({
        namespace: 'SetupTransportFullObjectSetHash',
        value: {
            objectType: 'SetupTransportFullObjectSet',
            objectVersion: 1,
            setupProfileId: 'CollectiveBgvSetup-v1',
            transportProfileId:
                'sealed-lattice-setup-binary-chunked-transport-v1',
            transportedObjects: [
                {
                    objectName: transportedVssObject.objectName,
                    objectRole: transportedVssObject.objectRole,
                    objectRoot: transportedVssObject.objectRoot,
                    byteLength: transportedVssObject.byteLength,
                    chunkStartIndex: transportedVssObject.chunkStartIndex,
                    chunkCount: transportedVssObject.chunkCount,
                    chunkRoot: transportedVssObject.chunkRoot,
                    fullObjectHash: transportedVssObject.fullObjectHash,
                },
            ],
            totalByteLength: setupTransportTotalByteLength,
            chunkCount: setupTransportChunkCount,
            chunkHashes,
        },
    });
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
        transportedObjects: [transportedVssObject],
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
    Promise<JsonRecord>
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

export function acceptedActiveStaticSetupTheoremCertificate(
    kernel: TranscriptCoreKernel,
    setupPackage: JsonRecord,
): JsonRecord {
    const setupContext = setupPackage.setupContext as JsonRecord;
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
            secretConfidentialityCorruptTrusteeBound:
                firstProfileDecryptionThreshold - 1,
            fullRosterSetupCompletionRequired: true,
        },
        livenessModel: {
            model: 'secure-with-abort',
            setupCompletionQuorum: firstProfileParticipantCount,
            participantCount: firstProfileParticipantCount,
        },
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
            publicKeyShareSuccinctProofSetRoot: optionalNestedHashFromRecord(
                setupPackage,
                'publicKeyShareSuccinctProofs',
                'publicKeyShareSuccinctProofSetRoot',
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
        claimBoundary: {
            remainingDependencies: [],
            integrationDependencies: [],
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
        packageShapePrivateVssEnvelopeCommitments(
            kernel,
            profile,
            setupContext,
            commonRandomness,
            vssCoefficientCommitments,
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
        acceptedSetupCommitmentSecurityCertificate(profile);
    const setupProofAccountingCertificate =
        acceptedSetupProofAccountingCertificate(profile);
    const heSecurityCertificate = acceptedHeSecurityCertificate(profile);
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

export async function acceptedShapedSetupPackage(
    kernel: TranscriptCoreKernel,
    profile: BgvCollectiveSetupProfileDescription,
): Promise<JsonRecord> {
    const cacheKey = acceptedShapedSetupPackageCacheKey(kernel, profile);
    let acceptedShapedSetupPackagePromise =
        acceptedShapedSetupPackageCacheByProfileKey.get(cacheKey);
    if (acceptedShapedSetupPackagePromise === undefined) {
        acceptedShapedSetupPackagePromise = buildAcceptedShapedSetupPackage(
            kernel,
            profile,
        );
        acceptedShapedSetupPackageCacheByProfileKey.set(
            cacheKey,
            acceptedShapedSetupPackagePromise,
        );
    }

    return cloneJsonRecord(await acceptedShapedSetupPackagePromise);
}
