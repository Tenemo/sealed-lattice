import { validHash } from '../../bgv-passive-setup-fixtures.js';
import {
    firstProfileDecryptionThreshold,
    firstProfileParticipantCount,
    hexToBytes,
    jsonRecord,
    textEncoder,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import { hash512Hex } from '#packages/crypto/src/index';
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
    type SetupPackageVssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentBundle,
    type VssCoefficientOpeningMaterial,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeOpeningMaterial,
} from '#packages/protocol/src/setup/vss-coefficient-commitments';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import type {
    BgvCollectiveSetupProfileDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';

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
