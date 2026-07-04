import { validHash } from '../../bgv-passive-setup-fixtures.js';
import {
    firstRosterDecryptionThreshold,
    firstRosterParticipantCount,
    hexToBytes,
    jsonRecord,
    textEncoder,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import { compactVssTrusteeSecretCoefficients } from './compact-vss-material.js';

import { hash512Hex } from '#packages/crypto/src/index';
import { type CompactVssCoefficientCommitmentSet } from '#packages/protocol/src/setup/compact-vss-commitments';
import {
    createSameSecretConsistencyStatementSet,
    createSameSecretProofSet,
    sameSecretProofFamily,
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
    BgvCollectiveSetupParametersDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';

const sameSecretProofBytesHash = (proofBytesHex: string): string =>
    hash512Hex(
        'sealed-lattice/setup/same-secret-linkage-anchor/proof-bytes-v1',
        [hexToBytes(proofBytesHex)],
    );

export function acceptedSameSecretConsistency(
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    vssCoefficientCommitments: VssCoefficientCommitmentSet,
): SameSecretConsistencyStatementSet {
    return createSameSecretConsistencyStatementSet({
        setupContext,
        qSharePrimes: parameters.qShare.primes,
        participantCount: firstRosterParticipantCount,
        thresholdDegree: firstRosterDecryptionThreshold,
        vssCoefficientCommitments,
    });
}

// The same-secret consistency statement on the compact path binds the compact
// coefficient commitment roots. The consistency builder reads the full-VSS field
// names (sourceTrusteeCommitmentRoot, per-commitment commitmentRoot), so present
// the compact set through a view that aliases those to the compact roots the
// accepted-setup verifier recomputes.
export function acceptedCompactSameSecretConsistency(
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    compactCoefficientCommitmentSet: CompactVssCoefficientCommitmentSet,
): SameSecretConsistencyStatementSet {
    const compactCoefficientView = {
        ceremonyId: setupContext.ceremonyId,
        manifestHash: setupContext.manifestHash,
        rosterHash: setupContext.rosterHash,
        setupParametersHash: setupContext.setupParametersHash,
        setupEpoch: setupContext.setupEpoch,
        vssCoefficientCommitmentRoot:
            compactCoefficientCommitmentSet.coefficientCommitmentRoot,
        sourceTrusteeRecords:
            compactCoefficientCommitmentSet.sourceTrusteeRecords.map(
                (sourceTrusteeRecord) => ({
                    ceremonyId: setupContext.ceremonyId,
                    manifestHash: setupContext.manifestHash,
                    rosterHash: setupContext.rosterHash,
                    setupParametersHash: setupContext.setupParametersHash,
                    setupEpoch: setupContext.setupEpoch,
                    sourceTrusteeIdentity:
                        sourceTrusteeRecord.sourceTrusteeIdentity,
                    sourceTrusteeRosterPosition:
                        sourceTrusteeRecord.sourceTrusteeRosterPosition,
                    sourceTrusteeCommitmentRoot:
                        sourceTrusteeRecord.sourceCoefficientCommitmentRoot,
                    coefficientCommitments:
                        sourceTrusteeRecord.coefficientCommitments.map(
                            (coefficientCommitment) => ({
                                rnsLimbIndex:
                                    coefficientCommitment.rnsLimbIndex,
                                rnsPrime: coefficientCommitment.rnsPrime,
                                shamirCoefficientIndex:
                                    coefficientCommitment.shamirCoefficientIndex,
                                commitmentRoot:
                                    coefficientCommitment.coefficientCommitmentRoot,
                            }),
                        ),
                }),
            ),
    };

    return createSameSecretConsistencyStatementSet({
        setupContext,
        qSharePrimes: parameters.qShare.primes,
        participantCount: parameters.participantCount,
        thresholdDegree: parameters.qDec,
        vssCoefficientCommitments:
            compactCoefficientView as unknown as VssCoefficientCommitmentSet,
    });
}

// The setup commitment randomness width is (2 * module rank) + 1 = 5, opaque to
// the verifier (the commitment is hiding). Any deterministic ternary vector of
// this width works for the data-basis same-secret anchor commitments.
const setupCommitmentRandomnessWidth = 5;

const compactSameSecretDataBasisRandomness = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    ringDegree: number,
): number[][] =>
    Array.from(
        { length: setupCommitmentRandomnessWidth },
        (_unusedColumn, randomnessColumnIndex) =>
            Array.from(
                { length: ringDegree },
                (_unusedCoefficient, coefficientPosition) =>
                    [-1, 0, 1][
                        (sourceTrusteeRosterPosition +
                            rnsLimbIndex +
                            randomnessColumnIndex +
                            coefficientPosition) %
                            3
                    ],
            ),
    );

// The same-secret proofs on the compact path stay data-basis proofs: each trustee
// commits its constant (secret) coefficient into every RNS prime with the setup
// commitment and proves those commitments open to one short ternary secret. The
// compact same-secret bridge links these data-basis anchors to the compact
// target-basis constant commitments through that same secret.
export function acceptedCompactSameSecretProofs(
    kernel: TranscriptCoreKernel,
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    publicMatrixSeedHash: string,
    compactSameSecretConsistency: SameSecretConsistencyStatementSet,
    compactCoefficientCommitmentRoot: string,
    ringDegree: number,
): SameSecretProofSet {
    const qSharePrimes = parameters.qShare.primes;
    // The data-basis anchor material is computed here, so bind a deterministic
    // anchor root for the compact path.
    const dataBasisAnchorMaterialRoot = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'CompactVssDataBasisSameSecretAnchorMaterial',
            coefficientCommitmentRoot: compactCoefficientCommitmentRoot,
        },
    });
    const proofMaterials: SameSecretProofMaterial[] = Array.from(
        { length: parameters.participantCount },
        (_unusedTrustee, sourceTrusteeRosterPosition) => {
            const trusteeIdentity = `trustee-${String(sourceTrusteeRosterPosition)}`;
            const secretCoefficients = compactVssTrusteeSecretCoefficients(
                sourceTrusteeRosterPosition,
                ringDegree,
            );
            const openingRandomnessByLimb = qSharePrimes.map(
                (_rnsPrime, rnsLimbIndex) =>
                    compactSameSecretDataBasisRandomness(
                        sourceTrusteeRosterPosition,
                        rnsLimbIndex,
                        ringDegree,
                    ),
            );
            const constantCommitments = qSharePrimes.map(
                (rnsPrime, rnsLimbIndex) => {
                    const messageCoefficients = secretCoefficients.map(
                        (secretCoefficient) =>
                            secretCoefficient < 0
                                ? rnsPrime - 1
                                : secretCoefficient,
                    );

                    return kernel.computeSetupCommitmentFromOpening({
                        publicMatrixSeedHash,
                        sourceRnsLimbIndex: rnsLimbIndex,
                        sourceMessageModulus: rnsPrime,
                        shamirCoefficientIndex: 0,
                        messageCoefficients,
                        randomnessByColumn:
                            openingRandomnessByLimb[rnsLimbIndex],
                        ringDegree,
                    }).commitment;
                },
            );
            const generatedProof = kernel.generateTrusteeEvaluationKeyProof({
                context: {
                    ceremonyId: setupContext.ceremonyId,
                    manifestHash: setupContext.manifestHash,
                    rosterHash: setupContext.rosterHash,
                    trusteeIdentity,
                    trusteeRosterPosition: sourceTrusteeRosterPosition,
                    setupEpoch: setupContext.setupEpoch,
                    vssCoefficientCommitmentMaterialRoot:
                        dataBasisAnchorMaterialRoot,
                },
                ringDegree,
                keys: [],
                sameSecretLinkage: {
                    publicMatrixSeedHash,
                    commitments: constantCommitments,
                },
                secretCoefficients,
                errorCoefficientsByKey: [],
                negativeIndicatorCoefficients: secretCoefficients.map(
                    (secretCoefficient) => (secretCoefficient < 0 ? 1 : 0),
                ),
                openingRandomnessByLimb,
                proofRandomnessSeedHex: hash512Hex(
                    'sealed-lattice-test/compact-same-secret-proof-seed-v1',
                    [textEncoder.encode(String(sourceTrusteeRosterPosition))],
                ),
                proofRandomnessNonceHex: hash512Hex(
                    'sealed-lattice-test/compact-same-secret-proof-nonce-v1',
                    [textEncoder.encode(String(sourceTrusteeRosterPosition))],
                ),
            });
            if (generatedProof.proofFamily !== sameSecretProofFamily) {
                throw new Error('generated proof must be a same-secret proof.');
            }

            return {
                proofFamily: sameSecretProofFamily,
                trusteeIdentity,
                trusteeRosterPosition: sourceTrusteeRosterPosition,
                statementHash: generatedProof.statementHash,
                proofBytesHash: sameSecretProofBytesHash(
                    generatedProof.proofBytesHex,
                ),
                proofBytesHex: generatedProof.proofBytesHex,
            };
        },
    );

    return createSameSecretProofSet({
        setupContext,
        qSharePrimes,
        participantCount: parameters.participantCount,
        sameSecretConsistency: compactSameSecretConsistency,
        vssCoefficientCommitmentMaterial: {
            vssCoefficientCommitmentMaterialRoot: dataBasisAnchorMaterialRoot,
            participantCount: parameters.participantCount,
            rnsLimbCount: qSharePrimes.length,
            vssCoefficientCommitmentRoot: compactCoefficientCommitmentRoot,
            ringDegree,
        } as unknown as SetupPackageVssCoefficientCommitmentMaterialSet,
        proofMaterials,
    });
}

export function sameSecretProofsWithDriftedStatementHashes(
    parameters: BgvCollectiveSetupParametersDescription,
    setupPackage: JsonRecord,
): SameSecretProofSet {
    const sameSecretConsistency =
        setupPackage.sameSecretConsistency as SameSecretConsistencyStatementSet;
    const proofBytesHex = '00';
    const proofMaterials: SameSecretProofMaterial[] =
        sameSecretConsistency.statementRecords.map((statementRecord) => ({
            proofFamily: sameSecretProofFamily,
            trusteeIdentity: statementRecord.trusteeIdentity,
            trusteeRosterPosition: statementRecord.trusteeRosterPosition,
            statementHash: validHash('7'),
            proofBytesHash: sameSecretProofBytesHash(proofBytesHex),
            proofBytesHex,
        }));

    return createSameSecretProofSet({
        setupContext: setupPackage.setupContext as CollectiveBgvSetupContext,
        qSharePrimes: parameters.qShare.primes,
        participantCount: firstRosterParticipantCount,
        sameSecretConsistency,
        vssCoefficientCommitmentMaterial:
            setupPackage.vssCoefficientCommitmentMaterial as SetupPackageVssCoefficientCommitmentMaterialSet,
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
    parameters: BgvCollectiveSetupParametersDescription,
    setupPackage: JsonRecord,
    vssCoefficientCommitmentBundle: VssCoefficientCommitmentBundle,
): SameSecretProofSet {
    const setupContext = setupPackage.setupContext as CollectiveBgvSetupContext;
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
                const constantCommitments = parameters.qShare.primes.map(
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
                const openingRandomnessByLimb = parameters.qShare.primes.map(
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
                    proofFamily: sameSecretProofFamily,
                    trusteeIdentity:
                        sourceTrusteeOpeningMaterial.sourceTrusteeIdentity,
                    trusteeRosterPosition:
                        sourceTrusteeOpeningMaterial.sourceTrusteeRosterPosition,
                    statementHash: generatedProof.statementHash,
                    proofBytesHash: sameSecretProofBytesHash(
                        generatedProof.proofBytesHex,
                    ),
                    proofBytesHex: generatedProof.proofBytesHex,
                };
            },
        );

    return createSameSecretProofSet({
        setupContext,
        qSharePrimes: parameters.qShare.primes,
        participantCount: firstRosterParticipantCount,
        sameSecretConsistency:
            setupPackage.sameSecretConsistency as SameSecretConsistencyStatementSet,
        vssCoefficientCommitmentMaterial:
            setupPackage.vssCoefficientCommitmentMaterial as SetupPackageVssCoefficientCommitmentMaterialSet,
        proofMaterials,
    });
}
