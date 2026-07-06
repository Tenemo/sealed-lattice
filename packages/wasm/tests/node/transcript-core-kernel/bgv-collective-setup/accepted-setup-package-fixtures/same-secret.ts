import { hexToBytes, textEncoder } from '../setup-fixture-primitives.js';

import { vssPublicTrusteeSecretCoefficients } from './vss-material.js';

import { hash512Hex } from '#packages/crypto/src/index';
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
    type VssCoefficientCommitmentSet,
} from '#packages/protocol/src/setup/vss-coefficient-commitments';
import { type VssPublicCoefficientCommitmentSet } from '#packages/protocol/src/setup/vss-commitments';
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

// The same-secret consistency statement binds the public VSS coefficient
// commitment roots. The consistency builder reads the full-VSS field names
// (sourceTrusteeCommitmentRoot, per-commitment commitmentRoot), so present the
// commitment set through a view that aliases those to the roots the
// accepted-setup verifier recomputes.
export function acceptedSameSecretConsistency(
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    coefficientCommitmentSet: VssPublicCoefficientCommitmentSet,
): SameSecretConsistencyStatementSet {
    const coefficientView = {
        ceremonyId: setupContext.ceremonyId,
        manifestHash: setupContext.manifestHash,
        rosterHash: setupContext.rosterHash,
        setupParametersHash: setupContext.setupParametersHash,
        setupEpoch: setupContext.setupEpoch,
        vssCoefficientCommitmentRoot:
            coefficientCommitmentSet.coefficientCommitmentRoot,
        sourceTrusteeRecords: coefficientCommitmentSet.sourceTrusteeRecords.map(
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
                            rnsLimbIndex: coefficientCommitment.rnsLimbIndex,
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
            coefficientView as unknown as VssCoefficientCommitmentSet,
    });
}

// The setup commitment randomness width is (2 * module rank) + 1 = 5, opaque to
// the verifier (the commitment is hiding). Any deterministic ternary vector of
// this width works for the data-basis same-secret anchor commitments.
const setupCommitmentRandomnessWidth = 5;

const sameSecretDataBasisRandomness = (
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

// The same-secret proofs stay data-basis proofs: each trustee commits its
// constant (secret) coefficient into every RNS prime with the setup commitment
// and proves those commitments open to one short ternary secret. The same-secret
// bridge links these data-basis anchors to the target-basis constant commitments
// through that same secret.
export function acceptedSameSecretProofs(
    kernel: TranscriptCoreKernel,
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    publicMatrixSeedHash: string,
    sameSecretConsistency: SameSecretConsistencyStatementSet,
    coefficientCommitmentRoot: string,
    ringDegree: number,
): SameSecretProofSet {
    const qSharePrimes = parameters.qShare.primes;
    // The data-basis anchor material is computed here, so bind a deterministic
    // anchor root.
    const dataBasisAnchorMaterialRoot = kernel.deriveCanonicalObjectHash({
        value: {
            objectType: 'VssPublicDataBasisSameSecretAnchorMaterial',
            coefficientCommitmentRoot: coefficientCommitmentRoot,
        },
    });
    const proofMaterials: SameSecretProofMaterial[] = Array.from(
        { length: parameters.participantCount },
        (_unusedTrustee, sourceTrusteeRosterPosition) => {
            const trusteeIdentity = `trustee-${String(sourceTrusteeRosterPosition)}`;
            const secretCoefficients = vssPublicTrusteeSecretCoefficients(
                sourceTrusteeRosterPosition,
                ringDegree,
            );
            const openingRandomnessByLimb = qSharePrimes.map(
                (_rnsPrime, rnsLimbIndex) =>
                    sameSecretDataBasisRandomness(
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
                    'sealed-lattice-test/accepted-same-secret-proof-seed-v1',
                    [textEncoder.encode(String(sourceTrusteeRosterPosition))],
                ),
                proofRandomnessNonceHex: hash512Hex(
                    'sealed-lattice-test/accepted-same-secret-proof-nonce-v1',
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
        sameSecretConsistency: sameSecretConsistency,
        vssCoefficientCommitmentMaterial: {
            vssCoefficientCommitmentMaterialRoot: dataBasisAnchorMaterialRoot,
            participantCount: parameters.participantCount,
            rnsLimbCount: qSharePrimes.length,
            vssCoefficientCommitmentRoot: coefficientCommitmentRoot,
            ringDegree,
        } as unknown as SetupPackageVssCoefficientCommitmentMaterialSet,
        proofMaterials,
    });
}
