import {
    minimumSuccinctProofFixtureRingDegree,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import type {
    SameSecretConsistencyStatementSet,
    SameSecretProofSet,
} from '#packages/protocol/src/setup/same-secret-consistency-records';
import {
    createThresholdShareCommitmentBinding,
    createBinaryChunkedSameSecretBridgeProofMaterialTransport,
    createBinaryChunkedVssShareLinkageProofMaterialTransport,
    createVssPublicAggregateThresholdCommitmentSet,
    createVssPublicCoefficientCommitmentSet,
    createVssPublicRecipientShareCommitmentSet,
    createVssSameSecretBridgeProofMaterialSet,
    createVssSameSecretBridgeStatementSet,
    createVssShareLinkageProofMaterialSet,
    createVssShareLinkageStatement,
    type TransportedSameSecretBridgeProofMaterialSet,
    type TransportedVssShareLinkageProofMaterialSet,
    type VssPublicCoefficientCommitmentSet,
    type VssPublicCoefficientCredential,
    type VssPublicRecipientShareCommitmentSet,
    type VssPublicSourceTrusteeOpeningState,
} from '#packages/protocol/src/setup/vss-commitments';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import type {
    BgvCollectiveSetupParametersDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import { createVssCommitmentComputers } from '#tests/support/vss-commitment-computer';

// The source trustee's centered ternary secret coefficient, deterministic per
// (trustee, coefficient position). The shamir-zero coefficient message is this
// secret reduced into each RNS prime, so the same-secret proof and the
// same-secret bridge bind one consistent secret.
export const vssPublicTrusteeSecretCoefficient = (
    sourceTrusteeRosterPosition: number,
    coefficientPosition: number,
): number =>
    [-1, 0, 1][(sourceTrusteeRosterPosition + coefficientPosition) % 3];

export const vssPublicTrusteeSecretCoefficients = (
    sourceTrusteeRosterPosition: number,
    ringDegree: number,
): number[] =>
    Array.from(
        { length: ringDegree },
        (_unusedCoefficient, coefficientPosition) =>
            vssPublicTrusteeSecretCoefficient(
                sourceTrusteeRosterPosition,
                coefficientPosition,
            ),
    );

// The trustee's Shamir coefficient message reduced into one RNS prime. The
// constant (shamir-zero) coefficient carries the centered ternary secret; higher
// coefficients carry a deterministic bounded residue that reproduces valid
// covered-message digits.
const vssPublicCoefficientMessage = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    rnsPrime: number,
    ringDegree: number,
): number[] => {
    if (shamirCoefficientIndex === 0) {
        return Array.from(
            { length: ringDegree },
            (_unusedCoefficient, coefficientPosition) => {
                const secretCoefficient = vssPublicTrusteeSecretCoefficient(
                    sourceTrusteeRosterPosition,
                    coefficientPosition,
                );

                return secretCoefficient < 0 ? rnsPrime - 1 : secretCoefficient;
            },
        );
    }

    return Array.from(
        { length: ringDegree },
        (_unusedCoefficient, coefficientPosition) =>
            ((sourceTrusteeRosterPosition + 1) * 17 +
                (rnsLimbIndex + 1) * 5 +
                (shamirCoefficientIndex + 1) * 3 +
                (coefficientPosition % 11)) %
            rnsPrime,
    );
};

// Deterministic centered ternary commitment randomness. It is opaque to the
// verifier (the commitment is hiding), so any deterministic ternary
// value works as long as the commit and the proof reuse the same column, which
// the builders guarantee by threading it through the credentials.
const vssPublicCoefficientRandomness = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    ringDegree: number,
): number[][] =>
    Array.from({ length: 2 }, (_unusedColumn, randomnessColumnIndex) =>
        Array.from(
            { length: ringDegree },
            (_unusedCoefficient, coefficientPosition) =>
                [-1, 0, 1][
                    (sourceTrusteeRosterPosition +
                        rnsLimbIndex +
                        shamirCoefficientIndex +
                        randomnessColumnIndex +
                        coefficientPosition) %
                        3
                ],
        ),
    );

const vssPublicRecipientShareRandomness = (
    sourceTrusteeRosterPosition: number,
    recipientRosterPosition: number,
    rnsLimbIndex: number,
    ringDegree: number,
): number[][] => {
    const seedOffset =
        10_000 +
        sourceTrusteeRosterPosition * 503 +
        recipientRosterPosition * 37 +
        rnsLimbIndex * 11;

    return Array.from({ length: 2 }, (_unusedColumn, randomnessColumnIndex) =>
        Array.from(
            { length: ringDegree },
            (_unusedCoefficient, coefficientPosition) =>
                ((seedOffset +
                    randomnessColumnIndex * 5 +
                    coefficientPosition * 7) %
                    3) -
                1,
        ),
    );
};

const vssPublicSourceTrusteeOpeningStates = (
    qSharePrimes: readonly number[],
    ringDegree: number,
    participantCount: number,
    thresholdDegree: number,
): VssPublicSourceTrusteeOpeningState[] =>
    Array.from(
        { length: participantCount },
        (_unusedTrustee, sourceTrusteeRosterPosition) => ({
            sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
            sourceTrusteeRosterPosition,
            coefficientOpenings: qSharePrimes.flatMap(
                (rnsPrime, rnsLimbIndex) =>
                    Array.from(
                        { length: thresholdDegree },
                        (_unusedShamir, shamirCoefficientIndex) => ({
                            rnsLimbIndex,
                            rnsPrime,
                            shamirCoefficientIndex,
                            coefficientMessage: vssPublicCoefficientMessage(
                                sourceTrusteeRosterPosition,
                                rnsLimbIndex,
                                shamirCoefficientIndex,
                                rnsPrime,
                                ringDegree,
                            ),
                        }),
                    ),
            ),
        }),
    );

export type VssPublicMaterial = {
    readonly coefficientCommitmentSet: VssPublicCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: VssPublicRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: JsonRecord;
    readonly shareLinkageStatement: JsonRecord;
    readonly shareLinkageProofMaterialSet: JsonRecord;
    readonly transportedVssShareLinkageProofMaterial: TransportedVssShareLinkageProofMaterialSet;
    readonly thresholdShareCommitmentBinding: JsonRecord;
    readonly coefficientCredentials: readonly VssPublicCoefficientCredential[];
    readonly ringDegree: number;
};

// Build the VSS public material (coefficient, recipient-share and
// aggregate threshold commitment sets, the share-linkage statement and proof
// material, and the threshold-share commitment binding) by driving the
// protocol builders with the kernel-backed commitment and proof
// computers. The same-secret bridge is built separately because it also binds
// the accepted same-secret proof.
export function acceptedVssPublicMaterial(
    kernel: TranscriptCoreKernel,
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    publicMatrixSeedHash: string,
): VssPublicMaterial {
    const { vssPublicCommitmentComputer, vssShareLinkageProofComputer } =
        createVssCommitmentComputers(kernel);
    const qSharePrimes = parameters.qShare.primes;
    const ringDegree = minimumSuccinctProofFixtureRingDegree;
    const participantCount = parameters.participantCount;
    const thresholdDegree = parameters.qDec;
    const sourceTrusteeOpeningStates = vssPublicSourceTrusteeOpeningStates(
        qSharePrimes,
        ringDegree,
        participantCount,
        thresholdDegree,
    );

    const coefficientCommitmentBundle = createVssPublicCoefficientCommitmentSet(
        {
            setupContext,
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes,
            ringDegree,
            thresholdDegree,
            sourceTrusteeOpeningStates,
            coefficientOpeningRandomness: ({
                trusteeRosterPosition,
                rnsLimbIndex,
                shamirCoefficientIndex,
            }) =>
                vssPublicCoefficientRandomness(
                    trusteeRosterPosition,
                    rnsLimbIndex,
                    shamirCoefficientIndex,
                    ringDegree,
                ),
            computeVssPublicCommitment: vssPublicCommitmentComputer,
        },
    );
    const recipientShareCommitmentBundle =
        createVssPublicRecipientShareCommitmentSet({
            setupContext,
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes,
            ringDegree,
            thresholdDegree,
            sourceTrusteeOpeningStates,
            recipientShareOpeningRandomness: ({
                sourceTrusteeRosterPosition,
                recipientRosterPosition,
                rnsLimbIndex,
            }) =>
                vssPublicRecipientShareRandomness(
                    sourceTrusteeRosterPosition,
                    recipientRosterPosition,
                    rnsLimbIndex,
                    ringDegree,
                ),
            computeVssPublicCommitment: vssPublicCommitmentComputer,
        });
    const aggregateThresholdCommitmentSet =
        createVssPublicAggregateThresholdCommitmentSet({
            setupContext,
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes,
            ringDegree,
            recipientShareCredentials:
                recipientShareCommitmentBundle.recipientShareCredentials,
        });
    const shareLinkageStatement = createVssShareLinkageStatement({
        setupContext,
        publicMatrixSeedHash,
        targetBasisHash: parameters.canonicalTargetBasisHash,
        coefficientCommitmentSet:
            coefficientCommitmentBundle.coefficientCommitmentSet,
        recipientShareCommitmentSet:
            recipientShareCommitmentBundle.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
    });
    const embeddedShareLinkageProofMaterialSet =
        createVssShareLinkageProofMaterialSet({
            deriveProofMaterialSetRoot: false,
            statement: shareLinkageStatement,
            coefficientCommitmentSet:
                coefficientCommitmentBundle.coefficientCommitmentSet,
            recipientShareCommitmentSet:
                recipientShareCommitmentBundle.recipientShareCommitmentSet,
            coefficientCredentials:
                coefficientCommitmentBundle.coefficientCredentials,
            recipientShareCredentials:
                recipientShareCommitmentBundle.recipientShareCredentials,
            shareLinkageProofRandomness: ({
                sourceTrusteeRosterPosition,
                proofRecordIndex,
            }) => ({
                seedHex: kernel.deriveCanonicalObjectHash({
                    value: {
                        objectType: 'VssShareLinkageProofRandomness',
                        fixture: 'seed',
                        sourceTrusteeRosterPosition,
                        proofRecordIndex,
                    },
                }),
                nonceHex: kernel.deriveCanonicalObjectHash({
                    value: {
                        objectType: 'VssShareLinkageProofRandomness',
                        fixture: 'nonce',
                        sourceTrusteeRosterPosition,
                        proofRecordIndex,
                    },
                }),
            }),
            generateVssShareLinkageProof: vssShareLinkageProofComputer,
        });
    const shareLinkageProofTransport =
        createBinaryChunkedVssShareLinkageProofMaterialTransport(
            embeddedShareLinkageProofMaterialSet,
        );
    const shareLinkageProofMaterialSet =
        shareLinkageProofTransport.proofMaterialSet;
    const transportedVssShareLinkageProofMaterial =
        shareLinkageProofTransport.transportedVssShareLinkageProofMaterial;
    const thresholdShareCommitmentBinding =
        createThresholdShareCommitmentBinding({
            coefficientCommitmentSet:
                coefficientCommitmentBundle.coefficientCommitmentSet,
            statement: shareLinkageStatement,
            aggregateThresholdCommitmentSet,
            shareLinkageProofMaterialSetRoot: String(
                shareLinkageProofMaterialSet.proofMaterialSetRoot,
            ),
        });

    return {
        coefficientCommitmentSet:
            coefficientCommitmentBundle.coefficientCommitmentSet,
        recipientShareCommitmentSet:
            recipientShareCommitmentBundle.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
        shareLinkageStatement,
        shareLinkageProofMaterialSet,
        transportedVssShareLinkageProofMaterial,
        thresholdShareCommitmentBinding,
        coefficientCredentials:
            coefficientCommitmentBundle.coefficientCredentials,
        ringDegree,
    };
}

export type SameSecretBridge = {
    readonly bridgeStatementSet: JsonRecord;
    readonly bridgeProofMaterialSet: JsonRecord;
    readonly transportedSameSecretBridgeProofMaterial: TransportedSameSecretBridgeProofMaterialSet;
};

// Build the same-secret bridge: per source trustee it binds the
// target-basis constant coefficient commitments to the accepted data-basis
// same-secret proof, and one succinct bridge proof shows both open to the same
// centered ternary secret. The bridge secret must be the exact secret the
// same-secret proof binds.
export function acceptedSameSecretBridge(
    kernel: TranscriptCoreKernel,
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    publicMatrixSeedHash: string,
    vssPublicMaterial: VssPublicMaterial,
    sameSecretConsistency: SameSecretConsistencyStatementSet,
    sameSecretProofs: SameSecretProofSet,
): SameSecretBridge {
    const { sameSecretBridgeProofComputer } =
        createVssCommitmentComputers(kernel);
    const bridgeStatementSet = createVssSameSecretBridgeStatementSet({
        setupContext,
        publicMatrixSeedHash,
        targetBasisHash: parameters.canonicalTargetBasisHash,
        coefficientCommitmentSet: vssPublicMaterial.coefficientCommitmentSet,
        sameSecretConsistency: sameSecretConsistency,
        sameSecretProofs: sameSecretProofs,
    });
    const embeddedBridgeProofMaterialSet =
        createVssSameSecretBridgeProofMaterialSet({
            deriveProofMaterialSetRoot: false,
            statementSet: bridgeStatementSet,
            coefficientCredentials: vssPublicMaterial.coefficientCredentials,
            bridgeSecret: ({ sourceTrusteeRosterPosition }) => ({
                secretCoefficients: vssPublicTrusteeSecretCoefficients(
                    sourceTrusteeRosterPosition,
                    vssPublicMaterial.ringDegree,
                ),
            }),
            bridgeProofRandomness: ({ sourceTrusteeRosterPosition }) => ({
                seedHex: kernel.deriveCanonicalObjectHash({
                    value: {
                        objectType: 'SameSecretBridgeProofRandomness',
                        fixture: 'seed',
                        sourceTrusteeRosterPosition,
                    },
                }),
                nonceHex: kernel.deriveCanonicalObjectHash({
                    value: {
                        objectType: 'SameSecretBridgeProofRandomness',
                        fixture: 'nonce',
                        sourceTrusteeRosterPosition,
                    },
                }),
            }),
            generateSameSecretBridgeProof: sameSecretBridgeProofComputer,
        });
    const bridgeProofTransport =
        createBinaryChunkedSameSecretBridgeProofMaterialTransport(
            embeddedBridgeProofMaterialSet,
        );
    const bridgeProofMaterialSet = bridgeProofTransport.proofMaterialSet;
    const transportedSameSecretBridgeProofMaterial =
        bridgeProofTransport.transportedSameSecretBridgeProofMaterial;

    return {
        bridgeStatementSet,
        bridgeProofMaterialSet,
        transportedSameSecretBridgeProofMaterial,
    };
}
