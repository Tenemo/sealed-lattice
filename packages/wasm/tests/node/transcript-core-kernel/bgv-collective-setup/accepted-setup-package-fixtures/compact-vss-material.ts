import {
    minimumSuccinctProofFixtureRingDegree,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import {
    createCompactThresholdShareCommitmentBinding,
    createCompactVssAggregateThresholdCommitmentSet,
    createCompactVssCoefficientCommitmentSet,
    createCompactVssRecipientShareCommitmentSet,
    createCompactVssSameSecretBridgeProofMaterialSet,
    createCompactVssSameSecretBridgeStatementSet,
    createCompactVssShareLinkageProofMaterialSet,
    createCompactVssShareLinkageStatement,
    type CompactVssCoefficientCommitmentSet,
    type CompactVssCoefficientCredential,
    type CompactVssRecipientShareCommitmentSet,
    type CompactVssSourceTrusteeOpeningState,
} from '#packages/protocol/src/setup/compact-vss-commitments';
import type {
    SameSecretConsistencyStatementSet,
    SameSecretProofSet,
} from '#packages/protocol/src/setup/same-secret-consistency-records';
import { type CollectiveBgvSetupContext } from '#packages/protocol/src/setup/vss-share-verification-records';
import type {
    BgvCollectiveSetupParametersDescription,
    TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import {
    compactSameSecretBridgeProofComputer,
    compactVssCommitmentComputer,
    compactVssShareLinkageProofComputer,
} from '#tests/support/compact-vss-commitment-computer';

// The source trustee's centered ternary secret coefficient, deterministic per
// (trustee, coefficient position). The shamir-zero coefficient message is this
// secret reduced into each RNS prime, so the same-secret proof and the compact
// same-secret bridge bind one consistent secret.
export const compactVssTrusteeSecretCoefficient = (
    sourceTrusteeRosterPosition: number,
    coefficientPosition: number,
): number =>
    [-1, 0, 1][(sourceTrusteeRosterPosition + coefficientPosition) % 3];

export const compactVssTrusteeSecretCoefficients = (
    sourceTrusteeRosterPosition: number,
    ringDegree: number,
): number[] =>
    Array.from(
        { length: ringDegree },
        (_unusedCoefficient, coefficientPosition) =>
            compactVssTrusteeSecretCoefficient(
                sourceTrusteeRosterPosition,
                coefficientPosition,
            ),
    );

// The trustee's Shamir coefficient message reduced into one RNS prime. The
// constant (shamir-zero) coefficient carries the centered ternary secret; higher
// coefficients carry a deterministic bounded residue that reproduces valid
// covered-message digits.
const compactVssCoefficientMessage = (
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
                const secretCoefficient = compactVssTrusteeSecretCoefficient(
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
// verifier (the compact commitment is hiding), so any deterministic ternary
// value works as long as the commit and the proof reuse the same column, which
// the builders guarantee by threading it through the credentials.
const compactVssCoefficientRandomness = (
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

const compactVssRecipientShareRandomness = (
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

const compactVssSourceTrusteeOpeningStates = (
    qSharePrimes: readonly number[],
    ringDegree: number,
    participantCount: number,
    thresholdDegree: number,
): CompactVssSourceTrusteeOpeningState[] =>
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
                            coefficientMessage: compactVssCoefficientMessage(
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

export type CompactVssMaterial = {
    readonly coefficientCommitmentSet: CompactVssCoefficientCommitmentSet;
    readonly recipientShareCommitmentSet: CompactVssRecipientShareCommitmentSet;
    readonly aggregateThresholdCommitmentSet: JsonRecord;
    readonly shareLinkageStatement: JsonRecord;
    readonly shareLinkageProofMaterialSet: JsonRecord;
    readonly thresholdShareCommitmentBinding: JsonRecord;
    readonly coefficientCredentials: readonly CompactVssCoefficientCredential[];
    readonly ringDegree: number;
};

// Build the compact VSS public material (coefficient, recipient-share and
// aggregate threshold commitment sets, the share-linkage statement and proof
// material, and the compact threshold-share commitment binding) by driving the
// protocol builders with the kernel-backed compact commitment and proof
// computers. The same-secret bridge is built separately because it also binds
// the accepted same-secret proof.
export function acceptedCompactVssMaterial(
    kernel: TranscriptCoreKernel,
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    publicMatrixSeedHash: string,
): CompactVssMaterial {
    const qSharePrimes = parameters.qShare.primes;
    const ringDegree = minimumSuccinctProofFixtureRingDegree;
    const participantCount = parameters.participantCount;
    const thresholdDegree = parameters.qDec;
    const sourceTrusteeOpeningStates = compactVssSourceTrusteeOpeningStates(
        qSharePrimes,
        ringDegree,
        participantCount,
        thresholdDegree,
    );

    const coefficientCommitmentBundle =
        createCompactVssCoefficientCommitmentSet({
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
                compactVssCoefficientRandomness(
                    trusteeRosterPosition,
                    rnsLimbIndex,
                    shamirCoefficientIndex,
                    ringDegree,
                ),
            computeCompactVssCommitment: compactVssCommitmentComputer,
        });
    const recipientShareCommitmentBundle =
        createCompactVssRecipientShareCommitmentSet({
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
                compactVssRecipientShareRandomness(
                    sourceTrusteeRosterPosition,
                    recipientRosterPosition,
                    rnsLimbIndex,
                    ringDegree,
                ),
            computeCompactVssCommitment: compactVssCommitmentComputer,
        });
    const aggregateThresholdCommitmentSet =
        createCompactVssAggregateThresholdCommitmentSet({
            setupContext,
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes,
            ringDegree,
            recipientShareCredentials:
                recipientShareCommitmentBundle.recipientShareCredentials,
        });
    const shareLinkageStatement = createCompactVssShareLinkageStatement({
        setupContext,
        publicMatrixSeedHash,
        targetBasisHash: parameters.canonicalTargetBasisHash,
        coefficientCommitmentSet:
            coefficientCommitmentBundle.coefficientCommitmentSet,
        recipientShareCommitmentSet:
            recipientShareCommitmentBundle.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
    });
    const shareLinkageProofMaterialSet =
        createCompactVssShareLinkageProofMaterialSet({
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
                        objectType: 'CompactVssShareLinkageProofRandomness',
                        fixture: 'seed',
                        sourceTrusteeRosterPosition,
                        proofRecordIndex,
                    },
                }),
                nonceHex: kernel.deriveCanonicalObjectHash({
                    value: {
                        objectType: 'CompactVssShareLinkageProofRandomness',
                        fixture: 'nonce',
                        sourceTrusteeRosterPosition,
                        proofRecordIndex,
                    },
                }),
            }),
            generateCompactVssShareLinkageProof:
                compactVssShareLinkageProofComputer,
        });
    const thresholdShareCommitmentBinding =
        createCompactThresholdShareCommitmentBinding({
            coefficientCommitmentSet:
                coefficientCommitmentBundle.coefficientCommitmentSet,
            statement: shareLinkageStatement,
            aggregateThresholdCommitmentSet,
            shareLinkageProofMaterialSetRoot:
                shareLinkageProofMaterialSet.proofMaterialSetRoot,
        });

    return {
        coefficientCommitmentSet:
            coefficientCommitmentBundle.coefficientCommitmentSet,
        recipientShareCommitmentSet:
            recipientShareCommitmentBundle.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
        shareLinkageStatement,
        shareLinkageProofMaterialSet,
        thresholdShareCommitmentBinding,
        coefficientCredentials:
            coefficientCommitmentBundle.coefficientCredentials,
        ringDegree,
    };
}

export type CompactSameSecretBridge = {
    readonly bridgeStatementSet: JsonRecord;
    readonly bridgeProofMaterialSet: JsonRecord;
};

// Build the compact same-secret bridge: per source trustee it binds the compact
// target-basis constant coefficient commitments to the accepted data-basis
// same-secret proof, and one succinct bridge proof shows both open to the same
// centered ternary secret. The bridge secret must be the exact secret the
// same-secret proof binds.
export function acceptedCompactSameSecretBridge(
    kernel: TranscriptCoreKernel,
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    publicMatrixSeedHash: string,
    compactVssMaterial: CompactVssMaterial,
    compactSameSecretConsistency: SameSecretConsistencyStatementSet,
    compactSameSecretProofs: SameSecretProofSet,
): CompactSameSecretBridge {
    const bridgeStatementSet = createCompactVssSameSecretBridgeStatementSet({
        setupContext,
        publicMatrixSeedHash,
        targetBasisHash: parameters.canonicalTargetBasisHash,
        coefficientCommitmentSet: compactVssMaterial.coefficientCommitmentSet,
        sameSecretConsistency: compactSameSecretConsistency,
        sameSecretProofs: compactSameSecretProofs,
    });
    const bridgeProofMaterialSet =
        createCompactVssSameSecretBridgeProofMaterialSet({
            statementSet: bridgeStatementSet,
            coefficientCredentials: compactVssMaterial.coefficientCredentials,
            bridgeSecret: ({ sourceTrusteeRosterPosition }) => ({
                secretCoefficients: compactVssTrusteeSecretCoefficients(
                    sourceTrusteeRosterPosition,
                    compactVssMaterial.ringDegree,
                ),
            }),
            bridgeProofRandomness: ({ sourceTrusteeRosterPosition }) => ({
                seedHex: kernel.deriveCanonicalObjectHash({
                    value: {
                        objectType: 'CompactSameSecretBridgeProofRandomness',
                        fixture: 'seed',
                        sourceTrusteeRosterPosition,
                    },
                }),
                nonceHex: kernel.deriveCanonicalObjectHash({
                    value: {
                        objectType: 'CompactSameSecretBridgeProofRandomness',
                        fixture: 'nonce',
                        sourceTrusteeRosterPosition,
                    },
                }),
            }),
            generateCompactSameSecretBridgeProof:
                compactSameSecretBridgeProofComputer,
        });

    return { bridgeStatementSet, bridgeProofMaterialSet };
}
