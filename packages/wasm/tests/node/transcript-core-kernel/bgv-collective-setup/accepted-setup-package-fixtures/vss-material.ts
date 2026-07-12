import {
    minimumSuccinctProofFixtureRingDegree,
    type JsonRecord,
} from '../setup-fixture-primitives.js';

import type { SetupProofMaterialChunkSource } from '#packages/protocol/src/setup/setup-proof-material-transport';
import {
    createVssCoefficientCommitmentBundle,
    type VssCoefficientCommitmentMaterialSet,
    type VssCoefficientCommitmentSet,
    type VssSourceTrusteeCoefficientOpeningState,
} from '#packages/protocol/src/setup/vss-coefficient-commitments';
import {
    appendVssAggregateThresholdProofMaterials,
    createThresholdShareCommitmentBinding,
    assembleVssPublicAggregateThresholdCommitmentSet,
    createBinaryChunkedSameSecretBridgeProofMaterialTransport,
    createBinaryChunkedVssShareLinkageProofMaterialTransport,
    createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle,
    createVssPublicCoefficientCommitmentSet,
    createVssPublicRecipientShareCommitmentSet,
    createVssSameSecretBridgeProofMaterialSet,
    createVssSameSecretBridgeStatementSet,
    createVssShareLinkageProofMaterialSet,
    createVssShareLinkageStatement,
    type TransportedSameSecretBridgeProofMaterialSet,
    type TransportedVssShareLinkageProofMaterialSet,
    type VssCommittedMaterialSeedProvider,
    type VssPublicCoefficientCommitmentSet,
    type VssPublicCoefficientCredential,
    type LocalTrusteeVssPublicAggregateOpeningCredentialHandoff,
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

// Deterministic private material seed per committed-material commitment. It is
// opaque to the verifier (the commitment is hiding), so any deterministic
// 128-character lowercase hexadecimal value works as long as the commit and the
// proof reuse the same seed, which the builders guarantee by threading it
// through the credentials. The canonical object hash already has the required
// protocol-hash shape, so the fixture derives seeds from the commitment
// coordinates through the kernel instead of inventing new derivation code.
const vssCommittedMaterialSeedProvider = (
    kernel: TranscriptCoreKernel,
): VssCommittedMaterialSeedProvider => {
    return (input) =>
        kernel.deriveCanonicalObjectHash({
            value: {
                objectType: 'VssCommittedMaterialSeedFixture',
                commitmentRole: input.commitmentRole,
                rnsLimbIndex: input.rnsLimbIndex,
                rnsPrime: input.rnsPrime,
                ...(input.sourceTrusteeRosterPosition === undefined
                    ? {}
                    : {
                          sourceTrusteeRosterPosition:
                              input.sourceTrusteeRosterPosition,
                      }),
                ...(input.shamirCoefficientIndex === undefined
                    ? {}
                    : {
                          shamirCoefficientIndex: input.shamirCoefficientIndex,
                      }),
                ...(input.recipientRosterPosition === undefined
                    ? {}
                    : {
                          recipientRosterPosition:
                              input.recipientRosterPosition,
                      }),
            },
        });
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
    readonly localTrusteeAggregateOpeningCredentialHandoffs: readonly LocalTrusteeVssPublicAggregateOpeningCredentialHandoff[];
    readonly shareLinkageStatement: JsonRecord;
    readonly shareLinkageProofMaterialSet: JsonRecord;
    readonly transportedVssShareLinkageProofMaterial: TransportedVssShareLinkageProofMaterialSet;
    readonly thresholdShareCommitmentBinding: JsonRecord;
    readonly coefficientCredentials: readonly VssPublicCoefficientCredential[];
    readonly proofMaterialChunkSources: readonly SetupProofMaterialChunkSource[];
    readonly ringDegree: number;
};

// Build the VSS public material (coefficient, recipient-share and
// aggregate threshold commitment sets, the share-linkage statement and proof
// material, and the threshold-share commitment binding) by driving the
// protocol builders with the kernel-backed commitment and proof
// computers. The same-secret bridge is built separately because it also binds
// the accepted same-secret proof.
export async function acceptedVssPublicMaterial(
    kernel: TranscriptCoreKernel,
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    publicMatrixSeedHash: string,
): Promise<VssPublicMaterial> {
    const vssCommitmentComputers = createVssCommitmentComputers(kernel);
    const {
        vssCommittedMaterialCommitmentComputer,
        vssAggregateThresholdProofComputer,
        vssShareLinkageProofComputer,
    } = vssCommitmentComputers;
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
    const committedMaterialSeed = vssCommittedMaterialSeedProvider(kernel);

    const coefficientCommitmentBundle = createVssPublicCoefficientCommitmentSet(
        {
            setupContext,
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes,
            ringDegree,
            thresholdDegree,
            sourceTrusteeOpeningStates,
            committedMaterialSeed,
            computeVssCommittedMaterialCommitment:
                vssCommittedMaterialCommitmentComputer,
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
            committedMaterialSeed,
            computeVssCommittedMaterialCommitment:
                vssCommittedMaterialCommitmentComputer,
        });
    const localAggregateThresholdCommitmentBundles = [];
    for (
        let localTrusteeRosterPosition = 0;
        localTrusteeRosterPosition < participantCount;
        localTrusteeRosterPosition += 1
    ) {
        localAggregateThresholdCommitmentBundles.push(
            await createLocalTrusteeVssPublicAggregateThresholdCommitmentBundle(
                {
                    setupContext,
                    publicMatrixSeedHash,
                    participantCount,
                    qSharePrimes,
                    ringDegree,
                    coefficientCommitmentSet:
                        coefficientCommitmentBundle.coefficientCommitmentSet,
                    recipientShareCommitmentSet:
                        recipientShareCommitmentBundle.recipientShareCommitmentSet,
                    localTrusteeRosterPosition,
                    localRecipientShareCredentials:
                        recipientShareCommitmentBundle.recipientShareCredentials.filter(
                            (credential) =>
                                credential.recipientRosterPosition ===
                                localTrusteeRosterPosition,
                        ),
                    committedMaterialSeed,
                    computeVssCommittedMaterialCommitment:
                        vssCommittedMaterialCommitmentComputer,
                    aggregateThresholdProofRandomness: ({
                        recipientRosterPosition,
                        rnsLimbIndex,
                    }) => ({
                        seedHex: kernel.deriveCanonicalObjectHash({
                            value: {
                                objectType:
                                    'VssAggregateThresholdProofRandomness',
                                fixture: 'seed',
                                recipientRosterPosition,
                                rnsLimbIndex,
                            },
                        }),
                        nonceHex: kernel.deriveCanonicalObjectHash({
                            value: {
                                objectType:
                                    'VssAggregateThresholdProofRandomness',
                                fixture: 'nonce',
                                recipientRosterPosition,
                                rnsLimbIndex,
                            },
                        }),
                    }),
                    generateVssShareLinkageProof:
                        vssAggregateThresholdProofComputer,
                },
            ),
        );
    }
    const aggregateThresholdCommitmentSet =
        assembleVssPublicAggregateThresholdCommitmentSet({
            publicMatrixSeedHash,
            participantCount,
            qSharePrimes,
            ringDegree,
            recipientShareCommitmentSet:
                recipientShareCommitmentBundle.recipientShareCommitmentSet,
            publicAggregateThresholdCommitmentContributions:
                localAggregateThresholdCommitmentBundles.map(
                    (bundle) =>
                        bundle.publicAggregateThresholdCommitmentContribution,
                ),
        });
    const shareLinkageStatement = createVssShareLinkageStatement({
        setupContext,
        publicMatrixSeedHash,
        coefficientCommitmentSet:
            coefficientCommitmentBundle.coefficientCommitmentSet,
        recipientShareCommitmentSet:
            recipientShareCommitmentBundle.recipientShareCommitmentSet,
        aggregateThresholdCommitmentSet,
    });
    const embeddedShareLinkageProofMaterialSet =
        await createVssShareLinkageProofMaterialSet({
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
        appendVssAggregateThresholdProofMaterials(
            shareLinkageProofTransport.transportedVssShareLinkageProofMaterial,
            localAggregateThresholdCommitmentBundles.flatMap(
                (bundle) => bundle.aggregateThresholdProofMaterials,
            ),
        );
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
        localTrusteeAggregateOpeningCredentialHandoffs:
            localAggregateThresholdCommitmentBundles.map(
                (bundle) =>
                    bundle.localTrusteeAggregateOpeningCredentialHandoff,
            ),
        shareLinkageStatement,
        shareLinkageProofMaterialSet,
        transportedVssShareLinkageProofMaterial,
        thresholdShareCommitmentBinding,
        coefficientCredentials:
            coefficientCommitmentBundle.coefficientCredentials,
        proofMaterialChunkSources:
            vssCommitmentComputers.proofMaterialChunkSources(),
        ringDegree,
    };
}

export type SameSecretBridge = {
    readonly bridgeStatementSet: JsonRecord;
    readonly bridgeProofMaterialSet: JsonRecord;
    readonly transportedSameSecretBridgeProofMaterial: TransportedSameSecretBridgeProofMaterialSet;
    readonly sourceCoefficientCommitmentSet: VssCoefficientCommitmentSet;
    readonly sourceCoefficientCommitmentMaterialSet: VssCoefficientCommitmentMaterialSet;
    readonly proofMaterialChunkSources: readonly SetupProofMaterialChunkSource[];
};

const sourceCommitmentRandomness = (
    sourceTrusteeRosterPosition: number,
    rnsLimbIndex: number,
    shamirCoefficientIndex: number,
    ringDegree: number,
): number[][] =>
    Array.from({ length: 5 }, (_unusedColumn, randomnessColumnIndex) =>
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

// Build the combined bridge: canonical BDLOP source commitments and target
// committed material are proven to share one centered ternary trustee secret.
export async function acceptedSameSecretBridge(
    kernel: TranscriptCoreKernel,
    setupContext: CollectiveBgvSetupContext,
    parameters: BgvCollectiveSetupParametersDescription,
    publicMatrixSeedHash: string,
    vssPublicMaterial: VssPublicMaterial,
): Promise<SameSecretBridge> {
    const vssCommitmentComputers = createVssCommitmentComputers(kernel);
    const { sameSecretBridgeProofComputer } = vssCommitmentComputers;
    const ringDegree = vssPublicMaterial.ringDegree;
    const sourceTrusteeOpeningStates: VssSourceTrusteeCoefficientOpeningState[] =
        Array.from(
            { length: parameters.participantCount },
            (_unusedTrustee, sourceTrusteeRosterPosition) => ({
                sourceTrusteeIdentity: `trustee-${String(sourceTrusteeRosterPosition)}`,
                sourceTrusteeRosterPosition,
                coefficientOpenings: parameters.qShare.primes.flatMap(
                    (rnsPrime, rnsLimbIndex) =>
                        Array.from(
                            { length: parameters.qDec },
                            (_unusedCoefficient, shamirCoefficientIndex) => ({
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
                                randomnessByColumn: sourceCommitmentRandomness(
                                    sourceTrusteeRosterPosition,
                                    rnsLimbIndex,
                                    shamirCoefficientIndex,
                                    ringDegree,
                                ),
                            }),
                        ),
                ),
            }),
        );
    const sourceCommitmentBundle = createVssCoefficientCommitmentBundle({
        setupContext,
        publicMatrixSeedHash,
        qSharePrimes: parameters.qShare.primes,
        ringDegree,
        participantCount: parameters.participantCount,
        thresholdDegree: parameters.qDec,
        sourceTrusteeOpeningStates,
        setupCommitmentComputer: (commitmentInput) =>
            kernel.computeSetupCommitmentFromOpening(commitmentInput),
    });
    const bridgeStatementSet = createVssSameSecretBridgeStatementSet({
        setupContext,
        publicMatrixSeedHash,
        coefficientCommitmentSet: vssPublicMaterial.coefficientCommitmentSet,
        sourceCoefficientCommitmentSet: sourceCommitmentBundle.commitmentSet,
        sourceCoefficientCommitmentMaterialSet:
            sourceCommitmentBundle.materialSet,
    });
    const embeddedBridgeProofMaterialSet =
        await createVssSameSecretBridgeProofMaterialSet({
            deriveProofMaterialSetRoot: false,
            statementSet: bridgeStatementSet,
            coefficientCredentials: vssPublicMaterial.coefficientCredentials,
            sourceWitness: ({ sourceTrusteeRosterPosition }) => {
                const sourceOpeningMaterial =
                    sourceCommitmentBundle
                        .privateOpeningMaterialBySourceTrustee[
                        sourceTrusteeRosterPosition
                    ];
                if (sourceOpeningMaterial === undefined) {
                    throw new Error(
                        'Same-secret bridge fixture requires source opening material for every trustee.',
                    );
                }
                const sourceConstantOpenings = [
                    ...sourceOpeningMaterial.coefficientOpenings.filter(
                        (opening) => opening.shamirCoefficientIndex === 0,
                    ),
                ].sort((left, right) => left.rnsLimbIndex - right.rnsLimbIndex);
                return {
                    secretCoefficients: vssPublicTrusteeSecretCoefficients(
                        sourceTrusteeRosterPosition,
                        ringDegree,
                    ),
                    sourceOpeningRandomnessByLimb: sourceConstantOpenings.map(
                        (opening) => opening.randomnessByColumn,
                    ),
                };
            },
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
        sourceCoefficientCommitmentSet: sourceCommitmentBundle.commitmentSet,
        sourceCoefficientCommitmentMaterialSet:
            sourceCommitmentBundle.materialSet,
        proofMaterialChunkSources:
            vssCommitmentComputers.proofMaterialChunkSources(),
    };
}
