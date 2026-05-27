import { currentRecoveryEpochMap } from './fixtures.js';
import {
    lowerHexDigest,
    type ContributionBuild,
    type NegativeCheck,
    type TranscriptCoreKernel,
    type Variant,
} from './shared.js';

import {
    canonicalJson,
    deriveProtocolDigest,
} from '#packages/crypto/src/index';
import { selectFirstValidAggregateContributions } from '#packages/protocol/src/ballot-privacy/index';
import type {
    AggregateContribution,
    ProtocolDigest,
} from '#packages/types/src/index';

const assertFailure = (action: () => unknown): string | null => {
    try {
        const result = action();
        if (
            typeof result === 'object' &&
            result !== null &&
            'ok' in result &&
            (result as { readonly ok?: unknown }).ok === false
        ) {
            return null;
        }

        return 'mutation unexpectedly passed';
    } catch (error) {
        return `mutation threw a harness exception: ${
            error instanceof Error ? error.message : String(error)
        }`;
    }
};

const mutateLastHexDigit = (value: unknown): string => {
    const hex = String(value);
    const replacement = hex.endsWith('0') ? '1' : '0';

    return `${hex.slice(0, -1)}${replacement}`;
};

const bridgeWithMutatedProof = (
    bridgeEncryption: Record<string, unknown>,
    proofMutator: (proof: Record<string, unknown>) => void,
): Record<string, unknown> => {
    const proof = JSON.parse(
        Buffer.from(
            String(bridgeEncryption.bridgeProofBytesHex),
            'hex',
        ).toString('utf8'),
    ) as Record<string, unknown>;
    proofMutator(proof);
    const bridgeProofBytesHex = Buffer.from(
        canonicalJson(proof),
        'utf8',
    ).toString('hex');
    const bridgeProofBytesDigest = deriveProtocolDigest('ProofBytesDigest', {
        proofBytesHex: bridgeProofBytesHex,
        purpose: 'sealed-lattice-aggregate-bridge-encryption-proof-bytes-v1',
    });

    return {
        ...bridgeEncryption,
        bridgeProofBytesHex,
        bridgeProofBytesDigest,
        bridgeProofRoot: deriveProtocolDigest('BridgeProofRecordDigest', {
            aggregateDerivationComponentDigest:
                bridgeEncryption.aggregateDerivationComponentDigest,
            aggregateDerivationStatementDigest:
                bridgeEncryption.aggregateDerivationStatementDigest,
            bgvPublicKeyRoot: bridgeEncryption.bgvPublicKeyRoot,
            bridgeProofProfileDigest: bridgeEncryption.bridgeProofProfileDigest,
            bridgeProofStatementDigest:
                bridgeEncryption.bridgeProofStatementDigest,
            collectivePublicKeyRoot: bridgeEncryption.collectivePublicKeyRoot,
            encryptedAggregateShareCiphertextRoot:
                bridgeEncryption.encryptedAggregateShareCiphertextRoot,
            proofBytesDigest: bridgeProofBytesDigest,
            purpose: 'sealed-lattice-aggregate-bridge-encryption-proof-root-v1',
        }),
    };
};

export const runCheapNegativeChecks = (input: {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly contribution: ContributionBuild;
    readonly heParamDigest: ProtocolDigest;
    readonly kernel: TranscriptCoreKernel;
    readonly setupPackage: Record<string, unknown>;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const base = {
        optionCount: input.variant.optionCount,
        rosterSize: input.variant.rosterSize,
        suite: 'cheap' as const,
    };
    const verifyBridge = (
        aggregateDerivationComponent: unknown,
        bridgeEncryption: unknown,
        setupPackage: unknown,
        aggregateSelectionPolicyDigest = input.aggregateSelectionPolicyDigest,
    ): unknown =>
        input.kernel.verifyAggregateBridgeEncryption({
            aggregateDerivationComponent,
            aggregateSelectionPolicyDigest,
            bridgeEncryption,
            bridgeWitnessPrivacyProfileDigest:
                input.bridgeWitnessPrivacyProfileDigest,
            heParamDigest: input.heParamDigest,
            setupPackage,
        });
    const component = input.contribution.aggregateDerivationComponent;
    const bridgeEncryption = input.contribution.bridgeEncryption;
    const checks: readonly [string, () => unknown][] = [
        [
            'wrong n',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            participantCount:
                                component.statement.participantCount + 1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong m',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            optionCount: component.statement.optionCount + 1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong shareVectorWidth',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            shareVectorWidth:
                                component.statement.shareVectorWidth + 1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong threshold profile hash',
            () =>
                verifyBridge(component, bridgeEncryption, {
                    ...input.setupPackage,
                    setupInputs: {
                        ...(input.setupPackage.setupInputs as Record<
                            string,
                            unknown
                        >),
                        thresholdProfileDigest: lowerHexDigest(
                            'wrong-threshold-profile',
                        ),
                    },
                }),
        ],
        [
            'wrong contributor index',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            contributorRosterPosition:
                                component.statement.contributorRosterPosition +
                                1,
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong BGV profile hash',
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        profileDigest: lowerHexDigest('wrong-bgv-profile'),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong public key root',
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        bgvPublicKeyRoot: lowerHexDigest('wrong-bgv-key'),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong aggregate input layout hash',
            () =>
                verifyBridge(component, bridgeEncryption, {
                    ...input.setupPackage,
                    profileBindings: {
                        ...(input.setupPackage.profileBindings as Record<
                            string,
                            unknown
                        >),
                        encryptedAggregateInputLayoutDigest:
                            lowerHexDigest('wrong-layout'),
                    },
                }),
        ],
        [
            'wrong encrypted aggregate input root',
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        encryptedAggregateInputRoot: lowerHexDigest(
                            'wrong-encrypted-aggregate-input-root',
                        ),
                    },
                    input.setupPackage,
                ),
        ],
        [
            'wrong encrypted aggregate reconstruction hash',
            () =>
                verifyBridge(component, bridgeEncryption, {
                    ...input.setupPackage,
                    profileBindings: {
                        ...(input.setupPackage.profileBindings as Record<
                            string,
                            unknown
                        >),
                        encryptedAggregateReconstructionDigest: lowerHexDigest(
                            'wrong-encrypted-aggregate-reconstruction',
                        ),
                    },
                }),
        ],
        [
            'wrong VotingClosed hash',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            votingClosedBoardHeadDigest:
                                lowerHexDigest('wrong-board-head'),
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'wrong selected ballot set hash',
            () =>
                verifyBridge(
                    {
                        ...component,
                        statement: {
                            ...component.statement,
                            ballotSetDigest: lowerHexDigest('wrong-ballot-set'),
                        },
                    },
                    bridgeEncryption,
                    input.setupPackage,
                ),
        ],
        [
            'pending bridge record selected',
            () => {
                const pendingContribution: AggregateContribution = {
                    ...input.contribution.aggregateContribution,
                    bridgeProofRecord: {
                        ...input.contribution.aggregateContribution
                            .bridgeProofRecord,
                        bridgeProofVerificationStatus:
                            'BridgeProofBackendPending',
                    },
                };

                return selectFirstValidAggregateContributions({
                    aggregateContributionQuorum: 1,
                    contributions: [pendingContribution],
                    currentRecoveryEpochMap: currentRecoveryEpochMap([
                        pendingContribution,
                    ]),
                    expectedAggregateSelectionPolicyDigest:
                        input.aggregateSelectionPolicyDigest,
                    requiredPostVotingClosedContextDigest:
                        pendingContribution.postVotingClosedContextDigest,
                });
            },
        ],
        [
            'sampled-only bridge evidence accepted',
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        bridgeProofVerificationStatus:
                            'BridgeProofBackendPending',
                    },
                    input.setupPackage,
                ),
        ],
        [
            'witness disclosure flag present',
            () =>
                verifyBridge(
                    component,
                    {
                        ...bridgeEncryption,
                        bgvPlaintext: [1, 2, 3],
                    },
                    input.setupPackage,
                ),
        ],
    ];

    return checks.map(([check, action]) => {
        const failureReason = assertFailure(action);

        return {
            ...base,
            check,
            expectedFailureObserved: failureReason === null,
            failureReason,
        };
    });
};

export const runSentinelNegativeChecks = (input: {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly bridgeWitnessPrivacyProfileDigest: ProtocolDigest;
    readonly contribution: ContributionBuild;
    readonly heParamDigest: ProtocolDigest;
    readonly kernel: TranscriptCoreKernel;
    readonly setupPackage: Record<string, unknown>;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const base = {
        optionCount: input.variant.optionCount,
        rosterSize: input.variant.rosterSize,
        suite: 'sentinel' as const,
    };
    const verifyMutatedProof = (
        check: string,
        proofMutator: (proof: Record<string, unknown>) => void,
    ): NegativeCheck => {
        const mutatedBridge = bridgeWithMutatedProof(
            input.contribution.bridgeEncryption,
            proofMutator,
        );
        const failureReason = assertFailure(() =>
            input.kernel.verifyAggregateBridgeEncryption({
                aggregateDerivationComponent:
                    input.contribution.aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    input.aggregateSelectionPolicyDigest,
                bridgeEncryption: mutatedBridge,
                bridgeWitnessPrivacyProfileDigest:
                    input.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: input.heParamDigest,
                setupPackage: input.setupPackage,
            }),
        );

        return {
            ...base,
            check,
            expectedFailureObserved: failureReason === null,
            failureReason,
        };
    };
    const verifyMutatedPublicInput = (
        check: string,
        mutation: {
            readonly aggregateDerivationComponent?: unknown;
            readonly bridgeEncryption?: unknown;
            readonly setupPackage?: unknown;
        },
    ): NegativeCheck => {
        const failureReason = assertFailure(() =>
            input.kernel.verifyAggregateBridgeEncryption({
                aggregateDerivationComponent:
                    mutation.aggregateDerivationComponent ??
                    input.contribution.aggregateDerivationComponent,
                aggregateSelectionPolicyDigest:
                    input.aggregateSelectionPolicyDigest,
                bridgeEncryption:
                    mutation.bridgeEncryption ??
                    input.contribution.bridgeEncryption,
                bridgeWitnessPrivacyProfileDigest:
                    input.bridgeWitnessPrivacyProfileDigest,
                heParamDigest: input.heParamDigest,
                setupPackage: mutation.setupPackage ?? input.setupPackage,
            }),
        );

        return {
            ...base,
            check,
            expectedFailureObserved: failureReason === null,
            failureReason,
        };
    };
    const mutateSharedWitnessResponse =
        (fieldName: string): ((proof: Record<string, unknown>) => void) =>
        (proof) => {
            const sharedProof = proof.bridgeSharedWitnessProof as {
                readonly checks: Record<string, unknown>[];
            };
            sharedProof.checks[0][fieldName] = mutateLastHexDigit(
                sharedProof.checks[0][fieldName],
            );
        };
    const checks = [
        verifyMutatedProof(
            'wrong M6 opening',
            mutateSharedWitnessResponse('aggregateOpeningResponseHex'),
        ),
        verifyMutatedProof(
            'wrong reduced coordinate',
            mutateSharedWitnessResponse('aggregateReducedResponseHex'),
        ),
        verifyMutatedProof(
            'wrong quotient',
            mutateSharedWitnessResponse('aggregateQuotientResponseHex'),
        ),
        verifyMutatedPublicInput('wrong quotient bound', {
            aggregateDerivationComponent: {
                ...input.contribution.aggregateDerivationComponent,
                shareCommitmentMessageBoundCert: {
                    ...input.contribution.aggregateDerivationComponent
                        .shareCommitmentMessageBoundCert,
                    quotientBoundForAggregateReduction:
                        input.contribution.aggregateDerivationComponent
                            .shareCommitmentMessageBoundCert
                            .quotientBoundForAggregateReduction + 1,
                },
            },
        }),
        verifyMutatedProof(
            'wrong encoded coordinate order',
            mutateSharedWitnessResponse('aggregateShareResponseHex'),
        ),
        verifyMutatedProof('wrong slot layout', (proof) => {
            const statement = proof.bridgeProofStatement as Record<
                string,
                unknown
            >;
            statement.bridgeLayoutDigest = lowerHexDigest('wrong-slot-layout');
        }),
        verifyMutatedProof(
            'wrong batch encoding',
            mutateSharedWitnessResponse('batchCoefficientResponseHex'),
        ),
        verifyMutatedProof('wrong plaintext polynomial', (proof) => {
            proof.plaintextRoot = lowerHexDigest('wrong-plaintext-polynomial');
        }),
        verifyMutatedPublicInput('wrong RNS limb', {
            bridgeEncryption: {
                ...input.contribution.bridgeEncryption,
                canonicalBytesHex: mutateLastHexDigit(
                    input.contribution.bridgeEncryption.canonicalBytesHex,
                ),
            },
        }),
        verifyMutatedPublicInput('wrong ciphertext component', {
            bridgeEncryption: {
                ...input.contribution.bridgeEncryption,
                ciphertextRoot: lowerHexDigest('wrong-ciphertext-component'),
            },
        }),
        verifyMutatedProof(
            'wrong encryption randomness',
            mutateSharedWitnessResponse('cipherRandomizerResponseHex'),
        ),
        verifyMutatedProof(
            'wrong noise bound',
            mutateSharedWitnessResponse('boundedPerturbationZeroResponseHex'),
        ),
        verifyMutatedPublicInput('wrong collective public key', {
            setupPackage: {
                ...input.setupPackage,
                collectivePublicKey: {
                    ...(input.setupPackage.collectivePublicKey as Record<
                        string,
                        unknown
                    >),
                    collectivePublicKeyRoot: lowerHexDigest(
                        'wrong-collective-public-key',
                    ),
                },
            },
        }),
        verifyMutatedPublicInput('wrong setup root', {
            setupPackage: {
                ...input.setupPackage,
                setupPackageDigest: lowerHexDigest('wrong-setup-package'),
            },
        }),
        verifyMutatedPublicInput('wrong board context', {
            aggregateDerivationComponent: {
                ...input.contribution.aggregateDerivationComponent,
                statement: {
                    ...input.contribution.aggregateDerivationComponent
                        .statement,
                    votingClosedBoardHeadDigest: lowerHexDigest(
                        'wrong-board-context',
                    ),
                },
            },
        }),
        verifyMutatedPublicInput('wrong action context', {
            aggregateDerivationComponent: {
                ...input.contribution.aggregateDerivationComponent,
                statement: {
                    ...input.contribution.aggregateDerivationComponent
                        .statement,
                    contributorActionContextDigest: lowerHexDigest(
                        'wrong-action-context',
                    ),
                },
            },
        }),
        verifyMutatedProof(
            'same M6 subproof but different BGV plaintext',
            (proof) => {
                proof.plaintextRoot = lowerHexDigest('wrong-plaintext-root');
            },
        ),
        verifyMutatedProof(
            'same BGV ciphertext but different M6 commitment',
            (proof) => {
                proof.aggregateRelationCommitmentDigest = lowerHexDigest(
                    'wrong-aggregate-relation',
                );
            },
        ),
        verifyMutatedProof('forged BridgeProofRelationChecked', (proof) => {
            proof.bridgeSharedWitnessProof = {
                objectType: 'AggregateBridgeSharedWitnessProof',
            };
        }),
        verifyMutatedProof(
            'witness field included in public artifact',
            (proof) => {
                proof.aggregateIntegerShareVector = [1, 2, 3];
            },
        ),
    ];

    return checks;
};

export const runSelectionNegativeChecks = (input: {
    readonly aggregateSelectionPolicyDigest: ProtocolDigest;
    readonly postVotingClosedContextDigest: ProtocolDigest;
    readonly selectedContributionRecords: readonly AggregateContribution[];
    readonly trusteeAggregateThreshold: number;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const remainingContributions = input.selectedContributionRecords.slice(1);
    const failureReason = assertFailure(() =>
        selectFirstValidAggregateContributions({
            aggregateContributionQuorum: input.trusteeAggregateThreshold,
            contributions: remainingContributions,
            currentRecoveryEpochMap: currentRecoveryEpochMap(
                remainingContributions,
            ),
            expectedAggregateSelectionPolicyDigest:
                input.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                input.postVotingClosedContextDigest,
        }),
    );
    const firstContribution = input.selectedContributionRecords[0];
    const staleRecoveryEpochFailureReason = assertFailure(() =>
        selectFirstValidAggregateContributions({
            aggregateContributionQuorum: input.trusteeAggregateThreshold,
            contributions: input.selectedContributionRecords,
            currentRecoveryEpochMap: {
                ...currentRecoveryEpochMap(input.selectedContributionRecords),
                [firstContribution.contributorIdentity]: {
                    currentDeviceEpoch: firstContribution.deviceEpoch,
                    currentRecoveryEpoch: firstContribution.recoveryEpoch + 1,
                    signerIdentity: firstContribution.contributorIdentity,
                },
            },
            expectedAggregateSelectionPolicyDigest:
                input.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                input.postVotingClosedContextDigest,
        }),
    );
    const clonedDeviceEpochFailureReason = assertFailure(() =>
        selectFirstValidAggregateContributions({
            aggregateContributionQuorum: input.trusteeAggregateThreshold,
            contributions: input.selectedContributionRecords,
            currentRecoveryEpochMap: {
                ...currentRecoveryEpochMap(input.selectedContributionRecords),
                [firstContribution.contributorIdentity]: {
                    currentDeviceEpoch: firstContribution.deviceEpoch + 1,
                    currentRecoveryEpoch: firstContribution.recoveryEpoch,
                    signerIdentity: firstContribution.contributorIdentity,
                },
            },
            expectedAggregateSelectionPolicyDigest:
                input.aggregateSelectionPolicyDigest,
            requiredPostVotingClosedContextDigest:
                input.postVotingClosedContextDigest,
        }),
    );

    return [
        {
            check: 'wrong selected contributor set',
            expectedFailureObserved: failureReason === null,
            failureReason,
            optionCount: input.variant.optionCount,
            rosterSize: input.variant.rosterSize,
            suite: 'cheap',
        },
        {
            check: 'stale recovery epoch',
            expectedFailureObserved: staleRecoveryEpochFailureReason === null,
            failureReason: staleRecoveryEpochFailureReason,
            optionCount: input.variant.optionCount,
            rosterSize: input.variant.rosterSize,
            suite: 'cheap',
        },
        {
            check: 'cloned device epoch',
            expectedFailureObserved: clonedDeviceEpochFailureReason === null,
            failureReason: clonedDeviceEpochFailureReason,
            optionCount: input.variant.optionCount,
            rosterSize: input.variant.rosterSize,
            suite: 'cheap',
        },
    ];
};
