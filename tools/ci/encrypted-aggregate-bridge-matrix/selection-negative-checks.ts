import { currentRecoveryEpochMap } from './fixtures.js';
import {
    assertFailure,
    expectedVerifierFailure,
} from './negative-check-assertions.js';
import { type NegativeCheck, type Variant } from './shared.js';

import { selectFirstValidAggregateContributions } from '#packages/protocol/src/ballot-privacy/index';
import type {
    AggregateContribution,
    ProtocolHash,
} from '#packages/types/src/index';

export const runSelectionNegativeChecks = (input: {
    readonly aggregateSelectionPolicyHash: ProtocolHash;
    readonly postVotingClosedContextHash: ProtocolHash;
    readonly selectedContributionRecords: readonly AggregateContribution[];
    readonly trusteeAggregateThreshold: number;
    readonly variant: Variant;
}): readonly NegativeCheck[] => {
    const remainingContributions = input.selectedContributionRecords.slice(1);
    const failureReason = assertFailure(
        () =>
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: input.trusteeAggregateThreshold,
                contributions: remainingContributions,
                currentRecoveryEpochMap: currentRecoveryEpochMap(
                    remainingContributions,
                ),
                expectedAggregateSelectionPolicyHash:
                    input.aggregateSelectionPolicyHash,
                requiredPostVotingClosedContextHash:
                    input.postVotingClosedContextHash,
            }),
        expectedVerifierFailure(
            'selected contribution quorum refusal',
            /quorum|selected|contribution|valid/iu,
        ),
    );
    const firstContribution = input.selectedContributionRecords[0];
    const staleRecoveryEpochFailureReason = assertFailure(
        () =>
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: input.trusteeAggregateThreshold,
                contributions: input.selectedContributionRecords,
                currentRecoveryEpochMap: {
                    ...currentRecoveryEpochMap(
                        input.selectedContributionRecords,
                    ),
                    [firstContribution.contributorIdentity]: {
                        currentDeviceEpoch: firstContribution.deviceEpoch,
                        currentRecoveryEpoch:
                            firstContribution.recoveryEpoch + 1,
                        signerIdentity: firstContribution.contributorIdentity,
                    },
                },
                expectedAggregateSelectionPolicyHash:
                    input.aggregateSelectionPolicyHash,
                requiredPostVotingClosedContextHash:
                    input.postVotingClosedContextHash,
            }),
        expectedVerifierFailure(
            'stale recovery epoch refusal',
            /recovery epoch|stale|epoch|current/iu,
        ),
    );
    const clonedDeviceEpochFailureReason = assertFailure(
        () =>
            selectFirstValidAggregateContributions({
                aggregateContributionQuorum: input.trusteeAggregateThreshold,
                contributions: input.selectedContributionRecords,
                currentRecoveryEpochMap: {
                    ...currentRecoveryEpochMap(
                        input.selectedContributionRecords,
                    ),
                    [firstContribution.contributorIdentity]: {
                        currentDeviceEpoch: firstContribution.deviceEpoch + 1,
                        currentRecoveryEpoch: firstContribution.recoveryEpoch,
                        signerIdentity: firstContribution.contributorIdentity,
                    },
                },
                expectedAggregateSelectionPolicyHash:
                    input.aggregateSelectionPolicyHash,
                requiredPostVotingClosedContextHash:
                    input.postVotingClosedContextHash,
            }),
        expectedVerifierFailure(
            'cloned device epoch refusal',
            /device epoch|cloned|epoch|current/iu,
        ),
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
