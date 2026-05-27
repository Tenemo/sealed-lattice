import type {
    AggregateContributionSelection,
    AggregateContributionSelectionInput,
    RefusalRecord,
} from '@sealed-lattice/types';

import {
    createRefusal,
    uniqueStrings,
} from '../../../common/verification-helpers.js';
import { deriveValidatedFirstValidOrder } from '../../../ordering/index.js';
import { deriveSelectedAggregateContributionOrderDigest } from '../digests.js';

import { verifyAggregateContributionStructure } from './aggregate-contribution.js';

export const selectFirstValidAggregateContributions = (
    input: AggregateContributionSelectionInput,
): AggregateContributionSelection => {
    const refusedObjects: RefusalRecord[] = [];
    if (
        !Number.isSafeInteger(input.aggregateContributionQuorum) ||
        input.aggregateContributionQuorum <= 0
    ) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'Aggregate contribution quorum must be a positive safe integer.',
                input.expectedAggregateSelectionPolicyDigest,
            ),
        );
    }
    const structurallyValidContributions = input.contributions.filter(
        (contribution) => {
            const verification =
                verifyAggregateContributionStructure(contribution);
            if (!verification.ok) {
                refusedObjects.push(...verification.refusedObjects);
                return false;
            }
            if (
                contribution.bridgeProofRecord.bridgeProofVerificationStatus !==
                'BridgeProofRelationChecked'
            ) {
                refusedObjects.push(
                    createRefusal(
                        'OperationUnavailable',
                        'Aggregate contribution is not proof-valid for the supported bridge relation.',
                        contribution.aggregateContributionDigest,
                        'AggregateContribution',
                    ),
                );
                return false;
            }

            return true;
        },
    );
    const firstValidOrdering = deriveValidatedFirstValidOrder({
        currentRecoveryEpochMap: input.currentRecoveryEpochMap,
        expectedSelectionPolicyDigest:
            input.expectedAggregateSelectionPolicyDigest,
        maxPerIdentity: 1,
        objects: structurallyValidContributions.map((contribution) => ({
            actionSequence: contribution.actionSequence,
            boardPosition: contribution.boardPosition,
            boardSequence: contribution.boardSequence,
            contextDigest: contribution.postVotingClosedContextDigest,
            deviceEpoch: contribution.deviceEpoch,
            isByteIdenticalRetransmission: false,
            objectDigest: contribution.aggregateContributionDigest,
            objectType: 'AggregateContribution',
            recoveryEpoch: contribution.recoveryEpoch,
            signerIdentity: contribution.contributorIdentity,
        })),
        requiredContextDigest: input.requiredPostVotingClosedContextDigest,
        selectionPolicyDigest: input.expectedAggregateSelectionPolicyDigest,
    });
    refusedObjects.push(...firstValidOrdering.refusedObjects);

    const contributionByDigest = new Map(
        structurallyValidContributions.map((contribution) => [
            contribution.aggregateContributionDigest,
            contribution,
        ]),
    );
    const orderedContributions = firstValidOrdering.orderedObjects.flatMap(
        (orderedObject) => {
            const contribution = contributionByDigest.get(
                orderedObject.objectDigest,
            );

            return contribution === undefined ? [] : [contribution];
        },
    );
    const selectedContributions = orderedContributions.slice(
        0,
        input.aggregateContributionQuorum,
    );
    if (selectedContributions.length < input.aggregateContributionQuorum) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'Not enough proof-valid aggregate contributions exist for the aggregate quorum.',
                input.expectedAggregateSelectionPolicyDigest,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            acceptedDigests: [],
            firstValidOrderDigest: undefined,
            ok: false,
            orderedContributionDigests: orderedContributions.map(
                (contribution) => contribution.aggregateContributionDigest,
            ),
            refusedObjects,
            selectedContributions: [],
            statusLabels: [],
            unresolvedReason:
                refusedObjects[0]?.code ?? 'FirstValidPolicyMismatch',
        };
    }

    const firstValidOrderDigest =
        deriveSelectedAggregateContributionOrderDigest({
            requiredPostVotingClosedContextDigest:
                input.requiredPostVotingClosedContextDigest,
            selectedAggregateContributionDigests: selectedContributions.map(
                (contribution) => contribution.aggregateContributionDigest,
            ),
            selectionPolicyDigest: input.expectedAggregateSelectionPolicyDigest,
        });

    return {
        acceptedDigests: uniqueStrings([
            firstValidOrderDigest,
            ...selectedContributions.map(
                (contribution) => contribution.aggregateContributionDigest,
            ),
        ]),
        firstValidOrderDigest,
        ok: true,
        orderedContributionDigests: orderedContributions.map(
            (contribution) => contribution.aggregateContributionDigest,
        ),
        refusedObjects: [],
        selectedContributions,
        statusLabels: [],
        unresolvedReason: null,
    };
};
