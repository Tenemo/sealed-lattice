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
import { deriveSelectedAggregateContributionOrderHash } from '../hashes.js';

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
                input.expectedAggregateSelectionPolicyHash,
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
                        contribution.aggregateContributionHash,
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
        expectedSelectionPolicyHash: input.expectedAggregateSelectionPolicyHash,
        maxPerIdentity: 1,
        objects: structurallyValidContributions.map((contribution) => ({
            actionSequence: contribution.actionSequence,
            boardPosition: contribution.boardPosition,
            boardSequence: contribution.boardSequence,
            contextHash: contribution.postVotingClosedContextHash,
            deviceEpoch: contribution.deviceEpoch,
            isByteIdenticalRetransmission: false,
            objectHash: contribution.aggregateContributionHash,
            objectType: 'AggregateContribution',
            recoveryEpoch: contribution.recoveryEpoch,
            signerIdentity: contribution.contributorIdentity,
        })),
        requiredContextHash: input.requiredPostVotingClosedContextHash,
        selectionPolicyHash: input.expectedAggregateSelectionPolicyHash,
    });
    refusedObjects.push(...firstValidOrdering.refusedObjects);

    const contributionByHash = new Map(
        structurallyValidContributions.map((contribution) => [
            contribution.aggregateContributionHash,
            contribution,
        ]),
    );
    const orderedContributions = firstValidOrdering.orderedObjects.flatMap(
        (orderedObject) => {
            const contribution = contributionByHash.get(
                orderedObject.objectHash,
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
                input.expectedAggregateSelectionPolicyHash,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            acceptedHashes: [],
            firstValidOrderHash: undefined,
            ok: false,
            orderedContributionHashes: orderedContributions.map(
                (contribution) => contribution.aggregateContributionHash,
            ),
            refusedObjects,
            selectedContributions: [],
            statusLabels: [],
            unresolvedReason:
                refusedObjects[0]?.code ?? 'FirstValidPolicyMismatch',
        };
    }

    const firstValidOrderHash = deriveSelectedAggregateContributionOrderHash({
        requiredPostVotingClosedContextHash:
            input.requiredPostVotingClosedContextHash,
        selectedAggregateContributionHashes: selectedContributions.map(
            (contribution) => contribution.aggregateContributionHash,
        ),
        selectionPolicyHash: input.expectedAggregateSelectionPolicyHash,
    });

    return {
        acceptedHashes: uniqueStrings([
            firstValidOrderHash,
            ...selectedContributions.map(
                (contribution) => contribution.aggregateContributionHash,
            ),
        ]),
        firstValidOrderHash,
        ok: true,
        orderedContributionHashes: orderedContributions.map(
            (contribution) => contribution.aggregateContributionHash,
        ),
        refusedObjects: [],
        selectedContributions,
        statusLabels: [],
        unresolvedReason: null,
    };
};
