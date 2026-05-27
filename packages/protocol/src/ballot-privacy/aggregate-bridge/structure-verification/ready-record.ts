import type {
    AggregateContribution,
    AggregateReadyRecord,
    AggregateReadyRecordBuildInput,
    InterpolationCoefficientReport,
    ProtocolDigest,
    RefusalRecord,
} from '@sealed-lattice/types';

import { deriveInterpolationCoefficientReport } from '../../../plaintext-oracle/index.js';
import {
    createAggregateRefusal,
    protocolDigestPattern,
} from '../../aggregate-derivation/constants.js';
import {
    deriveAggregateReadyRecordDigest,
    deriveEncryptedAggregateReconstructionRoot,
    deriveSelectedAggregateContributionOrderDigest,
} from '../digests.js';

import { verifyAggregateContributionStructure } from './aggregate-contribution.js';
import {
    aggregateReadyDigestFieldNames,
    collectDigestShapeRefusals,
    collectForbiddenWitnessFieldRefusals,
} from './shared.js';

const interpolationReportsMatch = (
    leftReport: InterpolationCoefficientReport,
    rightReport: InterpolationCoefficientReport,
): boolean =>
    leftReport.reportDigest === rightReport.reportDigest &&
    leftReport.centeredL1CoefficientSum ===
        rightReport.centeredL1CoefficientSum &&
    leftReport.maxCenteredAbsCoefficient ===
        rightReport.maxCenteredAbsCoefficient &&
    leftReport.rosterSize === rightReport.rosterSize &&
    leftReport.threshold === rightReport.threshold &&
    leftReport.contributorRosterPositions.length ===
        rightReport.contributorRosterPositions.length &&
    leftReport.contributorRosterPositions.every(
        (position, positionIndex) =>
            position === rightReport.contributorRosterPositions[positionIndex],
    ) &&
    leftReport.coefficients.length === rightReport.coefficients.length &&
    leftReport.coefficients.every((coefficient, coefficientIndex) => {
        const rightCoefficient = rightReport.coefficients[coefficientIndex];

        return (
            coefficient.rosterPosition === rightCoefficient?.rosterPosition &&
            coefficient.coefficient === rightCoefficient.coefficient &&
            coefficient.centeredCoefficient ===
                rightCoefficient.centeredCoefficient
        );
    });

const requireSameSelectedContext = (
    selectedContributions: readonly AggregateContribution[],
): AggregateContribution => {
    const firstContribution = selectedContributions[0];
    if (firstContribution === undefined) {
        throw new RangeError(
            'Aggregate-ready record requires at least one selected aggregate contribution.',
        );
    }
    const sharedFields = [
        'ceremonyId',
        'manifestDigest',
        'rosterDigest',
        'pollSpecDigest',
        'thresholdProfileDigest',
        'setupPackageDigest',
        'participantCount',
        'optionCount',
        'shareVectorWidth',
        'ballotSetDigest',
        'votingClosedBoardHeadDigest',
        'postVotingClosedContextDigest',
        'aggregateSelectionPolicyDigest',
        'encryptedAggregateBridgeDigest',
        'encryptedAggregateTargetBasisDataRoot',
        'encryptedAggregateReconstructionDigest',
        'bridgeWitnessPrivacyProfileDigest',
        'bgvBatchEncoderDigest',
        'bridgeLayoutDigest',
        'encryptedAggregateInputLayoutDigest',
        'topKEvaluatorInputLayoutDigest',
        'bgvProfileDigest',
        'collectivePublicKeyRoot',
    ] as const;

    for (const contribution of selectedContributions) {
        for (const sharedField of sharedFields) {
            if (contribution[sharedField] !== firstContribution[sharedField]) {
                throw new RangeError(
                    `Aggregate-ready selected contributions must agree on ${sharedField}.`,
                );
            }
        }
    }

    return firstContribution;
};

export const createAggregateReadyRecord = (
    input: AggregateReadyRecordBuildInput,
): AggregateReadyRecord => {
    if (
        input.selectedContributions.length !==
            input.aggregateContributionQuorum ||
        input.aggregateContributionQuorum <= 0
    ) {
        throw new RangeError(
            'Aggregate-ready record requires exactly the aggregate contribution quorum.',
        );
    }
    for (const contribution of input.selectedContributions) {
        const verification = verifyAggregateContributionStructure(contribution);
        if (!verification.ok) {
            throw new RangeError(
                'Aggregate-ready record requires structurally valid selected aggregate contributions.',
            );
        }
        if (
            contribution.bridgeProofRecord.bridgeProofVerificationStatus !==
            'BridgeProofRelationChecked'
        ) {
            throw new RangeError(
                'Aggregate-ready record requires proof-checked selected aggregate contributions.',
            );
        }
    }
    const firstContribution = requireSameSelectedContext(
        input.selectedContributions,
    );
    const selectedContributorRosterPositions = input.selectedContributions.map(
        (contribution) => contribution.contributorRosterPosition,
    );
    const interpolationCoefficientReport = deriveInterpolationCoefficientReport(
        {
            contributorRosterPositions: selectedContributorRosterPositions,
            rosterSize: input.rosterSize,
            threshold: input.aggregateContributionQuorum,
        },
    );
    if (
        input.suppliedInterpolationCoefficientReport !== undefined &&
        !interpolationReportsMatch(
            input.suppliedInterpolationCoefficientReport,
            interpolationCoefficientReport,
        )
    ) {
        throw new RangeError(
            'Supplied aggregate interpolation coefficient report does not match recomputation.',
        );
    }
    const selectedAggregateContributionDigests =
        input.selectedContributions.map(
            (contribution) => contribution.aggregateContributionDigest,
        );
    const expectedFirstValidOrderDigest =
        deriveSelectedAggregateContributionOrderDigest({
            requiredPostVotingClosedContextDigest:
                firstContribution.postVotingClosedContextDigest,
            selectedAggregateContributionDigests,
            selectionPolicyDigest:
                firstContribution.aggregateSelectionPolicyDigest,
        });
    if (input.firstValidOrderDigest !== expectedFirstValidOrderDigest) {
        throw new RangeError(
            'Aggregate-ready record first-valid order digest does not match the selected contribution order.',
        );
    }
    const encryptedAggregateShareCiphertextRoots =
        input.selectedContributions.map(
            (contribution) =>
                contribution.encryptedAggregateShareCiphertextRoot,
        );
    const encryptedAggregateReconstructionRoot =
        deriveEncryptedAggregateReconstructionRoot({
            aggregateSelectionPolicyDigest:
                firstContribution.aggregateSelectionPolicyDigest,
            encryptedAggregateReconstructionDigest:
                firstContribution.encryptedAggregateReconstructionDigest,
            encryptedAggregateShareCiphertextRoots,
            firstValidOrderDigest: expectedFirstValidOrderDigest,
            interpolationCoefficientReportDigest:
                interpolationCoefficientReport.reportDigest,
            selectedAggregateContributionDigests,
        });
    const recordPayload: Omit<
        AggregateReadyRecord,
        'aggregateReadyRecordDigest'
    > = {
        aggregateContributionQuorum: input.aggregateContributionQuorum,
        aggregateSelectionPolicyDigest:
            firstContribution.aggregateSelectionPolicyDigest,
        ballotSetDigest: firstContribution.ballotSetDigest,
        bgvBatchEncoderDigest: firstContribution.bgvBatchEncoderDigest,
        bgvProfileDigest: firstContribution.bgvProfileDigest,
        bridgeLayoutDigest: firstContribution.bridgeLayoutDigest,
        bridgeWitnessPrivacyProfileDigest:
            firstContribution.bridgeWitnessPrivacyProfileDigest,
        centeredL1CoefficientSum:
            interpolationCoefficientReport.centeredL1CoefficientSum,
        ceremonyId: firstContribution.ceremonyId,
        collectivePublicKeyRoot: firstContribution.collectivePublicKeyRoot,
        encryptedAggregateBridgeDigest:
            firstContribution.encryptedAggregateBridgeDigest,
        encryptedAggregateInputLayoutDigest:
            firstContribution.encryptedAggregateInputLayoutDigest,
        encryptedAggregateReconstructionDigest:
            firstContribution.encryptedAggregateReconstructionDigest,
        encryptedAggregateReconstructionRoot,
        encryptedAggregateShareCiphertextRoots,
        encryptedAggregateTargetBasisDataRoot:
            firstContribution.encryptedAggregateTargetBasisDataRoot,
        firstValidOrderDigest: expectedFirstValidOrderDigest,
        interpolationCoefficientReportDigest:
            interpolationCoefficientReport.reportDigest,
        interpolationCoefficients: interpolationCoefficientReport.coefficients,
        manifestDigest: firstContribution.manifestDigest,
        maxCenteredAbsCoefficient:
            interpolationCoefficientReport.maxCenteredAbsCoefficient,
        objectType: 'AggregateReadyRecord',
        objectVersion: 1,
        optionCount: firstContribution.optionCount,
        pollSpecDigest: firstContribution.pollSpecDigest,
        postVotingClosedContextDigest:
            firstContribution.postVotingClosedContextDigest,
        rosterSize: input.rosterSize,
        rosterDigest: firstContribution.rosterDigest,
        selectedAggregateContributionDigests,
        selectedContributorIdentities: input.selectedContributions.map(
            (contribution) => contribution.contributorIdentity,
        ),
        selectedContributorInterpolationPoints:
            interpolationCoefficientReport.contributorRosterPositions,
        selectedContributorRosterPositions,
        setupPackageDigest: firstContribution.setupPackageDigest,
        shareVectorWidth: firstContribution.shareVectorWidth,
        thresholdProfileDigest: firstContribution.thresholdProfileDigest,
        topKEvaluatorInputLayoutDigest:
            firstContribution.topKEvaluatorInputLayoutDigest,
        votingClosedBoardHeadDigest:
            firstContribution.votingClosedBoardHeadDigest,
    };

    return {
        ...recordPayload,
        aggregateReadyRecordDigest:
            deriveAggregateReadyRecordDigest(recordPayload),
    };
};

export const verifyAggregateReadyRecordStructure = (
    record: AggregateReadyRecord,
): {
    readonly acceptedDigests: readonly ProtocolDigest[];
    readonly aggregateReadyRecordDigest?: ProtocolDigest;
    readonly ok: boolean;
    readonly refusedObjects: readonly RefusalRecord[];
    readonly statusLabels: readonly string[];
    readonly unresolvedReason: string | null;
} => {
    const recordDigest = record.aggregateReadyRecordDigest;
    const { aggregateReadyRecordDigest, ...recordWithoutDigest } = record;
    void aggregateReadyRecordDigest;
    let expectedRecordDigest: string | undefined;
    const refusedObjects: RefusalRecord[] = [
        ...collectForbiddenWitnessFieldRefusals(
            record,
            recordDigest,
            'aggregateReadyRecord',
        ),
        ...collectDigestShapeRefusals(
            record as unknown as Record<string, unknown>,
            aggregateReadyDigestFieldNames,
            recordDigest,
        ),
    ];
    try {
        expectedRecordDigest =
            deriveAggregateReadyRecordDigest(recordWithoutDigest);
    } catch (error) {
        refusedObjects.push(
            createAggregateRefusal(
                `Aggregate-ready record digest could not be canonicalized: ${
                    error instanceof Error ? error.message : String(error)
                }.`,
                recordDigest,
            ),
        );
    }
    const recomputedInterpolationReport = deriveInterpolationCoefficientReport({
        contributorRosterPositions: record.selectedContributorRosterPositions,
        rosterSize: record.rosterSize,
        threshold: record.aggregateContributionQuorum,
    });
    const recomputedFirstValidOrderDigest =
        deriveSelectedAggregateContributionOrderDigest({
            requiredPostVotingClosedContextDigest:
                record.postVotingClosedContextDigest,
            selectedAggregateContributionDigests:
                record.selectedAggregateContributionDigests,
            selectionPolicyDigest: record.aggregateSelectionPolicyDigest,
        });
    const recomputedReconstructionRoot =
        deriveEncryptedAggregateReconstructionRoot({
            aggregateSelectionPolicyDigest:
                record.aggregateSelectionPolicyDigest,
            encryptedAggregateReconstructionDigest:
                record.encryptedAggregateReconstructionDigest,
            encryptedAggregateShareCiphertextRoots:
                record.encryptedAggregateShareCiphertextRoots,
            firstValidOrderDigest: record.firstValidOrderDigest,
            interpolationCoefficientReportDigest:
                recomputedInterpolationReport.reportDigest,
            selectedAggregateContributionDigests:
                record.selectedAggregateContributionDigests,
        });
    const selectedLengths = [
        record.selectedAggregateContributionDigests.length,
        record.selectedContributorIdentities.length,
        record.selectedContributorRosterPositions.length,
        record.selectedContributorInterpolationPoints.length,
        record.encryptedAggregateShareCiphertextRoots.length,
        record.interpolationCoefficients.length,
    ];
    const arraysMatchQuorum = selectedLengths.every(
        (length) => length === record.aggregateContributionQuorum,
    );
    const allSelectedDigestsAreCanonical = [
        ...record.selectedAggregateContributionDigests,
        ...record.encryptedAggregateShareCiphertextRoots,
    ].every((digestValue) => protocolDigestPattern.test(digestValue));

    if (
        record.objectType !== 'AggregateReadyRecord' ||
        record.objectVersion !== 1 ||
        expectedRecordDigest === undefined ||
        record.aggregateReadyRecordDigest !== expectedRecordDigest ||
        !Number.isSafeInteger(record.rosterSize) ||
        record.rosterSize < 3 ||
        record.rosterSize > 20 ||
        !Number.isSafeInteger(record.optionCount) ||
        record.optionCount < 2 ||
        record.optionCount > 20 ||
        !Number.isSafeInteger(record.shareVectorWidth) ||
        record.shareVectorWidth !== record.optionCount * 11 ||
        !Number.isSafeInteger(record.aggregateContributionQuorum) ||
        record.aggregateContributionQuorum <= 0 ||
        record.aggregateContributionQuorum > record.rosterSize ||
        !arraysMatchQuorum ||
        !allSelectedDigestsAreCanonical ||
        record.selectedContributorInterpolationPoints.some(
            (position, positionIndex) =>
                position !==
                record.selectedContributorRosterPositions[positionIndex],
        ) ||
        record.firstValidOrderDigest !== recomputedFirstValidOrderDigest ||
        record.interpolationCoefficientReportDigest !==
            recomputedInterpolationReport.reportDigest ||
        record.centeredL1CoefficientSum !==
            recomputedInterpolationReport.centeredL1CoefficientSum ||
        record.maxCenteredAbsCoefficient !==
            recomputedInterpolationReport.maxCenteredAbsCoefficient ||
        !interpolationReportsMatch(
            {
                centeredL1CoefficientSum: record.centeredL1CoefficientSum,
                coefficients: record.interpolationCoefficients,
                contributorRosterPositions:
                    record.selectedContributorRosterPositions,
                maxCenteredAbsCoefficient: record.maxCenteredAbsCoefficient,
                reportDigest: record.interpolationCoefficientReportDigest,
                rosterSize: record.rosterSize,
                threshold: record.aggregateContributionQuorum,
            },
            recomputedInterpolationReport,
        ) ||
        record.encryptedAggregateReconstructionRoot !==
            recomputedReconstructionRoot
    ) {
        refusedObjects.push(
            createAggregateRefusal(
                'Aggregate-ready record digest, variant dimensions, interpolation coefficients, or reconstruction root is invalid.',
                recordDigest,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            acceptedDigests: [],
            aggregateReadyRecordDigest: recordDigest,
            ok: false,
            refusedObjects,
            statusLabels: [],
            unresolvedReason:
                refusedObjects[0]?.code ?? 'AggregateReadyRecordInvalid',
        };
    }

    return {
        acceptedDigests: [
            record.aggregateReadyRecordDigest,
            record.encryptedAggregateReconstructionRoot,
            record.interpolationCoefficientReportDigest,
        ],
        aggregateReadyRecordDigest: recordDigest,
        ok: true,
        refusedObjects: [],
        statusLabels: ['AggregateReadyRecordVerified'],
        unresolvedReason: null,
    };
};
