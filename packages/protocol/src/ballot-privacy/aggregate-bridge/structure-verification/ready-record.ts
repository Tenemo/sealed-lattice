import type {
    AggregateContribution,
    AggregateReadyRecord,
    AggregateReadyRecordBuildInput,
    InterpolationCoefficientReport,
    ProtocolHash,
    RefusalRecord,
} from '@sealed-lattice/types';

import {
    createAggregateRefusal,
    protocolHashPattern,
} from '../../aggregate-derivation/constants.js';
import { deriveInterpolationCoefficientReport } from '../../plaintext-oracle-helpers.js';
import {
    deriveAggregateReadyRecordHash,
    deriveEncryptedAggregateReconstructionRoot,
    deriveSelectedAggregateContributionOrderHash,
} from '../hashes.js';

import { verifyAggregateContributionStructure } from './aggregate-contribution.js';
import {
    aggregateReadyHashFieldNames,
    collectHashShapeRefusals,
    collectForbiddenWitnessFieldRefusals,
} from './shared.js';

const interpolationReportsMatch = (
    leftReport: InterpolationCoefficientReport,
    rightReport: InterpolationCoefficientReport,
): boolean =>
    leftReport.reportHash === rightReport.reportHash &&
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
        'manifestHash',
        'rosterHash',
        'pollSpecHash',
        'thresholdProfileHash',
        'setupPackageHash',
        'participantCount',
        'optionCount',
        'shareVectorWidth',
        'ballotSetHash',
        'votingClosedBoardHeadHash',
        'postVotingClosedContextHash',
        'aggregateSelectionPolicyHash',
        'encryptedAggregateBridgeHash',
        'encryptedAggregateTargetBasisRoot',
        'encryptedAggregateReconstructionHash',
        'bridgeWitnessPrivacyProfileHash',
        'bgvBatchEncoderHash',
        'bridgeLayoutHash',
        'encryptedAggregateInputLayoutHash',
        'topKEvaluatorInputLayoutHash',
        'bgvProfileHash',
        'collectivePublicKeyRoot',
        'collectivePublicKeyCoefficientRoot',
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
    const selectedAggregateContributionHashes = input.selectedContributions.map(
        (contribution) => contribution.aggregateContributionHash,
    );
    const expectedFirstValidOrderHash =
        deriveSelectedAggregateContributionOrderHash({
            requiredPostVotingClosedContextHash:
                firstContribution.postVotingClosedContextHash,
            selectedAggregateContributionHashes,
            selectionPolicyHash: firstContribution.aggregateSelectionPolicyHash,
        });
    if (input.firstValidOrderHash !== expectedFirstValidOrderHash) {
        throw new RangeError(
            'Aggregate-ready record first-valid order hash does not match the selected contribution order.',
        );
    }
    const encryptedAggregateShareCiphertextRoots =
        input.selectedContributions.map(
            (contribution) =>
                contribution.encryptedAggregateShareCiphertextRoot,
        );
    const encryptedAggregateReconstructionRoot =
        deriveEncryptedAggregateReconstructionRoot({
            aggregateSelectionPolicyHash:
                firstContribution.aggregateSelectionPolicyHash,
            encryptedAggregateReconstructionHash:
                firstContribution.encryptedAggregateReconstructionHash,
            encryptedAggregateShareCiphertextRoots,
            firstValidOrderHash: expectedFirstValidOrderHash,
            interpolationCoefficientReportHash:
                interpolationCoefficientReport.reportHash,
            selectedAggregateContributionHashes,
        });
    const recordPayload: Omit<
        AggregateReadyRecord,
        'aggregateReadyRecordHash'
    > = {
        aggregateContributionQuorum: input.aggregateContributionQuorum,
        aggregateSelectionPolicyHash:
            firstContribution.aggregateSelectionPolicyHash,
        ballotSetHash: firstContribution.ballotSetHash,
        bgvBatchEncoderHash: firstContribution.bgvBatchEncoderHash,
        bgvProfileHash: firstContribution.bgvProfileHash,
        bridgeLayoutHash: firstContribution.bridgeLayoutHash,
        bridgeWitnessPrivacyProfileHash:
            firstContribution.bridgeWitnessPrivacyProfileHash,
        centeredL1CoefficientSum:
            interpolationCoefficientReport.centeredL1CoefficientSum,
        ceremonyId: firstContribution.ceremonyId,
        collectivePublicKeyRoot: firstContribution.collectivePublicKeyRoot,
        collectivePublicKeyCoefficientRoot:
            firstContribution.collectivePublicKeyCoefficientRoot,
        encryptedAggregateBridgeHash:
            firstContribution.encryptedAggregateBridgeHash,
        encryptedAggregateInputLayoutHash:
            firstContribution.encryptedAggregateInputLayoutHash,
        encryptedAggregateReconstructionHash:
            firstContribution.encryptedAggregateReconstructionHash,
        encryptedAggregateReconstructionRoot,
        encryptedAggregateShareCiphertextRoots,
        encryptedAggregateTargetBasisRoot:
            firstContribution.encryptedAggregateTargetBasisRoot,
        firstValidOrderHash: expectedFirstValidOrderHash,
        interpolationCoefficientReportHash:
            interpolationCoefficientReport.reportHash,
        interpolationCoefficients: interpolationCoefficientReport.coefficients,
        manifestHash: firstContribution.manifestHash,
        maxCenteredAbsCoefficient:
            interpolationCoefficientReport.maxCenteredAbsCoefficient,
        objectType: 'AggregateReadyRecord',
        objectVersion: 1,
        optionCount: firstContribution.optionCount,
        pollSpecHash: firstContribution.pollSpecHash,
        postVotingClosedContextHash:
            firstContribution.postVotingClosedContextHash,
        rosterSize: input.rosterSize,
        rosterHash: firstContribution.rosterHash,
        selectedAggregateContributionHashes,
        selectedContributorIdentities: input.selectedContributions.map(
            (contribution) => contribution.contributorIdentity,
        ),
        selectedContributorInterpolationPoints:
            interpolationCoefficientReport.contributorRosterPositions,
        selectedContributorRosterPositions,
        setupPackageHash: firstContribution.setupPackageHash,
        shareVectorWidth: firstContribution.shareVectorWidth,
        thresholdProfileHash: firstContribution.thresholdProfileHash,
        topKEvaluatorInputLayoutHash:
            firstContribution.topKEvaluatorInputLayoutHash,
        votingClosedBoardHeadHash: firstContribution.votingClosedBoardHeadHash,
    };

    return {
        ...recordPayload,
        aggregateReadyRecordHash: deriveAggregateReadyRecordHash(recordPayload),
    };
};

export const verifyAggregateReadyRecordStructure = (
    record: AggregateReadyRecord,
): {
    readonly acceptedHashes: readonly ProtocolHash[];
    readonly aggregateReadyRecordHash?: ProtocolHash;
    readonly ok: boolean;
    readonly refusedObjects: readonly RefusalRecord[];
    readonly statusLabels: readonly string[];
    readonly unresolvedReason: string | null;
} => {
    const recordHash = record.aggregateReadyRecordHash;
    const { aggregateReadyRecordHash, ...recordWithoutHash } = record;
    void aggregateReadyRecordHash;
    let expectedRecordHash: string | undefined;
    const refusedObjects: RefusalRecord[] = [
        ...collectForbiddenWitnessFieldRefusals(
            record,
            recordHash,
            'aggregateReadyRecord',
        ),
        ...collectHashShapeRefusals(
            record,
            aggregateReadyHashFieldNames,
            recordHash,
        ),
    ];
    try {
        expectedRecordHash = deriveAggregateReadyRecordHash(recordWithoutHash);
    } catch (error) {
        refusedObjects.push(
            createAggregateRefusal(
                `Aggregate-ready record hash could not be canonicalized: ${
                    error instanceof Error ? error.message : String(error)
                }.`,
                recordHash,
            ),
        );
    }
    const recomputedInterpolationReport = deriveInterpolationCoefficientReport({
        contributorRosterPositions: record.selectedContributorRosterPositions,
        rosterSize: record.rosterSize,
        threshold: record.aggregateContributionQuorum,
    });
    const recomputedFirstValidOrderHash =
        deriveSelectedAggregateContributionOrderHash({
            requiredPostVotingClosedContextHash:
                record.postVotingClosedContextHash,
            selectedAggregateContributionHashes:
                record.selectedAggregateContributionHashes,
            selectionPolicyHash: record.aggregateSelectionPolicyHash,
        });
    const recomputedReconstructionRoot =
        deriveEncryptedAggregateReconstructionRoot({
            aggregateSelectionPolicyHash: record.aggregateSelectionPolicyHash,
            encryptedAggregateReconstructionHash:
                record.encryptedAggregateReconstructionHash,
            encryptedAggregateShareCiphertextRoots:
                record.encryptedAggregateShareCiphertextRoots,
            firstValidOrderHash: record.firstValidOrderHash,
            interpolationCoefficientReportHash:
                recomputedInterpolationReport.reportHash,
            selectedAggregateContributionHashes:
                record.selectedAggregateContributionHashes,
        });
    const selectedLengths = [
        record.selectedAggregateContributionHashes.length,
        record.selectedContributorIdentities.length,
        record.selectedContributorRosterPositions.length,
        record.selectedContributorInterpolationPoints.length,
        record.encryptedAggregateShareCiphertextRoots.length,
        record.interpolationCoefficients.length,
    ];
    const arraysMatchQuorum = selectedLengths.every(
        (length) => length === record.aggregateContributionQuorum,
    );
    const allSelectedHashesAreCanonical = [
        ...record.selectedAggregateContributionHashes,
        ...record.encryptedAggregateShareCiphertextRoots,
    ].every((HashValue) => protocolHashPattern.test(HashValue));

    if (
        record.objectType !== 'AggregateReadyRecord' ||
        record.objectVersion !== 1 ||
        expectedRecordHash === undefined ||
        record.aggregateReadyRecordHash !== expectedRecordHash ||
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
        !allSelectedHashesAreCanonical ||
        record.selectedContributorInterpolationPoints.some(
            (position, positionIndex) =>
                position !==
                record.selectedContributorRosterPositions[positionIndex],
        ) ||
        record.firstValidOrderHash !== recomputedFirstValidOrderHash ||
        record.interpolationCoefficientReportHash !==
            recomputedInterpolationReport.reportHash ||
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
                reportHash: record.interpolationCoefficientReportHash,
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
                'Aggregate-ready record hash, variant dimensions, interpolation coefficients, or reconstruction root is invalid.',
                recordHash,
            ),
        );
    }

    if (refusedObjects.length > 0) {
        return {
            acceptedHashes: [],
            aggregateReadyRecordHash: recordHash,
            ok: false,
            refusedObjects,
            statusLabels: [],
            unresolvedReason:
                refusedObjects[0]?.code ?? 'AggregateReadyRecordInvalid',
        };
    }

    return {
        acceptedHashes: [
            record.aggregateReadyRecordHash,
            record.encryptedAggregateReconstructionRoot,
            record.interpolationCoefficientReportHash,
        ],
        aggregateReadyRecordHash: recordHash,
        ok: true,
        refusedObjects: [],
        statusLabels: ['AggregateReadyRecordVerified'],
        unresolvedReason: null,
    };
};
