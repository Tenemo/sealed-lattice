import {
    createContribution,
    createSyntheticBallotPackageShell,
    currentRecoveryEpochMap,
    setupParticipants,
} from './fixtures.js';
import {
    runCheapNegativeChecks,
    runSelectionNegativeChecks,
    runSentinelNegativeChecks,
} from './negative-checks.js';
import {
    benchmarkVariantKeys,
    claimTierForRosterSize,
    measure,
    publicArtifactIsWitnessClean,
    roundedMilliseconds,
    sentinelVariants,
    variantKey,
    type TranscriptCoreKernel,
    type Variant,
    type VariantBuildResult,
} from './shared.js';

import {
    canonicalJson,
    deriveProtocolDigest,
} from '#packages/crypto/src/index';
import {
    createAggregateReadyRecord,
    createBallotPrivacyProfileSet,
    createShareCommitmentMessageBoundCert,
    selectFirstValidAggregateContributions,
    verifyAggregateReadyRecordStructure,
} from '#packages/protocol/src/ballot-privacy/index';
import { deriveThresholdProfile } from '#packages/protocol/src/lifecycle/thresholds';
import { createVariantBallotProofRecordGenerationFixture } from '#packages/protocol/tests/node/ballot-privacy-proof-record-generation-fixtures/fixture-assembly.js';

export const buildVariant = (input: {
    readonly kernel: TranscriptCoreKernel;
    readonly variant: Variant;
}): VariantBuildResult => {
    const thresholdProfile = deriveThresholdProfile({
        casualMicroRosterAcknowledged: input.variant.rosterSize < 10,
        rosterSize: input.variant.rosterSize,
    });
    const trusteeAggregateThreshold = thresholdProfile.pvssThreshold;
    const fixture = createVariantBallotProofRecordGenerationFixture({
        optionCount: input.variant.optionCount,
        rosterSize: input.variant.rosterSize,
    });
    const ballotPackage = createSyntheticBallotPackageShell({ fixture });
    const profileSet = createBallotPrivacyProfileSet({
        optionCount: input.variant.optionCount,
    });
    const certificate = createShareCommitmentMessageBoundCert({
        maximumCanonicalTurnout: 20,
        shareCommitmentProfile: profileSet.shareCommitmentProfile,
    });
    const setupPackage = input.kernel.generateBgvPassiveSetup({
        ceremonyId: fixture.statement.ceremonyId,
        manifestDigest: fixture.statement.manifestDigest,
        participants: setupParticipants(input.variant.rosterSize),
        rosterDigest: fixture.statement.rosterDigest,
        setupSeed: `encrypted-aggregate-bridge-${variantKey(input.variant)}`,
        thresholdProfileDigest: fixture.statement.thresholdProfileDigest,
    }) as Record<string, unknown>;
    if (setupPackage.ok === false) {
        throw new Error(
            `Setup generation failed: ${canonicalJson(setupPackage)}`,
        );
    }
    const aggregateSelectionPolicyDigest = deriveProtocolDigest(
        'AggregateSelectionPolicyDigest',
        {
            optionCount: input.variant.optionCount,
            purpose: 'encrypted-aggregate-bridge-selection-policy-v1',
            rosterSize: input.variant.rosterSize,
            thresholdProfileDigest: fixture.statement.thresholdProfileDigest,
        },
    );
    const bridgeWitnessPrivacyProfileDigest = deriveProtocolDigest(
        'BridgeWitnessPrivacyProfileDigest',
        {
            optionCount: input.variant.optionCount,
            purpose: 'encrypted-aggregate-bridge-witness-privacy-v1',
            rosterSize: input.variant.rosterSize,
        },
    );
    const heParamDigest = deriveProtocolDigest('HEParamDigest', {
        optionCount: input.variant.optionCount,
        purpose: 'encrypted-aggregate-bridge-he-param-v1',
        rosterSize: input.variant.rosterSize,
    });
    const contributions = Array.from(
        { length: trusteeAggregateThreshold },
        (_unusedValue, contributorIndex) =>
            createContribution({
                aggregateSelectionPolicyDigest,
                ballotPackage,
                bridgeWitnessPrivacyProfileDigest,
                certificate,
                contributorRosterPosition: contributorIndex + 1,
                heParamDigest,
                kernel: input.kernel,
                setupPackage,
                unsafeSmallRosterAcknowledged: input.variant.rosterSize < 10,
                variant: input.variant,
            }),
    );
    const selectedContributionRecords = contributions.map(
        (contribution) => contribution.aggregateContribution,
    );
    const selection = selectFirstValidAggregateContributions({
        aggregateContributionQuorum: trusteeAggregateThreshold,
        contributions: selectedContributionRecords,
        currentRecoveryEpochMap: currentRecoveryEpochMap(
            selectedContributionRecords,
        ),
        expectedAggregateSelectionPolicyDigest: aggregateSelectionPolicyDigest,
        requiredPostVotingClosedContextDigest:
            selectedContributionRecords[0].postVotingClosedContextDigest,
    });
    if (!selection.ok || selection.firstValidOrderDigest === undefined) {
        throw new Error(
            `Contribution selection failed: ${canonicalJson(selection)}`,
        );
    }
    const firstValidOrderDigest = selection.firstValidOrderDigest;
    const aggregateReadyMeasurement = measure(() =>
        createAggregateReadyRecord({
            aggregateContributionQuorum: trusteeAggregateThreshold,
            firstValidOrderDigest,
            rosterSize: input.variant.rosterSize,
            selectedContributions: selection.selectedContributions,
        }),
    );
    const aggregateReadyVerificationMeasurement = measure(() =>
        verifyAggregateReadyRecordStructure(aggregateReadyMeasurement.result),
    );
    if (!aggregateReadyVerificationMeasurement.result.ok) {
        throw new Error(
            `Aggregate-ready verification failed: ${canonicalJson(
                aggregateReadyVerificationMeasurement.result,
            )}`,
        );
    }
    const firstBridge = contributions[0].bridgeEncryption;
    const rowBase = {
        aggregateCoordinateCount: fixture.statement.shareVectorWidth,
        aggregateReadyVerificationTime: roundedMilliseconds(
            aggregateReadyVerificationMeasurement.elapsedMilliseconds,
        ),
        claimTier: claimTierForRosterSize(input.variant.rosterSize),
        ciphertextShape: {
            basisId: firstBridge.basisId,
            canonicalByteLength: firstBridge.canonicalByteLength,
            coefficientCount: firstBridge.coefficientCount,
            level: firstBridge.level,
            slotCount: firstBridge.slotCount,
        },
        failureReason: null,
        optionCount: input.variant.optionCount,
        proofByteLength: contributions.reduce(
            (sum, contribution) => sum + contribution.proofByteLength,
            0,
        ),
        proverTime: contributions.reduce(
            (sum, contribution) =>
                sum + roundedMilliseconds(contribution.proverTime),
            0,
        ),
        publicArtifactWitnessCleanResult: publicArtifactIsWitnessClean({
            aggregateReadyRecord: aggregateReadyMeasurement.result,
            bridgeEncryption: contributions.map(
                (contribution) => contribution.bridgeEncryption,
            ),
            contributions: selectedContributionRecords,
        }),
        rosterSize: input.variant.rosterSize,
        selectedContributionCount: trusteeAggregateThreshold,
        shareVectorWidth: fixture.statement.shareVectorWidth,
        status: 'passed' as const,
        thresholdProfileHash: fixture.statement.thresholdProfileDigest,
        trusteeAggregateThreshold,
        verifierTime: contributions.reduce(
            (sum, contribution) =>
                sum + roundedMilliseconds(contribution.verifierTime),
            0,
        ),
    };
    const privateRelationMeasurement = measure(() =>
        input.kernel.evaluateAggregateBridgeRelation({
            aggregateDerivationComponent:
                contributions[0].aggregateDerivationComponent,
            aggregateSelectionPolicyDigest,
            aggregateWitness: contributions[0].aggregateWitness,
            bridgeEncryption: contributions[0].bridgeEncryption,
            bridgeWitnessPrivacyProfileDigest,
            heParamDigest,
            proverRandomnessHex: '77'.repeat(32),
            setupPackage,
        }),
    );
    const privateRelation = privateRelationMeasurement.result as Record<
        string,
        unknown
    >;
    if (privateRelation.ok !== true) {
        throw new Error(
            `Private bridge relation failed: ${canonicalJson(privateRelation)}`,
        );
    }
    const negativeChecks = [
        ...runCheapNegativeChecks({
            aggregateSelectionPolicyDigest,
            bridgeWitnessPrivacyProfileDigest,
            contribution: contributions[0],
            heParamDigest,
            kernel: input.kernel,
            setupPackage,
            variant: input.variant,
        }),
        ...runSelectionNegativeChecks({
            aggregateSelectionPolicyDigest,
            postVotingClosedContextDigest:
                selectedContributionRecords[0].postVotingClosedContextDigest,
            selectedContributionRecords,
            trusteeAggregateThreshold,
            variant: input.variant,
        }),
        ...(sentinelVariants.has(variantKey(input.variant))
            ? runSentinelNegativeChecks({
                  aggregateSelectionPolicyDigest,
                  bridgeWitnessPrivacyProfileDigest,
                  contribution: contributions[0],
                  heParamDigest,
                  kernel: input.kernel,
                  setupPackage,
                  variant: input.variant,
              })
            : []),
    ];

    return {
        aggregateReadyRow: {
            ...rowBase,
            aggregateReadyVerificationTime: roundedMilliseconds(
                aggregateReadyVerificationMeasurement.elapsedMilliseconds,
            ),
        },
        benchmarkRow: benchmarkVariantKeys.has(variantKey(input.variant))
            ? rowBase
            : null,
        negativeChecks,
        privateRelationRow: {
            ...rowBase,
            proverTime: roundedMilliseconds(
                privateRelationMeasurement.elapsedMilliseconds,
            ),
            verifierTime: 0,
        },
        proofRow: rowBase,
    };
};
