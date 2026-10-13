import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileBallotEncryptionRelationCensus } from '#tests/ballot-encryption-relation-model.js';
import { compileBoundedLinearPolynomialProofCensus } from '#tests/bounded-linear-polynomial-proof-model.js';
import { compileBoundedLookupCensus } from '#tests/bounded-lookup-model.js';
import {
    compileBrowserWordProverResources,
    compileContributionGenerationResources,
} from '#tests/browser-word-prover-resource-model.js';
import { compileCertificateCustodyCensus } from '#tests/certificate-custody-model.js';
import { compileCloseResponseCensus } from '#tests/close-response-model.js';
import {
    compareCommitmentEquivocationHybrids,
    compareDuplicateCommitmentInputs,
} from '#tests/commitment-equivocation-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import {
    compileBallotWordProofLayout,
    compileFullWordProofLayout,
    compileLinkedReleaseWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import { compileLinkedReleaseRelationCensus } from '#tests/linked-release-relation-model.js';
import { compileOrdinaryWorkflowResources } from '#tests/ordinary-workflow-resource-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantCloseCustody } from '#tests/participant-close-custody-model.js';
import {
    compileContributionProofStorage,
    compileParticipantCustodyCensus,
} from '#tests/participant-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compilePreparationResources } from '#tests/preparation-resource-model.js';
import { compileProofFieldReductionCensus } from '#tests/proof-field-reduction-model.js';
import { compileProofHashDomainCensus } from '#tests/proof-hash-domain-model.js';
import {
    firstOracleResumeHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { proofRelationCatalogue } from '#tests/proof-relation-catalogue-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import { compileRecipientKeyUniquenessBound } from '#tests/recipient-key-uniqueness-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationSourceRandomness } from '#tests/registration-source-randomness-model.js';
import { compileRelationIntegerLiftingCensus } from '#tests/relation-integer-lifting-model.js';
import { compileReleaseShareLiftingCensus } from '#tests/release-share-lifting-model.js';
import { compileReleaseVerificationWorkload } from '#tests/release-verification-work-model.js';
import { compileRnsArithmeticResourceCensus } from '#tests/rns-arithmetic-resource-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSelectedOpeningTransformCensus } from '#tests/selected-opening-transform-model.js';
import { compileSetupAggregateResources } from '#tests/setup-aggregate-resource-model.js';
import { compileSetupRandomnessCensus } from '#tests/setup-randomness-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-relation/shape.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { compileFixedSpongeInitializationCensus } from '#tests/sponge-initialization-model.js';
import {
    compileProfileBfvCensus,
    compileSupportedProfileCensus,
    completionProfile,
    deriveSupportedProfile,
    listSupportedProfiles,
} from '#tests/supported-profile-model.js';
import { compileSupportedThresholdCompletionProfiles } from '#tests/threshold-completion-model.js';
import { verifyThresholdKeyAggregationModel } from '#tests/threshold-key-aggregation-model.js';
import { compileThresholdReleaseNoiseCensus } from '#tests/threshold-release-noise-model.js';
import {
    compileFamilyRoundErrorCensus,
    compileProofRoundErrorCensus,
    compileWideChallengeCompilerCensus,
} from '#tests/wide-challenge-compiler-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';
import { formatCount } from '#tools/ci/census/format.js';
import { readParticipantArtifactResources } from '#tools/ci/participant-artifact-resources.js';

export const compileCensusInputs = () => {
    const resourceArtifact = readParticipantArtifactResources();
    const workflowResources = [
        deriveSupportedProfile(10, 10),
        deriveSupportedProfile(20, 20),
    ].map((profile) =>
        compileOrdinaryWorkflowResources(profile, resourceArtifact),
    );
    const completion = completionProfile();
    const thresholdProfiles = compileSupportedThresholdCompletionProfiles();
    const boundedLinearProof = compileBoundedLinearPolynomialProofCensus();
    const boundedLookup = compileBoundedLookupCensus();
    const smallLimbProofField = compileSmallLimbProofFieldCensus();
    const proofFieldReduction = compileProofFieldReductionCensus();
    const recipientKeyUniqueness = compileRecipientKeyUniquenessBound();
    const proofVerifierQueries = compileProofVerifierQueryCensus();
    const releaseVerification = compileReleaseVerificationWorkload({
        replayedCandidates: 1n,
        changedEnvelopes: 0n,
        changedProofBodies: 0n,
    });
    const closeResponses = compileCloseResponseCensus();
    const thresholdKeyAggregation = verifyThresholdKeyAggregationModel();
    const thresholdReleaseNoise = compileThresholdReleaseNoiseCensus();
    const participantCustody = compileParticipantCustodyCensus(completion);
    const contributionProofStorage =
        compileContributionProofStorage(completion);
    const participantBallotCustody =
        compileParticipantBallotCustody(completion);
    const participantCloseCustody = compileParticipantCloseCustody(completion);
    const largestCloseCustody = compileParticipantCloseCustody(
        listSupportedProfiles().slice(-1)[0],
    );
    const participantReleaseCustody =
        compileParticipantReleaseCustody(completion);
    const commonMatrixSampling = compileCommonMatrixSamplingCensus(completion);
    const fixedSpongeInitialization =
        compileFixedSpongeInitializationCensus(completion);
    const wideChallengeCompiler =
        compileWideChallengeCompilerCensus(completion);
    const sampledRoundErrors = compileProofRoundErrorCensus(completion);
    const familyRoundErrors = compileFamilyRoundErrorCensus();
    const effectiveRelations = new Map<string, Set<string>>();
    for (const entry of proofRelationCatalogue())
        effectiveRelations.set(
            entry.role,
            (effectiveRelations.get(entry.role) ?? new Set()).add(
                entry.arithmeticKey,
            ),
        );
    const proofHashDomain = compileProofHashDomainCensus();
    const fullWordProof = compileFullWordProofLayout(completion);
    const ballotWordProof = compileBallotWordProofLayout(completion);
    const ballotBody = compileBallotBodyCensus(completion);
    const browserWordProver = compileBrowserWordProverResources(completion);
    const contributionGeneration =
        compileContributionGenerationResources(completion);
    const contributionBody = compileContributionBodyCensus(completion);
    const setupAggregate = compileSetupAggregateResources(completion);
    const preparationResources = compilePreparationResources(completion);
    const setupRandomness = compileSetupRandomnessCensus(completion);
    const registrationSourceRandomness = compileRegistrationSourceRandomness(
        completion.participantCount,
        completion.optionCount,
    );
    const registrationKey = compileRecipientKeyCensus();
    const registrationEnrollment = compileRegistrationEnrollmentCensus();
    const firstOracleCheckpoint =
        compileFirstOracleCheckpointCensus(completion);
    const selectedOpeningTransform = compileSelectedOpeningTransformCensus();
    const commitmentEquivocation = compareCommitmentEquivocationHybrids(
        3,
        2,
        'complete-slice',
    );
    const commitmentPrefix = compareCommitmentEquivocationHybrids(
        2,
        2,
        'complete-slice',
        2,
        1,
    );
    const duplicateCommitmentInputs = compareDuplicateCommitmentInputs(false);
    const rosterProposals = thresholdProfiles.map((profile) =>
        compileRosterProposalCensus(profile.participantCount),
    );
    const selectionWires = thresholdProfiles.map((profile) =>
        compileSetupSelectionWireCensus(profile.participantCount),
    );
    const commonAgreement = compileCommonAgreementDegreeCensus();
    const rnsArithmetic = compileRnsArithmeticResourceCensus(completion);
    const setupRelation = compileSetupContributionRelationCensus(completion);
    const linkedRelease = compileLinkedReleaseRelationCensus(completion);
    const relationLifting = compileRelationIntegerLiftingCensus();
    const linkedReleaseProof = compileLinkedReleaseWordProofLayout(completion);
    const ballotRelation = compileBallotEncryptionRelationCensus(completion);
    const fixedModulusBfv = compileProfileBfvCensus(completion);
    const supportedProfiles = compileSupportedProfileCensus();
    const maximumFirstOracleResume = supportedProfiles.profiles
        .flat()
        .map((profile) => {
            const setup = proofHashProfiles(profile).find(
                (value) => value.role === 'setup',
            )!;
            return firstOracleResumeHashWork(
                setup.firstWidth,
                setup.roleBytes,
                (setup.firstWidth - 48n) / 16n,
            ).completeInputFactor;
        })
        .reduce((maximum, factor) => (factor > maximum ? factor : maximum), 0n);
    const contributionBodies = supportedProfiles.profiles.map((row) =>
        row.map((profile) => compileContributionBodyCensus(profile)),
    );
    // A roster's setup contributions, which every participant verifies, at the
    // option count with the largest bodies.
    const contributionCorpus = contributionBodies.map((row, index) => ({
        participants: supportedProfiles.profiles[index][0].participantCount,
        bytes: row.reduce(
            (largest, body) =>
                body.maximumEligibleOfferBodies > largest
                    ? body.maximumEligibleOfferBodies
                    : largest,
            0n,
        ),
    }));
    // The mobile runtime's public corpus planning target plus its fifty
    // percent variance.
    const publicCorpusVarianceCeiling = (2_147_483_648n * 3n) / 2n;
    const countsAbove = (bound: bigint): string => {
        const counts = contributionCorpus
            .filter((entry) => entry.bytes > bound)
            .map((entry) => entry.participants);
        if (counts.length === 0) return 'none';
        if (counts.length === 1) return formatCount(counts[0]);
        return counts.every(
            (count, index) => index === 0 || count === counts[index - 1] + 1,
        )
            ? `${formatCount(counts[0])} to ${formatCount(counts[counts.length - 1])}`
            : counts.map((count) => formatCount(count)).join(', ');
    };
    const certificateCustody = compileCertificateCustodyCensus();
    const wideShareLifting = compileWideShareLiftingCensus(
        completion.shareLifting,
    );
    const releaseShareLifting = compileReleaseShareLiftingCensus(
        completion.releaseLifting,
    );
    if (
        thresholdKeyAggregation.maximumScaledReconstructionCoefficientOneNorm !==
            thresholdReleaseNoise.exactMaximumScaledReconstructionCoefficientOneNorm ||
        thresholdKeyAggregation.maximumSimulationCoefficientOneNorm !==
            thresholdReleaseNoise.exactMaximumSimulationCoefficientOneNorm
    ) {
        throw new Error(
            'Independent modular and rational interpolation models disagree.',
        );
    }
    return {
        thresholdProfiles,
        thresholdKeyAggregation,
        recipientKeyUniqueness,
        boundedLinearProof,
        boundedLookup,
        wideShareLifting,
        releaseShareLifting,
        ballotRelation,
        ballotWordProof,
        ballotBody,
        completion,
        fixedModulusBfv,
        maximumFirstOracleResume,
        releaseVerification,
        proofVerifierQueries,
        registrationSourceRandomness,
        participantBallotCustody,
        participantCloseCustody,
        largestCloseCustody,
        participantReleaseCustody,
        linkedRelease,
        linkedReleaseProof,
        setupRelation,
        relationLifting,
        rnsArithmetic,
        commonAgreement,
        sampledRoundErrors,
        familyRoundErrors,
        effectiveRelations,
        proofHashDomain,
        wideChallengeCompiler,
        supportedProfiles,
        fullWordProof,
        browserWordProver,
        setupRandomness,
        contributionGeneration,
        registrationKey,
        registrationEnrollment,
        firstOracleCheckpoint,
        selectedOpeningTransform,
        contributionBody,
        setupAggregate,
        participantCustody,
        contributionProofStorage,
        selectionWires,
        preparationResources,
        resourceArtifact,
        workflowResources,
        rosterProposals,
        commonMatrixSampling,
        fixedSpongeInitialization,
        certificateCustody,
        contributionBodies,
        publicCorpusVarianceCeiling,
        countsAbove,
        proofFieldReduction,
        smallLimbProofField,
        commitmentEquivocation,
        commitmentPrefix,
        duplicateCommitmentInputs,
        closeResponses,
        thresholdReleaseNoise,
    };
};
export type CensusInputs = ReturnType<typeof compileCensusInputs>;
