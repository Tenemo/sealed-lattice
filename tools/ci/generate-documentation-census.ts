import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import {
    compileCompleteAuthenticationFrameWork,
    compileCompleteCredentialIntentBounds,
    compileCompletedAuthenticationCensus,
    compileCurrentCredentialIntentBounds,
    compileCurrentSignatureHashInputs,
    compileCurrentSignatureSamplingBounds,
    compileSignatureCounterBoundary,
    compileBallotSignatureHashWork,
} from '#tests/authentication-work-model.js';
import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileBallotEncryptionRelationCensus } from '#tests/ballot-encryption-relation-model.js';
import { compileBoundedLinearPolynomialProofCensus } from '#tests/bounded-linear-polynomial-proof-model.js';
import { compileBoundedLookupCensus } from '#tests/bounded-lookup-model.js';
import {
    compileBrowserWordProverResources,
    compileContributionGenerationResources,
} from '#tests/browser-word-prover-resource-model.js';
import {
    compileCertificateCustodyCensus,
    fullHolderRequirements,
} from '#tests/certificate-custody-model.js';
import { compileClearPreparationResources } from '#tests/clear-preparation-resource-model.js';
import { compileCloseResponseCensus } from '#tests/close-response-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import {
    compareCommitmentEquivocationHybrids,
    compareDuplicateCommitmentInputs,
    compileCommitmentEquivocationBound,
} from '#tests/commitment-equivocation-model.js';
import { compileCommitmentExtractionBound } from '#tests/commitment-extraction-bound-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import {
    compileCommonMatrixSamplingCensus,
    compileCommonMatrixInitializationCensus,
} from '#tests/common-matrix-sampling-model.js';
import {
    ceilingLog2,
    compileComposedSecurityLedger,
    compileReductionWork,
    compileUnitCallCostSensitivity,
    fheCommonStreamGuesses,
    keccakReferenceCost,
    minimumHonestRosterMembers,
} from '#tests/composed-security-ledger-model.js';
import {
    sparseRoutingWork,
    labelledHashExtractionWork,
    prefixOracleWork,
    prefixOracleQueriesPerAccess,
} from '#tests/compressed-oracle-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileFheKeySourceScreenResources } from '#tests/fhe-key-source-resource-model.js';
import { compileFirstOracleCheckpointCensus } from '#tests/first-oracle-checkpoint-model.js';
import {
    compileBallotWordProofLayout,
    compileFullWordProofLayout,
    compileLinkedReleaseWordProofLayout,
} from '#tests/full-word-proof-layout-model.js';
import { compileHashRowCheckpointCensus } from '#tests/hash-row-checkpoint-model.js';
import { compileLinkedReleaseRelationCensus } from '#tests/linked-release-relation-model.js';
import {
    compileOperationProofDraws,
    operationSeedBytes,
    operationSeedCount,
} from '#tests/operation-seed-model.js';
import {
    oracleDomainWork,
    programmedOracleDomainWork,
    prefixReplacementBaseQueriesPerAccess,
    shadowOracleDomainWork,
} from '#tests/oracle-domain-model.js';
import { compileOrdinaryWorkflowResources } from '#tests/ordinary-workflow-resource-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantCloseCustody } from '#tests/participant-close-custody-model.js';
import {
    compileContributionProofStorage,
    compileParticipantCustodyCensus,
    compileParticipantVaultKeyClasses,
} from '#tests/participant-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileProofCompilerChronology } from '#tests/proof-compiler-chronology-model.js';
import { compileProofFieldReductionCensus } from '#tests/proof-field-reduction-model.js';
import { compileProofHashDomainCensus } from '#tests/proof-hash-domain-model.js';
import {
    compileProofHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { compileProofRandomnessBudgets } from '#tests/proof-randomness-budget-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { compileRecipientKeyUniquenessBound } from '#tests/recipient-key-uniqueness-model.js';
import { compileOpeningShareResources } from '#tests/recoverable-opening-share-model.js';
import {
    compileBoundedOpeningShareProofResources,
    compilePublicOperatorScreenResources,
    compileRecoverableSetupResourceScreen,
    compileRecoverableSeedSharingProofResources,
} from '#tests/recoverable-setup-resource-model.js';
import { compileRegistrationCustodyCensus } from '#tests/registration-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { compileRegistrationSourceRandomness } from '#tests/registration-source-randomness-model.js';
import { compileReleaseShareLiftingCensus } from '#tests/release-share-lifting-model.js';
import { compileReleaseVerificationWorkload } from '#tests/release-verification-work-model.js';
import { compileRnsArithmeticResourceCensus } from '#tests/rns-arithmetic-resource-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSelectedOpeningTransformCensus } from '#tests/selected-opening-transform-model.js';
import { compileSetupAggregateResources } from '#tests/setup-aggregate-resource-model.js';
import {
    compileSetupContributionRelationCensus,
    deriveSetupContributionShape,
} from '#tests/setup-contribution-relation-model.js';
import {
    compileSetupRandomnessCensus,
    setupGaussianParameters,
} from '#tests/setup-randomness-model.js';
import {
    compileSetupSelectionCensus,
    countStagePath,
    preparationStagePath,
} from '#tests/setup-selection-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import { compileSigningLoopSourceComparison } from '#tests/signing-loop-estimate-model.js';
import { compileSimulatorKeyKnowledgeCensus } from '#tests/simulator-key-knowledge-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { compileSparseSupportSamplingCensus } from '#tests/sparse-sampling-bound-model.js';
import { compileFixedSpongeInitializationCensus } from '#tests/sponge-initialization-model.js';
import {
    compileProfileBfvCensus,
    compileSupportedProfileCensus,
    completionProfile,
    completionProfileCounts,
    deriveSupportedProfile,
    listSupportedProfiles,
} from '#tests/supported-profile-model.js';
import { compileSupportedThresholdCompletionProfiles } from '#tests/threshold-completion-model.js';
import { verifyThresholdKeyAggregationModel } from '#tests/threshold-key-aggregation-model.js';
import { compileThresholdReleaseNoiseCensus } from '#tests/threshold-release-noise-model.js';
import {
    compileProofRoundErrorCensus,
    compileWideChallengeCompilerCensus,
} from '#tests/wide-challenge-compiler-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';
import { readParticipantArtifactResources } from '#tools/ci/participant-artifact-resources.js';

const formatCount = (value: bigint | number): string =>
    `\`${value.toLocaleString('en-US')}\``;

const table = (
    header: readonly string[],
    rows: readonly (readonly string[])[],
): string =>
    [
        `| ${header.join(' | ')} |`,
        `| ${header.map(() => '---').join(' | ')} |`,
        ...rows.map((row) => `| ${row.join(' | ')} |`),
    ].join('\n');

export const renderDocumentationCensus = (): string => {
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
    const proofHashDomain = compileProofHashDomainCensus();
    const fullWordProof = compileFullWordProofLayout(completion);
    const ballotWordProof = compileBallotWordProofLayout(completion);
    const ballotBody = compileBallotBodyCensus(completion);
    const browserWordProver = compileBrowserWordProverResources(completion);
    const contributionGeneration =
        compileContributionGenerationResources(completion);
    const contributionBody = compileContributionBodyCensus(completion);
    const setupAggregate = compileSetupAggregateResources(completion);
    const clearPreparation = compileClearPreparationResources(completion);
    const setupRandomness = compileSetupRandomnessCensus(completion);
    const registrationSourceRandomness = compileRegistrationSourceRandomness(
        completion.participantCount,
        completion.optionCount,
    );
    const registrationKey = compileRegistrationKeyRelationCensus();
    const registrationCustody = compileRegistrationCustodyCensus();
    const registrationEnrollment = compileRegistrationEnrollmentCensus();
    const hashRowCheckpoint = compileHashRowCheckpointCensus();
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
    const clearSelectionWires = thresholdProfiles.map((profile) =>
        compileSetupSelectionWireCensus(profile.participantCount),
    );
    const commonAgreement = compileCommonAgreementDegreeCensus();
    const rnsArithmetic = compileRnsArithmeticResourceCensus(completion);
    const setupRelation = compileSetupContributionRelationCensus(completion);
    const linkedRelease = compileLinkedReleaseRelationCensus(completion);
    const linkedReleaseProof = compileLinkedReleaseWordProofLayout(completion);
    const ballotRelation = compileBallotEncryptionRelationCensus(completion);
    const fixedModulusBfv = compileProfileBfvCensus(completion);
    const supportedProfiles = compileSupportedProfileCensus();
    const recoverableSetup = compileRecoverableSetupResourceScreen(
        completion.participantCount,
        completion.optionCount,
    );
    const boundedSeedSharingProof = compileRecoverableSeedSharingProofResources(
        4,
        2,
        256n,
        4n,
    );
    const fullFourParticipantSeedSharingProof =
        compileRecoverableSeedSharingProofResources(4, 2);
    const boundedOpeningShareProof = compileOpeningShareResources(4, 256n);
    const boundedOpeningNative = compileBoundedOpeningShareProofResources();
    const publicOperatorScreens = (['seed', 'opening'] as const).map(
        compilePublicOperatorScreenResources,
    );
    const recoverableSetupProfiles = supportedProfiles.profiles.flatMap((row) =>
        row.map((profile) =>
            compileRecoverableSetupResourceScreen(
                profile.participantCount,
                profile.optionCount,
            ),
        ),
    );
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
    const securityLedger = compileComposedSecurityLedger();
    const populationLedger = compileComposedSecurityLedger(
        securityLedger.maximumCredentialPopulation,
    );
    const largestLedgerProfile =
        securityLedger.profiles[securityLedger.profiles.length - 1];
    const largestRosterWork = compileReductionWork(
        largestLedgerProfile.potentialCredentialCount,
        largestLedgerProfile.extractedCommitmentCount,
    );
    const unitCallCost = compileUnitCallCostSensitivity();
    const signedExponent = (exponent: bigint): string =>
        `\`${exponent < 0n ? '-' : ''}${(exponent < 0n ? -exponent : exponent).toLocaleString('en-US')}\``;
    const distinctJoined = (values: readonly (bigint | number)[]): string =>
        [...new Set(values.map((value) => value.toString()))]
            .map((value) => formatCount(BigInt(value)))
            .join(', ');
    const rangeOf = (values: readonly (bigint | number)[]): string => {
        const sorted = values
            .map((value) => BigInt(value))
            .sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
        const [low, high] = [sorted[0], sorted[sorted.length - 1]];
        return low === high
            ? formatCount(low)
            : `${formatCount(low)} to ${formatCount(high)}`;
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

    return `${[
        '# Documentation census',
        '',
        'Generated by `pnpm run docs:census` from the independent TypeScript models under `tests/`. Do not edit by hand. These are model-derived development values, not a protocol theorem, concrete FHE parameter approval, browser measurement, or supported-phone qualification. A section that names no participant or option count evaluates the completion profile of ten participants and ten options; the supported profile census and the composed security ledger cover every supported profile.',
        '',
        '## Threshold completion census',
        '',
        'The lifecycle census allows independently bounded disappearance and corrupt-refusal sets. The scope of this stronger candidate availability model is owned by [non-forking state](non-forking-state.md#release-threshold-under-the-candidate-availability-model); its responder floor is not an additional mandatory fault budget.',
        '',
        'For each supported roster, the model uses `f = floor((n - 1) / 3)`, all `n` setup receipts, inventory-certificate threshold `q = n - f`, result-release threshold `d = max(f + 1, 2)`, which is also the number of setup contributors, the first `d` roster positions, and minimum turnout `m = f + 2` accepted ballots. At least one setup contributor is honest because `d > f`, and no single one knows the key because `d >= 2`. All-roster receipts leave at least `n - 2f >= d` honest verified share holders after any `f` disappear, and `d < n`. At most `f` accepted ballots are corrupt, so a released result combines at least two honest ballots. When every honest participant votes, omitting `f` honest ballots while every corrupt participant abstains leaves `n - 2f` accepted ballots; the no-result column marks rosters where that is below `m`. A `q` close certificate has at least `n - 2f` honest locked signers, and two such certificates share at least `2q - n > f` positions, so a conflicting certificate needs an honest signer to sign twice. Every named set is counted; isomorphic joint cases are checked with exact multiplicity, and profiles through twelve participants are also brute-force cross-checked over the underlying bit masks.',
        '',
        table(
            [
                'Participants',
                'Maximum corrupt',
                'Inventory certificate',
                'Result release',
                'Minimum turnout',
                'No result forceable at full honest turnout',
                'Setup receipts',
                'Guaranteed honest responders / honest certificate signers',
                'Minimum certificate intersection',
                'Mandatory release positions',
                'Corruption/disappearance/refusal cases',
                'Ordered certificate pairs',
                'Brute-force cross-check',
            ],
            thresholdProfiles.map((profile) => [
                String(profile.participantCount),
                String(profile.maximumCorruptParticipantCount),
                String(profile.inventoryCertificateThreshold),
                String(profile.resultReleaseThreshold),
                String(profile.minimumTurnout),
                profile.noResultForceableAtFullHonestTurnout ? 'yes' : 'no',
                String(profile.setupReceiptThreshold),
                String(profile.guaranteedHonestResponderCount),
                String(profile.minimumCertificateIntersection),
                String(profile.mandatoryReleaseParticipantCount),
                formatCount(profile.corruptionDisappearanceRefusalCaseCount),
                formatCount(profile.orderedCertificatePairCount),
                profile.bruteForceCrossChecked ? 'yes' : 'class-counted',
            ]),
        ),
        '',
        '## Threshold key-aggregation structural census',
        '',
        'This finite-ring model checks that independently generated linear encryption, relinearization, and rotation-key contributions aggregate under one global secret, while degree-three Shamir redistributions at the KLLPS-style monomial points reconstruct from every four-position subset. It also checks the target-dependent flooded partial-decryption equation for every subset. It omits commitments, proofs, encryption of private shares, rounding correctness, and security reductions.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Participant count',
                    formatCount(thresholdKeyAggregation.participantCount),
                ],
                [
                    'Release threshold',
                    formatCount(thresholdKeyAggregation.releaseThreshold),
                ],
                [
                    'Authorized release subsets checked',
                    formatCount(
                        thresholdKeyAggregation.authorizedReleaseSetCount,
                    ),
                ],
                [
                    'Monomial interpolation points',
                    formatCount(
                        thresholdKeyAggregation.monomialInterpolationPointCount,
                    ),
                ],
                [
                    'Linear aggregate key equations checked',
                    formatCount(
                        thresholdKeyAggregation.aggregatePublicKeyEquationCount,
                    ),
                ],
                [
                    'Flooded release equations checked',
                    formatCount(thresholdKeyAggregation.releaseEquationCount),
                ],
                [
                    'Tampered share changed reconstruction',
                    thresholdKeyAggregation.tamperedShareChangedReconstruction
                        ? 'yes'
                        : 'no',
                ],
                [
                    'Wrong target changed partial decryption',
                    thresholdKeyAggregation.wrongTargetChangedPartialDecryption
                        ? 'yes'
                        : 'no',
                ],
                [
                    'Experiment coefficient modulus',
                    formatCount(thresholdKeyAggregation.coefficientModulus),
                ],
                [
                    'Experiment ring degree',
                    formatCount(thresholdKeyAggregation.ringDegree),
                ],
                [
                    'Experiment gadget length',
                    formatCount(thresholdKeyAggregation.gadgetLength),
                ],
            ],
        ),
        '',
        '## Recipient-key uniqueness census',
        '',
        'For an ideal uniformly sampled common ring element, a determinant and union bound limits the event that any public key has two bounded witnesses. The event covers every recipient public key at once. The exponent below bounds this statistical bad-matrix event only; it is not a computational-security level and does not cover the real SHAKE common-string generator, selective completion conditioning, or proof composition.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Current registration ring degree',
                    formatCount(recipientKeyUniqueness.polynomialModulusDegree),
                ],
                [
                    'Current registration modulus prime factor',
                    formatCount(recipientKeyUniqueness.primeModulus),
                ],
                [
                    'Recipient secret coefficient bound',
                    formatCount(recipientKeyUniqueness.secretCoefficientBound),
                ],
                [
                    'Recipient error coefficient bound',
                    formatCount(recipientKeyUniqueness.errorCoefficientBound),
                ],
                [
                    'Secret difference values per coefficient',
                    formatCount(
                        recipientKeyUniqueness.secretDifferenceValueCount,
                    ),
                ],
                [
                    'Error difference values per coefficient',
                    formatCount(
                        recipientKeyUniqueness.errorDifferenceValueCount,
                    ),
                ],
                [
                    'Squared determinant-union base numerator',
                    formatCount(
                        recipientKeyUniqueness.squaredFailureBaseNumerator,
                    ),
                ],
                [
                    'Uniform-matrix failure exponent',
                    formatCount(
                        recipientKeyUniqueness.uniformMatrixFailureExponent,
                    ),
                ],
            ],
        ),
        '',
        '## Bounded polynomial proof census',
        '',
        'Finite encoded-proof and lookup experiments. Degree membership is checked by complete interpolation in the linear experiment. These counts do not instantiate a committed ordinary IOP.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Linear experiment field order',
                    formatCount(boundedLinearProof.prime),
                ],
                [
                    'Systematic domain size',
                    formatCount(boundedLinearProof.systematicSize),
                ],
                [
                    'Evaluation domain size',
                    formatCount(boundedLinearProof.domainSize),
                ],
                [
                    'Mask coefficient count',
                    formatCount(boundedLinearProof.maskDimension),
                ],
                [
                    'Maximum witness degree',
                    formatCount(boundedLinearProof.witnessDegree),
                ],
                [
                    'Maximum masked-sum degree',
                    formatCount(boundedLinearProof.sumDegree),
                ],
                [
                    'Independent sum-mask degree',
                    formatCount(boundedLinearProof.sumMaskDegree),
                ],
                [
                    'Short-mask joint views checked',
                    formatCount(boundedLinearProof.shortMaskViews.checkedViews),
                ],
                [
                    'Short-mask joint observation dimension',
                    formatCount(
                        boundedLinearProof.shortMaskViews.observationCount,
                    ),
                ],
                [
                    'Minimum short-mask observation rank',
                    formatCount(boundedLinearProof.shortMaskViews.minimumRank),
                ],
                [
                    'Maximum rank without the quotient mask',
                    formatCount(
                        boundedLinearProof.shortMaskViews
                            .maximumRankWithoutQuotientMask,
                    ),
                ],
                [
                    'Accepted valid challenge pairs',
                    formatCount(boundedLinearProof.trueAcceptanceCount),
                ],
                [
                    'Accepted invalid challenge pairs',
                    formatCount(boundedLinearProof.falseAcceptanceCount),
                ],
                [
                    'Accepting simulated challenge pairs',
                    formatCount(
                        boundedLinearProof.simulatedFalseAcceptanceCount,
                    ),
                ],
                [
                    'False range-quotient table degree',
                    formatCount(boundedLinearProof.invalidNormTableDegree),
                ],
                [
                    'Tampered witness table degree',
                    formatCount(boundedLinearProof.tamperedWitnessTableDegree),
                ],
                [
                    'Lookup base-field characteristic',
                    formatCount(boundedLookup.basePrime),
                ],
                [
                    'Lookup extension degree',
                    formatCount(boundedLookup.extensionDegree),
                ],
                [
                    'Lookup challenge count',
                    formatCount(boundedLookup.challengeCount),
                ],
                [
                    'Valid lookup acceptances',
                    formatCount(boundedLookup.validAcceptances),
                ],
                [
                    'Targeted invalid lookup acceptances',
                    formatCount(boundedLookup.invalidAcceptances),
                ],
                [
                    'Invalid acceptances when the occurrence count wraps',
                    formatCount(boundedLookup.characteristicWrapAcceptances),
                ],
            ],
        ),
        '',
        '## Wide sharing and release lifting census',
        '',
        'Candidate bounds for byte-aligned integer sharing and the dense release relation. The finite experiments independently construct the integer products, decrypt encrypted evaluations, and reproduce the out-of-range modular aliases. They do not implement the complete public proof or admit a distribution.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Share-encryption scale', formatCount(wideShareLifting.scale)],
                [
                    'Share-encryption modulus',
                    formatCount(wideShareLifting.modulus),
                ],
                [
                    'Nonconstant sharing coefficient radius',
                    formatCount(wideShareLifting.sharingRadius),
                ],
                [
                    'Nonconstant sharing coefficient bits',
                    formatCount(wideShareLifting.sharingCoefficientBits),
                ],
                [
                    'Share-encryption secret support weight',
                    formatCount(wideShareLifting.encryptionSupportWeight),
                ],
                [
                    'Shared FHE secret support weight',
                    formatCount(wideShareLifting.sharedSecretSupportWeight),
                ],
                [
                    'Joint sharing-translation numerator',
                    formatCount(wideShareLifting.privacyNumerator),
                ],
                [
                    'Aggregate sharing coefficient bound',
                    formatCount(wideShareLifting.aggregateSharingMaximum),
                ],
                ['Sharing limb radix', formatCount(wideShareLifting.radix)],
                [
                    'Sharing quotient magnitude bound',
                    formatCount(wideShareLifting.quotientBound),
                ],
                [
                    'Sharing carry magnitude bound',
                    formatCount(wideShareLifting.carryBound),
                ],
                [
                    'Complete sharing limb residual bound',
                    formatCount(wideShareLifting.residualBound),
                ],
                [
                    'Sharing equations checked',
                    formatCount(wideShareLifting.checkedEquations),
                ],
                [
                    'Carry needed by the false sharing equation',
                    formatCount(wideShareLifting.aliasCarry),
                ],
                [
                    'Dense release limb radix',
                    formatCount(releaseShareLifting.radix),
                ],
                [
                    'Dense release carry magnitude bound',
                    formatCount(releaseShareLifting.carryBound),
                ],
                [
                    'Complete dense release limb residual bound',
                    formatCount(releaseShareLifting.residualBound),
                ],
                [
                    'Dense release equations checked',
                    formatCount(releaseShareLifting.checkedEquations),
                ],
                [
                    'Carry needed by the false release equation',
                    formatCount(releaseShareLifting.aliasCarry),
                ],
            ],
        ),
        '',
        '## Linked ballot encryption census',
        '',
        'The model links a complete bounded score vector to the exact FHE comparison-window packing, literal FHE score tail, and auxiliary score encryption. Every integer quotient, carry, and centered plaintext endpoint is explicit. The auxiliary scheme is for simulator input recovery; it has no participant decryption action.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Auxiliary ring degree',
                    formatCount(auxiliaryInputEncryptionParameters.degree),
                ],
                [
                    'Auxiliary ciphertext modulus',
                    formatCount(auxiliaryInputEncryptionParameters.modulus),
                ],
                [
                    'Auxiliary plaintext modulus',
                    formatCount(
                        auxiliaryInputEncryptionParameters.plaintextModulus,
                    ),
                ],
                [
                    'Auxiliary plaintext scale',
                    formatCount(auxiliaryInputEncryptionParameters.scale),
                ],
                [
                    'Auxiliary ephemeral and proof-game secret support',
                    formatCount(auxiliaryInputEncryptionParameters.support),
                ],
                [
                    'Auxiliary good-key proof-game noise bound',
                    formatCount(ballotRelation.auxiliaryGoodKeyNoiseBound),
                ],
                ['FHE integer limbs', formatCount(ballotRelation.limbs)],
                [
                    'Honest FHE encryption quotient bound',
                    formatCount(ballotRelation.trueQuotientBound),
                ],
                [
                    'Honest FHE encryption carry bound',
                    formatCount(ballotRelation.trueCarryBound),
                ],
                [
                    'Accepted FHE limb residual bound',
                    formatCount(ballotRelation.residualBound),
                ],
                [
                    'Honest packing quotient bound',
                    formatCount(ballotRelation.packingQuotientBound),
                ],
                [
                    'Accepted packing residual bound',
                    formatCount(ballotRelation.packingResidualBound),
                ],
                [
                    'Accepted auxiliary residual bound',
                    formatCount(ballotRelation.auxiliaryResidualBound),
                ],
                ['Word columns', formatCount(ballotRelation.wordColumns)],
                ['Boolean columns', formatCount(ballotRelation.booleanColumns)],
                [
                    'Additional quadratic constraints',
                    formatCount(ballotRelation.additionalQuadraticConstraints),
                ],
                [
                    'Maximum simultaneously retained product input columns',
                    formatCount(ballotRelation.maximumLiveProductColumns),
                ],
                [
                    'Two-coset product input cache payload bytes',
                    formatCount(ballotRelation.zeroProductCacheBytes),
                ],
                [
                    'Proof header bytes',
                    formatCount(ballotWordProof.headerBytes),
                ],
                [
                    'First oracle row bytes',
                    formatCount(ballotWordProof.firstWidth),
                ],
                [
                    'Second oracle row bytes',
                    formatCount(ballotWordProof.secondWidth),
                ],
                [
                    'Maximum incremental proof bytes',
                    formatCount(ballotWordProof.maximumMultiproofBytes),
                ],
                [
                    'Maximum cached node digest bytes',
                    formatCount(ballotWordProof.maximumCachedNodeDigestBytes),
                ],
                [
                    'Retained leaf-salt seed bytes',
                    formatCount(ballotWordProof.saltSeedBytes),
                ],
                [
                    'Prover mask bytes',
                    formatCount(ballotWordProof.proverMaskBytes),
                ],
                [
                    'Minimum requested proof randomness bytes before field-sampling rejection',
                    formatCount(ballotWordProof.minimumRequestedRandomBytes),
                ],
                [
                    'Resident public operator payload bytes',
                    formatCount(ballotWordProof.residentPublicOperatorBytes),
                ],
                [
                    'Additional narrow memberships',
                    formatCount(ballotRelation.narrowMemberships),
                ],
                [
                    'Single-entry inverse columns',
                    formatCount(ballotRelation.lookupEntries),
                ],
                [
                    'Full-profile affine rows',
                    formatCount(ballotRelation.affineRows),
                ],
            ],
        ),
        '',
        '## Ballot body census',
        '',
        'The framed body carries the bound context, both ciphertext pairs, and the exact proof. The verifier obtains only the FHE aggregate public key from certified setup and derives the FHE common coordinate and both fixed auxiliary coordinates locally. The complete expanded relation still has eight polynomials. Framing alone supplies no signature, publication, or ballot authority.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Context bytes', formatCount(ballotBody.contextBytes)],
                [
                    'Protocol proof role bytes',
                    formatCount(ballotBody.proofRoleBytes),
                ],
                ['Body header bytes', formatCount(ballotBody.headerBytes)],
                [
                    'Ciphertext payload bytes',
                    formatCount(ballotBody.ciphertextBytes),
                ],
                [
                    'Reconstructed public input bytes',
                    formatCount(ballotBody.reconstructedInputBytes),
                ],
                [
                    'Certified setup key input bytes',
                    formatCount(ballotBody.setupKeyInputBytes),
                ],
                [
                    'Locally derived common and fixed-pair input bytes',
                    formatCount(ballotBody.locallyDerivedInputBytes),
                ],
                [
                    'Minimum proof bytes',
                    formatCount(ballotBody.minimumProofBytes),
                ],
                [
                    'Maximum proof bytes',
                    formatCount(ballotBody.maximumProofBytes),
                ],
                ['Signature bytes', formatCount(ballotBody.signatureBytes)],
                [
                    'Envelope header bytes',
                    formatCount(ballotBody.envelopeBytes),
                ],
                [
                    'Maximum body bytes',
                    formatCount(ballotBody.maximumBodyBytes),
                ],
                [
                    'Maximum signed body bytes',
                    formatCount(ballotBody.maximumSignedBodyBytes),
                ],
                [
                    'Body identity hash prefix bytes',
                    formatCount(ballotBody.hashPrefixBytes),
                ],
                [
                    'Maximum body identity hash input bytes',
                    formatCount(ballotBody.maximumHashInputBytes),
                ],
            ],
        ),
        '',
        '## Authentication frames and completed prefix',
        '',
        'The pure FIPS 204 interface frames each participant application message as zero, one-byte context length, context, message. The representative hashes tr followed by that frame. These rows cover participant credentials. The counts exclude all other ML-DSA hashing, key expansion, rejection loops, semantic-body hashing, state and transfer work. Signing an application digest through this interface is distinct from HashML-DSA.',
        '',
        table(
            [
                'Purpose',
                'Message bytes',
                'FIPS frame bytes',
                'Representative input bytes',
                'Representative permutations',
            ],
            compileCompleteAuthenticationFrameWork().map((role) => [
                role.purpose,
                formatCount(role.messageBytes),
                formatCount(role.frameBytes),
                formatCount(role.representativeInputBytes),
                formatCount(role.representativePermutations),
            ]),
        ),
        '',
        'The current pure ML-DSA-65 internal calls have the following input shapes. A missing literal output cap is recorded for each rejection sampler. This does not bound arbitrary adversary queries or future protocol purposes.',
        '',
        table(
            ['Purpose', 'Primitive', 'Input bytes', 'Literal output bytes'],
            compileCurrentSignatureHashInputs().rows.map((row) => [
                row.purpose,
                row.family,
                formatCount(row.inputBytes),
                row.outputBytes === null
                    ? 'No source cap'
                    : formatCount(row.outputBytes),
            ]),
        ),
        '',
        'The following ideal-XOF bad-event bounds union over the entire sampler seed space before adaptive input selection. Analytical output caps do not change the library. Subsequent preservation requires the stated oracle-programming chronology; the main signing rejection event and complete time conversion remain separate.',
        '',
        table(
            [
                'Sampler',
                'Seed bytes',
                'Candidate positions',
                'Required rejections',
                'Analytical output cap bytes',
                'All-seed failure exponent',
            ],
            compileCurrentSignatureSamplingBounds().map((row) => [
                row.purpose,
                ...[
                    row.inputBytes,
                    row.candidatePositions,
                    row.requiredRejections,
                    row.outputBytes,
                    row.failureExponent,
                ].map(formatCount),
            ]),
        ),
        '',
        'The preserved through-ballot prefix counts first-evaluated intents, including signatures never delivered. Repeated evaluation of retained coins consumes runtime but no new cached signing-oracle query. Keep this prefix separate from the full-action branches below; neither table supplies a lifetime credential population, repeated-work bound or complete signature-security claim.',
        '',
        table(
            [
                'Credential role',
                'Current purposes',
                'First-evaluated intent bound',
            ],
            compileCurrentCredentialIntentBounds().map((value) => [
                value.role,
                value.purposes.join(', '),
                formatCount(value.firstEvaluatedIntentBound),
            ]),
        ),
        '',
        "For one original credential/action under the retained-state invariant, the ballot is optional and at most one; the close intent blocks a new ballot attempt. Every participant signs one close response, and the organizer also its close intent and proposal. No-result omits release. Encrypted release may omit the participant's own target vote, but cannot bypass a pending target intent or start target signing after release begins. The no-result row is a maximum allowing an own target vote, not a claim that every participant supplies one.",
        '',
        table(
            [
                'Participants',
                'Branch',
                'Credential role',
                'Fixed purposes',
                'Optional purposes',
                'First-evaluated intent bound',
            ],
            compileCompleteCredentialIntentBounds(
                completion.participantCount,
            ).map((value) => [
                formatCount(value.participantCount),
                value.branch,
                value.role,
                value.fixedPurposes.join(', '),
                value.optionalPurposes.join(', '),
                formatCount(value.firstEvaluatedIntentBound),
            ]),
        ),
        '',
        'One native ballot-signing evaluation regenerates the original ML-DSA key, then Sign expands the public matrix again. The checked-counter boundary below is conditional on the declared overflow-checking build and the sampler read event. It bounds work until success or the arithmetic boundary; it does not bound the probability of signing failure. Hash-permutation work applies when executing the concrete SHAKE implementation; a simulated oracle instead needs its own circuit cost.',
        '',
        table(
            ['Property', 'Value'],
            (() => {
                const boundary = compileSignatureCounterBoundary(),
                    work = compileBallotSignatureHashWork(
                        boundary.fullIterations,
                        boundary.partialMaskCalls,
                    );
                const rows: [string, bigint][] = [
                    ['Distinct mask nonces', boundary.nonceCapacity],
                    [
                        'Complete mask-vector iterations',
                        boundary.fullIterations,
                    ],
                    ['Partial final mask calls', boundary.partialMaskCalls],
                    ['Hash calls including key regeneration', work.hashCalls],
                    ['Cumulative hash input bytes', work.inputBytes],
                    [
                        'Cumulative hash output byte bound',
                        work.outputBytesUpperBound,
                    ],
                    [
                        'Concrete SHAKE permutation bound',
                        work.permutationsUpperBound,
                    ],
                ];
                return rows.map(([label, value]) => [
                    label,
                    formatCount(value),
                ]);
            })(),
        ),
        '',
        'FIPS 204 Appendix C uses a geometric repetition estimate. The official potential-update supplement corrects the mean and minimum loop limit. The following exponents are exact calculations within that source model, not established implementation failure probabilities or security levels; mean alone does not imply the geometric tail. The inspected counter remains above both source limits.',
        '',
        table(
            [
                'Source model',
                'Mean numerator',
                'Mean denominator',
                'Source minimum iterations',
                'Estimated exponent at source limit',
                'Estimated exponent at original limit',
                'Estimated exponent at checked counter',
            ],
            compileSigningLoopSourceComparison().map((row) => [
                row.source,
                ...[
                    row.meanNumerator,
                    row.meanDenominator,
                    row.minimumIterations,
                    row.atSourceLimit.failureExponent,
                    row.atOriginalLimit.failureExponent,
                    row.atCheckedCounter.failureExponent,
                ].map(formatCount),
            ]),
        ),
        '',
        'The following completed, all-cooperating prefixes use the completion profile and one completed registration per roster participant. A signed ballot counts here even if it will fail inner verification. Additional registrations are an explicit census input. These public record counts are not lifetime honest-key or signing-oracle bounds; they exclude abandoned enrollment, additional intents, repeated evaluation, verification, recovery and the unimplemented closing/release purposes.',
        '',
        table(
            [
                'Signed ballots',
                'Signed records',
                'Signature bytes',
                'Application message bytes',
                'FIPS frame bytes',
                'Representative permutations',
            ],
            [0, Number(fixedModulusBfv.participantCount)].map((ballots) => {
                const value = compileCompletedAuthenticationCensus(
                    Number(fixedModulusBfv.participantCount),
                    fixedModulusBfv.participantCount,
                    ballots,
                );
                return [
                    formatCount(ballots),
                    formatCount(value.signatures),
                    formatCount(value.signatureBytes),
                    formatCount(value.signingMessageBytes),
                    formatCount(value.signingFrameBytes),
                    formatCount(value.representativePermutations),
                ];
            }),
        ),
        '',
        '## Proof hash byte and permutation work',
        '',
        "Construct each commitment tree once, process the Fiat-Shamir transcript and context once, or consume one canonical verifier pass. Logical hash inputs and outputs are unchanged by the prover's and the verifier's public-prefix reuse; the permutation columns separate that implementation from recomputing every prefix. Clone/allocation work, statement-digest passes, fixed-matrix generation, wrappers, checkpoint/replay work and lifetime multiplicities remain separate. These are not quantum gate bounds or a full participant total. The release row uses the authenticated protocol role specified by the foundation owner.",
        '',
        table(
            [
                'Role',
                'Role bytes',
                'Verifier message bytes',
                'Prover core logical input bytes',
                'Prover permutations without prefix reuse',
                'Prover permutations with prefix reuse',
                'Verifier core hash input bytes',
                'Verifier permutations without prefix reuse',
                'Verifier permutations with prefix reuse',
                'One statement-digest pass permutations',
            ],
            proofHashProfiles(completion).map((profile) => {
                const value = compileProofHashWork(completion, profile);
                return [
                    profile.role,
                    formatCount(value.roleBytes),
                    formatCount(profile.messageBytes),
                    formatCount(value.proverCore.inputBytes),
                    formatCount(
                        value.proverCoreWithoutPrefixReuse.permutations,
                    ),
                    formatCount(value.proverCore.permutations),
                    formatCount(value.verifierCore.inputBytes),
                    formatCount(
                        value.verifierCoreWithoutPrefixReuse.permutations,
                    ),
                    formatCount(value.verifierCore.permutations),
                    formatCount(value.statementDigestPass.permutations),
                ];
            }),
        ),
        '',
        '## Release verification attempts',
        '',
        'A valid relation body paired with a correctly signed envelope claiming the wrong body identity is rejected only after complete proof verification. The public context survives that rejection. These counts apply per complete attempt with that context already verified; multiply by the number of attempts. Exact replay, changed envelopes with a fixed proof, and changed proof bodies remain separate populations. Executed calls do not establish distinct oracle points, a simulator lower bound, a lifetime limit or a full reduction cost. The calls of every attempt are oracle calls of the experiment, so the comparisons assign the entire query cap to this core alone, before subtracting any other charged work. Signature work, common-polynomial expansion and any additional predecessor reload remain separately chargeable.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Mandatory proof-core calls excluding Merkle work',
                    formatCount(
                        releaseVerification.perAttempt.minimumProofCoreQueries,
                    ),
                ],
                [
                    'Plain statement-digest passes outside the core',
                    formatCount(
                        releaseVerification.perAttempt
                            .plainStatementDigestPasses,
                    ),
                ],
                [
                    'Completed release-body digest passes outside the core',
                    formatCount(
                        releaseVerification.perAttempt
                            .completedBodyDigestPasses,
                    ),
                ],
                [
                    'Known calls excluding Merkle, signature and common-polynomial work',
                    formatCount(
                        releaseVerification.perAttempt.minimumKnownHashCalls,
                    ),
                ],
                [
                    'Full attempts within the query cap using the core upper bound',
                    formatCount(
                        releaseVerification.maximumAttemptsCoveredByCoreUpperBound,
                    ),
                ],
                [
                    'First attempt count exceeding the query cap from mandatory core calls alone',
                    formatCount(
                        releaseVerification.firstAttemptCountExceedingCoreLowerBound,
                    ),
                ],
            ],
        ),
        '',
        '## Proof verifier query bounds',
        '',
        'Logical hash queries for one canonical proof-core verification attempt under the current common-agreement profile. Expanded ancestors are hashed only once across canonical incremental openings. These bounds exclude statement reconstruction, fixed-matrix generation, outer authentication, additional attempts, hash input/output byte work, and the prover or simulator. They are neither a lifetime population nor a complete reduction runtime.',
        '',
        table(
            ['Hash purpose', 'Maximum queries per attempt'],
            [
                [
                    'Salted leaves',
                    formatCount(proofVerifierQueries.maximumLeafQueries),
                ],
                [
                    'Expanded tree parents',
                    formatCount(proofVerifierQueries.maximumNodeQueries),
                ],
                [
                    'Verifier messages',
                    formatCount(proofVerifierQueries.verifierMessageQueries),
                ],
                [
                    'Chain states',
                    formatCount(proofVerifierQueries.chainStateQueries),
                ],
                [
                    'Message roots',
                    formatCount(proofVerifierQueries.messageRootQueries),
                ],
                [
                    'Statement context',
                    formatCount(proofVerifierQueries.contextQueries),
                ],
                [
                    'Proof-core subtotal',
                    formatCount(proofVerifierQueries.maximumCoreQueries),
                ],
            ],
        ),
        '',
        table(
            [
                'Tree ordinal',
                'Leaves',
                'Maximum opened leaves',
                'Maximum expanded parents',
            ],
            proofVerifierQueries.groups.map((group, index) => [
                formatCount(index),
                formatCount(group.length),
                formatCount(group.maximumLeafQueries),
                formatCount(group.maximumNodeQueries),
            ]),
        ),
        '',
        '## Sparse-support sampling comparison',
        '',
        'This proof-only comparison caps each existing balanced sparse sampler at twice its support size on the same random tape. Before completion, each conditional rejection probability is at most (support - 1) / degree; a rejected-position union gives the per-call bound (4 * (support - 1) / degree)^support, capped at one. These are not new runtime limits or permissions to retry. Count every invocation in the relevant execution, including failed operations. The browser columns charge complete fresh reader fills, including discarded tails; native draws request only their examined words. Other sampling, provider failures and complete generation/work populations remain separate.',
        '',
        table(
            [
                'Sampler',
                'Degree',
                'Support',
                'Calls per named operation',
                'Comparison draw cap',
                'Maximum examined bytes',
                'Maximum browser RNG bytes',
                'Per-call failure bits',
            ],
            compileSparseSupportSamplingCensus(completion).map((value) => [
                value.role,
                formatCount(value.degree),
                formatCount(value.support),
                formatCount(value.callsPerOperation),
                formatCount(value.maximumDraws),
                formatCount(value.maximumExaminedBytes),
                formatCount(value.maximumBrowserRandomBytes),
                formatCount(value.failureBits),
            ]),
        ),
        '',
        '## Proof simulator randomness budgets',
        '',
        "These limits cover each complete word-proof role and one fresh programmed wide verifier message. Extra buffered reads are charged by the rejected-field-word event bound over the invocation cap, the honest-proof budget of the compiler, because each role's simulator runs at most once per honest proof and a restored participant replays completed proofs. Witness/key generation, participant lifecycle and other primitive samplers remain separate.",
        '',
        table(
            [
                'Role',
                'Ordinary proof baseline bytes',
                'Programmed-message bytes',
                'Extra buffered reads',
                'Maximum simulator bytes',
                'Invocation cap',
                'Failure allocation bits',
            ],
            compileProofRandomnessBudgets(completion).map((value) => [
                value.role,
                formatCount(value.ordinaryBaselineBytes),
                formatCount(value.programmedMessageBytes),
                formatCount(value.extraReads),
                formatCount(value.failure.maximumBytes),
                formatCount(value.invocationCap),
                formatCount(value.failureAllocationBits),
            ]),
        ),
        '',
        '## Operation randomness seeds',
        '',
        "Fresh randomness that the participant module's samplers and provers draw for a contribution generation or continuation, a ballot or a release is SHAKE256 output over its stream's domain and one seed that the participant's root retains before the operation draws any byte. The contribution's original FHE secret and first encryption error come from its separately retained registration source. A repeated operation reads its retained seed again, so it draws the same bytes; no finite budget is exhausted. The count bounds operation seeds of one roster: two for each eligible contributor and two for each participant, excluding the registration sources below. An honest ballot's and release's proof streams serve exactly the listed bytes when no candidate word is rejected; a release's include its noise, drawn in whole reads.",
        '',
        table(
            ['Property', 'Value'],
            [
                ['Seed bytes', formatCount(operationSeedBytes)],
                [
                    'Seeds per roster at the completion profile',
                    formatCount(operationSeedCount(completion)),
                ],
                [
                    'Seeds per roster at the largest profile',
                    formatCount(
                        operationSeedCount(
                            listSupportedProfiles().slice(-1)[0],
                        ),
                    ),
                ],
                [
                    'Ballot proof-stream bytes at the completion profile',
                    formatCount(compileOperationProofDraws(completion).ballot),
                ],
                [
                    'Release proof-stream bytes at the completion profile',
                    formatCount(compileOperationProofDraws(completion).release),
                ],
            ],
        ),
        '',
        '## Registration source randomness and hash work',
        '',
        'This local census uses the completion profile as both the final roster and the original poll maximum. The model takes the original maximum explicitly because a smaller final roster does not erase the families sampled at enrollment. Each family has an independent retained source seed and commitment salt; the source samples one balanced FHE secret and the first encryption error. Its direct SHAKE reader has no browser RNG buffer tail. Source-output maxima below use the existing proof-only sparse draw comparison, never a runtime limit. Reconstructing a source repeats work on the same seed, while common-polynomial streams can repeat the same input across families. The summed permutations are computational work, not distinct oracle queries. Abandoned credentials, repeated reconstruction and the global source-seed population require separate accounting; these rows do not establish the composed security ledger.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Original poll maximum',
                    formatCount(
                        registrationSourceRandomness.originalPollMaximumParticipants,
                    ),
                ],
                [
                    'Source seeds per original enrollment',
                    formatCount(registrationSourceRandomness.sourceSeedCount),
                ],
                [
                    'Fresh seed and salt bytes per original enrollment',
                    formatCount(
                        registrationSourceRandomness.freshSeedAndSaltBytes,
                    ),
                ],
                [
                    'Source Gaussian samples per original enrollment',
                    formatCount(registrationSourceRandomness.gaussianSamples),
                ],
                [
                    'Source sparse calls per original enrollment',
                    formatCount(registrationSourceRandomness.sparseCalls),
                ],
                [
                    'Hash permutations per original enrollment under the sparse comparison',
                    formatCount(
                        registrationSourceRandomness.comparisonHashPermutations,
                    ),
                ],
            ],
        ),
        '',
        table(
            [
                'Family',
                'Modulus bytes',
                'Sampler bits',
                'Source input bytes',
                'Minimum source output bytes',
                'Comparison maximum source output bytes',
                'Commitment input bytes',
                'Common stream output bytes',
                'Source permutations',
                'Commitment permutations',
                'Common permutations',
            ],
            registrationSourceRandomness.families.map((family) => [
                formatCount(family.index),
                formatCount(family.modulusBytes),
                formatCount(family.sampleBits),
                formatCount(family.sourceInputBytes),
                formatCount(family.minimumSourceOutputBytes),
                formatCount(family.comparisonMaximumSourceOutputBytes),
                formatCount(family.commitmentInputBytes),
                formatCount(family.commonOutputBytes),
                formatCount(family.comparisonSourcePermutations),
                formatCount(family.commitmentPermutations),
                formatCount(family.commonPermutations),
            ]),
        ),
        '',
        '## Participant ballot custody',
        '',
        'Private ballot suffix and payload bounds, excluding the already retained participant root and its earlier records. The encoded suffix supplies no verification or signing authority by itself.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Maximum ballot state bytes',
                    formatCount(participantBallotCustody.maximumStateBytes),
                ],
                [
                    'Maximum body records',
                    formatCount(participantBallotCustody.maximumBodyRecords),
                ],
                [
                    'Maximum encrypted body bytes',
                    formatCount(
                        participantBallotCustody.maximumEncryptedBodyBytes,
                    ),
                ],
                ...participantBallotCustody.phaseBytes.map((value) => [
                    'Phase ' + value.phase + ' state bytes',
                    formatCount(value.bytes),
                ]),
            ],
        ),
        '',
        '## Participant close custody',
        '',
        'Private close suffix and record bounds, excluding the already retained participant root and its earlier records. The suffix retains the accepted close inputs in arrival order with one key per encrypted record, so restoration replays them into the same state through the owning state machine. Before an intent the suffix only collects, alongside every ballot phase. Held bodies bound the delivery events, since the state machine refuses an input that changes nothing, and only the organizer adds one event per other responder and retains its proposal body and coins when its response completes. The per-roster table uses the completion option count, and the held bodies dominate the record bytes. The encoded suffix supplies no verification or signing authority by itself.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Maximum close state bytes',
                    formatCount(participantCloseCustody.maximumStateBytes),
                ],
                [
                    'Maximum collecting state bytes',
                    formatCount(participantCloseCustody.collectingBytes),
                ],
                [
                    'Maximum close events',
                    formatCount(participantCloseCustody.maximumEvents),
                ],
                [
                    'Maximum close records',
                    formatCount(participantCloseCustody.maximumRecords),
                ],
                [
                    'Maximum encrypted close record bytes',
                    formatCount(
                        participantCloseCustody.maximumEncryptedRecordBytes,
                    ),
                ],
                [
                    'Maximum organizer encrypted close record bytes',
                    formatCount(
                        participantCloseCustody.maximumOrganizerEncryptedRecordBytes,
                    ),
                ],
                [
                    'Maximum organizer encrypted close record bytes at the largest profile',
                    formatCount(
                        largestCloseCustody.maximumOrganizerEncryptedRecordBytes,
                    ),
                ],
                ...participantCloseCustody.phaseBytes.map((value) => [
                    'Phase ' + value.phase + ' state bytes',
                    formatCount(value.bytes),
                ]),
            ],
        ),
        '',
        table(
            [
                'Participants',
                'Maximum close state bytes',
                'Maximum close events',
                'Maximum close records',
                'Maximum encrypted close record bytes',
                'Maximum organizer encrypted close record bytes',
            ],
            thresholdProfiles.map(({ participantCount }) => {
                const value = compileParticipantCloseCustody(
                    deriveSupportedProfile(
                        participantCount,
                        completionProfileCounts.optionCount,
                    ),
                );
                return [
                    formatCount(participantCount),
                    formatCount(value.maximumStateBytes),
                    formatCount(value.maximumEvents),
                    formatCount(value.maximumRecords),
                    formatCount(value.maximumEncryptedRecordBytes),
                    formatCount(value.maximumOrganizerEncryptedRecordBytes),
                ];
            }),
        ),
        '',
        '## Participant release custody',
        '',
        'Private release suffix and payload bounds for one original-key release under the retained certified target, excluding the earlier participant state. Repeated execution draws the same bytes from the retained seed. The encoded suffix supplies no verification or signing authority by itself.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Authenticated proof role bytes',
                    formatCount(participantReleaseCustody.proofRoleBytes),
                ],
                [
                    'Maximum release state bytes',
                    formatCount(participantReleaseCustody.maximumStateBytes),
                ],
                [
                    'Maximum body bytes',
                    formatCount(participantReleaseCustody.maximumBodyBytes),
                ],
                [
                    'Maximum body records',
                    formatCount(participantReleaseCustody.maximumBodyRecords),
                ],
                [
                    'Maximum encrypted body bytes',
                    formatCount(
                        participantReleaseCustody.maximumEncryptedBodyBytes,
                    ),
                ],
                ...participantReleaseCustody.phaseBytes.map((value) => [
                    'Phase ' + value.phase + ' state bytes',
                    formatCount(value.bytes),
                ]),
            ],
        ),
        '',
        '## Linked release relation census',
        '',
        'The recipient-key, encrypted aggregate-decryption, and dense partial-release equations use the same hidden share and original recipient secret. These are exact integer-lifting and layout values; the emitted proof and target capability remain separate.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Hidden aggregate-share bits',
                    formatCount(linkedRelease.shareBits),
                ],
                [
                    'Aggregate decoding-error bits',
                    formatCount(linkedRelease.decodingErrorBits),
                ],
                [
                    'Aggregate decoding-quotient bits',
                    formatCount(linkedRelease.decodingQuotientBits),
                ],
                [
                    'Aggregate decoding-carry bits',
                    formatCount(linkedRelease.decodingCarryBits),
                ],
                [
                    'Honest decoding quotient bound',
                    formatCount(linkedRelease.trueDecodingQuotientBound),
                ],
                [
                    'Honest decoding carry bound',
                    formatCount(linkedRelease.trueDecodingCarryBound),
                ],
                [
                    'Accepted decoding residual bound',
                    formatCount(linkedRelease.decodingResidualBound),
                ],
                ['Word columns', formatCount(linkedRelease.wordColumns)],
                [
                    'Additional narrow memberships',
                    formatCount(linkedRelease.narrowMemberships),
                ],
                ['Boolean columns', formatCount(linkedRelease.booleanColumns)],
                [
                    'Single-entry inverse columns',
                    formatCount(linkedRelease.lookupEntries),
                ],
                [
                    'Full-profile affine rows',
                    formatCount(linkedRelease.affineRows),
                ],
                [
                    'First release-oracle row bytes',
                    formatCount(linkedReleaseProof.firstWidth),
                ],
                [
                    'Second release-oracle row bytes',
                    formatCount(linkedReleaseProof.secondWidth),
                ],
                [
                    'Maximum canonical release-proof bytes',
                    formatCount(linkedReleaseProof.maximumMultiproofBytes),
                ],
                [
                    'Resident release affine-operator bytes',
                    formatCount(linkedReleaseProof.residentPublicOperatorBytes),
                ],
            ],
        ),
        '',
        '## Setup contribution operator census',
        '',
        'The complete reduced-ring model exercises the FHE key, encrypted-share, range and support relations. Full-profile affine rows scale those same equation families to the full ring degree. The full-degree KLSW auxiliary secret remains part of setup; the fixed auxiliary ballot pair supplies no setup secret, equation, column or public polynomial.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Word columns', formatCount(setupRelation.wordColumns)],
                ['Boolean columns', formatCount(setupRelation.booleanColumns)],
                [
                    'Additional narrow-error memberships',
                    formatCount(setupRelation.errorColumns),
                ],
                [
                    'Disjoint positive/negative pairs',
                    formatCount(setupRelation.disjointPairs),
                ],
                [
                    'Exact support-sum rows',
                    formatCount(setupRelation.supportRows),
                ],
                [
                    'Full-profile affine rows',
                    formatCount(setupRelation.affineRows),
                ],
                [
                    'Single-entry inverse columns',
                    formatCount(setupRelation.lookupEntries),
                ],
                [
                    'Full resident affine coefficient bytes',
                    formatCount(setupRelation.fullAffineCoefficientByteLength),
                ],
                [
                    'One public adjoint coefficient vector bytes',
                    formatCount(
                        setupRelation.singlePublicAdjointCoefficientByteLength,
                    ),
                ],
                [
                    'Largest signed public polynomial bytes',
                    formatCount(
                        setupRelation.largestPublicPolynomialByteLength,
                    ),
                ],
                [
                    'Maximum public polynomial query points',
                    formatCount(setupRelation.maximumPublicQueryCount),
                ],
                [
                    'One public polynomial query-value bytes',
                    formatCount(setupRelation.publicQueryValueByteLength),
                ],
                [
                    'All affine coefficients at query points bytes',
                    formatCount(setupRelation.fullAffineQueryValueByteLength),
                ],
                [
                    'Query-transform vectors and twiddles bytes',
                    formatCount(
                        setupRelation.publicQueryTransformVectorByteLength,
                    ),
                ],
                [
                    'Full-ring query cosets',
                    formatCount(setupRelation.fullRingQueryCosets),
                ],
                [
                    'Expanded statement polynomials',
                    formatCount(setupRelation.expandedStatementPolynomialCount),
                ],
                [
                    'Expanded statement header bytes',
                    formatCount(
                        setupRelation.expandedStatementHeaderByteLength,
                    ),
                ],
                [
                    'Expanded statement bytes',
                    formatCount(setupRelation.expandedStatementByteLength),
                ],
                [
                    'Maximum encoded queried-operator bytes',
                    formatCount(setupRelation.maximumEncodedOperatorByteLength),
                ],
                [
                    'Maximum exact integer limb-convolution magnitude',
                    formatCount(
                        setupRelation.maximumIntegerLimbConvolutionMagnitude,
                    ),
                ],
                [
                    'Synthetic witness header bytes',
                    formatCount(setupRelation.syntheticWitnessHeaderByteLength),
                ],
                [
                    'Synthetic witness bytes',
                    formatCount(setupRelation.syntheticWitnessByteLength),
                ],
            ],
        ),
        '',
        'The query-transform subtotal includes the coefficient and scratch vectors, one base-field twiddle table, and the queried output vector. It excludes input chunks, parser records, query-index groups, allocator behavior, stack, JavaScript, and the rest of proof verification. The experimental expanded statement repeats common matrices and recipient public keys in the verifier input; its length is not the contributor upload size. The encoded operator includes the statement digest, target, final row weight, and queried coefficients.',
        '',
        '## Exact RNS arithmetic census',
        '',
        "The recursive-context floor comes from the pinned library allocation structure. The alternative uses flat scalar transform plans and sufficiently wide auxiliary integer residues, then exact CRT lifting and rounding under the existing cryptographic modulus. The evaluation's working storage holds the transformed key records; scheduled ciphertexts remain a separate live-set cost.",
        '',
        table(
            ['Property', 'Value'],
            [
                ['Polynomial degree', formatCount(rnsArithmetic.degree)],
                [
                    'Base primes in the wrapper screen',
                    formatCount(rnsArithmetic.basePrimes),
                ],
                [
                    'Extended primes in the wrapper screen',
                    formatCount(rnsArithmetic.multiplicationPrimes),
                ],
                [
                    'Pinned library transform-table bytes per prime',
                    formatCount(rnsArithmetic.tableBytesPerPrime),
                ],
                [
                    'Recursive extended-context transform tables alone',
                    formatCount(rnsArithmetic.recursiveTableBytes),
                ],
                [
                    'Auxiliary primes for exact integer products',
                    formatCount(rnsArithmetic.exactProductPrimes),
                ],
                [
                    'Flat transform-plan table bytes per prime',
                    formatCount(rnsArithmetic.flatTableBytesPerPrime),
                ],
                [
                    'Flat transform-table bytes',
                    formatCount(rnsArithmetic.flatTableBytes),
                ],
                [
                    'Machine words per canonical cryptographic coefficient',
                    formatCount(rnsArithmetic.coefficientWords),
                ],
                [
                    'Canonical polynomial working bytes',
                    formatCount(rnsArithmetic.canonicalPolynomialBytes),
                ],
                [
                    "Stored records of a multiplication's keys",
                    formatCount(rnsArithmetic.multiplicationKeyRecordBytes),
                ],
            ],
        ),
        '',
        '## Common-agreement degree census',
        '',
        'The direct ordinary-IOP argument uses one common agreement set for every original, shifted, and virtual oracle. Individual proximity is insufficient. The candidate stays inside the proven unique-decoding FRI radius and requires more common points than the complete degree and rational-identity bounds.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Systematic domain size',
                    formatCount(commonAgreement.systematicSize),
                ],
                [
                    'Reed-Solomon code dimension',
                    formatCount(commonAgreement.codeDimension),
                ],
                [
                    'Evaluation domain size',
                    formatCount(commonAgreement.domainSize),
                ],
                [
                    'Distance numerator',
                    formatCount(commonAgreement.distanceNumerator),
                ],
                [
                    'Distance denominator',
                    formatCount(commonAgreement.distanceDenominator),
                ],
                [
                    'Minimum common agreement points',
                    formatCount(commonAgreement.minimumAgreementPoints),
                ],
                [
                    'Smallest declared degree in the shifted stack',
                    formatCount(commonAgreement.minimumDeclaredDegree),
                ],
                [
                    'Largest degree-shift identity degree',
                    formatCount(commonAgreement.maximumShiftIdentityDegree),
                ],
                [
                    'Largest relation-identity degree in the word profile',
                    formatCount(commonAgreement.maximumRelationIdentityDegree),
                ],
                [
                    'Independent query pairs',
                    formatCount(commonAgreement.queries),
                ],
                [
                    'Joint masking dimension',
                    formatCount(commonAgreement.maskDimension),
                ],
            ],
        ),
        '',
        '## Wide-challenge compiler census',
        '',
        'The current conditional ordinary round bound uses BCIKS20 Theorem 7.2 and Claim 8.5 with the reviewed consistency-weight state. At the displayed agreement threshold and rate, the proof-analysis parameter changes no verifier bytes. Each role separately compares exact-uniform query sampling against its density-adjusted maximum of the restricted lookup, affine and coalesced batching/weighted-fold terms. The underlying common-agreement, degree, masking and semantic correspondence premises remain explicit in the security argument; these arithmetic rows establish no end-to-end security level.',
        '',
        table(
            ['Weighted-fold operand', 'Value'],
            [
                [
                    'Proof-analysis parameter',
                    formatCount(
                        sampledRoundErrors.weightedFri.analysisParameter,
                    ),
                ],
                [
                    'Rate numerator',
                    formatCount(sampledRoundErrors.weightedFri.rateNumerator),
                ],
                [
                    'Rate denominator',
                    formatCount(sampledRoundErrors.weightedFri.rateDenominator),
                ],
                [
                    'Agreement numerator',
                    formatCount(
                        sampledRoundErrors.weightedFri.agreementNumerator,
                    ),
                ],
                [
                    'Agreement denominator',
                    formatCount(
                        sampledRoundErrors.weightedFri.agreementDenominator,
                    ),
                ],
                [
                    'Weighted-fold rational numerator',
                    formatCount(sampledRoundErrors.weightedFri.upper.numerator),
                ],
                [
                    'Weighted-fold rational denominator',
                    formatCount(
                        sampledRoundErrors.weightedFri.upper.denominator,
                    ),
                ],
                [
                    'Weighted-fold conservative integer numerator',
                    formatCount(sampledRoundErrors.weightedFri.ceiling),
                ],
            ],
        ),
        '',
        table(
            [
                'Role',
                'Original oracles',
                'Virtual oracles',
                'Lookup root degree',
                'Affine rows',
                'Complete message bytes',
                'Consumed base-field samples',
                'Query dominates sampled algebraic bound',
            ],
            sampledRoundErrors.roles.map((role) => [
                role.name,
                ...[
                    role.originalOracles,
                    role.virtualOracles,
                    role.lookupRootDegree,
                    role.affineRows,
                    role.messageBytes,
                    role.baseFieldSamples,
                ].map(formatCount),
                role.queryDominates ? 'Yes' : 'No',
            ]),
        ),
        '',
        'The [fixed proof-domain catalogue](../tests/proof-relation-catalogue-model.ts) independently derives the immutable four-purpose descriptors, original participant-identity role framing and complete context grammar. The [raw-domain and mixed-width graph model](../tests/proof-hash-domain-model.ts) keeps raw namespace membership separate from canonical context resolution, allows compatible profile aliases, and compares whole relation-sized prefixes of the maximum output word. Generic mutable relation descriptors remain excluded. These source-conformance and finite structural checks do not establish proof soundness, an honest-credential scope or an end-to-end security level.',
        '',
        table(
            ['Finite-family operand', 'Value'],
            [
                [
                    'Maximum raw input bits W_F',
                    formatCount(proofHashDomain.maximumInputBits),
                ],
                [
                    'Fixed hash-label sentinels b_F',
                    formatCount(proofHashDomain.sentinelCount),
                ],
                [
                    'Minimum complete verifier-message bits',
                    formatCount(proofHashDomain.minimumMessageBits),
                ],
                [
                    'Maximum complete verifier-message bits Lambda',
                    formatCount(proofHashDomain.maximumMessageBits),
                ],
                [
                    'Maximum accepted verifier expansion queries M_F',
                    formatCount(
                        proofHashDomain.maximumAcceptedExpansionQueries,
                    ),
                ],
            ],
        ),
        '',
        'W_F bounds complete raw inputs recognized by the fixed grammar, including full statements rather than their identifiers; it is expressed in bits for the conservative substring reference bound and does not bound arbitrary auxiliary oracle inputs. The only fixed hash-label sentinel is the zero initial-state label; absent or malformed predecessors resolve to no context or oracle entry. M_F reuses the source-linked shared-path Merkle and transcript expansion census. The finite-family expression still requires the complete prior oracle history and mapped reducer costs; these operands select no numerical security claim.',
        '',
        'The following prefix-compiler caps and exponents are historical role-union reference arithmetic. Its conservative algebraic numerator now includes the weighted folding term, but its finite corrupt-role population and whole-experiment composition are not established for clear preparation. The current finite-family argument takes a maximum of the per-role sampled-round bounds above without adding a family union factor. Reference exponents below do not select a new honest-credential scope or claim admission, end-to-end security, or phone qualification.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Field elements in the largest verifier message',
                    formatCount(wideChallengeCompiler.fieldElements),
                ],
                [
                    'Base-field samples in that message',
                    formatCount(wideChallengeCompiler.baseFieldSamples),
                ],
                [
                    'Complete verifier-message bytes',
                    formatCount(wideChallengeCompiler.challengeBytes),
                ],
                [
                    'Merkle and message-root tag bits',
                    formatCount(wideChallengeCompiler.tagBits),
                ],
                [
                    'Leaf and message salt bits',
                    formatCount(wideChallengeCompiler.saltBits),
                ],
                [
                    'Relative hash-balance exponent',
                    formatCount(wideChallengeCompiler.relativeBalanceBits),
                ],
                [
                    'Non-salt input bit-length bound',
                    formatCount(wideChallengeCompiler.maximumNonSaltInputBits),
                ],
                [
                    'Committed-node budget per proof',
                    formatCount(wideChallengeCompiler.committedNodeBudget),
                ],
                [
                    'Honest-proof budget',
                    formatCount(wideChallengeCompiler.honestProofBudget),
                ],
                [
                    'Conditional Merkle-privacy exponent over every honest proof',
                    formatCount(wideChallengeCompiler.merklePrivacyBits),
                ],
                [
                    'Programmed verifier-message budget',
                    formatCount(wideChallengeCompiler.programmedMessageBudget),
                ],
                [
                    'Conditional adaptive-reprogramming exponent',
                    formatCount(wideChallengeCompiler.reprogrammingBits),
                ],
                [
                    'Independent final query pairs',
                    formatCount(wideChallengeCompiler.queryCount),
                ],
                [
                    'Oracle-call cap of the experiment',
                    formatCount(wideChallengeCompiler.adversaryQueries),
                ],
                [
                    'Queries after prefix and role routing',
                    formatCount(wideChallengeCompiler.chargedQueries),
                ],
                [
                    'Accepted proof-role budget',
                    formatCount(wideChallengeCompiler.roleBudget),
                ],
                [
                    'Lookup entry count',
                    formatCount(wideChallengeCompiler.lookupEntryCount),
                ],
                [
                    'Lookup residual root-degree bound',
                    formatCount(wideChallengeCompiler.lookupRootDegree),
                ],
                [
                    'Lookup challenge-space size',
                    formatCount(wideChallengeCompiler.lookupChallengeSpace),
                ],
                [
                    'Affine residual root-degree bound',
                    formatCount(wideChallengeCompiler.affineRootDegree),
                ],
                [
                    'Correlated batching rows',
                    formatCount(wideChallengeCompiler.correlatedRowCount),
                ],
                [
                    'Batching and first-fold numerator',
                    formatCount(
                        wideChallengeCompiler.batchingAndFirstFoldNumerator,
                    ),
                ],
                [
                    'Uniform-field algebraic event numerator',
                    formatCount(
                        wideChallengeCompiler.ordinaryAlgebraicNumerator,
                    ),
                ],
                [
                    'Historical role-union QROM reference exponent',
                    formatCount(wideChallengeCompiler.failureBits),
                ],
            ],
        ),
        '',
        '## Proof compiler chronology',
        '',
        'Multi-roster population rows retain the historical all-confirmation divisor and are reference arithmetic only. Current local proof counts include every eligible offer, but the divisor does not bound clear-candidate exposure before certification and supplies no current credential scope or security claim.',
        '',
        'Proofs, programming points and commitments that one poll emits under the lifecycle rules owned by the security argument, against the caps the compiler charges. Every honest registration publishes a registration proof before any roster exists, including one no roster takes, so the largest honest credential population bounds them; each setup contributor adds at most one contribution proof and each participant at most one ballot and release proof, because those purposes occupy one-shot slots. A restored participant replays identical bytes and one that loses unfinished work stops. At that population a corrupt organizer can split the honest registrations into as many rosters of one participant count as their honest members allow: each honest registration confirms at most one, and a roster with at most `f` corrupt members holds `n-f` honest ones. The direct simulator programs one verifier message per simulated proof, and accepted proof roles are the registrations and proving positions of those rosters. Committed nodes count every leaf and internal node of every tree and every salted message root. The non-salt input is the widest salted leaf or message-root input without its salt, over every proof role; each cell is the range over the option counts of one participant count.',
        '',
        table(
            [
                'Participants',
                'Honest proofs, one registration per participant',
                'Rosters at the largest credential population',
                'Honest proofs at that population',
                'Accepted proof roles at that population',
                'Programmed verifier messages at that population',
                'Committed nodes per proof',
                'Widest non-salt input bits',
            ],
            supportedProfiles.profiles.map((row) => {
                const chronologies = row.map((profile) =>
                    compileProofCompilerChronology(
                        profile,
                        securityLedger.maximumCredentialPopulation,
                        securityLedger.maximumRosterCount,
                    ),
                );
                const [first] = chronologies;
                if (!chronologies.every((value) => value.withinCaps))
                    throw new Error(
                        'A supported profile exceeds a charged compiler cap.',
                    );
                return [
                    formatCount(row[0].participantCount),
                    formatCount(
                        compileProofCompilerChronology(row[0]).honestProofs,
                    ),
                    formatCount(first.rosters),
                    formatCount(first.honestProofs),
                    formatCount(first.acceptedRoles),
                    formatCount(first.programmedMessages),
                    rangeOf(
                        chronologies.map(
                            (value) => value.committedNodesPerProof,
                        ),
                    ),
                    rangeOf(
                        chronologies.map(
                            (value) => value.widestNonSaltInputBits,
                        ),
                    ),
                ];
            }),
        ),
        '',
        '## Full word-proof encoding census',
        '',
        'The emitted full-size prototype retains the complete verification domain. The smaller prover interpolation set is an honest-computation optimization justified by the degree bound, not a verifier relaxation. Canonical incremental Merkle multiproofs authenticate each leaf against the first previously verified subtree and omit already known path hashes. Cache payload counts exclude map/allocation overhead, which requires measurement.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'FRI folds to the terminal constant',
                    formatCount(fullWordProof.foldCount),
                ],
                [
                    'Fixed proof header bytes',
                    formatCount(fullWordProof.headerBytes),
                ],
                [
                    'First-oracle leaf payload bytes',
                    formatCount(fullWordProof.firstWidth),
                ],
                [
                    'Second-oracle leaf payload bytes',
                    formatCount(fullWordProof.secondWidth),
                ],
                [
                    'Maximum proof bytes with independent paths',
                    formatCount(fullWordProof.maximumProofBytes),
                ],
                [
                    'Maximum proof bytes with incremental multiproofs',
                    formatCount(fullWordProof.maximumMultiproofBytes),
                ],
                [
                    'Maximum cached node-digest bytes',
                    formatCount(fullWordProof.maximumCachedNodeDigestBytes),
                ],
                [
                    'Prover combination interpolation points',
                    formatCount(fullWordProof.proverInterpolationPoints),
                ],
                [
                    'Expanded first-oracle bytes hashed',
                    formatCount(fullWordProof.expandedFirstOracleBytes),
                ],
                [
                    'Expanded second-oracle bytes hashed',
                    formatCount(fullWordProof.expandedSecondOracleBytes),
                ],
                [
                    'Retained leaf-salt seed bytes',
                    formatCount(fullWordProof.saltSeedBytes),
                ],
                [
                    'Uniform prover-mask bytes',
                    formatCount(fullWordProof.proverMaskBytes),
                ],
            ],
        ),
        '',
        '## Browser word-prover resource census',
        '',
        'The browser experiment streams public inputs, retains their prepared common-polynomial adjoints until the affine pass, and emits one proof record at a time. These conservative allocation allowances describe the experimental live-data schedule. They are not measurements of browser-private memory, authenticated checkpoints, a complete action, or phone qualification.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Full-degree common-polynomial adjoints',
                    formatCount(browserWordProver.fullDegreeCommonPolynomials),
                ],
                [
                    'Prepared adjoint bytes',
                    formatCount(browserWordProver.preparedAdjointBytes),
                ],
                [
                    'Enforced maximum bytes per opaque hasher',
                    formatCount(browserWordProver.maximumHasherBytes),
                ],
                [
                    'Metadata and allocator allowance bytes',
                    formatCount(
                        browserWordProver.metadataAndAllocatorAllowance,
                    ),
                ],
                ...browserWordProver.stages.map((stage) => [
                    `Allocation allowance: ${stage.stage}`,
                    formatCount(stage.bytes),
                ]),
            ],
        ),
        '',
        '## Contribution generation and sampling census',
        '',
        'The combined browser path keeps witness columns inside Rust, regenerates fixed common polynomials, and retains the remaining public statement and proof as bounded local blobs. Allocation allowances require measured closure. The sampling rows describe one completed roster whose original poll maximum equals its displayed size: every enrolled participant samples its recipient error and every source family, then the complete eligible pool reuses each original first error while sampling its remaining contribution errors. A different original maximum is an explicit model operand. The sampling bound charges finite-word quantization and the omitted Gaussian tails for that local corpus; it does not bound abandoned credentials or establish lattice or composed-protocol security.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Gaussian density parameter numerator',
                    formatCount(setupGaussianParameters.sigmaNumerator),
                ],
                [
                    'Gaussian density parameter denominator',
                    formatCount(setupGaussianParameters.sigmaDenominator),
                ],
                [
                    'Gaussian sample bits',
                    formatCount(setupGaussianParameters.sampleBits),
                ],
                [
                    'Encoded nonterminal cumulative thresholds',
                    formatCount(setupRandomness.thresholdCount),
                ],
                [
                    'Cumulative table bytes',
                    formatCount(setupRandomness.encodedThresholdBytes),
                ],
                [
                    'Fresh error samples per contribution operation',
                    formatCount(setupRandomness.samplesPerContribution),
                ],
                [
                    'Original poll maximum for these sampling rows',
                    formatCount(
                        setupRandomness.originalPollMaximumParticipants,
                    ),
                ],
                [
                    'Source families per enrollment',
                    formatCount(setupRandomness.sourceFamilyCount),
                ],
                [
                    'Error samples per original source family',
                    formatCount(setupRandomness.samplesPerSourceFamily),
                ],
                [
                    'Recipient and source error samples per enrollment',
                    formatCount(setupRandomness.samplesPerEnrollment),
                ],
                [
                    'Error samples across preparation and registration',
                    formatCount(setupRandomness.samplesPerPreparation),
                ],
                [
                    'Gaussian uniform sample bytes per contribution operation',
                    formatCount(setupRandomness.contributionSampleBytes),
                ],
                [
                    'Preparation sampling-distance exponent',
                    formatCount(setupRandomness.preparationSamplingBits),
                ],
                [
                    'Witness-generation allocation allowance bytes',
                    formatCount(contributionGeneration.generationAllowance),
                ],
                [
                    'Combined allocation allowance bytes',
                    formatCount(contributionGeneration.combinedAllowance),
                ],
                [
                    'Retained verified-roster payload bytes',
                    formatCount(
                        contributionGeneration.retainedRosterPayloadBytes,
                    ),
                ],
                [
                    'Additional roster input-buffer bytes',
                    formatCount(
                        contributionGeneration.additionalInputBufferBytes,
                    ),
                ],
                [
                    'Public coefficient allocation allowance bytes',
                    formatCount(
                        contributionGeneration.publicCoefficientAllowance,
                    ),
                ],
                [
                    'Expanded public working bytes',
                    formatCount(
                        contributionGeneration.expandedPublicWorkingBytes,
                    ),
                ],
                [
                    'Regenerated common-polynomial bytes',
                    formatCount(contributionGeneration.regeneratedCommonBytes),
                ],
                [
                    'Reused verified recipient-key bytes',
                    formatCount(contributionGeneration.reusedRecipientBytes),
                ],
                [
                    'Retained public working bytes',
                    formatCount(contributionGeneration.publicWorkingBytes),
                ],
                [
                    'Maximum public emission batch bytes',
                    formatCount(
                        contributionGeneration.maximumPublicEmissionBatch,
                    ),
                ],
            ],
        ),
        '',
        '## Registration key relation census',
        '',
        'The recipient-key relation binds the original balanced sparse secret to its fixed-suite common polynomial and public key. It uses distinct statement/proof domains and the same full verification domain as the contribution proof. The bounds below cover both radix equations and the exact support rows; key ownership, signatures, private-state sealing, and whole-protocol security remain separate obligations.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Polynomial degree', formatCount(registrationKey.degree)],
                ['Ciphertext modulus', formatCount(registrationKey.modulus)],
                ['Secret support', formatCount(registrationKey.support)],
                ['Word columns', formatCount(registrationKey.wordColumns)],
                [
                    'Boolean columns',
                    formatCount(registrationKey.booleanColumns),
                ],
                ['Lookup memberships', formatCount(registrationKey.lookups)],
                ['Affine rows', formatCount(registrationKey.affineRows)],
                [
                    'Original oracles',
                    formatCount(registrationKey.originalOracles),
                ],
                [
                    'Virtual constraint oracles',
                    formatCount(registrationKey.virtualOracles),
                ],
                [
                    'Honest quotient magnitude bound',
                    formatCount(registrationKey.honestQuotient),
                ],
                [
                    'Honest carry magnitude bound',
                    formatCount(registrationKey.honestCarry),
                ],
                [
                    'Maximum accepted integer limb residual magnitude',
                    formatCount(registrationKey.maximumLimbResidual),
                ],
                [
                    'Canonical public-key bytes',
                    formatCount(registrationKey.publicKeyBytes),
                ],
                [
                    'Expanded statement bytes',
                    formatCount(registrationKey.statementBytes),
                ],
                [
                    'First-oracle leaf bytes',
                    formatCount(registrationKey.firstLeafBytes),
                ],
                [
                    'Second-oracle leaf bytes',
                    formatCount(registrationKey.secondLeafBytes),
                ],
                [
                    'Proof header bytes',
                    formatCount(registrationKey.proofHeaderBytes),
                ],
                [
                    'Maximum encoded proof bytes',
                    formatCount(registrationKey.maximumProofBytes),
                ],
                [
                    'Maximum public coefficient query bytes',
                    formatCount(registrationKey.maximumCoefficientQueryBytes),
                ],
            ],
        ),
        '',
        '## Registration custody census',
        '',
        'This completed-key capsule retains sorted secret positions and a bounded encrypted manifest over every staged public record. Payload totals exclude IndexedDB metadata and the browser-managed CryptoKey representation. The AES block and hash-polynomial counts describe this fixed sealing schedule; they do not establish a primitive-security bound or general checkpoint protocol.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Secret index bytes',
                    formatCount(registrationCustody.indexBytes),
                ],
                [
                    'Private capsule plaintext bytes',
                    formatCount(registrationCustody.secretPlaintextBytes),
                ],
                [
                    'Encrypted capsule bytes',
                    formatCount(registrationCustody.capsuleBytes),
                ],
                [
                    'Maximum retained data records',
                    formatCount(registrationCustody.recordCount),
                ],
                [
                    'Manifest prefix bytes',
                    formatCount(registrationCustody.manifestPrefixBytes),
                ],
                [
                    'Record reference bytes',
                    formatCount(registrationCustody.recordReferenceBytes),
                ],
                [
                    'Maximum manifest plaintext bytes',
                    formatCount(registrationCustody.maximumManifestBytes),
                ],
                [
                    'Maximum encrypted root bytes',
                    formatCount(registrationCustody.maximumRootBytes),
                ],
                [
                    'Maximum root associated-data bytes',
                    formatCount(registrationCustody.maximumRootAssociatedBytes),
                ],
                [
                    'Maximum capsule associated-data bytes',
                    formatCount(
                        registrationCustody.maximumCapsuleAssociatedBytes,
                    ),
                ],
                [
                    'Maximum restoration input bytes',
                    formatCount(registrationCustody.maximumRestoreInputBytes),
                ],
                [
                    'Maximum retained payload bytes',
                    formatCount(registrationCustody.retainedPayloadBytes),
                ],
                [
                    'Capsule seal invocations',
                    formatCount(registrationCustody.capsuleSealInvocations),
                ],
                [
                    'Root seal invocations',
                    formatCount(registrationCustody.rootSealInvocations),
                ],
                [
                    'Distinct capsule AES block inputs',
                    formatCount(registrationCustody.capsuleDistinctBlockInputs),
                ],
                [
                    'Distinct root AES block inputs',
                    formatCount(registrationCustody.rootDistinctBlockInputs),
                ],
                [
                    'Maximum capsule authentication polynomial degree',
                    formatCount(registrationCustody.maximumCapsuleHashDegree),
                ],
                [
                    'Maximum root authentication polynomial degree',
                    formatCount(registrationCustody.maximumRootHashDegree),
                ],
            ],
        ),
        '',
        '## Registration enrollment census',
        '',
        'The combined enrollment record binds a canonical public username, actual credentials, and the complete recipient-key proof. Separate data keys seal the original recipient key and signing seed; the encrypted local root retains those keys and references every record. From the roster transition on, the root also references the retained roster and the retained registration, each keyed to the credential. Payload counts exclude database metadata and browser-managed root-key storage.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Signing public-key bytes',
                    formatCount(registrationEnrollment.signingPublicKeyBytes),
                ],
                [
                    'Signature bytes',
                    formatCount(registrationEnrollment.signatureBytes),
                ],
                [
                    'Maximum canonical username bytes',
                    formatCount(registrationEnrollment.maximumUsernameBytes),
                ],
                [
                    'Maximum poll-definition bytes',
                    formatCount(
                        registrationEnrollment.maximumPollDefinitionBytes,
                    ),
                ],
                [
                    'Poll-definition framing bytes',
                    formatCount(
                        registrationEnrollment.pollDefinitionOverheadBytes,
                    ),
                ],
                [
                    'Maximum creator input bytes',
                    formatCount(
                        registrationEnrollment.maximumCreatorInputBytes,
                    ),
                ],
                [
                    'Maximum join input bytes',
                    formatCount(registrationEnrollment.maximumJoinInputBytes),
                ],
                [
                    'Maximum username ingress bytes',
                    formatCount(
                        registrationEnrollment.maximumUsernameIngressBytes,
                    ),
                ],
                [
                    'Maximum encoded header bytes',
                    formatCount(registrationEnrollment.maximumHeaderBytes),
                ],
                [
                    'Maximum header input bytes',
                    formatCount(registrationEnrollment.maximumHeaderInputBytes),
                ],
                [
                    'Proof-role bytes',
                    formatCount(registrationEnrollment.proofRoleBytes),
                ],
                [
                    'Recipient-key capsule bytes',
                    formatCount(registrationEnrollment.recipientCapsuleBytes),
                ],
                [
                    'Signing-seed capsule bytes',
                    formatCount(registrationEnrollment.signingCapsuleBytes),
                ],
                [
                    'Maximum enrollment records before proposal signing',
                    formatCount(
                        registrationEnrollment.maximumEnrollmentRecords,
                    ),
                ],
                [
                    'Maximum retained records',
                    formatCount(registrationEnrollment.maximumRecords),
                ],
                [
                    'Manifest prefix bytes',
                    formatCount(registrationEnrollment.manifestPrefixBytes),
                ],
                [
                    'Maximum completed-enrollment manifest plaintext bytes',
                    formatCount(
                        registrationEnrollment.maximumEnrollmentManifestBytes,
                    ),
                ],
                [
                    'Maximum locked-proposal manifest plaintext bytes',
                    formatCount(
                        registrationEnrollment.maximumProposalIntentManifestBytes,
                    ),
                ],
                [
                    'Maximum manifest plaintext bytes',
                    formatCount(registrationEnrollment.maximumManifestBytes),
                ],
                [
                    'Maximum encrypted root bytes',
                    formatCount(registrationEnrollment.maximumRootBytes),
                ],
                [
                    'Maximum retained roster bytes',
                    formatCount(
                        registrationEnrollment.maximumRetainedRosterBytes,
                    ),
                ],
                [
                    'Retained registration bytes',
                    formatCount(
                        registrationEnrollment.retainedRegistrationBytes,
                    ),
                ],
                [
                    'Recipient capsule associated-data bytes',
                    formatCount(
                        registrationEnrollment.recipientAssociatedBytes,
                    ),
                ],
                [
                    'Signing capsule associated-data bytes',
                    formatCount(registrationEnrollment.signingAssociatedBytes),
                ],
                [
                    'Root associated-data bytes',
                    formatCount(registrationEnrollment.rootAssociatedBytes),
                ],
                [
                    'Maximum restoration input bytes',
                    formatCount(
                        registrationEnrollment.maximumRestoreInputBytes,
                    ),
                ],
                [
                    'Maximum retained payload bytes',
                    formatCount(
                        registrationEnrollment.maximumRetainedPayloadBytes,
                    ),
                ],
                [
                    'Distinct initial root-key AES block inputs',
                    formatCount(
                        registrationEnrollment.initialRootDistinctBlockInputs,
                    ),
                ],
                [
                    'Maximum distinct AES block inputs per proposal root key',
                    formatCount(registrationEnrollment.rootDistinctBlockInputs),
                ],
                [
                    'Distinct signing-capsule AES block inputs',
                    formatCount(
                        registrationEnrollment.signingDistinctBlockInputs,
                    ),
                ],
            ],
        ),
        '',
        '## Hash-row checkpoint census',
        '',
        'The bounded experiment serializes one live proof-row hash array and seals it in ordered chunks. These counts cover one array and one data key; they exclude the remaining prover state, authenticated root, database overhead, key wrapping, repeated checkpoints, retries, and session unions. The primitive-input and authentication-degree operands are not an end-to-end security bound.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Proof-domain rows', formatCount(hashRowCheckpoint.rowCount)],
                [
                    'Serialized hash-state bytes per row',
                    formatCount(hashRowCheckpoint.serializedStateBytes),
                ],
                ['Rows per chunk', formatCount(hashRowCheckpoint.rowsPerChunk)],
                ['Encrypted chunks', formatCount(hashRowCheckpoint.chunkCount)],
                [
                    'Maximum chunk plaintext bytes',
                    formatCount(hashRowCheckpoint.maximumPlaintextChunkBytes),
                ],
                [
                    'Maximum sealed chunk bytes',
                    formatCount(hashRowCheckpoint.maximumSealedChunkBytes),
                ],
                [
                    'Complete plaintext bytes',
                    formatCount(hashRowCheckpoint.plaintextBytes),
                ],
                [
                    'Complete sealed bytes',
                    formatCount(hashRowCheckpoint.sealedBytes),
                ],
                [
                    'Associated-data bytes per chunk',
                    formatCount(hashRowCheckpoint.associatedBytes),
                ],
                [
                    'Distinct AES block inputs per array key',
                    formatCount(hashRowCheckpoint.distinctAesBlockInputs),
                ],
                [
                    'Maximum authentication polynomial degree',
                    formatCount(
                        hashRowCheckpoint.maximumAuthenticationPolynomialDegree,
                    ),
                ],
            ],
        ),
        '',
        '## First-oracle checkpoint census',
        '',
        'The complete first-oracle checkpoint retains the actual witness, masks, leaf-salt seed, and partial row hashes. Lookup multiplicities, empty tree nodes, and the initial transcript are reconstructed. Each private record uses a separate data key. The browser root also retains encrypted generated public inputs; fixed common polynomials and verified recipient keys are reconstructed from predecessors. Counts exclude database overhead and later proof phases, repeated checkpoints, and their security and resource unions.',
        '',
        table(
            ['Private field', 'Plaintext bytes', 'Encrypted records'],
            firstOracleCheckpoint.fields.map((field) => [
                field.name,
                formatCount(field.plaintextBytes),
                formatCount(field.recordCount),
            ]),
        ),
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Private encrypted records',
                    formatCount(firstOracleCheckpoint.recordCount),
                ],
                [
                    'Private checkpoint plaintext bytes',
                    formatCount(firstOracleCheckpoint.plaintextBytes),
                ],
                [
                    'Private checkpoint ciphertext bytes',
                    formatCount(firstOracleCheckpoint.ciphertextBytes),
                ],
                [
                    'Private record key bytes',
                    formatCount(firstOracleCheckpoint.dataKeyBytes),
                ],
                [
                    'Private record hash bytes',
                    formatCount(firstOracleCheckpoint.recordHashBytes),
                ],
                [
                    'Maximum private plaintext record bytes',
                    formatCount(
                        firstOracleCheckpoint.maximumPlaintextRecordBytes,
                    ),
                ],
                [
                    'Maximum private ciphertext record bytes',
                    formatCount(
                        firstOracleCheckpoint.maximumCiphertextRecordBytes,
                    ),
                ],
                [
                    'Checkpoint header bytes for the protocol role',
                    formatCount(firstOracleCheckpoint.headerBytes),
                ],
                [
                    'Checkpoint import bytes including routing context',
                    formatCount(firstOracleCheckpoint.importBytes),
                ],
                [
                    'Header digest input bytes including fixed domain',
                    formatCount(firstOracleCheckpoint.headerDigestInputBytes),
                ],
                [
                    'Header digest permutations per record',
                    formatCount(firstOracleCheckpoint.headerDigestPermutations),
                ],
                [
                    'Header digest permutations per complete seal or import pass',
                    formatCount(
                        firstOracleCheckpoint.headerDigestPermutationsPerPass,
                    ),
                ],
                [
                    'Maximum checkpoint header bytes',
                    formatCount(firstOracleCheckpoint.maximumHeaderBytes),
                ],
                [
                    'Encrypted public-input records',
                    formatCount(firstOracleCheckpoint.publicRecordCount),
                ],
                [
                    'Public-input plaintext bytes',
                    formatCount(firstOracleCheckpoint.publicPlaintextBytes),
                ],
                [
                    'Public-input ciphertext bytes',
                    formatCount(firstOracleCheckpoint.publicCiphertextBytes),
                ],
                [
                    'Maximum browser root plaintext bytes',
                    formatCount(
                        firstOracleCheckpoint.maximumRootPlaintextBytes,
                    ),
                ],
                [
                    'Maximum retained checkpoint payload bytes',
                    formatCount(
                        firstOracleCheckpoint.maximumRetainedPayloadBytes,
                    ),
                ],
            ],
        ),
        '',
        '## Selected opening transform census',
        '',
        'The forward transform follows only branches needed by the public opening indices. Bounds allow all selected indices to occupy one coset and count additions, subtractions, and scalar multiplications separately by the same branch ceiling. The full coefficient buffer, inverse transform, coset preparation, existing proof records, allocator overhead, and tree data remain additional. Index pairs use the scalar WebAssembly word width.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Transform length',
                    formatCount(selectedOpeningTransform.transformLength),
                ],
                [
                    'Maximum selected outputs in one coset',
                    formatCount(selectedOpeningTransform.maximumSelected),
                ],
                [
                    'Transform levels',
                    formatCount(selectedOpeningTransform.levels),
                ],
                [
                    'Full forward butterflies',
                    formatCount(selectedOpeningTransform.fullButterflies),
                ],
                [
                    'Maximum selected operations of each butterfly kind',
                    formatCount(
                        selectedOpeningTransform.maximumSelectedBranches,
                    ),
                ],
                [
                    'Maximum live selection-pair bytes',
                    formatCount(
                        selectedOpeningTransform.maximumSelectionPairBytes,
                    ),
                ],
                [
                    'Maximum selection-index bytes',
                    formatCount(
                        selectedOpeningTransform.maximumSelectionIndexBytes,
                    ),
                ],
                [
                    'Maximum selected base-output bytes',
                    formatCount(
                        selectedOpeningTransform.maximumSelectedBaseOutputBytes,
                    ),
                ],
                [
                    'Maximum selected extension-output bytes',
                    formatCount(
                        selectedOpeningTransform.maximumSelectedExtensionOutputBytes,
                    ),
                ],
            ],
        ),
        '',
        '## Contribution body census',
        '',
        'The active profile frames one complete contribution as a fixed header, its owned public polynomials in the compiled statement order, and its complete proof. Fixed common inputs, the statement header, and previously verified recipient keys are reconstructed from predecessors. The body is a virtual concatenation of bounded records; these payload counts do not allocate another whole-body copy or include checkpoint, database or signature overhead.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Participants',
                    formatCount(contributionBody.participantCount),
                ],
                [
                    'Owned public polynomials',
                    formatCount(contributionBody.polynomials.length),
                ],
                [
                    'Body header bytes',
                    formatCount(contributionBody.headerBytes),
                ],
                [
                    'Owned polynomial payload bytes',
                    formatCount(contributionBody.polynomialPayloadBytes),
                ],
                [
                    'Minimum proof framing bytes',
                    formatCount(contributionBody.minimumProofBytes),
                ],
                [
                    'Maximum proof bytes',
                    formatCount(contributionBody.maximumProofBytes),
                ],
                [
                    'Maximum complete body bytes',
                    formatCount(contributionBody.maximumBodyBytes),
                ],
                [
                    'Registered-coordinate opening salt bytes inside SCB2',
                    formatCount(contributionBody.sourceOpeningSaltBytes),
                ],
                [
                    'Ordinary body hash-prefix bytes',
                    formatCount(contributionBody.hashPrefixBytes),
                ],
                [
                    'Minimum ordinary body hash-input bytes',
                    formatCount(contributionBody.minimumHashInputBytes),
                ],
                [
                    'Maximum ordinary body hash-input bytes',
                    formatCount(contributionBody.maximumHashInputBytes),
                ],
                [
                    'Minimum input enclosing bit exponent',
                    formatCount(
                        contributionBody.minimumHashInputEnclosingBitExponent,
                    ),
                ],
                [
                    'Maximum input enclosing bit exponent',
                    formatCount(
                        contributionBody.maximumHashInputEnclosingBitExponent,
                    ),
                ],
                [
                    'Maximum eligible-offer body payload bytes',
                    formatCount(contributionBody.maximumEligibleOfferBodies),
                ],
            ],
        ),
        '',
        '## Preparation selection and registration binding screen',
        '',
        'The [selection model](../tests/setup-selection-model.ts) checks the fixed eligible pool, selected subset and quorum intersection. Its close-only counterexample keeps a valid ballot under one setup, enough honest pre-close holders and a closing quorum for another setup: the ciphertext cannot be retargeted. The [candidate analysis](collective-preparation-analysis.md#registration-bound-clear-preparation) owns that failure and the pre-ballot certification repair. These counts do not establish a construction or its security loss.',
        '',
        table(
            [
                'Participants',
                'Eligible',
                'Selected',
                'Quorum',
                'Minimum honest selected',
                'Minimum quorum intersection',
                'Possible selected sets',
            ],
            [3, 10, 20].map((participants) => {
                const value = compileSetupSelectionCensus(participants);
                return [
                    participants,
                    value.eligibleCount,
                    value.selectedCount,
                    value.quorum,
                    value.minimumHonestSelected,
                    value.minimumCertificateIntersection,
                    value.possibleSelectedSets,
                ].map(formatCount);
            }),
        ),
        '',
        'Candidate productive-stage upper bounds include registration, setup, an optional ballot and the existing close/target/release/outcome suffix. Same-stage restarts, status checks and organizer collection sessions add no nodes. The paths require the local coalescences in the [visit owner](non-forking-state.md#preparation-candidate-stage-paths), complete retained payload availability and no additional participant-dependent output. They are conditional stage graphs, not emitted workflow measurements or a security verdict. Nonvoters may still perform setup before a later close request and therefore share this conservative bound.',
        '',
        table(
            ['Candidate path', 'Participant stages', 'Organizer stages'],
            (
                [
                    'clear-close-only',
                    'clear-certified',
                    'recoverable-sealed',
                ] as const
            ).map((candidate) => [
                candidate,
                formatCount(
                    countStagePath(preparationStagePath(candidate, false)),
                ),
                formatCount(
                    countStagePath(preparationStagePath(candidate, true)),
                ),
            ]),
        ),
        '',
        'The [registration binding screen](../tests/registration-setup-binding-model.ts) commits separately to each possible FHE encryption-key coordinate. It derives distinct FHE families from both modulus and common-matrix sample width for every roster the poll permits. Only the final roster entry opens; seeds are independent across families. Generated bytes count all candidate coordinates hashed during registration, not their simultaneous residency or upload. Digest and private seed/salt figures are payload subtotals excluding canonical framing, signatures, custody, work and restart amplification. The auxiliary pair is fixed public input with no real participant secret; its separate good-key phase bound is used only in the [candidate proof games](security-argument.md#registration-bound-clear-preparation-argument). This does not change the existing parameter table or prove the changed simulator.',
        '',
        table(
            [
                'Maximum participants / options',
                'FHE families',
                'Commitment digest payload bytes',
                'Private seed and salt payload bytes',
                'Generated public coordinate bytes',
                'Largest public coordinate bytes',
                'Weakest FHE uniform-matrix uniqueness exponent',
                'Fixed auxiliary public pair bytes',
                'Auxiliary good-key phase error bound',
                'Auxiliary scale',
            ],
            [
                [3, 2],
                [10, 10],
                [20, 20],
            ].map(([participants, options]) => {
                const screen = compileRegistrationSetupBindingScreen(
                    participants,
                    options,
                );
                const weakest = screen.fhe.reduce(
                    (minimum, family) =>
                        family.uniqueness.uniformMatrixFailureExponent < minimum
                            ? family.uniqueness.uniformMatrixFailureExponent
                            : minimum,
                    screen.fhe[0].uniqueness.uniformMatrixFailureExponent,
                );
                return [
                    `${participants} / ${options}`,
                    formatCount(screen.fhe.length),
                    formatCount(screen.commitmentDigestPayloadBytes),
                    formatCount(screen.privateSeedAndSaltPayloadBytes),
                    formatCount(screen.generatedPublicCoordinateBytes),
                    formatCount(screen.largestPublicCoordinateBytes),
                    formatCount(weakest),
                    formatCount(screen.auxiliary.fixedPublicPairBytes),
                    formatCount(screen.auxiliary.goodKeyPhaseError),
                    formatCount(screen.auxiliary.scale),
                ];
            }),
        ),
        '',
        'The FHE uniqueness exponents apply to independently uniform common polynomials and all bounded public keys, using the existing determinant lemma with the current ternary and error supports. The auxiliary good-key bound is `(2*h_aux+1)*E`, and twice this value must be strictly below its scale. Fixed-suite sampling and initialization, all distinct matrices, global auxiliary-key reuse, commitment extraction/equivocation, adaptive selection, proof soundness and the complete global credential population still require their separate charges. These exponents are not end-to-end security bits.',
        '',
        '### FHE key source generation screen',
        '',
        'The [source screen model](../tests/fhe-key-source-resource-model.ts) counts one full-ring original source and its reconstruction into the first contribution gadget. It retains a fixed synthetic seed, public digest and bounded samples between phases; no complete public coordinate or private source survives the phase transition. The source phase includes its retained sparse/error vectors, temporary sparse transform, first-key word columns, public/native-check working vectors and allocation allowance. Continuation conservatively reuses the existing complete contribution-generation allowance plus the retained first-key error. The separate reference phase uses direct sparse BigInt convolution at fixed coordinates. These are phase planning allowances, not measured peaks, a complete registration or a proof-generation bound.',
        '',
        table(
            ['Source-screen property', 'Value'],
            (() => {
                const screen = compileFheKeySourceScreenResources();
                return [
                    ['Participants', screen.participantCount],
                    ['Options', screen.optionCount],
                    ['Ring degree', screen.degree],
                    [
                        'Signed public coefficient bytes',
                        screen.coefficientBytes,
                    ],
                    ['Common coefficient sample bits', screen.commonSampleBits],
                    [
                        'Independent coordinate samples',
                        screen.samplePositions.length,
                    ],
                    ['Canonical FKS1 report bytes', screen.reportBytes],
                    ['Output capacity bytes', screen.outputCapacity],
                    [
                        'Original private source payload bytes',
                        screen.sourcePayloadBytes,
                    ],
                    [
                        'First-key word-column payload bytes',
                        screen.keyWitnessBytes,
                    ],
                    [
                        'Source generation phase allowance bytes',
                        screen.sourcePhaseBytes,
                    ],
                    [
                        'First-gadget continuation phase allowance bytes',
                        screen.continuationPhaseBytes,
                    ],
                    [
                        'Independent reference phase allowance bytes',
                        screen.referencePhaseBytes,
                    ],
                    [
                        'Native operation planning bytes',
                        screen.nativePlanningBytes,
                    ],
                    [
                        'Scalar operation planning bytes',
                        screen.scalarPlanningBytes,
                    ],
                ].map(([label, value]) => [
                    String(label),
                    formatCount(value as number | bigint),
                ]);
            })(),
        ),
        '',
        '## Recoverable setup resource screen',
        '',
        'Existing-format arithmetic for the [recoverable sealed preparation candidate](security-argument.md#recoverable-sealed-preparation-candidate), computed by the independent [resource model](../tests/recoverable-setup-resource-model.ts). The eligible pool is `k=d+f` and the selected subset is `s=d=max(f+1,2)`. One existing inner contribution body has bound `B` from the contribution-body model, including its existing proof. Thus `kB` bounds the unchanged inner-body bytes of all eligible offers, while `sB` bounds only the selected inner bodies. Selected reads never remove unselected offers from the uploaded corpus.',
        '',
        'The candidate encrypts each opening-seed evaluation as two polynomials in the original registered-recipient ring. Its raw ciphertext subtotal is `k*n*2*N*w`, where `N` and the signed coefficient width `w` come from the registration-key relation and modulus. This is distinct from the smaller fixed auxiliary ring used by ballots, which contributes no inner setup-body polynomial. Outer proofs and the public opening-share batch projection are counted separately below. One opening batch carries the public integer shares of every selected package and one proof under its recipient key; the corpus screen counts one batch from every roster participant. The original common polynomial, registered key and source ciphertexts are predecessors, never counted again as new opening uploads. These figures bound only the named components, not a final candidate package; they are not a lower bound or an impossibility result. They exclude new sealed-body length and padding framing, opening-statement headers, package and opening signatures and metadata, ECHO/READY carriers, registrations, ballots, result release, storage amplification, transfers and execution work. Any changed inner proof or parameter invalidates the reuse of `B`; full correctness, security and resource derivation remain open.',
        '',
        table(
            ['Completion-profile operand', 'Value'],
            [
                [
                    'Participants',
                    formatCount(recoverableSetup.participantCount),
                ],
                ['Options', formatCount(recoverableSetup.optionCount)],
                [
                    'Fault bound for each budget',
                    formatCount(recoverableSetup.maximumFaultCount),
                ],
                [
                    'Eligible contributor pool',
                    formatCount(recoverableSetup.eligibleContributorCount),
                ],
                [
                    'Selected contributions',
                    formatCount(recoverableSetup.selectedContributorCount),
                ],
                ['ECHO threshold', formatCount(recoverableSetup.echoThreshold)],
                [
                    'READY relay threshold',
                    formatCount(recoverableSetup.readyRelayThreshold),
                ],
                [
                    'READY delivery threshold',
                    formatCount(recoverableSetup.readyDeliveryThreshold),
                ],
                [
                    'Seed-share polynomial degree',
                    formatCount(recoverableSetup.seedSharePolynomialDegree),
                ],
                [
                    'Seed-share encoded coefficient bytes',
                    formatCount(recoverableSetup.seedShareCoefficientBytes),
                ],
                [
                    'Raw ciphertext bytes per recipient',
                    formatCount(recoverableSetup.seedShareCiphertextBytes),
                ],
                [
                    'Seed-share ciphertexts per offer',
                    formatCount(recoverableSetup.seedShareCiphertextsPerOffer),
                ],
                [
                    'Eligible-pool seed-share ciphertext count',
                    formatCount(
                        recoverableSetup.eligibleSeedShareCiphertextCount,
                    ),
                ],
                [
                    'Selected seed-share ciphertext count',
                    formatCount(
                        recoverableSetup.selectedSeedShareCiphertextCount,
                    ),
                ],
                [
                    'Profiles screened',
                    formatCount(recoverableSetupProfiles.length),
                ],
            ],
        ),
        '',
        table(
            [
                'Candidate component subtotal in bytes',
                'Completion profile',
                'Minimum and first attaining profile',
                'Maximum and first attaining profile',
            ],
            (
                [
                    ['One inner body bound', 'maximumInnerBodyBytes'],
                    [
                        'All eligible inner bodies',
                        'maximumEligibleInnerBodyCorpusBytes',
                    ],
                    [
                        'Selected inner bodies',
                        'maximumSelectedInnerBodyCorpusBytes',
                    ],
                    [
                        'All eligible raw seed-share ciphertexts',
                        'eligibleSeedShareCiphertextBytes',
                    ],
                    [
                        'Selected raw seed-share ciphertexts',
                        'selectedSeedShareCiphertextBytes',
                    ],
                    [
                        'All eligible inner bodies and raw seed-share ciphertexts',
                        'maximumEligibleBodyAndSeedCiphertextBytes',
                    ],
                    [
                        'Selected inner bodies and raw seed-share ciphertexts',
                        'maximumSelectedBodyAndSeedCiphertextBytes',
                    ],
                    [
                        'All eligible outer proofs',
                        'maximumEligibleOuterProofBytes',
                    ],
                    ['Selected outer proofs', 'maximumSelectedOuterProofBytes'],
                    [
                        'All eligible inner bodies, raw seed-share ciphertexts and outer proofs',
                        'maximumEligibleBodyCiphertextAndOuterProofBytes',
                    ],
                    [
                        'One public opening-share batch and proof, without framing',
                        'maximumOpeningBatchPayloadBytes',
                    ],
                    [
                        'Payload of d valid opening batches and proofs',
                        'maximumThresholdOpeningBatchPayloadBytes',
                    ],
                    [
                        'All n public opening batches and proofs',
                        'maximumAllOpeningBatchPayloadBytes',
                    ],
                    [
                        'Eligible offers plus all opening payloads and proofs',
                        'maximumPreparationPayloadSubtotalBytes',
                    ],
                ] as const
            ).map(([label, field]) => {
                const minimum = recoverableSetupProfiles.reduce(
                    (smallest, value) =>
                        value[field] < smallest[field] ? value : smallest,
                );
                const maximum = recoverableSetupProfiles.reduce(
                    (largest, value) =>
                        value[field] > largest[field] ? value : largest,
                );
                const atProfile = (value: typeof recoverableSetup) =>
                    `${formatCount(value[field])} at ${formatCount(value.participantCount)} participants, ${formatCount(value.optionCount)} options`;
                return [
                    label,
                    formatCount(recoverableSetup[field]),
                    atProfile(minimum),
                    atProfile(maximum),
                ];
            }),
        ),
        '',
        '### Outer seed-sharing proof layout and live-set planning',
        '',
        "The [bounded relation](../crates/protocol-research/seed-sharing-proof/src/layout.rs) retains the common proof engine dimensions even though its physical ring and seed are reduced. The full-ring columns extend the same witness-family count using the existing supported profile's conservative sharing cube, limb and carry widths; they are a model projection, not an implemented full-roster proof. Each nonconstant sharing coefficient contributes its low and high signed variables. Each recipient contributes the two quotient/carry/error triples, two sparse Boolean columns and two support rows; the seed adds one Boolean column whose first seed-width positions the public operator reads. The shared [word-proof layout](../tests/full-word-proof-layout-model.ts) supplies the encoded multiproof bound, including Merkle paths.",
        '',
        "The factored operator retains each recipient-key adjoint, one common adjoint, the sharing bases and the seed prefix; word and support columns share geometric terms. The [public-operator buffer model](../tests/public-polynomial-operator-resource-model.ts) retains the parser fingerprints and canonical encoding chunk during construction, one serialized operator column, and the scalar query evaluator's materialized geometric vectors, outputs, scratch and twiddles. Full-profile sharing-basis counts extrapolate the factorization beyond the fixed bounded fixture. Native planning conservatively adds these buffers, the existing public-coefficient allocation allowance, two encoded statement polynomial payloads and one complete proof-size allowance to the [generic prover schedule](../tests/browser-word-prover-resource-model.ts). The native case streams proofs. Metadata and allocator allowances are already in that schedule. These plans are not measured peaks or complete bounds for fixture generation, verification, browser integration or setup; an oversized conservative plan does not prove a memory lower bound.",
        '',
        table(
            [
                'Property',
                'Bounded native relation',
                'Same roster with full ring and seed',
                'Completion-profile full ring and seed',
            ],
            (
                [
                    ['Participants', (value) => value.participantCount],
                    ['Options', (value) => value.optionCount],
                    [
                        'Physical polynomial degree',
                        (value) => value.polynomialDegree,
                    ],
                    ['Opening seed bits', (value) => value.seedBits],
                    [
                        'Sharing coefficient bits',
                        (value) => value.sharingCoefficientBits,
                    ],
                    ['Sharing limb bits', (value) => value.limbBits],
                    [
                        'Constant-equation carry bits',
                        (value) => value.carryBits,
                    ],
                    ['Systematic proof rows', (value) => value.systematicSize],
                    [
                        'Verification domain points',
                        (value) => value.verificationDomainSize,
                    ],
                    ['Mask dimension', (value) => value.maskDimension],
                    ['Queries', (value) => value.queryCount],
                    ['Word columns', (value) => value.relation.wordColumns],
                    [
                        'Boolean columns',
                        (value) => value.relation.booleanColumns,
                    ],
                    ['Lookup entries', (value) => value.relation.lookupEntries],
                    [
                        'Disjoint Boolean pairs',
                        (value) => value.relation.disjointPairs,
                    ],
                    ['Support rows', (value) => value.relation.supportRows],
                    [
                        'Affine rows including support',
                        (value) => value.relation.affineRows,
                    ],
                    [
                        'Maximum encoded multiproof bytes',
                        (value) => value.layout.maximumMultiproofBytes,
                    ],
                    [
                        'Generic prover maximum live-byte allowance',
                        (value) => value.proofEngine.maximumLiveBytes,
                    ],
                    [
                        'Retained operator value vectors',
                        (value) => value.residentValueColumns,
                    ],
                    [
                        'Resident physical operator bytes',
                        (value) => value.residentOperatorBytes,
                    ],
                    [
                        'Operator build coefficient and encoding buffers',
                        (value) => value.operatorBuildBufferBytes,
                    ],
                    [
                        'Operator scalar query buffers',
                        (value) => value.operatorQueryBufferBytes,
                    ],
                    [
                        'Native proof planning bytes',
                        (value) => value.nativeProofPlanningBytes,
                    ],
                ] satisfies readonly (readonly [
                    string,
                    (value: typeof boundedSeedSharingProof) => bigint | number,
                ])[]
            ).map(([label, select]) => [
                label,
                formatCount(select(boundedSeedSharingProof)),
                formatCount(select(fullFourParticipantSeedSharingProof)),
                formatCount(select(recoverableSetup.outerProof)),
            ]),
        ),
        '',
        '### Public opening-share relation and payload screen',
        '',
        'The [opening-share model](../tests/recoverable-opening-share-model.ts) projects one original recipient-key equation and one decoding equation for every selected package. The public integer shares have an explicit canonical range; the verifier must derive the centered ciphertext difference from the authenticated source ciphertext and the supplied share. A different bounded recipient-key witness cannot change that plaintext under the [opening-share argument](security-argument.md#recoverable-sealed-preparation-candidate). The selected decision, package identities, original key and complete scope remain required inputs of the future protocol. This is a relation and format projection, not an emitted opening protocol or a decryption capability.',
        '',
        'The projected batch uses the shared word engine: signed quotient and carry words, a narrow registration error, a signed recovery error split into words and Boolean remainder bits, and one sparse recipient-secret pair. Its factored operator retains one combined secret adjoint, a geometric signed-variable term and a support term; construction still needs a transient parser vector, and query evaluation materializes its geometric inputs. The byte subtotal includes only new public integer-share vectors and their encoded proof. Expanded statement polynomial bytes include existing predecessors for verification work, not new uploads. Operator buffers are separate from the generic proof-engine allowance; public-input reconstruction, full protocol framing, fixture generation, remaining verifier work, storage and browser integration remain outside that allowance.',
        '',
        table(
            [
                'Property',
                'Bounded opening relation projection',
                'Completion-profile projection',
            ],
            (
                [
                    [
                        'Participants',
                        (value) => value.parameters.participantCount,
                    ],
                    [
                        'Selected packages in each batch',
                        (value) => value.parameters.selectedCount,
                    ],
                    [
                        'Physical polynomial degree',
                        (value) => value.physicalDegree,
                    ],
                    [
                        'Maximum public share magnitude',
                        (value) => value.parameters.maximumShare,
                    ],
                    [
                        'Honest decoding-error magnitude bound',
                        (value) => value.parameters.honestError,
                    ],
                    [
                        'Accepted recovery-error signed bits',
                        (value) => value.parameters.recoveryErrorBits,
                    ],
                    [
                        'Quotient and carry signed bits',
                        (value) => value.parameters.signedWordBits,
                    ],
                    [
                        'Maximum accepted limb residual magnitude bound',
                        (value) => value.parameters.maximumLimbResidual,
                    ],
                    ['Word columns', (value) => value.wordColumns],
                    ['Boolean columns', (value) => value.booleanColumns],
                    ['Lookup entries', (value) => value.lookupEntries],
                    ['Disjoint Boolean pairs', (value) => value.disjointPairs],
                    ['Support rows', (value) => value.supportRows],
                    [
                        'Retained operator value vectors',
                        (value) => value.residentValueColumns,
                    ],
                    [
                        'Resident physical operator bytes',
                        (value) => value.residentOperatorBytes,
                    ],
                    [
                        'Operator build coefficient and encoding buffers',
                        (value) => value.operatorBuildBufferBytes,
                    ],
                    [
                        'Operator scalar query buffers',
                        (value) => value.operatorQueryBufferBytes,
                    ],
                    [
                        'Affine rows including support',
                        (value) => value.affineRows,
                    ],
                    [
                        'Public integer-share coefficient bytes',
                        (value) => value.parameters.shareCoefficientBytes,
                    ],
                    [
                        'New public integer-share payload bytes per batch',
                        (value) => value.publicShareBytes,
                    ],
                    [
                        'Expanded statement polynomial bytes including predecessors',
                        (value) => value.expandedStatementPolynomialBytes,
                    ],
                    [
                        'Maximum encoded multiproof bytes per batch',
                        (value) => value.layout.maximumMultiproofBytes,
                    ],
                    [
                        'Generic prover maximum live-byte allowance',
                        (value) => value.proofEngine.maximumLiveBytes,
                    ],
                ] satisfies readonly (readonly [
                    string,
                    (value: typeof boundedOpeningShareProof) => bigint | number,
                ])[]
            ).map(([label, select]) => [
                label,
                formatCount(select(boundedOpeningShareProof)),
                formatCount(select(recoverableSetup.openingProof)),
            ]),
        ),
        '',
        'The bounded native opening fixture admits two distinct seed-sharing records through their actual verifier, then generates one positive opening batch and one hostile proof for a shifted public share. Its selected descriptor is a fixture premise. The native proving allowance below includes two retained source statements, the physical operator, derived equation constants, bounded public statement copies and serialization; it takes the maximum of the successive second-source and opening proof stages. These are allocation allowances, not measured memory or a full bound on fixture generation, verification, storage, browser execution or the complete preparation workflow. The fresh-artifact envelope excludes the separately copied input proofs.',
        '',
        table(
            ['Bounded native fixture property', 'Value'],
            [
                [
                    'Seed-sharing statement bytes',
                    boundedOpeningNative.seedStatementBytes,
                ],
                [
                    'Opening statement bytes',
                    boundedOpeningNative.openingStatementBytes,
                ],
                [
                    'Resident physical opening operator bytes',
                    boundedOpeningNative.residentOperatorBytes,
                ],
                [
                    'Retained source coefficient allocation allowance',
                    boundedOpeningNative.retainedSourceCoefficientAllowanceBytes,
                ],
                [
                    'Second-source proving stage allowance',
                    boundedOpeningNative.secondSourceStageBytes,
                ],
                [
                    'Opening proving stage allowance',
                    boundedOpeningNative.openingStageBytes,
                ],
                [
                    'Sequential native proving allowance',
                    boundedOpeningNative.nativeProofPlanningBytes,
                ],
                [
                    'Maximum new binary artifact bytes',
                    boundedOpeningNative.maximumNewArtifactBytes,
                ],
            ].map(([label, value]) => [
                String(label),
                formatCount(value as bigint),
            ]),
        ),
        '',
        '### Full-ring public-operator screen',
        '',
        'The [standalone public-operator screen](../crates/protocol-research/public-operator-screen/src/lib.rs) consumes canonical public recipes through the same arithmetic accumulators as the bounded proof paths. Its fixed roster and sharing shape use the full physical ring; it creates no witness, proof, verified package or participant capability. One canonical recipe chunk is temporary during construction. Independent direct-equation checks cover selected physical coordinates and the target; whole query-output comparison uses the existing interpolation kernel through a different column assembly order and is not an independent proof of every equation. One combined physical column and its query result are retained at a time before the factored query evaluation. The model takes the maximum of those phases plus the existing metadata and allocator allowance, without a whole decoded statement or proof engine. These are pre-execution allocation plans; process guards and actual native/scalar measurements remain required.',
        '',
        table(
            ['Property', 'Seed-sharing operator', 'Opening-share operator'],
            (
                [
                    ['Participants', (value) => value.participants],
                    [
                        'Sharing and recovery threshold',
                        (value) => value.threshold,
                    ],
                    ['Selected packages', (value) => value.selectedCount],
                    ['Opening seed bits', (value) => value.seedBits],
                    ['Physical degree', (value) => value.degree],
                    ['Relation columns', (value) => value.columns],
                    [
                        'Canonical public polynomials consumed',
                        (value) => value.polynomialCount,
                    ],
                    ['Query indices', (value) => value.queryCount],
                    [
                        'Independent physical coordinates',
                        (value) => value.physicalSamples.length,
                    ],
                    [
                        'Reported query coordinates',
                        (value) => value.querySamples.length,
                    ],
                    ['Exact report bytes', (value) => value.reportBytes],
                    ['ABI output capacity', (value) => value.outputCapacity],
                    [
                        'Maximum canonical input chunk bytes',
                        (value) => value.maximumInputChunkBytes,
                    ],
                    [
                        'Retained operator coefficient bytes',
                        (value) => value.residentOperatorBytes,
                    ],
                    [
                        'Largest phase coefficient/buffer bytes',
                        (value) => value.maximumBufferBytes,
                    ],
                    [
                        'Metadata and allocator allowance',
                        (value) => value.metadataAndAllocatorAllowance,
                    ],
                    [
                        'Process planning allowance',
                        (value) => value.planningBytes,
                    ],
                ] satisfies readonly (readonly [
                    string,
                    (
                        value: (typeof publicOperatorScreens)[number],
                    ) => bigint | number,
                ])[]
            ).map(([label, select]) => [
                label,
                ...publicOperatorScreens.map((value) =>
                    formatCount(select(value)),
                ),
            ]),
        ),
        '',
        '## Setup aggregate cache census',
        '',
        'The public aggregator replaces one coefficient-aligned chunk of the previous ordinal in each awaited atomic put/delete transaction. The resulting mixed cache is disposable scratch until complete offer verification and all aggregate digests succeed; failure clears it and drops the aggregator while preserving verified offer holders and authenticated private authority. Counts below bound logical payload and successful cache traffic; physical database journals, garbage collection, allocation overhead, failed candidates and participant private state require separate evidence.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Canonical aggregate bytes',
                    formatCount(setupAggregate.aggregateBytes),
                ],
                [
                    'Aggregate coefficients',
                    formatCount(setupAggregate.coefficients),
                ],
                [
                    'Chunks per cache generation',
                    formatCount(setupAggregate.cacheChunks),
                ],
                [
                    'Maximum cache read bytes',
                    formatCount(setupAggregate.maximumReadBytes),
                ],
                [
                    'Largest complete polynomial bytes',
                    formatCount(setupAggregate.maximumPolynomialBytes),
                ],
                [
                    'Logical cache payload including one replacement chunk',
                    formatCount(setupAggregate.maximumLogicalCachePayloadBytes),
                ],
                [
                    'Contribution polynomial read bytes',
                    formatCount(setupAggregate.contributionReadBytes),
                ],
                [
                    'Previous-generation cache read bytes',
                    formatCount(setupAggregate.previousCacheReadBytes),
                ],
                [
                    'Provisional cache write bytes',
                    formatCount(setupAggregate.provisionalCacheWriteBytes),
                ],
                [
                    'Complete final readback bytes',
                    formatCount(setupAggregate.completeReadbackBytes),
                ],
            ],
        ),
        '',
        '## Shared participant custody census',
        '',
        'The shared root retains original enrollment records, the selected signed proposal, contribution state, and signing-record keys and identities. The expanded statement header is regenerated rather than retained as another body record. The existing length-prefixed contribution header field instead retains the canonical SCB2 body header from completed generation onward, replacing the retired first-oracle progress header. Proof storage always seals the maximum proof capacity into fixed slots. A complete consumer pass authenticates every slot and checks its zero tail, supplying only the actual-length prefix; commitment completion waits for that pass, and the existing body-commitment preflight precedes publication. The maximum payload, record-key, tag and reference envelopes already reserved this capacity. The added body header changes completed metadata and any maxima it dominates. The payload bound includes checkpoint/body overlap and signing records; browser database, key-store, and journal overhead remain measured quantities.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Participants', formatCount(participantCustody.participants)],
                [
                    'Owned polynomial records',
                    formatCount(participantCustody.publicRecords.length),
                ],
                [
                    'Private checkpoint records',
                    formatCount(participantCustody.checkpointLengths.length),
                ],
                [
                    'Contribution metadata prefix bytes',
                    formatCount(participantCustody.metadataPrefixBytes),
                ],
                [
                    'Maximum checkpoint metadata bytes',
                    formatCount(
                        participantCustody.maximumCheckpointMetadataBytes,
                    ),
                ],
                [
                    'Maximum completed metadata bytes',
                    formatCount(
                        participantCustody.maximumCompletedMetadataBytes,
                    ),
                ],
                [
                    'Retained completed body-header bytes',
                    formatCount(participantCustody.completedBodyHeaderBytes),
                ],
                [
                    'Fixed proof storage slots',
                    formatCount(contributionProofStorage.records.length),
                ],
                [
                    'Fixed proof plaintext capacity bytes',
                    formatCount(contributionProofStorage.plaintextBytes),
                ],
                [
                    'Fixed encrypted proof capacity bytes',
                    formatCount(contributionProofStorage.ciphertextBytes),
                ],
                [
                    'Fixed proof record-key bytes',
                    formatCount(contributionProofStorage.dataKeyBytes),
                ],
                [
                    'Fixed proof record-identity bytes',
                    formatCount(contributionProofStorage.recordIdentityBytes),
                ],
                [
                    'Fixed proof reference bytes in root',
                    formatCount(contributionProofStorage.recordReferenceBytes),
                ],
                [
                    'Maximum encrypted participant root bytes',
                    formatCount(participantCustody.maximumRootBytes),
                ],
                [
                    'Maximum release state bytes',
                    formatCount(participantCustody.maximumReleaseStateBytes),
                ],
                [
                    'Maximum close state bytes',
                    formatCount(participantCustody.maximumCloseStateBytes),
                ],
                [
                    'Maximum target-signing state bytes',
                    formatCount(
                        participantCustody.maximumTargetSigningStateBytes,
                    ),
                ],
                [
                    'Maximum participant root records',
                    formatCount(participantCustody.maximumRootRecords),
                ],
                [
                    'Retained setup reference bytes',
                    formatCount(participantCustody.setupReferenceBytes),
                ],
                [
                    'Maximum public body ciphertext bytes',
                    formatCount(
                        participantCustody.maximumPublicBodyCiphertextBytes,
                    ),
                ],
                [
                    'Maximum signing plaintext payload bytes',
                    formatCount(
                        participantCustody.maximumSigningPlaintextBytes,
                    ),
                ],
                [
                    'Maximum retained payload and overlap bytes',
                    formatCount(participantCustody.maximumRetainedPayloadBytes),
                ],
            ],
        ),
        '',
        'Preparation and later roots have distinct inventories. PRE1 frames independent own-offer, selection and endorsement slots; PCS4 carries its own phase. Activation authenticates the complete predecessor before clearing all slots and retiring source material. Later roots therefore retain an empty preparation journal beside ballot, close, target and release state.',
        '',
        table(
            ['Authenticated journal property', 'Bytes'],
            [
                [
                    'Empty preparation journal',
                    formatCount(participantCustody.emptyPreparationBytes),
                ],
                [
                    'Maximum own-offer state',
                    formatCount(participantCustody.maximumMetadataBytes),
                ],
                [
                    'Maximum organizer selection slot',
                    formatCount(participantCustody.maximumSelectionSlotBytes),
                ],
                [
                    'Maximum endorsement slot',
                    formatCount(participantCustody.maximumEndorsementSlotBytes),
                ],
                [
                    'Maximum complete preparation journal',
                    formatCount(participantCustody.maximumPreparationBytes),
                ],
                [
                    'Maximum preparation root',
                    formatCount(participantCustody.maximumPreparationRootBytes),
                ],
                [
                    'Maximum prepared later root',
                    formatCount(participantCustody.maximumPreparedRootBytes),
                ],
            ],
        ),
        '',
        'Actual padding growth depends on an observed complete proof length `L`, not the header-only framing lower bound, which does not establish an achievable proof. With capacity `P`, chunk size `C`, `M=ceil(P/C)` and `m=ceil(L/C)`, the added proof payload is `P-L`, the added record count is `M-m`, and added encrypted proof bytes are `P-L+16*(M-m)`. The completed root adds the body header and `106*(M-m)` reference bytes; the root tag count does not change. Each actual full authentication/consumer pass reads that complete encrypted proof delta again, and an ordinary write pays it once. The [projection model](../tests/participant-custody-model.ts) takes the observed length and explicit pass count; it assumes no extra preflight passes and does not turn per-pass costs into lifetime populations. Checkpoint authentication and atomic retirement remain required, with their payload already included in the overlap bound. Public proof bytes remain the original `L`-byte prefix.',
        '',
        '## Participant vault key work',
        '',
        'These per-key upper bounds follow the emitted fixed-nonce AES-GCM layouts. Initial intent and completion share one key with distinct nonces; every later root and child record uses a fresh key. Corpus counts exclude aborted writes, abandoned enrollment and recovery. They are not lifetime key limits. Later-root counts and every lifetime encryption/read population remain unmeasured; repeated reads add work even when they reuse existing block inputs. The root nonce in a single-use class is normalized because its value does not change these per-key counts.',
        '',
        table(
            [
                'Key class',
                'Maximum keys per completed corpus',
                'Encryption calls per key',
                'Maximum AES inputs for encryption',
                'Algorithmic encryption AES call bound',
                'Maximum GHASH degree',
            ],
            compileParticipantVaultKeyClasses(completion).map((value) => [
                value.name,
                value.maximumPerCompletedCorpus === null
                    ? 'Unmeasured'
                    : formatCount(value.maximumPerCompletedCorpus),
                formatCount(value.encryptionWork.invocations),
                formatCount(value.encryptionWork.distinctAesInputUpperBound),
                formatCount(value.encryptionWork.algorithmicAesCallUpperBound),
                formatCount(value.encryptionWork.maximumHashDegree),
            ]),
        ),
        '',
        'For a supplied complete per-key history, the work model separately counts encryption and verification invocations, repeated block computations and the union of block inputs. Its statistical numerators are conditional on the stated secret-key PRP replacement; the AES assumption, full populations and whole-protocol advantage are additional obligations.',
        '',
        '## Clear setup selection wire and resources',
        '',
        'Offers authenticate complete ordinary body identities under the original roster and author. Exactly the roster-derived selected count enters the canonical proposal, and exactly the inventory quorum signs its certificate. Different valid signer subsets carry the same semantic setup identity. Whole-body commitments, later opening messages and unanimous confirmation carriers are absent. The independent lifecycle model covers own-work coexistence, one-shot endorsements, original-state restoration and authenticated retirement; it assumes the complete owning proof/signature verifiers and the named published-store retention contract.',
        '',
        table(
            [
                'Participants',
                'Eligible',
                'Selected',
                'Quorum',
                'Offer envelope bytes',
                'Selection body bytes',
                'Endorsement body bytes',
                'Endorsement packet bytes',
                'Certificate bytes',
            ],
            clearSelectionWires.map((wire) =>
                [
                    wire.participantCount,
                    wire.eligibleCount,
                    wire.selectedCount,
                    wire.quorum,
                    wire.offerEnvelopeBytes,
                    wire.selectionBodyBytes,
                    wire.endorsementBodyBytes,
                    wire.endorsementPacketBytes,
                    wire.certificateBytes,
                ].map(formatCount),
            ),
        ),
        '',
        table(
            ['Completion-profile component', 'Value'],
            [
                [
                    'Maximum eligible body corpus bytes',
                    formatCount(clearPreparation.maximumEligibleBodyBytes),
                ],
                [
                    'Maximum selected body corpus bytes',
                    formatCount(clearPreparation.maximumSelectedBodyBytes),
                ],
                [
                    'Maximum eligible signed-offer corpus bytes',
                    formatCount(clearPreparation.maximumEligibleOfferBytes),
                ],
                [
                    'Maximum certified setup payload bytes',
                    formatCount(clearPreparation.maximumCertifiedSetupBytes),
                ],
                [
                    'Maximum endorsement packet corpus bytes',
                    formatCount(clearPreparation.maximumEndorsementPacketBytes),
                ],
                [
                    'Maximum offer proofs',
                    formatCount(clearPreparation.maximumOfferProofs),
                ],
                [
                    'Maximum untrusted discovery page bytes',
                    formatCount(clearPreparation.maximumDiscoveryPageBytes),
                ],
                [
                    'Maximum generation and continuation seeds',
                    formatCount(
                        clearPreparation.maximumGenerationAndContinuationSeeds,
                    ),
                ],
                [
                    'Selected proof verifications per fresh reader',
                    formatCount(
                        clearPreparation.selectedProofVerificationsPerReader,
                    ),
                ],
                [
                    'Fresh selected-offer verification read bytes',
                    formatCount(
                        clearPreparation.maximumOfferVerificationReadBytes,
                    ),
                ],
                [
                    'Organizer selected polynomial aggregation reread bytes',
                    formatCount(clearPreparation.selectedPolynomialRereadBytes),
                ],
                [
                    'Exact proof lookahead bytes',
                    formatCount(clearPreparation.selectedProofLookaheadBytes),
                ],
                [
                    'Proof lookahead transport reservation bytes',
                    formatCount(clearPreparation.maximumLookaheadIngressBytes),
                ],
                [
                    'Matching retained-input certificate activation read bytes',
                    formatCount(
                        clearPreparation.maximumMatchingCertificateActivationReadBytes,
                    ),
                ],
                [
                    'Fresh certificate activation read bytes',
                    formatCount(
                        clearPreparation.maximumFreshCertificateActivationReadBytes,
                    ),
                ],
                [
                    'Clean preparation logical download bytes',
                    formatCount(
                        clearPreparation.maximumCleanPreparationDownloadBytes,
                    ),
                ],
                [
                    'Clean organizer preparation logical download bytes',
                    formatCount(
                        clearPreparation.maximumCleanOrganizerPreparationDownloadBytes,
                    ),
                ],
                [
                    'Clean preparation participant upload bytes',
                    formatCount(
                        clearPreparation.maximumCleanParticipantUploadBytes,
                    ),
                ],
                [
                    'Clean preparation total upload bytes',
                    formatCount(clearPreparation.maximumCleanTotalUploadBytes),
                ],
                [
                    'Transfer planning target bytes',
                    formatCount(clearPreparation.transferPlanningBytes),
                ],
                [
                    'Preparation download planning margin bytes',
                    formatCount(
                        clearPreparation.transferPlanningBytes -
                            clearPreparation.maximumCleanPreparationDownloadBytes,
                    ),
                ],
                [
                    'Organizer preparation download planning margin bytes',
                    formatCount(
                        clearPreparation.transferPlanningBytes -
                            clearPreparation.maximumCleanOrganizerPreparationDownloadBytes,
                    ),
                ],
                [
                    'Participant upload planning margin bytes',
                    formatCount(
                        clearPreparation.transferPlanningBytes -
                            clearPreparation.maximumCleanParticipantUploadBytes,
                    ),
                ],
                [
                    'Total upload planning margin bytes',
                    formatCount(
                        clearPreparation.transferPlanningBytes -
                            clearPreparation.maximumCleanTotalUploadBytes,
                    ),
                ],
                [
                    'Volatile offer polynomial-identity payload bytes',
                    formatCount(
                        clearPreparation.volatileOfferPolynomialIdentityBytes,
                    ),
                ],
            ],
        ),
        '',
        'Fresh participants fuse selected-body polynomial reads with full offer verification and aggregation, retaining bounded proof-header lookahead and certificate handling. Organizer discovery verifies selected offers before signing; endorsement reuses those verified holders in the same worker and rereads only their polynomials for aggregation. Matching original SPI1 avoids another proof pass at activation; losing or absent local endorsement uses the fresh certificate path. Complete exact named reads with owning verification establish publication under the monotone public-store premise, so selected bodies are not uploaded again. Each extra cache miss or restart must charge its actual verification and aggregation passes; there is no finite lifetime count. These preparation-only logical payload margins exclude registration, ballots, closing, release and transport overhead, and therefore do not establish complete-action qualification.',
        '',
        'The organizer performs one full selected-offer verification pass during discovery and reuses those holders when endorsing in the same worker; the additional read is only the selected polynomial payload. The following preparation-only screen charges that reread and every eligible discovery page. Polynomial-only floors exclude proofs and metadata; exceeding the planning variance ceiling with such a floor requires architecture review. The variance ceiling is not an absolute cryptographic or allocation limit.',
        '',
        table(
            [
                'Profile',
                'Participant polynomial-read floor',
                'Participant logical-download maximum',
                'Organizer polynomial-read floor',
                'Organizer logical-download maximum',
                'Participant upload maximum',
                'Total upload maximum',
                'Eligible polynomial-upload floor',
                'Planning variance ceiling',
            ],
            [
                [10, 10],
                [20, 20],
            ].map(([participants, options]) => {
                const value = compileClearPreparationResources(
                    deriveSupportedProfile(participants, options),
                );
                return [
                    participants + '/' + options,
                    ...[
                        value.cleanParticipantPolynomialReadFloorBytes,
                        value.maximumCleanPreparationDownloadBytes,
                        value.cleanOrganizerPolynomialReadFloorBytes,
                        value.maximumCleanOrganizerPreparationDownloadBytes,
                        value.maximumCleanParticipantUploadBytes,
                        value.maximumCleanTotalUploadBytes,
                        value.completeEligiblePolynomialUploadFloorBytes,
                        value.planningVarianceCeilingBytes,
                    ].map(formatCount),
                ];
            }),
        ),
        '',
        '## Complete ordinary workflow resource screen',
        '',
        'The [workflow model](../tests/ordinary-workflow-resource-model.ts) follows one successful ordinary traversal with all roster members casting, responding, evaluating, voting, releasing and reading the result. Its ordinary schedule generates only the selected contributors; the separate eligible-corpus row allows every eligible author to publish. Body sizes are canonical maxima, not predictions of sampled proof sizes. The [candidate publication model](../tests/candidate-publication-model.ts) enumerates each complete manifest, immutable uploaded chunk, discovery entry, logical-key record, receipt and named readback. It includes repeated registration, poll, certificate and close-intent publications. Responders and the organizer forward immutable body references only after comparing every referenced byte with their authenticated custody; unavailable original chunks require uploading those same retained bytes. The stored-corpus figures count protocol payload and routing records, with filesystem allocation and journal costs separate. Publication readback totals are additional to ordinary public-input reads. Invalid inputs, retries and arbitrary extra visits have no finite lifetime population here.',
        '',
        'The artifact operands below come from the existing shared SDK build. Census generation verifies every recorded source digest and the packaged runtime identity, refuses a missing or stale build, and never triggers a build. Regenerate and check this section after the shared SDK build. These byte lengths identify delivered artifacts, not a phone measurement. The SDK embeds the worker source and creates worker/helper Blob URLs, so network bootstrap is one SDK bundle per page load plus one module per actual primary-worker invocation; the embedded worker is not charged twice. The ordinary target-signing call uses one worker, and the subsequent release/result calls restore its intact target. A cache-miss release/result call can automatically start a second worker and must charge both module fetches. Host-page bytes, transport headers and application delivery remain separate operands.',
        '',
        table(
            ['Built runtime operand', 'Value'],
            [
                [
                    'Runtime identity',
                    `\`${resourceArtifact.identity.runtime}\``,
                ],
                ['SDK entry digest', `\`${resourceArtifact.sdkDigest}\``],
                [
                    'SDK bundle bytes per page load',
                    formatCount(resourceArtifact.sdkBytes),
                ],
                [
                    'Module bytes per operation invocation',
                    formatCount(resourceArtifact.moduleBytes),
                ],
                [
                    'Embedded worker source bytes',
                    formatCount(resourceArtifact.workerBytes),
                ],
            ],
        ),
        '',
        table(
            ['Property', ...workflowResources.map((value) => value.profile)],
            [
                [
                    'Ordinary selected offer count',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].offers,
                ],
                [
                    'All-eligible offer count',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[1].offers,
                ],
                [
                    'Ordinary complete public corpus bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].publicCorpusBytes,
                ],
                [
                    'All-eligible complete public corpus bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[1].publicCorpusBytes,
                ],
                [
                    'Ordinary total upload bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].totalUploadBytes,
                ],
                [
                    'All-eligible total upload bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[1].totalUploadBytes,
                ],
                [
                    'Organizer upload bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.organizerUploadBytes,
                ],
                [
                    'Organizer closure copies',
                    (value: (typeof workflowResources)[number]) =>
                        value.organizerClosureCopyBytes,
                ],
                [
                    'Responders’ listed-envelope copies',
                    (value: (typeof workflowResources)[number]) =>
                        value.responderListedCopyBytes,
                ],
                [
                    'Maximum body reupload when original references are unavailable',
                    (value: (typeof workflowResources)[number]) =>
                        value.maximumMissingReferenceUploadBytes,
                ],
                [
                    'Bodies forwarded by byte-checked references',
                    (value: (typeof workflowResources)[number]) =>
                        value.ordinaryReferencedBodyBytes,
                ],
                [
                    'Publication readbacks, reference checks and receipts',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicationReceivedBytes,
                ],
                [
                    'Publication requests including reference checks',
                    (value: (typeof workflowResources)[number]) =>
                        value.candidatePublicationRequests,
                ],
                [
                    'Uploaded candidate manifest bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.candidateManifestBytes,
                ],
                [
                    'Largest emitted candidate manifest',
                    (value: (typeof workflowResources)[number]) =>
                        value.maximumManifestBytes,
                ],
                [
                    'Largest emitted candidate file count',
                    (value: (typeof workflowResources)[number]) =>
                        value.maximumManifestFiles,
                ],
                [
                    'Standalone reader routing metadata',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicReaderRoutingBytes,
                ],
                [
                    'Fresh standalone reader protocol bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicReaderProtocolBytes,
                ],
                [
                    'Fresh standalone reader plus one SDK/module delivery',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicReaderColdDeliveryBytes,
                ],
                [
                    'Ordinary operation-worker invocations',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].workerInvocations,
                ],
                [
                    'All-eligible operation-worker invocations',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[1].workerInvocations,
                ],
                [
                    'Ordinary module-download bytes across participants',
                    (value: (typeof workflowResources)[number]) =>
                        value.rows[0].moduleDownloadBytes,
                ],
            ].map(([label, select]) => [
                label as string,
                ...workflowResources.map((value) =>
                    formatCount(
                        (
                            select as (
                                value: (typeof workflowResources)[number],
                            ) => bigint
                        )(value),
                    ),
                ),
            ]),
        ),
        '',
        'The standalone reader has no participant custody and streams every usable ballot for barrier authentication, classification and evaluation import before checking the target votes and release shares. Participants with intact close custody read those bodies locally. Roster restoration refetches complete registered headers and recipient keys, preserving its own retained verification instead of repeating registration proofs. Metadata allowances are conservative: held close responses can avoid target reads, and an existing setup certificate avoids assembly reads. These are protocol-read upper bounds, not exact ordinary network traces. The action rows exclude bootstrap; add the actual module for each primary-worker invocation and the SDK for each page load. Cumulative download rows are distinct from the per-action planning target.',
        '',
        table(
            [
                'Clean protocol read upper bound',
                ...workflowResources.map((value) => value.profile),
            ],
            [
                [
                    'One roster restoration',
                    (value: (typeof workflowResources)[number]) =>
                        value.rosterRestoreBytes,
                ],
                [
                    'Preparation endorsement and activation',
                    (value: (typeof workflowResources)[number]) =>
                        value.preparationReaderBytes,
                ],
                [
                    'Organizer selection, endorsement and activation',
                    (value: (typeof workflowResources)[number]) =>
                        value.preparationOrganizerBytes,
                ],
                [
                    'Other member’s two close invocations',
                    (value: (typeof workflowResources)[number]) =>
                        value.nonorganizerCloseBytes,
                ],
                [
                    'Organizer’s two close invocations',
                    (value: (typeof workflowResources)[number]) =>
                        value.organizerCloseBytes,
                ],
                [
                    'Target action',
                    (value: (typeof workflowResources)[number]) =>
                        value.targetReadBytes,
                ],
                [
                    'Release action with retained target',
                    (value: (typeof workflowResources)[number]) =>
                        value.releaseReadBytes,
                ],
                [
                    'Result action with retained target',
                    (value: (typeof workflowResources)[number]) =>
                        value.resultReadBytes,
                ],
                [
                    'Cumulative member without an offer',
                    (value: (typeof workflowResources)[number]) =>
                        value.noncontributorProtocolReads,
                ],
                [
                    'Cumulative member with one offer',
                    (value: (typeof workflowResources)[number]) =>
                        value.contributorProtocolReads,
                ],
                [
                    'Cumulative organizer',
                    (value: (typeof workflowResources)[number]) =>
                        value.organizerProtocolReads,
                ],
            ].map(([label, select]) => [
                label as string,
                ...workflowResources.map((value) =>
                    formatCount(
                        (
                            select as (
                                value: (typeof workflowResources)[number],
                            ) => bigint
                        )(value),
                    ),
                ),
            ]),
        ),
        '',
        '## Scalar evaluation storage screen',
        '',
        'The [independent storage model](../tests/evaluation-storage-model.ts) emits the existing algebraic ranking DAG in the Rust program’s DFS order and interprets the scalar capacity and eviction policy without ciphertexts or proofs. It preserves the pinned completion-program identity. The farthest next use is evicted first, with greatest index breaking ties; a reloaded value keeps its stored copy until final use. Old host key records coexist with newly written spills before awaited cache deletion, and replacement ordinal writes follow that deletion. These are successful logical store payloads; physical database journals, garbage collection, Blob allocation and process memory are separate evidence.',
        '',
        table(
            [
                'Scalar schedule operand',
                ...workflowResources.map((value) => value.profile),
            ],
            [
                [
                    'Instructions',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.program.instructions.length),
                ],
                [
                    'One stored ciphertext bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.capacity.storedValueBytes,
                ],
                [
                    'Multiplication-key record bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.capacity.multiplicationKeyBytes,
                ],
                [
                    'One scalar job allowance bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.capacity.jobBytes,
                ],
                [
                    'First spill writes',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.spillCount),
                ],
                [
                    'Reloads',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.reloadCount),
                ],
                [
                    'Resident-only drops of stored values',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.dropCount),
                ],
                [
                    'Peak live spilled values',
                    (value: (typeof workflowResources)[number]) =>
                        BigInt(value.evaluation.peakStored),
                ],
                [
                    'Peak evaluation-store payload bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.peakBytes,
                ],
                [
                    'Scratch planning variance ceiling',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.scratchVarianceCeilingBytes,
                ],
                [
                    'All key-bank writes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.keyBankWriteBytes,
                ],
                [
                    'Spill writes and matching readback, each',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.spillWriteBytes,
                ],
                [
                    'Reload read bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluation.reloadBytes,
                ],
                [
                    'Preparation retained and aggregate payload subtotal',
                    (value: (typeof workflowResources)[number]) =>
                        value.prepRetainedAndAggregatePayloadBytes,
                ],
                [
                    'Closed custody and aggregate payload subtotal',
                    (value: (typeof workflowResources)[number]) =>
                        value.closedCustodyAndAggregatePayloadBytes,
                ],
                [
                    'Evaluation custody, aggregate and store payload subtotal',
                    (value: (typeof workflowResources)[number]) =>
                        value.evaluationCustodyAndStorePayloadBytes,
                ],
                [
                    'Completed release payload subtotal',
                    (value: (typeof workflowResources)[number]) =>
                        value.releaseEndPayloadBytes,
                ],
                [
                    'Maximum retained target Vec / immutable Blob bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.retainedTarget.maximumRetainedBytes,
                ],
                [
                    'Maximum retained-target copied slice bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.retainedTarget.maximumSliceBytes,
                ],
                [
                    'Local publication data-kind payload reads across participants',
                    (value: (typeof workflowResources)[number]) =>
                        value.publicationRecordPayloadReadBytes,
                ],
                [
                    'Maximum registration-publication record bytes',
                    (value: (typeof workflowResources)[number]) =>
                        value.maximumPublicationRecordBytes,
                ],
            ].map(([label, select]) => [
                label as string,
                ...workflowResources.map((value) =>
                    formatCount(
                        (
                            select as (
                                value: (typeof workflowResources)[number],
                            ) => bigint
                        )(value),
                    ),
                ),
            ]),
        ),
        '',
        'The retained-target repair bounds each copied JavaScript slice while preserving the full Rust output and single immutable stored Blob. Public data-kind publication now uses a complete preflight followed by guarded record-sized delivery; the local payload-read row charges those two passes, with root/head/count authority checks additional and no change to upload bytes. The custody subtotals still need residual record/head metadata, restart overlap and physical storage accounting before they establish a complete origin-storage bound. The largest profile remains outside the scratch planning variance ceiling and its organizer’s preparation polynomial-read floor remains outside the transfer variance ceiling; no largest-profile resource closure follows from the smaller ordinary corpus or bounded copy repair.',
        '',
        '## Roster proposal census',
        '',
        'The proposal binds the ordered complete registration-body identities under an authenticated poll. Its public corpus includes every recipient key and proof, registration header and signature, and one signed poll definition. The contribution generator consumes the verified records directly and has no caller-supplied key-digest carrier. Retained payload counts exclude allocator and verifier scratch. These public input records do not supply organizer authorization or participant confirmation.',
        '',
        table(
            [
                'Participants',
                'Proposal bytes',
                'Contribution role bytes',
                'Retained recipient-key bytes',
                'Retained record payload bytes',
                'Maximum public corpus bytes',
            ],
            rosterProposals.map((proposal) => [
                String(proposal.participantCount),
                formatCount(proposal.proposalBytes),
                formatCount(proposal.roleBytes),
                formatCount(proposal.retainedRecipientKeyBytes),
                formatCount(proposal.retainedRecordPayloadBytes),
                formatCount(proposal.maximumPublicCorpusBytes),
            ]),
        ),
        '',
        '## Common-matrix sampling census',
        '',
        'A fixed admitted suite label selects independent ideal-oracle words. Exact modulo-law enumeration checks the residue distance and the corresponding conditional full-oracle law. The complete bound includes all FHE common polynomials, the common sharing polynomial and both fixed auxiliary coordinates. Registration fixes the common share polynomial before the roster size is known, so the sharing and auxiliary families use one profile-independent sample width within half the distance allocation, and the FHE width follows the profile. Caller-selected labels, adaptive parameter grinding, the fixed SHAKE implementation, and cryptographic security of the resulting keys are not established by this sampling calculation.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'FHE sample bits per coefficient',
                    formatCount(commonMatrixSampling.fheBitsPerCoefficient),
                ],
                [
                    'Sharing and auxiliary sample bits per coefficient',
                    formatCount(
                        commonMatrixSampling.fixedFamilyBitsPerCoefficient,
                    ),
                ],
                [
                    'FHE common polynomials',
                    formatCount(commonMatrixSampling.fhePolynomialCount),
                ],
                [
                    'Common coefficients across all roles',
                    formatCount(commonMatrixSampling.coefficientCount),
                ],
                [
                    'Expanded common-matrix sampling bytes',
                    formatCount(commonMatrixSampling.expandedSampleBytes),
                ],
                [
                    'Complete oracle-distribution distance exponent',
                    formatCount(commonMatrixSampling.distanceBits),
                ],
            ],
        ),
        '',
        'Common-matrix XOF initialization reuses the fixed-work residue-fibre sampler. Each common polynomial is one fixed input with a complete output prefix; consecutive wide words encode its coefficients. The sampler makes one bounded draw per coefficient and adds its explicit modulo bias. It does not use a rejection-loop or exhaustion term.',
        '',
        table(
            ['Property', 'Value'],
            (() => {
                const initialization =
                    compileCommonMatrixInitializationCensus(completion);
                return [
                    ['Programmed XOF inputs', initialization.programmedInputs],
                    [
                        'Programmed prefix bytes',
                        initialization.programmedPrefixBytes,
                    ],
                    [
                        'Extra fibre sampling bits',
                        initialization.extraSamplingBits,
                    ],
                    ['Random bits consumed', initialization.randomBits],
                    [
                        'Byte-aligned random input bytes',
                        initialization.randomBytes,
                    ],
                    ['Fibre bias numerator', initialization.biasNumerator],
                    ['Fibre bias denominator', initialization.biasDenominator],
                ].map(([label, value]) => [
                    String(label),
                    formatCount(value as bigint),
                ]);
            })(),
        ),
        '',
        table(
            [
                'Common family',
                'Polynomials',
                'Coefficients',
                'Random bits per coefficient',
                'Programmed prefix bytes',
            ],
            compileCommonMatrixInitializationCensus(completion).families.map(
                (value) => [
                    value.name,
                    ...[
                        value.polynomials,
                        value.coefficients,
                        value.randomBitsPerCoefficient,
                        value.programmedPrefixBytes,
                    ].map(formatCount),
                ],
            ),
        ),
        '',
        '## Fixed sponge initialization census',
        '',
        'These counts instantiate the conditional fixed-input initialization lemma for the current common-vector seed encoding. Each unique seed and its longest required output prefix are counted once. The distance includes residue-word sampling, capacity conditioning, one-pass capacity-sampling failure, and bounded fiber-sampling bias in an ideal permutation; it is not fixed-Keccak or end-to-end security.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Distinct fixed seeds',
                    formatCount(fixedSpongeInitialization.seeds.length),
                ],
                [
                    'Maximum unpadded seed bytes',
                    formatCount(fixedSpongeInitialization.maximumSeedBytes),
                ],
                ['Rate bits', formatCount(fixedSpongeInitialization.rateBits)],
                [
                    'Capacity bits',
                    formatCount(fixedSpongeInitialization.capacityBits),
                ],
                [
                    'Permutation output blocks across fixed prefixes',
                    formatCount(fixedSpongeInitialization.outputBlocks),
                ],
                [
                    'Capacity-conditioning distance exponent',
                    formatCount(
                        fixedSpongeInitialization.conditioningFailureExponent,
                    ),
                ],
                [
                    'Extra random bits for bounded fiber sampling',
                    formatCount(fixedSpongeInitialization.extraSamplingBits),
                ],
                [
                    'Maximum random bits per simulated fiber word',
                    formatCount(
                        fixedSpongeInitialization.maximumFiberRandomBits,
                    ),
                ],
                [
                    'Combined initialization distance exponent',
                    formatCount(
                        fixedSpongeInitialization.combinedInitializationFailureExponent,
                    ),
                ],
            ],
        ),
        '',
        '## Certificate custody census',
        '',
        "The counterexample delivers all continuing honest participants' messages but permits suppression of earlier sends from participants who disappeared. Full holders possess the entire certificate and every required predecessor; individual signers do not establish that premise.",
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Full-holder threshold examined',
                    formatCount(certificateCustody.fullHolderThreshold),
                ],
                [
                    'Named custody configurations checked',
                    formatCount(certificateCustody.checkedConfigurations),
                ],
                [
                    'Minimum surviving honest full holders',
                    formatCount(
                        certificateCustody.minimumSurvivingHonestFullHolders,
                    ),
                ],
                [
                    'Recoverable signatures in the unique-collector counterexample',
                    formatCount(
                        certificateCustody.counterexample.recoverableSignatures,
                    ),
                ],
                [
                    'Required target signatures',
                    formatCount(certificateCustody.counterexample.quorum),
                ],
                [
                    'Full-copy holders sufficient without ledger delivery',
                    formatCount(
                        fullHolderRequirements(
                            certificateCustody.participantCount,
                            certificateCustody.corruptCount,
                            certificateCustody.corruptCount,
                            1,
                        ).requiredHolders,
                    ),
                ],
                [
                    'Coded holders sufficient at the release reconstruction threshold',
                    formatCount(
                        fullHolderRequirements(
                            certificateCustody.participantCount,
                            certificateCustody.corruptCount,
                            certificateCustody.corruptCount,
                            certificateCustody.corruptCount + 1,
                        ).requiredHolders,
                    ),
                ],
            ],
        ),
        '',
        '## Fixed-modulus BFV noise census',
        '',
        'Exact worst-case noise screen for the uniform comparison and duplicated ranking-window candidate. The full integer tensor-rounding and KLSW relinearization equations are checked independently. This screen does not establish the circular-key assumption, complete proof compiler, browser cost, or protocol admission.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Participants', formatCount(fixedModulusBfv.participantCount)],
                ['Options', formatCount(fixedModulusBfv.optionCount)],
                [
                    'Ciphertext polynomial degree',
                    formatCount(fixedModulusBfv.polynomialDegree),
                ],
                [
                    'Plaintext subring degree',
                    formatCount(fixedModulusBfv.plaintextSubringDegree),
                ],
                [
                    'Plaintext modulus',
                    formatCount(fixedModulusBfv.plaintextModulus),
                ],
                [
                    'Ciphertext modulus',
                    formatCount(fixedModulusBfv.ciphertextModulus),
                ],
                [
                    'Release modulus',
                    formatCount(fixedModulusBfv.releaseModulus),
                ],
                [
                    'Per-contributor secret support weight',
                    formatCount(fixedModulusBfv.secretSupportWeight),
                ],
                [
                    'Accepted error magnitude bound',
                    formatCount(fixedModulusBfv.errorBound),
                ],
                ['Gadget base', formatCount(fixedModulusBfv.gadgetBase)],
                [
                    'Gadget coordinates',
                    formatCount(fixedModulusBfv.gadgetLength),
                ],
                [
                    'Comparison block width',
                    formatCount(fixedModulusBfv.comparisonBlockWidth),
                ],
                [
                    'Ciphertext multiplications',
                    formatCount(fixedModulusBfv.multiplications),
                ],
                [
                    'Ciphertext additions',
                    formatCount(fixedModulusBfv.additions),
                ],
                [
                    'Scalar plaintext products',
                    formatCount(fixedModulusBfv.scalarProducts),
                ],
                [
                    'Vector plaintext products',
                    formatCount(fixedModulusBfv.plaintextProducts),
                ],
                ['Unit rotations', formatCount(fixedModulusBfv.rotations)],
                [
                    'Separately rounded tensor-coordinate products',
                    formatCount(fixedModulusBfv.tensorProducts),
                ],
                [
                    'Relinearization external products',
                    formatCount(
                        fixedModulusBfv.relinearizationExternalProducts,
                    ),
                ],
                [
                    'Relinearization gadget decompositions',
                    formatCount(
                        fixedModulusBfv.relinearizationGadgetDecompositions,
                    ),
                ],
                [
                    'Rotation external products including the common vector',
                    formatCount(fixedModulusBfv.rotationExternalProducts),
                ],
                [
                    'Rotation gadget decompositions',
                    formatCount(fixedModulusBfv.rotationGadgetDecompositions),
                ],
                [
                    'Total polynomial products inside gadget external products',
                    formatCount(fixedModulusBfv.gadgetPolynomialProducts),
                ],
                [
                    'Final modulus-switch coefficient roundings',
                    formatCount(fixedModulusBfv.finalModulusSwitchCoefficients),
                ],
                [
                    'Plaintext additions',
                    formatCount(fixedModulusBfv.plaintextAdditions),
                ],
                [
                    'Comparison multiplicative depth',
                    formatCount(fixedModulusBfv.comparisonDepth),
                ],
                [
                    'Ranking multiplicative depth',
                    formatCount(fixedModulusBfv.rankingDepth),
                ],
                [
                    'Comparison error bound bits',
                    formatCount(fixedModulusBfv.comparisonErrorBits),
                ],
                [
                    'Ranking error bound bits',
                    formatCount(fixedModulusBfv.rankingErrorBits),
                ],
                [
                    'Error after final modulus switch',
                    formatCount(fixedModulusBfv.releaseError),
                ],
                [
                    'Signed uniform release-noise bits',
                    formatCount(fixedModulusBfv.releaseNoiseBits),
                ],
                [
                    'Statistical target bits',
                    formatCount(fixedModulusBfv.statisticalBits),
                ],
                [
                    'Joint translated-cube bound holds',
                    fixedModulusBfv.jointStatisticalBoundHolds ? 'yes' : 'no',
                ],
                [
                    'Complete release correctness inequality holds',
                    fixedModulusBfv.releaseCorrect ? 'yes' : 'no',
                ],
                [
                    'Public key-contribution corpus bytes before sharing and proofs',
                    formatCount(fixedModulusBfv.publicKeyCorpusBytes),
                ],
            ],
        ),
        '',
        '## Supported profile census',
        '',
        'Parameters of every supported participant and option count under the derivation rules owned by the security argument. Thresholds come from the threshold completion rules; the interpolation norms are exact maxima over every subset; each share-lifting width is the widest sound limb; the ciphertext and release moduli are the smallest lengths of the fixed prime form that decode the ranking graph and satisfy the flooded release and its lifting. These are arithmetic derivations, not attack estimates, resource bounds, an implementation or admission.',
        '',
        table(
            [
                'Participants',
                'Corrupt bound',
                'Inventory threshold',
                'Release threshold',
                'Minimum turnout',
                'Interpolation ring degree',
                'Clearing factor',
                'Scaled reconstruction one-norm',
                'Simulation one-norm',
                'Joint simulation sum',
                'Sharing coefficient bits',
                'Share limb bits',
                'Share carry bits',
                'Release share bits',
                'Release quotient bits',
            ],
            supportedProfiles.profiles.map((row) => {
                const [first] = row;
                return [
                    formatCount(first.participantCount),
                    formatCount(first.maximumCorruptParticipantCount),
                    formatCount(first.inventoryCertificateThreshold),
                    formatCount(first.releaseThreshold),
                    formatCount(first.minimumTurnout),
                    formatCount(first.interpolation.interpolationRingDegree),
                    formatCount(first.interpolation.clearingFactor),
                    formatCount(
                        first.interpolation.maximumScaledReconstructionOneNorm,
                    ),
                    formatCount(first.interpolation.maximumSimulationOneNorm),
                    formatCount(
                        first.interpolation.maximumJointSimulationOneNormSum,
                    ),
                    formatCount(first.shareLifting.sharingCoefficientBits),
                    formatCount(first.shareLifting.limbBits),
                    formatCount(first.shareLifting.carryBits),
                    distinctJoined(
                        row.map((profile) => profile.releaseLifting.shareBits),
                    ),
                    distinctJoined(
                        row.map(
                            (profile) => profile.releaseLifting.quotientBits,
                        ),
                    ),
                ];
            }),
        ),
        '',
        'Ciphertext modulus bits by participant count (rows) and option count (columns):',
        '',
        table(
            [
                'Participants',
                ...supportedProfiles.optionCounts.map((count) => String(count)),
            ],
            supportedProfiles.profiles.map((row) => [
                formatCount(row[0].participantCount),
                ...row.map((profile) => formatCount(profile.ciphertext.bits)),
            ]),
        ),
        '',
        table(
            [
                'Modulus',
                'Bits',
                'Odd factor over the plaintext modulus',
                'Proth witness',
                'Gadget coordinates',
                'Profiles',
            ],
            [
                ...supportedProfiles.ciphertextModuli.map((prime) => [
                    'Ciphertext',
                    formatCount(prime.bits),
                    formatCount(
                        prime.oddFactor / fixedModulusBfv.plaintextModulus,
                    ),
                    formatCount(prime.witness),
                    formatCount(prime.gadgetLength),
                    formatCount(prime.profileCount),
                ]),
                ...supportedProfiles.releaseModuli.map((prime) => [
                    'Release',
                    formatCount(prime.bits),
                    formatCount(
                        prime.oddFactor / fixedModulusBfv.plaintextModulus,
                    ),
                    formatCount(prime.witness),
                    'none',
                    formatCount(supportedProfiles.profiles.flat().length),
                ]),
            ],
        ),
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Supported profiles',
                    formatCount(supportedProfiles.profiles.flat().length),
                ],
                [
                    'Smallest ciphertext modulus bits',
                    formatCount(supportedProfiles.minimumCiphertextModulusBits),
                ],
                [
                    'Largest ciphertext modulus bits',
                    formatCount(supportedProfiles.maximumCiphertextModulusBits),
                ],
                [
                    'Release-noise bits range',
                    supportedProfiles.releaseNoiseBitRange
                        .map((value) => formatCount(value))
                        .join(' to '),
                ],
                [
                    'Largest ranking multiplicative depth',
                    formatCount(supportedProfiles.maximumRankingDepth),
                ],
                [
                    'Largest ranking error bound bits',
                    formatCount(supportedProfiles.maximumRankingErrorBits),
                ],
                [
                    'Smallest release correctness margin bits, rounded down',
                    `\`${(Number(supportedProfiles.tightestRelease.marginHundredths) / 100).toFixed(2)}\` at ${formatCount(supportedProfiles.tightestRelease.participantCount)} participants and ${formatCount(supportedProfiles.tightestRelease.optionCount)} options`,
                ],
                [
                    'Profiles with a release correctness margin under one bit',
                    formatCount(supportedProfiles.releaseMarginsUnderOneBit),
                ],
            ],
        ),
        '',
        'Proof and body layouts of every supported profile under the same derivation rules. Each cell is the range over the option counts of one participant count.',
        '',
        table(
            [
                'Participants',
                'FHE common-matrix sample bits',
                'Setup word columns',
                'Setup affine rows',
                'Verifier message bytes',
                'Largest contribution body bytes',
                'All contribution body bytes',
                'Largest ballot body bytes',
            ],
            supportedProfiles.profiles.map((row, index) => [
                formatCount(row[0].participantCount),
                rangeOf(
                    row.map(
                        (profile) =>
                            compileCommonMatrixSamplingCensus(profile)
                                .fheBitsPerCoefficient,
                    ),
                ),
                rangeOf(
                    row.map(
                        (profile) =>
                            deriveSetupContributionShape(profile).wordColumns,
                    ),
                ),
                rangeOf(
                    row.map(
                        (profile) =>
                            deriveSetupContributionShape(profile).affineRows,
                    ),
                ),
                rangeOf(
                    row.map(
                        (profile) =>
                            compileWideChallengeCompilerCensus(profile)
                                .challengeBytes,
                    ),
                ),
                rangeOf(
                    contributionBodies[index].map(
                        (body) => body.maximumBodyBytes,
                    ),
                ),
                rangeOf(
                    contributionBodies[index].map(
                        (body) => body.maximumEligibleOfferBodies,
                    ),
                ),
                rangeOf(
                    row.map(
                        (profile) =>
                            compileBallotBodyCensus(profile).maximumBodyBytes,
                    ),
                ),
            ]),
        ),
        '',
        'Only the first `d` roster positions contribute to the setup. Every participant verifies all contributions of its roster. The mobile runtime sets the public corpus variance ceiling fifty percent above its planning target. A participant count is listed when some option count exceeds the ceiling.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Public corpus variance ceiling',
                    formatCount(publicCorpusVarianceCeiling),
                ],
                [
                    'Participant counts whose contributions exceed the variance ceiling',
                    countsAbove(publicCorpusVarianceCeiling),
                ],
            ],
        ),
        '',
        '## Composed security ledger',
        '',
        'Reference arithmetic for the all-confirmation chronology; the [candidate ledger scope](security-argument.md#registration-bound-clear-preparation-argument) owns its missing registration-source and replacement-preparation correspondence. These rows set no revised credential scope or security-bits claim. An experiment costs every gate of the adversary and of every honest operation, and each SHAKE call is charged the chi multiplications of the FIPS 202 permutations it runs. A protocol has b bits when its advantage is at most T/2^b at every cost T; the 80-bit target is split equally among the groups below. A corrupt organizer can complete several rosters of one poll, of any supported sizes, for disjoint honest groups; each honest registration confirms at most one roster, and a roster that reaches an honest opening holds at least `n-f` honest registrations, so the honest credential population bounds the number of such rosters. Statistical terms are evaluated at the query cap of the proof compiler and the largest honest credential population of a poll, and each term takes its largest value over every supported profile; every roster has one profile, so the subtotal bounds each roster, and the ledger charges it once for every roster that can reach an honest opening. The last column names the first profile that attains a term that varies between profiles. Every profile reduces the same FHE common streams modulo its own ciphertext modulus, and the adversary may fix the profile after querying them, so the FHE Ring-LWE and circular-security reductions also guess the ciphertext modulus. Required bits are the levels at which each unreduced assumption must hold for the ledger to meet the target. They are not attack estimates, a reduction or admission.',
        '',
        table(
            ['Statistical term', 'Bound exponent', 'Largest at'],
            [
                ...populationLedger.statistical.terms.map((term) => [
                    term.name,
                    signedExponent(
                        ceilingLog2({
                            numerator: term.numerator,
                            denominator:
                                1n <<
                                populationLedger.statistical.denominatorBits,
                        }),
                    ),
                    term.largestAt === undefined
                        ? 'every profile'
                        : [
                              `${term.largestAt.participantCount} participants`,
                              ...(term.largestAt.optionCount === undefined
                                  ? []
                                  : [`${term.largestAt.optionCount} options`]),
                          ].join(', '),
                ]),
                [
                    'Subtotal per roster',
                    signedExponent(
                        populationLedger.statistical.subtotalExponent,
                    ),
                    'every profile',
                ],
                [
                    'Charged for every roster',
                    signedExponent(
                        populationLedger.statistical.chargedExponent,
                    ),
                    'every profile',
                ],
            ],
        ),
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Security target bits',
                    formatCount(securityLedger.securityTargetBits),
                ],
                ['Budget groups', formatCount(securityLedger.groups.length)],
                [
                    'Budget bits per group',
                    formatCount(securityLedger.budgetBits),
                ],
                [
                    'Permutation charge gates',
                    formatCount(keccakReferenceCost.permutationCharge),
                ],
                [
                    'Widest SHAKE rate bits',
                    formatCount(keccakReferenceCost.widestRateBits),
                ],
                [
                    'Extraction routing coefficient exponent, per squared cost',
                    signedExponent(
                        ceilingLog2(largestRosterWork.quadraticCoefficient),
                    ),
                ],
                [
                    'Cell routing coefficient exponent, per cost',
                    signedExponent(
                        ceilingLog2(largestRosterWork.linearCoefficient),
                    ),
                ],
                [
                    'Extraction selection coefficient exponent, per cost',
                    signedExponent(
                        ceilingLog2(largestRosterWork.extractionCoefficient),
                    ),
                ],
                [
                    'Plain reduction coefficient exponent at the largest roster, per cost',
                    signedExponent(
                        ceilingLog2(largestRosterWork.plainCoefficient),
                    ),
                ],
                [
                    'Honest credential population of one poll within the ML-DSA-65 group',
                    formatCount(securityLedger.signatureCredentialPopulation),
                ],
                [
                    'Least honest registrations of a roster that reaches an honest opening',
                    formatCount(minimumHonestRosterMembers),
                ],
                [
                    'Largest honest credential population of one poll',
                    formatCount(securityLedger.maximumCredentialPopulation),
                ],
                [
                    'Rosters of that population that can reach an honest opening',
                    formatCount(securityLedger.maximumRosterCount),
                ],
                [
                    'Proof roles accepted across those rosters',
                    formatCount(securityLedger.maximumAcceptedProofRoles),
                ],
                [
                    'Identity collision exponent, per cost',
                    signedExponent(securityLedger.identityCollisionExponent),
                ],
                [
                    'Ciphertext moduli guessed by the FHE reductions',
                    formatCount(fheCommonStreamGuesses()),
                ],
                [
                    'FHE Ring-LWE requirement if every call cost one gate',
                    formatCount(unitCallCost.requiredBits),
                ],
            ],
        ),
        '',
        'Required bits by participant count, with one roster and one potential honest credential per participant:',
        '',
        table(
            [
                'Participants',
                'Extracted commitments',
                ...largestLedgerProfile.hybrids.map(
                    (row) =>
                        `${row.assumption}, ${row.reduction === 'plain' ? 'without' : 'with'} extraction`,
                ),
            ],
            securityLedger.profiles.map((profile) => [
                formatCount(profile.participantCount),
                formatCount(profile.extractedCommitmentCount),
                ...profile.hybrids.map((row) => formatCount(row.requiredBits)),
            ]),
        ),
        '',
        table(
            [
                'Assumption',
                'Required bits, one roster and one credential per participant',
                'Required bits at the largest credential population, every roster at the largest size',
            ],
            securityLedger.maximumRequiredBits.map((row) => [
                row.assumption,
                formatCount(row.requiredBits),
                formatCount(
                    populationLedger.maximumRequiredBits.find(
                        (value) => value.assumption === row.assumption,
                    )!.requiredBits,
                ),
            ]),
        ),
        '',
        '## Proof-field coefficient-fold bounds',
        '',
        'For radix B and reduction offset k, the first high limb is bounded by k^2+k-1. The second high limb is at most one. In the carry case the final high limb is at most k*(k^2+k-1)+k-1; otherwise it is already below B. These exact bounds justify the narrower intermediate types without changing the modulus, representatives or field product.',
        '',
        table(
            ['Property', 'Bound'],
            [
                [
                    'Largest small coefficient',
                    formatCount(proofFieldReduction.maximumSmallFactor),
                ],
                [
                    'First high limb',
                    formatCount(proofFieldReduction.maximumFirstHigh),
                ],
                [
                    'Second high limb',
                    formatCount(proofFieldReduction.maximumSecondHigh),
                ],
                [
                    'Final high limb when a second carry exists',
                    formatCount(proofFieldReduction.maximumCarriedFinalHigh),
                ],
            ],
        ),
        '',
        '## Small-limb proof-field census',
        '',
        'Proth-certified base field and certified cubic extension for the lookup direction. Large-modulus equations require a separate integer limb-and-carry compiler with complete bounds.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Base-field modulus',
                    formatCount(smallLimbProofField.modulus),
                ],
                ['Word radix', formatCount(smallLimbProofField.wordRadix)],
                [
                    'Reduction offset',
                    formatCount(smallLimbProofField.reductionOffset),
                ],
                [
                    'Proth odd factor',
                    formatCount(smallLimbProofField.oddFactor),
                ],
                [
                    'Proth witness',
                    formatCount(smallLimbProofField.prothWitness),
                ],
                [
                    'Cubic nonresidue',
                    formatCount(smallLimbProofField.cubicNonresidue),
                ],
                [
                    'Field bits',
                    formatCount(smallLimbProofField.modulusBitLength),
                ],
                [
                    'Packed base-field bytes',
                    formatCount(
                        smallLimbProofField.packedFieldElementByteLength,
                    ),
                ],
                [
                    'Packed extension-field bytes',
                    formatCount(
                        smallLimbProofField.packedExtensionElementByteLength,
                    ),
                ],
                [
                    'Certified transform order',
                    formatCount(smallLimbProofField.transformOrder),
                ],
                [
                    'Certified transform root',
                    formatCount(smallLimbProofField.transformRoot),
                ],
            ],
        ),
        '',
        '## Simulator recipient-key availability',
        '',
        'An encryption reduction with one unknown honest recipient key uses other honest recipient keys for corrupt-contribution interpolation. These are combinatorial availability counts only; the actual sharing scheme, decryption correctness and ciphertext/proof contracts remain separate. More than one unknown key is not silently assumed to satisfy the same count.',
        '',
        table(
            [
                'Participants',
                'Corruption bound',
                'Required evaluations',
                'Known honest keys with one challenge',
                'Maximum unknown honest keys from the count alone',
            ],
            compileSimulatorKeyKnowledgeCensus().map((value) => [
                formatCount(value.participants),
                formatCount(value.faults),
                formatCount(value.threshold),
                formatCount(value.knownHonestWithOneChallenge),
                formatCount(value.maximumUnknownHonestKeys),
            ]),
        ),
        '',
        '## Early commitment extraction census',
        '',
        'DFMS21 Corollary 4.8 for full-body contribution commitments, including losing frozen inventory views. Fixed-suite public matrices remove the former seed-commitment stage. The sum charges both simulator disturbance and valid-opening mismatch. Theorem 4.3 additionally gives O(Q*E*Time[f] + Q^2): the displayed coefficients do not instantiate its constants, reversible gate costs, or the rest of the reduction. This is an ideal-QROM arithmetic bound, not a setup or fixed-hash security claim.',
        '',
        table(
            [
                'Participants',
                'Relevant commitments',
                'Hash output bits',
                'Quantum query bound',
                'Relation-evaluation coefficient Q*E',
                'Quadratic-query coefficient Q^2',
                'Combined failure exponent',
            ],
            [10, 20].map((participantCount) => {
                const bound =
                    compileCommitmentExtractionBound(participantCount);
                return [
                    formatCount(participantCount),
                    formatCount(bound.extractedCommitmentCount),
                    formatCount(bound.hashOutputBitLength),
                    formatCount(bound.quantumQueryCount),
                    formatCount(bound.simulatorRelationEvaluationCoefficient),
                    formatCount(bound.simulatorQuadraticQueryCoefficient),
                    bound.combinedFailureExponent === undefined
                        ? 'No extraction event'
                        : formatCount(bound.combinedFailureExponent),
                ];
            }),
        ),
        '',
        'The fixed-output rows above are the baseline. A coherent SHAKE prefix wrapper computes a complete finite stream value, copies only the requested prefix and uncomputes the complete value. The following stream rows charge its full-value oracle calls and retain the same normalized prefix-match ratios from DFMS21 Remark 4.2. The finite stream width remains a separate resource operand; a fixed body/hash width does not bound every adversarial input or output.',
        '',
        table(
            [
                'Participants',
                'Stream wrapper',
                'Logical stream accesses',
                'Simulated full-value queries',
                'Quadratic-query coefficient',
                'Combined failure exponent',
            ],
            [10, 20].flatMap((participants) =>
                [1n, prefixReplacementBaseQueriesPerAccess].map(
                    (baseQueriesPerAccess) => {
                        const logical =
                                compileCommitmentExtractionBound(
                                    participants,
                                ).quantumQueryCount,
                            bound = compileCommitmentExtractionBound(
                                participants,
                                baseQueriesPerAccess *
                                    prefixOracleQueriesPerAccess *
                                    logical,
                            );
                        return [
                            formatCount(participants),
                            baseQueriesPerAccess === 1n
                                ? 'Base stream'
                                : 'Programmed stream',
                            formatCount(logical),
                            formatCount(bound.quantumQueryCount),
                            formatCount(
                                bound.simulatorQuadraticQueryCoefficient,
                            ),
                            bound.combinedFailureExponent === undefined
                                ? 'No extraction event'
                                : formatCount(bound.combinedFailureExponent),
                        ];
                    },
                ),
            ),
        ),
        '',
        '## Compressed-oracle circuit work',
        '',
        "The declared gate basis is X, CNOT, Toffoli and controlled-H, each acting on at most three qubits. The sorted database uses one spare tuple while routing the queried value to a separate register. Clean computation includes inverse evaluation and register swaps. These bounded examples verify the circuit family; they are not the protocol's full input domain or query population.",
        '',
        table(
            [
                'Prior queries',
                'Input bits',
                'Hash bits',
                'Removal compute gates',
                'Insertion compute gates',
                'Clean routing gates',
                'Oracle-call gates',
                'Oracle qubits',
            ],
            [
                [0n, 2n, 1n],
                [1n, 2n, 1n],
                [2n, 2n, 1n],
                [1n, 1n, 2n],
            ].map(([prior, input, output]) => {
                const work = sparseRoutingWork(prior, input, output);
                return [
                    prior,
                    input,
                    output,
                    work.removeGates,
                    work.insertGates,
                    work.routingGates,
                    work.roundTripRoutingGates + work.localUpdateGates,
                    work.routingQubits + output,
                ].map(formatCount);
            }),
        ),
        '',
        table(
            [
                'Local hash output bits',
                'Controlled-H gates',
                'X gates',
                'CNOT gates',
                'Toffoli gates',
                'Total local update gates',
            ],
            [1n, 2n, 3n, 512n].map((bits) => {
                const work = sparseRoutingWork(0n, 1n, bits);
                return [
                    bits,
                    work.localUpdate.controlledHadamard,
                    work.localUpdate.not,
                    work.localUpdate.cnot,
                    work.localUpdate.toffoli,
                    work.localUpdateGates,
                ].map(formatCount);
            }),
        ),
        '',
        'Classical extraction computes the first matching active entry into a fresh output and cleans all predicate work before measuring that output. The following labelled-hash examples include their predicate computation; a different sender parser needs its actual relation circuit. Other adversary registers, circuit-generation work, full oracle routing and computational-assumption advantages remain separate.',
        '',
        table(
            [
                'Database capacity',
                'Input bits',
                'Hash bits',
                'Label bits',
                'Classical extraction gates',
                'Measured output qubits',
                'Extraction qubits',
            ],
            [
                [0n, 2n, 1n, 1n],
                [1n, 2n, 1n, 1n],
                [2n, 2n, 1n, 1n],
                [3n, 64n, 512n, 16n],
            ].map(([capacity, input, output, label]) =>
                [
                    capacity,
                    input,
                    output,
                    label,
                    labelledHashExtractionWork(capacity, input, output, label)
                        .extractionGates,
                    labelledHashExtractionWork(capacity, input, output, label)
                        .measuredQubits,
                    labelledHashExtractionWork(capacity, input, output, label)
                        .extractionQubits,
                ].map(formatCount),
            ),
        ),
        '',
        'The following supplied-width prefix examples include both full-value calls, clean prefix-copy work and its extra workspace. They do not assign a maximum stream width or a complete participant/reduction total.',
        '',
        table(
            [
                'Logical accesses',
                'Input bits',
                'Maximum stream bits',
                'Full-value queries',
                'Clean prefix-copy gates per access',
                'Query gates',
                'Oracle qubit bound',
            ],
            [
                [1n, 2n, 1n],
                [1n, 2n, 2n],
                [3n, 64n, 512n],
            ].map(([queries, input, output]) => {
                const work = prefixOracleWork(queries, input, output);
                return [
                    queries,
                    input,
                    output,
                    work.fullValueQueries,
                    work.copyGates,
                    work.queryGates,
                    work.maximumQubits,
                ].map(formatCount);
            }),
        ),
        '',
        'The domain adapter below visits every eligible input-length class and output chunk for each declared query shape. Cells retain their databases across shape changes. Counts include clean length/sentinel controllers and all prefix calls. These are supplied-shape circuit bounds; extraction, other algorithm registers and classical circuit generation/dispatch remain separate. The full contribution row uses its actual maximum emitted input length for one honest query and does not bound adversarial queries.',
        '',
        table(
            [
                'Query shape',
                'Logical queries',
                'Input capacity bits',
                'Output capacity bits',
                'First chunk bits',
                'Cells',
                'Full-value calls',
                'Controller gates',
                'Total query gates',
                'Database qubits',
                'Oracle qubit bound',
            ],
            [
                {
                    name: 'Small correspondence',
                    count: 3n,
                    inputCapacity: 3n,
                    outputCapacity: 5n,
                    firstChunkBits: 2n,
                },
                {
                    name: 'Complete contribution input',
                    count: 1n,
                    inputCapacity:
                        8n *
                        compileContributionBodyCensus(completion)
                            .maximumHashInputBytes,
                    outputCapacity: 512n,
                    firstChunkBits: 512n,
                },
            ].map(({ name, firstChunkBits, ...run }) => {
                const work = oracleDomainWork([run], firstChunkBits);
                return [
                    name,
                    ...[
                        run.count,
                        run.inputCapacity,
                        run.outputCapacity,
                        firstChunkBits,
                        BigInt(work.cells.length),
                        work.fullValueQueries,
                        work.controllerGates,
                        work.queryGates,
                        work.databaseQubits,
                        work.maximumQubits,
                    ].map(formatCount),
                ];
            }),
        ),
        '',
        'A programmed-prefix read calls the complete base stream adapter twice around a clean replacement copy. The following bounded shape counts both layers and retains prior component capacity. Classical record payload excludes object metadata and dispatch work; neither is declared free.',
        '',
        table(
            [
                'Logical reads',
                'Input capacity bits',
                'Output capacity bits',
                'Replacement input bits',
                'Replacement prefix bits',
                'Full-value calls',
                'Replacement-copy gates',
                'Total query gates',
                'Oracle qubit bound',
                'Classical record payload bits',
            ],
            [[3n, 4n, 5n, 3n, 4n]].map(
                ([
                    count,
                    inputCapacity,
                    outputCapacity,
                    inputBits,
                    prefixBits,
                ]) => {
                    const work = programmedOracleDomainWork(
                        [{ count, inputCapacity, outputCapacity }],
                        2n,
                        [{ inputBits, prefixBits }],
                    );
                    return [
                        count,
                        inputCapacity,
                        outputCapacity,
                        inputBits,
                        prefixBits,
                        work.base.fullValueQueries,
                        work.copyGates,
                        work.queryGates,
                        work.maximumQubits,
                        work.classicalRecordPayloadBits,
                    ].map(formatCount);
                },
            ),
        ),
        '',
        'The hidden-slice example keeps two independent shadows before one opening and one afterward. It preserves both databases and the programmed background across stages. Slice selection, nested background copies and all shadow calls are charged; record metadata, initialization and complete reduction-time conversion remain separate.',
        '',
        table(
            [
                'Background full-value calls',
                'Shadow full-value calls',
                'Slice-controller gates',
                'Replacement-copy gates',
                'Total query gates',
                'Oracle qubit bound',
                'Classical slice prefix bits',
                'Maximum programming record payload bits',
            ],
            [
                (() => {
                    const work = shadowOracleDomainWork(
                        [
                            {
                                count: 2n,
                                inputCapacity: 4n,
                                outputCapacity: 3n,
                                activeShadows: [0, 1],
                                replacements: [],
                            },
                            {
                                count: 3n,
                                inputCapacity: 4n,
                                outputCapacity: 3n,
                                activeShadows: [1],
                                replacements: [
                                    { inputBits: 4n, prefixBits: 2n },
                                ],
                            },
                        ],
                        2n,
                        [2n, 3n],
                    );
                    return [
                        work.base.fullValueQueries,
                        work.shadows.reduce(
                            (sum, value) => sum + value.fullValueQueries,
                            0n,
                        ),
                        work.routingGates,
                        work.copyGates,
                        work.queryGates,
                        work.maximumQubits,
                        work.classicalSlicePrefixBits,
                        work.maximumProgrammingRecordPayloadBits,
                    ].map(formatCount);
                })(),
            ],
        ),
        '',
        '## Full-body commitment equivocation census',
        '',
        'The original whole-message extension uses a separate hidden salt slice for each potential honest credential, with one commitment per sender scope. The fixed credential tape also charges unused credentials, preserving adaptive activation inside the wrapper. These supplied scope caps are conditional operands, not derived lifetime limits. Its bound sums the single-sender one-way-to-hiding hybrids and does not multiply by the body bit length. The ideal-XOF credential-collision term accounts separately for equal original seeds and equal public matrix-seed prefixes. Controlled oracle calls exclude credential generation, routing, input/output processing and actual oracle-simulator cost; complete reduction time and fixed-function correspondence remain open.',
        '',
        table(
            [
                'Participants',
                'Potential credential scope cap',
                'Salt bits',
                'Quantum query bound',
                'Failure exponent',
                'Controlled oracle call bound',
                'Ideal credential-collision numerator',
                'Ideal credential-collision denominator',
            ],
            [
                [10, 10n],
                [10, 30n],
                [20, 20n],
            ].map(([participantCount, scopes]) => {
                const bound = compileCommitmentEquivocationBound(
                    Number(participantCount),
                    BigInt(scopes),
                );
                return [
                    formatCount(participantCount),
                    formatCount(bound.credentialScopeCount),
                    formatCount(bound.saltBitLength),
                    formatCount(bound.quantumQueryCount),
                    formatCount(bound.failureExponent),
                    formatCount(bound.maximumControlledOracleCalls),
                    formatCount(bound.credentialCollisionNumerator),
                    formatCount(bound.credentialCollisionDenominator),
                ];
            }),
        ),
        '',
        'The finite model compares exact joint density matrices conditioned on the complete post-opening oracle and public transcript. Its alternate constructions test incomplete masking, retained shadow values, and unwanted changes to the uncommitted output suffix. This enumerates selected receivers rather than proving quantum security.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Full-message real cases',
                    formatCount(commitmentEquivocation.realCases),
                ],
                [
                    'Full-message simulated cases',
                    formatCount(commitmentEquivocation.simulatedCases),
                ],
                [
                    'Full-message classical blocks',
                    formatCount(commitmentEquivocation.classicalBlocks),
                ],
                [
                    'Full-message differing entries',
                    formatCount(commitmentEquivocation.differingEntries),
                ],
                [
                    'Prefix-programming simulated cases',
                    formatCount(commitmentPrefix.simulatedCases),
                ],
                [
                    'Prefix-programming differing entries',
                    formatCount(commitmentPrefix.differingEntries),
                ],
                [
                    'Duplicate-input distinguishing events',
                    formatCount(duplicateCommitmentInputs.simulatedEvents),
                ],
                [
                    'Duplicate-input simulated cases',
                    formatCount(duplicateCommitmentInputs.simulatedCases),
                ],
            ],
        ),
        '',
        '## Close-response census',
        '',
        "Each roster uses the close quorum `q = n - f`, guarantees inclusion of an on-time envelope that `f + 1` honest participants received before responding, and omits at most `f` honest ballots. A response lists at most two envelopes per slot. With every honest participant voting, omitting `f` honest ballots while every corrupt participant abstains leaves `n - 2f` accepted ballots. The stage bound adds three preparation visits to the ballot, close response, target signature, release share and verification; the organizer's close intent and proposal replace its response and signature. Prioritized message-level executions attain every stage bound.",
        '',
        table(
            [
                'Participants',
                'Maximum corrupt',
                'Close quorum',
                'Inclusion holders',
                'Maximum honest omission',
                'Accepted at full honest turnout after omission',
                'Minimum turnout',
                'No result forceable',
                'Maximum listed envelopes per response',
                'Organizer visits',
                'Voter visits',
                'Nonvoter visits',
            ],
            closeResponses.profiles.map((profile) => [
                formatCount(profile.participantCount),
                formatCount(profile.faultBound),
                formatCount(profile.quorum),
                formatCount(profile.inclusionHolderThreshold),
                formatCount(profile.maximumHonestOmission),
                formatCount(profile.acceptedAtFullHonestTurnoutAfterOmission),
                formatCount(profile.minimumTurnout),
                profile.noResultForceableAtFullHonestTurnout ? 'yes' : 'no',
                formatCount(profile.maximumListedEntriesPerResponse),
                formatCount(profile.visits.organizerStageBound),
                formatCount(profile.visits.voterStageBound),
                formatCount(profile.visits.nonvoterStageBound),
            ]),
        ),
        '',
        'The joint views enumerate every held set, answered intent, proposal and corrupt listing for three and four participants, including a corrupt organizer with two close times. Nonorganizer positions have identical roles, so one nonorganizer corruption represents each. Every 64th view is rebuilt through the reference response, proposal, inventory and contract checks.',
        '',
        table(
            [
                'Participants',
                'Corruption cases',
                'Views',
                'Inventories',
                'Reference cross-checks',
                'Maximum honest omission',
                'No-result inventories',
                'Contract findings',
            ],
            closeResponses.joint.map((census) => [
                formatCount(census.participantCount),
                formatCount(census.corruptionCases),
                formatCount(census.views),
                formatCount(census.inventories),
                formatCount(census.referenceCrossChecks),
                formatCount(census.maximumHonestOmission),
                formatCount(census.noResultInventories),
                census.findings.length === 0
                    ? 'none'
                    : census.findings.join(', '),
            ]),
        ),
        '',
        'The brute force covers every corruption set, every proposal containing the organizer and every honest lister set.',
        '',
        table(
            [
                'Participants',
                'Corruption sets',
                'Proposals',
                'Lister sets',
                'Minimum inclusion margin',
                'Maximum honest authors outside a proposal',
                'Tight omission witness',
            ],
            closeResponses.bruteForce.map((census) => [
                formatCount(census.participantCount),
                formatCount(census.corruptionSets),
                formatCount(census.proposals),
                formatCount(census.listerSetChecks),
                formatCount(census.minimumInclusionMargin),
                formatCount(census.maximumOmittedAuthors),
                census.tightOmissionWitness ? 'yes' : 'no',
            ]),
        ),
        '',
        "The message-level executions cover every completion-profile corruption set with an honest or corrupt organizer, full and partial honest turnout, departures before the close and after certification, relay isolation of `f` honest voters, and corrupt equivocation, backdating, withheld bodies, abstention, refused signatures and replayed messages of another action. In the targeted executions the corrupt participants sign no response, fill the two body slots of an honest organizer with late envelopes and give every other honest participant a different on-time envelope. In the organizer-only executions the relay shows corrupt ballots and responses to the organizer alone. In the hidden executions corrupt authors give their ballots to every honest participant but the organizer before the close and sign no response. Every participant holds at most two bodies for one slot and discards late ones at its intent lock. With its response, each other responder forwards the body of every other slot it lists alone that the organizer did not hold at its intent lock, and the organizer reads a body it lacks from its author or from such a copy. A signer verifies a proposal once its named responses, listed envelopes and usable bodies reached it, which the organizer's closure supplies.",
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Corruption sets',
                    formatCount(closeResponses.execution.corruptionSets),
                ],
                [
                    'Executions',
                    formatCount(closeResponses.execution.executions),
                ],
                [
                    'Certified executions',
                    formatCount(closeResponses.execution.certifiedExecutions),
                ],
                [
                    'Maximum honest omission',
                    formatCount(closeResponses.execution.maximumHonestOmission),
                ],
                [
                    'No result at full honest turnout',
                    formatCount(
                        closeResponses.execution.forcedNoResultExecutions,
                    ),
                ],
                [
                    'Largest honest response listing',
                    formatCount(closeResponses.execution.maximumListedEntries),
                ],
                [
                    'Certified targeted executions',
                    `${formatCount(closeResponses.execution.targetedCertifiedExecutions)} of ${formatCount(closeResponses.execution.targetedExecutions)}`,
                ],
                [
                    'Certified organizer-only executions',
                    `${formatCount(closeResponses.execution.organizerOnlyCertifiedExecutions)} of ${formatCount(closeResponses.execution.organizerOnlyExecutions)}`,
                ],
                [
                    'Certified hidden executions',
                    `${formatCount(closeResponses.execution.hiddenCertifiedExecutions)} of ${formatCount(closeResponses.execution.hiddenExecutions)}`,
                ],
                [
                    'Most bodies one responder forwards',
                    formatCount(
                        closeResponses.execution.maximumForwardedPerResponder,
                    ),
                ],
                [
                    'Most bodies one responder forwards to an honest organizer',
                    formatCount(
                        closeResponses.execution
                            .maximumForwardedToHonestOrganizer,
                    ),
                ],
                [
                    'Most bodies held at once for one slot',
                    formatCount(closeResponses.execution.maximumHeldPerSlot),
                ],
                [
                    'Most bodies received for one honest slot',
                    formatCount(
                        closeResponses.execution.maximumReceivedPerHonestSlot,
                    ),
                ],
                [
                    'Most bodies received for one corrupt slot',
                    formatCount(
                        closeResponses.execution.maximumReceivedPerCorruptSlot,
                    ),
                ],
                [
                    'Most organizer body requests for one slot',
                    formatCount(
                        closeResponses.execution
                            .maximumOrganizerRequestsPerSlot,
                    ),
                ],
                [
                    'Contract findings',
                    closeResponses.execution.findings.length === 0
                        ? 'none'
                        : closeResponses.execution.findings.join(', '),
                ],
            ],
        ),
        '',
        'Each review obligation fails under its variant and holds under the maintained rule. The support-rule row replays the rejected organizer-selected union, the author-route row replays signers that read records only from their authors and responders, and the author-body row replays an organizer that reads bodies only from their authors.',
        '',
        table(
            ['Variant', 'Outcome'],
            [
                [
                    'Holdings lost at a restart before responding',
                    closeResponses.counterexamples.volatileRetentionFindings.join(
                        ', ',
                    ),
                ],
                [
                    'Holdings retained until the response',
                    closeResponses.counterexamples.durableRetentionFindings
                        .length === 0
                        ? 'none'
                        : closeResponses.counterexamples.durableRetentionFindings.join(
                              ', ',
                          ),
                ],
                [
                    'Omitted voters and corrupt participants refuse target signatures',
                    `${formatCount(closeResponses.counterexamples.refusalHonestSigners)} honest signers of ${formatCount(closeResponses.counterexamples.refusalQuorum)}, ${formatCount(closeResponses.counterexamples.refusalCertifiedTargets)} certified targets`,
                ],
                [
                    'Omitted voters sign the valid target',
                    `${formatCount(closeResponses.counterexamples.omittedSignerCertifiedTargets)} certified target with ${formatCount(closeResponses.counterexamples.omittedSignerHonestOmission)} honest omissions`,
                ],
                [
                    `Unlimited per-slot listing, ${String(closeResponses.counterexamples.equivocations)} equivocations`,
                    `${formatCount(closeResponses.counterexamples.uncappedResponseEntries)} entries`,
                ],
                [
                    'Two envelopes per slot',
                    `${formatCount(closeResponses.counterexamples.cappedResponseEntries)} entries`,
                ],
                [
                    'Organizer answers at its intent; a corrupt author then fills its body slots and splits the others',
                    `${formatCount(closeResponses.counterexamples.earlyOrganizerSelection)} of ${formatCount(closeResponses.counterexamples.organizerStallQuorum)} responses selected`,
                ],
                [
                    'Organizer answers at its proposal and lists two known envelopes',
                    `${formatCount(closeResponses.counterexamples.lateOrganizerSelection)} of ${formatCount(closeResponses.counterexamples.organizerStallQuorum)} responses selected`,
                ],
                [
                    'Support rule includes a ballot every honest participant holds',
                    closeResponses.counterexamples.supportRuleIncludesEnvelope
                        ? 'yes'
                        : 'no',
                ],
                [
                    'Union rule includes it',
                    closeResponses.counterexamples.unionRuleIncludesEnvelope
                        ? 'yes'
                        : 'no',
                ],
                [
                    'Signers read only authors and responders; a corrupt author and responder show theirs to the organizer alone',
                    `${formatCount(closeResponses.counterexamples.authorRouteCertifiedTargets)} certified targets, findings: ${closeResponses.counterexamples.authorRouteFindings.join(', ')}`,
                ],
                [
                    'The organizer reads bodies only from their authors; a corrupt author hides its ballot from the organizer alone',
                    `${formatCount(closeResponses.counterexamples.authorBodyCertifiedTargets)} certified targets, findings: ${closeResponses.counterexamples.authorBodyFindings.join(', ')}`,
                ],
                [
                    'Responders forward the bodies the organizer did not hold at its lock',
                    `${formatCount(closeResponses.counterexamples.forwardingCertifiedTargets)} certified target, findings: ${
                        closeResponses.counterexamples.forwardingFindings
                            .length === 0
                            ? 'none'
                            : closeResponses.counterexamples.forwardingFindings.join(
                                  ', ',
                              )
                    }`,
                ],
                [
                    'The organizer publishes its closure before its proposal',
                    `${formatCount(closeResponses.counterexamples.closureCertifiedTargets)} certified target, findings: ${
                        closeResponses.counterexamples.closureFindings
                            .length === 0
                            ? 'none'
                            : closeResponses.counterexamples.closureFindings.join(
                                  ', ',
                              )
                    }`,
                ],
            ],
        ),
        '',
        '## Threshold release flooding bound',
        '',
        'For ten participants and release threshold four, one rational-ring implementation enumerates every coefficient over the reduced degree-eight negacyclic subring, while the independent modular-ring model obtains the same maxima. The KLLPS26 trigonometric expression remains as a looser analytic cross-check. All noise-budget figures are floors from the dominant flooding term only: they omit the expanded public-proof radius, remaining correctness terms, proof slack, multi-query and multi-session unions, and hidden constants. They are not approved FHE parameters.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Authorized release subsets enumerated',
                    formatCount(thresholdReleaseNoise.authorizedSubsetCount),
                ],
                [
                    'Production interpolation-point exponent stride',
                    formatCount(
                        thresholdReleaseNoise.productionInterpolationPointExponentStride,
                    ),
                ],
                [
                    'Bounded-integer scaled reconstructions checked',
                    formatCount(
                        thresholdReleaseNoise.boundedIntegerSharingReconstructionCount,
                    ),
                ],
                [
                    'Lagrange coefficients enumerated',
                    formatCount(thresholdReleaseNoise.lagrangeCoefficientCount),
                ],
                [
                    'Exact maximum scaled reconstruction coefficient one-norm',
                    formatCount(
                        thresholdReleaseNoise.exactMaximumScaledReconstructionCoefficientOneNorm,
                    ),
                ],
                [
                    'Exact maximum simulation coefficient one-norm',
                    formatCount(
                        thresholdReleaseNoise.exactMaximumSimulationCoefficientOneNorm,
                    ),
                ],
                [
                    'Maximum sum of simulation coefficient one-norms over all honest releases',
                    formatCount(
                        thresholdReleaseNoise.exactMaximumJointSimulationCoefficientOneNormSum,
                    ),
                ],
                [
                    'Joint-release dominant noise reserve at 80 statistical bits',
                    formatCount(
                        thresholdReleaseNoise.jointTargetSecurityDominantNoiseReserveBitLength,
                    ),
                ],
                [
                    'Exact interpolation product',
                    formatCount(
                        thresholdReleaseNoise.exactInterpolationProduct,
                    ),
                ],
                [
                    'Trigonometric interpolation-product upper bound',
                    `\`${thresholdReleaseNoise.interpolationProductBound.toFixed(6)}\``,
                ],
                [
                    'Exact dominant noise-budget floor at 80 statistical bits',
                    formatCount(
                        thresholdReleaseNoise.exactTargetSecurityDominantNoiseBudgetLowerBoundBitLength,
                    ),
                ],
                [
                    'Exact dominant noise-budget floor at 128 statistical bits',
                    formatCount(
                        thresholdReleaseNoise.exactConservativeSecurityDominantNoiseBudgetLowerBoundBitLength,
                    ),
                ],
                [
                    'Analytic dominant noise-budget floor at 80 statistical bits',
                    formatCount(
                        thresholdReleaseNoise.targetSecurityDominantNoiseBudgetLowerBoundBitLength,
                    ),
                ],
                [
                    'Analytic dominant noise-budget floor at 128 statistical bits',
                    formatCount(
                        thresholdReleaseNoise.conservativeSecurityDominantNoiseBudgetLowerBoundBitLength,
                    ),
                ],
            ],
        ),
        '',
        '## Close wire census',
        '',
        'Exact canonical lengths of the signed close messages and bounds on the closure of one close barrier. A response lists at most two envelopes for one slot, and a proposal names exactly `q` responses. A response is authenticated against its listed envelopes alone; only a usable slot needs its complete body, so conflicting corrupt envelopes add envelope metadata but no body. An honest author signs one envelope, so only the `f` corrupt slots can exceed one union envelope. A participant holds at most two complete bodies for one slot; its intent lock discards late bodies and refuses later ones, so a corrupt slot can deliver at most two bodies before the lock and two after it. Delivery adds a new envelope to a slot only while fewer than two are known, and the lock also discards late envelopes. The organizer answers only when it can propose, lists two known envelopes of a slot without their bodies, and requests at most one body for a slot. Only the organizer takes responses; it retains the first of each responder with exactly the listed envelopes it did not know. Packets add a four-byte body length and the signature. The bounds exclude setup bytes, target evaluation, certificates, release shares and storage-engine overhead.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Envelope bytes', formatCount(ballotBody.envelopeBytes)],
                [
                    'Closure submission bytes',
                    formatCount(
                        compileCloseWireCensus(completion).submissionBytes,
                    ),
                ],
                [
                    'Close intent body bytes',
                    formatCount(
                        compileCloseWireCensus(completion).intentBodyBytes,
                    ),
                ],
                [
                    'Empty response body bytes',
                    formatCount(
                        compileCloseWireCensus(completion)
                            .minimumResponseBodyBytes,
                    ),
                ],
            ],
        ),
        '',
        table(
            [
                'Participants',
                'Close quorum',
                'Maximum response body bytes',
                'Proposal body bytes',
                'Maximum union envelopes',
                'Maximum barrier metadata bytes',
                'Barrier signature checks',
                'Maximum held bodies',
                'Maximum received bodies',
                'Maximum known envelopes',
                'Maximum organizer known envelopes',
            ],
            thresholdProfiles.map(({ participantCount }) => {
                const value = compileCloseWireCensus(
                    deriveSupportedProfile(
                        participantCount,
                        completionProfileCounts.optionCount,
                    ),
                );
                return [
                    formatCount(participantCount),
                    formatCount(value.closeQuorum),
                    formatCount(value.maximumResponseBodyBytes),
                    formatCount(value.proposalBodyBytes),
                    formatCount(value.maximumUnionEnvelopes),
                    formatCount(value.maximumBarrierMetadataBytes),
                    formatCount(value.barrierSignatureVerifications),
                    formatCount(value.maximumHeldBodies),
                    formatCount(value.maximumReceivedBodies),
                    formatCount(value.maximumKnownEnvelopes),
                    formatCount(value.maximumOrganizerKnownEnvelopes),
                ];
            }),
        ),
        '',
        'Each response carries its listed envelopes in order and a retrievable body for each singly listed slot, including its author. The organizer publishes every usable body in its proposal closure. Body locators are reused only after complete byte comparison with authenticated custody; unavailable originals are uploaded from that same custody. The following payload bounds are separate from the routing records and readback costs in the complete workflow screen.',
        '',
        table(
            [
                'Participants',
                'Listed envelope copy bytes',
                'Most forwarded bodies',
                'Most forwarded body bytes',
            ],
            thresholdProfiles.map(({ participantCount }) => {
                const value = compileCloseWireCensus(
                    deriveSupportedProfile(
                        participantCount,
                        completionProfileCounts.optionCount,
                    ),
                );
                return [
                    formatCount(participantCount),
                    formatCount(value.maximumListedCopyBytes),
                    formatCount(value.maximumForwardedBodies),
                    formatCount(value.maximumForwardedBodyBytes),
                ];
            }),
        ),
    ].join('\n')}\n`;
};

const normalizeCensusLine = (line: string): string =>
    line.startsWith('|')
        ? line
              .split('|')
              .map((cell) => cell.trim().replace(/^-{3,}$/u, '---'))
              .join('|')
        : line;

const normalizeCensusText = (text: string): string[] =>
    text.replace(/\r\n/g, '\n').split('\n').map(normalizeCensusLine);

export const findFirstCensusMismatch = (
    stored: string,
    rendered: string,
): number | undefined => {
    const storedLines = normalizeCensusText(stored);
    const renderedLines = normalizeCensusText(rendered);
    const length = Math.max(storedLines.length, renderedLines.length);
    for (let index = 0; index < length; index += 1) {
        if (storedLines[index] !== renderedLines[index]) return index + 1;
    }
    return undefined;
};

const usage =
    'Usage: generate-documentation-census.ts (--output <file> | --check <file> | --print)';

const main = async (): Promise<void> => {
    const rawArguments = process.argv.slice(2);
    const argumentsList =
        rawArguments[0] === '--' ? rawArguments.slice(1) : rawArguments;
    const rendered = renderDocumentationCensus();
    if (argumentsList.length === 1 && argumentsList[0] === '--print') {
        process.stdout.write(rendered);
        return;
    }
    if (argumentsList.length !== 2 || argumentsList[1] === undefined) {
        throw new Error(usage);
    }
    const targetPath = path.resolve(argumentsList[1]);
    if (argumentsList[0] === '--output') {
        await writeFile(targetPath, rendered, 'utf8');
        process.stdout.write(
            `Wrote ${String(Buffer.byteLength(rendered))} bytes to ${targetPath}\n`,
        );
        return;
    }
    if (argumentsList[0] === '--check') {
        const stored = await readFile(targetPath, 'utf8');
        const mismatch = findFirstCensusMismatch(stored, rendered);
        if (mismatch !== undefined) {
            throw new Error(
                `The stored census is stale at line ${String(mismatch)}; regenerate it with --output.`,
            );
        }
        process.stdout.write('The stored census matches the models.\n');
        return;
    }
    throw new Error(usage);
};

if (import.meta.main) await main();
