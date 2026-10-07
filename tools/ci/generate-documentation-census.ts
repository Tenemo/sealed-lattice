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
import {
    compileClearPreparationLedger,
    compileClearPreparationPollPopulations,
} from '#tests/clear-preparation-ledger-model.js';
import { compileClearPreparationResources } from '#tests/clear-preparation-resource-model.js';
import { compileCloseResponseCensus } from '#tests/close-response-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import {
    compareCommitmentEquivocationHybrids,
    compareDuplicateCommitmentInputs,
} from '#tests/commitment-equivocation-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import {
    compileCommonMatrixSamplingCensus,
    compileCommonMatrixInitializationCensus,
} from '#tests/common-matrix-sampling-model.js';
import {
    sparseRoutingWork,
    labelledHashExtractionWork,
    prefixOracleWork,
    oracleMaskRoutingWork,
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
    compilePrivateRandomnessScopes,
    operationSeedBytes,
    operationSeedCount,
} from '#tests/operation-seed-model.js';
import {
    compileClassicalReaderOracleBudget,
    compileFullCircuitOracleBudget,
    compileOraclePermutationBudget,
    shakePermutationGateCharge,
} from '#tests/oracle-budget-model.js';
import {
    oracleDomainWork,
    programmedOracleDomainWork,
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
    firstOracleResumeHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import {
    compileFirstOracleReadVariation,
    compileProofRandomnessBudgets,
} from '#tests/proof-randomness-budget-model.js';
import { compileProofVerifierQueryCensus } from '#tests/proof-verifier-query-model.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import { compileRecipientKeyUniquenessBound } from '#tests/recipient-key-uniqueness-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import {
    compileRegistrationSetupBindingScreen,
    sourceOpeningSaltBytes,
} from '#tests/registration-setup-binding-model.js';
import { minimumRegistrationSourceInputBytes } from '#tests/registration-source-domain-model.js';
import {
    compileRegistrationSourceRandomness,
    compileRegistrationSourceExtractionWork,
} from '#tests/registration-source-randomness-model.js';
import { compileRelationIntegerLiftingCensus } from '#tests/relation-integer-lifting-model.js';
import { compileReleaseShareLiftingCensus } from '#tests/release-share-lifting-model.js';
import { compileReleaseVerificationWorkload } from '#tests/release-verification-work-model.js';
import { compileRnsArithmeticResourceCensus } from '#tests/rns-arithmetic-resource-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import {
    atMost,
    compileAuthenticationGroup,
    compileIdentityCollisionGroup,
    compileRecordCreationPricing,
    compileSecurityLedger,
    compileSemanticUseCharges,
    compileSoundnessCharge,
    compileStatisticalTerms,
    ledgerGroups,
    maximumChargedQueries,
    rational,
    rationalCeilingLog2,
    soundnessChargeAt,
    statisticalRatioAt,
    type Rational,
    type StatisticalTerm,
} from '#tests/security-ledger-model.js';
import {
    compileFhePopulationLimits,
    compileSecurityMarginScreen,
    instanceAttackScreens,
    populationSearchCap,
    type ReductionVariant,
} from '#tests/security-margin-screen-model.js';
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
import { compileSetupShareArithmeticBounds } from '#tests/setup-share-arithmetic-model.js';
import { compileSigningLoopSourceComparison } from '#tests/signing-loop-estimate-model.js';
import { compileSimulatorKeyKnowledgeCensus } from '#tests/simulator-key-knowledge-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    compileFheGadgetArithmeticBounds,
    compileRecipientKeyArithmeticBounds,
    compileSourceArithmeticBounds,
    compileSourceCoefficientAllocation,
} from '#tests/source-coefficient-allocation-model.js';
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

// The whole base-two logarithm of further work, or none when the priced work
// alone already exceeds the level.
const formatWorkAllowance = (allowance: bigint): string =>
    allowance > 0n ? formatCount(allowance.toString(2).length - 1) : 'none';

const formatLog2Cost = (value: number): string =>
    Number.isFinite(value) ? `\`${value.toFixed(2)}\`` : 'no finite cost';

const formatPopulationLimit = (limit: bigint | undefined): string =>
    limit === undefined ? 'none' : formatCount(limit);

// The largest ratio of each statistical term to the experiment's cost over
// every supported profile at the search cap, and the largest subtotals.
const compileStatisticalTermMaxima = () => {
    const terms = new Map<
        string,
        { scope: StatisticalTerm['scope']; ratio: Rational }
    >();
    const subtotals = new Map<string, Rational>();
    for (const profile of listSupportedProfiles()) {
        for (const term of compileStatisticalTerms(profile)) {
            const ratio = term.ratioAt(populationSearchCap);
            const current = terms.get(term.name);
            if (current === undefined || !atMost(ratio, current.ratio))
                terms.set(term.name, { scope: term.scope, ratio });
        }
        for (const [label, scope] of [
            ['Outside the proofs', 'outside the proofs'],
            ['Proofs', 'proofs'],
            ['Every term', undefined],
        ] as const) {
            const ratio = statisticalRatioAt(
                profile,
                populationSearchCap,
                scope,
            );
            const current = subtotals.get(label) ?? rational(0n);
            if (!atMost(ratio, current)) subtotals.set(label, ratio);
        }
    }
    return { terms, subtotals };
};

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
    const registrationKey = compileRecipientKeyCensus();
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
        'The preserved through-ballot prefix counts first-evaluated intents, including signatures never delivered. Repeated deterministic signing consumes runtime but no new cached signing-oracle query. Keep this prefix separate from the full-action branches below; neither table supplies a lifetime credential population, repeated-work bound or complete signature-security claim.',
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
        'The first table counts initial commitment-tree leaf/node hashing, the Fiat-Shamir transcript and context once, or one canonical verifier pass. Prover prefixes are initialized per row/subtree job and per level above those subtrees. Logical hash inputs and outputs are unchanged by prefix reuse; the permutation columns retain the actual initialization multiplicity. The second table adds bounded opening-block reconstruction and leaf-salt expansion. Operation/mask randomness streams, clone/allocation work, statement-digest passes, fixed-matrix generation, wrappers, checkpoint/replay work and lifetime multiplicities remain separate. The Merkle expansion factor bounds a complete-input hash against its remaining uncached permutations, not the full reduction. These are FIPS reference-permutation counts, not native timings, quantum gate bounds or a full participant total. The release row uses the authenticated protocol role specified by the foundation owner.',
        '',
        table(
            [
                'Role',
                'Role bytes',
                'Verifier message bytes',
                'Prover core logical input bytes',
                'Prover permutations without prefix reuse',
                'Prover permutations with prefix reuse',
                'Prover prefix initializations',
                'Merkle complete-input factor',
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
                    formatCount(
                        value.groups.reduce(
                            (sum, group) =>
                                sum + group.prefixReuse.initializations,
                            0n,
                        ),
                    ),
                    formatCount(
                        value.groups.reduce(
                            (maximum, group) =>
                                group.prefixReuse.completeInputFactor > maximum
                                    ? group.prefixReuse.completeInputFactor
                                    : maximum,
                            0n,
                        ),
                    ),
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
        'The first two trees retain leaf digests. The linear and folding trees restore the complete aligned blocks containing queried leaves, then rebuild the lower internal-node cache used by path writing. Each emitted record also expands its original leaf salt again. Counts below bound one complete producer pass at the independently bounded query counts; repeated calls are work, not new salt-seed scopes. Correlations between stages can make the sum conservative.',
        '',
        table(
            [
                'Role',
                'Opening leaf hashes bound',
                'Opening node hashes bound',
                'Leaf-salt expansions bound',
                'Opening fixed-hash permutations bound',
                'Tree/transcript/salt permutations subtotal',
            ],
            proofHashProfiles(completion).map((profile) => {
                const value = compileProofHashWork(completion, profile);
                return [
                    profile.role,
                    formatCount(
                        value.groups.reduce(
                            (sum, group) =>
                                sum +
                                BigInt(group.openingCounts.restoredLeaves),
                            0n,
                        ),
                    ),
                    formatCount(
                        value.groups.reduce(
                            (sum, group) =>
                                sum + BigInt(group.openingCounts.nodeHashes),
                            0n,
                        ),
                    ),
                    formatCount(value.proverLeafSaltExpansion.queries),
                    formatCount(value.proverOpeningHashes.permutations),
                    formatCount(value.proverHashSubtotal.permutations),
                ];
            }),
        ),
        '',
        'A first-oracle checkpoint may retain all base columns while leaving the extension degree-mask column unhashed. The following rows use that latest cut, which maximizes the complete-input/resumed-permutation ratio for each fixed role and profile. The bound applies separately to every completed replay without recharging historical absorption. Original input availability, its reconstruction and storage, authentication, incomplete calls and private-state coupling remain separate. Use the larger of this factor and the covered reader/Merkle factor in a mixed oracle schedule; do not multiply those alternative conversions.',
        '',
        table(
            [
                'Participants / options',
                'First leaf bytes including framing',
                'Retained prefix bytes per leaf',
                'Remaining input bytes per leaf',
                'Complete-input permutations per leaf',
                'Resumed permutations per leaf',
                'Complete-input factor',
            ],
            [
                [3, 2],
                [10, 10],
                [20, 20],
            ].map(([participants, options]) => {
                const profile = deriveSupportedProfile(participants, options);
                const setup = proofHashProfiles(profile).find(
                    (value) => value.role === 'setup',
                )!;
                const work = firstOracleResumeHashWork(
                    setup.firstWidth,
                    setup.roleBytes,
                    (setup.firstWidth - 48n) / 16n,
                );
                return [
                    `${participants} / ${options}`,
                    ...[
                        work.completeInputBytes,
                        work.retainedPrefixBytes,
                        work.remainingInputBytes,
                        work.completeInputPermutations,
                        work.resumedPermutations,
                        work.completeInputFactor,
                    ].map(formatCount),
                ];
            }),
        ),
        '',
        table(
            ['Scope', 'Complete-input factor'],
            [
                [
                    'Maximum over every supported profile with its emitted setup role',
                    formatCount(maximumFirstOracleResume),
                ],
            ],
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
        '## Recipient-key arithmetic bounds',
        '',
        'The original recipient key uses the same fixed-limb generator at the share modulus. Its retained-key check reduces a*s+b; the centered public key adds one bounded coefficient term to the sparse product, not another secret-support position. Both rows check normalization, leading-prefix reduction and signed machine ranges. For an authentic generated key the restored residue is its original error, whose negative endpoint is permitted and whose positive endpoint is excluded by the native check. Public-key validation, source-stream comparisons, allocation history and custody remain separate obligations.',
        '',
        table(
            [
                'Operation',
                'Limbs',
                'Maximum quotient estimate',
                'Maximum centered quotient magnitude',
                'Maximum normalization carry magnitude',
            ],
            Object.entries(compileRecipientKeyArithmeticBounds()).map(
                ([operation, row]) => [
                    operation === 'generated'
                        ? 'Generation'
                        : 'Retained-key validation',
                    formatCount(row.limbs),
                    formatCount(row.maximumQuotientEstimate),
                    formatCount(row.maximumQuotient),
                    formatCount(row.maximumNormalizationCarry),
                ],
            ),
        ),
        '',
        '## Original-source arithmetic bounds',
        '',
        'These bounds apply to the original first FHE key coordinate with centered common coefficients, the fixed sparse-secret support and the bounded source error. Every supported profile is checked against the transform range, signed machine integers, reducer leading-digit and one-correction premises, and the emitted quotient/carry widths. They rule out the named arithmetic refusals for those source inputs; they are not peak-allocation bounds or claims about other setup equations.',
        '',
        table(
            [
                'Participants / options',
                'Limbs',
                'Leading modulus digit',
                'Maximum quotient estimate',
                'Maximum centered quotient magnitude',
                'Maximum witness carry magnitude',
            ],
            [
                deriveSupportedProfile(3, 2),
                completion,
                deriveSupportedProfile(20, 20),
            ].map((profile) => {
                const row = compileSourceArithmeticBounds(profile);
                return [
                    `${profile.participantCount} / ${profile.optionCount}`,
                    formatCount(row.limbs),
                    formatCount(row.leadingModulusDigit),
                    formatCount(row.maximumQuotientEstimate),
                    formatCount(row.maximumQuotient),
                    formatCount(row.maximumWitnessCarry),
                ];
            }),
        ),
        '',
        '## Generated setup arithmetic bounds',
        '',
        'The FHE-key bound additionally covers both signs of every gadget power multiplying a ternary source or its signed automorphism. It checks all supported profiles against the same scalar reducer, machine ranges and quotient/carry widths as the original first-coordinate case. The table summarizes all gadget powers in each displayed profile. These are arithmetic refusal bounds, not a complete generation/allocation or proof-simulation result.',
        '',
        table(
            [
                'Participants / options',
                'Gadget powers',
                'Largest direct multiplier bits',
                'Maximum quotient estimate',
                'Maximum centered quotient magnitude',
                'Maximum witness carry magnitude',
            ],
            [
                deriveSupportedProfile(3, 2),
                completion,
                deriveSupportedProfile(20, 20),
            ].map((profile) => {
                const rows = compileFheGadgetArithmeticBounds(profile);
                const maximum = (values: bigint[]) =>
                    values.reduce(
                        (largest, value) => (value > largest ? value : largest),
                        0n,
                    );
                return [
                    `${profile.participantCount} / ${profile.optionCount}`,
                    formatCount(rows.length),
                    formatCount(
                        maximum(
                            rows.map((row) => row.directMultiplierMagnitude),
                        ).toString(2).length,
                    ),
                    formatCount(
                        maximum(rows.map((row) => row.maximumQuotientEstimate)),
                    ),
                    formatCount(
                        maximum(rows.map((row) => row.maximumQuotient)),
                    ),
                    formatCount(
                        maximum(rows.map((row) => row.maximumWitnessCarry)),
                    ),
                ];
            }),
        ),
        '',
        'Share generation is checked for arbitrary canonical recipient polynomials without assuming a valid key witness. The bounds cover signed sharing evaluations, low/high decomposition and offset, both ciphertext components, normalization, reduction and emitted carry widths. Every supported profile is checked; the table shows the constant component and its linear counterpart separately. A wider unsupported limb control exceeds the signed offset range, so passing the actual profile checks is load-bearing.',
        '',
        table(
            [
                'Participants / options',
                'Component',
                'Limb bits',
                'Offset magnitude bits',
                'Maximum quotient estimate',
                'Maximum witness carry magnitude',
                'Signed carry bits',
            ],
            [
                deriveSupportedProfile(3, 2),
                completion,
                deriveSupportedProfile(20, 20),
            ].flatMap((profile) =>
                compileSetupShareArithmeticBounds(profile).map((row) => [
                    `${profile.participantCount} / ${profile.optionCount}`,
                    row.component,
                    formatCount(profile.shareLifting.limbBits),
                    formatCount(row.maximumOffset.toString(2).length),
                    formatCount(row.maximumQuotientEstimate),
                    formatCount(row.maximumWitnessCarry),
                    formatCount(row.carryBits),
                ]),
            ),
        ),
        '',
        '## Source coefficient normalization comparison',
        '',
        'For one original FHE source coordinate, this conditional comparison counts the centered residues that make the pinned scalar BigUint constructor shrink its allocation. It uses independent source randomness and a uniform common polynomial: one nonzero sparse coefficient is a unit, so every output coefficient has a uniform marginal. The coordinate union bound needs no independence between coefficients. The table does not bound allocation for fixed adversarial inputs, all registrations, all source families, complete operations or provider failures; the source-stream and common-sampling comparisons retain their separate costs.',
        '',
        table(
            [
                'Participants / options',
                'Modulus bits',
                'Constructor u32 capacity',
                'Shrink below magnitude bits',
                'Coefficients',
                'One-coordinate exception bits',
            ],
            [
                deriveSupportedProfile(3, 2),
                completion,
                deriveSupportedProfile(20, 20),
            ].map((profile) => {
                const row = compileSourceCoefficientAllocation(profile);
                return [
                    `${profile.participantCount} / ${profile.optionCount}`,
                    formatCount(row.modulusBits),
                    formatCount(row.constructorWords),
                    formatCount(row.shrinkMagnitudeBits),
                    formatCount(row.coefficientCount),
                    formatCount(row.exceptionBits),
                ];
            }),
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
        '## Buffered field-sampling observations',
        '',
        'The native private-mask sampler reads complete buffers, accepts words below the field prime and discards the unread tail of its final buffer. In an independent uniform stream, its complete waiting-count tuple is independent of the ordered accepted values; rounding to full reads preserves that independence, and the next consumer starts at the fresh buffer boundary. This is a conditional sampler law, not the seed-expansion comparison or complete private-state argument. Replays retain the original tape and counts.',
        '',
        table(
            ['Degree-mask observation', 'Value'],
            (() => {
                const value = compileFirstOracleReadVariation();
                return [
                    [
                        'Required base-field values',
                        formatCount(value.requiredValues),
                    ],
                    [
                        'Words in one native read',
                        formatCount(value.bufferWords),
                    ],
                    ['Minimum reads', formatCount(value.minimumReads)],
                    [
                        'Probability of an extra read, lower bound',
                        `2^-${value.lowerProbabilityExponent}`,
                    ],
                    [
                        'Probability of an extra read, upper bound',
                        `2^-${value.upperProbabilityExponent}`,
                    ],
                ];
            })(),
        ),
        '',
        'The interval follows from the union and two-term Bonferroni bounds on a rejection in the exactly filled minimum degree-mask prefix. The event is sampler-work variation, not a privacy failure, and is not itself a 2^-80-small term. Discarding it would require an explicit population and whole-experiment cost charge under the accepted normalized target. The observation argument instead retains its exact waiting law; these probability bounds alone give no security verdict.',
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
        '## Private randomness scope inventory',
        '',
        'These whole-poll upper bounds count original source entries and original operation intents, including unfinished work. The example uses the completion-profile poll maximum and option count, with its participant count as an illustrative original-registration budget; it is not a security limit on that population or a one-roster workload. Each registration can contribute at most one original generation/continuation pair, ballot and release. A tree scope fixes one seed and permits every encoded leaf index; it is not one XOF query. Setup samplers consume the retained operation stream directly, and replay adds work without a new seed or scope.',
        '',
        ...(() => {
            const registrations = BigInt(completion.participantCount);
            const value = compilePrivateRandomnessScopes(
                registrations * registrationSourceRandomness.sourceSeedCount,
                registrations,
                registrations,
                registrations,
            );
            return [
                table(
                    ['Raw purpose', 'Potential scopes', 'Scopes with reads'],
                    value.domains.map((row) => [
                        row.domain,
                        formatCount(row.initialized),
                        formatCount(row.read),
                    ]),
                ),
                '',
                table(
                    ['Property', 'Upper bound'],
                    [
                        [
                            'Original registration budget in this example',
                            formatCount(registrations),
                        ],
                        [
                            'Original operation seeds',
                            formatCount(value.operationSeeds),
                        ],
                        [
                            'Salt seeds per complete proof',
                            formatCount(value.treesPerProof),
                        ],
                        [
                            'Original tree-seed scopes',
                            formatCount(value.treeSeedScopes),
                        ],
                        [
                            'All seeded-randomness draws in this inventory',
                            formatCount(value.maximumSeedDraws),
                        ],
                        [
                            'All potential scopes',
                            formatCount(value.maximumInitializedScopes),
                        ],
                        [
                            'All scopes with reads',
                            formatCount(value.maximumReadScopes),
                        ],
                        [
                            'Seed-pair union bound after an independent-tape comparison',
                            `${formatCount(value.seedCollisionPairs)}/2^${value.seedCollisionDenominator.toString(2).length - 1}`,
                        ],
                    ],
                ),
            ];
        })(),
        '',
        'These scopes are separate from commitment-salt shadow scopes and explicit proof-programming records. A simulation using one shadow function per private-randomness scope must account for the additional scopes and their full query histories. Unread initialized streams still have construction and sponge work. The conditional seed-pair term is not an adversarial query-hit bound, and none of these counts supplies a complete reduction time or a new primitive assumption.',
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
                'Source-target raw mask bits',
                'Source-target cell mask bits',
                'Complete input-cell bits',
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
                formatCount(family.commitmentMaskRawBits),
                formatCount(family.commitmentMaskCellBits),
                formatCount(family.commitmentInputCellBits),
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
        'Private close suffix and record bounds, excluding the already retained participant root and its earlier records. The suffix retains the accepted close inputs in arrival order with one key per encrypted record, so restoration replays them into the same state through the owning state machine. Before an intent the suffix only collects, alongside every ballot phase. Held bodies bound the delivery events, since the state machine refuses an input that changes nothing, and only the organizer adds one event per other responder and retains its proposal exact body when its response completes. The per-roster table uses the completion option count, and the held bodies dominate the record bytes. The encoded suffix supplies no verification or signing authority by itself.',
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
        '## Relation integer-lifting census',
        '',
        `Each accepted affine row of the setup, ballot and release relations has an integer residual bounded by the sum of its terms over the accepted witness box. A bound below the proof field makes field equality integer equality; complete public limbs and zero end carries then recover each original equation. Each row is the largest bound over the ${relationLifting.profileCount} supported profiles, with the first profile that attains it.`,
        '',
        table(
            [
                'Relation',
                'Row family',
                'Limb bits',
                'Limbs',
                'Largest accepted residual bound',
                'Bits below the proof field, rounded down',
                'First profile at the bound',
            ],
            relationLifting.families.map((family) => [
                family.relation,
                family.family,
                family.limbBits.length === 0
                    ? 'whole field elements'
                    : family.limbBits
                          .map((value) => formatCount(value))
                          .join(' or '),
                family.limbs.length === 1
                    ? formatCount(family.limbs[0])
                    : `${formatCount(family.limbs[0])} to ${formatCount(family.limbs[family.limbs.length - 1])}`,
                formatCount(family.residualBound),
                `\`${(Number(family.hundredthsBelowField) / 100).toFixed(2)}\``,
                `${formatCount(family.participantCount)} participants and ${formatCount(family.optionCount)} options`,
            ]),
        ),
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
        'Local producer counts for one roster, including every eligible offer even if it is not selected. Registration has no proof role. These counts do not bound speculative verification or all preselection exposure scopes; the composed ledger below owns those separate populations.',
        '',
        table(
            [
                'Participants',
                'Maximum honest proof scopes in one roster',
                'Accepted role slots',
                'Programmed verifier messages',
                'Committed nodes per proof',
                'Widest non-salt input bits',
            ],
            supportedProfiles.profiles.map((row) => {
                const chronologies = row.map(compileProofCompilerChronology);
                const [first] = chronologies;
                if (!chronologies.every((value) => value.withinCaps))
                    throw new Error(
                        'A supported profile exceeds a local compiler cap.',
                    );
                return [
                    formatCount(row[0].participantCount),
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
        '## Recipient key census',
        '',
        'Registration authenticates the complete canonical recipient polynomial. The bounded key equation is checked in the linked release relation; registration carries no separate key proof.',
        '',
        table(
            ['Property', 'Value'],
            [
                ['Polynomial degree', formatCount(registrationKey.degree)],
                ['Ciphertext modulus', formatCount(registrationKey.modulus)],
                ['Honest secret support', formatCount(registrationKey.support)],
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
        'The complete first-oracle checkpoint retains the actual witness, masks, leaf-salt seed, and partial row hashes. Lookup multiplicities, empty tree nodes, and the initial transcript are reconstructed. Each private record uses a separate data key. The browser root also retains encrypted generated public inputs; fixed common polynomials and verified recipient keys are reconstructed from predecessors. The proof-randomness minima split at this checkpoint: generation supplies the first-oracle masks and tree seed, while continuation supplies every response salt, starting with the salt preceding the lookup challenge. These minima exclude witness sampling and extra reads caused by rejected field candidates. Storage counts exclude database overhead and later proof phases, repeated checkpoints, and their security and resource unions.',
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
                    'Minimum generation proof-randomness bytes',
                    formatCount(
                        firstOracleCheckpoint.minimumGenerationProofRandomBytes,
                    ),
                ],
                [
                    'Minimum continuation proof-randomness bytes',
                    formatCount(
                        firstOracleCheckpoint.minimumContinuationProofRandomBytes,
                    ),
                ],
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
        'Preparation and later roots have distinct inventories. PRE2 frames independent own-offer, selection and endorsement slots; PCS5 carries its own phase. Activation authenticates the complete predecessor before clearing all slots and retiring source material. Later roots therefore retain an empty preparation journal beside ballot, close, target and release state.',
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
        'The standalone reader has no participant custody and streams every usable ballot for barrier authentication, classification and evaluation import before checking the target votes and release shares. Participants with intact close custody read those bodies locally. Roster restoration refetches complete registered headers and recipient keys, recomputing their canonical body identities against its retained verification. Metadata allowances are conservative: held close responses can avoid target reads, and an existing setup certificate avoids assembly reads. These are protocol-read upper bounds, not exact ordinary network traces. The action rows exclude bootstrap; add the actual module for each primary-worker invocation and the SDK for each page load. Cumulative download rows are distinct from the per-action planning target.',
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
        'The [clear-preparation argument](security-argument.md#clear-candidate-joint-ledger) owns the conditional hybrid interfaces. The first tables evaluate fixed-roster-size structural upper bounds at the displayed example original-honest-registration population H, including abandoned and unselected registrations; H is not an admitted population limit. Whole-poll bounds permitting different roster sizes follow separately. Started private preparation and certified rosters have different bounds. Original contribution scopes include failed or unfinished generation before publication; a replay of the same retained intent adds work but no new scope. Primitive comparison counts include the source-family or selected-position guesses where required, but exclude semantic-use error charges and reduction-time operands. The assumption group limits at the end of this section are conditional on the proof-compiler gate; no end-to-end security level is emitted.',
        '',
        table(
            [
                'Participants',
                'Example H',
                'Started preparation rosters',
                'Certified rosters',
                'Source entries, option range',
                'Source-mask scopes',
                'Corrupt source extractions',
                'Honest proof scopes',
                'Recipient key and ciphertext comparisons',
            ],
            supportedProfiles.profiles.map((row) => {
                const ledgers = row.map((profile) =>
                    compileClearPreparationLedger(
                        profile,
                        BigInt(profile.participantCount),
                    ),
                );
                const [first] = ledgers;
                return [
                    formatCount(row[0].participantCount),
                    formatCount(first.originalHonestRegistrations),
                    formatCount(first.maximumStartedPreparationRosters),
                    formatCount(first.maximumCertifiedRosters),
                    rangeOf(
                        ledgers.map((value) => value.generatedSourceEntries),
                    ),
                    formatCount(first.sourceMaskScopes),
                    formatCount(first.maximumCorruptSourceExtractions),
                    formatCount(first.maximumHonestProofScopes),
                    formatCount(
                        first.recipientKeyComparisons +
                            first.recipientCiphertextComparisons,
                    ),
                ];
            }),
        ),
        '',
        table(
            [
                'Participants',
                'Selected position sets',
                'FHE modulus guesses',
                'FHE tuple comparisons',
                'Selected FHE key comparisons',
                'FHE ballot comparisons',
                'Messages per FHE ballot comparison',
                'Global auxiliary key comparisons',
                'Auxiliary ballot comparisons',
                'Messages per auxiliary comparison',
            ],
            supportedProfiles.profiles.map((row) => {
                const value = compileClearPreparationLedger(
                    row[0],
                    BigInt(row[0].participantCount),
                );
                return [
                    row[0].participantCount,
                    value.selectedPositionSets,
                    value.sharedFheModulusGuesses,
                    value.fheTupleComparisons,
                    value.fheSelectedKeyComparisons,
                    value.fheBallotComparisons,
                    value.messagesPerFheBallotComparison,
                    value.auxiliaryKeyComparisons,
                    value.auxiliaryBallotComparisons,
                    value.messagesPerAuxiliaryBallotComparison,
                ].map(formatCount);
            }),
        ),
        '',
        'A whole poll can contain forked rosters of different permitted sizes. The next table minimizes honest endorsement consumption over that entire size range and bounds recipient rows and extraction requests by its largest permitted roster and corruption budget. A fixed completion-profile denominator does not cover smaller certified rosters, and a smaller selected-roster bound does not cover larger stalled offers. Primitive advantages must still maximize each complete family/profile summand with its own loss and reduction time, not just substitute the numerically largest dimensions.',
        '',
        table(
            [
                'Poll maximum participants',
                'Example H',
                'Minimum honest endorsers per certificate',
                'Maximum certified rosters',
                'Maximum honest-recipient rows',
                'Maximum source-extraction requests',
            ],
            supportedProfiles.profiles.map((row) => {
                const poll = compileClearPreparationPollPopulations(
                    row[0].participantCount,
                    row[0].optionCount,
                    BigInt(row[0].participantCount),
                );
                return [
                    poll.pollMaximumParticipants,
                    poll.originalHonestRegistrations,
                    poll.minimumHonestEndorsersPerCertificate,
                    poll.maximumCertifiedRosters,
                    poll.maximumHonestRecipientRows,
                    poll.maximumCorruptSourceExtractions,
                ].map(formatCount);
            }),
        ),
        '',
        'The source-extraction cache has one lookup per corrupt eligible registration at a roster’s first honest generation. Repeated original-generation work reuses its resolved references. Each lookup reserves a fresh row, with only misses occupying it; unsuccessful extraction is cached with a false coordinate-validity bit and a true presence bit. Keys contain the verified registration body identity and an immutable source-family ordinal, under the separately charged identity-binding premise. Values use the largest catalogue coordinate width. The following whole-poll circuit bound charges complete linear scans, copying, cleanup and zero-row initialization, including unused rows after hits. It excludes the oracle extraction and coordinate decoding priced below, circuit construction and the rest of the protocol simulator.',
        '',
        table(
            [
                'Poll maximum participants',
                'Example H',
                'Maximum cache lookups',
                'Cache key bits',
                'Cache value bits',
                'Retained cache bits',
                'Cache gates',
            ],
            supportedProfiles.profiles.map((row) => {
                const ledger = compileClearPreparationPollPopulations(
                    row[0].participantCount,
                    row[0].optionCount,
                    BigInt(row[0].participantCount),
                );
                return [
                    row[0].participantCount,
                    ledger.originalHonestRegistrations,
                    ledger.maximumSourceCacheLookups,
                    ledger.sourceCache.keyBits,
                    ledger.sourceCache.valueBits,
                    ledger.sourceCache.maximumRetainedBits,
                    ledger.sourceCache.totalGates,
                ].map(formatCount);
            }),
        ),
        '',
        'Oracle simulation is priced from declared query schedules in the compressed-oracle circuit census. That accounting includes persistent components, clean prefix wrappers and all supplied shadow streams. The margin screen below derives the FHE reduction’s capacities from the accepted experiment-cost convention, prices its protocol wrappers and solves for the FHE comparisons’ own population limit, and the assumption group limits below solve for every group’s.',
        '',
        '### FHE security margin screen',
        '',
        'The [margin model](../tests/security-margin-screen-model.ts) tests whether the current FHE comparisons can reach the target with the current parameters. It charges every single-key FHE Ring-LWE comparison of the [clear-preparation ledger](security-argument.md#clear-candidate-joint-ledger) at one original honest registration per participant, expanding each multi-message ballot comparison over its messages. The withdrawn ledger’s seven assumption groups share the 2^-80 budget equally. Each requirement charges the reduction’s work at the largest complete experiment within 2^80 gates that fills whole permutation slots. The reduction’s work depends on an experiment only through those slots and its query routing grows with their square, so that experiment has the largest reduction ratio; the source cache and the extractions’ fixed work, which do not grow with the experiment, leave every smaller experiment’s ratio below it, as the margin test checks at the population limits. The lattice assumptions hold relative to the ideal SHAKE oracle, so the forwarded column, which adds no work, is the floor for a reduction that never reads or programs the attacker’s queries. The FHE embedding fixes each pivot’s honest coordinate after its registration commitment from extracted corrupt registration coordinates, so it reads and programs the registration-source commitment domain with one commitment shadow per potential sender scope. The source-domain column implements only that domain, forwards every other query and prices the complete reduction except the simulated proofs’ record creation: its query circuits, the replacement wrapper for every programmed honest proof, the classical-reader and resumed-hash conversions of the forwarded honest calls and the forwarded calls themselves, every corrupt registration-source extraction with its coordinate decoding, and the source cache. A call reaches that domain only if its input capacity holds the shortest registration-source input, so it costs at least that input’s permutations, and every source input lies in one dyadic input class; the database terms are the full-domain bound restricted to those calls and that class. The converted honest calls read private streams and proof hashes outside that domain, so the conversions enlarge only the forwarded calls. The background column prices only the query circuits of a reduction that implements the whole function itself, as one without the oracle-relative assumption must, and the shadow column adds its commitment shadows. The reader column applies the classical fixed-input reader conversion that participant code uses. The resumed column applies the larger conversion for setup first-oracle leaf hashes resumed from an authenticated checkpoint, conditional on the original input staying available to the adapter. Those four columns omit every other reduction cost, so they are lower bounds. Each row shows the option count whose source-domain requirement leaves the least further work within its own criterion floor, the largest modulus among equals. The floors are the cheapest core-SVP screens that the [security argument](security-argument.md#ledger) cites; a screen at one modulus bounds the same attack at every smaller supported modulus. Attack costs follow the accepted convention, without quantum random-access memory, so the classical floor over every algorithm of the estimator’s full estimate is the criterion. The quantum model’s sieving speedup assumes that memory, so its floor is a stress test. Neither model counts gates as the convention does. The last column is the further reduction work, in whole log2 gates, that keeps the source-domain requirement within the whole bits of the criterion floor, or none where the priced work alone exceeds them; the simulated proofs’ record creation must fit within it.',
        '',
        table(
            [
                'Participants',
                'Options',
                'Modulus bits',
                'Selected position sets',
                'FHE Ring-LWE comparisons',
                'Required bits, forwarded oracle',
                'Required bits, source-domain reduction',
                'Required bits, background oracle',
                'Required bits, commitment shadows',
                'Required bits, shadows and readers',
                'Resume factor',
                'Required bits, shadows and resumed hashes',
                'Classical screened-attack floor',
                'Quantum screened-attack floor',
                'Unpriced work within the criterion, log2 gates',
            ],
            compileSecurityMarginScreen().map((row) => {
                const required = (variant: ReductionVariant) =>
                    formatCount(
                        row.requirements.find(
                            (value) => value.variant === variant,
                        )!.requiredBits,
                    );
                return [
                    formatCount(row.participantCount),
                    formatCount(row.optionCount),
                    formatCount(row.modulusBits),
                    formatCount(row.selectedPositionSets),
                    formatCount(row.comparisons),
                    required('forwarded oracle'),
                    required('source-domain reduction'),
                    required('background oracle'),
                    required('commitment shadows'),
                    required('commitment shadows and readers'),
                    formatCount(row.operands.resumeFactor),
                    required('commitment shadows and resumed hashes'),
                    `\`${row.criterion.log2Cost.toFixed(2)}\`, ${row.criterion.attack} at ${formatCount(row.criterion.modulusBits)} bits`,
                    `\`${row.stressTest.log2Cost.toFixed(2)}\`, ${row.stressTest.attack} at ${formatCount(row.stressTest.modulusBits)} bits`,
                    formatWorkAllowance(row.criterionAllowance),
                ];
            }),
        ),
        '',
        'This screen is a necessary condition, not a security level. Where a requirement exceeds the criterion floor, the priced reduction cannot establish the target at those parameters, whatever its remaining costs.',
        '',
        'A larger original honest registration population raises the source-domain requirement by about two bits per doubling: one for the comparisons and one for the commitment shadows. The following limits are the largest original honest registration populations of one poll of each participant count, whatever its option count, whose source-domain requirement stays within the whole bits each floor supports at that option count’s modulus. Each limit names the option count and modulus that bind it. They are the FHE comparisons’ own limit; the assumption group limits below add the other groups, and the simulated proofs’ record creation must fit within the unpriced work. Each unpriced column gives the further reduction work, in whole log2 gates, that every option count still absorbs at that limit.',
        '',
        table(
            [
                'Participants',
                'Criterion options',
                'Criterion modulus bits',
                'Criterion level bits',
                'Original honest registrations within the criterion',
                'Unpriced work at that limit, log2 gates',
                'Stress-test options',
                'Stress-test modulus bits',
                'Stress-test level bits',
                'Original honest registrations within the stress test',
                'Unpriced work at that limit, log2 gates',
            ],
            compileFhePopulationLimits().map((row) => [
                formatCount(row.participantCount),
                ...[row.criterion, row.stressTest].flatMap((limit) => [
                    formatCount(limit.optionCount),
                    formatCount(limit.modulusBits),
                    formatCount(limit.levelBits),
                    formatCount(limit.honestRegistrations),
                    formatWorkAllowance(limit.allowance),
                ]),
            ]),
        ),
        '',
        '### Assumption group limits',
        '',
        'The [security ledger model](../tests/security-ledger-model.ts) derives each assumption group’s own limit on a poll’s original honest registrations and takes the poll’s limit as the smallest, conditional on the proof-compiler gate. The seven groups share the budget as above, so each bounds the ratio of its contribution to the experiment’s cost by 2^-83 at every experiment within 2^80 gates. The lattice groups price their comparisons with the source-domain reduction of the screen above. Circular security of the honest evaluation-key tuples is judged against the FHE instance’s floor at each option count’s modulus, as the owner decided on 2026-10-07. The fixed share-encryption and auxiliary instances use the following core-SVP screens of the pinned estimator with unlimited samples; an attack whose estimate has no finite cost at any block size has no floor, and an instance without a finite screen in a cost model imposes no limit in it. A group that stays within its level at 2^64 registrations has no limit below that search cap, shown as none.',
        '',
        table(
            [
                'Instance',
                'Attack',
                'Cost model',
                'Modulus bits',
                'Core-SVP log2 cost',
            ],
            (['share encryption', 'auxiliary'] as const).flatMap((instance) =>
                instanceAttackScreens[instance].map((screen) => [
                    instance === 'share encryption'
                        ? 'Share encryption'
                        : 'Auxiliary',
                    screen.attack,
                    screen.costModel,
                    formatCount(screen.modulusBits),
                    formatLog2Cost(screen.log2Cost),
                ]),
            ),
        ),
        '',
        'The accepted reading of the ML-DSA-65 claim bounds the forgery of one key by T^2/2^192 at cost T. A union over the original honest credentials charges each key’s reduction, which runs the real experiment with that key’s signing oracle and tests every honest verification under it against the frames its intents fixed. The test adds at most the displayed gates per verification, while every verification computes at least the displayed permutations, so the reduction costs at most (1+rho)T, and the limit is the largest population with H((1+rho)T)^2/2^192 <= T/2^83 at T = 2^80. Every identity, retained tag and signed-frame digest is a 512-bit SHAKE256 prefix, so one compressed-oracle collision bound covers them all at every experiment, whatever the population.',
        '',
        (() => {
            const authentication = compileAuthenticationGroup();
            const identity = compileIdentityCollisionGroup();
            return table(
                ['Property', 'Value'],
                [
                    [
                        'Signed frames per original credential',
                        formatCount(authentication.signedFramesPerKey),
                    ],
                    [
                        'Forgery-test gates per verification',
                        formatCount(authentication.comparisonGates),
                    ],
                    [
                        'Shortest frame-digest input bytes',
                        formatCount(authentication.shortestFrameInputBytes),
                    ],
                    [
                        'Least permutations per verification',
                        formatCount(authentication.verificationPermutations),
                    ],
                    [
                        'Least verification gates',
                        formatCount(authentication.verificationGates),
                    ],
                    [
                        'Original honest registrations within the authentication budget',
                        formatCount(authentication.honestRegistrations),
                    ],
                    [
                        'Identity-collision ratio to experiment cost, log2 upper bound',
                        formatCount(rationalCeilingLog2(identity.ratio)),
                    ],
                ],
            );
        })(),
        '',
        'Each statistical term is bounded relative to the experiment’s cost. A once-global term, or a term charged per operation of one kind, is bounded by its value over one permutation charge, since every operation costs at least one. Query-dependent terms use at most four charged queries per permutation charge of the experiment, and population-dependent terms are evaluated at the population. The following shows each term’s largest bound over every supported profile at 2^64 original honest registrations; the subtotals round each term up to a multiple of 2^-1024. Terms outside the proofs do not depend on the proof-compiler gate.',
        '',
        ...(() => {
            const maxima = compileStatisticalTermMaxima();
            return [
                table(
                    [
                        'Term',
                        'Scope',
                        'Largest ratio at 2^64 registrations, log2 upper bound',
                    ],
                    [...maxima.terms].map(([name, { scope, ratio }]) => [
                        name,
                        scope,
                        formatCount(rationalCeilingLog2(ratio)),
                    ]),
                ),
                '',
                table(
                    [
                        'Subtotal',
                        'Largest ratio at 2^64 registrations, log2 upper bound',
                    ],
                    [...maxima.subtotals].map(([label, ratio]) => [
                        label,
                        formatCount(rationalCeilingLog2(ratio)),
                    ]),
                ),
            ];
        })(),
        '',
        'The proof-soundness term charges the finite-family tagged soundness bound at both endpoints of every comparison whose endpoint games use true accepted corrupt statements: every lattice comparison, and four steps outside them, namely original-history recovery with prescribed release, both corrupt-ballot recovery switches and the terminal identity. Its operands are the whole suite’s.',
        '',
        (() => {
            const soundness = compileSoundnessCharge();
            const queries = maximumChargedQueries();
            return table(
                ['Property', 'Value'],
                [
                    [
                        'Largest round error, log2 upper bound',
                        formatCount(rationalCeilingLog2(soundness.roundError)),
                    ],
                    ['Raw input bits', formatCount(soundness.inputBits)],
                    ['Hash-label sentinels', formatCount(soundness.sentinels)],
                    [
                        'Accepted expansion queries',
                        formatCount(soundness.expansionQueries),
                    ],
                    ['Message bits', formatCount(soundness.messageBits)],
                    ['Tag bits', formatCount(soundness.tagBits)],
                    ['Largest charged queries', formatCount(queries)],
                    [
                        'One charge at those queries, log2 upper bound',
                        formatCount(
                            rationalCeilingLog2(soundnessChargeAt(queries)),
                        ),
                    ],
                ],
            );
        })(),
        '',
        table(
            [
                'Participants',
                'Charges independent of the population',
                'Charges per original registration, largest option count',
            ],
            supportedProfiles.profiles.map((row) => {
                const charges = row.map(compileSemanticUseCharges);
                const largest = (field: 'constant' | 'slope') =>
                    charges.reduce(
                        (maximum, value) =>
                            value[field] > maximum ? value[field] : maximum,
                        0n,
                    );
                return [
                    formatCount(row[0].participantCount),
                    formatCount(largest('constant')),
                    formatCount(largest('slope')),
                ];
            }),
        ),
        '',
        'The criterion table uses each lattice group’s classical floor, and the stress-test table replaces those floors by the quantum ones; the other groups are the same in both. The poll limit is the smallest group limit.',
        '',
        ...(() => {
            const ledger = compileSecurityLedger();
            return (['criterion', 'stressTest'] as const).flatMap(
                (floor, index) => [
                    ...(index === 0 ? [] : ['']),
                    table(
                        [
                            'Participants',
                            ...ledgerGroups,
                            floor === 'criterion'
                                ? 'Poll limit within the criterion'
                                : 'Poll limit within the stress test',
                            'Binding group',
                        ],
                        ledger.map((row) => [
                            formatCount(row.participantCount),
                            ...ledgerGroups.map((group) =>
                                formatPopulationLimit(
                                    row[floor].limits.get(group),
                                ),
                            ),
                            formatCount(row[floor].binding.limit),
                            row[floor].binding.group,
                        ]),
                    ),
                ],
            );
        })(),
        '',
        'Each simulated proof replaces one honest proof, and the direct simulator runs the unchanged proof writer on public dummy columns, adding only the dummy entries’ sampling, their public affine pairing, one constant-coefficient adjustment and the programmed message. Every honest proof costs at least its prover’s hash permutations, so an experiment holds at most one simulated proof per that many permutation charges. Because the decisive experiment has the largest reduction ratio, record creation fits within every lattice level at every experiment when its added work per simulated proof is at most those permutation charges times the unpriced work at the poll’s limit over the decisive experiment. The last column divides that by the dummy entries of the largest proof role, every systematic coordinate of its original oracles, giving the work each entry may cost.',
        '',
        table(
            [
                'Participants',
                'Poll limit within the criterion',
                'Unpriced work at that limit, log2 gates',
                'Least prover permutations per honest proof',
                'Dummy entries per simulated proof',
                'Added work per simulated proof within every level, log2 gates',
                'Added work per dummy entry within every level, log2 gates',
            ],
            compileRecordCreationPricing().map((row) => [
                formatCount(row.participantCount),
                formatCount(row.honestRegistrations),
                formatWorkAllowance(row.allowance),
                formatCount(row.leastProverPermutations),
                formatCount(row.largestDummyEntries),
                formatWorkAllowance(row.workPerProof),
                formatWorkAllowance(row.workPerEntry),
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
                'Constructed tuple-index words',
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
                    work.constructorTupleIndexWords,
                ].map(formatCount);
            }),
        ),
        '',
        'Tuple-index words count the row arrays constructed by the sparse routing emitter. Direct column indexing removes the repeated row materialization inside output-bit selection. This is a constructor allocation operand, not a bit-operation, dispatch, or complete construction-time bound; emitted gates are unchanged.',
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
        '### Declared maximum-length oracle budget',
        '',
        'These are upper bounds for the maintained query circuits when every call is charged at its declared maximum input and output capacities. The permutation budget is the sum of those FIPS 202 reference charges, using the widest SHAKE rate conservatively. The bound sums all persistent input-class/output-chunk databases and squares each nested query multiplier in the routing term. This conditional circuit bound does not normalize arbitrary coherent-length or expected-work algorithms. Extraction, independent shadow streams and their dispatch, programming-record creation, classical circuit generation and the rest of the reduction remain separate.',
        '',
        table(
            [
                'Maximum-length permutations',
                'First output chunk bits',
                'Programmed records',
                'Controller length-bit bound',
                'Cell-bit visits bound',
                'Base query gates bound',
                'Programmed query gates bound',
            ],
            [1n, 1024n, 1n << 40n].flatMap((permutations) =>
                [0n, 1024n].map((records) => {
                    const bound = compileOraclePermutationBudget(
                        permutations,
                        512n,
                        records,
                    );
                    return [
                        permutations,
                        512n,
                        records,
                        bound.lengthBitsUpperBound,
                        bound.componentBitVisitsUpperBound,
                        bound.baseQueryGatesUpperBound,
                        bound.programmedQueryGatesUpperBound,
                    ].map(formatCount);
                }),
            ),
        ),
        '',
        '### Full-circuit query and source extraction budgets',
        '',
        'The owner-selected full-circuit convention charges controlled permutation slots regardless of branch probability. Separate input and output maxima are bounded by a rectangle costing at most twice that slot budget. These examples price the complete programmed/background query circuit, every declared shadow and its selection circuit. All caller queries must enter the supplied budget; extra reduction calls, non-oracle computation and constructor work cannot be silently charged to the original experiment. The record and shadow counts below are declared examples, not a numerical registration limit.',
        '',
        table(
            [
                'Charged gates',
                'Maximum logical queries',
                'Maximum-length permutations',
                'Programmed records',
                'Shadow streams',
                'All shadow query gates bound',
            ],
            [
                [shakePermutationGateCharge, 0n, 0n],
                [1n << 40n, 10n, 20n],
                [1n << 80n, 1024n, 1024n],
            ].map(([gates, records, shadows]) => {
                const work = compileFullCircuitOracleBudget(
                    gates,
                    512n,
                    records,
                    shadows,
                );
                return [
                    gates,
                    work.maximumLogicalQueries,
                    work.maximumLengthPermutations,
                    records,
                    shadows,
                    work.shadowQueryGatesUpperBound,
                ].map(formatCount);
            }),
        ),
        '',
        'The following alternative also covers classical fixed-input XOF readers whose roots pay their complete input absorption and whose effective stream stays unchanged. Their cursor clones share a cache; separate initializations still use the same underlying XOF. An initial prefix scaled to absorption work, followed by doubling, bounds the adapter at five times the reference permutations. Each budget also has a row using the maximum emitted first-oracle replay factor derived in the proof-hash section, conditional on authenticated original-input availability. These rows replace the complete-query-only conversion above for their respective mixed interface; the conversion factors are not multiplied. All extra reduction-producer reads need their own caller budget. Reader-cache payload bounds exclude resumed hash inputs and their reconstruction/storage, handles, cursor/lookup logic, output copying, circuit construction and the oracle circuit itself. Other shared unfinished input hashes and mutable oracle epochs remain outside these conversions.',
        '',
        table(
            [
                'Charged caller gates',
                'Complete-input factor',
                'Covered prefix permutations',
                'Cached input bits bound',
                'Cached output bits bound',
                'Output growth overlap bits bound',
                'Programmed records',
                'Shadow streams',
                'All shadow query gates bound',
            ],
            [
                [shakePermutationGateCharge, 0n, 0n],
                [1n << 40n, 10n, 20n],
                [1n << 80n, 1024n, 1024n],
            ].flatMap(([gates, records, shadows]) =>
                [5n, maximumFirstOracleResume].map((factor) => {
                    const work = compileClassicalReaderOracleBudget(
                        gates,
                        512n,
                        records,
                        shadows,
                        factor,
                    );
                    return [
                        gates,
                        factor,
                        work.maximumLengthPermutations,
                        work.cacheInputBitsUpperBound,
                        work.cacheOutputBitsUpperBound,
                        work.cacheGrowthOverlapBitsUpperBound,
                        records,
                        shadows,
                        work.shadowQueryGatesUpperBound,
                    ].map(formatCount);
                }),
            ),
        ),
        '',
        'The raw registration-source slice fixes the source grammar, original owner, immutable family and salt at their actual bit positions. Its exact length is checked; poll/runtime and the coordinate payload stay unconstrained. Current protocol credential hash calls are shorter than this source language even at its syntactic minimum. This separates raw oracle inputs, not their potentially dependent message values. Retained tags have the distinct fixed ProtocolHash prefix.',
        '',
        table(
            ['Source/credential boundary', 'Bytes'],
            [
                [
                    'Maximum current credential hash input',
                    formatCount(
                        compileCurrentSignatureHashInputs().maximumInputBytes,
                    ),
                ],
                [
                    'Syntactic minimum source input',
                    formatCount(minimumRegistrationSourceInputBytes()),
                ],
            ],
        ),
        '',
        'The following query-controller and prepared-extraction counts use the completion poll family inventory, an output prefix equal to the commitment width and a declared extraction database capacity. The separate returned-coordinate circuit checks the extracted poll/runtime, canonical centered coefficients and absence of negative zero, then copies the salt and coordinate or a zero dummy with a distinct validity bit. It includes clean compute/copy/uncompute even on missing or malformed extraction. The independent query circuit, cache indexing, circuit construction and later polynomial arithmetic remain separate costs.',
        '',
        table(
            [
                'Source family',
                'Raw input bits',
                'Hidden-slice compared bits',
                'One-slice clean routing gates',
                'Extraction component capacity',
                'Prepared selection gates per request',
                'Coordinate decoding gates per request',
                'Prepared selection and decoding gates per request',
            ],
            (() => {
                const extraction = compileRegistrationSourceExtractionWork(
                    completion.participantCount,
                    completion.optionCount,
                    1n << 40n,
                    1n,
                );
                return registrationSourceRandomness.families.map(
                    (family, index) => {
                        const inputBits = 8n * family.commitmentInputBytes;
                        const comparedBits =
                            family.commitmentMaskRawBits +
                            8n * sourceOpeningSaltBytes;
                        const routing = oracleMaskRoutingWork(inputBits, 512n, [
                            { inputLength: inputBits, comparedBits },
                        ]);
                        return [
                            family.index,
                            inputBits,
                            comparedBits,
                            routing.computeAndUncomputeGates,
                            1n << 40n,
                            extraction.families[index].preparedSelectionGates,
                            extraction.families[index].coordinateDecodingGates,
                            extraction.families[index]
                                .preparedSelectionAndDecodingGates,
                        ].map(formatCount);
                    },
                );
            })(),
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
        '## Commitment equivocation finite model',
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
