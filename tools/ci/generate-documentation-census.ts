import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';

import { archiveHolderRequirements } from '#tests/archive-availability-model.js';
import { compileBatchedPublicationVisitCensus } from '#tests/batched-publication-model.js';
import { compileBoundedIntegerSharingPrivacyCensus } from '#tests/bounded-integer-sharing-privacy-model.js';
import { compileBoundedLinearPolynomialProofCensus } from '#tests/bounded-linear-polynomial-proof-model.js';
import { compileBoundedLookupCensus } from '#tests/bounded-lookup-model.js';
import { compileByteCarryLiftingCensus } from '#tests/byte-carry-lifting-model.js';
import { compileCandidateSetupProofFieldCensus } from '#tests/candidate-setup-proof-field-model.js';
import { compileCertificateCustodyCensus } from '#tests/certificate-custody-model.js';
import { compileCommitmentExtractionBound } from '#tests/commitment-extraction-bound-model.js';
import { compileCommonAgreementDegreeCensus } from '#tests/common-agreement-degree-model.js';
import { compileCommonMatrixSamplingCensus } from '#tests/common-matrix-sampling-model.js';
import {
    exactRankingModelConstants,
    compilePackedRankingEvaluationGraph,
    verifyExactRankingModel,
} from '#tests/exact-ranking-model.js';
import { compileFheKeyIntegerEmbeddingBounds } from '#tests/fhe-key-integer-embedding-model.js';
import { compileFixedModulusBfvCensus } from '#tests/fixed-modulus-bfv-model.js';
import { compileFixedWitnessReleaseSimulationCensus } from '#tests/fixed-witness-release-simulation-model.js';
import { compileGenericCommitAndOpenProofResourceCensus } from '#tests/generic-commit-and-open-proof-resource-model.js';
import { compileLinkedReleaseRelationCensus } from '#tests/linked-release-relation-model.js';
import { compileParticipantVisitDependencyCensus } from '#tests/participant-visit-dependency-model.js';
import {
    createFalseBinaryRelationTable,
    enumerateRandomizedEncodingViews,
} from '#tests/polynomial-oracle-boundary-model.js';
import { verifyPublicEncryptedSharingModel } from '#tests/public-encrypted-sharing-model.js';
import { compilePublicEncryptedSharingProofResourceCensus } from '#tests/public-encrypted-sharing-proof-resource-model.js';
import { runPublicationCloseRaceModel } from '#tests/publication-close-race-model.js';
import { compilePublicationCutCensus } from '#tests/publication-cut-model.js';
import { compileRecipientKeyUniquenessBound } from '#tests/recipient-key-uniqueness-model.js';
import { compileReleaseShareLiftingCensus } from '#tests/release-share-lifting-model.js';
import { compileRnsArithmeticResourceCensus } from '#tests/rns-arithmetic-resource-model.js';
import { compileSetupContributionRelationCensus } from '#tests/setup-contribution-relation-model.js';
import { compileShareEncryptionCrossModulusCensus } from '#tests/share-encryption-cross-modulus-model.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import { compileSupportedThresholdCompletionProfiles } from '#tests/threshold-completion-model.js';
import { verifyThresholdKeyAggregationModel } from '#tests/threshold-key-aggregation-model.js';
import { compileThresholdKeyAggregationResourceLowerBound } from '#tests/threshold-key-aggregation-resource-model.js';
import { compileThresholdReleaseNoiseCensus } from '#tests/threshold-release-noise-model.js';
import { compileWideChallengeCompilerCensus } from '#tests/wide-challenge-compiler-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';

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
    const thresholdProfiles = compileSupportedThresholdCompletionProfiles();
    const boundedIntegerSharing = compileBoundedIntegerSharingPrivacyCensus();
    const boundedLinearProof = compileBoundedLinearPolynomialProofCensus();
    const boundedLookup = compileBoundedLookupCensus();
    const byteCarryLifting = compileByteCarryLiftingCensus();
    const smallLimbProofField = compileSmallLimbProofFieldCensus();
    const candidateSetupProofField = compileCandidateSetupProofFieldCensus();
    const recipientKeyUniqueness = compileRecipientKeyUniquenessBound();
    const releaseSimulation = compileFixedWitnessReleaseSimulationCensus();
    const closeRace = runPublicationCloseRaceModel(10, false);
    const thresholdKeyAggregation = verifyThresholdKeyAggregationModel();
    const thresholdKeyResources =
        compileThresholdKeyAggregationResourceLowerBound();
    const thresholdReleaseNoise = compileThresholdReleaseNoiseCensus();
    const participantVisits = compileParticipantVisitDependencyCensus();
    const batchedPublicationVisits = compileBatchedPublicationVisitCensus();
    const commonMatrixSampling = compileCommonMatrixSamplingCensus();
    const wideChallengeCompiler = compileWideChallengeCompilerCensus();
    const commonAgreement = compileCommonAgreementDegreeCensus();
    const rnsArithmetic = compileRnsArithmeticResourceCensus();
    const setupRelation = compileSetupContributionRelationCensus();
    const linkedRelease = compileLinkedReleaseRelationCensus();
    const publicEncryptedSharing = verifyPublicEncryptedSharingModel();
    const publicEncryptedSharingProof =
        compilePublicEncryptedSharingProofResourceCensus();
    const shareEncryptionCrossModulus =
        compileShareEncryptionCrossModulusCensus();
    const fheKeyEmbedding = compileFheKeyIntegerEmbeddingBounds();
    const fixedModulusBfv = compileFixedModulusBfvCensus();
    const certificateCustody = compileCertificateCustodyCensus();
    const publicationCut = compilePublicationCutCensus();
    const wideShareLifting = compileWideShareLiftingCensus();
    const releaseShareLifting = compileReleaseShareLiftingCensus();
    const firstMaskedView = enumerateRandomizedEncodingViews(0, 1, [2, 3]);
    const secondMaskedView = enumerateRandomizedEncodingViews(1, 1, [2, 3]);
    const falseRelation = createFalseBinaryRelationTable();
    const genericProofResources =
        compileGenericCommitAndOpenProofResourceCensus();
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
    const rankingCensus = verifyExactRankingModel();
    const completionGraph = compilePackedRankingEvaluationGraph(10, 10, 10);
    const maximumGraph = compilePackedRankingEvaluationGraph(20, 20, 20);

    return `${[
        '# Documentation census',
        '',
        'Generated by `pnpm run docs:census` from the independent TypeScript models under `tests/`. Do not edit by hand. These are model-derived development values, not a protocol theorem, concrete FHE parameter approval, browser measurement, or supported-phone qualification.',
        '',
        '## Threshold completion census',
        '',
        'For each supported roster, the model uses `f = floor((n - 1) / 3)`, all `n` setup receipts, inventory-certificate threshold `q = n - f`, and result-release threshold `d = f + 1`. All-roster receipts leave at least `n - 2f >= d` honest verified share holders after any `f` disappear. A `q` publication or close certificate has at least `n - 2f` honest locked signers, leaving at most `2f < q` positions able to pass it with the conflicting certificate. Every named set is counted; isomorphic joint cases are checked with exact multiplicity, and profiles through twelve participants are also brute-force cross-checked over the underlying bit masks.',
        '',
        table(
            [
                'Participants',
                'Maximum corrupt',
                'Inventory certificate',
                'Result release',
                'Setup receipts',
                'Guaranteed honest responders / publication waiters',
                'Minimum certificate intersection',
                'Maximum post-close publication signers',
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
                String(profile.setupReceiptThreshold),
                String(profile.guaranteedHonestResponderCount),
                String(profile.minimumCertificateIntersection),
                String(profile.maximumPostClosePublicationSignerCount),
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
        '## Public encrypted-sharing structural census',
        '',
        'This independent finite-ring model generates one additive share-encryption key per recipient, encrypts every contributor-recipient evaluation of a degree-three Shamir polynomial, adds ciphertexts by recipient, decrypts each aggregate, and reconstructs the common secret from every four-position subset. Its production bound assumes ternary key and ciphertext witnesses and derives a zero-failure coefficient scale from exact convolution bounds. It does not establish Ring-LWE security, public-key witness uniqueness, proof soundness or zero knowledge, the production ring mapping, or browser feasibility.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Toy ring degree',
                    formatCount(publicEncryptedSharing.toyRingDegree),
                ],
                [
                    'Contributor-recipient ciphertexts checked',
                    formatCount(
                        publicEncryptedSharing.contributorRecipientCiphertextsChecked,
                    ),
                ],
                [
                    'Aggregate ciphertexts checked',
                    formatCount(
                        publicEncryptedSharing.aggregateCiphertextsChecked,
                    ),
                ],
                [
                    'Authorized reconstruction subsets checked',
                    formatCount(
                        publicEncryptedSharing.authorizedReconstructionSubsetsChecked,
                    ),
                ],
                [
                    'Tampered ciphertext changed aggregate share',
                    publicEncryptedSharing.tamperedCiphertextChangedShare
                        ? 'yes'
                        : 'no',
                ],
                [
                    'Production single-ciphertext noise coefficient bound',
                    formatCount(
                        publicEncryptedSharing.productionSingleCiphertextNoiseCoefficientBound,
                    ),
                ],
                [
                    'Production aggregate noise coefficient bound',
                    formatCount(
                        publicEncryptedSharing.productionAggregateNoiseCoefficientBound,
                    ),
                ],
                [
                    'Production share-encoding scale',
                    formatCount(
                        publicEncryptedSharing.productionShareEncodingScale,
                    ),
                ],
            ],
        ),
        '',
        '## Bounded-integer sharing privacy census',
        '',
        'For every corrupt three-position set, this exact reduced-ring model constructs the integral degree-three basis polynomial that equals one at the secret point and zero at the corrupt evaluation points. It exhausts every extreme secret-difference block, lifts the maximum translation across the production ring and ten hybrid steps, and chooses the smallest power-of-two coefficient bound meeting the stated uniform-cube statistical-distance inequality. It then searches a deterministic Proth sequence for a prime above the centered aggregate-share span and verifies the exact Proth witness and transform congruence. The resulting plaintext and share-encryption moduli are arithmetic bounds, not a complete privacy proof, Ring-LWE parameter approval, or implementation.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Corrupt subsets checked',
                    formatCount(boundedIntegerSharing.corruptSubsetsChecked),
                ],
                [
                    'Reduced-ring blocks',
                    formatCount(boundedIntegerSharing.reducedRingBlockCount),
                ],
                [
                    'Production interpolation-point exponent stride',
                    formatCount(
                        boundedIntegerSharing.productionInterpolationPointExponentStride,
                    ),
                ],
                [
                    'Maximum nonconstant basis one-norm',
                    formatCount(
                        boundedIntegerSharing.maximumBasisNonconstantOneNorm,
                    ),
                ],
                [
                    'Maximum translation one-norm per reduced block',
                    formatCount(
                        boundedIntegerSharing.maximumBlockTranslationOneNorm,
                    ),
                ],
                [
                    'Maximum production translation per contribution',
                    formatCount(
                        boundedIntegerSharing.maximumProductionTranslationOneNormPerContribution,
                    ),
                ],
                [
                    'Maximum ten-hybrid translation',
                    formatCount(
                        boundedIntegerSharing.maximumHybridTranslationOneNorm,
                    ),
                ],
                [
                    'Statistical privacy bits',
                    formatCount(
                        boundedIntegerSharing.statisticalPrivacyBitLength,
                    ),
                ],
                [
                    'Sharing-coefficient sampling bound',
                    formatCount(boundedIntegerSharing.coefficientSamplingBound),
                ],
                [
                    'Aggregate share coefficient bound',
                    formatCount(
                        boundedIntegerSharing.aggregateShareCoefficientBound,
                    ),
                ],
                [
                    'Share plaintext-span bits',
                    formatCount(
                        boundedIntegerSharing.sharePlaintextSpanBitLength,
                    ),
                ],
                [
                    'Share plaintext prime',
                    formatCount(boundedIntegerSharing.sharePlaintextModulus),
                ],
                [
                    'Share plaintext prime bits',
                    formatCount(
                        boundedIntegerSharing.sharePlaintextModulusBitLength,
                    ),
                ],
                [
                    'Share plaintext prime Proth multiplier',
                    formatCount(
                        boundedIntegerSharing.sharePlaintextPrimeMultiplier,
                    ),
                ],
                [
                    'Share plaintext prime Proth exponent',
                    formatCount(
                        boundedIntegerSharing.sharePlaintextTransformExponent,
                    ),
                ],
                [
                    'Share plaintext prime Proth witness',
                    formatCount(
                        boundedIntegerSharing.sharePlaintextPrimeWitness,
                    ),
                ],
                [
                    'Proth candidates checked',
                    formatCount(
                        boundedIntegerSharing.sharePlaintextPrimeCandidateCount,
                    ),
                ],
                [
                    'Share-encryption modulus bits',
                    formatCount(
                        boundedIntegerSharing.shareEncryptionModulusBitLength,
                    ),
                ],
            ],
        ),
        '',
        '## Threshold key-aggregation resource floor',
        '',
        'This lower bound screens a depth-sized BGV layout at polynomial modulus degree 32,768. It retains three approximately 55-bit primes after the qualification graph, assigns one approximately 34-bit prime to each consumed multiplication level, and accounts separately for two approximately 60-bit auxiliary evaluation-key primes. The rejected private-opening representation commits to each of four sharing coefficients separately with the smallest computationally hiding BDLOP18 layout and sends one evaluation plus its three-element opening to each remote recipient. The replacement public encrypted-sharing floor uses the certified bounded-integer plaintext prime and model-derived 21-bit zero-failure encoding scale, one common-matrix public-key ring element per recipient, and two ciphertext ring elements for every contributor-recipient pair. It counts the exact KLSW (b,d,v,h) contribution: encryption reuses b[0] and one automorphism uses one h vector. Common vectors are regenerated and their runtime work is omitted. It assumes compact bit-packed transfer elements, and omits every proof, framing byte, scratch allocation, and JavaScript/WebAssembly copy. The tuple is a resource falsifier informed by native development and attack-estimator probes, not a security parameter approval or browser result.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Candidate ciphertext-modulus bits',
                    formatCount(
                        thresholdKeyResources.candidateCiphertextModulusBitLength,
                    ),
                ],
                [
                    'Candidate auxiliary-modulus bits',
                    formatCount(
                        thresholdKeyResources.auxiliaryModulusBitLength,
                    ),
                ],
                [
                    'Candidate combined-modulus bits',
                    formatCount(
                        thresholdKeyResources.candidateCombinedModulusBitLength,
                    ),
                ],
                [
                    'Ciphertext RNS limbs',
                    formatCount(
                        thresholdKeyResources.ciphertextModulusLimbCount,
                    ),
                ],
                [
                    'Serialized ring element',
                    formatCount(
                        thresholdKeyResources.oneSerializedRingElementByteLength,
                    ),
                ],
                [
                    'Ring elements in one public-key contribution',
                    formatCount(
                        thresholdKeyResources.publicKeyContributionRingElementCount,
                    ),
                ],
                [
                    'One public-key contribution',
                    formatCount(
                        thresholdKeyResources.onePublicKeyContributionByteLength,
                    ),
                ],
                [
                    'Ten public-key contributions',
                    formatCount(
                        thresholdKeyResources.publicKeyContributionCorpusByteLength,
                    ),
                ],
                [
                    'Ring elements in four coefficient commitments per contributor',
                    formatCount(
                        thresholdKeyResources.coefficientCommitmentRingElementCountPerContributor,
                    ),
                ],
                [
                    'Four coefficient commitments per contributor',
                    formatCount(
                        thresholdKeyResources.coefficientCommitmentByteLengthPerContributor,
                    ),
                ],
                [
                    'Ten coefficient commitments',
                    formatCount(
                        thresholdKeyResources.coefficientCommitmentCorpusByteLength,
                    ),
                ],
                [
                    'Ring elements in one remote private carrier',
                    formatCount(
                        thresholdKeyResources.minimumPrivateCarrierRingElementCount,
                    ),
                ],
                [
                    'Remote raw-share payload floor',
                    formatCount(
                        thresholdKeyResources.minimumRemoteSharePayloadByteLength,
                    ),
                ],
                [
                    'Private-opening overhead',
                    formatCount(
                        thresholdKeyResources.privateOpeningOverheadByteLength,
                    ),
                ],
                [
                    'Remote private-sharing payload floor',
                    formatCount(
                        thresholdKeyResources.minimumRemotePrivateSharingPayloadByteLength,
                    ),
                ],
                [
                    'Compact-opening proof budget before the variance ceiling',
                    formatCount(
                        thresholdKeyResources.availableCompactOpeningProofCorpusByteLength,
                    ),
                ],
                [
                    'Compact-opening proof budget per remote carrier',
                    formatCount(
                        thresholdKeyResources.availableCompactOpeningProofPerCarrierByteLength,
                    ),
                ],
                [
                    'Share-encryption aggregate noise coefficient bound',
                    formatCount(
                        thresholdKeyResources.shareEncryptionAggregateNoiseCoefficientBound,
                    ),
                ],
                [
                    'Share-encoding scale',
                    formatCount(thresholdKeyResources.shareEncodingScale),
                ],
                [
                    'Share-encryption modulus bits',
                    formatCount(
                        thresholdKeyResources.shareEncryptionModulusBitLength,
                    ),
                ],
                [
                    'Serialized share-encryption ring element',
                    formatCount(
                        thresholdKeyResources.oneSerializedShareEncryptionRingElementByteLength,
                    ),
                ],
                [
                    'Ten share-encryption public keys',
                    formatCount(
                        thresholdKeyResources.shareEncryptionPublicKeyCorpusByteLength,
                    ),
                ],
                [
                    'Ring elements in one optimistic public encrypted share',
                    formatCount(
                        thresholdKeyResources.minimumPublicEncryptedShareCiphertextRingElementCount,
                    ),
                ],
                [
                    'Public encrypted-share corpus floor',
                    formatCount(
                        thresholdKeyResources.minimumPublicEncryptedShareCorpusByteLength,
                    ),
                ],
                [
                    'Public encrypted-sharing setup floor before proofs',
                    formatCount(
                        thresholdKeyResources.minimumPublicEncryptedSharingSetupCorpusByteLength,
                    ),
                ],
                [
                    'Public encrypted-sharing proof budget before the variance ceiling',
                    formatCount(
                        thresholdKeyResources.availablePublicEncryptedSharingProofBudgetByteLength,
                    ),
                ],
                [
                    'Public encrypted-sharing proof budget per contributor',
                    formatCount(
                        thresholdKeyResources.availablePublicEncryptedSharingProofPerContributorByteLength,
                    ),
                ],
                [
                    'Setup transfer corpus floor',
                    formatCount(
                        thresholdKeyResources.minimumSetupTransferCorpusByteLength,
                    ),
                ],
                [
                    'Setup transfer variance ceiling',
                    formatCount(
                        thresholdKeyResources.setupTransferVarianceCeilingByteLength,
                    ),
                ],
                [
                    'Above setup-transfer variance ceiling',
                    thresholdKeyResources.exceedsSetupTransferVarianceCeiling
                        ? 'yes'
                        : 'no',
                ],
                [
                    'Completion evaluation data live set',
                    formatCount(
                        thresholdKeyResources.completionEvaluationDataLiveByteLength,
                    ),
                ],
                [
                    'Aggregate relinearization key live set',
                    formatCount(
                        thresholdKeyResources.aggregateRelinearizationKeyLiveByteLength,
                    ),
                ],
                [
                    'Evaluation plus relinearization floor',
                    formatCount(
                        thresholdKeyResources.minimumEvaluationLiveByteLengthWithRelinearizationKey,
                    ),
                ],
                [
                    'One aggregate unit-rotation key',
                    formatCount(
                        thresholdKeyResources.aggregateUnitRotationKeyLiveByteLength,
                    ),
                ],
                [
                    'Evaluation plus all required evaluation keys floor',
                    formatCount(
                        thresholdKeyResources.minimumEvaluationLiveByteLengthWithAllEvaluationKeys,
                    ),
                ],
                [
                    'Ciphertexts plus current streamed evaluation-key floor',
                    formatCount(
                        thresholdKeyResources.scheduledPeakCiphertextAndCurrentEvaluationKeyByteLength,
                    ),
                ],
                [
                    'Streaming headroom before scratch and copies',
                    formatCount(
                        thresholdKeyResources.streamingMemoryHeadroomBeforeScratchByteLength,
                    ),
                ],
                [
                    'One-key-pass-per-operation local reads',
                    formatCount(
                        thresholdKeyResources.oneKeyPassPerOperationReadByteLength,
                    ),
                ],
                [
                    'WebAssembly absolute memory bound',
                    formatCount(
                        thresholdKeyResources.webAssemblyAbsoluteMemoryBoundByteLength,
                    ),
                ],
                [
                    'Fully resident evaluation plus relinearization above the absolute bound',
                    thresholdKeyResources.exceedsWebAssemblyAbsoluteMemoryBound
                        ? 'yes'
                        : 'no',
                ],
                [
                    'Fully resident evaluation plus all keys above the absolute bound',
                    thresholdKeyResources.exceedsWebAssemblyAbsoluteMemoryBoundWithAllEvaluationKeys
                        ? 'yes'
                        : 'no',
                ],
            ],
        ),
        '',
        '## Public encrypted-sharing proof screen',
        '',
        "This optimistic direct-Ligero screen counts two multiplication constraints for each ternary coefficient, one binary constraint for every shifted-encoding bit, the exact upper-endpoint constraint, and one constraint for each linear ring-coordinate equation. It then searches the discrete power-of-two code dimensions in the exact AHIV22 Section 5.3 communication expression, including Merkle authentication paths. The soundness and random-oracle exponents compensate the CMS19 quadratic and cubic losses for an assumed quantum-query bound plus a component margin, but omit the theorem's asymptotic constant. The screen also omits complete modulus conversion, proof framing and roots, a fixed-hash instantiation, release proofs, and every implementation allocation. Expanded witness and encoded-oracle bytes are proof-field representations, not measured live sets.",
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Ternary ring elements per contributor',
                    formatCount(
                        publicEncryptedSharingProof.ternaryRingElementCountPerContributor,
                    ),
                ],
                [
                    'Sharing-coefficient decomposition bits',
                    formatCount(
                        publicEncryptedSharingProof.sharingCoefficientDecompositionBitLength,
                    ),
                ],
                [
                    'Binary-decomposition ring elements per contributor',
                    formatCount(
                        publicEncryptedSharingProof.binaryDecompositionRingElementCountPerContributor,
                    ),
                ],
                [
                    'Bounded ring elements per contributor',
                    formatCount(
                        publicEncryptedSharingProof.boundedRingElementCountPerContributor,
                    ),
                ],
                [
                    'Bounded coefficients per contributor',
                    formatCount(
                        publicEncryptedSharingProof.boundedCoefficientCountPerContributor,
                    ),
                ],
                [
                    'Ternary constraints per contributor',
                    formatCount(
                        publicEncryptedSharingProof.ternaryConstraintCountPerContributor,
                    ),
                ],
                [
                    'Binary-decomposition constraints per contributor',
                    formatCount(
                        publicEncryptedSharingProof.binaryDecompositionConstraintCountPerContributor,
                    ),
                ],
                [
                    'Binary endpoint constraints per contributor',
                    formatCount(
                        publicEncryptedSharingProof.binaryEndpointConstraintCountPerContributor,
                    ),
                ],
                [
                    'Linear constraints per contributor',
                    formatCount(
                        publicEncryptedSharingProof.linearConstraintCountPerContributor,
                    ),
                ],
                [
                    'Optimistic circuit constraints per contributor',
                    formatCount(
                        publicEncryptedSharingProof.optimisticCircuitConstraintCountPerContributor,
                    ),
                ],
                [
                    'Proof field-element bits',
                    formatCount(
                        publicEncryptedSharingProof.proofFieldElementBitLength,
                    ),
                ],
                [
                    'Interactive soundness bits after query-loss compensation',
                    formatCount(
                        publicEncryptedSharingProof.interactiveSoundnessBitLength,
                    ),
                ],
                [
                    'Random-oracle output bits after query-loss compensation',
                    formatCount(
                        publicEncryptedSharingProof.randomOracleOutputBitLength,
                    ),
                ],
                [
                    'Ligero query count',
                    formatCount(publicEncryptedSharingProof.ligeroQueryCount),
                ],
                [
                    'Ligero repetition count',
                    formatCount(
                        publicEncryptedSharingProof.ligeroRepetitionCount,
                    ),
                ],
                [
                    'Ligero message block length',
                    formatCount(
                        publicEncryptedSharingProof.ligeroMessageBlockLength,
                    ),
                ],
                [
                    'Ligero code dimension',
                    formatCount(
                        publicEncryptedSharingProof.ligeroCodeDimension,
                    ),
                ],
                [
                    'Ligero code length',
                    formatCount(publicEncryptedSharingProof.ligeroCodeLength),
                ],
                [
                    'Ligero witness rows',
                    formatCount(
                        publicEncryptedSharingProof.ligeroWitnessRowCount,
                    ),
                ],
                [
                    'Optimistic Ligero proof per contributor',
                    formatCount(
                        publicEncryptedSharingProof.optimisticLigeroProofByteLengthPerContributor,
                    ),
                ],
                [
                    'Optimistic ten-proof corpus',
                    formatCount(
                        publicEncryptedSharingProof.optimisticTenProofCorpusByteLength,
                    ),
                ],
                [
                    'Proof budget remaining per contributor',
                    formatCount(
                        publicEncryptedSharingProof.proofBudgetRemainingByteLengthPerContributor,
                    ),
                ],
                [
                    'Fits setup proof budget before fixed hash and lifting constant',
                    publicEncryptedSharingProof.fitsSetupProofBudgetBeforeFixedHashAndLiftingConstant
                        ? 'yes'
                        : 'no',
                ],
                [
                    'Expanded bounded witness per contributor',
                    formatCount(
                        publicEncryptedSharingProof.expandedBoundedWitnessByteLengthPerContributor,
                    ),
                ],
                [
                    'Public input per contributor',
                    formatCount(
                        publicEncryptedSharingProof.publicInputByteLengthPerContributor,
                    ),
                ],
                [
                    'Public input plus expanded witness per contributor',
                    formatCount(
                        publicEncryptedSharingProof.publicInputPlusExpandedWitnessByteLengthPerContributor,
                    ),
                ],
                [
                    'Encoded proof-oracle field elements per contributor',
                    formatCount(
                        publicEncryptedSharingProof.encodedProofOracleFieldElementCountPerContributor,
                    ),
                ],
                [
                    'Encoded proof oracle per contributor',
                    formatCount(
                        publicEncryptedSharingProof.encodedProofOracleByteLengthPerContributor,
                    ),
                ],
                [
                    'Encoded proof oracle above setup-storage variance ceiling',
                    publicEncryptedSharingProof.exceedsSetupStorageVarianceCeiling
                        ? 'yes'
                        : 'no',
                ],
            ],
        ),
        '',
        '## Candidate setup-proof field census',
        '',
        "This arithmetic model verifies the exact power-form modulus, factors its base completely, checks one Pocklington witness for every distinct prime divisor of the factored modulus-minus-one, and verifies the production negacyclic-transform congruence. Pocklington's theorem therefore certifies the candidate as prime without relying on a probabilistic primality test. Its exact value also exceeds every bounded direct FHE key residual, including the quotient term. Packed transfer and uint64-limb storage are separate quantities. This selects a field for proof experiments only; it does not prove PIOP security, approve the FHE tuple, or establish browser feasibility.",
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Proof-field modulus',
                    formatCount(candidateSetupProofField.modulus),
                ],
                [
                    'Proof-field modulus bits',
                    formatCount(candidateSetupProofField.modulusBitLength),
                ],
                [
                    'Canonical field-element bytes',
                    formatCount(candidateSetupProofField.modulusByteLength),
                ],
                [
                    'Field element in uint64 limbs',
                    formatCount(candidateSetupProofField.limbByteLength),
                ],
                [
                    'Minimum field modulus for direct FHE key embedding',
                    formatCount(fheKeyEmbedding.minimumProofFieldModulus),
                ],
                [
                    'FHE key quotient ring elements per contributor',
                    formatCount(
                        fheKeyEmbedding.quotientRingElementCountPerContributor,
                    ),
                ],
                [
                    'FHE key quotient magnitude bound',
                    formatCount(fheKeyEmbedding.maximumQuotientMagnitude),
                ],
                ['Power base', formatCount(candidateSetupProofField.powerBase)],
                [
                    'Power exponent',
                    formatCount(candidateSetupProofField.powerExponent),
                ],
                [
                    'Base prime factors certified',
                    formatCount(candidateSetupProofField.basePrimeFactorCount),
                ],
                [
                    'Pocklington witnesses checked',
                    formatCount(
                        candidateSetupProofField.pocklingtonWitnessCount,
                    ),
                ],
                [
                    'Required transform order',
                    formatCount(candidateSetupProofField.transformOrder),
                ],
            ],
        ),
        '',
        '## Share-encryption cross-modulus census',
        '',
        'This exact arithmetic model embeds the composite share-encryption congruences into the much larger candidate setup-proof field. It derives centered numerator bounds, one integer quotient bound for the share-encryption public-key equation and each ciphertext component, and the minimum proof-field width that prevents a false field equality from wrapping. A separate reduced-ring execution constructs valid quotients and rejects a changed public residue. These results establish only the integer embedding and its witness floor; they do not prove the surrounding PIOP, Ring-LWE security, or browser feasibility.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Share-encryption modulus',
                    formatCount(
                        shareEncryptionCrossModulus.shareEncryptionModulus,
                    ),
                ],
                [
                    'Per-contribution share coefficient bound',
                    formatCount(
                        shareEncryptionCrossModulus.perContributionShareCoefficientBound,
                    ),
                ],
                [
                    'Public-key quotient bound',
                    formatCount(
                        shareEncryptionCrossModulus.shareEncryptionKeyQuotientBound,
                    ),
                ],
                [
                    'Ciphertext-first quotient bound',
                    formatCount(
                        shareEncryptionCrossModulus.ciphertextFirstQuotientBound,
                    ),
                ],
                [
                    'Ciphertext-second quotient bound',
                    formatCount(
                        shareEncryptionCrossModulus.ciphertextSecondQuotientBound,
                    ),
                ],
                [
                    'Quotient ring elements per contributor',
                    formatCount(
                        shareEncryptionCrossModulus.quotientRingElementCountPerContributor,
                    ),
                ],
                [
                    'Quotient norm decomposition length',
                    formatCount(
                        shareEncryptionCrossModulus.quotientNormDecompositionLength,
                    ),
                ],
                [
                    'Signed quotient storage bits per coefficient',
                    formatCount(
                        shareEncryptionCrossModulus.quotientSignedEncodingBitLength,
                    ),
                ],
                [
                    'Quotient norm digit ring elements',
                    formatCount(
                        shareEncryptionCrossModulus.quotientNormDigitRingElementCountPerContributor,
                    ),
                ],
                [
                    'Minimum no-wrap proof-field bits',
                    formatCount(
                        shareEncryptionCrossModulus.minimumProofFieldElementBitLength,
                    ),
                ],
                [
                    'Candidate proof-field bits',
                    formatCount(
                        shareEncryptionCrossModulus.candidateProofFieldElementBitLength,
                    ),
                ],
                [
                    'Reduced-ring coefficient equations checked',
                    formatCount(
                        shareEncryptionCrossModulus.toyCoefficientEquationCount,
                    ),
                ],
                [
                    'Changed residue rejected',
                    shareEncryptionCrossModulus.toyTamperRejected
                        ? 'yes'
                        : 'no',
                ],
            ],
        ),
        '',
        '## Polynomial oracle boundary census',
        '',
        'These exact finite-field counterexamples reject the one-mask, reused-query projection and bare-table compilation. Sufficient independent masks repair only the displayed witness-query marginal; low-degree binding, all auxiliary-polynomial views, QROM compilation, and a complete regeneration schedule remain unproved. No proof-size or streaming-feasibility claim is derived from these examples.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'One-mask support per witness after two distinct queries',
                    formatCount(firstMaskedView.size),
                ],
                [
                    'Shared views between the two one-mask witnesses',
                    formatCount(
                        [...firstMaskedView.keys()].filter((view) =>
                            secondMaskedView.has(view),
                        ).length,
                    ),
                ],
                [
                    'Two-mask support per witness after two queries',
                    formatCount(
                        enumerateRandomizedEncodingViews(0, 2, [2, 3]).size,
                    ),
                ],
                [
                    'False binary relation table checks passed',
                    formatCount(falseRelation.entries.length),
                ],
                [
                    'Required quotient maximum degree',
                    formatCount(falseRelation.claimedQuotientMaximumDegree),
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
                    'Recipient-key coefficient bound',
                    formatCount(recipientKeyUniqueness.coefficientBound),
                ],
                [
                    'Difference values per coefficient',
                    formatCount(recipientKeyUniqueness.differenceValueCount),
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
        '## Byte and carry lifting census',
        '',
        'The scalar residual bound covers every accepted signed quotient and carry for the experimental FHE key equation. The finite ring checks positive integer rows and a false large-modulus equation that becomes an alias without the carry bound.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Finite experiment ring degree',
                    formatCount(byteCarryLifting.degree),
                ],
                [
                    'Public coefficient limb count',
                    formatCount(byteCarryLifting.limbCount),
                ],
                ['Limb radix', formatCount(byteCarryLifting.radix)],
                [
                    'Signed quotient magnitude bound',
                    formatCount(byteCarryLifting.quotientBound),
                ],
                [
                    'Signed carry magnitude bound',
                    formatCount(byteCarryLifting.carryBound),
                ],
                [
                    'Maximum accepted per-limb residual bound',
                    formatCount(byteCarryLifting.residualBound),
                ],
                ['Proof-field modulus', formatCount(byteCarryLifting.field)],
                [
                    'Positive integer equations checked',
                    formatCount(byteCarryLifting.positiveIntegerEquations),
                ],
                [
                    'Maximum carry in finite positive cases',
                    formatCount(byteCarryLifting.maximumCarry),
                ],
                [
                    'Maximum quotient in finite positive cases',
                    formatCount(byteCarryLifting.maximumQuotient),
                ],
                [
                    'Carry required by the field alias',
                    formatCount(byteCarryLifting.largestCheatingCarry),
                ],
                [
                    'Out-of-range alias carries',
                    formatCount(byteCarryLifting.outOfRangeCarries),
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
            ],
        ),
        '',
        '## Setup contribution operator census',
        '',
        'The complete reduced-ring model exercises every key, encrypted-share, auxiliary-key, range, and support relation. Full-profile affine rows scale those same equation families to their actual ring degrees. Unused auxiliary padding has no public meaning and needs no zero constraint; support sums read only active coefficients.',
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
            ],
        ),
        '',
        '## Exact RNS arithmetic census',
        '',
        'The recursive-context floor comes from the pinned library allocation structure. The alternative uses flat scalar transform plans and sufficiently wide auxiliary integer residues, then exact CRT lifting and rounding under the existing cryptographic modulus. Cached public transforms and scheduled ciphertexts remain separate live-set costs.',
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
                    'Transform-table bytes per prime',
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
                    'All transformed multiplication-key working bytes',
                    formatCount(rnsArithmetic.cachedMultiplicationKeyBytes),
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
                    'Conservative degree-shift identity degree',
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
        'Conditional soundness screen for the full word-layout shape under the prefix-BCS lemma. The underlying IOP must separately establish its common-agreement and algebraic transition bounds, and the implementation must meet the charged query, verification, and role budgets. This does not include setup privacy, proof zero knowledge, lattice assumptions, fixed-function assumptions, or phone qualification.',
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
                    'Conditional Merkle-privacy exponent after the role union',
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
                    'Adversarial oracle-query budget',
                    formatCount(wideChallengeCompiler.adversaryQueries),
                ],
                [
                    'Verification and expansion oracle budget',
                    formatCount(wideChallengeCompiler.verificationBudget),
                ],
                [
                    'Queries after prefix and role routing',
                    formatCount(wideChallengeCompiler.chargedQueries),
                ],
                [
                    'Proof-role union budget',
                    formatCount(wideChallengeCompiler.roleBudget),
                ],
                [
                    'Conditional QROM soundness exponent',
                    formatCount(wideChallengeCompiler.failureBits),
                ],
            ],
        ),
        '',
        '## Common-matrix sampling census',
        '',
        'A fixed admitted suite label selects independent ideal-oracle words. Exact modulo-law enumeration checks the residue distance and the corresponding conditional full-oracle law. The complete bound includes all FHE, sharing, and auxiliary common polynomials. Caller-selected labels, adaptive parameter grinding, the fixed SHAKE implementation, and cryptographic security of the resulting keys are not established by this sampling calculation.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Sample bits per coefficient',
                    formatCount(commonMatrixSampling.bitsPerCoefficient),
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
        '## Publication cut census',
        '',
        "The freeze-and-union model retains complete ECHO certificates inside each honest READY sender's close report. The intersection census checks every named completed-publication quorum, close quorum, and maximum corruption set. It establishes the required honest reporter, not a complete protocol or a visit bound.",
        '',
        table(
            ['Property', 'Value'],
            [
                ['Participants', formatCount(publicationCut.participantCount)],
                [
                    'Publication and close quorum',
                    formatCount(publicationCut.quorum),
                ],
                [
                    'Named intersections checked',
                    formatCount(publicationCut.checkedIntersections),
                ],
                [
                    'Minimum honest reporters of every completed publication',
                    formatCount(
                        publicationCut.minimumHonestPublicationReporters,
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
                        archiveHolderRequirements(
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
                        archiveHolderRequirements(
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
        '## Early commitment extraction census',
        '',
        'DFMS21 Corollary 4.8 for full-body contribution commitments, including losing frozen inventory views. Fixed-suite public matrices remove the former seed-commitment stage. The sum charges both simulator disturbance and valid-opening mismatch. This is an ideal-QROM arithmetic bound, not a setup or fixed-hash security claim.',
        '',
        table(
            [
                'Participants',
                'Relevant commitments',
                'Hash output bits',
                'Quantum query bound',
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
                    bound.combinedFailureExponent === undefined
                        ? 'No extraction event'
                        : formatCount(bound.combinedFailureExponent),
                ];
            }),
        ),
        '',
        '## Fixed-witness release simulation census',
        '',
        'This scalar counterexample applies the KLLPS simulation equation with three fixed corrupt coordinates and one honest release. Using the actual ciphertext plaintext satisfies the expanded noise relation; substituting another output decodes that output but violates the relation to the fixed honest setup witness. It rejects that simulator chronology, not threshold FHE as a family.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Same-plaintext noise checks passed',
                    formatCount(
                        releaseSimulation.samePlaintextNoiseChecksPassed,
                    ),
                ],
                [
                    'Changed-plaintext noise checks refused',
                    formatCount(
                        releaseSimulation.changedPlaintextNoiseChecksRefused,
                    ),
                ],
            ],
        ),
        '',
        '## Publication and close local-view census',
        '',
        'The rejected close rule can strand an honest READY sender when other honest parties close before receiving its complete ECHO evidence. Every honest message is eventually delivered, while corrupt parties remain silent. Neither publication nor close obtains its quorum. This is a pre-certification liveness counterexample and does not invalidate the post-certification threshold arithmetic.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Continuing honest participants in the close race',
                    formatCount(closeRace.honestParticipants),
                ],
                [
                    'READY signers after complete delayed delivery',
                    formatCount(closeRace.readySigners),
                ],
                [
                    'Close signers after complete delayed delivery',
                    formatCount(closeRace.closeSigners),
                ],
                [
                    'Delivered honest messages',
                    formatCount(closeRace.deliveredMessages),
                ],
                [
                    'Unresolved honest READY waiters',
                    formatCount(closeRace.unresolvedReadyWaiters),
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
        '## Generic commit-and-open setup-proof floor',
        '',
        'This optimistic subtotal applies the pinned 128-bit quantum ZKB++/Unruh repetition count and only the binary-multiplication term of its proof-size formula to the bounded coefficients in the depth-sized setup witness. It charges an unrealistically favorable one non-linear gate per bounded coefficient and omits all inputs, commitments, openings, linear work, encrypted sharing expansion, and proof framing. It rejects this direct generic compiler for setup, not commit-and-open proofs or lattice-native proofs as families.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Quantum-security parallel repetitions',
                    formatCount(
                        genericProofResources.quantumSecurityParallelRepetitionCount,
                    ),
                ],
                [
                    'Proof bits per binary multiplication gate',
                    formatCount(
                        genericProofResources.proofBitsPerBinaryMultiplicationGate,
                    ),
                ],
                [
                    'Bounded ring elements per setup witness',
                    formatCount(
                        genericProofResources.boundedRingElementCountPerSetupContribution,
                    ),
                ],
                [
                    'Bounded coefficients per setup witness',
                    formatCount(
                        genericProofResources.boundedCoefficientCountPerSetupContribution,
                    ),
                ],
                [
                    'Proof floor per setup contribution',
                    formatCount(
                        genericProofResources.minimumProofSizePerSetupContributionByteLength,
                    ),
                ],
                [
                    'Ten-proof corpus floor',
                    formatCount(
                        genericProofResources.minimumProofCorpusByteLength,
                    ),
                ],
                [
                    'Setup plus proof subtotal',
                    formatCount(
                        genericProofResources.combinedSetupAndProofSubtotalByteLength,
                    ),
                ],
                [
                    'Above setup-transfer variance ceiling',
                    genericProofResources.exceedsSetupTransferVarianceCeiling
                        ? 'yes'
                        : 'no',
                ],
            ],
        ),
        '',
        '## Participant visit dependency census',
        '',
        'The preparation prefix counts joining, roster confirmation and seed commitment, seed opening, verified share-encryption keys, setup contributions, all-roster receipts, and an optional ballot attempt. The completing witness then executes the freeze-and-union publication model with immediate delivery, all enabled work coalesced, and corrupt participants refusing after valid preparation. Publication, close, target certification, release, and terminal retrieval exceed the ceiling. An additional setup-proof commitment wave is not charged, so it cannot rescue this rejected composition. These are witnessed costs, not worst-case upper bounds.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Participants in the sequential witness',
                    formatCount(participantVisits.participantCount),
                ],
                [
                    'First participant preparation visits including joining',
                    formatCount(participantVisits.preparationWitnessVisitCount),
                ],
                [
                    'First ballot author visits through its attempt',
                    formatCount(
                        participantVisits.ballotAuthorWitnessVisitCount,
                    ),
                ],
                [
                    'Remaining productive visits within the mandatory ceiling',
                    formatCount(participantVisits.remainingVisitBudget),
                ],
                [
                    'First participant visits in the completing witness',
                    formatCount(participantVisits.completionWitnessVisitCount),
                ],
                [
                    'Completing witness visits above the mandatory ceiling',
                    formatCount(participantVisits.completionWitnessExcess),
                ],
                [
                    'Fixed-suite preparation with eager publication, favorable witness',
                    formatCount(
                        participantVisits.commonMatrixCompletionWitnessVisitCount,
                    ),
                ],
                [
                    'Fixed-suite preparation with eager publication, interleaved ballots',
                    formatCount(
                        participantVisits.interleavedCommonMatrixWitnessVisitCount,
                    ),
                ],
                [
                    'Batched close candidate, conditional result-stage bound',
                    formatCount(
                        batchedPublicationVisits.maximumParticipantStages,
                    ),
                ],
                [
                    'Batched close candidate, conditional no-result-stage bound',
                    formatCount(batchedPublicationVisits.maximumNoResultStages),
                ],
                [
                    'Preferred visit count',
                    formatCount(participantVisits.preferredVisitCount),
                ],
                [
                    'Mandatory visit ceiling',
                    formatCount(participantVisits.maximumPermittedVisitCount),
                ],
            ],
        ),
        '',
        '## Exact ranking arithmetic census',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Plaintext modulus used by the arithmetic experiment',
                    formatCount(exactRankingModelConstants.plaintextModulus),
                ],
                [
                    'Maximum total difference magnitude',
                    formatCount(exactRankingModelConstants.maximumDifference),
                ],
                [
                    'Comparison interpolation points',
                    formatCount(rankingCensus.exhaustiveComparisonPointCount),
                ],
                [
                    'Comparison polynomial degree',
                    formatCount(rankingCensus.comparisonPolynomialDegree),
                ],
                [
                    'Nonzero comparison coefficients',
                    formatCount(
                        rankingCensus.comparisonPolynomialNonzeroCoefficientCount,
                    ),
                ],
                [
                    'Rank-equality domains checked',
                    formatCount(rankingCensus.equalityDomainCount),
                ],
                [
                    'Packed option/result-width layouts checked',
                    formatCount(rankingCensus.packedLayoutCount),
                ],
                [
                    'Participant/option profiles checked',
                    formatCount(
                        rankingCensus.testedParticipantOptionProfileCount,
                    ),
                ],
                [
                    'Adversarial and deterministic score matrices checked',
                    formatCount(rankingCensus.testedMatrixCount),
                ],
                [
                    'Result-width executions checked',
                    formatCount(rankingCensus.testedTopCountExecutionCount),
                ],
            ],
        ),
        '',
        'The comparison returns one when a lower canonical option position has a nonnegative total difference. This incorporates the lower-position tie rule. Rank-equality polynomials are independently interpolated and exhaustively checked on every rank domain from two through twenty options.',
        '',
        '## Packed ranking graph census',
        '',
        'The graph uses one packed ciphertext per accepted ballot. Each power-of-two option block reserves the requested-rank lanes, then carries every opponent-minus-current score difference. Slot-varying coefficients select strict or non-strict comparison according to the canonical tie order, so one block-size-24 Paterson-Stockmeyer evaluation computes every ordered-pair predicate. Repeated unit-direction rotations accumulate one encrypted rank per block and copy it backward across the requested-rank lanes; one slot-varying equality evaluation yields a one-hot encoding of exactly the requested identifiers. The terminal decoder checks and converts that leakage-equivalent encoding. The ciphertext-byte projection assumes a polynomial modulus degree of 32,768, 64-bit RNS limbs, and one remaining data prime per consumed multiplicative level; the release-capable resource screen separately retains its bottom-prime reserve. It counts scheduled data ciphertexts only; evaluation keys, scratch allocations, serialization copies, proof data, and the WebAssembly runtime are additional. This is not a selected parameter set.',
        '',
        table(
            [
                'Graph property',
                'Ten participants/options',
                'Twenty participants/options',
            ],
            [
                [
                    'Ordered pair-difference lanes',
                    formatCount(completionGraph.orderedPairDifferenceLaneCount),
                    formatCount(maximumGraph.orderedPairDifferenceLaneCount),
                ],
                [
                    'Packed ballot lanes including block padding',
                    formatCount(completionGraph.packedBallotLaneCount),
                    formatCount(maximumGraph.packedBallotLaneCount),
                ],
                [
                    'Multiplicative depth',
                    formatCount(completionGraph.multiplicativeDepth),
                    formatCount(maximumGraph.multiplicativeDepth),
                ],
                [
                    'Ciphertext multiplications',
                    formatCount(completionGraph.ciphertextMultiplicationCount),
                    formatCount(maximumGraph.ciphertextMultiplicationCount),
                ],
                [
                    'Relinearizations',
                    formatCount(completionGraph.relinearizationCount),
                    formatCount(maximumGraph.relinearizationCount),
                ],
                [
                    'Relinearization-key ring-limb reads with one pass per operation',
                    formatCount(
                        completionGraph.relinearizationKeyRingLimbReadCount,
                    ),
                    formatCount(
                        maximumGraph.relinearizationKeyRingLimbReadCount,
                    ),
                ],
                [
                    'Rotations',
                    formatCount(completionGraph.rotationCount),
                    formatCount(maximumGraph.rotationCount),
                ],
                [
                    'Rotation-key ring-limb reads with one pass per operation',
                    formatCount(completionGraph.rotationKeyRingLimbReadCount),
                    formatCount(maximumGraph.rotationKeyRingLimbReadCount),
                ],
                [
                    'Ciphertext additions',
                    formatCount(completionGraph.ciphertextAdditionCount),
                    formatCount(maximumGraph.ciphertextAdditionCount),
                ],
                [
                    'Plaintext multiplications',
                    formatCount(completionGraph.plaintextMultiplicationCount),
                    formatCount(maximumGraph.plaintextMultiplicationCount),
                ],
                [
                    'Scheduled peak live ciphertexts',
                    formatCount(
                        completionGraph.scheduledPeakLiveCiphertextCount,
                    ),
                    formatCount(maximumGraph.scheduledPeakLiveCiphertextCount),
                ],
                [
                    'Projected scheduled peak ciphertext bytes',
                    formatCount(
                        completionGraph.scheduledPeakCiphertextByteLength,
                    ),
                    formatCount(maximumGraph.scheduledPeakCiphertextByteLength),
                ],
                [
                    'Materialized graph nodes',
                    formatCount(
                        completionGraph.materializedCiphertextNodeCount,
                    ),
                    formatCount(maximumGraph.materializedCiphertextNodeCount),
                ],
            ],
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
