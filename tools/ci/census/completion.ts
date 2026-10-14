import { fullHolderRequirements } from '#tests/certificate-custody-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import {
    completionProfileCounts,
    deriveSupportedProfile,
} from '#tests/supported-profile-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';
import type { CensusInputs } from '#tools/ci/census/inputs.js';

export const renderThresholdCompletionCensus = ({
    thresholdProfiles,
}: Pick<CensusInputs, 'thresholdProfiles'>): string[] => [
    '## Threshold completion census',
    '',
    'The lifecycle census allows independently bounded disappearance and corrupt-refusal sets. The scope of this stronger candidate availability model is owned by [non-forking state](private:candidate-availability-threshold); its responder floor is not an additional mandatory fault budget.',
    '',
    'For each supported roster, the model uses `f = floor((n - 1) / 3)`, inventory-certificate threshold `q = n - f`, result-release threshold `d = max(f + 1, 2)`, which is also the number of selected setup contributors, and minimum turnout `m = f + 2` accepted ballots. At least one selected contributor is honest because `d > f`, and no single one knows the key because `d >= 2`. Every roster member derives its release share from the certified setup, so any `f` disappearances and `f` corruptions leave at least `n - 2f >= d` honest share holders, and `d < n`. At most `f` accepted ballots are corrupt, so a released result combines at least two honest ballots. When every honest participant votes, omitting `f` honest ballots while every corrupt participant abstains leaves `n - 2f` accepted ballots; the no-result column marks rosters where that is below `m`. A `q` close certificate has at least `n - 2f` honest locked signers, and two such certificates share at least `2q - n > f` positions, so a conflicting certificate needs an honest signer to sign twice. Every named set is counted; isomorphic joint cases are checked with exact multiplicity, and profiles through twelve participants are also brute-force cross-checked over the underlying bit masks.',
    '',
    table(
        [
            'Participants',
            'Maximum corrupt',
            'Inventory certificate',
            'Result release',
            'Minimum turnout',
            'No result forceable at full honest turnout',
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
            String(profile.guaranteedHonestResponderCount),
            String(profile.minimumCertificateIntersection),
            String(profile.mandatoryReleaseParticipantCount),
            formatCount(profile.corruptionDisappearanceRefusalCaseCount),
            formatCount(profile.orderedCertificatePairCount),
            profile.bruteForceCrossChecked ? 'yes' : 'class-counted',
        ]),
    ),
    '',
];

export const renderThresholdKeyAggregationStructuralCensus = ({
    thresholdKeyAggregation,
}: Pick<CensusInputs, 'thresholdKeyAggregation'>): string[] => [
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
                formatCount(thresholdKeyAggregation.authorizedReleaseSetCount),
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
];

export const renderRecipientKeyUniquenessCensus = ({
    recipientKeyUniqueness,
}: Pick<CensusInputs, 'recipientKeyUniqueness'>): string[] => [
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
                formatCount(recipientKeyUniqueness.secretDifferenceValueCount),
            ],
            [
                'Error difference values per coefficient',
                formatCount(recipientKeyUniqueness.errorDifferenceValueCount),
            ],
            [
                'Squared determinant-union base numerator',
                formatCount(recipientKeyUniqueness.squaredFailureBaseNumerator),
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
];

export const renderCertificateCustodyCensus = ({
    certificateCustody,
}: Pick<CensusInputs, 'certificateCustody'>): string[] => [
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
                'Required target votes',
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
];

export const renderCloseResponseCensus = ({
    closeResponses,
}: Pick<CensusInputs, 'closeResponses'>): string[] => [
    '## Close-response census',
    '',
    "Each roster uses the close quorum `q = n - f`, guarantees inclusion of an on-time envelope that `f + 1` honest participants received before responding, and omits at most `f` honest ballots. A response lists at most two envelopes per slot. With every honest participant voting, omitting `f` honest ballots while every corrupt participant abstains leaves `n - 2f` accepted ballots. The stage bound adds three preparation visits, for registration, roster confirmation with the contribution offer and setup selection with endorsement, to setup verification with the ballot, the close response, target signature, release share and verification; the organizer's close intent and proposal replace its response and signature, and a nonvoter verifies setup in a visit of its own. Prioritized message-level executions attain every stage bound.",
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
            census.findings.length === 0 ? 'none' : census.findings.join(', '),
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
            ['Executions', formatCount(closeResponses.execution.executions)],
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
                formatCount(closeResponses.execution.forcedNoResultExecutions),
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
                    closeResponses.execution.maximumForwardedToHonestOrganizer,
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
                    closeResponses.execution.maximumOrganizerRequestsPerSlot,
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
                'Omitted voters and corrupt participants refuse target votes',
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
                    closeResponses.counterexamples.forwardingFindings.length ===
                    0
                        ? 'none'
                        : closeResponses.counterexamples.forwardingFindings.join(
                              ', ',
                          )
                }`,
            ],
            [
                'The organizer publishes its closure before its proposal',
                `${formatCount(closeResponses.counterexamples.closureCertifiedTargets)} certified target, findings: ${
                    closeResponses.counterexamples.closureFindings.length === 0
                        ? 'none'
                        : closeResponses.counterexamples.closureFindings.join(
                              ', ',
                          )
                }`,
            ],
        ],
    ),
    '',
];

export const renderThresholdReleaseFloodingBound = ({
    thresholdReleaseNoise,
}: Pick<CensusInputs, 'thresholdReleaseNoise'>): string[] => [
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
                formatCount(thresholdReleaseNoise.exactInterpolationProduct),
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
];

export const renderCloseWireCensus = ({
    ballotBody,
    completion,
    thresholdProfiles,
}: Pick<
    CensusInputs,
    'ballotBody' | 'completion' | 'thresholdProfiles'
>): string[] => {
    const completionWire = compileCloseWireCensus(completion);
    const rosterWires = thresholdProfiles.map(({ participantCount }) => ({
        participantCount,
        value: compileCloseWireCensus(
            deriveSupportedProfile(
                participantCount,
                completionProfileCounts.optionCount,
            ),
        ),
    }));
    return [
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
                    formatCount(completionWire.submissionBytes),
                ],
                [
                    'Close intent body bytes',
                    formatCount(completionWire.intentBodyBytes),
                ],
                [
                    'Empty response body bytes',
                    formatCount(completionWire.minimumResponseBodyBytes),
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
            rosterWires.map(({ participantCount, value }) => [
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
            ]),
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
            rosterWires.map(({ participantCount, value }) => [
                formatCount(participantCount),
                formatCount(value.maximumListedCopyBytes),
                formatCount(value.maximumForwardedBodies),
                formatCount(value.maximumForwardedBodyBytes),
            ]),
        ),
    ];
};
