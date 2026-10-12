import { compileProofCompilerChronology } from '#tests/proof-compiler-chronology-model.js';
import { formatCount, table, rangeOf } from '#tools/ci/census/format.js';
import type { CensusInputs } from '#tools/ci/census/inputs.js';

export const renderBoundedPolynomialProofCensus = ({
    boundedLinearProof,
    boundedLookup,
}: Pick<CensusInputs, 'boundedLinearProof' | 'boundedLookup'>): string[] => [
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
                formatCount(boundedLinearProof.shortMaskViews.observationCount),
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
                formatCount(boundedLinearProof.simulatedFalseAcceptanceCount),
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
];

export const renderProofVerifierQueryBounds = ({
    proofVerifierQueries,
}: Pick<CensusInputs, 'proofVerifierQueries'>): string[] => [
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
];

export const renderRelationIntegerLiftingCensus = ({
    relationLifting,
}: Pick<CensusInputs, 'relationLifting'>): string[] => [
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
];

export const renderCommonAgreementDegreeCensus = ({
    commonAgreement,
}: Pick<CensusInputs, 'commonAgreement'>): string[] => [
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
            ['Evaluation domain size', formatCount(commonAgreement.domainSize)],
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
            ['Independent query pairs', formatCount(commonAgreement.queries)],
            [
                'Joint masking dimension',
                formatCount(commonAgreement.maskDimension),
            ],
        ],
    ),
    '',
];

export const renderWideChallengeCompilerCensus = ({
    sampledRoundErrors,
    familyRoundErrors,
    effectiveRelations,
    commonAgreement,
    proofHashDomain,
    wideChallengeCompiler,
}: Pick<
    CensusInputs,
    | 'sampledRoundErrors'
    | 'familyRoundErrors'
    | 'effectiveRelations'
    | 'commonAgreement'
    | 'proofHashDomain'
    | 'wideChallengeCompiler'
>): string[] => [
    '## Wide-challenge compiler census',
    '',
    'The current conditional ordinary round bound uses BCIKS20 Theorem 7.2 and Claim 8.5 with the reviewed consistency-weight state. At the displayed agreement threshold and rate, the proof-analysis parameter changes no verifier bytes. Each role separately compares exact-uniform query sampling against its density-adjusted maximum of the restricted lookup, affine and coalesced batching/weighted-fold terms. The underlying common-agreement, degree, masking and semantic correspondence premises remain explicit in the security argument; these arithmetic rows establish no end-to-end security level.',
    '',
    table(
        ['Weighted-fold operand', 'Value'],
        [
            [
                'Proof-analysis parameter',
                formatCount(sampledRoundErrors.weightedFri.analysisParameter),
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
                formatCount(sampledRoundErrors.weightedFri.agreementNumerator),
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
                formatCount(sampledRoundErrors.weightedFri.upper.denominator),
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
    'Every effective relation of the fixed family is some supported profile\x27s relation, so the maxima over every profile cover every relation. The [ordinary round-by-round soundness theorem](private:round-by-round-soundness) bounds each relation\x27s round error by the larger of the query term and its sampled algebraic bound; the margin is the least whole number of bits by which the query term exceeds that bound for one relation of the purpose.',
    '',
    table(
        [
            'Purpose',
            'Effective relations',
            'Largest original and virtual oracles',
            'Largest lookup root degree',
            'Largest affine rows',
            'Largest consumed base-field samples',
            'Least query margin in whole bits',
            'Query term is every relation\x27s round error',
        ],
        familyRoundErrors.purposes.map((purpose) => [
            purpose.name,
            formatCount(effectiveRelations.get(purpose.name)?.size ?? 0),
            ...[
                purpose.oracles,
                purpose.lookupRootDegree,
                purpose.affineRows,
                purpose.baseFieldSamples,
                purpose.queryMarginBits,
            ].map(formatCount),
            purpose.queryDominates ? 'Yes' : 'No',
        ]),
    ),
    '',
    table(
        ['Family round error', 'Value'],
        [
            ['Query draws', formatCount(commonAgreement.queries)],
            [
                'Query term bits below one, rounded down',
                formatCount(familyRoundErrors.queryErrorBits),
            ],
            [
                'Largest round error equals the query term',
                familyRoundErrors.maximumRoundError.numerator *
                    familyRoundErrors.queryError.denominator ===
                familyRoundErrors.queryError.numerator *
                    familyRoundErrors.maximumRoundError.denominator
                    ? 'Yes'
                    : 'No',
            ],
        ],
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
                formatCount(proofHashDomain.maximumAcceptedExpansionQueries),
            ],
        ],
    ),
    '',
    'W_F bounds complete raw inputs recognized by the fixed grammar, including full statements rather than their identifiers; it is expressed in bits for the conservative substring reference bound and does not bound arbitrary auxiliary oracle inputs. The only fixed hash-label sentinel is the zero initial-state label; absent or malformed predecessors resolve to no context or oracle entry. M_F reuses the source-linked shared-path Merkle and transcript expansion census. The finite-family expression still requires the complete prior oracle history and mapped reducer costs; these operands select no numerical security claim.',
    '',
    'The following prefix-compiler caps and exponents are historical role-union reference arithmetic. Its conservative algebraic numerator now includes the weighted folding term, but its finite corrupt-role population and whole-experiment composition are not established for preparation. The current finite-family argument takes a maximum of the per-role sampled-round bounds above without adding a family union factor. Reference exponents below do not select a new honest-credential scope or claim admission, end-to-end security, or supported-phone qualification.',
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
                formatCount(wideChallengeCompiler.ordinaryAlgebraicNumerator),
            ],
            [
                'Historical role-union QROM reference exponent',
                formatCount(wideChallengeCompiler.failureBits),
            ],
        ],
    ),
    '',
];

export const renderProofCompilerChronology = ({
    supportedProfiles,
}: Pick<CensusInputs, 'supportedProfiles'>): string[] => [
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
                    chronologies.map((value) => value.committedNodesPerProof),
                ),
                rangeOf(
                    chronologies.map((value) => value.widestNonSaltInputBits),
                ),
            ];
        }),
    ),
    '',
];

export const renderFullWordProofEncodingCensus = ({
    fullWordProof,
}: Pick<CensusInputs, 'fullWordProof'>): string[] => [
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
];

export const renderProofFieldCoefficientFoldBounds = ({
    proofFieldReduction,
}: Pick<CensusInputs, 'proofFieldReduction'>): string[] => [
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
];

export const renderSmallLimbProofFieldCensus = ({
    smallLimbProofField,
}: Pick<CensusInputs, 'smallLimbProofField'>): string[] => [
    '## Small-limb proof-field census',
    '',
    'Proth-certified base field and certified cubic extension for the lookup direction. Large-modulus equations require a separate integer limb-and-carry compiler with complete bounds.',
    '',
    table(
        ['Property', 'Value'],
        [
            ['Base-field modulus', formatCount(smallLimbProofField.modulus)],
            ['Word radix', formatCount(smallLimbProofField.wordRadix)],
            [
                'Reduction offset',
                formatCount(smallLimbProofField.reductionOffset),
            ],
            ['Proth odd factor', formatCount(smallLimbProofField.oddFactor)],
            ['Proth witness', formatCount(smallLimbProofField.prothWitness)],
            [
                'Cubic nonresidue',
                formatCount(smallLimbProofField.cubicNonresidue),
            ],
            ['Field bits', formatCount(smallLimbProofField.modulusBitLength)],
            [
                'Packed base-field bytes',
                formatCount(smallLimbProofField.packedFieldElementByteLength),
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
];
