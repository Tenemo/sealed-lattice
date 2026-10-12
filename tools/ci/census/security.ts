import { compileCurrentSignatureHashInputs } from '#tests/authentication-work-model.js';
import {
    sparseRoutingWork,
    labelledHashExtractionWork,
    prefixOracleWork,
    oracleMaskRoutingWork,
} from '#tests/compressed-oracle-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
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
import {
    compilePreparationLedger,
    compilePreparationPollPopulations,
} from '#tests/preparation-ledger-model.js';
import {
    compileProofHashWork,
    firstOracleResumeHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { sourceOpeningSaltBytes } from '#tests/registration-setup-binding-model.js';
import { minimumRegistrationSourceInputBytes } from '#tests/registration-source-domain-model.js';
import { compileRegistrationSourceExtractionWork } from '#tests/registration-source-randomness-model.js';
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
import { compileSimulatorKeyKnowledgeCensus } from '#tests/simulator-key-knowledge-model.js';
import {
    deriveSupportedProfile,
    listSupportedProfiles,
} from '#tests/supported-profile-model.js';
import {
    formatCount,
    table,
    formatWorkAllowance,
    formatLog2Cost,
    formatPopulationLimit,
    rangeOf,
} from '#tools/ci/census/format.js';
import type { CensusInputs } from '#tools/ci/census/inputs.js';

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
export const renderProofHashByteAndPermutationWork = ({
    completion,
    maximumFirstOracleResume,
}: Pick<CensusInputs, 'completion' | 'maximumFirstOracleResume'>): string[] => [
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
                formatCount(value.proverCoreWithoutPrefixReuse.permutations),
                formatCount(value.proverCore.permutations),
                formatCount(
                    value.groups.reduce(
                        (sum, group) => sum + group.prefixReuse.initializations,
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
                formatCount(value.verifierCoreWithoutPrefixReuse.permutations),
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
                            sum + BigInt(group.openingCounts.restoredLeaves),
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
];

export const renderComposedSecurityLedger = ({
    supportedProfiles,
}: Pick<CensusInputs, 'supportedProfiles'>): string[] => [
    '## Composed security ledger',
    '',
    'The [preparation argument](private:preparation-ledger) owns the conditional hybrid interfaces. The first tables evaluate fixed-roster-size structural upper bounds at the displayed example original-honest-registration population H, including abandoned and unselected registrations; H is not an admitted population limit. Whole-poll bounds permitting different roster sizes follow separately. Started private preparation and certified rosters have different bounds. Original contribution scopes include failed or unfinished generation before publication; a replay of the same retained intent adds work but no new scope. Primitive comparison counts include the source-family or selected-position guesses where required, but exclude semantic-use error charges and reduction-time operands. The assumption group limits at the end of this section take their proof terms from the proof-compiler gate\x27s theorems; no end-to-end security level is emitted.',
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
                compilePreparationLedger(
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
                rangeOf(ledgers.map((value) => value.generatedSourceEntries)),
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
            const value = compilePreparationLedger(
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
            const poll = compilePreparationPollPopulations(
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
            const ledger = compilePreparationPollPopulations(
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
    'The [margin model](../tests/security-margin-screen-model.ts) tests whether the current FHE comparisons can reach the target with the current parameters. It charges every single-key FHE Ring-LWE comparison of the [preparation ledger](private:preparation-ledger) at one original honest registration per participant, expanding each multi-message ballot comparison over its messages. The withdrawn ledger’s seven assumption groups share the 2^-80 budget equally. Each requirement charges the reduction’s work at the largest complete experiment within 2^80 gates that fills whole permutation slots. The reduction’s work depends on an experiment only through those slots and its query routing grows with their square, so that experiment has the largest reduction ratio; the source cache and the extractions’ fixed work, which do not grow with the experiment, leave every smaller experiment’s ratio below it, as the margin test checks at the population limits. The lattice assumptions hold relative to the ideal SHAKE oracle, so the forwarded column, which adds no work, is the floor for a reduction that never reads or programs the attacker’s queries. The FHE embedding fixes each pivot’s honest coordinate after its registration commitment from extracted corrupt registration coordinates, so it reads and programs the registration-source commitment domain with one commitment shadow per potential sender scope. The source-domain column implements only that domain, forwards every other query and prices the complete reduction except the simulated proofs’ record creation: its query circuits, the replacement wrapper for every programmed honest proof, the classical-reader and resumed-hash conversions of the forwarded honest calls and the forwarded calls themselves, every corrupt registration-source extraction with its coordinate decoding, and the source cache. A call reaches that domain only if its input capacity holds the shortest registration-source input, so it costs at least that input’s permutations, and every source input lies in one dyadic input class; the database terms are the full-domain bound restricted to those calls and that class. The converted honest calls read private streams and proof hashes outside that domain, so the conversions enlarge only the forwarded calls. The background column prices only the query circuits of a reduction that implements the whole function itself, as one without the oracle-relative assumption must, and the shadow column adds its commitment shadows. The reader column applies the classical fixed-input reader conversion that participant code uses. The resumed column applies the larger conversion for setup first-oracle leaf hashes resumed from an authenticated checkpoint, conditional on the original input staying available to the adapter. Those four columns omit every other reduction cost, so they are lower bounds. Each row shows the option count whose source-domain requirement leaves the least further work within its own criterion floor, the largest modulus among equals. The floors are the cheapest core-SVP screens that the [security argument](private:security-ledger) cites; a screen at one modulus bounds the same attack at every smaller supported modulus. Attack costs follow the accepted convention, without quantum random-access memory, so the classical floor over every algorithm of the estimator’s full estimate is the criterion. The quantum model’s sieving speedup assumes that memory, so its floor is a stress test. Neither model counts gates as the convention does. The last column is the further reduction work, in whole log2 gates, that keeps the source-domain requirement within the whole bits of the criterion floor, or none where the priced work alone exceeds them; the simulated proofs’ record creation must fit within it.',
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
                    row.requirements.find((value) => value.variant === variant)!
                        .requiredBits,
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
    'The [security ledger model](../tests/security-ledger-model.ts) derives each assumption group’s own limit on a poll’s original honest registrations and takes the poll’s limit as the smallest, with the proof terms resting on the proof-compiler gate’s theorems. The seven groups share the budget as above, so each bounds the ratio of its contribution to the experiment’s cost by 2^-83 at every experiment within 2^80 gates. The lattice groups price their comparisons with the source-domain reduction of the screen above. Circular security of the honest evaluation-key tuples is judged against the FHE instance’s floor at each option count’s modulus. The fixed share-encryption and auxiliary instances use the following core-SVP screens of the pinned estimator with unlimited samples; an attack whose estimate has no finite cost at any block size has no floor, and an instance without a finite screen in a cost model imposes no limit in it. A group that stays within its level at 2^64 registrations has no limit below that search cap, shown as none.',
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
                            formatPopulationLimit(row[floor].limits.get(group)),
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
];

export const renderSimulatorRecipientKeyAvailability = (): string[] => [
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
];

export const renderCompressedOracleCircuitWork = ({
    completion,
    maximumFirstOracleResume,
    registrationSourceRandomness,
}: Pick<
    CensusInputs,
    'completion' | 'maximumFirstOracleResume' | 'registrationSourceRandomness'
>): string[] => [
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
            ([count, inputCapacity, outputCapacity, inputBits, prefixBits]) => {
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
    'The full-circuit convention charges controlled permutation slots regardless of branch probability. Separate input and output maxima are bounded by a rectangle costing at most twice that slot budget. These examples price the complete programmed/background query circuit, every declared shadow and its selection circuit. All caller queries must enter the supplied budget; extra reduction calls, non-oracle computation and constructor work cannot be silently charged to the original experiment. The record and shadow counts below are declared examples, not a numerical registration limit.',
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
    'The raw registration-source slice fixes the source grammar, original owner, immutable family and salt at their actual bit positions. Its exact length is checked; the poll and the coordinate payload stay unconstrained. Current protocol credential hash calls are shorter than this source language even at its syntactic minimum. This separates raw oracle inputs, not their potentially dependent message values. Retained tags have the distinct fixed ProtocolHash prefix.',
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
    'The following query-controller and prepared-extraction counts use the completion poll family inventory, an output prefix equal to the commitment width and a declared extraction database capacity. The separate returned-coordinate circuit checks the extracted poll, canonical centered coefficients and absence of negative zero, then copies the salt and coordinate or a zero dummy with a distinct validity bit. It includes clean compute/copy/uncompute even on missing or malformed extraction. The independent query circuit, cache indexing, circuit construction and later polynomial arithmetic remain separate costs.',
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
                            replacements: [{ inputBits: 4n, prefixBits: 2n }],
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
];

export const renderCommitmentEquivocationFiniteModel = ({
    commitmentEquivocation,
    commitmentPrefix,
    duplicateCommitmentInputs,
}: Pick<
    CensusInputs,
    'commitmentEquivocation' | 'commitmentPrefix' | 'duplicateCommitmentInputs'
>): string[] => [
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
];
