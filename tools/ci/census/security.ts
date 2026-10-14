import {
    compilePreparationLedger,
    compilePreparationPollPopulations,
} from '#tests/preparation-ledger-model.js';
import {
    atMost,
    rational,
    rationalCeilingLog2,
    type Rational,
} from '#tests/security-ledger/rational.js';
import {
    compileAuthenticationGroup,
    compileIdentityCollisionGroup,
    compileRecordCreationPricing,
    compileSecurityLedger,
    compileSemanticUseCharges,
    compileSoundnessCharge,
    compileStatisticalTerms,
    ledgerGroups,
    maximumChargedQueries,
    soundnessChargeAt,
    statisticalRatioAt,
    type StatisticalTerm,
} from '#tests/security-ledger-model.js';
import { instanceAttackScreens } from '#tests/security-margin/attack-screens.js';
import {
    compileFhePopulationLimits,
    populationSearchCap,
} from '#tests/security-margin/population-limits.js';
import { type ReductionVariant } from '#tests/security-margin/reduction-work.js';
import { compileSecurityMarginScreen } from '#tests/security-margin-screen-model.js';
import {
    compileSupportedProfileCensus,
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

export const renderComposedSecurityLedger = (): string[] => {
    const supportedProfiles = compileSupportedProfileCensus();
    return [
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
    ];
};
