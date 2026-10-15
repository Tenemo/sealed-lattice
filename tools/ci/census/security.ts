import {
    compilePreparationFamilyInventory,
    compilePreparationLedger,
} from '#tests/preparation-ledger-model.js';
import { rationalCeilingLog2 } from '#tests/security-ledger/rational.js';
import {
    compileErrorEnvelope,
    compileSecurityLedger,
    compileSecurityOperands,
    ledgerGroupBudget,
    ledgerGroups,
    securityProofEnvelope,
    semanticEndpointBudget,
    semanticMacroEdges,
} from '#tests/security-ledger-model.js';
import { latticeAssumptionGroups } from '#tests/security-margin/attack-screens.js';
import { compileLatticePopulationLimits } from '#tests/security-margin/population-limits.js';
import {
    compileReductionWork,
    constructionPopulation,
    fixedReductionComponentBounds,
    maximumExperimentGates,
    minimumReductionWork,
    reductionPopulationLimit,
    securityTargetBits,
    slopeReductionComponentBounds,
} from '#tests/security-margin/reduction-work.js';
import {
    latticeRequirementAt,
    profilesByParticipantCount,
} from '#tests/security-margin-screen-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';

// A population that reaches the representation ceiling is limited by the
// reduction's metadata domain rather than by the group's attack floor.
const populationCell = (column: {
    honestRegistrations: bigint;
    metadataLimited: boolean;
}) =>
    column.metadataLimited
        ? `${formatCount(column.honestRegistrations)} (representation ceiling)`
        : formatCount(column.honestRegistrations);

export const renderComposedSecurityLedger = (): string[] => {
    const ledger = compileSecurityLedger(),
        operands = compileSecurityOperands();
    const commonPopulation = ledger.reduce(
        (minimum, row) =>
            row.criterion.binding.limit < minimum
                ? row.criterion.binding.limit
                : minimum,
        ledger[0].criterion.binding.limit,
    );
    const work = compileReductionWork(constructionPopulation);
    const ratioBits = (
        value: { numerator: bigint; denominator: bigint },
        originalWork: bigint,
    ) =>
        value.numerator === 0n
            ? 'Zero'
            : formatCount(
                  rationalCeilingLog2({
                      numerator: value.numerator << securityTargetBits,
                      denominator: value.denominator * originalWork,
                  }),
              );
    return [
        '## Composed security ledger',
        '',
        'The [security argument](private:preparation-ledger) owns the complete hybrid and source correspondence. These tables recompute its numerical consequences under the declared primitive curves and the accepted attack-cost convention. Original honest credentials include abandoned and unselected registrations across every roster of one poll. Per-group limits are not independent permissions: the joint limit is their minimum. The quantum-memory column is a stress test.',
        '',
        table(
            ['Operand', 'Value'],
            [
                ['Security target bits', formatCount(securityTargetBits)],
                [
                    'Minimum late reduction work',
                    formatCount(minimumReductionWork),
                ],
                [
                    'Maximum nontrivial original work',
                    formatCount(maximumExperimentGates),
                ],
                [
                    'Constructed reference population',
                    formatCount(constructionPopulation),
                ],
                [
                    'Fixed reference reduction work bound',
                    formatCount(work.fixedWork),
                ],
                [
                    'Reference original-work multiplier',
                    formatCount(work.workSlope),
                ],
                [
                    'Fixed reference external-query bound',
                    formatCount(work.fixedExternalQueries),
                ],
                [
                    'Representation-derived population ceiling',
                    formatCount(reductionPopulationLimit()),
                ],
                [
                    'Complete catalogue family guesses',
                    formatCount(compilePreparationFamilyInventory().length),
                ],
                [
                    'Maximum source families in one poll',
                    formatCount(operands.maximumSourceFamilies),
                ],
                [
                    'Programmed prefix bits',
                    formatCount(securityProofEnvelope.programmedPrefixBits),
                ],
                [
                    'Accepted proof expansion bound',
                    formatCount(securityProofEnvelope.expansionQueries),
                ],
                [
                    'All-profile sufficient original credential population',
                    formatCount(commonPopulation),
                ],
            ],
        ),
        '',
        'Beyond the reference population, the complete fixed work grows at most cubically, the work slope quadratically, and fixed queries and original memory linearly. The explicit rounding reserve remains included. The representation ceiling comes from the full maximum-work memory inequality; it is not a search cutoff. Each advantage ratio is convex in the original work after division by the target, so both endpoints of each chronological interval decide its bound.',
        '',
        table(
            ['Constructed component', 'Fixed reference work bound'],
            Object.entries(fixedReductionComponentBounds).map(
                ([name, bound]) => [
                    name[0].toUpperCase() +
                        name
                            .slice(1)
                            .replace(/([a-z])([A-Z])/gu, '$1 $2')
                            .toLowerCase(),
                    formatCount(bound),
                ],
            ),
        ),
        '',
        table(
            ['Constructed component', 'Reference original-work multiplier'],
            Object.entries(slopeReductionComponentBounds).map(
                ([name, bound]) => [
                    name[0].toUpperCase() +
                        name
                            .slice(1)
                            .replace(/([a-z])([A-Z])/gu, '$1 $2')
                            .toLowerCase(),
                    formatCount(bound),
                ],
            ),
        ),
        '',
        table(
            ['Semantic endpoint operand', 'Value'],
            [
                [
                    'Named nonprimitive macro edges',
                    formatCount(semanticMacroEdges.length),
                ],
                [
                    'Fixed macro capacity',
                    formatCount(semanticEndpointBudget.fixedMacroCapacity),
                ],
                [
                    'Purpose guesses per original credential',
                    formatCount(
                        semanticEndpointBudget.authenticationEmbeddingsPerCredential,
                    ),
                ],
                [
                    'Credential-seed endpoints per original credential',
                    formatCount(
                        semanticEndpointBudget.credentialSeedEndpointsPerCredential,
                    ),
                ],
                [
                    'Early representation endpoints',
                    formatCount(
                        semanticEndpointBudget.earlyRepresentationEndpoints,
                    ),
                ],
                [
                    'Normalization reserve',
                    formatCount(semanticEndpointBudget.normalizationMultiplier),
                ],
            ],
        ),
        '',
        table(
            ['Group', 'Budget numerator', 'Budget denominator'],
            ledgerGroups.map((group) => {
                const budget = ledgerGroupBudget(group);
                return [
                    group,
                    formatCount(budget.numerator),
                    formatCount(budget.denominator),
                ];
            }),
        ),
        '',
        table(
            [
                'Participants',
                'Example original credentials',
                'Source families',
                'Source ciphertext hops',
                'Tuple hops',
                'FHE ballot hops',
                'Recipient key and row hops',
                'Auxiliary key and ballot hops',
            ],
            profilesByParticipantCount().map(
                ({ participantCount, profiles }) => {
                    const profile = profiles.reduce((left, right) =>
                        compilePreparationLedger(left, 1n).sourceFamilies >=
                        compilePreparationLedger(right, 1n).sourceFamilies
                            ? left
                            : right,
                    );
                    const row = compilePreparationLedger(
                        profile,
                        constructionPopulation,
                    );
                    return [
                        formatCount(participantCount),
                        formatCount(constructionPopulation),
                        formatCount(row.sourceFamilies),
                        formatCount(row.sourceCiphertextComparisons),
                        formatCount(row.fheTupleComparisons),
                        formatCount(row.fheBallotComparisons),
                        formatCount(
                            row.recipientKeyComparisons +
                                row.recipientCiphertextComparisons,
                        ),
                        formatCount(
                            row.auxiliaryKeyComparisons +
                                row.auxiliaryBallotComparisons,
                        ),
                    ];
                },
            ),
        ),
        '',
        'The source list follows the poll’s permitted rosters. Early FHE and tuple guesses cover the entire parameter catalogue before preprocessing, so the calculation does not condition on a later public poll choice. Source ciphertexts use the complete joint multi-sample auxiliary interface. The sharing and prescribed-release translations each occur once globally; semantic failure is still charged at every endpoint that needs a true corrupt relation.',
        '',
        ...latticeAssumptionGroups.flatMap((group) => [
            `### ${group}`,
            '',
            table(
                [
                    'Participants',
                    'Binding options',
                    'Criterion bits',
                    'Required bits at reference population',
                    'Criterion population',
                    'Stress bits',
                    'Stress population',
                ],
                compileLatticePopulationLimits(group).map((row) => {
                    const profile = profilesByParticipantCount()
                        .find(
                            (value) =>
                                value.participantCount === row.participantCount,
                        )!
                        .profiles.find(
                            (value) =>
                                value.optionCount === row.criterion.optionCount,
                        )!;
                    return [
                        formatCount(row.participantCount),
                        formatCount(row.criterion.optionCount),
                        formatCount(row.criterion.levelBits),
                        formatCount(
                            latticeRequirementAt(
                                group,
                                profile,
                                constructionPopulation,
                            ).requiredBits,
                        ),
                        populationCell(row.criterion),
                        formatCount(row.stressTest.levelBits),
                        populationCell(row.stressTest),
                    ];
                }),
            ),
            '',
        ]),
        '### Joint population limits',
        '',
        table(
            [
                'Participants',
                'Criterion population',
                'Binding group',
                'Stress population',
                'Stress binding group',
            ],
            ledger.map((row) => [
                formatCount(row.participantCount),
                formatCount(row.criterion.binding.limit),
                row.criterion.binding.group,
                formatCount(row.stressTest.binding.limit),
                row.stressTest.binding.group,
            ]),
        ),
        '',
        table(
            [
                'Group',
                'All-profile criterion population',
                'All-profile stress population',
            ],
            ledgerGroups.map((group) => [
                group,
                formatCount(
                    ledger.reduce(
                        (minimum, row) =>
                            row.criterion.limits.get(group)! < minimum
                                ? row.criterion.limits.get(group)!
                                : minimum,
                        ledger[0].criterion.limits.get(group)!,
                    ),
                ),
                formatCount(
                    ledger.reduce(
                        (minimum, row) =>
                            row.stressTest.limits.get(group)! < minimum
                                ? row.stressTest.limits.get(group)!
                                : minimum,
                        ledger[0].stressTest.limits.get(group)!,
                    ),
                ),
            ]),
        ),
        '',
        '### Full-interval error checks',
        '',
        'Each displayed integer is the ceiling base-two logarithm of that group’s error divided by the target at the indicated work. The arithmetic retains every positive term and the complete population-dependent query history; no unit-cost query bound is substituted at larger populations.',
        '',
        table(
            [
                'Original credentials',
                'Original work',
                'Authentication ratio bits',
                'Identity ratio bits',
                'Statistical ratio bits',
            ],
            [constructionPopulation, commonPopulation].flatMap((population) =>
                compileErrorEnvelope(population).map((row) => [
                    formatCount(population),
                    formatCount(row.work),
                    ratioBits(row.authentication, row.work),
                    ratioBits(row.identity, row.work),
                    ratioBits(row.statistical, row.work),
                ]),
            ),
        ),
        '',
    ];
};
