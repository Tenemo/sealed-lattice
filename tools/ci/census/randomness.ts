import {
    compileCommonMatrixInitializationCensus,
    compileCommonMatrixSamplingCensus,
} from '#tests/common-matrix-sampling-model.js';
import {
    compileOperationProofDraws,
    compilePrivateRandomnessScopes,
    operationSeedBytes,
    operationSeedCount,
} from '#tests/operation-seed-model.js';
import {
    compileFirstOracleReadVariation,
    compileProofRandomnessBudgets,
} from '#tests/proof-randomness-budget-model.js';
import { compileRegistrationSourceRandomness } from '#tests/registration-source-randomness-model.js';
import { compileSparseSupportSamplingCensus } from '#tests/sparse-sampling-bound-model.js';
import { compileFixedSpongeInitializationCensus } from '#tests/sponge-initialization-model.js';
import {
    completionProfile,
    largestSupportedProfile,
} from '#tests/supported-profile-model.js';
import { formatCount, table } from '#tools/ci/census/format.js';

export const renderSparseSupportSamplingComparison = (): string[] => {
    const completion = completionProfile();
    return [
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
    ];
};

export const renderProofSimulatorRandomnessBudgets = (): string[] => {
    const completion = completionProfile();
    return [
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
    ];
};

export const renderBufferedFieldSamplingObservations = (): string[] => [
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
                ['Words in one native read', formatCount(value.bufferWords)],
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
    'The interval follows from the union and two-term Bonferroni bounds on a rejection in the exactly filled minimum degree-mask prefix. This sampler-work variation occurs too often to discard as a security failure. Discarding it would require an explicit population and whole-experiment cost charge under the accepted normalized target. The observation argument retains its exact waiting law; these probability bounds alone give no security verdict.',
    '',
];

export const renderOperationRandomnessSeeds = (): string[] => {
    const completion = completionProfile();
    return [
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
                    formatCount(operationSeedCount(largestSupportedProfile())),
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
    ];
};

export const renderPrivateRandomnessScopeInventory = (): string[] => {
    const completion = completionProfile();
    const registrationSourceRandomness = compileRegistrationSourceRandomness(
        completion.participantCount,
        completion.optionCount,
    );
    return [
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
        'These scopes are separate from per-family source seed scopes and explicit proof-programming records. A simulation using one shadow function per private-randomness scope must account for the additional scopes and their full query histories. Unread initialized streams still have construction and sponge work. The conditional seed-pair term is not an adversarial query-hit bound, and none of these counts supplies a complete reduction time or a new primitive assumption.',
        '',
    ];
};

export const renderRegistrationSourceRandomnessAndHashWork = (): string[] => {
    const completion = completionProfile();
    const value = compileRegistrationSourceRandomness(
        completion.participantCount,
        completion.optionCount,
    );
    return [
        '## Registration source randomness and hash work',
        '',
        'Each permitted family retains one original seed. Separate purpose streams sample its FHE secret and first error, and its auxiliary encryption ephemeral and four error vectors. The signed registration binds the complete canonical ciphertexts. Regeneration repeats the original streams. Sparse comparison caps bound reduction work and do not add runtime retries; repeated common inputs remain the same oracle coordinates.',
        '',
        table(
            ['Property', 'Value'],
            [
                [
                    'Original poll maximum',
                    formatCount(value.originalPollMaximumParticipants),
                ],
                ['Original source seeds', formatCount(value.sourceSeedCount)],
                ['Fresh seed bytes', formatCount(value.freshSeedBytes)],
                ['Finite error samples', formatCount(value.gaussianSamples)],
                ['Balanced sparse samples', formatCount(value.sparseCalls)],
                [
                    'Hash permutations under the sparse comparison',
                    formatCount(value.comparisonHashPermutations),
                ],
                [
                    'Samples per source ciphertext comparison',
                    formatCount(value.sourceCiphertextSamples),
                ],
                [
                    'Samples in the shared auxiliary key transition',
                    formatCount(value.sharedAuxiliaryKeySamples),
                ],
            ],
        ),
        '',
        table(
            [
                'Family',
                'Modulus bytes',
                'FHE sampler bits',
                'Private input bytes',
                'Maximum source stream bytes',
                'Maximum encryption stream bytes',
                'Ciphertext-binding input bytes',
                'Source permutations',
                'Encryption permutations',
                'Binding permutations',
                'Common permutations',
            ],
            value.families.map((family) => [
                formatCount(family.index),
                formatCount(family.modulusBytes),
                formatCount(family.sampleBits),
                formatCount(family.sourceInputBytes),
                formatCount(family.comparisonMaximumSourceOutputBytes),
                formatCount(family.comparisonMaximumEncryptionOutputBytes),
                formatCount(family.bindingInputBytes),
                formatCount(family.comparisonSourcePermutations),
                formatCount(family.comparisonEncryptionPermutations),
                formatCount(family.bindingPermutations),
                formatCount(family.commonPermutations),
            ]),
        ),
        '',
    ];
};

export const renderCommonMatrixSamplingCensus = (): string[] => {
    const completion = completionProfile();
    const commonMatrixSampling = compileCommonMatrixSamplingCensus(completion);
    return [
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
    ];
};

export const renderFixedSpongeInitializationCensus = (): string[] => {
    const completion = completionProfile();
    const fixedSpongeInitialization =
        compileFixedSpongeInitializationCensus(completion);
    return [
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
    ];
};
