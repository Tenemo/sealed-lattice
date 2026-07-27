import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const selectedLatticeEstimatorRevision =
    '3e48ef421ec256afddb3e7d2249a77eab6e9ba12';
export const selectedLatticeEstimatorSourceTreeSha256 =
    'c8489bdbf73ab6b0ccd7dd23fe007d8c83bf38adc4359d9709d896dc994c6b09';
export const selectedLatticeEstimatorContainerImage =
    'docker.io/sagemath/sagemath@sha256:ec32d9752b3a11c628103ca6802db890b63cbe9bb480cfea02de09656ecc84a2';
export const selectedLatticeEstimatorSageVersion = '9.5';
export const selectedLatticeAssuranceTargetBits = 80;

export const selectedLatticeAttackIdentifiers = [
    'primalUsvp',
    'primalBdd',
    'dual',
    'dualHybrid',
] as const;

const repositoryRoot = fileURLToPath(new URL('../../', import.meta.url));

const sourcePaths = [
    'crates/sealed-lattice-kernel/src/bgv/parameters.rs',
    'crates/sealed-lattice-kernel/src/bgv/parameters/root_parameters.rs',
    'crates/sealed-lattice-kernel/src/bgv/key_switch_topology.rs',
    'crates/sealed-lattice-kernel/src/bgv/evaluator/candidate_evidence.rs',
    'crates/sealed-lattice-kernel/src/bgv/evaluator/top_k/mod.rs',
    'crates/sealed-lattice-kernel/src/bgv/evaluator/top_k/rotations.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/generation_population.rs',
    'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/generation_relinearization.rs',
    'crates/sealed-lattice-kernel/src/bgv/proof_suite/relation_plan/ballot_validity_adapter.rs',
    'crates/sealed-lattice-kernel/src/foundation/schemas.rs',
] as const;

const estimatorProgramPath = 'tools/ci/selected-lattice-security-estimator.py';

type JsonPrimitive = boolean | null | number | string;
export type JsonValue =
    | JsonPrimitive
    | readonly JsonValue[]
    | { readonly [fieldName: string]: JsonValue };

type SelectedTopology = {
    readonly dataPrimes: readonly number[];
    readonly dataPrimesPerBlock: number;
    readonly evaluatorWorkingLevel: number;
    readonly galoisSchedule: readonly {
        readonly catalogLevel: number;
        readonly galoisElement: number;
    }[];
    readonly optionCount: number;
    readonly participantCount: number;
    readonly plaintextModulus: number;
    readonly polynomialDegree: number;
    readonly relinearizationLevels: readonly number[];
    readonly specialPrimes: readonly number[];
    readonly targetCiphertextLevel: number;
};

type EstimatorInput = {
    readonly activeAssuranceTarget: JsonValue;
    readonly assumptions: JsonValue;
    readonly diagnosticCases: readonly JsonValue[];
    readonly distributions: JsonValue;
    readonly estimator: JsonValue;
    readonly estimatorConfiguration: JsonValue;
    readonly limitations: readonly string[];
    readonly sampleCensus: JsonValue;
    readonly sourceAuthority: readonly JsonValue[];
    readonly topology: JsonValue;
};

const escapeRegularExpression = (value: string): string =>
    value.replace(/[.*+?^${}()|[\]\\]/gu, '\\$&');

const requireMatch = (
    pattern: RegExp,
    source: string,
    description: string,
): RegExpMatchArray => {
    const match = source.match(pattern);
    if (match === null) {
        throw new Error(`Could not derive ${description} from live source.`);
    }
    return match;
};

const parseRustInteger = (value: string): number => {
    const parsed = Number.parseInt(value.replace(/_/gu, ''), 10);
    if (!Number.isSafeInteger(parsed) || parsed < 0) {
        throw new Error(`Rust integer ${value} is outside the safe range.`);
    }
    return parsed;
};

const deriveIntegerConstant = (source: string, name: string): number => {
    const escapedName = escapeRegularExpression(name);
    const match = requireMatch(
        new RegExp(
            `(?:pub\\(crate\\)\\s+)?const\\s+${escapedName}\\s*:[^=]+=\\s*([0-9][0-9_]*)\\s*;`,
            'su',
        ),
        source,
        name,
    );
    return parseRustInteger(match[1] ?? '');
};

const deriveIntegerArray = (
    source: string,
    name: string,
): readonly number[] => {
    const escapedName = escapeRegularExpression(name);
    const match = requireMatch(
        new RegExp(
            `(?:pub\\(crate\\)\\s+)?const\\s+${escapedName}\\s*:\\s*\\[[^\\]]+\\]\\s*=\\s*\\[(.*?)\\]\\s*;`,
            'su',
        ),
        source,
        name,
    );
    const body = match[1] ?? '';
    const values = [...body.matchAll(/(?<![A-Za-z0-9_])([0-9][0-9_]*)/gu)].map(
        (valueMatch) => parseRustInteger(valueMatch[1] ?? ''),
    );
    if (values.length === 0) {
        throw new Error(`${name} must contain at least one value.`);
    }
    return values;
};

const sha256 = (payload: Uint8Array): string =>
    createHash('sha256').update(payload).digest('hex');

const compareOrdinal = (left: string, right: string): number =>
    left < right ? -1 : left > right ? 1 : 0;

const sortJson = (value: JsonValue): JsonValue => {
    if (Array.isArray(value)) {
        const arrayValue = value as readonly JsonValue[];
        return arrayValue.map((entry) => sortJson(entry));
    }
    if (value !== null && typeof value === 'object') {
        const recordValue = value as {
            readonly [fieldName: string]: JsonValue;
        };
        return Object.fromEntries(
            Object.entries(recordValue)
                .sort(([left], [right]) => compareOrdinal(left, right))
                .map(([fieldName, fieldValue]) => [
                    fieldName,
                    sortJson(fieldValue),
                ]),
        );
    }
    return value;
};

export const canonicalJsonText = (value: JsonValue): string =>
    JSON.stringify(sortJson(value));

export const canonicalJsonSha256 = (value: JsonValue): string =>
    sha256(Buffer.from(canonicalJsonText(value), 'utf8'));

const readSourceFiles = async (
    rootPath: string,
): Promise<ReadonlyMap<string, Buffer>> => {
    const entries = await Promise.all(
        [...sourcePaths, estimatorProgramPath].map(
            async (relativePath) =>
                [
                    relativePath,
                    await readFile(path.join(rootPath, relativePath)),
                ] as const,
        ),
    );
    return new Map(entries);
};

const sourceText = (
    sources: ReadonlyMap<string, Buffer>,
    relativePath: string,
): string => {
    const payload = sources.get(relativePath);
    if (payload === undefined) {
        throw new Error(`Source authority ${relativePath} is missing.`);
    }
    return payload.toString('utf8');
};

const deriveSelectedTopology = (
    sources: ReadonlyMap<string, Buffer>,
): SelectedTopology => {
    const parametersSource = sourceText(
        sources,
        'crates/sealed-lattice-kernel/src/bgv/parameters.rs',
    );
    const rootsSource = sourceText(
        sources,
        'crates/sealed-lattice-kernel/src/bgv/parameters/root_parameters.rs',
    );
    const keySwitchSource = sourceText(
        sources,
        'crates/sealed-lattice-kernel/src/bgv/key_switch_topology.rs',
    );
    const candidateSource = sourceText(
        sources,
        'crates/sealed-lattice-kernel/src/bgv/evaluator/candidate_evidence.rs',
    );
    const evaluatorSource = sourceText(
        sources,
        'crates/sealed-lattice-kernel/src/bgv/evaluator/top_k/mod.rs',
    );
    const rotationsSource = sourceText(
        sources,
        'crates/sealed-lattice-kernel/src/bgv/evaluator/top_k/rotations.rs',
    );
    const foundationSource = sourceText(
        sources,
        'crates/sealed-lattice-kernel/src/foundation/schemas.rs',
    );
    const participantCount = deriveIntegerConstant(
        foundationSource,
        'PROTOTYPE_PARTICIPANT_COUNT',
    );
    const optionCountMatch = requireMatch(
        /pub\s+(?:const|static)\s+FOUNDATION_PROFILE.*?option_count:\s*([0-9][0-9_]*)/su,
        foundationSource,
        'foundation option count',
    );
    const scatterLevel = deriveIntegerConstant(
        evaluatorSource,
        'SCATTER_KEY_LEVEL',
    );
    const traceLevel = deriveIntegerConstant(
        evaluatorSource,
        'TRACE_KEY_LEVEL',
    );
    const scatterElements = deriveIntegerArray(
        rotationsSource,
        'SCATTER_GALOIS_ELEMENTS',
    );
    const traceElements = deriveIntegerArray(
        rotationsSource,
        'TRACE_GALOIS_ELEMENTS',
    );
    const exactRelinearizationCatalog =
        'relinearization_levels: vec![SELECTED_RELINEARIZATION_KEY_LEVEL]';
    if (candidateSource.split(exactRelinearizationCatalog).length !== 2) {
        throw new Error(
            'The production candidate must contain exactly one relinearization level.',
        );
    }
    const topology: SelectedTopology = {
        polynomialDegree: deriveIntegerConstant(
            parametersSource,
            'POLYNOMIAL_DEGREE',
        ),
        plaintextModulus: deriveIntegerConstant(
            parametersSource,
            'PLAINTEXT_MODULUS',
        ),
        dataPrimes: deriveIntegerArray(rootsSource, 'DATA_PRIMES'),
        specialPrimes: deriveIntegerArray(rootsSource, 'SPECIAL_PRIMES'),
        dataPrimesPerBlock: deriveIntegerConstant(
            keySwitchSource,
            'KEY_SWITCH_DATA_PRIMES_PER_BLOCK',
        ),
        evaluatorWorkingLevel: deriveIntegerConstant(
            evaluatorSource,
            'SELECTED_EVALUATOR_WORKING_LEVEL',
        ),
        relinearizationLevels: [
            deriveIntegerConstant(
                evaluatorSource,
                'SELECTED_RELINEARIZATION_KEY_LEVEL',
            ),
        ],
        galoisSchedule: [
            ...scatterElements
                .map((galoisElement) => ({
                    catalogLevel: scatterLevel,
                    galoisElement,
                }))
                .sort(
                    (left, right) => left.galoisElement - right.galoisElement,
                ),
            ...traceElements
                .map((galoisElement) => ({
                    catalogLevel: traceLevel,
                    galoisElement,
                }))
                .sort(
                    (left, right) => left.galoisElement - right.galoisElement,
                ),
        ],
        targetCiphertextLevel: deriveIntegerConstant(
            evaluatorSource,
            'CANONICAL_TARGET_CIPHERTEXT_LEVEL',
        ),
        participantCount,
        optionCount: parseRustInteger(optionCountMatch[1] ?? ''),
    };
    const expectedGaloisSchedule = [
        [15, 14],
        [19, 14],
        [219, 14],
        [257, 18],
        [1_025, 18],
        [8_193, 18],
    ];
    const expectedGeometry =
        topology.polynomialDegree === 32_768 &&
        topology.plaintextModulus === 257 &&
        topology.dataPrimes.length === 23 &&
        topology.specialPrimes.length === 3 &&
        topology.dataPrimesPerBlock === 3 &&
        topology.evaluatorWorkingLevel === 22 &&
        topology.relinearizationLevels.length === 1 &&
        topology.relinearizationLevels[0] === 22 &&
        topology.targetCiphertextLevel === 7 &&
        topology.participantCount === 10 &&
        topology.optionCount === 20 &&
        topology.galoisSchedule.every(
            (entry, index) =>
                entry.galoisElement === expectedGaloisSchedule[index]?.[0] &&
                entry.catalogLevel === expectedGaloisSchedule[index]?.[1],
        ) &&
        [...topology.dataPrimes, ...topology.specialPrimes].every(
            (modulus) => modulus % topology.plaintextModulus === 1,
        );
    if (!expectedGeometry) {
        throw new Error(
            'The live candidate is not the selected exact topology.',
        );
    }
    return topology;
};

const dataBlockCount = (
    catalogLevel: number,
    dataPrimesPerBlock: number,
): number => Math.ceil((catalogLevel + 1) / dataPrimesPerBlock);

const deriveSampleCensus = (topology: SelectedTopology): JsonValue => {
    const relinearizationLevel = topology.relinearizationLevels[0];
    if (relinearizationLevel === undefined) {
        throw new Error('The relinearization level is missing.');
    }
    const relinearizationBlockCount = dataBlockCount(
        relinearizationLevel,
        topology.dataPrimesPerBlock,
    );
    const galoisCountsByLevel = new Map<number, number>();
    for (const entry of topology.galoisSchedule) {
        galoisCountsByLevel.set(
            entry.catalogLevel,
            (galoisCountsByLevel.get(entry.catalogLevel) ?? 0) + 1,
        );
    }
    const galoisRows = [...galoisCountsByLevel.entries()]
        .sort(([left], [right]) => right - left)
        .map(([catalogLevel, keyCount]) => {
            const decompositionBlockCount = dataBlockCount(
                catalogLevel,
                topology.dataPrimesPerBlock,
            );
            const commonUniformPolynomialCount =
                keyCount * decompositionBlockCount;
            const sourceRelationCount =
                topology.participantCount * commonUniformPolynomialCount;
            const deterministicDerivedRelationCount =
                commonUniformPolynomialCount;
            return {
                family: 'galois',
                catalogLevel,
                keyCount,
                decompositionBlockCount,
                sourceRelationCount,
                deterministicDerivedRelationCount,
                publicRelationCount:
                    sourceRelationCount + deterministicDerivedRelationCount,
                commonUniformPolynomialCount,
                generatedComponentViewCount:
                    commonUniformPolynomialCount +
                    sourceRelationCount +
                    deterministicDerivedRelationCount,
                distinctPublicPolynomialCount:
                    commonUniformPolynomialCount +
                    sourceRelationCount +
                    deterministicDerivedRelationCount,
                relationClass: 'transformed-secret circular or KDM exposure',
            };
        });
    const publicKeyRow = {
        family: 'collectivePublicKey',
        catalogLevel: topology.evaluatorWorkingLevel,
        basis: 'orderedDataPrimePrefix',
        sourceRelationCount: topology.participantCount,
        deterministicDerivedRelationCount: 1,
        publicRelationCount: topology.participantCount + 1,
        commonUniformPolynomialCount: 1,
        generatedComponentViewCount: topology.participantCount + 2,
        distinctPublicPolynomialCount: topology.participantCount + 2,
        ordinaryMarginalRelationCountPerParticipant: 1,
        relationClass: 'ordinary marginal plus deterministic aggregate',
    };
    const relinearizationRow = {
        family: 'relinearization',
        catalogLevel: relinearizationLevel,
        keyCount: topology.relinearizationLevels.length,
        decompositionBlockCount: relinearizationBlockCount,
        roundOneLeftSourceRelationCount:
            topology.participantCount * relinearizationBlockCount,
        roundOneRightSourceRelationCount:
            topology.participantCount * relinearizationBlockCount,
        roundTwoSourceRelationCount:
            topology.participantCount * relinearizationBlockCount,
        roundOneAggregateRelationCount: 2 * relinearizationBlockCount,
        runtimeKeyRelationCount: relinearizationBlockCount,
        sourceRelationCount:
            3 * topology.participantCount * relinearizationBlockCount,
        deterministicDerivedRelationCount: 3 * relinearizationBlockCount,
        publicRelationCount:
            3 * (topology.participantCount + 1) * relinearizationBlockCount,
        commonUniformPolynomialCount: relinearizationBlockCount,
        runtimeKeyHalfComponentViewCount: 2 * relinearizationBlockCount,
        duplicateRuntimeAViewCount: relinearizationBlockCount,
        generatedComponentViewCount: 35 * relinearizationBlockCount,
        distinctPublicPolynomialCount: 34 * relinearizationBlockCount,
        ordinarySecretMarginalRelationCountPerParticipant:
            relinearizationBlockCount,
        ordinaryEphemeralMarginalRelationCountPerParticipant:
            relinearizationBlockCount,
        relationClass:
            'ordinary marginals embedded in a joint secret-square circular or KDM exposure',
    };
    const rows = [publicKeyRow, relinearizationRow, ...galoisRows];
    const sum = (fieldName: string): number =>
        rows.reduce((total, row) => {
            const value = row[fieldName as keyof typeof row];
            if (typeof value !== 'number') {
                throw new Error(`Sample-census field ${fieldName} is missing.`);
            }
            return total + value;
        }, 0);
    const summary = {
        sourceRelationCountPerParticipant: 61,
        sourceRelationCountForRoster: sum('sourceRelationCount'),
        deterministicDerivedRelationCount: sum(
            'deterministicDerivedRelationCount',
        ),
        completePublicRelationCount:
            sum('sourceRelationCount') +
            sum('deterministicDerivedRelationCount'),
        finalRuntimeKeyRelationCount: 45,
        commonUniformPolynomialCount: sum('commonUniformPolynomialCount'),
        generatedComponentViewCount: sum('generatedComponentViewCount'),
        distinctPublicPolynomialCount: sum('distinctPublicPolynomialCount'),
        duplicateComponentViewCount:
            sum('generatedComponentViewCount') -
            sum('distinctPublicPolynomialCount'),
    };
    const expectedSummary = {
        sourceRelationCountPerParticipant: 61,
        sourceRelationCountForRoster: 610,
        deterministicDerivedRelationCount: 61,
        completePublicRelationCount: 671,
        finalRuntimeKeyRelationCount: 45,
        commonUniformPolynomialCount: 45,
        generatedComponentViewCount: 724,
        distinctPublicPolynomialCount: 716,
        duplicateComponentViewCount: 8,
    };
    if (canonicalJsonText(summary) !== canonicalJsonText(expectedSummary)) {
        throw new Error('The exact production public-sample census drifted.');
    }
    return {
        countingRule:
            'One setup relation is one ring equation for one B-like polynomial and its derived or reused A-like polynomial. Deterministic aggregates remain visible but are not fresh independent samples.',
        setupRows: rows,
        setupSummary: summary,
        ballotExposure: {
            maximumAcceptedBallotCount: topology.participantCount,
            ciphertextsPerBallot: 2,
            maximumFreshBallotCiphertextCount: topology.participantCount * 2,
            freshRandomizerDistribution: 'independent centered ternary',
            freshErrorDistributionPerComponent:
                'independent centered binomial two',
            relationClass:
                'ciphertext exposure under the collective key; not an additional independent setup sample',
        },
        deterministicCiphertextViews: {
            publishedAggregateCiphertextCount: 2,
            publishedTargetCiphertextCount: 2,
            independentSampleCount: 0,
            relationClass:
                'deterministic homomorphic functions of accepted ballot ciphertexts and verified evaluator keys',
        },
    };
};

const product = (values: readonly number[]): bigint =>
    values.reduce((result, value) => result * BigInt(value), 1n);

const deriveDiagnosticCases = (
    topology: SelectedTopology,
): readonly JsonValue[] => {
    const relinearizationLevel = topology.relinearizationLevels[0];
    if (relinearizationLevel === undefined) {
        throw new Error('The relinearization level is missing.');
    }
    const relinearizationBlockCount = dataBlockCount(
        relinearizationLevel,
        topology.dataPrimesPerBlock,
    );
    const cases = [
        {
            identifier: 'oneIndividualPublicKeyShare',
            catalogLevel: topology.evaluatorWorkingLevel,
            includeSpecialBasis: false,
            ringRelationCount: 1,
            purpose:
                'One exact ordinary public-key-share marginal before ring structure is relaxed.',
        },
        {
            identifier: 'completePublicKeyCensus',
            catalogLevel: topology.evaluatorWorkingLevel,
            includeSpecialBasis: false,
            ringRelationCount: topology.participantCount + 1,
            purpose:
                'All public-key contribution and aggregate rows pooled as a scalar-LWE stress view.',
        },
        {
            identifier: 'ordinaryRelinearizationRightMarginal',
            catalogLevel: relinearizationLevel,
            includeSpecialBasis: true,
            ringRelationCount: relinearizationBlockCount,
            purpose:
                'The eight ordinary round-one-right marginals for one trustee secret.',
        },
        {
            identifier: 'completeRelinearizationCensus',
            catalogLevel: relinearizationLevel,
            includeSpecialBasis: true,
            ringRelationCount:
                3 * (topology.participantCount + 1) * relinearizationBlockCount,
            purpose:
                'All relinearization rows pooled as a scalar-LWE stress view; circular rows are not reduced by this diagnostic.',
        },
        {
            identifier: 'completeLevel18GaloisCensus',
            catalogLevel: 18,
            includeSpecialBasis: true,
            ringRelationCount:
                3 *
                (topology.participantCount + 1) *
                dataBlockCount(18, topology.dataPrimesPerBlock),
            purpose:
                'All level-18 Galois rows pooled as a scalar-LWE stress view; transformed-secret KDM structure remains an assumption.',
        },
        {
            identifier: 'completeLevel14GaloisCensus',
            catalogLevel: 14,
            includeSpecialBasis: true,
            ringRelationCount:
                3 *
                (topology.participantCount + 1) *
                dataBlockCount(14, topology.dataPrimesPerBlock),
            purpose:
                'All level-14 Galois rows pooled as a scalar-LWE stress view; transformed-secret KDM structure remains an assumption.',
        },
        {
            identifier: 'completeBallotCiphertextCensus',
            catalogLevel: topology.evaluatorWorkingLevel,
            includeSpecialBasis: false,
            ringRelationCount: topology.participantCount * 2,
            purpose:
                'All fresh ballot ciphertexts pooled as a scalar-LWE stress view; public-key encryption composition remains separate.',
        },
    ];
    return cases.map((diagnosticCase) => {
        const orderedModuli = [
            ...topology.dataPrimes.slice(0, diagnosticCase.catalogLevel + 1),
            ...(diagnosticCase.includeSpecialBasis
                ? topology.specialPrimes
                : []),
        ];
        const modulus = product(orderedModuli);
        return {
            identifier: diagnosticCase.identifier,
            purpose: diagnosticCase.purpose,
            catalogLevel: diagnosticCase.catalogLevel,
            basis: diagnosticCase.includeSpecialBasis
                ? 'QTimesKeySwitchP'
                : 'Q',
            orderedModuli,
            modulus: modulus.toString(10),
            modulusLog2: Math.log2(Number(modulus)),
            ringRelationCount: diagnosticCase.ringRelationCount,
            scalarSampleCount:
                diagnosticCase.ringRelationCount * topology.polynomialDegree,
        };
    });
};

const deriveDistributions = (
    sources: ReadonlyMap<string, Buffer>,
    topology: SelectedTopology,
): JsonValue => {
    const populationSource = sourceText(
        sources,
        'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/generation_population.rs',
    );
    const relinearizationSource = sourceText(
        sources,
        'crates/sealed-lattice-kernel/src/bgv/setup/accepted_setup/generation_relinearization.rs',
    );
    for (const [source, name, expectedValue] of [
        [populationSource, 'SECRET_CONTRIBUTION_DISTRIBUTION_PURPOSE', 1],
        [populationSource, 'PUBLIC_KEY_ERROR_DISTRIBUTION_PURPOSE', 2],
        [
            relinearizationSource,
            'RELINEARIZATION_EPHEMERAL_SECRET_DISTRIBUTION_PURPOSE',
            3,
        ],
        [
            relinearizationSource,
            'RELINEARIZATION_ROUND_ONE_LEFT_ERROR_DISTRIBUTION_PURPOSE',
            4,
        ],
        [
            relinearizationSource,
            'RELINEARIZATION_ROUND_ONE_RIGHT_ERROR_DISTRIBUTION_PURPOSE',
            5,
        ],
        [
            relinearizationSource,
            'RELINEARIZATION_ROUND_TWO_ERROR_DISTRIBUTION_PURPOSE',
            6,
        ],
        [populationSource, 'GALOIS_ERROR_DISTRIBUTION_PURPOSE', 7],
    ] as const) {
        if (deriveIntegerConstant(source, name) !== expectedValue) {
            throw new Error(`Distribution purpose ${name} drifted.`);
        }
    }
    for (const [source, name] of [
        [populationSource, 'PUBLIC_KEY_ERROR_CENTERED_BINOMIAL_PARAMETER'],
        [populationSource, 'GALOIS_ERROR_CENTERED_BINOMIAL_PARAMETER'],
        [
            relinearizationSource,
            'RELINEARIZATION_ERROR_CENTERED_BINOMIAL_PARAMETER',
        ],
    ] as const) {
        if (deriveIntegerConstant(source, name) !== 2) {
            throw new Error(`Distribution parameter ${name} drifted.`);
        }
    }
    const activeFaultBound = Math.floor((topology.participantCount - 1) / 3);
    const corruptionCases = Array.from(
        { length: activeFaultBound + 1 },
        (_, corruptionCount) => {
            const honestContributionCount =
                topology.participantCount - corruptionCount;
            return {
                corruptionCount,
                honestContributionCount,
                collectiveSecretCoefficientDistribution: {
                    exactLaw: `convolution of ${honestContributionCount} independent uniform centered-ternary variables plus a known proof-bounded shift`,
                    mean: 0,
                    variance: `${2 * honestContributionCount}/3`,
                    supportBeforeKnownShift: [
                        -honestContributionCount,
                        honestContributionCount,
                    ],
                },
                honestAggregateErrorCoefficientDistribution: {
                    exactLaw: `centered binomial ${2 * honestContributionCount}`,
                    mean: 0,
                    variance: honestContributionCount,
                    support: [
                        -2 * honestContributionCount,
                        2 * honestContributionCount,
                    ],
                },
                maliciousContributionTreatment:
                    'Proof-bounded coordinated values are treated as known shifts, not honest noise.',
            };
        },
    );
    return {
        trusteeSecretContribution: {
            exactCoefficientLaw: 'uniform centered ternary',
            support: [-1, 1],
            variance: '2/3',
            independence:
                'Independent across honest trustees and coefficients under the action-root sampler assumption.',
        },
        relinearizationEphemeralSecret: {
            exactCoefficientLaw: 'uniform centered ternary',
            support: [-1, 1],
            variance: '2/3',
            independence:
                "Fresh per honest trustee and setup attempt; shared only across that trustee's two relinearization rounds.",
        },
        setupErrors: {
            exactCoefficientLaw: 'centered binomial two',
            support: [-2, 2],
            variance: 1,
            families: [
                'collective public key',
                'relinearization round one left',
                'relinearization round one right',
                'relinearization round two',
                'Galois key',
            ],
        },
        ballotEncryption: {
            randomizerExactCoefficientLaw: 'uniform centered ternary',
            errorExactCoefficientLaw: 'centered binomial two',
            errorPolynomialCountPerCiphertext: 2,
        },
        corruptionCases,
    };
};

const limitations = (): readonly string[] => [
    'The calculation is a generic scalar-LWE known-attack diagnostic, not an RLWE reduction or proof. It does not close algebraic, subfield, ideal, module, or distribution-specific attacks.',
    'Scalarization exposes every declared row count but does not make the cyclic scalar equations independent. Reused public polynomials, different secrets, deterministic aggregates, bases, and correlated messages remain explicit in the census.',
    'The estimator uses one uniform ternary secret and centered-binomial-two error as a named small-secret proxy. It does not implement the exact seven-through-ten-fold collective-secret convolutions or prove monotonicity across the four corruption cases.',
    'Relinearization and Galois rows contain secret-square, ephemeral-secret, and transformed-secret messages. Their marginal estimates do not establish joint circular or KDM security, malicious collective-setup composition, or auxiliary-input security for correlated proof, VSS, and commitment views.',
    'The ballot diagnostic is a pooled public-key-encryption stress view. Deterministic aggregate, evaluator, and target ciphertexts are not counted as fresh independent samples, and one-shot target release still requires its separate CPAD and threshold assumptions.',
    'The quantum figures use the named heuristic nearest-neighbor model for the listed lattice-reduction attacks. They are neither a proof against every quantum algorithm nor a common-proof QROM result.',
    'The active 80-bit target is review policy. Meeting it does not establish a 128-bit hardened profile, a NIST category, production readiness, or supported-phone qualification.',
];

export const buildSelectedLatticeEstimatorInput = async (
    rootPath = repositoryRoot,
): Promise<EstimatorInput> => {
    const sources = await readSourceFiles(rootPath);
    const topology = deriveSelectedTopology(sources);
    const sourceAuthority = sourcePaths.map((relativePath) => {
        const payload = sources.get(relativePath);
        if (payload === undefined) {
            throw new Error(`Source authority ${relativePath} is missing.`);
        }
        return { path: relativePath, sha256: sha256(payload) };
    });
    const estimatorProgram = sources.get(estimatorProgramPath);
    if (estimatorProgram === undefined) {
        throw new Error('The Sage estimator program is missing.');
    }
    return {
        sourceAuthority,
        estimator: {
            repository: 'https://github.com/malb/lattice-estimator',
            revision: selectedLatticeEstimatorRevision,
            sourceTreeSha256: selectedLatticeEstimatorSourceTreeSha256,
            containerImageReference: selectedLatticeEstimatorContainerImage,
            sageVersion: selectedLatticeEstimatorSageVersion,
            estimatorProgramPath,
            estimatorProgramSha256: sha256(estimatorProgram),
            classicalReductionCostModel: 'MATZOV classical',
            quantumReductionCostModel: 'MATZOV list_decoding-naive_quantum',
            attacks: selectedLatticeAttackIdentifiers,
        },
        activeAssuranceTarget: {
            bits: selectedLatticeAssuranceTargetBits,
            materialSuccessThreshold: 'at least one half',
            role: 'Evidence-review policy only; not a suite field or runtime-verifier input.',
        },
        topology: {
            polynomialDegree: topology.polynomialDegree,
            plaintextModulus: topology.plaintextModulus,
            orderedDataPrimes: topology.dataPrimes,
            orderedSpecialPrimes: topology.specialPrimes,
            dataPrimesPerDecompositionBlock: topology.dataPrimesPerBlock,
            evaluatorWorkingLevel: topology.evaluatorWorkingLevel,
            relinearizationLevels: topology.relinearizationLevels,
            galoisKeySchedule: topology.galoisSchedule,
            targetCiphertextLevel: topology.targetCiphertextLevel,
            participantCount: topology.participantCount,
            optionCount: topology.optionCount,
        },
        distributions: deriveDistributions(sources, topology),
        sampleCensus: deriveSampleCensus(topology),
        diagnosticCases: deriveDiagnosticCases(topology),
        estimatorConfiguration: {
            dimension: topology.polynomialDegree,
            secretDistributionProxy: 'uniform ternary',
            errorDistributionProxy:
                'centered binomial two after plaintext-unit normalization',
            normalization:
                'Every selected data and special prime is one modulo 257. Multiplication by the inverse of 257 preserves uniform A and maps a public 257-times-CB2 error to CB2.',
            sampleCountRule: 'ring relation count times polynomial degree',
            successMetric:
                'base-two logarithm of estimator rop, conservatively truncated to twelve decimal places',
            attackCoverage: selectedLatticeAttackIdentifiers,
        },
        assumptions: {
            structuredSecret:
                'The exact collective secret is the corruption-case convolution in this record. The estimator proxy is not a reduction from that structured law.',
            multiSample:
                'The exact finite census is recorded, but pooling correlated ring rows as independent scalar samples is only a stress diagnostic.',
            circularAndKdm:
                'Joint security of secret-square, transformed-secret, evaluator-key, proof, VSS, and commitment auxiliary inputs requires the named joint circular or KDM assumption and a separate composition reduction.',
            maliciousContributions:
                'At least seven honest contributions are independently sampled; up to three proof-bounded adversarial contributions are coordinated known shifts.',
            ballotEncryption:
                'Fresh ballot randomizers and errors use the exact laws recorded here. Security of their joint public-key-encryption exposure requires the underlying RLWE encryption reduction.',
            targetRelease:
                'One-shot target authorization narrows exposure but does not prove CPAD security; the threshold-release argument and flooding assumptions remain separate.',
        },
        limitations: limitations(),
    };
};

const isRecord = (value: unknown): value is Record<string, unknown> =>
    value !== null && typeof value === 'object' && !Array.isArray(value);

const requireRecord = (
    value: unknown,
    description: string,
): Record<string, unknown> => {
    if (!isRecord(value)) {
        throw new Error(`${description} must be an object.`);
    }
    return value;
};

const requireFinitePositiveNumber = (
    value: unknown,
    description: string,
): number => {
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) {
        throw new Error(`${description} must be a finite positive number.`);
    }
    return value;
};

const requirePositiveInteger = (
    value: unknown,
    description: string,
): number => {
    const parsed = requireFinitePositiveNumber(value, description);
    if (!Number.isSafeInteger(parsed)) {
        throw new Error(`${description} must be a positive safe integer.`);
    }
    return parsed;
};

export const parseJsonValue = (text: string): JsonValue =>
    JSON.parse(text) as JsonValue;

export const validateSelectedLatticeEvidence = (
    evidenceValue: JsonValue,
    expectedInput: EstimatorInput,
): {
    readonly minimumClassicalSecurityBitsLowerBound: number;
    readonly minimumQuantumSecurityBitsLowerBound: number;
} => {
    const evidence = requireRecord(evidenceValue, 'Evidence');
    if (
        evidence.recordKind !==
            'selected-lattice-security-estimator-evidence' ||
        evidence.recordVersion !== 1
    ) {
        throw new Error(
            'The lattice-security evidence kind or version is wrong.',
        );
    }
    const outputPayloadSha256 = evidence.outputPayloadSha256;
    if (typeof outputPayloadSha256 !== 'string') {
        throw new Error('The output payload digest is missing.');
    }
    const unhashedEvidence = { ...evidence };
    delete unhashedEvidence.outputPayloadSha256;
    if (
        outputPayloadSha256 !==
        canonicalJsonSha256(unhashedEvidence as JsonValue)
    ) {
        throw new Error('The output payload digest does not match.');
    }
    if (
        evidence.inputPayloadSha256 !== canonicalJsonSha256(expectedInput) ||
        canonicalJsonText(evidence.input as JsonValue) !==
            canonicalJsonText(expectedInput)
    ) {
        throw new Error('The estimator evidence input is stale or mismatched.');
    }
    if (!Array.isArray(evidence.estimates)) {
        throw new Error('The estimator result list is missing.');
    }
    const diagnosticCases = expectedInput.diagnosticCases.map((value) =>
        requireRecord(value, 'Diagnostic case'),
    );
    if (evidence.estimates.length !== diagnosticCases.length) {
        throw new Error('The estimator result count is wrong.');
    }
    let minimumClassical = Number.POSITIVE_INFINITY;
    let minimumQuantum = Number.POSITIVE_INFINITY;
    for (const [caseIndex, estimateValue] of evidence.estimates.entries()) {
        const estimate = requireRecord(estimateValue, 'Estimator result');
        const expectedCase = diagnosticCases[caseIndex];
        if (
            estimate.identifier !== expectedCase?.identifier ||
            estimate.catalogLevel !== expectedCase.catalogLevel ||
            estimate.basis !== expectedCase.basis ||
            estimate.ringRelationCount !== expectedCase.ringRelationCount ||
            estimate.scalarSampleCount !== expectedCase.scalarSampleCount
        ) {
            throw new Error(
                'An estimator result does not match its exact input case.',
            );
        }
        const estimatorScalarSampleCount = requirePositiveInteger(
            estimate.scalarSampleCount,
            'Estimator scalar sample count',
        );
        const estimatedModulusLog2 = requireFinitePositiveNumber(
            estimate.modulusLog2LowerBound,
            'Estimator modulus logarithm',
        );
        const expectedModulusLog2 = requireFinitePositiveNumber(
            expectedCase.modulusLog2,
            'Input modulus logarithm',
        );
        if (
            estimatedModulusLog2 > expectedModulusLog2 ||
            expectedModulusLog2 - estimatedModulusLog2 >= 1e-9
        ) {
            throw new Error(
                'An estimator modulus logarithm does not match its exact input case.',
            );
        }
        const models = requireRecord(estimate.models, 'Estimator models');
        for (const modelIdentifier of ['classical', 'quantum'] as const) {
            const model = requireRecord(
                models[modelIdentifier],
                `${modelIdentifier} estimator model`,
            );
            const attacks = requireRecord(
                model.attacks,
                `${modelIdentifier} attacks`,
            );
            if (
                canonicalJsonText(Object.keys(attacks).sort()) !==
                canonicalJsonText([...selectedLatticeAttackIdentifiers].sort())
            ) {
                throw new Error(
                    `${modelIdentifier} attack coverage is incomplete or unexpected.`,
                );
            }
            const attackCosts = selectedLatticeAttackIdentifiers.map(
                (attackIdentifier) => {
                    const attack = requireRecord(
                        attacks[attackIdentifier],
                        `${modelIdentifier} ${attackIdentifier} result`,
                    );
                    requirePositiveInteger(
                        attack.blockSize,
                        `${modelIdentifier} ${attackIdentifier} block size`,
                    );
                    if (attack.latticeDimension !== undefined) {
                        requirePositiveInteger(
                            attack.latticeDimension,
                            `${modelIdentifier} ${attackIdentifier} lattice dimension`,
                        );
                    }
                    if (attack.usedScalarSamples !== undefined) {
                        const usedScalarSamples = requirePositiveInteger(
                            attack.usedScalarSamples,
                            `${modelIdentifier} ${attackIdentifier} used scalar samples`,
                        );
                        if (usedScalarSamples > estimatorScalarSampleCount) {
                            throw new Error(
                                `${modelIdentifier} ${attackIdentifier} used more scalar samples than supplied.`,
                            );
                        }
                    }
                    return requireFinitePositiveNumber(
                        attack.securityBitsLowerBound,
                        `${modelIdentifier} ${attackIdentifier} security bits`,
                    );
                },
            );
            const modelMinimum = requireFinitePositiveNumber(
                model.minimumSecurityBitsLowerBound,
                `${modelIdentifier} minimum security bits`,
            );
            if (modelMinimum !== Math.min(...attackCosts)) {
                throw new Error(
                    `${modelIdentifier} minimum does not match the attack rows.`,
                );
            }
            if (modelIdentifier === 'classical') {
                minimumClassical = Math.min(minimumClassical, modelMinimum);
            } else {
                minimumQuantum = Math.min(minimumQuantum, modelMinimum);
            }
        }
    }
    const summary = requireRecord(evidence.summary, 'Estimator summary');
    if (
        summary.minimumClassicalSecurityBitsLowerBound !== minimumClassical ||
        summary.minimumQuantumSecurityBitsLowerBound !== minimumQuantum ||
        summary.materialSuccessThreshold !== 'at least one half' ||
        summary.scope !==
            'Known-attack scalar-LWE diagnostics under the explicitly named proxy model; reductions and joint structured or circular security remain separate assumptions.'
    ) {
        throw new Error(
            'The estimator summary does not match the case rows and scope.',
        );
    }
    if (
        minimumClassical < selectedLatticeAssuranceTargetBits ||
        minimumQuantum < selectedLatticeAssuranceTargetBits
    ) {
        throw new Error(
            'The selected lattice parameters fall below the active known-attack work target.',
        );
    }
    return {
        minimumClassicalSecurityBitsLowerBound: minimumClassical,
        minimumQuantumSecurityBitsLowerBound: minimumQuantum,
    };
};

export const selectedLatticeEvidencePath = path.join(
    repositoryRoot,
    'test-vectors',
    'selected-lattice-security-estimator-evidence.json',
);

export const selectedLatticeRepositoryRoot = repositoryRoot;
