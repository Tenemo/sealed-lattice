import assert from 'node:assert/strict';

import { compileClearPreparationLedger } from '#tests/clear-preparation-ledger-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    compileClassicalReaderOracleBudget,
    compileFullCircuitOracleBudget,
    compileSourceDomainOracleBudget,
    shakePermutationGateCharge,
} from '#tests/oracle-budget-model.js';
import {
    firstOracleResumeHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { registrationSourceMask } from '#tests/registration-source-domain-model.js';
import { compileRegistrationSourceExtractionWork } from '#tests/registration-source-randomness-model.js';
import {
    listSupportedProfiles,
    supportedProfileRanges,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';

// The frozen target: an adversary whose complete experiment costs T gates has
// advantage at most T/2^80. Above 2^80 gates the bound is trivial.
export const securityTargetBits = 80n;

// The assumption groups of the security ledger that share the 2^-80 budget:
// the FHE, share-encryption and auxiliary Ring-LWE comparisons, evaluation-key
// circular security, ML-DSA authentication, identity collisions and the
// statistical terms. Each group receives 2^-(80+3).
const budgetGroupCount = 7n;

// Smallest integer k with numerator/denominator <= 2^k.
export const ceilingLog2 = (numerator: bigint, denominator = 1n): bigint => {
    assert.ok(numerator > 0n && denominator > 0n);
    let exponent = 0n;
    while (numerator > denominator << exponent) exponent += 1n;
    while (numerator << 1n <= denominator << exponent) exponent -= 1n;
    return exponent;
};

export const budgetSplitBits = ceilingLog2(budgetGroupCount);

// Core-SVP (ADPS16) estimates from the pinned lattice estimator for the FHE
// instance: ring degree 65,536, a balanced sparse ternary secret with 512
// entries of each sign and error width 3.2. Every supported FHE modulus shares
// the dimension and both distributions, so an estimate at a modulus bounds
// the same attack at every smaller supported modulus from below. Attack costs
// follow the accepted convention, without quantum random-access memory, so
// the classical model's screens of every algorithm of the estimator's full
// estimate decide the criterion. The quantum model's sieving speedup assumes
// that memory, so its estimates are a stress test. Neither model counts gates
// the way the convention does, so both remain screens.
export const fheAttackScreens = [
    {
        attack: 'primal hybrid',
        costModel: 'quantum',
        modulusBits: 992n,
        log2Cost: 184.72988147620254,
    },
    {
        attack: 'bounded distance',
        costModel: 'quantum',
        modulusBits: 992n,
        log2Cost: 188.94500011465215,
    },
    {
        attack: 'dual hybrid',
        costModel: 'quantum',
        modulusBits: 992n,
        log2Cost: 188.41500000000104,
    },
    {
        attack: 'primal hybrid',
        costModel: 'quantum',
        modulusBits: 960n,
        log2Cost: 192.2702204826055,
    },
    {
        attack: 'primal hybrid',
        costModel: 'quantum',
        modulusBits: 928n,
        log2Cost: 200.5386561206966,
    },
    {
        attack: 'primal hybrid',
        costModel: 'quantum',
        modulusBits: 896n,
        log2Cost: 209.760800138559,
    },
    {
        attack: 'primal hybrid',
        costModel: 'classical',
        modulusBits: 992n,
        log2Cost: 201.53907185206296,
    },
    {
        attack: 'primal hybrid',
        costModel: 'classical',
        modulusBits: 960n,
        log2Cost: 210.08719723641488,
    },
    {
        attack: 'primal hybrid',
        costModel: 'classical',
        modulusBits: 928n,
        log2Cost: 219.28562463733982,
    },
    {
        attack: 'unique SVP',
        costModel: 'classical',
        modulusBits: 960n,
        log2Cost: 217.54,
    },
    {
        attack: 'bounded distance',
        costModel: 'classical',
        modulusBits: 960n,
        log2Cost: 217.54000418240523,
    },
    {
        attack: 'primal hybrid without meet-in-the-middle',
        costModel: 'classical',
        modulusBits: 960n,
        log2Cost: 215.83538369914376,
    },
    {
        attack: 'primal hybrid with Babai lifting',
        costModel: 'classical',
        modulusBits: 960n,
        log2Cost: 214.48815634813218,
    },
    {
        attack: 'dual',
        costModel: 'classical',
        modulusBits: 960n,
        log2Cost: 217.54,
    },
    {
        attack: 'dual hybrid',
        costModel: 'classical',
        modulusBits: 960n,
        log2Cost: 216.956,
    },
] as const;

export type FheAttackScreen = (typeof fheAttackScreens)[number];

// The lattice-reduction algorithms of the pinned estimator's full estimate,
// plus the meet-in-the-middle primal hybrid without Babai lifting that its
// authors call overly optimistic for the attacker. Its other algorithms yield
// no screen at this dimension: coded-BKW reports no finite cost and Arora-Ge
// does not finish.
export const criterionAttacks: readonly FheAttackScreen['attack'][] = [
    'unique SVP',
    'bounded distance',
    'primal hybrid',
    'primal hybrid without meet-in-the-middle',
    'primal hybrid with Babai lifting',
    'dual',
    'dual hybrid',
];

// The screen of one attack and cost model at the smallest screened modulus
// at least as large as the profile's.
const coveringScreen = (
    attack: FheAttackScreen['attack'],
    costModel: FheAttackScreen['costModel'],
    modulusBits: bigint,
): FheAttackScreen | undefined =>
    fheAttackScreens
        .filter(
            (screen) =>
                screen.attack === attack &&
                screen.costModel === costModel &&
                screen.modulusBits >= modulusBits,
        )
        .sort((left, right) =>
            left.modulusBits < right.modulusBits ? -1 : 1,
        )[0];

// The cheapest covering screen of one cost model over the given attacks: no
// recorded screen of that model costs less at this modulus.
const screenedFloor = (
    costModel: FheAttackScreen['costModel'],
    attacks: readonly FheAttackScreen['attack'][],
    modulusBits: bigint,
) => {
    const covering = attacks.map((attack) =>
        coveringScreen(attack, costModel, modulusBits),
    );
    assert.ok(
        covering.every((screen) => screen !== undefined),
        'No screen covers this modulus.',
    );
    return covering.reduce((lowest, screen) =>
        screen.log2Cost < lowest.log2Cost ? screen : lowest,
    );
};

// The criterion floor covers every criterion attack in the classical model;
// the stress-test floor covers every attack the quantum model screened.
export const fheKnownAttackFloor = (modulusBits: bigint) => ({
    criterion: screenedFloor('classical', criterionAttacks, modulusBits),
    stressTest: screenedFloor(
        'quantum',
        [
            ...new Set(
                fheAttackScreens
                    .filter((screen) => screen.costModel === 'quantum')
                    .map((screen) => screen.attack),
            ),
        ],
        modulusBits,
    ),
});

export type AttackScreen = Readonly<{
    attack: string;
    costModel: 'classical' | 'quantum';
    modulusBits: bigint;
    log2Cost: number;
}>;

// Core-SVP screens from the pinned estimator for the suite's two fixed
// instances, which every profile shares: degree 65,536 with the 158-bit
// sharing modulus, and degree 4,096 with the 35-bit auxiliary modulus. Both
// use balanced sparse ternary secrets with 128 entries of each sign, the
// width-3.2 error of every emitted sampler and, for the attacker, unbounded
// samples. An attack whose estimate has no finite cost at any block size has
// an infinite screen. The classical screens of every algorithm of the full
// estimate decide the criterion; the quantum screens are a stress test.
export const instanceAttackScreens: Readonly<
    Record<'share encryption' | 'auxiliary', readonly AttackScreen[]>
> = {
    'share encryption': [
        {
            attack: 'unique SVP',
            costModel: 'classical',
            modulusBits: 158n,
            log2Cost: Number.POSITIVE_INFINITY,
        },
        {
            attack: 'bounded distance',
            costModel: 'classical',
            modulusBits: 158n,
            log2Cost: Number.POSITIVE_INFINITY,
        },
        {
            attack: 'primal hybrid',
            costModel: 'classical',
            modulusBits: 158n,
            log2Cost: 610.1471552614535,
        },
        {
            attack: 'primal hybrid without meet-in-the-middle',
            costModel: 'classical',
            modulusBits: 158n,
            log2Cost: 738.7002118029999,
        },
        {
            attack: 'primal hybrid with Babai lifting',
            costModel: 'classical',
            modulusBits: 158n,
            log2Cost: 628.1599186312503,
        },
        {
            attack: 'dual',
            costModel: 'classical',
            modulusBits: 158n,
            log2Cost: Number.POSITIVE_INFINITY,
        },
        {
            attack: 'dual hybrid',
            costModel: 'classical',
            modulusBits: 158n,
            log2Cost: Number.POSITIVE_INFINITY,
        },
        {
            attack: 'coded BKW',
            costModel: 'classical',
            modulusBits: 158n,
            log2Cost: Number.POSITIVE_INFINITY,
        },
        {
            attack: 'unique SVP',
            costModel: 'quantum',
            modulusBits: 158n,
            log2Cost: Number.POSITIVE_INFINITY,
        },
        {
            attack: 'bounded distance',
            costModel: 'quantum',
            modulusBits: 158n,
            log2Cost: Number.POSITIVE_INFINITY,
        },
        {
            attack: 'dual hybrid',
            costModel: 'quantum',
            modulusBits: 158n,
            log2Cost: Number.POSITIVE_INFINITY,
        },
        {
            attack: 'primal hybrid',
            costModel: 'quantum',
            modulusBits: 158n,
            log2Cost: 593.460876850818,
        },
        {
            attack: 'primal hybrid without meet-in-the-middle',
            costModel: 'quantum',
            modulusBits: 158n,
            log2Cost: 713.7818160198522,
        },
        {
            attack: 'primal hybrid with Babai lifting',
            costModel: 'quantum',
            modulusBits: 158n,
            log2Cost: 609.9031610086014,
        },
    ],
    auxiliary: [
        {
            attack: 'unique SVP',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 405.00399999999996,
        },
        {
            attack: 'bounded distance',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 405.5351072984547,
        },
        {
            attack: 'primal hybrid',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 282.58789841170767,
        },
        {
            attack: 'primal hybrid without meet-in-the-middle',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 344.50991114725474,
        },
        {
            attack: 'primal hybrid with Babai lifting',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 327.02025390058486,
        },
        {
            attack: 'dual',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 409.96799999999996,
        },
        {
            attack: 'dual hybrid',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 376.9798371302914,
        },
        {
            attack: 'coded BKW',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 521.6940086703631,
        },
        {
            attack: 'primal hybrid',
            costModel: 'quantum',
            modulusBits: 35n,
            log2Cost: 268.5681008420732,
        },
        {
            attack: 'bounded distance',
            costModel: 'quantum',
            modulusBits: 35n,
            log2Cost: 368.1202384652496,
        },
        {
            attack: 'dual hybrid',
            costModel: 'quantum',
            modulusBits: 35n,
            log2Cost: 344.79779792804027,
        },
    ],
};

// The fixed instances' criterion also covers coded BKW, which reports a
// finite cost at the auxiliary instance's small dimension but none at the
// share-encryption instance's.
const instanceCriterionAttacks: readonly string[] = [
    ...criterionAttacks,
    'coded BKW',
];

// The cheapest finite screen of each cost model. Every criterion attack must
// have a classical screen, finite or not; a model without any finite screen
// has no floor.
export const instanceKnownAttackFloor = (
    instance: keyof typeof instanceAttackScreens,
) => {
    const screens = instanceAttackScreens[instance];
    for (const attack of instanceCriterionAttacks)
        assert.ok(
            screens.some(
                (screen) =>
                    screen.attack === attack &&
                    screen.costModel === 'classical',
            ),
            `No classical ${attack} screen covers the ${instance} instance.`,
        );
    const cheapest = (costModel: AttackScreen['costModel']) =>
        screens
            .filter(
                (screen) =>
                    screen.costModel === costModel &&
                    Number.isFinite(screen.log2Cost),
            )
            .reduce<AttackScreen | undefined>(
                (lowest, screen) =>
                    lowest === undefined || screen.log2Cost < lowest.log2Cost
                        ? screen
                        : lowest,
                undefined,
            );
    return {
        criterion: cheapest('classical'),
        stressTest: cheapest('quantum'),
    };
};

// The reduction-work operand of an FHE comparison at an experiment of
// `experimentGates`: the work the reduction adds to that experiment. The
// lattice assumptions hold relative to the ideal SHAKE oracle, so a
// reduction that never reads or programs the attacker's queries forwards
// them and adds nothing; that floor omits even the programming wrapper. The
// FHE embedding fixes the pivot's coordinate from extracted corrupt
// registration coordinates, so it reads and programs the registration-source
// commitment domain: under that assumption it implements only that domain,
// with one honest-commitment shadow per potential sender scope, and forwards
// every other query. Its variant prices the complete reduction except the
// simulated proofs' record creation: the source-domain query circuits, the
// programmed honest proofs' replacement wrapper, the classical-reader and
// resumed-hash conversions and the forwarded calls, the corrupt
// registration-source extractions with coordinate decoding, and the source
// cache. A reduction that implements the whole function itself, as one
// without that assumption must, pays the four nested interfaces after it;
// those variants price only the maintained query circuits, so their
// requirements are lower bounds on what such a reduction needs.
export type ReductionVariant =
    | 'forwarded oracle'
    | 'source-domain reduction'
    | 'background oracle'
    | 'commitment shadows'
    | 'commitment shadows and readers'
    | 'commitment shadows and resumed hashes';

export const reductionVariants: readonly ReductionVariant[] = [
    'forwarded oracle',
    'source-domain reduction',
    'background oracle',
    'commitment shadows',
    'commitment shadows and readers',
    'commitment shadows and resumed hashes',
];

// The exact registration-source commitment input lengths over the immutable
// family catalogue, which every poll of the largest roster size and each
// option count spans.
let catalogueSourceInputBits: readonly bigint[] | undefined;
export const registrationSourceInputBits = (): readonly bigint[] => {
    if (catalogueSourceInputBits !== undefined) return catalogueSourceInputBits;
    const { participants, options } = supportedProfileRanges();
    const lengths = new Set<bigint>();
    for (
        let optionCount = options.minimum;
        optionCount <= options.maximum;
        optionCount++
    )
        for (const family of compileRegistrationSetupBindingScreen(
            participants.maximum,
            optionCount,
        ).fhe) {
            let modulus = family.modulus;
            const bytes: number[] = [];
            while (modulus > 0n) {
                bytes.push(Number(modulus & 255n));
                modulus >>= 8n;
            }
            const source = registrationSourceMask(
                new Uint8Array(1952),
                Uint8Array.from(bytes),
                BigInt(family.sampleBits),
                Number(fixedModulusBfvInputs.polynomialDegree),
            );
            lengths.add(8n * BigInt(source.inputBytes));
        }
    catalogueSourceInputBits = [...lengths].sort((left, right) =>
        left < right ? -1 : 1,
    );
    return catalogueSourceInputBits;
};

// The complete-input conversion of a setup proof's first-oracle leaf hash
// resumed from its authenticated checkpoint prefix. It depends on the profile
// alone, so a population search compiles it once.
const resumeFactors = new Map<SupportedProfile, bigint>();
const firstOracleResumeFactor = (profile: SupportedProfile) => {
    const cached = resumeFactors.get(profile);
    if (cached !== undefined) return cached;
    const setup = proofHashProfiles(profile).find(
        (value) => value.role === 'setup',
    );
    assert.ok(setup !== undefined);
    const factor = firstOracleResumeHashWork(
        setup.firstWidth,
        setup.roleBytes,
        (setup.firstWidth - 48n) / 16n,
    ).completeInputFactor;
    resumeFactors.set(profile, factor);
    return factor;
};

// The ledger populations one reduction acts on at a profile and original
// honest registration population.
export type ReductionOperands = Readonly<{
    participantCount: number;
    optionCount: number;
    sourceMaskScopes: bigint;
    honestProofScopes: bigint;
    corruptSourceExtractions: bigint;
    sourceCacheGates: bigint;
    resumeFactor: bigint;
}>;

const reductionOperands = (
    profile: SupportedProfile,
    ledger: ReturnType<typeof compileClearPreparationLedger>,
    resumeFactor: bigint,
): ReductionOperands => ({
    participantCount: profile.participantCount,
    optionCount: profile.optionCount,
    sourceMaskScopes: ledger.sourceMaskScopes,
    // Each simulated honest proof programs one wide verifier message.
    honestProofScopes: ledger.maximumHonestProofScopes,
    corruptSourceExtractions: ledger.maximumCorruptSourceExtractions,
    sourceCacheGates: ledger.sourceCache.totalGates,
    resumeFactor,
});

// The prepared selection and decoding of one extraction request is linear in
// the requests, so one request per profile and capacity is compiled once.
const extractionGatesPerRequest = new Map<string, bigint>();
const extractionGates = (operands: ReductionOperands, capacity: bigint) => {
    const key = `${String(operands.participantCount)}:${String(operands.optionCount)}:${String(capacity)}`;
    let perRequest = extractionGatesPerRequest.get(key);
    if (perRequest === undefined) {
        perRequest = compileRegistrationSourceExtractionWork(
            operands.participantCount,
            operands.optionCount,
            capacity,
            1n,
        ).maximumPreparedSelectionAndDecodingGates;
        extractionGatesPerRequest.set(key, perRequest);
    }
    return operands.corruptSourceExtractions * perRequest;
};

export const reductionGates = (
    variant: ReductionVariant,
    experimentGates: bigint,
    operands: ReductionOperands,
) => {
    if (variant === 'forwarded oracle') return 0n;
    // The commitment digest width is the first output chunk.
    const firstChunkBits = 512n;
    if (variant === 'source-domain reduction') {
        // The conversions cover classical readers at five and resumed hashes
        // at their own factor.
        const budget = compileSourceDomainOracleBudget(
            experimentGates,
            firstChunkBits,
            registrationSourceInputBits(),
            operands.honestProofScopes,
            operands.sourceMaskScopes,
            operands.resumeFactor < 5n ? 5n : operands.resumeFactor,
        );
        // Extraction scans the source component's whole capacity.
        return (
            budget.shadowQueryGatesUpperBound +
            budget.forwardedCallGatesUpperBound +
            extractionGates(
                operands,
                budget.sourceComponentCapacityUpperBound,
            ) +
            operands.sourceCacheGates
        );
    }
    if (variant === 'background oracle')
        // The full-domain components alone: no simulated honest commitment,
        // no programmed record and no extraction.
        return compileFullCircuitOracleBudget(experimentGates, firstChunkBits)
            .baseQueryGatesUpperBound;
    if (variant === 'commitment shadows')
        // The FHE embedding fixes the pivot's honest coordinate after its
        // registration commitment, so the honest commitments stay simulated:
        // one shadow per potential sender scope.
        return compileFullCircuitOracleBudget(
            experimentGates,
            firstChunkBits,
            0n,
            operands.sourceMaskScopes,
        ).shadowQueryGatesUpperBound;
    // The participant code reads its private streams through classical
    // fixed-input readers, whose conversion replaces the complete-input one.
    // A restored checkpoint resumes its first-oracle leaf hashes from their
    // retained prefixes, which needs the larger conversion when the original
    // input stays available to the adapter.
    return compileClassicalReaderOracleBudget(
        experimentGates,
        firstChunkBits,
        0n,
        operands.sourceMaskScopes,
        variant === 'commitment shadows and readers' ||
            operands.resumeFactor < 5n
            ? 5n
            : operands.resumeFactor,
    ).shadowQueryGatesUpperBound;
};

// The experiment that decides each requirement. The reduction work depends on
// an experiment's cost only through its whole permutation slots, so within
// one slot interval the ratio Tred(T)/T is largest at the interval's first
// gate count. The query circuits' routing grows with the square of the slots,
// so across intervals the ratio grows with the slots; the source cache and
// the extractions' fixed work matter only at experiments whose routing has
// fallen by far more, as the margin test checks at the population limits,
// where the slack is smallest. The largest whole-slot experiment within 2^80
// gates therefore decides every requirement.
export const decisiveExperimentGates =
    ((1n << securityTargetBits) / shakePermutationGateCharge) *
    shakePermutationGateCharge;

// Smallest lambda with comparisons*Tred(T)/2^lambda <= T/2^(80+split) for
// every T <= 2^80, where Tred(T) = T + reduction work(T).
export const requiredFheAssumptionBits = (
    comparisons: bigint,
    reductionWorkGates: bigint,
    experimentGates = decisiveExperimentGates,
) =>
    securityTargetBits +
    budgetSplitBits +
    ceilingLog2(
        comparisons * (experimentGates + reductionWorkGates),
        experimentGates,
    );

// A requirement of lambda bits holds at an attack floor of c bits when
// lambda <= c, so the integer level a floor supports is its whole part.
export const supportedLevelBits = (floor: AttackScreen) =>
    BigInt(Math.floor(floor.log2Cost));

// The further reduction work that keeps the requirement within a supported
// level: comparisons*(T + priced + W) <= T*2^(level-80-split). Negative when
// the priced work alone exceeds that level.
export const unpricedWorkAllowance = (
    comparisons: bigint,
    pricedGates: bigint,
    levelBits: bigint,
    experimentGates = decisiveExperimentGates,
) =>
    (experimentGates << (levelBits - securityTargetBits - budgetSplitBits)) /
        comparisons -
    experimentGates -
    pricedGates;

// The single-key Ring-LWE comparisons of the FHE instance in the clear
// preparation ledger. A good-key multi-message comparison over n messages
// expands into n single-message comparisons, as the ledger requires for a
// single-message assumption.
const fheRingLweComparisons = (
    ledger: ReturnType<typeof compileClearPreparationLedger>,
) =>
    ledger.fheSelectedKeyComparisons +
    ledger.fheBallotComparisons * ledger.messagesPerFheBallotComparison;

// The lattice assumption groups of the clear-preparation ledger. Each charges
// its own single-message comparisons; circular security of the honest
// evaluation-key tuple is judged against the FHE instance's floor.
export type LatticeAssumptionGroup =
    | 'FHE Ring-LWE'
    | 'Evaluation-key circular security'
    | 'Share-encryption Ring-LWE'
    | 'Auxiliary Ring-LWE';

export const latticeAssumptionGroups: readonly LatticeAssumptionGroup[] = [
    'FHE Ring-LWE',
    'Evaluation-key circular security',
    'Share-encryption Ring-LWE',
    'Auxiliary Ring-LWE',
];

export const latticeGroupComparisons = (
    group: LatticeAssumptionGroup,
    ledger: ReturnType<typeof compileClearPreparationLedger>,
) => {
    switch (group) {
        case 'FHE Ring-LWE':
            return fheRingLweComparisons(ledger);
        case 'Evaluation-key circular security':
            return ledger.fheTupleComparisons;
        case 'Share-encryption Ring-LWE':
            // Every recipient key's good/uniform/good sweep and both
            // replacements of every honest sharing row to an honest
            // recipient, one ciphertext each.
            return (
                ledger.recipientKeyComparisons +
                ledger.recipientCiphertextComparisons
            );
        case 'Auxiliary Ring-LWE':
            return (
                ledger.auxiliaryKeyComparisons +
                ledger.auxiliaryBallotComparisons *
                    ledger.messagesPerAuxiliaryBallotComparison
            );
    }
};

// A group's criterion and stress-test floors at a profile's FHE modulus. The
// share-encryption and auxiliary instances are fixed for the suite. A floor
// is undefined when no screened attack of that model has a finite cost.
export const latticeGroupFloors = (
    group: LatticeAssumptionGroup,
    modulusBits: bigint,
): Readonly<{
    criterion: AttackScreen | undefined;
    stressTest: AttackScreen | undefined;
}> => {
    switch (group) {
        case 'FHE Ring-LWE':
        case 'Evaluation-key circular security':
            return fheKnownAttackFloor(modulusBits);
        case 'Share-encryption Ring-LWE':
            return instanceKnownAttackFloor('share encryption');
        case 'Auxiliary Ring-LWE':
            return instanceKnownAttackFloor('auxiliary');
    }
};

// Every supported profile of each participant count, the largest modulus
// first and, among equal moduli, the most options first.
const profilesByParticipantCount = () => {
    const groups = new Map<number, SupportedProfile[]>();
    for (const profile of listSupportedProfiles()) {
        const group = groups.get(profile.participantCount) ?? [];
        group.push(profile);
        groups.set(profile.participantCount, group);
    }
    return [...groups.entries()]
        .sort(([left], [right]) => left - right)
        .map(([participantCount, profiles]) => ({
            participantCount,
            profiles: profiles.sort(
                (left, right) =>
                    right.ciphertext.bits - left.ciphertext.bits ||
                    right.optionCount - left.optionCount,
            ),
        }));
};

// The ledger, comparisons and reduction operands of a group at a profile and
// original honest registration population of one poll.
const groupComparisonInputs = (
    group: LatticeAssumptionGroup,
    profile: SupportedProfile,
    honestRegistrations: bigint,
) => {
    const ledger = compileClearPreparationLedger(profile, honestRegistrations);
    return {
        ledger,
        comparisons: latticeGroupComparisons(group, ledger),
        operands: reductionOperands(
            profile,
            ledger,
            firstOracleResumeFactor(profile),
        ),
    };
};

const fheComparisonInputs = (
    profile: SupportedProfile,
    honestRegistrations: bigint,
) => groupComparisonInputs('FHE Ring-LWE', profile, honestRegistrations);

// One profile's screen at one original honest registration per participant:
// the smallest population with every member honest. A larger population H
// adds about log2(H/n) bits for the comparisons and as many again for the
// source-domain reduction, whose shadows grow with H.
const screenProfile = (profile: SupportedProfile) => {
    const experimentGates = decisiveExperimentGates;
    const honestRegistrations = BigInt(profile.participantCount);
    const modulusBits = BigInt(profile.ciphertext.bits);
    const { criterion, stressTest } = fheKnownAttackFloor(modulusBits);
    const { ledger, comparisons, operands } = fheComparisonInputs(
        profile,
        honestRegistrations,
    );
    const requirements = reductionVariants.map((variant) => {
        const gates = reductionGates(variant, experimentGates, operands);
        const requiredBits = requiredFheAssumptionBits(
            comparisons,
            gates,
            experimentGates,
        );
        return {
            variant,
            reductionGates: gates,
            requiredBits,
            marginToCriterion: criterion.log2Cost - Number(requiredBits),
            marginToStressTest: stressTest.log2Cost - Number(requiredBits),
        };
    });
    const sourceDomain = requirements.find(
        (value) => value.variant === 'source-domain reduction',
    );
    assert.ok(sourceDomain !== undefined);
    return {
        participantCount: profile.participantCount,
        optionCount: profile.optionCount,
        modulusBits,
        honestRegistrations,
        selectedPositionSets: ledger.selectedPositionSets,
        sharedFheModulusGuesses: ledger.sharedFheModulusGuesses,
        operands,
        comparisons,
        criterion,
        stressTest,
        requirements,
        // The record creation of the simulated proofs is the reduction
        // work this variant leaves unpriced.
        criterionAllowance: unpricedWorkAllowance(
            comparisons,
            sourceDomain.reductionGates,
            supportedLevelBits(criterion),
            experimentGates,
        ),
    };
};

// Each participant count's binding profile: the option count whose
// source-domain requirement leaves the least further work within its own
// criterion level, the largest modulus among equals.
export const compileSecurityMarginScreen = () =>
    profilesByParticipantCount().map(({ profiles }) =>
        profiles
            .map(screenProfile)
            .reduce((binding, row) =>
                row.criterionAllowance < binding.criterionAllowance
                    ? row
                    : binding,
            ),
    );

// The source-domain requirement of a group's comparisons at a profile and an
// original honest registration population of one poll, charged at an
// experiment of the given cost; the decisive experiment decides it. Every
// lattice comparison of the clear-preparation hybrids runs inside the
// extracting simulator that the registration-source step installs, so each
// group's reduction pays the same source-domain work.
export const latticeRequirementAt = (
    group: LatticeAssumptionGroup,
    profile: SupportedProfile,
    honestRegistrations: bigint,
    experimentGates = decisiveExperimentGates,
) => {
    const { comparisons, operands } = groupComparisonInputs(
        group,
        profile,
        honestRegistrations,
    );
    const gates = reductionGates(
        'source-domain reduction',
        experimentGates,
        operands,
    );
    return {
        comparisons,
        operands,
        reductionGates: gates,
        requiredBits: requiredFheAssumptionBits(
            comparisons,
            gates,
            experimentGates,
        ),
    };
};

export const sourceDomainRequirementAt = (
    profile: SupportedProfile,
    honestRegistrations: bigint,
    experimentGates = decisiveExperimentGates,
) =>
    latticeRequirementAt(
        'FHE Ring-LWE',
        profile,
        honestRegistrations,
        experimentGates,
    );

// Population searches stop here; a group still within its level at this
// population has no limit below it.
export const populationSearchCap = 1n << 64n;

// The largest population at most the search cap for which a requirement that
// never falls as the population grows stays within its level. Doubling, or a
// population already known to exceed the level, and then bisection find it.
// Zero when one registration already exceeds the level; undefined when the
// cap itself stays within it.
export const largestPopulationWithin = (
    within: (population: bigint) => boolean,
    exceeding?: bigint,
): bigint | undefined => {
    let low = 0n;
    let high = exceeding ?? 1n;
    if (exceeding === undefined) {
        if (within(populationSearchCap)) return undefined;
        while (within(high)) {
            low = high;
            high *= 2n;
        }
    }
    while (high - low > 1n) {
        const middle = (low + high) / 2n;
        if (within(middle)) low = middle;
        else high = middle;
    }
    return low;
};

// A lattice group's own limit on the original honest registrations of a
// poll of each participant count, whatever its option count: the smallest
// over those option counts of the largest population whose priced
// source-domain requirement stays within the profile's own criterion level,
// and likewise within its quantum stress-test level. A profile that stays
// within its level at the smallest limit so far cannot lower it, so only the
// others are searched. At each limit, the further reduction work that every
// option count's level still absorbs bounds the unpriced record creation. A
// limit is undefined when no profile has one below the search cap, and a
// floor without a finite screen imposes none.
const solveLatticePopulationLimits = (group: LatticeAssumptionGroup) =>
    profilesByParticipantCount().map(({ participantCount, profiles }) => {
        const limit = (floor: 'criterion' | 'stressTest') => {
            const levelOf = (profile: SupportedProfile) => {
                const screen = latticeGroupFloors(
                    group,
                    BigInt(profile.ciphertext.bits),
                )[floor];
                return screen === undefined
                    ? undefined
                    : supportedLevelBits(screen);
            };
            let binding:
                | Readonly<{
                      profile: SupportedProfile;
                      levelBits: bigint;
                      honestRegistrations: bigint;
                  }>
                | undefined;
            for (const profile of profiles) {
                const levelBits = levelOf(profile);
                if (levelBits === undefined) continue;
                const within = (population: bigint) =>
                    latticeRequirementAt(group, profile, population)
                        .requiredBits <= levelBits;
                if (
                    binding !== undefined &&
                    within(binding.honestRegistrations)
                )
                    continue;
                const honestRegistrations = largestPopulationWithin(
                    within,
                    binding?.honestRegistrations,
                );
                if (honestRegistrations === undefined) continue;
                binding = { profile, levelBits, honestRegistrations };
            }
            if (binding === undefined) return undefined;
            assert.ok(
                binding.honestRegistrations > 0n,
                'One registration already exceeds the supported level.',
            );
            const { honestRegistrations } = binding;
            const allowance = profiles
                .map((profile) => {
                    const levelBits = levelOf(profile);
                    if (levelBits === undefined) return undefined;
                    const { comparisons, reductionGates: gates } =
                        latticeRequirementAt(
                            group,
                            profile,
                            honestRegistrations,
                        );
                    return unpricedWorkAllowance(comparisons, gates, levelBits);
                })
                .filter((value) => value !== undefined)
                .reduce((least, value) => (value < least ? value : least));
            return {
                optionCount: binding.profile.optionCount,
                modulusBits: BigInt(binding.profile.ciphertext.bits),
                levelBits: binding.levelBits,
                honestRegistrations,
                allowance,
            };
        };
        return {
            participantCount,
            criterion: limit('criterion'),
            stressTest: limit('stressTest'),
        };
    });

// Each group's limits are solved once.
const latticePopulationLimits = new Map<
    LatticeAssumptionGroup,
    ReturnType<typeof solveLatticePopulationLimits>
>();

export const compileLatticePopulationLimits = (
    group: LatticeAssumptionGroup,
) => {
    let limits = latticePopulationLimits.get(group);
    if (limits === undefined) {
        limits = solveLatticePopulationLimits(group);
        latticePopulationLimits.set(group, limits);
    }
    return limits;
};

// The FHE comparisons' own limits, which every participant count has.
export const compileFhePopulationLimits = () =>
    compileLatticePopulationLimits('FHE Ring-LWE').map((row) => {
        assert.ok(row.criterion !== undefined && row.stressTest !== undefined);
        return {
            participantCount: row.participantCount,
            criterion: row.criterion,
            stressTest: row.stressTest,
        };
    });
