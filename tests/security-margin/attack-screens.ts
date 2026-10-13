import assert from 'node:assert/strict';

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

type FheAttackScreen = (typeof fheAttackScreens)[number];

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

// The lattice assumption groups of the preparation ledger. Each charges
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
