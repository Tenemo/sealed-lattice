import assert from 'node:assert/strict';

export type AttackScreen = Readonly<{
    attack: string;
    costModel: 'classical' | 'quantum';
    modulusBits: bigint;
    log2Cost: number;
}>;

// Pinned unlimited-sample estimator operands. These calibrate the accepted
// actual-distribution assumptions; they are not lower bounds on all attacks.
// The classical model is the criterion. Quantum-memory estimates are stress
// evidence. Every FHE family is bounded by the largest screened modulus.
const criterionAttacks = [
    'unique SVP',
    'primal hybrid',
    'dual hybrid',
] as const;
const fheAttackScreens: readonly AttackScreen[] = [
    {
        attack: 'unique SVP',
        costModel: 'classical',
        modulusBits: 880n,
        log2Cost: 244.404,
    },
    {
        attack: 'primal hybrid',
        costModel: 'classical',
        modulusBits: 880n,
        log2Cost: 234.28285341625354,
    },
    {
        attack: 'dual hybrid',
        costModel: 'classical',
        modulusBits: 880n,
        log2Cost: 243.52800000000002,
    },
    {
        attack: 'unique SVP',
        costModel: 'quantum',
        modulusBits: 880n,
        log2Cost: 221.805,
    },
    {
        attack: 'primal hybrid',
        costModel: 'quantum',
        modulusBits: 880n,
        log2Cost: 214.34082891450038,
    },
    {
        attack: 'dual hybrid',
        costModel: 'quantum',
        modulusBits: 880n,
        log2Cost: 221.275,
    },
];

const instanceAttackScreens: Readonly<
    Record<'share encryption' | 'auxiliary', readonly AttackScreen[]>
> = {
    // The completed 2026-10-15 lattice-screen runs explicitly report an
    // infinite estimate for share unique SVP and dual hybrid, with exit code zero.
    // They are finite-search estimator outcomes, not missing estimates or
    // hardness proofs. The failed fresh quantum primal run is excluded.
    // The reconciled minima retain the lower completed classical/quantum
    // primal results from 2026-10-07 (13:26:15.130 and 13:49:02.909 UTC).
    'share encryption': [
        {
            attack: 'unique SVP',
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
            attack: 'dual hybrid',
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
            attack: 'primal hybrid',
            costModel: 'quantum',
            modulusBits: 158n,
            log2Cost: 593.460876850818,
        },
        {
            attack: 'dual hybrid',
            costModel: 'quantum',
            modulusBits: 158n,
            log2Cost: Number.POSITIVE_INFINITY,
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
            attack: 'primal hybrid',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 282.58789841170767,
        },
        {
            attack: 'dual hybrid',
            costModel: 'classical',
            modulusBits: 35n,
            log2Cost: 376.9798371302914,
        },
        {
            attack: 'unique SVP',
            costModel: 'quantum',
            modulusBits: 35n,
            log2Cost: 367.555,
        },
        {
            attack: 'primal hybrid',
            costModel: 'quantum',
            modulusBits: 35n,
            log2Cost: 268.5681008420732,
        },
        {
            attack: 'dual hybrid',
            costModel: 'quantum',
            modulusBits: 35n,
            log2Cost: 344.79779792804027,
        },
    ],
};

const floor = (
    screens: readonly AttackScreen[],
    costModel: AttackScreen['costModel'],
) => {
    const matching = screens.filter((screen) => screen.costModel === costModel);
    assert.ok(
        criterionAttacks.every((attack) =>
            matching.some((screen) => screen.attack === attack),
        ),
    );
    return matching.reduce((lowest, screen) =>
        screen.log2Cost < lowest.log2Cost ? screen : lowest,
    );
};

export const fheKnownAttackFloor = (modulusBits: bigint) => {
    assert.ok(
        modulusBits > 0n && modulusBits <= 880n,
        'The FHE modulus has no current attack screen.',
    );
    return {
        criterion: floor(fheAttackScreens, 'classical'),
        stressTest: floor(fheAttackScreens, 'quantum'),
    };
};
const instanceKnownAttackFloor = (
    instance: keyof typeof instanceAttackScreens,
) => ({
    criterion: floor(instanceAttackScreens[instance], 'classical'),
    stressTest: floor(instanceAttackScreens[instance], 'quantum'),
});

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

export const latticeGroupFloors = (
    group: LatticeAssumptionGroup,
    modulusBits: bigint,
) => {
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
