import assert from 'node:assert/strict';

import { compileClearPreparationLedger } from '#tests/clear-preparation-ledger-model.js';
import {
    compileClassicalReaderOracleBudget,
    compileFullCircuitOracleBudget,
} from '#tests/oracle-budget-model.js';
import {
    firstOracleResumeHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import {
    listSupportedProfiles,
    type SupportedProfile,
} from '#tests/supported-profile-model.js';

// The frozen target: an adversary whose complete experiment costs T gates has
// advantage at most T/2^80. Above 2^80 gates the bound is trivial.
export const securityTargetBits = 80n;

// The assumption groups that share the 2^-80 budget, as in the withdrawn
// composed ledger: statistical terms, signatures, identity collisions,
// share-encryption, auxiliary and FHE Ring-LWE, and evaluation-key circular
// security. Each group receives 2^-(80+3).
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
// the same attack at every smaller supported modulus from below. The quantum
// model's sieving speedup assumes quantum random-access memory, which the
// accepted cost convention does not provide; the classical model omits it.
// Neither counts gates the way the convention does, so both remain screens.
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
] as const;

export type FheAttackScreen = (typeof fheAttackScreens)[number];

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

// The quantum floor is the cheapest covering quantum screen over every
// screened attack: no recorded quantum screen costs less at this modulus.
export const fheKnownAttackFloor = (modulusBits: bigint) => {
    const quantum = [
        ...new Set(fheAttackScreens.map((screen) => screen.attack)),
    ].map((attack) => coveringScreen(attack, 'quantum', modulusBits));
    assert.ok(
        quantum.every((screen) => screen !== undefined),
        'No screen covers this modulus.',
    );
    const floor = quantum.reduce((lowest, screen) =>
        screen.log2Cost < lowest.log2Cost ? screen : lowest,
    );
    const primal = coveringScreen('primal hybrid', 'quantum', modulusBits)!;
    const classicalPrimal = coveringScreen(
        'primal hybrid',
        'classical',
        modulusBits,
    );
    assert.ok(classicalPrimal !== undefined);
    return { floor, primal, classicalPrimal };
};

// The oracle-simulation operand of an FHE comparison at an experiment of
// `experimentGates`, in three nested interfaces. A lattice challenger
// supplies no random oracle, so every reduction implements the background
// function itself. Each variant prices only the maintained query circuits, so
// each requirement below is a lower bound on what that reduction needs;
// extraction, proof simulation, record creation and every other part of the
// reduction only add work.
export type OracleSimulationVariant =
    | 'background oracle'
    | 'commitment shadows'
    | 'commitment shadows and readers'
    | 'commitment shadows and resumed hashes';

export const oracleSimulationVariants: readonly OracleSimulationVariant[] = [
    'background oracle',
    'commitment shadows',
    'commitment shadows and readers',
    'commitment shadows and resumed hashes',
];

// The complete-input conversion of a setup proof's first-oracle leaf hash
// resumed from its authenticated checkpoint prefix.
const firstOracleResumeFactor = (profile: SupportedProfile) => {
    const setup = proofHashProfiles(profile).find(
        (value) => value.role === 'setup',
    );
    assert.ok(setup !== undefined);
    return firstOracleResumeHashWork(
        setup.firstWidth,
        setup.roleBytes,
        (setup.firstWidth - 48n) / 16n,
    ).completeInputFactor;
};

export const oracleSimulationGates = (
    variant: OracleSimulationVariant,
    experimentGates: bigint,
    sourceMaskScopes: bigint,
    resumeFactor = 5n,
) => {
    // The commitment digest width is the first output chunk.
    const firstChunkBits = 512n;
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
            sourceMaskScopes,
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
        sourceMaskScopes,
        variant === 'commitment shadows and readers' || resumeFactor < 5n
            ? 5n
            : resumeFactor,
    ).shadowQueryGatesUpperBound;
};

// Smallest lambda with comparisons*Tred(T)/2^lambda <= T/2^(80+split) for
// every T <= 2^80, where Tred(T) = T + simulation(T). The ratio Tred(T)/T
// does not decrease with T, so T = 2^80 decides it.
export const requiredFheAssumptionBits = (
    comparisons: bigint,
    simulationGates: bigint,
    experimentGates = 1n << securityTargetBits,
) =>
    securityTargetBits +
    budgetSplitBits +
    ceilingLog2(
        comparisons * (experimentGates + simulationGates),
        experimentGates,
    );

// The single-key Ring-LWE comparisons of the FHE instance in the clear
// preparation ledger. A good-key multi-message comparison over n messages
// expands into n single-message comparisons, as the ledger requires for a
// single-message assumption.
const fheRingLweComparisons = (
    ledger: ReturnType<typeof compileClearPreparationLedger>,
) =>
    ledger.fheSelectedKeyComparisons +
    ledger.fheBallotComparisons * ledger.messagesPerFheBallotComparison;

const largestModulusProfiles = () => {
    const byParticipants = new Map<number, SupportedProfile>();
    for (const profile of listSupportedProfiles()) {
        const current = byParticipants.get(profile.participantCount);
        if (
            current === undefined ||
            profile.ciphertext.bits > current.ciphertext.bits
        )
            byParticipants.set(profile.participantCount, profile);
    }
    return [...byParticipants.values()].sort(
        (left, right) => left.participantCount - right.participantCount,
    );
};

// One original honest registration per participant: the smallest population
// with every member honest. A larger population H adds log2(H/n) bits.
export const compileSecurityMarginScreen = () => {
    const experimentGates = 1n << securityTargetBits;
    return largestModulusProfiles().map((profile) => {
        const honestRegistrations = BigInt(profile.participantCount);
        const ledger = compileClearPreparationLedger(
            profile,
            honestRegistrations,
        );
        const comparisons = fheRingLweComparisons(ledger);
        const modulusBits = BigInt(profile.ciphertext.bits);
        const { floor, primal, classicalPrimal } =
            fheKnownAttackFloor(modulusBits);
        const resumeFactor = firstOracleResumeFactor(profile);
        const requirements = oracleSimulationVariants.map((variant) => {
            const simulationGates = oracleSimulationGates(
                variant,
                experimentGates,
                ledger.sourceMaskScopes,
                resumeFactor,
            );
            const requiredBits = requiredFheAssumptionBits(
                comparisons,
                simulationGates,
                experimentGates,
            );
            return {
                variant,
                simulationGates,
                requiredBits,
                marginToFloor: floor.log2Cost - Number(requiredBits),
                marginToPrimal: primal.log2Cost - Number(requiredBits),
                marginToClassicalPrimal:
                    classicalPrimal.log2Cost - Number(requiredBits),
            };
        });
        return {
            participantCount: profile.participantCount,
            optionCount: profile.optionCount,
            modulusBits,
            honestRegistrations,
            selectedPositionSets: ledger.selectedPositionSets,
            sharedFheModulusGuesses: ledger.sharedFheModulusGuesses,
            sourceMaskScopes: ledger.sourceMaskScopes,
            resumeFactor,
            comparisons,
            floor,
            primal,
            classicalPrimal,
            requirements,
        };
    });
};
