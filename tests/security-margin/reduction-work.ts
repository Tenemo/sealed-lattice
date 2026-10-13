import assert from 'node:assert/strict';

import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import {
    compileClassicalReaderOracleBudget,
    compileFullCircuitOracleBudget,
    compileSourceDomainOracleBudget,
    shakePermutationGateCharge,
} from '#tests/oracle-budget-model.js';
import { compilePreparationLedger } from '#tests/preparation-ledger-model.js';
import {
    firstOracleResumeHashWork,
    proofHashProfiles,
} from '#tests/proof-hash-work-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import { registrationSourceMask } from '#tests/registration-source-domain-model.js';
import { compileRegistrationSourceExtractionWork } from '#tests/registration-source-randomness-model.js';
import { type AttackScreen } from '#tests/security-margin/attack-screens.js';
import {
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

export const firstOracleResumeFactor = (profile: SupportedProfile) => {
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
type ReductionOperands = Readonly<{
    participantCount: number;
    optionCount: number;
    sourceMaskScopes: bigint;
    honestProofScopes: bigint;
    corruptSourceExtractions: bigint;
    sourceCacheGates: bigint;
    resumeFactor: bigint;
}>;

export const reductionOperands = (
    profile: SupportedProfile,
    ledger: ReturnType<typeof compilePreparationLedger>,
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
