import assert from 'node:assert/strict';

import { type AttackScreen } from '#tests/security-margin/attack-screens.js';
import { compileReductionConstructorPrice } from '#tests/security-margin/constructor-price.js';

export const securityTargetBits = 128n;
export const minimumReductionWork = 1n << 29n;
export const maximumExperimentGates = (1n << securityTargetBits) - 1n;
const reductionMetadataBits = 384n;
export const constructionPopulation = 20n;
const latticeBudgetDenominator = 32n;

const ceilingDivide = (value: bigint, divisor: bigint) => {
    assert.ok(value >= 0n && divisor > 0n);
    return (value + divisor - 1n) / divisor;
};

const ceilingLog2 = (numerator: bigint, denominator = 1n): bigint => {
    assert.ok(numerator > 0n && denominator > 0n);
    let exponent = BigInt(
        numerator.toString(2).length - denominator.toString(2).length,
    );
    const covers = (value: bigint) =>
        value >= 0n
            ? numerator <= denominator << value
            : numerator << -value <= denominator;
    while (!covers(exponent)) exponent++;
    while (covers(exponent - 1n)) exponent--;
    return exponent;
};

// Independently maintained upper bounds for the complete constructed
// reduction at its reference population. Each includes initialization,
// literal instruction control, bit traffic and its declared hash routing.
// The proof owner derives them from the bounded constructors. They are
// deliberately rounded component bounds, not measured participant work.
export const fixedReductionComponentBounds = {
    caller: 1n << 83n,
    commonInitialization: 1n << 78n,
    authentication: 1n << 84n,
    statements: 1n << 91n,
    statementRouting: 1n << 95n,
    descriptors: 1n << 93n,
    descriptorRouting: 1n << 101n,
    earlySourceRecovery: 1n << 79n,
    recoveryArithmeticConstruction: 1n << 78n,
    firstPrescribedReleases: 1n << 87n,
    publicColumnTrees: 1n << 97n,
} as const;

export const slopeReductionComponentBounds = {
    caller: 1n << 72n,
    carriedHash: 1n << 54n,
    alternativeRecovery: 1n << 56n,
    masks: 1n << 27n,
} as const;

const fixedBase = Object.values(fixedReductionComponentBounds).reduce(
    (sum, value) => sum + value,
    0n,
);
const slopeBase = Object.values(slopeReductionComponentBounds).reduce(
    (sum, value) => sum + value,
    0n,
);

// Fixed origins include three public-column passes per original setup.
// Original query traffic remains charged separately at its exact slope.
const fixedQueryOriginBound = 1n << 29n;
const originalMemoryBound = 1n << 175n;
export const originalQueryDivisor = 38400n;

const constructedBase = compileReductionConstructorPrice(
    constructionPopulation,
);
for (const [component, work] of Object.entries(constructedBase.fixed))
    assert.ok(
        work <=
            fixedReductionComponentBounds[
                component as keyof typeof fixedReductionComponentBounds
            ],
        `The ${component} construction exceeds its fixed work bound.`,
    );
for (const [component, slope] of Object.entries(constructedBase.slope))
    assert.ok(
        slope <=
            slopeReductionComponentBounds[
                component as keyof typeof slopeReductionComponentBounds
            ],
        `The ${component} construction exceeds its original-work multiplier.`,
    );
assert.ok(constructedBase.fixedExternalQueries <= fixedQueryOriginBound);
assert.ok(constructedBase.originalMemory <= originalMemoryBound);

export const compileReductionWork = (honestRegistrations: bigint) => {
    assert.ok(honestRegistrations > 0n);
    const population =
        honestRegistrations < constructionPopulation
            ? constructionPopulation
            : honestRegistrations;
    const roundingReserve =
        honestRegistrations > constructionPopulation ? 2n : 1n;
    // The nonnegative component polynomials have degrees at most three,
    // two and one respectively. A path has at most one variable ceiling.
    const fixedWork =
        roundingReserve *
        ceilingDivide(
            fixedBase * population ** 3n,
            constructionPopulation ** 3n,
        );
    const workSlope =
        roundingReserve *
        ceilingDivide(
            slopeBase * population ** 2n,
            constructionPopulation ** 2n,
        );
    const fixedExternalQueries = ceilingDivide(
        fixedQueryOriginBound * population,
        constructionPopulation,
    );
    const originalMemory = ceilingDivide(
        originalMemoryBound * population,
        constructionPopulation,
    );
    const maximumOwnedBits =
        originalMemory +
        fixedWork +
        workSlope * maximumExperimentGates +
        2n * maximumExperimentGates;
    return {
        honestRegistrations,
        fixedWork,
        workSlope,
        fixedExternalQueries,
        originalMemory,
        maximumOwnedBits,
        uniformLateSlope:
            workSlope + ceilingDivide(fixedWork, minimumReductionWork),
    };
};

export const reductionMetadataFits = (honestRegistrations: bigint) =>
    compileReductionWork(honestRegistrations).maximumOwnedBits <
    1n << reductionMetadataBits;

let metadataLimit: bigint | undefined;
export const reductionPopulationLimit = () => {
    if (metadataLimit !== undefined) return metadataLimit;
    let upper = 1n;
    while (reductionMetadataFits(upper)) upper *= 2n;
    let lower = upper / 2n;
    while (lower + 1n < upper) {
        const middle = (lower + upper) / 2n;
        if (reductionMetadataFits(middle)) lower = middle;
        else upper = middle;
    }
    metadataLimit = lower;
    return lower;
};

export const supportedLevelBits = (floor: AttackScreen) => {
    assert.ok(Number.isFinite(floor.log2Cost));
    return BigInt(Math.floor(floor.log2Cost));
};

export const requiredAssumptionBits = (
    comparisons: bigint,
    honestRegistrations: bigint,
) => {
    assert.ok(comparisons > 0n);
    const { uniformLateSlope } = compileReductionWork(honestRegistrations);
    return ceilingLog2(
        latticeBudgetDenominator *
            (1n << securityTargetBits) *
            comparisons *
            uniformLateSlope,
    );
};
