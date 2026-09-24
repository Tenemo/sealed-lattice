import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

import {
    fixedModulusBfvInputs,
    verifyProthCertificate,
} from '#tests/fixed-modulus-bfv-model.js';
import { compileReleaseShareLiftingCensus } from '#tests/release-share-lifting-model.js';
import {
    clearedReconstructionCoefficient,
    compileSupportedProfileCensus,
    deriveRankingNoise,
    deriveReleaseInterpolation,
    deriveSupportedProfile,
    interpolationRingDegree,
    largestTransformPrimeBelow,
    supportedProfileRules,
} from '#tests/supported-profile-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';
import { compileThresholdReleaseNoiseCensus } from '#tests/threshold-release-noise-model.js';
import { compileWideShareLiftingCensus } from '#tests/wide-share-lifting-model.js';

const census = compileSupportedProfileCensus();
const profiles = census.profiles.flat();

// Independent ring arithmetic in Z[X]/(X^degree+1) over the integers.
type Element = number[];
const unit = (exponent: number, degree: number): Element => {
    const result = new Array<number>(degree).fill(0);
    const reduced = ((exponent % (2 * degree)) + 2 * degree) % (2 * degree);
    result[reduced % degree] = reduced < degree ? 1 : -1;
    return result;
};
const times = (left: Element, right: Element): Element => {
    const degree = left.length;
    const result = new Array<number>(degree).fill(0);
    for (let first = 0; first < degree; first++)
        for (let second = 0; second < degree; second++) {
            const product = left[first] * right[second];
            const index = first + second;
            if (index < degree) result[index] += product;
            else result[index - degree] -= product;
        }
    return result;
};
const minus = (left: Element, right: Element): Element =>
    left.map((value, index) => value - right[index]);
const rotate = (value: Element, exponent: number): Element => {
    const degree = value.length;
    const result = new Array<number>(degree).fill(0);
    value.forEach((coefficient, index) => {
        const target =
            (((index + exponent) % (2 * degree)) + 2 * degree) % (2 * degree);
        if (target < degree) result[target] += coefficient;
        else result[target - degree] -= coefficient;
    });
    return result;
};
// value * (X^first - X^second) through two signed rotations.
const timesBinomial = (
    value: Element,
    first: number,
    second: number,
): Element => minus(rotate(value, first), rotate(value, second));
const same = (left: Element, right: Element): boolean =>
    left.every((value, index) => value === right[index]);
const norm = (value: Element): number =>
    value.reduce((sum, coefficient) => sum + Math.abs(coefficient), 0);
const combinations = (values: readonly number[], size: number): number[][] =>
    size === 0
        ? [[]]
        : values.flatMap((value, index) =>
              combinations(values.slice(index + 1), size - 1).map((rest) => [
                  value,
                  ...rest,
              ]),
          );

const bitLength = (value: bigint): number => value.toString(2).length;
const power = (base: bigint, exponent: bigint, modulus: bigint): bigint => {
    let result = 1n;
    for (let remaining = exponent; remaining > 0n; remaining >>= 1n) {
        if (remaining & 1n) result = (result * base) % modulus;
        base = (base * base) % modulus;
    }
    return result;
};

describe('supported profile parameters', () => {
    it('reproduces the independently maintained ten-participant tuple', async () => {
        const profile = deriveSupportedProfile(10, 10);
        expect(profile.ciphertext.modulus).toBe(
            fixedModulusBfvInputs.ciphertextModulus,
        );
        expect(profile.release.modulus).toBe(
            fixedModulusBfvInputs.releaseModulus,
        );
        const threshold = compileThresholdReleaseNoiseCensus();
        expect(profile.interpolation).toMatchObject({
            releaseThreshold: threshold.releaseThreshold,
            interpolationRingDegree: threshold.spacedInterpolationSize / 2,
            maximumScaledReconstructionOneNorm:
                threshold.exactMaximumScaledReconstructionCoefficientOneNorm,
            maximumSimulationOneNorm:
                threshold.exactMaximumSimulationCoefficientOneNorm,
            maximumJointSimulationOneNormSum:
                threshold.exactMaximumJointSimulationCoefficientOneNormSum,
        });
        // The Rust witnesses fix the ten-participant radices and share range.
        const convolution = await readFile(
            'crates/protocol-research/setup-witness/src/convolution.rs',
            'utf8',
        );
        expect(convolution).toContain(
            `pub const RADIX_BITS: usize = ${profile.shareLifting.limbBits};`,
        );
        const release = await readFile(
            'crates/protocol-research/linked-release-proof/src/witness.rs',
            'utf8',
        );
        expect(release).toContain('let release_radix = 1i128 << 48;');
        expect(release).toContain(
            `share < -(BigInt::from(1) << ${profile.releaseLifting.shareBits - 1}usize)`,
        );
    });

    it('derives degree-one sharing and two-share release for three participants', () => {
        const profile = deriveSupportedProfile(3, 2);
        expect(profile.maximumCorruptParticipantCount).toBe(0);
        expect(profile.releaseThreshold).toBe(2);
        expect(profile.shareLifting.sharingDegree).toBe(1);
        expect(profile.releaseLifting.clearingFactor).toBe(2n);
        expect(
            compileWideShareLiftingCensus(profile.shareLifting),
        ).toMatchObject({ sharingDegree: 1, checkedEquations: 32 * 8 * 2 });
    });

    it('verifies every cleared Lagrange coefficient and recomputes each interpolation norm', () => {
        const failedIdentities: string[] = [];
        for (const participantCount of census.participantCounts) {
            const { resultReleaseThreshold: threshold } =
                compileThresholdCompletionProfile(participantCount);
            const degree = interpolationRingDegree(participantCount);
            expect(2 * degree).toBeGreaterThanOrEqual(participantCount);
            expect(degree).toBeLessThan(participantCount);
            let clearing = 1;
            while (clearing < threshold) clearing *= 2;
            const scaledOne = unit(0, degree).map((value) => value * clearing);
            const positions = Array.from(
                { length: participantCount },
                (_unused, index) => index,
            );
            // c*lambda_i(S)*prod_{j != i} (X^a_j - X^a_i) = c*prod_{j != i} X^a_j
            // determines c*lambda_i exactly, since each factor is invertible
            // over the rationals. Translates of S share their coefficients.
            let reconstruction = 0;
            for (const rest of combinations(
                positions.slice(1),
                threshold - 1,
            )) {
                const subset = [0, ...rest];
                for (const member of subset) {
                    const coefficient = clearedReconstructionCoefficient(
                        participantCount,
                        subset,
                        member,
                    );
                    let left = [...coefficient];
                    let exponentSum = 0;
                    for (const other of subset) {
                        if (other === member) continue;
                        left = timesBinomial(left, other, member);
                        exponentSum += other;
                    }
                    if (
                        !same(
                            left,
                            unit(exponentSum, degree).map(
                                (value) => value * clearing,
                            ),
                        )
                    )
                        failedIdentities.push(
                            `${participantCount}:${subset.join(',')}:${member}`,
                        );
                    reconstruction = Math.max(
                        reconstruction,
                        norm([...coefficient]),
                    );
                }
            }
            // A fixed set C and an honest h use 1/lambda_h(C+{h}), whose
            // product with the verified coefficient must equal c.
            const simulationNorms = new Map<string, number>();
            let simulation = 0,
                joint = 0;
            for (const fixedSet of combinations(positions, threshold - 1)) {
                let sum = 0;
                for (const honest of positions) {
                    if (fixedSet.includes(honest)) continue;
                    const key = fixedSet
                        .map(
                            (position) =>
                                (((honest - position) % (2 * degree)) +
                                    2 * degree) %
                                (2 * degree),
                        )
                        .sort((left, right) => left - right)
                        .join(',');
                    let value = simulationNorms.get(key);
                    if (value === undefined) {
                        const inverse = fixedSet.reduce(
                            (product, position) =>
                                timesBinomial(product, 0, honest - position),
                            unit(0, degree),
                        );
                        const subset = [...fixedSet, honest].sort(
                            (left, right) => left - right,
                        );
                        const product = times(inverse, [
                            ...clearedReconstructionCoefficient(
                                participantCount,
                                subset,
                                honest,
                            ),
                        ]);
                        if (!same(product, scaledOne))
                            failedIdentities.push(
                                `${participantCount}:${subset.join(',')}:${honest}`,
                            );
                        value = norm(inverse);
                        simulationNorms.set(key, value);
                    }
                    simulation = Math.max(simulation, value);
                    sum += value;
                }
                joint = Math.max(joint, sum);
            }
            expect(deriveReleaseInterpolation(participantCount)).toMatchObject({
                releaseThreshold: threshold,
                clearingFactor: BigInt(clearing),
                maximumScaledReconstructionOneNorm: BigInt(reconstruction),
                maximumSimulationOneNorm: BigInt(simulation),
                maximumJointSimulationOneNormSum: BigInt(joint),
            });
        }
        expect(failedIdentities).toEqual([]);
    });

    it('certifies each selected modulus as the largest transform prime of its length', () => {
        const plaintextModulus = fixedModulusBfvInputs.plaintextModulus;
        for (const prime of [
            ...census.ciphertextModuli,
            ...census.releaseModuli,
        ]) {
            const shift =
                prime.bits - supportedProfileRules.modulusOddFactorBits;
            expect(
                verifyProthCertificate(prime.oddFactor, shift, prime.witness),
            ).toBe(prime.modulus);
            expect(bitLength(prime.modulus)).toBe(prime.bits);
            expect(prime.oddFactor % plaintextModulus).toBe(0n);
            expect(prime.oddFactor < 1n << 32n).toBe(true);
            // Every larger candidate of the same form fails base-two Fermat.
            for (
                let factor = prime.oddFactor / plaintextModulus + 2n;
                plaintextModulus * factor < 1n << 32n;
                factor += 2n
            ) {
                const candidate =
                    plaintextModulus * factor * (1n << BigInt(shift)) + 1n;
                expect(power(2n, candidate - 1n, candidate)).not.toBe(1n);
            }
        }
        expect(census.releaseModuli).toHaveLength(1);
        expect(() => largestTransformPrimeBelow(64)).toThrow();
    });

    it('keeps every ranking operation decodable and every release lifting sound', () => {
        expect(profiles).toHaveLength(18 * 19);
        for (const profile of profiles) {
            expect(profile.ciphertext.bits % 32).toBe(0);
            expect(profile.release.bits % 48).toBe(0);
            expect(profile.gadgetLength).toBe(
                BigInt(Math.ceil(profile.ciphertext.bits / 144)),
            );
            expect(
                deriveRankingNoise(
                    profile.participantCount,
                    profile.optionCount,
                    profile.ciphertext.modulus,
                ),
            ).toBeDefined();
            expect(profile.releaseLifting.holds).toBe(true);
            expect(profile.shareLifting.holds).toBe(true);
        }
    });

    it('executes the share and release limb equations of every derived layout', () => {
        for (const participantCount of census.participantCounts) {
            const { shareLifting } = deriveSupportedProfile(
                participantCount,
                2,
            );
            const executed = compileWideShareLiftingCensus(shareLifting);
            expect(executed).toMatchObject({
                limbBits: shareLifting.limbBits,
                carryBits: shareLifting.carryBits,
            });
            expect(executed.maximumObservedCarry).toBeLessThanOrEqual(
                executed.trueCarryBound,
            );
        }
        const layouts = new Map(
            profiles.map((profile) => [
                [
                    profile.releaseThreshold,
                    profile.releaseNoiseBits,
                    profile.shareLifting.aggregateSharingMaximum,
                ].join(':'),
                profile.releaseLifting,
            ]),
        );
        for (const layout of layouts.values()) {
            const executed = compileReleaseShareLiftingCensus(layout);
            expect(executed.checkedEquations).toBe(32 * 8 * layout.outputLimbs);
            expect(executed.maximumObservedCarry).toBeLessThanOrEqual(
                executed.trueCarryBound,
            );
        }
    });

    it('refuses sizes outside the product profile', () => {
        expect(() => deriveSupportedProfile(2, 10)).toThrow();
        expect(() => deriveSupportedProfile(21, 10)).toThrow();
        expect(() => deriveSupportedProfile(10, 1)).toThrow();
        expect(() => deriveSupportedProfile(10, 21)).toThrow();
        expect(() => deriveSupportedProfile(10, 2.5)).toThrow();
    });
});
