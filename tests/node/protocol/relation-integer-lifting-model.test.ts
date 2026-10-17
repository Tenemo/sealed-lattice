import { describe, expect, it } from 'vitest';

import { compileBallotEncryptionRelationCensus } from '#tests/ballot-encryption-relation-model.js';
import { compileLinkedReleaseRelationCensus } from '#tests/linked-release-relation-model.js';
import {
    compileRelationIntegerLiftingCensus,
    integerLiftingResidualBound,
    relationIntegerLiftingFamilies,
    type IntegerLiftingFamily,
} from '#tests/relation-integer-lifting-model.js';
import { createSetupContributionRelationModel } from '#tests/setup-contribution-relation-model.js';
import {
    compileSetupEquation,
    type Equation,
} from '#tests/setup-relation/equations.js';
import { compileSmallLimbProofFieldCensus } from '#tests/small-limb-proof-field-model.js';
import {
    deriveSupportedProfile,
    listSupportedProfiles,
} from '#tests/supported-profile-model.js';

const proofField = compileSmallLimbProofFieldCensus().modulus;
const bound = (
    families: readonly IntegerLiftingFamily[],
    relation: IntegerLiftingFamily['relation'],
    family: string,
) => {
    const found = families.find(
        (value) => value.relation === relation && value.family === family,
    );
    if (found === undefined) throw new Error(`No ${relation} ${family}.`);
    return integerLiftingResidualBound(found);
};

describe('relation integer lifting', () => {
    it('bounds every accepted limb row of every supported profile below the proof field', () => {
        const census = compileRelationIntegerLiftingCensus();
        expect(census.profileCount).toBe(listSupportedProfiles().length);
        expect(
            census.families.map(
                ({ relation, family }) => `${relation}/${family}`,
            ),
        ).toEqual([
            'setup/FHE key equations',
            'setup/constant share equations',
            'setup/linear share equations',
            'setup/source encryption equations',
            'setup/support sums',
            'ballot/plaintext interval equations',
            'ballot/FHE encryption equations',
            'ballot/packing equations',
            'ballot/auxiliary encryption equations',
            'ballot/support sums',
            'release/recipient-key equations',
            'release/aggregate decoding equations',
            'release/partial decryption equations',
            'release/support sums',
        ]);
        for (const family of census.families) {
            expect(family.residualBound).toBeLessThan(proofField);
            expect(family.hundredthsBelowField).toBeGreaterThan(0n);
        }
        // Independent fixed-instance operands and the signed word/error
        // ranges bound all four source components, including e + 64.
        const auxiliaryScale = 101n << 20n;
        const auxiliaryModulus = 257n * auxiliaryScale + 1n;
        const sourceBound =
            (256n + 1n) * (auxiliaryModulus / 2n) +
            127n * auxiliaryScale +
            64n +
            auxiliaryModulus * (1n << 15n);
        // The relation models that derive each profile's layout charge the
        // same terms.
        for (const profile of listSupportedProfiles()) {
            const families = relationIntegerLiftingFamilies(profile);
            const ballot = compileBallotEncryptionRelationCensus(profile);
            expect(
                bound(families, 'setup', 'source encryption equations'),
            ).toBe(sourceBound);
            expect(
                bound(families, 'ballot', 'plaintext interval equations'),
            ).toBe(2n * 65_535n + 12_288n);
            expect(bound(families, 'ballot', 'FHE encryption equations')).toBe(
                ballot.residualBound,
            );
            expect(bound(families, 'ballot', 'packing equations')).toBe(
                ballot.packingResidualBound,
            );
            expect(
                bound(families, 'ballot', 'auxiliary encryption equations'),
            ).toBe(ballot.auxiliaryResidualBound);
            expect(
                bound(families, 'release', 'aggregate decoding equations'),
            ).toBe(
                compileLinkedReleaseRelationCensus(profile)
                    .decodingResidualBound,
            );
            expect(
                bound(families, 'release', 'partial decryption equations'),
            ).toBe(profile.releaseLifting.residualBound);
            expect(bound(families, 'setup', 'constant share equations')).toBe(
                profile.shareLifting.residualBound,
            );
        }
    });

    it('dominates every executed row of the reduced setup relation over its accepted box', () => {
        for (const [participantCount, optionCount] of [
            [3, 2],
            [13, 2],
            [20, 20],
        ]) {
            const profile = deriveSupportedProfile(
                participantCount,
                optionCount,
            );
            const families = relationIntegerLiftingFamilies(profile);
            const model = createSetupContributionRelationModel(profile);
            expect(model.verify()).toBe(true);
            const rows = model.rows();
            const sourceEquations = new Set(model.sourceEquations);
            const baseEquations = model.equations.filter(
                (equation) => !sourceEquations.has(equation),
            );
            const equationFamilies = (equations: readonly Equation[]) =>
                equations.flatMap((equation) =>
                    Array.from(
                        { length: equation.limbs * equation.degree },
                        () =>
                            sourceEquations.has(equation)
                                ? 'source encryption equations'
                                : equation.name.endsWith('/constant')
                                  ? 'constant share equations'
                                  : equation.name.endsWith('/linear')
                                    ? 'linear share equations'
                                    : 'FHE key equations',
                    ),
                );
            const baseSupportRows = 2 * (model.disjointPairs.length - 1);
            const firstSourceRow =
                baseEquations.reduce(
                    (sum, equation) => sum + equation.limbs * equation.degree,
                    0,
                ) + baseSupportRows;
            const sourceRows = model.sourceEquations.flatMap((equation) =>
                compileSetupEquation(equation, model.degree),
            );
            expect(model.sourceEquations).toHaveLength(4);
            expect(sourceRows).toHaveLength(4 * model.degree);
            expect(
                rows.slice(firstSourceRow, firstSourceRow + sourceRows.length),
            ).toEqual(sourceRows);
            const familyOf = [
                ...equationFamilies(baseEquations),
                ...Array<string>(baseSupportRows).fill('support sums'),
                ...equationFamilies(model.sourceEquations),
                'support sums',
                'support sums',
            ];
            expect(familyOf).toHaveLength(rows.length);
            const largest = new Map<string, bigint>();
            rows.forEach((row, index) => {
                // Every column ranges over its whole width independently,
                // which only enlarges the sparse secrets' box.
                const factors = new Map<string, bigint>();
                for (const term of row.terms) {
                    const key = `${term.column}:${term.position}`;
                    factors.set(key, (factors.get(key) ?? 0n) + term.factor);
                }
                let high = row.constant,
                    low = row.constant;
                for (const [key, factor] of factors) {
                    const column = model.columns[Number(key.split(':')[0])];
                    const extreme = factor * ((1n << BigInt(column.bits)) - 1n);
                    if (extreme > 0n) high += extreme;
                    else low += extreme;
                }
                const magnitude = high > -low ? high : -low;
                const family = familyOf[index];
                if (magnitude > (largest.get(family) ?? 0n))
                    largest.set(family, magnitude);
            });
            expect([...largest.keys()].sort()).toEqual([
                'FHE key equations',
                'constant share equations',
                'linear share equations',
                'source encryption equations',
                'support sums',
            ]);
            for (const [family, magnitude] of largest)
                expect(magnitude).toBeLessThanOrEqual(
                    bound(families, 'setup', family),
                );
        }
    });

    it('lifts the interval over the whole word box before tightening the plaintext range', () => {
        // For every first word, the field equation determines the second.
        // A wrapped negative complement must fail the ordinary word lookup.
        for (let first = 0n; first <= 65_535n; first++) {
            const complement = (12_288n - first + proofField) % proofField;
            expect(complement <= 65_535n).toBe(first <= 12_288n);
        }
        for (let first = 0n; first <= 12_288n; first++) {
            const complement = (12_288n - first + proofField) % proofField;
            expect(first + complement).toBe(12_288n);
            const plaintext = first - 6_144n;
            expect(plaintext).toBeGreaterThanOrEqual(-6_144n);
            expect(plaintext).toBeLessThanOrEqual(6_144n);
        }
    });

    it('refuses a residual that reaches the proof field and an operand its limbs cannot expand', () => {
        const family: IntegerLiftingFamily = {
            relation: 'setup',
            family: 'FHE key equations',
            limbBits: 96,
            limbs: 2,
            terms: [{ term: 'public key digit', bound: proofField - 1n }],
            publicMagnitudes: [
                { operand: 'ciphertext modulus', magnitude: (1n << 192n) - 1n },
            ],
        };
        expect(integerLiftingResidualBound(family)).toBe(proofField - 1n);
        expect(() =>
            integerLiftingResidualBound({
                ...family,
                terms: [...family.terms, { term: 'error', bound: 1n }],
            }),
        ).toThrow('residual reaches the proof field');
        expect(() =>
            integerLiftingResidualBound({
                ...family,
                publicMagnitudes: [
                    { operand: 'ciphertext modulus', magnitude: 1n << 192n },
                ],
            }),
        ).toThrow('limbs do not expand the ciphertext modulus');
        expect(() =>
            integerLiftingResidualBound({ ...family, limbBits: undefined }),
        ).toThrow('limbs do not expand the ciphertext modulus');
    });
});
