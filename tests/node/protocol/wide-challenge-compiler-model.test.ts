import { describe, expect, it } from 'vitest';

import { proofRelationCatalogueEntry } from '#tests/proof-relation-catalogue-model.js';
import {
    completionProfile,
    listSupportedProfiles,
} from '#tests/supported-profile-model.js';
import {
    compileFamilyRoundErrorCensus,
    compileWideChallengeCompilerCensus,
    compileProofRoundErrorCensus,
    jointModuloDensityBound,
    wideChallengeLayout,
} from '#tests/wide-challenge-compiler-model.js';
import {
    catalogueWordRelation,
    productionWordProofDomain,
    wordRelationShape,
} from '#tests/word-verifier-reference-model.js';

describe('wide verifier messages and short authentication tags', () => {
    it('derives the current three source families separately before taking a round-error maximum', () => {
        const value = compileProofRoundErrorCensus(completionProfile());
        expect(
            value.roles.map((role) => [
                role.name,
                role.originalOracles,
                role.virtualOracles,
            ]),
        ).toEqual([
            ['setup', 734, 413],
            ['ballot', 68, 42],
            ['release', 133, 73],
        ]);
        for (const role of value.roles) {
            expect(role.lookupChallengeSpace).toBe(
                value.prime ** 2n * (value.prime - 1n),
            );
            expect(role.density).toEqual({
                numerator: 1n << 256n,
                denominator:
                    (1n << 256n) -
                    BigInt(
                        3 *
                            (2 * (role.originalOracles + role.virtualOracles) +
                                1),
                    ) *
                        value.prime,
            });
            expect(role.roundError).toEqual(value.queryError);
        }
    });
    it('independently checks every profile and family against the unchanged query term', () => {
        const production = productionWordProofDomain();
        for (const profile of listSupportedProfiles()) {
            const value = compileProofRoundErrorCensus(profile);
            // The operands are the catalogue relation's, whose parameter
            // bytes declare one degree per batched oracle, and the reference
            // verifier draws two weights per oracle and the first fold.
            const catalogue = proofRelationCatalogueEntry(profile);
            for (const role of value.roles) {
                const entry = catalogue.find(
                    (candidate) => candidate.role === role.name,
                );
                expect(entry).toBeDefined();
                const shape = wordRelationShape(
                    catalogueWordRelation(entry!),
                    production,
                );
                expect([
                    role.originalOracles,
                    role.originalOracles + role.virtualOracles,
                    role.lookupEntries,
                    BigInt(role.messageBytes),
                    role.baseFieldSamples,
                ]).toEqual([
                    shape.original,
                    shape.oracles,
                    shape.lookups,
                    entry!.messageBytes,
                    3 * (2 * shape.oracles + 1),
                ]);
            }
            expect(value.prime).toBeGreaterThan(1n << 127n);
            expect(value.weightedFri.ceiling).toBeLessThan(1n << 56n);
            expect(value.queryError.numerator << 302n).toBeGreaterThan(
                value.queryError.denominator,
            );
            for (const role of value.roles) {
                const oracles = role.originalOracles + role.virtualOracles;
                expect(oracles).toBeLessThan(1 << 13);
                expect(role.lookupRootDegree).toBeLessThan(1n << 27n);
                expect(role.affineRows).toBeLessThan(1n << 28n);
                expect(role.baseFieldSamples).toBeLessThan(1 << 16);
                expect(role.density.numerator).toBeLessThan(
                    2n * role.density.denominator,
                );
                // This cross-product is the actual sampled-field algebraic
                // bound, including the non-base lookup space and density.
                expect(
                    role.sampledAlgebraic.numerator *
                        value.queryError.denominator,
                ).toBeLessThan(
                    value.queryError.numerator *
                        role.sampledAlgebraic.denominator,
                );
                expect(role.queryDominates).toBe(true);
            }
            expect(
                value.roles
                    .filter((role) => role.name !== 'setup')
                    .map((role) => role.messageBytes),
            ).toEqual([262144, 262144]);
            expect(value.maximumRoundError).toEqual(value.queryError);
        }
    });
    it('bounds every effective relation of each purpose by the query term', () => {
        const family = compileFamilyRoundErrorCensus();
        expect(family.maximumRoundError).toEqual(family.queryError);
        // (193/256)^704 lies between 2^-287 and 2^-286.
        expect(family.queryError).toEqual({
            numerator: 193n ** 704n,
            denominator: 256n ** 704n,
        });
        expect((193n ** 704n) << 286n).toBeLessThanOrEqual(256n ** 704n);
        expect((193n ** 704n) << 287n).toBeGreaterThan(256n ** 704n);
        expect(family.queryErrorBits).toBe(286);
        expect(family.purposes.map((purpose) => purpose.name)).toEqual([
            'setup',
            'ballot',
            'release',
        ]);
        for (const purpose of family.purposes) {
            expect(purpose.queryDominates).toBe(true);
            const { numerator, denominator } = purpose.sampledAlgebraic;
            const query = family.queryError;
            expect(
                (numerator * query.denominator) <<
                    BigInt(purpose.queryMarginBits),
            ).toBeLessThanOrEqual(query.numerator * denominator);
            expect(
                (numerator * query.denominator) <<
                    BigInt(purpose.queryMarginBits + 1),
            ).toBeGreaterThan(query.numerator * denominator);
            expect(purpose.queryMarginBits).toBeGreaterThan(0);
        }
    });
    it('fits every independent field challenge and all query indices in one message', () => {
        expect(wideChallengeLayout(64, 32, 720)).toEqual({
            fieldElements: 129,
            baseFieldSamples: 387,
            challengeBytes: 16384,
        });
        expect(wideChallengeLayout(1172, 704, 18240)).toEqual({
            fieldElements: 2345,
            baseFieldSamples: 7035,
            challengeBytes: 262144,
        });
    });

    it('refuses count overflow instead of emitting an inexact message length', () => {
        expect(() =>
            wideChallengeLayout(Number.MAX_SAFE_INTEGER, 1, 1),
        ).toThrow('exact count');
        expect(() =>
            wideChallengeLayout(1, 1, Number.MAX_SAFE_INTEGER),
        ).toThrow('exact count');
    });

    it('bounds event probabilities multiplicatively for the complete sample vector', () => {
        const modulus = 13n,
            space = 256n;
        const counts = Array.from({ length: Number(modulus) }, () => 0n);
        for (let word = 0n; word < space; word++)
            counts[Number(word % modulus)]++;
        const bound = jointModuloDensityBound(modulus, 8, 3);
        for (const first of counts)
            for (const second of counts)
                for (const third of counts)
                    expect(
                        first *
                            second *
                            third *
                            modulus ** 3n *
                            bound.denominator,
                    ).toBeLessThanOrEqual(space ** 3n * bound.numerator);
        expect(() => jointModuloDensityBound(modulus, 8, 20)).toThrow(
            'vacuous',
        );
    });

    it('charges prefix collisions even when complete oracle outputs differ', () => {
        let completeCollisions = 0,
            prefixCollisions = 0;
        for (let first = 0; first < 256; first++)
            for (let second = 0; second < 256; second++) {
                completeCollisions += Number(first === second);
                prefixCollisions += Number(first >>> 6 === second >>> 6);
            }
        expect(completeCollisions).toBe(256);
        expect(prefixCollisions).toBe(256 ** 2 / 4);
    });

    it('charges routing, verification, and role unions in the conditional compiler bound', () => {
        const census = compileWideChallengeCompilerCensus(completionProfile());
        expect(census.chargedQueries).toBe(4n * (1n << 80n));
        expect(census.roleBudget).toBe(65536n);
        expect(census.honestProofBudget).toBe(1n << 28n);
        expect(census.saltBits).toBe(2n * census.tagBits);
        // 2 * 2^28 honest proofs * 2^23 nodes over 2^160.
        expect(census.merklePrivacyBits).toBe(108);
        // One programmed message per honest proof: sqrt(9 * 2^56 * 2^82 /
        // 2^513) lies between 2^-186 and 2^-185.
        expect(census.programmedMessageBudget).toBe(census.honestProofBudget);
        expect(census.reprogrammingBits).toBe(185);
        expect(census.failureBits).toBeGreaterThanOrEqual(80);
        expect(
            census.failureNumerator << BigInt(census.failureBits),
        ).toBeLessThanOrEqual(census.failureDenominator);
        expect(
            census.failureNumerator << BigInt(census.failureBits + 1),
        ).toBeGreaterThan(census.failureDenominator);
    });
});
