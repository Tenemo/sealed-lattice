import { describe, expect, it } from 'vitest';

import {
    compileWideChallengeCompilerCensus,
    jointModuloDensityBound,
    wideChallengeLayout,
} from '#tests/wide-challenge-compiler-model.js';

describe('wide verifier messages and short authentication tags', () => {
    it('fits every independent field challenge and all query indices in one message', () => {
        expect(wideChallengeLayout(64, 32, 720)).toEqual({
            fieldElements: 129,
            baseFieldSamples: 387,
            challengeBytes: 16384,
        });
        expect(wideChallengeLayout(1177, 432, 18240)).toEqual({
            fieldElements: 2355,
            baseFieldSamples: 7065,
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
        const census = compileWideChallengeCompilerCensus();
        expect(census.chargedQueries).toBe(4n * ((1n << 80n) + (1n << 32n)));
        expect(census.roleBudget).toBe(65536n);
        expect(census.saltBits).toBe(2n * census.tagBits);
        expect(census.merklePrivacyBits).toBe(120);
        expect(census.programmedMessageBudget).toBe(32n * 65536n);
        expect(census.reprogrammingBits).toBeGreaterThanOrEqual(190);
        expect(census.failureBits).toBeGreaterThanOrEqual(80);
        expect(
            census.failureNumerator << BigInt(census.failureBits),
        ).toBeLessThanOrEqual(census.failureDenominator);
        expect(
            census.failureNumerator << BigInt(census.failureBits + 1),
        ).toBeGreaterThan(census.failureDenominator);
    });
});
