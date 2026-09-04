import { describe, expect, it } from 'vitest';

import {
    compileFixedWitnessReleaseSimulationCensus,
    fixedWitnessReleaseSimulation,
} from '#tests/fixed-witness-release-simulation-model.js';

describe('fixed-witness release simulation', () => {
    it('admits the true-plaintext shift and refuses the changed-plaintext shift across the support', () => {
        expect(compileFixedWitnessReleaseSimulationCensus()).toEqual({
            changedPlaintextNoiseChecksRefused: 34,
            samePlaintextNoiseChecksPassed: 34,
        });
    });

    it('separates decoding an ideal output from satisfying the fixed setup relation', () => {
        const actual = fixedWitnessReleaseSimulation(0, 0, 0n);
        expect(actual.decodedOutput).toBe(0n);
        expect(actual.apparentNoise).toBe(3n);
        const changed = fixedWitnessReleaseSimulation(0, 1, 0n);
        expect(changed.decodedOutput).toBe(1n);
        expect(changed.apparentNoise).toBe(3n - 3_855n);
        expect(changed.apparentNoise).toBeLessThan(-changed.releaseRadius);
        expect(() => fixedWitnessReleaseSimulation(0, 0, 9n)).toThrow(
            RangeError,
        );
        expect(() => fixedWitnessReleaseSimulation(0, 0, -9n)).toThrow(
            RangeError,
        );
    });
});
