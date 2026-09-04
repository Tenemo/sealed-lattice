import { describe, expect, it } from 'vitest';

import { compileCandidateBgvParameterCensus } from '#tests/candidate-bgv-parameter-model.js';

describe('candidate BGV parameter model', () => {
    it('derives the depth-sized modulus and release reserve from the graph', () => {
        expect(compileCandidateBgvParameterCensus()).toEqual({
            auxiliaryModulusBitLength: 120n,
            ciphertextModulusBitLength: 696n,
            ciphertextModulusLimbCount: 18n,
            combinedModulusBitLength: 816n,
            multiplicativeDepth: 14n,
            polynomialModulusDegree: 32_768n,
            retainedBottomModulusBitLength: 220n,
        });
    });
});
