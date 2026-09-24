import {
    compileCurrentSignatureHashInputs,
    compileCurrentSignatureSamplingBounds,
    compileSignatureCounterBoundary,
} from '#tests/authentication-work-model.js';
import { mlDsa65Parameters } from '#tests/ml-dsa-theorem-screen-model.js';
import { rejectionSubsetBound } from '#tests/proof-randomness-budget-model.js';

// Fresh output-prefix programming invalidates an earlier all-input sampler
// event unless these new random prefixes are charged separately. Replays do
// not refresh a prefix. These bounds do not establish the programming game.
export const compileProgrammedSignatureSamplerBounds = () => {
    const mask = compileCurrentSignatureHashInputs().rows.find(
        (row) => row.purpose === 'Mask expansion',
    )!;
    const challenge = compileCurrentSignatureSamplingBounds().find(
        (row) => row.purpose === 'Challenge polynomial sampling',
    )!;
    if (mask.outputBytes === null)
        throw new Error('Mask expansion needs its finite output prefix.');
    return [
        {
            purpose: 'Secret sampling after a mask-family refresh',
            inputBytes: mask.inputBytes,
            prefixBytes: mask.outputBytes,
            sampleBits: 4n,
            candidatePositions: 2n * mask.outputBytes,
            requiredSuccesses: mlDsa65Parameters.polynomialDegree,
            rejectedValues:
                16n - (2n * mlDsa65Parameters.secretCoefficientBound + 1n),
            refreshedPoints: compileSignatureCounterBoundary().nonceCapacity,
        },
        {
            purpose: 'Challenge sampling after a challenge-prefix refresh',
            inputBytes: challenge.inputBytes,
            prefixBytes: challenge.outputBytes,
            sampleBits: challenge.sampleBits,
            candidatePositions: challenge.candidatePositions,
            requiredSuccesses: challenge.requiredSuccesses,
            rejectedValues: challenge.rejectedValues,
            refreshedPoints: 1n,
        },
    ].map((row) => {
        const requiredRejections =
            row.candidatePositions - row.requiredSuccesses + 1n;
        const bound = rejectionSubsetBound({
            ...row,
            requiredRejections,
            inputCount: row.refreshedPoints,
        });
        let failureExponent = 0n;
        while (
            bound.numerator << (failureExponent + 1n) <=
            1n << bound.denominatorBits
        )
            failureExponent++;
        return { ...row, requiredRejections, ...bound, failureExponent };
    });
};
