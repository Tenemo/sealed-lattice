// Scalar counterexample to a simulator chronology, not a threshold-FHE
// implementation. KLLPS26 Figure 2 uses the actual ciphertext plaintext;
// substituting another plaintext changes the fixed-witness proof residual.
const ciphertextModulus = 65_537n;
const plaintextModulus = 17n;
const encodingScale =
    (ciphertextModulus + plaintextModulus / 2n) / plaintextModulus;
const secret = 7n;
const ciphertextLinearTerm = 23n;
const evaluationError = 3n;
const floodingRadius = 8n;
const releaseRadius = floodingRadius + evaluationError;

const modulo = (value: bigint): bigint =>
    ((value % ciphertextModulus) + ciphertextModulus) % ciphertextModulus;
const center = (value: bigint): bigint => {
    const residue = modulo(value);
    return residue > ciphertextModulus / 2n
        ? residue - ciphertextModulus
        : residue;
};
const share = (point: bigint): bigint =>
    secret + 2n * point - point * point + 3n * point ** 3n;

export const fixedWitnessReleaseSimulation = (
    encryptedOutput: 0 | 1,
    requestedOutput: 0 | 1,
    noise: bigint,
): Readonly<{
    apparentNoise: bigint;
    decodedOutput: bigint;
    releaseRadius: bigint;
}> => {
    if (noise < -floodingRadius || noise > floodingRadius) {
        throw new RangeError(
            'The example flooding noise is outside its support.',
        );
    }
    const ciphertextConstant = modulo(
        encodingScale * BigInt(encryptedOutput) +
            evaluationError -
            ciphertextLinearTerm * secret,
    );
    // Interpolation from secret point 0 and corrupt points 1,2,3 to holder 4
    // has coefficients (-1,4,-6,4), obtained independently from the cubic.
    const corruptShareTerm =
        ciphertextLinearTerm *
        (4n * share(1n) - 6n * share(2n) + 4n * share(3n));
    const simulatedShare = modulo(
        -(encodingScale * BigInt(requestedOutput) - ciphertextConstant) +
            corruptShareTerm +
            noise,
    );
    const apparentNoise = center(
        simulatedShare - ciphertextLinearTerm * share(4n),
    );
    // Reconstruction at zero from points 1,2,3,4 has weights (4,-6,4,-1).
    const phase = modulo(
        ciphertextConstant + corruptShareTerm - simulatedShare,
    );
    const decodedOutput =
        ((phase * plaintextModulus + ciphertextModulus / 2n) /
            ciphertextModulus) %
        plaintextModulus;
    return { apparentNoise, decodedOutput, releaseRadius };
};

export const compileFixedWitnessReleaseSimulationCensus = (): Readonly<{
    changedPlaintextNoiseChecksRefused: number;
    samePlaintextNoiseChecksPassed: number;
}> => {
    let changedPlaintextNoiseChecksRefused = 0;
    let samePlaintextNoiseChecksPassed = 0;
    for (const encrypted of [0, 1] as const) {
        for (const requested of [0, 1] as const) {
            for (
                let noise = -floodingRadius;
                noise <= floodingRadius;
                noise += 1n
            ) {
                const result = fixedWitnessReleaseSimulation(
                    encrypted,
                    requested,
                    noise,
                );
                if (result.decodedOutput !== BigInt(requested))
                    throw new Error('The simulated scalar output differs.');
                const withinBound =
                    result.apparentNoise >= -releaseRadius &&
                    result.apparentNoise <= releaseRadius;
                if (encrypted === requested && withinBound)
                    samePlaintextNoiseChecksPassed += 1;
                else if (encrypted !== requested && !withinBound)
                    changedPlaintextNoiseChecksRefused += 1;
                else
                    throw new Error(
                        'The fixed-witness counterexample changed.',
                    );
            }
        }
    }
    return {
        changedPlaintextNoiseChecksRefused,
        samePlaintextNoiseChecksPassed,
    };
};
