import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';

export const setupAggregateChunkBytes = 524_288n;

export const partitionAggregatePolynomial = (
    degree: bigint,
    coefficientBytes: bigint,
) => {
    if (
        degree <= 0n ||
        coefficientBytes <= 0n ||
        coefficientBytes > setupAggregateChunkBytes
    )
        throw new RangeError('Invalid aggregate polynomial shape.');
    const chunkCoefficients = setupAggregateChunkBytes / coefficientBytes;
    const chunks = (degree + chunkCoefficients - 1n) / chunkCoefficients;
    const finalCoefficients = degree - (chunks - 1n) * chunkCoefficients;
    return {
        bytes: degree * coefficientBytes,
        chunks,
        chunkBytes: chunkCoefficients * coefficientBytes,
        finalChunkBytes: finalCoefficients * coefficientBytes,
    };
};

export const compileSetupAggregateResources = () => {
    const body = compileContributionBodyCensus();
    const recipient = compileRegistrationKeyRelationCensus();
    const parameters = fixedModulusBfvInputs;
    let gadgetCount = 0;
    for (
        let value = 1n;
        value < parameters.ciphertextModulus;
        value *= parameters.gadgetBase
    )
        gadgetCount++;
    const fheEnd = 7 * gadgetCount;
    const auxiliaryIndex = fheEnd + 3 * body.participantCount + 2;
    const coefficientBytes = (modulus: bigint) =>
        1n + BigInt(Math.ceil(modulus.toString(2).length / 8));
    const polynomials = body.polynomials.map(({ expandedIndex, bytes }) => {
        const degree =
            expandedIndex === auxiliaryIndex
                ? auxiliaryInputEncryptionParameters.degree
                : parameters.polynomialDegree;
        const width =
            expandedIndex < fheEnd
                ? coefficientBytes(parameters.ciphertextModulus)
                : expandedIndex === auxiliaryIndex
                  ? coefficientBytes(auxiliaryInputEncryptionParameters.modulus)
                  : recipient.publicKeyBytes / degree;
        const partition = partitionAggregatePolynomial(degree, width);
        if (partition.bytes !== bytes)
            throw new Error('Aggregate and contribution encodings disagree.');
        return {
            index: expandedIndex,
            degree,
            coefficientBytes: width,
            ...partition,
        };
    });
    const aggregateBytes = polynomials.reduce(
        (sum, polynomial) => sum + polynomial.bytes,
        0n,
    );
    const participantCount = BigInt(body.participantCount);
    return {
        polynomials,
        aggregateBytes,
        coefficients: polynomials.reduce(
            (sum, polynomial) => sum + polynomial.degree,
            0n,
        ),
        cacheChunks: polynomials.reduce(
            (sum, polynomial) => sum + polynomial.chunks,
            0n,
        ),
        maximumReadBytes: setupAggregateChunkBytes,
        maximumPolynomialBytes: polynomials.reduce(
            (maximum, polynomial) =>
                polynomial.bytes > maximum ? polynomial.bytes : maximum,
            0n,
        ),
        maximumTwoGenerationPayloadBytes: 2n * aggregateBytes,
        contributionReadBytes: participantCount * aggregateBytes,
        previousCacheReadBytes: (participantCount - 1n) * aggregateBytes,
        provisionalCacheWriteBytes: participantCount * aggregateBytes,
        completeReadbackBytes: aggregateBytes,
    };
};
