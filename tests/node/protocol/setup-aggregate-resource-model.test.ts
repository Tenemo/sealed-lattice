import { describe, expect, it } from 'vitest';

import { auxiliaryInputEncryptionParameters } from '#tests/auxiliary-input-encryption-parameters.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
import {
    compileSetupAggregateResources,
    partitionAggregatePolynomial,
    setupAggregateChunkBytes,
} from '#tests/setup-aggregate-resource-model.js';

describe('setup aggregate cache resources', () => {
    it('matches an independent count of key and encrypted-share components', () => {
        const value = compileSetupAggregateResources();
        const parameters = fixedModulusBfvInputs;
        const recipient = compileRegistrationKeyRelationCensus();
        const gadgetCount = BigInt(
            Math.ceil(
                parameters.ciphertextModulus.toString(2).length /
                    (parameters.gadgetBase.toString(2).length - 1),
            ),
        );
        const fheWidth =
            1n +
            BigInt(
                Math.ceil(parameters.ciphertextModulus.toString(2).length / 8),
            );
        const auxiliaryWidth =
            1n +
            BigInt(
                Math.ceil(
                    auxiliaryInputEncryptionParameters.modulus.toString(2)
                        .length / 8,
                ),
            );
        const expected =
            4n * gadgetCount * parameters.polynomialDegree * fheWidth +
            2n * parameters.participantCount * recipient.publicKeyBytes +
            auxiliaryInputEncryptionParameters.degree * auxiliaryWidth;
        expect(value.aggregateBytes).toBe(expected);
        expect(value.coefficients).toBe(
            (4n * gadgetCount + 2n * parameters.participantCount) *
                parameters.polynomialDegree +
                auxiliaryInputEncryptionParameters.degree,
        );
        expect(value.maximumTwoGenerationPayloadBytes).toBe(2n * expected);
        expect(value.previousCacheReadBytes + value.completeReadbackBytes).toBe(
            value.contributionReadBytes,
        );
        expect(value.provisionalCacheWriteBytes).toBe(
            value.contributionReadBytes,
        );
    });

    it('partitions exact multiples and final partial chunks without splitting coefficients', () => {
        for (const width of [1n, 6n, 21n, 109n, setupAggregateChunkBytes]) {
            const capacity = setupAggregateChunkBytes / width;
            for (const degree of [1n, capacity, capacity + 1n, 2n * capacity]) {
                const value = partitionAggregatePolynomial(degree, width);
                expect(value.chunkBytes).toBeLessThanOrEqual(
                    setupAggregateChunkBytes,
                );
                expect(value.finalChunkBytes).toBeGreaterThan(0n);
                expect(value.finalChunkBytes).toBeLessThanOrEqual(
                    value.chunkBytes,
                );
                expect(
                    (value.chunks - 1n) * value.chunkBytes +
                        value.finalChunkBytes,
                ).toBe(degree * width);
                expect(value.chunkBytes % width).toBe(0n);
                expect(value.finalChunkBytes % width).toBe(0n);
            }
        }
        expect(() => partitionAggregatePolynomial(0n, 1n)).toThrow('shape');
        expect(() => partitionAggregatePolynomial(1n, 0n)).toThrow('shape');
        expect(() =>
            partitionAggregatePolynomial(1n, setupAggregateChunkBytes + 1n),
        ).toThrow('shape');
    });
});
