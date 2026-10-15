import { describe, expect, it } from 'vitest';

import { compileCommittedOfferCensus } from '#tests/committed-offer-model.js';
import { fixedModulusBfvInputs } from '#tests/fixed-modulus-bfv-model.js';
import { goalThresholds } from '#tests/node/protocol/reference/product-goals.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import {
    compileSetupAggregateResources,
    partitionAggregatePolynomial,
    setupAggregateChunkBytes,
} from '#tests/setup-aggregate-resource-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('setup aggregate cache resources', () => {
    it('matches an independent count of key and encrypted-share components', () => {
        const profile = completionProfile();
        const value = compileSetupAggregateResources(profile);
        const committed = compileCommittedOfferCensus(profile);
        const parameters = fixedModulusBfvInputs;
        const participantCount = BigInt(profile.participantCount);
        const recipient = compileRecipientKeyCensus();
        const gadgetCount = BigInt(
            Math.ceil(
                profile.ciphertext.modulus.toString(2).length /
                    (parameters.gadgetBase.toString(2).length - 1),
            ),
        );
        const fheWidth =
            1n +
            BigInt(
                Math.ceil(profile.ciphertext.modulus.toString(2).length / 8),
            );
        const expected =
            4n * gadgetCount * parameters.polynomialDegree * fheWidth +
            2n * participantCount * recipient.publicKeyBytes;
        expect(value.aggregateBytes).toBe(expected);
        expect(value.coefficients).toBe(
            (4n * gadgetCount + 2n * participantCount) *
                parameters.polynomialDegree,
        );
        const maximumReplacement = [fheWidth, 21n]
            .map((width) => (524288n / width) * width)
            .reduce((maximum, bytes) => (bytes > maximum ? bytes : maximum));
        expect(value.maximumReplacementChunkBytes).toBe(maximumReplacement);
        expect(value.maximumLogicalCachePayloadBytes).toBe(
            expected + maximumReplacement,
        );
        // Every recipient's share sums the certified selection's d entries,
        // with d the release threshold.
        const setupContributorCount = BigInt(
            goalThresholds(profile.participantCount).resultReleaseThreshold,
        );
        const streamed =
            parameters.polynomialDegree * fheWidth +
            2n * participantCount * recipient.publicKeyBytes;
        expect(value.contributionReadBytes).toBe(
            setupContributorCount * streamed + committed.maximumAggregateBytes,
        );
        expect(value.previousCacheReadBytes + value.completeReadbackBytes).toBe(
            (setupContributorCount - 1n) * streamed + expected,
        );
        expect(value.provisionalCacheWriteBytes).toBe(
            setupContributorCount * streamed + expected - streamed,
        );
        expect(value.collectionPhases.collection).toBe(
            2n * (committed.generatedAggregateBytes + streamed) + expected,
        );
        expect(value.maximumCollectionPayloadBytes).toBeGreaterThan(
            value.collectionPhases.collection,
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
