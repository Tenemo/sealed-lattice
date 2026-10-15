import { describe, expect, it } from 'vitest';

import { encodeCandidateManifest } from '#packages/sdk/src/participant/worker/relay/candidate-codec.js';
import { compileCommittedOfferCensus } from '#tests/committed-offer-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { goalThresholds } from '#tests/node/protocol/reference/product-goals.js';
import { compilePreparationResources } from '#tests/preparation-resource-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

describe('preparation public resource bounds', () => {
    it.each([
        [3, 2],
        [4, 20],
        [10, 10],
        [20, 20],
    ])(
        'distinguishes the eligible corpus from certified selected work at %i/%i',
        (participants, options) => {
            const profile = deriveSupportedProfile(participants, options);
            const body = compileContributionBodyCensus(profile);
            const aggregate = compileCommittedOfferCensus(profile);
            const committedBytes =
                body.polynomialPayloadBytes -
                body.streamedPolynomialPayloadBytes;
            const wire = compileSetupSelectionWireCensus(participants);
            const result = compilePreparationResources(profile);
            const {
                maximumCorruptParticipantCount: faults,
                resultReleaseThreshold: selected,
                inventoryCertificateThreshold: quorum,
            } = goalThresholds(participants);
            const eligible = selected + faults;
            expect(result.eligibleContributorCount).toBe(eligible);
            expect(result.setupContributorCount).toBe(selected);
            expect(result.quorum).toBe(quorum);
            expect(result.maximumEligibleBodyBytes).toBe(
                BigInt(eligible) * body.maximumBodyBytes,
            );
            expect(result.maximumSelectedBodyBytes).toBe(
                BigInt(selected) * body.maximumBodyBytes,
            );
            expect(
                result.maximumEligibleOfferBytes -
                    result.maximumSelectedOfferBytes,
            ).toBe(
                BigInt(faults) *
                    (body.maximumBodyBytes +
                        wire.offerEnvelopeBytes +
                        wire.signatureBytes),
            );
            expect(result.maximumEndorsementPacketBytes).toBe(
                BigInt(participants) * (2n + 64n + 3309n),
            );
            expect(result.quorumEndorsementPacketBytes).toBe(
                BigInt(quorum) * (2n + 64n + 3309n),
            );
            expect(result.maximumGenerationAndContinuationSeeds).toBe(
                2n * BigInt(eligible),
            );
            expect(result.maximumOfferProofs).toBe(BigInt(eligible));
            expect(result.selectedProofVerificationsPerReader).toBe(
                BigInt(selected),
            );
            const signedOffer =
                body.maximumBodyBytes + wire.offerEnvelopeBytes + 3309n;
            const manifest = (files: readonly (readonly [string, bigint])[]) =>
                BigInt(
                    encodeCandidateManifest({
                        files: files.map(([name, bytes]) => ({
                            name,
                            length: Number(bytes),
                            chunks: Array.from(
                                {
                                    length: Number(
                                        (bytes + 1_048_575n) / 1_048_576n,
                                    ),
                                },
                                () => 'ab'.repeat(16),
                            ),
                        })),
                    }).length,
                );
            const offerManifest = manifest([
                ['offer.bin', wire.offerEnvelopeBytes],
                ['offer-signature.bin', 3309n],
                ['body-header.bin', body.headerBytes],
                ...body.polynomials.map(
                    (polynomial) =>
                        [
                            'polynomial-' +
                                String(polynomial.expandedIndex).padStart(
                                    2,
                                    '0',
                                ) +
                                '.bin',
                            polynomial.bytes,
                        ] as const,
                ),
                ['proof.bin', body.maximumProofBytes],
            ]);
            const selectionManifest = manifest([
                ['selection.bin', wire.selectionBodyBytes],
                ['signature.bin', 3309n],
            ]);
            const endorsementManifest = manifest([
                ['endorsement.bin', wire.endorsementPacketBytes],
            ]);
            const certificateManifest = manifest([
                ['certificate.bin', wire.certificateBytes],
            ]);
            const aggregatePublications = [
                {
                    key: 'aggregate/' + '0'.repeat(128),
                    bytes:
                        aggregate.generatedAggregateBytes +
                        aggregate.aggregateManifestBytes,
                    manifest: manifest([
                        ['manifest.bin', aggregate.aggregateManifestBytes],
                        ...aggregate.committedPolynomials.map(
                            (index) =>
                                [
                                    'polynomial-' +
                                        String(index).padStart(2, '0') +
                                        '.bin',
                                    aggregate.generatedAggregateBytes /
                                        BigInt(
                                            aggregate.committedPolynomials
                                                .length,
                                        ),
                                ] as const,
                        ),
                    ]),
                },
                ...Array.from({ length: selected }, (_, ordinal) => ({
                    key:
                        'aggregate-evaluation/' +
                        '0'.repeat(128) +
                        '/' +
                        String(ordinal),
                    bytes: aggregate.maximumEvaluationProofBytes,
                    manifest: manifest([
                        ['proof.bin', aggregate.maximumEvaluationProofBytes],
                    ]),
                })),
            ];
            const aggregateUploads = aggregatePublications.reduce(
                (sum, value) => sum + value.bytes + value.manifest,
                0n,
            );
            const aggregateStored = aggregatePublications.reduce(
                (sum, value) =>
                    sum +
                    value.bytes +
                    value.manifest +
                    BigInt(value.key.length) +
                    16n,
                0n,
            );
            const aggregateRouting = aggregatePublications.reduce(
                (sum, value) => sum + value.manifest + 28n,
                0n,
            );
            const sourceKeyBytes = BigInt(
                Buffer.byteLength(
                    'contribution-' +
                        String(eligible - 1) +
                        '/' +
                        '0'.repeat(128),
                ),
            );
            expect(result.maximumCertifiedSetupBytes).toBe(
                BigInt(selected) *
                    (signedOffer +
                        committedBytes +
                        offerManifest +
                        sourceKeyBytes +
                        16n) +
                    aggregateStored +
                    wire.certificateBytes +
                    certificateManifest +
                    BigInt('setup-certificate'.length) +
                    16n,
            );
            expect(result.maximumCleanTotalUploadBytes).toBe(
                BigInt(eligible) *
                    (signedOffer + committedBytes + offerManifest + 64n) +
                    aggregateUploads +
                    wire.selectionBodyBytes +
                    3309n +
                    selectionManifest +
                    BigInt(participants) *
                        (wire.endorsementPacketBytes +
                            wire.certificateBytes +
                            endorsementManifest +
                            certificateManifest),
            );
            expect(result.maximumMatchingCertificateActivationReadBytes).toBe(
                2n * wire.certificateBytes +
                    certificateManifest +
                    40n +
                    12n +
                    16n * BigInt(participants) +
                    BigInt(participants) * wire.endorsementPacketBytes +
                    wire.selectionBodyBytes +
                    3309n +
                    result.maximumPreparationRoutingBytes,
            );
            expect(result.extraAggregateReadPassBytes).toBe(
                aggregate.maximumAggregateBytes +
                    aggregate.aggregateManifestBytes +
                    BigInt(selected) * aggregate.maximumEvaluationProofBytes,
            );
            expect(result.volatileOfferPolynomialIdentityBytes).toBe(
                BigInt(eligible * body.polynomials.length) * 64n,
            );
            expect(result.maximumCleanPreparationDownloadBytes).toBe(
                2n * (wire.selectionBodyBytes + 3309n) +
                    BigInt(selected) *
                        (signedOffer +
                            (body.maximumProofBytes < 1_048_576n
                                ? body.maximumProofBytes
                                : 1_048_576n)) +
                    wire.certificateBytes +
                    BigInt(participants) * wire.endorsementPacketBytes +
                    result.maximumPreparationRoutingBytes +
                    result.maximumAggregateReadBytes +
                    result.readerPublicationReceivedBytes,
            );
            expect(result.maximumPreparationRoutingBytes).toBe(
                aggregateRouting +
                    BigInt(selected) * (28n + offerManifest) +
                    2n * (28n + selectionManifest) +
                    BigInt(participants) * (28n + endorsementManifest) +
                    12n +
                    16n * BigInt(participants) +
                    certificateManifest,
            );
            expect(result.maximumCleanOrganizerPreparationDownloadBytes).toBe(
                result.maximumCleanPreparationDownloadBytes +
                    2n * BigInt(selected) * committedBytes +
                    aggregate.generatedAggregateBytes -
                    aggregate.maximumAggregateBytes +
                    result.organizerPublicationReceivedBytes -
                    result.readerPublicationReceivedBytes +
                    BigInt(eligible) * (8n + 4n + 64n) +
                    result.organizerSchedule.continuationReadBytes,
            );
            expect(result.organizerDiscoveryReadBytes).toBe(
                BigInt(eligible) * (8n + 4n + 64n),
            );
            expect(result.maximumDiscoveryPageBytes).toBe(
                BigInt(
                    Buffer.concat([
                        Buffer.alloc(8),
                        Buffer.alloc(4),
                        Buffer.alloc(64 * 64),
                    ]).length,
                ),
            );
            expect(result.eligibleOfferDiscoveryUploadBytes).toBe(
                BigInt(eligible) * 64n,
            );
            expect(result.cleanParticipantPolynomialReadFloorBytes).toBe(
                BigInt(selected) * body.streamedPolynomialPayloadBytes +
                    aggregate.generatedAggregateBytes,
            );
            expect(result.cleanOrganizerPolynomialReadFloorBytes).toBe(
                BigInt(selected) * body.streamedPolynomialPayloadBytes +
                    2n * BigInt(selected) * committedBytes +
                    2n * aggregate.generatedAggregateBytes,
            );
            expect(result.completeEligiblePolynomialUploadFloorBytes).toBe(
                BigInt(eligible) * body.polynomialPayloadBytes,
            );
            expect(result.planningVarianceCeilingBytes).toBe(3n * 1024n ** 3n);
        },
    );
});
