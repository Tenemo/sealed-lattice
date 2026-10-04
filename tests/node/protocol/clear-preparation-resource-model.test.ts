import { describe, expect, it } from 'vitest';

import { compileClearPreparationResources } from '#tests/clear-preparation-resource-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import { deriveSupportedProfile } from '#tests/supported-profile-model.js';

describe('clear preparation public resource bounds', () => {
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
            const wire = compileSetupSelectionWireCensus(participants);
            const result = compileClearPreparationResources(profile);
            const faults = Math.floor((participants - 1) / 3);
            const selected = Math.max(faults + 1, 2);
            const eligible = selected + faults;
            const quorum = participants - faults;
            expect(result.eligibleCount).toBe(eligible);
            expect(result.selectedCount).toBe(selected);
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
            expect(result.maximumCertifiedSetupBytes).toBe(
                result.maximumSelectedOfferBytes + wire.certificateBytes,
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
            expect(result.maximumCleanTotalUploadBytes).toBe(
                BigInt(eligible) * (signedOffer + 64n) +
                    wire.selectionBodyBytes +
                    3309n +
                    BigInt(participants) *
                        (wire.endorsementPacketBytes +
                            wire.certificateBytes +
                            64n),
            );
            expect(result.maximumMatchingCertificateActivationReadBytes).toBe(
                2n * wire.certificateBytes + 64n,
            );
            expect(result.extraAggregateReadPassBytes).toBe(
                BigInt(selected) * body.polynomialPayloadBytes,
            );
            expect(result.volatileOfferPolynomialIdentityBytes).toBe(
                BigInt(eligible * body.polynomials.length) * 64n,
            );
            expect(result.maximumCleanPreparationDownloadBytes).toBe(
                wire.selectionBodyBytes +
                    3309n +
                    BigInt(selected) *
                        (signedOffer +
                            body.minimumProofBytes +
                            body.polynomialPayloadBytes) +
                    2n * wire.certificateBytes +
                    64n +
                    BigInt(participants) * wire.endorsementPacketBytes,
            );
            expect(result.maximumCleanOrganizerPreparationDownloadBytes).toBe(
                result.maximumCleanPreparationDownloadBytes +
                    result.maximumOfferVerificationReadBytes +
                    BigInt(eligible) * (8n + 4n + 64n),
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
                2n * BigInt(selected) * body.polynomialPayloadBytes,
            );
            expect(result.cleanOrganizerPolynomialReadFloorBytes).toBe(
                3n * BigInt(selected) * body.polynomialPayloadBytes,
            );
            expect(result.completeEligiblePolynomialUploadFloorBytes).toBe(
                BigInt(eligible) * body.polynomialPayloadBytes,
            );
            expect(result.planningVarianceCeilingBytes).toBe(3n * 1024n ** 3n);
        },
    );
});
