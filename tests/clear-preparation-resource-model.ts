import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

// Public setup components for one fixed roster. These are maximum bytes,
// not measured traffic or simultaneous residency. Registration and local
// journal custody have their own owners; invalid/repeated traffic is unbounded.
export const compileClearPreparationResources = (profile: SupportedProfile) => {
    const body = compileContributionBodyCensus(profile);
    const wire = compileSetupSelectionWireCensus(profile.participantCount);
    const eligible = BigInt(wire.eligibleCount);
    const selected = BigInt(wire.selectedCount);
    const participants = BigInt(profile.participantCount);
    const signedOfferBytes = wire.offerEnvelopeBytes + wire.signatureBytes;
    const selectionProposalBytes =
        wire.selectionBodyBytes + wire.signatureBytes;
    const maximumSelectedOfferBytes =
        selected * (body.maximumBodyBytes + signedOfferBytes);
    const selectedPolynomialRereadBytes =
        selected * body.polynomialPayloadBytes;
    const selectedProofLookaheadBytes = selected * body.minimumProofBytes;
    const maximumOfferVerificationReadBytes =
        maximumSelectedOfferBytes + selectedProofLookaheadBytes;
    const maximumCertificateAssemblyReadBytes =
        participants * wire.endorsementPacketBytes;
    const maximumCleanPreparationDownloadBytes =
        selectionProposalBytes +
        maximumOfferVerificationReadBytes +
        2n * wire.certificateBytes +
        64n +
        maximumCertificateAssemblyReadBytes;
    // Selection and endorsement share a worker's complete verified holders.
    // Discovery still verifies offers before selection, so the organizer's
    // aggregation rereads their polynomials. Fresh participants fuse that
    // polynomial read with full offer verification and aggregation.
    // An honest author announces one ID. A bounded hint page adds its
    // untrusted u64 total and u32 count; corrupt additions are not capped here.
    const discoveryPageHeaderBytes = 8n + 4n;
    const organizerDiscoveryReadBytes =
        eligible * (discoveryPageHeaderBytes + 64n);
    const maximumCleanOrganizerPreparationDownloadBytes =
        maximumCleanPreparationDownloadBytes +
        selectedPolynomialRereadBytes +
        organizerDiscoveryReadBytes;
    const maximumCleanParticipantUploadBytes =
        body.maximumBodyBytes +
        signedOfferBytes +
        selectionProposalBytes +
        wire.endorsementPacketBytes +
        wire.certificateBytes +
        64n +
        64n;
    const maximumCleanTotalUploadBytes =
        eligible * (body.maximumBodyBytes + signedOfferBytes + 64n) +
        selectionProposalBytes +
        participants *
            (wire.endorsementPacketBytes + wire.certificateBytes + 64n);
    const transferPlanningBytes = 2_147_483_648n;
    return {
        eligibleCount: wire.eligibleCount,
        selectedCount: wire.selectedCount,
        quorum: wire.quorum,
        maximumEligibleBodyBytes: eligible * body.maximumBodyBytes,
        maximumSelectedBodyBytes: selected * body.maximumBodyBytes,
        maximumEligibleOfferBytes:
            eligible * (body.maximumBodyBytes + signedOfferBytes),
        maximumSelectedOfferBytes,
        selectionProposalBytes,
        certificateBytes: wire.certificateBytes,
        maximumEndorsementPacketBytes:
            BigInt(profile.participantCount) * wire.endorsementPacketBytes,
        quorumEndorsementPacketBytes:
            BigInt(wire.quorum) * wire.endorsementPacketBytes,
        // All bytes that must remain public for selected contribution and
        // certificate retrieval, beside the previously published registrations.
        maximumCertifiedSetupBytes:
            maximumSelectedOfferBytes + wire.certificateBytes,
        // An eligible participant can generate and continue one proof even
        // when its offer is not selected. No author is required after publication.
        maximumGenerationAndContinuationSeeds: 2n * eligible,
        maximumOfferProofs: eligible,
        selectedProofVerificationsPerReader: selected,
        // Complete exact named reads plus owning verification establish
        // published dependencies under monotone store retention; activation
        // never forwards the selected bodies again. Matching original SPI1
        // avoids another proof pass; losing/no endorsement follows the fresh path.
        maximumOfferVerificationReadBytes,
        selectedPolynomialRereadBytes,
        selectedProofLookaheadBytes,
        // Prefix cancellation may receive one transport chunk per proof;
        // this is separately reserved, not asserted as exact network traffic.
        maximumLookaheadIngressBytes: selected * (1n << 20n),
        maximumMatchingCertificateActivationReadBytes:
            2n * wire.certificateBytes + 64n,
        maximumFreshCertificateActivationReadBytes:
            2n * wire.certificateBytes +
            64n +
            maximumOfferVerificationReadBytes,
        maximumCertificateAssemblyReadBytes,
        maximumCleanPreparationDownloadBytes,
        maximumCleanOrganizerPreparationDownloadBytes,
        organizerDiscoveryReadBytes,
        maximumDiscoveryPageBytes: discoveryPageHeaderBytes + 64n * 64n,
        eligibleOfferDiscoveryUploadBytes: eligible * 64n,
        maximumCleanParticipantUploadBytes,
        maximumCleanTotalUploadBytes,
        transferPlanningBytes,
        planningVarianceCeilingBytes: (3n * transferPlanningBytes) / 2n,
        cleanParticipantPolynomialReadFloorBytes: selectedPolynomialRereadBytes,
        cleanOrganizerPolynomialReadFloorBytes:
            2n * selectedPolynomialRereadBytes,
        completeEligiblePolynomialUploadFloorBytes:
            eligible * body.polynomialPayloadBytes,
        preparationDownloadWithinPlanning:
            maximumCleanPreparationDownloadBytes <= transferPlanningBytes,
        organizerDownloadWithinPlanning:
            maximumCleanOrganizerPreparationDownloadBytes <=
            transferPlanningBytes,
        participantUploadWithinPlanning:
            maximumCleanParticipantUploadBytes <= transferPlanningBytes,
        totalUploadWithinPlanning:
            maximumCleanTotalUploadBytes <= transferPlanningBytes,
        // Exact extra work operands for an explicit number of public cache
        // misses or restarts. They are not finite lifetime populations.
        extraFullVerificationPassBytes: maximumOfferVerificationReadBytes,
        extraAggregateReadPassBytes: selectedPolynomialRereadBytes,
        volatileOfferPolynomialIdentityBytes:
            eligible * BigInt(body.polynomials.length) * 64n,
        additionalPolynomialHashStates: 1,
    };
};
