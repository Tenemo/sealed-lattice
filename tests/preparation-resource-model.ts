import { compileCandidatePublicationCensus } from '#tests/candidate-publication-model.js';
import { compileCommittedOfferCensus } from '#tests/committed-offer-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { sourceReadBytes } from '#tests/encrypted-registration-source-model.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';

const compileOrganizerCollectionSchedule = (profile: SupportedProfile) => {
    const body = compileContributionBodyCensus(profile);
    const aggregate = compileCommittedOfferCensus(profile);
    const wire = compileSetupSelectionWireCensus(profile.participantCount);
    const registration = compileRegistrationEnrollmentCensus();
    const chunk = 1n << 20n;
    const budget = ((1n << 31n) * 15n) / 16n;
    const prelude =
        registration.maximumPollDefinitionBytes +
        2n * registration.signatureBytes +
        compileRosterProposalCensus(profile.participantCount).proposalBytes +
        BigInt(profile.participantCount) *
            (registration.maximumHeaderBytes +
                compileRecipientKeyCensus().publicKeyBytes +
                registration.maximumSourceCiphertextBytes +
                registration.signatureBytes +
                2n * chunk);
    const fullOffer =
        sourceReadBytes +
        body.polynomialPayloadBytes +
        body.maximumProofBytes +
        body.headerBytes +
        wire.offerEnvelopeBytes +
        wire.signatureBytes +
        3n * chunk;
    const data = aggregate.generatedAggregateBytes + 2n * chunk;
    const evaluation =
        body.polynomialPayloadBytes -
        body.streamedPolynomialPayloadBytes +
        2n * aggregate.maximumEvaluationProofBytes +
        4n * chunk;
    const proof = aggregate.maximumEvaluationProofBytes + chunk;
    let collected = 0,
        published = false,
        completed = 0,
        finished = false,
        replayBytes = 0n;
    const calls: bigint[] = [];
    while (!finished) {
        let used = prelude;
        const before = `${collected}:${published}:${completed}`;
        while (
            collected < wire.setupContributorCount &&
            used + fullOffer <= budget
        ) {
            used += fullOffer;
            collected++;
        }
        if (collected === wire.setupContributorCount) {
            if (!published && used + data <= budget) {
                used += data;
                published = true;
            }
            if (published) {
                // Earlier public evaluation proofs are reverified on each call.
                used += BigInt(completed) * proof;
                replayBytes += BigInt(completed) * proof;
                while (
                    completed < wire.setupContributorCount &&
                    used + evaluation <= budget
                ) {
                    used += evaluation;
                    completed++;
                }
                if (
                    completed === wire.setupContributorCount &&
                    used + data <= budget
                ) {
                    used += data;
                    finished = true;
                }
            }
        }
        if (
            used > budget ||
            (!finished && before === `${collected}:${published}:${completed}`)
        )
            throw new Error(
                'A setup continuation cannot make bounded progress.',
            );
        calls.push(used);
    }
    return {
        calls,
        budget,
        prelude,
        fullOffer,
        evaluation,
        replayBytes,
        continuationReadBytes: replayBytes + BigInt(calls.length - 1) * prelude,
    };
};

// Public setup components for one fixed roster. These are maximum bytes,
// not measured traffic or simultaneous residency. Registration and local
// journal custody have their own owners; invalid/repeated traffic is unbounded.
export const compilePreparationResources = (profile: SupportedProfile) => {
    const body = compileContributionBodyCensus(profile);
    const aggregate = compileCommittedOfferCensus(profile);
    const wire = compileSetupSelectionWireCensus(profile.participantCount);
    const eligible = BigInt(wire.eligibleContributorCount);
    const selected = BigInt(wire.setupContributorCount);
    const participants = BigInt(profile.participantCount);
    const organizerSchedule = compileOrganizerCollectionSchedule(profile);
    const transport = compileCandidatePublicationCensus(
        profile,
        wire.eligibleContributorCount,
    ).preparation;
    const manifest = (prefix: string) =>
        transport.publications.find((publication) =>
            publication.key.startsWith(prefix),
        )!.manifestBytes;
    const certificatePublication = transport.publications.find(
        (publication) => publication.key === 'setup-certificate',
    )!;
    const largestStoredOffer = transport.publications
        .filter((publication) => publication.key.startsWith('contribution-'))
        .reduce(
            (largest, publication) =>
                publication.storedPayloadBytes > largest
                    ? publication.storedPayloadBytes
                    : largest,
            0n,
        );
    const signedOfferBytes = wire.offerEnvelopeBytes + wire.signatureBytes;
    const selectionProposalBytes =
        wire.selectionBodyBytes + wire.signatureBytes;
    const maximumSelectedOfferBytes =
        selected * (body.maximumBodyBytes + signedOfferBytes);
    const selectedPolynomialRereadBytes = 0n;
    const committedPolynomialBytes =
        body.polynomialPayloadBytes - body.streamedPolynomialPayloadBytes;
    const selectedCommittedPolynomialBytes =
        selected * committedPolynomialBytes;
    const maximumAggregateReadBytes =
        aggregate.maximumAggregateBytes +
        aggregate.aggregateManifestBytes +
        selected * aggregate.maximumEvaluationProofBytes;
    const generatedAggregateReadBytes =
        aggregate.generatedAggregateBytes +
        aggregate.aggregateManifestBytes +
        selected * aggregate.maximumEvaluationProofBytes;
    const aggregatePublications = transport.publications.filter(
        (publication) =>
            publication.key.startsWith('aggregate/') ||
            publication.key.startsWith('aggregate-evaluation/'),
    );
    const aggregateRoutingBytes = aggregatePublications.reduce(
        (sum, publication) => sum + 28n + publication.manifestBytes,
        0n,
    );
    const selectedProofLookaheadBytes =
        selected *
        (body.maximumProofBytes < 1_048_576n
            ? body.maximumProofBytes
            : 1_048_576n);
    const maximumOfferVerificationReadBytes =
        maximumSelectedOfferBytes +
        selectedProofLookaheadBytes +
        selected * sourceReadBytes;
    const maximumCertificateAssemblyReadBytes =
        participants * wire.endorsementPacketBytes;
    const maximumPreparationRoutingBytes =
        aggregateRoutingBytes +
        selected * (28n + manifest('contribution-')) +
        2n * (28n + manifest('selection')) +
        participants * (28n + manifest('selection-endorsement-')) +
        12n +
        16n * participants +
        manifest('setup-certificate');
    const readerPublicationReceivedBytes = transport.participants
        .slice(1)
        .reduce(
            (largest, participant) =>
                participant.receivedPayloadBytes > largest
                    ? participant.receivedPayloadBytes
                    : largest,
            0n,
        );
    const maximumCleanPreparationDownloadBytes =
        2n * selectionProposalBytes +
        maximumOfferVerificationReadBytes +
        maximumAggregateReadBytes +
        wire.certificateBytes +
        maximumCertificateAssemblyReadBytes +
        maximumPreparationRoutingBytes +
        readerPublicationReceivedBytes;
    // Discovery retains one verified offer long enough to add it locally.
    // Evaluation jobs fetch the committed part once and re-read their bounded
    // local copy; readers receive the aggregate and its per-offer proofs.
    // An honest author announces one ID. A bounded hint page adds its
    // untrusted u64 total and u32 count; corrupt additions are not capped here.
    const discoveryPageHeaderBytes = 8n + 4n;
    const organizerDiscoveryReadBytes =
        eligible * (discoveryPageHeaderBytes + 64n);
    const maximumCleanOrganizerPreparationDownloadBytes =
        maximumCleanPreparationDownloadBytes +
        2n * selectedCommittedPolynomialBytes +
        generatedAggregateReadBytes -
        maximumAggregateReadBytes +
        transport.participants[0].receivedPayloadBytes -
        readerPublicationReceivedBytes +
        organizerDiscoveryReadBytes +
        organizerSchedule.continuationReadBytes;
    const maximumCleanParticipantUploadBytes =
        transport.maximumParticipantUploadBytes;
    const maximumCleanTotalUploadBytes = transport.uploadedPayloadBytes;
    const transferPlanningBytes = 2_147_483_648n;
    return {
        eligibleContributorCount: wire.eligibleContributorCount,
        setupContributorCount: wire.setupContributorCount,
        quorum: wire.inventoryCertificateThreshold,
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
            BigInt(wire.inventoryCertificateThreshold) *
            wire.endorsementPacketBytes,
        // All bytes that must remain public for selected contribution and
        // certificate retrieval, beside the previously published registrations.
        maximumCertifiedSetupBytes:
            selected * largestStoredOffer +
            certificatePublication.storedPayloadBytes +
            aggregatePublications.reduce(
                (sum, publication) => sum + publication.storedPayloadBytes,
                0n,
            ),
        // An eligible participant can generate and continue one proof even
        // when its offer is not selected. No author is required after publication.
        maximumGenerationAndContinuationSeeds: 2n * eligible,
        maximumOfferProofs: eligible,
        selectedProofVerificationsPerReader: selected,
        // Complete exact named reads plus owning verification establish
        // published dependencies under monotone store retention; activation
        // never forwards the selected bodies again. A matching original
        // selection reference avoids another proof pass; losing/no endorsement
        // follows the fresh path.
        maximumOfferVerificationReadBytes,
        selectedCommittedPolynomialBytes,
        maximumAggregateReadBytes,
        generatedAggregateReadBytes,
        aggregateRoutingBytes,
        selectedPolynomialRereadBytes,
        selectedProofLookaheadBytes,
        // Prefix cancellation may receive one transport chunk per proof;
        // this is separately reserved, not asserted as exact network traffic.
        maximumLookaheadIngressBytes: selected * (1n << 20n),
        maximumMatchingCertificateActivationReadBytes:
            wire.certificateBytes +
            certificatePublication.receivedPayloadBytes +
            maximumCertificateAssemblyReadBytes +
            selectionProposalBytes +
            maximumPreparationRoutingBytes,
        maximumFreshCertificateActivationReadBytes:
            wire.certificateBytes +
            certificatePublication.receivedPayloadBytes +
            maximumCertificateAssemblyReadBytes +
            selectionProposalBytes +
            maximumPreparationRoutingBytes +
            maximumOfferVerificationReadBytes +
            maximumAggregateReadBytes,
        maximumCertificateAssemblyReadBytes,
        maximumCleanPreparationDownloadBytes,
        maximumCleanOrganizerPreparationDownloadBytes,
        organizerDiscoveryReadBytes,
        maximumDiscoveryPageBytes: discoveryPageHeaderBytes + 64n * 64n,
        eligibleOfferDiscoveryUploadBytes: eligible * 64n,
        maximumCleanParticipantUploadBytes,
        maximumCleanTotalUploadBytes,
        maximumPreparationRoutingBytes,
        maximumPublicationReceivedBytes:
            transport.maximumParticipantReceivedBytes,
        readerPublicationReceivedBytes,
        organizerPublicationReceivedBytes:
            transport.participants[0].receivedPayloadBytes,
        organizerSchedule,
        transferPlanningBytes,
        planningVarianceCeilingBytes: (3n * transferPlanningBytes) / 2n,
        cleanParticipantPolynomialReadFloorBytes:
            selected * body.streamedPolynomialPayloadBytes +
            aggregate.generatedAggregateBytes,
        cleanOrganizerPolynomialReadFloorBytes:
            selected * body.streamedPolynomialPayloadBytes +
            2n * selectedCommittedPolynomialBytes +
            2n * aggregate.generatedAggregateBytes,
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
        extraAggregateReadPassBytes: maximumAggregateReadBytes,
        volatileOfferPolynomialIdentityBytes:
            eligible * BigInt(body.polynomials.length) * 64n,
        additionalPolynomialHashStates: 1,
    };
};
