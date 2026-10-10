import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileCandidatePublicationCensus } from '#tests/candidate-publication-model.js';
import { compileClearPreparationResources } from '#tests/clear-preparation-resource-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileEvaluationStorage } from '#tests/evaluation-storage-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantCustodyCensus } from '#tests/participant-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRosterProposalCensus } from '#tests/roster-proposal-model.js';
import { compileSetupAggregateResources } from '#tests/setup-aggregate-resource-model.js';
import { compileSetupSelectionWireCensus } from '#tests/setup-selection-wire-model.js';
import type { SupportedProfile } from '#tests/supported-profile-model.js';
import {
    compileRetainedEvaluationResources,
    compileTargetSigningStateCensus,
} from '#tests/target-signing-state-model.js';

type RuntimeArtifactBytes = Readonly<{
    moduleBytes: bigint;
    sdkBytes: bigint;
    workerBytes: bigint;
}>;

// One clean, successful ordinary traversal: every member casts, responds,
// evaluates, votes and releases; retained setup and target caches survive.
// The two corpora differ only in whether d or all k eligible members offer.
// Proof bounds are canonical maxima, not predictions of sampled proof sizes.
export const compileOrdinaryWorkflowResources = (
    profile: SupportedProfile,
    artifact: RuntimeArtifactBytes,
) => {
    if (
        [artifact.moduleBytes, artifact.sdkBytes, artifact.workerBytes].some(
            (bytes) => bytes <= 0n,
        )
    )
        throw new RangeError('Missing built runtime artifact bytes.');
    const n = BigInt(profile.participantCount),
        d = BigInt(profile.setupContributorCount);
    const preparation = compileClearPreparationResources(profile);
    const k = BigInt(preparation.eligibleCount),
        q = BigInt(profile.inventoryCertificateThreshold);
    const registration = compileRegistrationEnrollmentCensus(),
        key = compileRecipientKeyCensus();
    const roster = compileRosterProposalCensus(profile.participantCount);
    const offer = compileContributionBodyCensus(profile),
        selection = compileSetupSelectionWireCensus(profile.participantCount);
    const ballot = compileBallotBodyCensus(profile),
        close = compileCloseWireCensus(profile),
        release = compileParticipantReleaseCustody(profile);
    const target = compileTargetSigningStateCensus(),
        retainedTarget = compileRetainedEvaluationResources(profile);
    const aggregate = compileSetupAggregateResources(profile),
        custody = compileParticipantCustodyCensus(profile),
        ballotCustody = compileParticipantBallotCustody(profile);
    const evaluation = compileEvaluationStorage(profile);
    const signature = registration.signatureBytes;
    const poll = registration.maximumPollDefinitionBytes + signature;
    const registrationRecord =
        key.publicKeyBytes + registration.maximumHeaderBytes + signature;
    const registrationCorpus =
        poll + n * registrationRecord + roster.proposalBytes + signature;
    const rosterRestorePayload =
        n * (registration.maximumHeaderBytes + key.publicKeyBytes);
    const signedOffer =
        offer.maximumBodyBytes + selection.offerEnvelopeBytes + signature;
    const response =
        close.minimumResponseBodyBytes + n * (2n + 64n) + 4n + signature;
    const signedRelease =
        release.maximumBodyBytes + release.envelopeBytes + signature;
    // All n original responses, q named closure copies, each nonorganizer's
    // n-envelope listed copy, n organizer closure envelopes and n body
    // references. The complete closure is independent of original authors.
    const closureCopies =
        q * response + n * close.submissionBytes + n * ballot.maximumBodyBytes;
    const listedCopies = n * n * close.submissionBytes;
    // Publishing the roster repeats the organizer's registration and poll.
    // Activators each POST their complete certificate. Final close
    // publication repeats the original intent; the proposal also carries it.
    const duplicateUploads =
        poll +
        registrationRecord +
        (n - 1n) * selection.certificateBytes +
        2n * close.intentPacketBytes;
    const rows = [
        { name: 'Ordinary selected contributors', offers: d },
        { name: 'All eligible contributors', offers: k },
    ].map(({ name, offers }) => {
        const transport = compileCandidatePublicationCensus(
            profile,
            Number(offers),
        );
        // Twelve ordinary calls per member: enrollment, publication, roster,
        // confirmation, selection/endorsement, activation, ballot, two close
        // calls, target, release and result. Each offered contribution adds
        // its call; the organizer additionally republishes the signed roster.
        const workerInvocations = 12n * n + offers + 1n;
        return {
            name,
            offers,
            publicCorpusBytes: transport.storedPayloadBytes,
            totalUploadBytes: transport.uploadedPayloadBytes,
            transport,
            workerInvocations,
            moduleDownloadBytes: workerInvocations * artifact.moduleBytes,
        };
    });
    const transport = rows[0].transport;
    const routing = (keyName: string) => {
        const copies = transport.publications.filter(
            (value) => value.key === keyName,
        );
        return 12n + 16n * BigInt(copies.length) + copies[0].manifestBytes;
    };
    const registrationRouting = transport.publications
        .filter((value) => value.key.startsWith('registration/'))
        .reduce((keys, value) => keys.add(value.key), new Set<string>());
    const rosterRoutingBytes = [...registrationRouting].reduce(
        (total, keyName) => total + routing(keyName),
        0n,
    );
    const rosterRestore = rosterRestorePayload + rosterRoutingBytes;
    const ballotRoutingBytes = routing('ballot-0');
    const voteRoutingBytes = Array.from({ length: Number(q) }, (_, position) =>
        routing('target-vote-' + String(position)),
    ).reduce((total, bytes) => total + bytes, 0n);
    const releaseRoutingBytes = Array.from(
        { length: Number(d) },
        (_, position) => routing('release-' + String(position)),
    ).reduce((total, bytes) => total + bytes, 0n);
    const publicReaderRoutingBytes =
        routing('poll') +
        routing('roster') +
        routing('setup-certificate') +
        rosterRoutingBytes +
        transport.publications
            .filter((value) => value.key.startsWith('contribution-'))
            .reduce((total, value) => total + routing(value.key), 0n) +
        routing('close-proposal') +
        voteRoutingBytes +
        releaseRoutingBytes;
    // The public reader holds no participant custody. It reads each usable
    // body for the barrier, classification and evaluation import, then q votes
    // and d complete release shares; it does not fetch a producer's target.
    const publicReaderProtocolBytes =
        registrationCorpus +
        selection.certificateBytes +
        preparation.maximumOfferVerificationReadBytes +
        close.intentPacketBytes +
        close.proposalPacketBytes +
        q * response +
        n * close.submissionBytes +
        3n * n * ballot.maximumBodyBytes +
        q * target.packetBytes +
        d * signedRelease +
        publicReaderRoutingBytes;
    const nonorganizerCloseBytes =
        2n * rosterRestore +
        (n - 1n) * ballot.maximumBodyBytes +
        2n * (n - 1n) * close.submissionBytes +
        close.intentPacketBytes +
        2n * (n - 1n) * ballotRoutingBytes +
        12n +
        routing('close-intent');
    const organizerCloseBytes =
        2n * rosterRestore +
        (n - 1n) * ballot.maximumBodyBytes +
        2n * (n - 1n) * close.submissionBytes +
        (q - 1n) * (response + n * close.submissionBytes) +
        2n * (n - 1n) * ballotRoutingBytes +
        Array.from({ length: Number(q - 1n) }, (_, index) =>
            routing('close-response-' + String(index + 1)),
        ).reduce((total, bytes) => total + bytes, 0n) +
        12n * (n - 1n);
    // Conservative metadata allowance: locally held responses can avoid
    // these reads, as an existing certificate can avoid preparation assembly.
    // These are upper bounds, not an exact ordinary network trace.
    const targetReadBytes =
        rosterRestore +
        close.intentPacketBytes +
        close.proposalPacketBytes +
        q * response +
        routing('close-proposal');
    const releaseReadBytes =
        rosterRestore + q * target.packetBytes + voteRoutingBytes;
    const resultReadBytes =
        releaseReadBytes + d * signedRelease + releaseRoutingBytes;
    const preparationReaderBytes =
        preparation.maximumCleanPreparationDownloadBytes + 2n * rosterRestore;
    const preparationOrganizerBytes =
        preparation.maximumCleanOrganizerPreparationDownloadBytes -
        preparation.organizerDiscoveryReadBytes +
        d * (12n + 64n) +
        2n * rosterRestore;
    const otherPublicationReceives = transport.participants.map(
        (participant, position) =>
            participant.receivedPayloadBytes -
            transport.preparation.participants[position].receivedPayloadBytes,
    );
    const largestOtherPublicationReceives = otherPublicationReceives
        .slice(1)
        .reduce((largest, value) => (value > largest ? value : largest), 0n);
    const noncontributorProtocolReads =
        poll +
        n * registrationRecord +
        rosterRoutingBytes +
        signature +
        routing('roster') +
        routing('poll') +
        preparationReaderBytes +
        nonorganizerCloseBytes +
        targetReadBytes +
        releaseReadBytes +
        resultReadBytes +
        largestOtherPublicationReceives;
    const contributorProtocolReads =
        noncontributorProtocolReads + rosterRestore;
    const organizerProtocolReads =
        n * registrationRecord +
        rosterRoutingBytes +
        rosterRestore +
        preparationOrganizerBytes +
        organizerCloseBytes +
        targetReadBytes +
        releaseReadBytes +
        resultReadBytes +
        otherPublicationReceives[0];
    const organizerUpload = transport.participants[0].uploadedPayloadBytes;
    // Successful logical retained payload. Baseline public enrollment fields
    // remain authenticated; source and own contribution/checkpoint stores retire
    // at activation. Add residual record/head metadata and physical IDB overhead
    // separately before treating this as a whole-origin storage bound.
    const preparedBase =
        registration.maximumRetainedPayloadBytes -
        registration.maximumRootBytes -
        registration.maximumSourceCapsuleBytes +
        custody.maximumPreparedRootBytes +
        custody.setupReferenceBytes +
        custody.setupCertificateBytes;
    const closeCustody =
        preparedBase +
        n * ballotCustody.maximumEncryptedBodyBytes +
        (n - 1n) * (close.submissionBytes + 16n) +
        (n - 1n) * (response + 16n);
    return {
        profile: `${profile.participantCount}/${profile.optionCount}`,
        rows,
        artifact,
        registrationCorpusBytes: registrationCorpus,
        // publishRecords preflights each complete public kind, then rereads
        // one original record per guarded POST. Authority checks are extra.
        publicationRecordPayloadReadBytes:
            2n *
            ((n + 1n) * registrationRecord +
                2n * poll +
                roster.proposalBytes +
                signature),
        maximumPublicationRecordBytes: 1_048_576n,
        rosterRestoreBytes: rosterRestore,
        noncontributorProtocolReads,
        contributorProtocolReads,
        organizerProtocolReads,
        signedOfferBytes: signedOffer,
        cleanResponseBytes: response,
        signedReleaseBytes: signedRelease,
        organizerClosureCopyBytes: closureCopies,
        responderListedCopyBytes: listedCopies,
        ordinaryForwardedBodyUploadBytes: 0n,
        ordinaryReferencedBodyBytes: transport.referencedBodyBytes,
        // If original chunks cannot be retrieved, each forwarder uploads the
        // same retained body. Arbitrary retries have no finite lifetime cap.
        maximumMissingReferenceUploadBytes: n * n * ballot.maximumBodyBytes,
        duplicateUploadBytes: duplicateUploads,
        organizerUploadBytes: organizerUpload,
        publicReaderProtocolBytes,
        publicReaderRoutingBytes,
        publicationReceivedBytes: transport.receivedPayloadBytes,
        maximumManifestBytes: transport.maximumManifestBytes,
        maximumManifestFiles: transport.maximumFiles,
        candidateManifestBytes: transport.manifestBytes,
        candidatePublicationRequests: transport.requests,
        publicReaderColdDeliveryBytes:
            publicReaderProtocolBytes +
            artifact.moduleBytes +
            artifact.sdkBytes,
        // The SDK entry embeds the worker text; do not add workerBytes again
        // to a page download. A worker invocation refetches only the module.
        moduleBytesPerInvocation: artifact.moduleBytes,
        workerSourceBytes: artifact.workerBytes,
        bootstrapForInvocations: (invocations: bigint, pageLoads: bigint) => {
            if (invocations < 0n || pageLoads < 0n)
                throw new RangeError('Negative runtime-delivery count.');
            return (
                invocations * artifact.moduleBytes +
                pageLoads * artifact.sdkBytes
            );
        },
        ordinaryOrganizerDiscoveryBytes: d * (12n + 64n),
        preparationReaderBytes:
            preparation.maximumCleanPreparationDownloadBytes +
            2n * rosterRestore,
        preparationOrganizerBytes:
            preparation.maximumCleanOrganizerPreparationDownloadBytes -
            preparation.organizerDiscoveryReadBytes +
            d * (12n + 64n) +
            2n * rosterRestore,
        nonorganizerCloseBytes,
        organizerCloseBytes,
        targetReadBytes,
        releaseReadBytes,
        resultReadBytes,
        prepRetainedAndAggregatePayloadBytes:
            custody.maximumRetainedPayloadBytes +
            aggregate.maximumLogicalCachePayloadBytes,
        closedCustodyAndAggregatePayloadBytes:
            closeCustody + aggregate.aggregateBytes,
        evaluationCustodyAndStorePayloadBytes:
            closeCustody + aggregate.aggregateBytes + evaluation.peakBytes,
        releaseEndPayloadBytes:
            closeCustody +
            aggregate.aggregateBytes +
            retainedTarget.maximumRetainedBytes +
            release.maximumEncryptedBodyBytes,
        evaluation,
        retainedTarget,
        planningBytes: preparation.transferPlanningBytes,
        planningVarianceCeilingBytes: preparation.planningVarianceCeilingBytes,
    };
};
