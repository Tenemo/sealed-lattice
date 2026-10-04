import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { compileClearPreparationResources } from '#tests/clear-preparation-resource-model.js';
import { compileCloseWireCensus } from '#tests/close-wire-model.js';
import { compileContributionBodyCensus } from '#tests/contribution-body-model.js';
import { compileEvaluationStorage } from '#tests/evaluation-storage-model.js';
import { compileParticipantBallotCustody } from '#tests/participant-ballot-custody-model.js';
import { compileParticipantCustodyCensus } from '#tests/participant-custody-model.js';
import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileRegistrationKeyRelationCensus } from '#tests/registration-key-relation-model.js';
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
        key = compileRegistrationKeyRelationCensus();
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
        key.publicKeyBytes +
        key.maximumProofBytes +
        registration.maximumHeaderBytes +
        signature;
    const registrationCorpus =
        poll + n * registrationRecord + roster.proposalBytes + signature;
    const rosterRestore =
        n * (registration.maximumHeaderBytes + key.publicKeyBytes);
    const signedOffer =
        offer.maximumBodyBytes + selection.offerEnvelopeBytes + signature;
    const announcedOffer = signedOffer + 64n;
    const signedSelection = selection.selectionBodyBytes + signature;
    const response =
        close.minimumResponseBodyBytes + n * (2n + 64n) + 4n + signature;
    const signedRelease =
        release.maximumBodyBytes + release.envelopeBytes + signature;
    const ballotPublication =
        ballot.maximumBodyBytes + close.submissionBytes + 64n;
    const setupShared =
        signedSelection +
        n * selection.endorsementPacketBytes +
        selection.certificateBytes +
        64n;
    // All n original responses, q named closure copies, each nonorganizer's
    // n-envelope listed copy, n organizer closure envelopes, and n-1 closure
    // bodies. The organizer's own body stays at its original ballot route.
    const closureCopies =
        q * response +
        n * close.submissionBytes +
        (n - 1n) * ballot.maximumBodyBytes;
    const listedCopies = (n - 1n) * n * close.submissionBytes;
    const closeShared =
        close.intentPacketBytes +
        close.proposalPacketBytes +
        n * response +
        closureCopies +
        listedCopies +
        n * 64n;
    const afterSetupShared =
        n * ballotPublication +
        closeShared +
        n * target.packetBytes +
        target.maximumBodyBytes +
        n * signedRelease;
    // Publishing the roster repeats the organizer's registration and poll.
    // Activators each POST the certificate/selector, even when already stored.
    // Final close publication repeats the original intent and held list.
    const duplicateUploads =
        poll +
        registrationRecord +
        (n - 1n) * (selection.certificateBytes + 64n) +
        close.intentPacketBytes +
        n * 64n;
    const rows = [
        { name: 'Ordinary selected contributors', offers: d },
        { name: 'All eligible contributors', offers: k },
    ].map(({ name, offers }) => {
        const publicCorpusBytes =
            registrationCorpus +
            offers * announcedOffer +
            setupShared +
            afterSetupShared;
        // Twelve ordinary calls per member: enrollment, publication, roster,
        // confirmation, selection/endorsement, activation, ballot, two close
        // calls, target, release and result. Each offered contribution adds
        // its call; the organizer additionally republishes the signed roster.
        const workerInvocations = 12n * n + offers + 1n;
        return {
            name,
            offers,
            publicCorpusBytes,
            totalUploadBytes: publicCorpusBytes + duplicateUploads,
            workerInvocations,
            moduleDownloadBytes: workerInvocations * artifact.moduleBytes,
        };
    });
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
        d * signedRelease;
    const nonorganizerCloseBytes =
        2n * rosterRestore +
        (n - 1n) * ballot.maximumBodyBytes +
        2n * (n - 1n) * (close.submissionBytes + 64n) +
        close.intentPacketBytes +
        n * 64n;
    const organizerCloseBytes =
        2n * rosterRestore +
        (n - 1n) * ballot.maximumBodyBytes +
        2n * (n - 1n) * (close.submissionBytes + 64n) +
        (n - 1n) * response;
    // Conservative metadata allowance: locally held responses can avoid
    // these reads, as an existing certificate can avoid preparation assembly.
    // These are upper bounds, not an exact ordinary network trace.
    const targetReadBytes =
        rosterRestore +
        close.intentPacketBytes +
        close.proposalPacketBytes +
        q * response;
    const releaseReadBytes = rosterRestore + q * target.packetBytes;
    const resultReadBytes = releaseReadBytes + d * signedRelease;
    const preparationReaderBytes =
        preparation.maximumCleanPreparationDownloadBytes + 2n * rosterRestore;
    const preparationOrganizerBytes =
        preparation.maximumCleanOrganizerPreparationDownloadBytes -
        preparation.organizerDiscoveryReadBytes +
        d * (12n + 64n) +
        2n * rosterRestore;
    const noncontributorProtocolReads =
        poll +
        n * registrationRecord +
        signature +
        preparationReaderBytes +
        nonorganizerCloseBytes +
        targetReadBytes +
        releaseReadBytes +
        resultReadBytes;
    const contributorProtocolReads =
        noncontributorProtocolReads + rosterRestore;
    const organizerProtocolReads =
        n * registrationRecord +
        rosterRestore +
        preparationOrganizerBytes +
        organizerCloseBytes +
        targetReadBytes +
        releaseReadBytes +
        resultReadBytes;
    const organizerUpload =
        2n * (poll + registrationRecord) +
        roster.proposalBytes +
        signature +
        preparation.maximumCleanParticipantUploadBytes +
        ballotPublication +
        2n * (close.intentPacketBytes + n * 64n) +
        response +
        close.proposalPacketBytes +
        closureCopies +
        target.packetBytes +
        target.maximumBodyBytes +
        signedRelease;
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
        custody.setupInventoryBytes;
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
        ordinaryForwardedBodyBytes: 0n,
        // A missing/malformed held list takes this separate one-publication
        // fallback. Arbitrary repeated invocations have no finite lifetime cap.
        maximumForwardedBodyFallbackBytes:
            (n - 1n) ** 2n * ballot.maximumBodyBytes,
        duplicateUploadBytes: duplicateUploads,
        organizerUploadBytes: organizerUpload,
        publicReaderProtocolBytes,
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
