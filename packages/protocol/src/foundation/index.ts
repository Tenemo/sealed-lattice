import type {
    FirstValidOrderingVerification,
    FoundationTranscriptComponentResults,
    FoundationTranscriptInput,
    FoundationTranscriptVerification,
    ProtocolVerificationStatusLabel,
    RefusalRecord,
    RecoveryEpochVerification,
    TargetFinalityVerification,
} from '@sealed-lattice/types';

import {
    createRefusal,
    isProtocolHashString,
    uniqueStrings,
    verificationExceptionMessage,
} from '../common/verification-helpers.js';
import { verifyTargetFinality } from '../finality/index.js';
import { deriveValidatedFirstValidOrder } from '../ordering/index.js';
import { verifyRecoveryEpochUpdate } from '../recovery/index.js';
import {
    verifyRosterExternalAcceptance,
    verifyRosterManifestTranscript,
} from '../roster/index.js';

const nextFoundationEvidence = [
    'direct ballot proof verification',
    'encrypted ballot aggregation',
    'evaluator replay verification',
    'target acceptance',
    'target-bound decryption',
    'decoded result verification',
    'supported-phone mobile runtime evidence',
] as const;

const emptyFirstValidOrdering: FirstValidOrderingVerification = {
    ok: false,
    statusLabels: [],
    acceptedHashes: [],
    refusedObjects: [],
    orderedObjects: [],
};

const emptyTargetFinality: TargetFinalityVerification = {
    ok: false,
    statusLabels: [],
    acceptedHashes: [],
    refusedObjects: [],
    validWitnessIdentities: [],
    equivocatingWitnessIdentities: [],
};

const buildFailure = (
    refusedObjects: readonly RefusalRecord[],
    componentResults?: Partial<FoundationTranscriptComponentResults>,
): FoundationTranscriptVerification => ({
    ok: false,
    statusLabels: [],
    acceptedHashes: [],
    refusedObjects,
    validWitnessIdentities: [],
    nextRequiredEvidence: nextFoundationEvidence,
    componentResults: {
        rosterManifest: componentResults?.rosterManifest ?? {
            ok: false,
            statusLabels: [],
            acceptedHashes: [],
            refusedObjects: [],
            participantIdentities: [],
        },
        rosterExternalAcceptance:
            componentResults?.rosterExternalAcceptance ?? {
                ok: false,
                statusLabels: [],
                acceptedHashes: [],
                refusedObjects: [],
            },
        recoveryEpochUpdates: componentResults?.recoveryEpochUpdates ?? [],
        firstValidOrdering:
            componentResults?.firstValidOrdering ?? emptyFirstValidOrdering,
        targetFinality: componentResults?.targetFinality ?? emptyTargetFinality,
    },
});

const collectCrossBindingRefusals = (
    input: FoundationTranscriptInput,
    componentResults: FoundationTranscriptComponentResults,
): readonly RefusalRecord[] => {
    const manifest = input.rosterManifestTranscript.electionManifest;
    const { manifestOpaqueBindings, manifestPolicyHashes } = manifest;
    const checkpoint = input.targetFinality.record.targetFinalityCheckpoint;
    const rosterParticipantIdentities = new Set(
        componentResults.rosterManifest.participantIdentities,
    );
    const rosterPublicKeyHashesByIdentity = new Map(
        input.rosterManifestTranscript.registrationEntries.map((entry) => [
            entry.participantIdentity.normalize('NFC'),
            entry.signingPublicKeyHash,
        ]),
    );
    const refusedObjects: RefusalRecord[] = [];

    if (input.rosterExternalAcceptance === undefined) {
        refusedObjects.push(
            createRefusal(
                'RosterExternalAcceptanceInvalid',
                'Foundation transcript requires one local roster external acceptance.',
                manifest.rosterHash,
                'RosterExternalAcceptance',
            ),
        );
    } else {
        const rosterAcceptance = input.rosterExternalAcceptance.acceptance;
        const acceptedParticipantIdentity =
            rosterAcceptance.participantIdentity.normalize('NFC');
        const acceptedParticipantPublicKeyHash =
            rosterPublicKeyHashesByIdentity.get(acceptedParticipantIdentity);
        if (
            input.rosterExternalAcceptance.expectedCeremonyId !==
                input.rosterManifestTranscript.ceremonyId ||
            input.rosterExternalAcceptance.expectedRosterHash !==
                manifest.rosterHash ||
            input.rosterExternalAcceptance.expectedElectionManifestHash !==
                manifest.electionManifestHash ||
            input.rosterExternalAcceptance.expectedAcceptedBoardHeadHash !==
                input.rosterManifestTranscript.manifestInclusionProof
                    .boardHeadHash ||
            acceptedParticipantPublicKeyHash === undefined ||
            input.rosterExternalAcceptance.expectedParticipantPublicKeyHash !==
                acceptedParticipantPublicKeyHash
        ) {
            refusedObjects.push(
                createRefusal(
                    'RosterExternalAcceptanceInvalid',
                    'Foundation roster acceptance must bind one frozen-roster participant, public key, manifest, roster hash, and accepted board head.',
                    rosterAcceptance.rosterExternalAcceptanceHash,
                    'RosterExternalAcceptance',
                ),
            );
        }
    }

    if (
        input.firstValidOrdering.selectionPolicyHash !==
            manifestPolicyHashes.firstValidPolicyHash ||
        input.firstValidOrdering.expectedSelectionPolicyHash !==
            manifestPolicyHashes.firstValidPolicyHash
    ) {
        refusedObjects.push(
            createRefusal(
                'FirstValidPolicyMismatch',
                'Foundation first-valid ordering must bind the manifest first-valid policy hash.',
                input.firstValidOrdering.selectionPolicyHash,
            ),
        );
    }

    for (const candidate of input.firstValidOrdering.objects) {
        if (candidate.objectType !== 'EncryptedBallot') {
            refusedObjects.push(
                createRefusal(
                    'WrongObjectType',
                    'Foundation first-valid ordering only accepts encrypted ballot object shells.',
                    candidate.objectHash,
                    candidate.objectType,
                ),
            );
        }
        if (!rosterParticipantIdentities.has(candidate.signerIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'RosterHashMismatch',
                    'Foundation first-valid candidate signer is not in the frozen roster.',
                    candidate.objectHash,
                    candidate.objectType,
                ),
            );
        }
    }

    if (
        input.targetFinality.targetFinalityPolicy.targetFinalityPolicyHash !==
            manifestPolicyHashes.targetFinalityPolicyHash ||
        input.targetFinality.witnessPolicy.witnessPolicyHash !==
            manifestPolicyHashes.witnessPolicyHash ||
        checkpoint.targetFinalityPolicyHash !==
            manifestPolicyHashes.targetFinalityPolicyHash ||
        checkpoint.witnessPolicyHash !== manifestPolicyHashes.witnessPolicyHash
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Foundation target-finality evidence must bind the manifest finality and witness policies.',
                input.targetFinality.record.targetFinalityRecordHash,
                'TargetFinalityRecord',
            ),
        );
    }

    if (
        checkpoint.electionManifestHash !== manifest.electionManifestHash ||
        checkpoint.thresholdProfileHash !==
            input.rosterManifestTranscript.frozenRosterProfile
                .thresholdProfileHash ||
        checkpoint.evaluatorReplayProfileHash !==
            manifestOpaqueBindings.evaluatorReplayProfileHash ||
        checkpoint.targetLayoutHash !== manifestOpaqueBindings.targetLayoutHash
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Foundation target proposal must bind the accepted manifest, frozen roster profile, evaluator replay profile, and target layout.',
                checkpoint.targetFinalityCheckpointHash,
                'TargetFinalityCheckpoint',
            ),
        );
    }

    if (
        checkpoint.topOptionCount !== input.expectedTopOptionCount ||
        input.expectedTopOptionCount !==
            input.rosterManifestTranscript.pollSpec.topOptionCount ||
        checkpoint.tiePolicyHash !== input.expectedTiePolicyHash
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Foundation target proposal must bind the expected top count and tie-policy hash.',
                checkpoint.targetFinalityCheckpointHash,
                'TargetFinalityCheckpoint',
            ),
        );
    }

    if (
        !isProtocolHashString(checkpoint.encryptedBallotAggregateHash) ||
        !isProtocolHashString(checkpoint.evaluatorReplayContextHash) ||
        !isProtocolHashString(checkpoint.evaluatorReplayRecordHash) ||
        !isProtocolHashString(checkpoint.targetCiphertextHash)
    ) {
        refusedObjects.push(
            createRefusal(
                'TargetFinalityPolicyMismatch',
                'Foundation target proposal must bind canonical direct-route placeholder hashes.',
                checkpoint.targetFinalityCheckpointHash,
                'TargetFinalityCheckpoint',
            ),
        );
    }

    return refusedObjects;
};

const verifyFoundationTranscriptUnchecked = (
    input: FoundationTranscriptInput,
): FoundationTranscriptVerification => {
    const rosterManifest = verifyRosterManifestTranscript(
        input.rosterManifestTranscript,
    );
    const rosterExternalAcceptance = verifyRosterExternalAcceptance(
        input.rosterExternalAcceptance,
    );
    const recoveryEpochUpdates: RecoveryEpochVerification[] = (
        input.recoveryEpochUpdates ?? []
    ).map((recoveryInput) => verifyRecoveryEpochUpdate(recoveryInput));
    const firstValidOrdering = deriveValidatedFirstValidOrder(
        input.firstValidOrdering,
    );
    const targetFinality = verifyTargetFinality(input.targetFinality);
    const componentResults = {
        rosterManifest,
        rosterExternalAcceptance,
        recoveryEpochUpdates,
        firstValidOrdering,
        targetFinality,
    };
    const refusedObjects = [
        ...rosterManifest.refusedObjects,
        ...rosterExternalAcceptance.refusedObjects,
        ...recoveryEpochUpdates.flatMap((result) => result.refusedObjects),
        ...firstValidOrdering.refusedObjects,
        ...targetFinality.refusedObjects,
        ...collectCrossBindingRefusals(input, componentResults),
    ];
    const accepted =
        refusedObjects.length === 0 &&
        rosterManifest.ok &&
        rosterExternalAcceptance.ok &&
        recoveryEpochUpdates.every((result) => result.ok) &&
        firstValidOrdering.ok &&
        targetFinality.ok;
    // Status labels (including recovery-epoch labels) are aggregated regardless of acceptance and are also returned on the rejected path.
    const statusLabels: readonly ProtocolVerificationStatusLabel[] =
        uniqueStrings([
            ...rosterManifest.statusLabels,
            ...rosterExternalAcceptance.statusLabels,
            ...recoveryEpochUpdates.flatMap((result) => result.statusLabels),
            ...firstValidOrdering.statusLabels,
            ...targetFinality.statusLabels,
        ]);

    if (!accepted) {
        return {
            ...buildFailure(refusedObjects, componentResults),
            statusLabels,
            forkEvidence:
                targetFinality.forkEvidence ?? rosterManifest.forkEvidence,
        };
    }

    return {
        ok: true,
        statusLabels,
        acceptedHashes: uniqueStrings([
            ...rosterManifest.acceptedHashes,
            ...rosterExternalAcceptance.acceptedHashes,
            ...recoveryEpochUpdates.flatMap((result) => result.acceptedHashes),
            ...firstValidOrdering.acceptedHashes,
            ...targetFinality.acceptedHashes,
        ]),
        refusedObjects: [],
        electionManifestHash: rosterManifest.electionManifestHash,
        rosterHash: rosterManifest.rosterHash,
        rosterExternalAcceptanceHash:
            rosterExternalAcceptance.rosterExternalAcceptanceHash,
        firstValidOrderHash: firstValidOrdering.firstValidOrderHash,
        targetProposalHash: targetFinality.targetProposalHash,
        targetFinalityCheckpointHash:
            targetFinality.targetFinalityCheckpointHash,
        targetFinalityRecordHash: targetFinality.targetFinalityRecordHash,
        validWitnessIdentities: targetFinality.validWitnessIdentities,
        nextRequiredEvidence: nextFoundationEvidence,
        componentResults,
    };
};

export const verifyFoundationTranscript = (
    input: FoundationTranscriptInput,
): FoundationTranscriptVerification => {
    try {
        return verifyFoundationTranscriptUnchecked(input);
    } catch (error) {
        return buildFailure([
            createRefusal(
                'ManifestHashMismatch',
                verificationExceptionMessage(
                    'Foundation transcript could not be canonicalized or validated.',
                    error,
                ),
                undefined,
                'ElectionManifest',
            ),
        ]);
    }
};
