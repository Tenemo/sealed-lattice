import { verifySignedObjectSignature } from '@sealed-lattice/crypto';
import {
    ballotValidityProofProfileId,
    bgvPassiveSetupProfileId,
    directComparisonProfileId,
    encryptedBallotAggregateProfileId,
    encryptedBallotLayoutProfileId,
    evaluatorReplayProfileId,
    mobileProfileId,
    targetDecryptionProfileId,
} from '@sealed-lattice/types';
import type {
    ElectionManifest,
    InclusionProof,
    ProtocolHash,
    RefusalRecord,
    RegistrationEntry,
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    RosterManifestTranscriptInput,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import {
    createRefusal,
    defaultSignedRootContextHash,
    isNonNegativeInteger,
    isProtocolHashString,
    signedObjectRootByteLength,
} from '../common/verification-helpers.js';

import {
    deriveElectionManifestHash,
    deriveRegistrationEntryHash,
    deriveRosterExternalAcceptanceHash,
    deriveTrusteeSetupEntryHash,
} from './hashes.js';

// Exact-schema lock: the manifest's opaque bindings must carry precisely this
// set of field names or it fails closed.
const manifestOpaqueBindingFieldNames = new Set([
    'bgvPassiveSetupProfileId',
    'encryptedBallotLayoutProfileId',
    'ballotValidityProofProfileId',
    'encryptedBallotAggregateProfileId',
    'evaluatorReplayProfileId',
    'directComparisonProfileId',
    'targetDecryptionProfileId',
    'mobileProfileId',
    'heParamHash',
    'bgvPassiveSetupPackageHash',
    'bgvSetupParameterCertificateHash',
    'bgvProfileHash',
    'rustBgvBackendProfileHash',
    'bgvPublicKeyRoot',
    'collectivePublicKeyRoot',
    'collectiveSecretDistributionCertificateHash',
    'errorDistributionCertificateHash',
    'keySwitchDecompositionHash',
    'canonicalCiphertextConventionHash',
    'bgvBatchEncoderHash',
    'encryptedBallotLayoutHash',
    'ballotValidityProofProfileHash',
    'encryptedBallotAggregateProfileHash',
    'encryptedBallotAggregateLayoutHash',
    'directAggregateLayoutHash',
    'comparisonInputDerivationCircuitHash',
    'encryptedComparisonInputHash',
    'encryptedSparseTargetProjectionHash',
    'targetLayoutHash',
    'evaluatorReplayProfileHash',
    'directComparisonProfileHash',
    'evaluationNoiseProfileHash',
    'heEvaluationNoiseCertHash',
    'allowedEvaluatorOpsHash',
    'rotSetHash',
    'evaluationKeyRoot',
    'evaluationKeySizeProfileHash',
    'thresholdShareVerificationKeyRoot',
    'thresholdShareVerificationKeyHash',
    'trusteeThresholdVerificationKeyHash',
    'targetDecryptionProfileHash',
    'targetThresholdDecryptabilityCertificateHash',
    'targetBasisHash',
    'mobileProfileHash',
]);

const manifestOpaqueBindingFieldCount = manifestOpaqueBindingFieldNames.size;

const collectManifestOpaqueBindingRefusals = (
    manifest: ElectionManifest,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const bindings = manifest.manifestOpaqueBindings;

    if (
        bindings.bgvPassiveSetupProfileId !== bgvPassiveSetupProfileId ||
        bindings.encryptedBallotLayoutProfileId !==
            encryptedBallotLayoutProfileId ||
        bindings.ballotValidityProofProfileId !==
            ballotValidityProofProfileId ||
        bindings.encryptedBallotAggregateProfileId !==
            encryptedBallotAggregateProfileId ||
        bindings.evaluatorReplayProfileId !== evaluatorReplayProfileId ||
        bindings.directComparisonProfileId !== directComparisonProfileId ||
        bindings.targetDecryptionProfileId !== targetDecryptionProfileId ||
        bindings.mobileProfileId !== mobileProfileId
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Election manifest must bind the fixed direct encrypted ballot, evaluator replay, target decryption, and mobile profile identifiers.',
                manifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }
    // Enforce the exact-schema lock: the binding object must have exactly the
    // expected number of keys AND no key outside the allowed set (rejects both
    // missing and extra fields).
    const bindingFieldNames = Object.keys(bindings);
    if (
        bindingFieldNames.length !== manifestOpaqueBindingFieldCount ||
        bindingFieldNames.some(
            (fieldName) => !manifestOpaqueBindingFieldNames.has(fieldName),
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Election manifest opaque bindings must use the current direct encrypted ballot schema.',
                manifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }

    const requiredHashFields = [
        bindings.heParamHash,
        bindings.bgvPassiveSetupPackageHash,
        bindings.bgvSetupParameterCertificateHash,
        bindings.bgvProfileHash,
        bindings.rustBgvBackendProfileHash,
        bindings.bgvPublicKeyRoot,
        bindings.collectivePublicKeyRoot,
        bindings.collectiveSecretDistributionCertificateHash,
        bindings.errorDistributionCertificateHash,
        bindings.keySwitchDecompositionHash,
        bindings.canonicalCiphertextConventionHash,
        bindings.bgvBatchEncoderHash,
        bindings.encryptedBallotLayoutHash,
        bindings.ballotValidityProofProfileHash,
        bindings.encryptedBallotAggregateProfileHash,
        bindings.encryptedBallotAggregateLayoutHash,
        bindings.directAggregateLayoutHash,
        bindings.comparisonInputDerivationCircuitHash,
        bindings.encryptedComparisonInputHash,
        bindings.encryptedSparseTargetProjectionHash,
        bindings.targetLayoutHash,
        bindings.evaluatorReplayProfileHash,
        bindings.directComparisonProfileHash,
        bindings.evaluationNoiseProfileHash,
        bindings.heEvaluationNoiseCertHash,
        bindings.allowedEvaluatorOpsHash,
        bindings.rotSetHash,
        bindings.evaluationKeyRoot,
        bindings.evaluationKeySizeProfileHash,
        bindings.thresholdShareVerificationKeyRoot,
        bindings.thresholdShareVerificationKeyHash,
        bindings.trusteeThresholdVerificationKeyHash,
        bindings.targetDecryptionProfileHash,
        bindings.targetThresholdDecryptabilityCertificateHash,
        bindings.targetBasisHash,
        bindings.mobileProfileHash,
    ];

    if (
        requiredHashFields.some((HashField) => !isProtocolHashString(HashField))
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Election manifest opaque bindings must include canonical downstream profile and certificate Hashes.',
                manifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }

    return refusedObjects;
};

export const verifyRegistrationEntry = (
    input: RosterManifestTranscriptInput,
    entry: RegistrationEntry,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedHash = deriveRegistrationEntryHash({
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantIdentity: entry.participantIdentity,
        recoveryEpoch: entry.recoveryEpoch,
        signingPublicKeyHash: entry.signingPublicKeyHash,
    });

    if (entry.registrationEntryHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Registration entry hash does not match its canonical payload.',
                entry.registrationEntryHash,
                'RegistrationEntry',
            ),
        );
    }
    if (
        entry.objectType !== 'RegistrationEntry' ||
        entry.objectVersion !== 1 ||
        !isNonNegativeInteger(entry.boardSequence) ||
        !isNonNegativeInteger(entry.boardPosition) ||
        !isNonNegativeInteger(entry.recoveryEpoch) ||
        !isNonNegativeInteger(entry.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Registration entry object shape is not canonical.',
                entry.registrationEntryHash,
                'RegistrationEntry',
            ),
        );
    }
    if (entry.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Registration entry ceremony does not match the transcript.',
                entry.registrationEntryHash,
                'RegistrationEntry',
            ),
        );
    }
    if (entry.boardSequence >= input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Registration entry must appear before the roster freeze board sequence.',
                entry.registrationEntryHash,
                'RegistrationEntry',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(entry.signature, {
        objectType: 'RegistrationEntry',
        objectVersion: 1,
        signerRole: 'Participant',
        signerIdentity: entry.participantIdentity,
        ceremonyId: input.ceremonyId,
        manifestHash: null,
        objectRoot: entry.registrationEntryHash,
        boardHeadHash: null,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: entry.recoveryEpoch,
        deviceEpoch: entry.deviceEpoch,
        contextHash: defaultSignedRootContextHash,
        publicKeyHash: entry.signingPublicKeyHash,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const verifyTrusteeSetupEntry = (
    input: RosterManifestTranscriptInput,
    entry: TrusteeSetupEntry,
    expectedPublicKeyHash: ProtocolHash | undefined,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedHash = deriveTrusteeSetupEntryHash({
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        bgvProfileHash: entry.bgvProfileHash,
        collectivePublicKeyRoot: entry.collectivePublicKeyRoot,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        evaluationKeyRoot: entry.evaluationKeyRoot,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantSetupRecordHash: entry.participantSetupRecordHash,
        publicKeyShareRoot: entry.publicKeyShareRoot,
        recoveryEpoch: entry.recoveryEpoch,
        rotSetHash: entry.rotSetHash,
        rustBgvBackendProfileHash: entry.rustBgvBackendProfileHash,
        setupProfileId: entry.setupProfileId,
        targetDecryptionProfileId: entry.targetDecryptionProfileId,
        thresholdShareVerificationKeyRoot:
            entry.thresholdShareVerificationKeyRoot,
        trusteeThresholdVerificationKeyHash:
            entry.trusteeThresholdVerificationKeyHash,
        trusteeIdentity: entry.trusteeIdentity,
        trusteeSetupRoot: entry.trusteeSetupRoot,
    });

    if (entry.trusteeSetupEntryHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry hash does not match its canonical payload.',
                entry.trusteeSetupEntryHash,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (
        entry.objectType !== 'TrusteeSetupEntry' ||
        entry.objectVersion !== 1 ||
        entry.setupProfileId !== bgvPassiveSetupProfileId ||
        entry.targetDecryptionProfileId !== targetDecryptionProfileId ||
        !isNonNegativeInteger(entry.boardSequence) ||
        !isNonNegativeInteger(entry.boardPosition) ||
        !isNonNegativeInteger(entry.recoveryEpoch) ||
        !isNonNegativeInteger(entry.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry object shape is not canonical.',
                entry.trusteeSetupEntryHash,
                'TrusteeSetupEntry',
            ),
        );
    }
    const requiredSetupHashes = [
        entry.trusteeSetupRoot,
        entry.bgvProfileHash,
        entry.rustBgvBackendProfileHash,
        entry.participantSetupRecordHash,
        entry.publicKeyShareRoot,
        entry.collectivePublicKeyRoot,
        entry.trusteeThresholdVerificationKeyHash,
        entry.thresholdShareVerificationKeyRoot,
        entry.evaluationKeyRoot,
        entry.rotSetHash,
    ];
    if (
        requiredSetupHashes.some(
            (HashField) => !isProtocolHashString(HashField),
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry must bind complete passive BGV setup roots and Hashes.',
                entry.trusteeSetupEntryHash,
                'TrusteeSetupEntry',
            ),
        );
    }
    const manifestBindings = input.electionManifest.manifestOpaqueBindings;
    if (
        entry.bgvProfileHash !== manifestBindings.bgvProfileHash ||
        entry.rustBgvBackendProfileHash !==
            manifestBindings.rustBgvBackendProfileHash ||
        entry.collectivePublicKeyRoot !==
            manifestBindings.collectivePublicKeyRoot ||
        entry.thresholdShareVerificationKeyRoot !==
            manifestBindings.thresholdShareVerificationKeyRoot ||
        entry.evaluationKeyRoot !== manifestBindings.evaluationKeyRoot ||
        entry.rotSetHash !== manifestBindings.rotSetHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry passive BGV setup roots must match the election manifest setup bindings.',
                entry.trusteeSetupEntryHash,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (entry.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Trustee setup entry ceremony does not match the transcript.',
                entry.trusteeSetupEntryHash,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (entry.boardSequence >= input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Trustee setup entry must appear before the roster freeze board sequence.',
                entry.trusteeSetupEntryHash,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (expectedPublicKeyHash === undefined) {
        refusedObjects.push(
            createRefusal(
                'RosterHashMismatch',
                'Trustee setup identity is not in the frozen roster.',
                entry.trusteeSetupEntryHash,
                'TrusteeSetupEntry',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(entry.signature, {
        objectType: 'TrusteeSetupEntry',
        objectVersion: 1,
        signerRole: 'Trustee',
        signerIdentity: entry.trusteeIdentity,
        ceremonyId: input.ceremonyId,
        manifestHash: null,
        objectRoot: entry.trusteeSetupEntryHash,
        boardHeadHash: null,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: entry.recoveryEpoch,
        deviceEpoch: entry.deviceEpoch,
        contextHash: defaultSignedRootContextHash,
        publicKeyHash: expectedPublicKeyHash,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const verifyManifest = (
    input: RosterManifestTranscriptInput,
    rosterHash: ProtocolHash | undefined,
    manifest: ElectionManifest = input.electionManifest,
    manifestInclusionProof: InclusionProof = input.manifestInclusionProof,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedHash = deriveElectionManifestHash({
        boardPosition: manifest.boardPosition,
        boardSequence: manifest.boardSequence,
        ceremonyId: manifest.ceremonyId,
        manifestOpaqueBindings: manifest.manifestOpaqueBindings,
        manifestPolicyHashes: manifest.manifestPolicyHashes,
        objectType: manifest.objectType,
        objectVersion: manifest.objectVersion,
        pollSpecHash: manifest.pollSpecHash,
        rosterHash: manifest.rosterHash,
        thresholdProfileHash: manifest.thresholdProfileHash,
    });

    if (manifest.electionManifestHash !== expectedHash) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Election manifest hash does not match its canonical payload.',
                manifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }
    if (
        manifest.objectType !== 'ElectionManifest' ||
        manifest.objectVersion !== 1 ||
        !isNonNegativeInteger(manifest.boardSequence) ||
        !isNonNegativeInteger(manifest.boardPosition)
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Election manifest object shape is not canonical.',
                manifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }
    refusedObjects.push(...collectManifestOpaqueBindingRefusals(manifest));
    if (manifest.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Election manifest ceremony does not match the transcript.',
                manifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }
    if (rosterHash !== undefined && manifest.rosterHash !== rosterHash) {
        refusedObjects.push(
            createRefusal(
                'RosterHashMismatch',
                'Election manifest roster hash does not match the frozen roster.',
                manifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }
    if (manifest.boardSequence < input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Election manifest must not precede the roster freeze board sequence.',
                manifest.electionManifestHash,
                'ElectionManifest',
            ),
        );
    }
    if (
        manifestInclusionProof.includedObjectType !== 'ElectionManifest' ||
        manifestInclusionProof.includedObjectHash !==
            manifest.electionManifestHash
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Manifest inclusion proof does not bind the election manifest hash.',
                manifestInclusionProof.inclusionProofHash,
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(manifest.signature, {
        objectType: 'ElectionManifest',
        objectVersion: 1,
        signerRole: 'Organizer',
        signerIdentity: input.organizerIdentity,
        ceremonyId: input.ceremonyId,
        manifestHash: null,
        objectRoot: manifest.electionManifestHash,
        boardHeadHash: null,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        contextHash: defaultSignedRootContextHash,
        publicKeyHash: input.organizerPublicKeyHash,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const verifyRosterExternalAcceptance = (
    input: RosterExternalAcceptanceVerificationInput,
): RosterExternalAcceptanceVerification => {
    try {
        const { acceptance } = input;
        const refusedObjects: RefusalRecord[] = [];
        const expectedHash = deriveRosterExternalAcceptanceHash({
            acceptedBoardHeadHash: acceptance.acceptedBoardHeadHash,
            ceremonyId: acceptance.ceremonyId,
            electionManifestHash: acceptance.electionManifestHash,
            objectType: acceptance.objectType,
            objectVersion: acceptance.objectVersion,
            participantIdentity: acceptance.participantIdentity,
            rosterHash: acceptance.rosterHash,
            warningTextVersion: acceptance.warningTextVersion,
        });

        if (acceptance.rosterExternalAcceptanceHash !== expectedHash) {
            refusedObjects.push(
                createRefusal(
                    'RosterExternalAcceptanceInvalid',
                    'Roster external acceptance hash does not match its canonical payload.',
                    acceptance.rosterExternalAcceptanceHash,
                    'RosterExternalAcceptance',
                ),
            );
        }
        if (
            acceptance.objectType !== 'RosterExternalAcceptance' ||
            acceptance.objectVersion !== 1 ||
            acceptance.ceremonyId !== input.expectedCeremonyId ||
            acceptance.rosterHash !== input.expectedRosterHash ||
            acceptance.electionManifestHash !==
                input.expectedElectionManifestHash ||
            acceptance.acceptedBoardHeadHash !==
                input.expectedAcceptedBoardHeadHash ||
            acceptance.warningTextVersion.trim().length === 0
        ) {
            refusedObjects.push(
                createRefusal(
                    'RosterExternalAcceptanceInvalid',
                    'Roster external acceptance does not bind the expected frozen roster view.',
                    acceptance.rosterExternalAcceptanceHash,
                    'RosterExternalAcceptance',
                ),
            );
        }

        const signatureResult = verifySignedObjectSignature(
            acceptance.signature,
            {
                objectType: 'RosterExternalAcceptance',
                objectVersion: 1,
                signerRole: 'Participant',
                signerIdentity: acceptance.participantIdentity,
                ceremonyId: acceptance.ceremonyId,
                manifestHash: acceptance.electionManifestHash,
                objectRoot: acceptance.rosterExternalAcceptanceHash,
                boardHeadHash: acceptance.acceptedBoardHeadHash,
                byteLength: signedObjectRootByteLength,
                recoveryEpoch: 0,
                deviceEpoch: 0,
                contextHash: defaultSignedRootContextHash,
                publicKeyHash: input.expectedParticipantPublicKeyHash,
            },
        );
        refusedObjects.push(...signatureResult.refusedObjects);

        return {
            ok: refusedObjects.length === 0,
            acceptedHashes:
                refusedObjects.length === 0
                    ? [acceptance.rosterExternalAcceptanceHash]
                    : [],
            refusedObjects,
            rosterExternalAcceptanceHash:
                refusedObjects.length === 0
                    ? acceptance.rosterExternalAcceptanceHash
                    : undefined,
        };
    } catch {
        return {
            ok: false,
            acceptedHashes: [],
            refusedObjects: [
                createRefusal(
                    'RosterExternalAcceptanceInvalid',
                    'Roster external acceptance could not be canonicalized or validated.',
                    undefined,
                    'RosterExternalAcceptance',
                ),
            ],
        };
    }
};
