import { verifySignedObjectSignature } from '@sealed-lattice/crypto';
import {
    bgvPassiveSetupProfileId,
    bridgeWitnessPrivacyProfileId,
    cpadProfileId,
    encryptedAggregateBridgeProfileId,
    evaluationProofProfileId,
    mobileProfileId,
    thresholdDecryptionProfileId,
} from '@sealed-lattice/types';
import type {
    ElectionManifest,
    InclusionProof,
    ProtocolDigest,
    ReceiverKeyRegistration,
    RefusalRecord,
    RegistrationEntry,
    RosterExternalAcceptanceVerification,
    RosterExternalAcceptanceVerificationInput,
    RosterManifestTranscriptInput,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import {
    createRefusal,
    defaultSignedRootContextDigest,
    isNonNegativeInteger,
    signedObjectRootByteLength,
} from '../common/verification-helpers.js';

import {
    deriveElectionManifestDigest,
    deriveReceiverKeyRegistrationDigest,
    deriveRegistrationEntryDigest,
    deriveRosterExternalAcceptanceDigest,
    deriveTrusteeSetupEntryDigest,
} from './digests.js';

const protocolDigestPattern = /^[0-9a-f]{128}$/u;

const isProtocolDigestString = (value: ProtocolDigest): boolean =>
    protocolDigestPattern.test(value);

const manifestOpaqueBindingFieldNames = new Set([
    'encryptedAggregateBridgeProfileId',
    'bgvPassiveSetupProfileId',
    'bridgeWitnessPrivacyProfileId',
    'heParamDigest',
    'bgvPassiveSetupPackageDigest',
    'bgvSetupParameterCertificateDigest',
    'bgvProfileDigest',
    'rustBgvBackendProfileDigest',
    'bgvPublicKeyRoot',
    'collectivePublicKeyRoot',
    'collectiveSecretDistributionCertificateDigest',
    'errorDistributionCertificateDigest',
    'keySwitchDecompositionDigest',
    'canonicalCiphertextConventionDigest',
    'encryptedAggregateBridgeDigest',
    'bridgeWitnessPrivacyProfileDigest',
    'bgvBatchEncoderDigest',
    'bridgeLayoutDigest',
    'encryptedAggregateInputRoot',
    'encryptedAggregateShareCiphertextRoot',
    'encryptedAggregateReconstructionDigest',
    'scoreBitDerivationCircuitDigest',
    'encryptedScoreBitInputDigest',
    'comparisonInputDerivationCircuitDigest',
    'encryptedComparisonInputDigest',
    'evaluationNoiseProfileDigest',
    'heEvaluationNoiseCertDigest',
    'allowedEvaluatorOpsDigest',
    'rotSetDigest',
    'evaluationKeyRoot',
    'evaluationKeySizeProfileDigest',
    'thresholdShareVerificationKeyRoot',
    'thresholdShareVerificationKeyDigest',
    'evaluationProofProfileId',
    'evaluationProofProfileDigest',
    'thresholdDecryptionProfileId',
    'thresholdDecryptionProfileDigest',
    'kllpsTargetDecryptionProfileDigest',
    'cpadProfileId',
    'cpadProfileDigest',
    'targetBasisDigest',
    'mobileProfileId',
    'bridgeBenchmarkReportPolicyDigest',
]);

const manifestOpaqueBindingFieldCount = manifestOpaqueBindingFieldNames.size;

const collectManifestOpaqueBindingRefusals = (
    manifest: ElectionManifest,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const bindings = manifest.manifestOpaqueBindings;

    if (
        bindings.encryptedAggregateBridgeProfileId !==
            encryptedAggregateBridgeProfileId ||
        bindings.bgvPassiveSetupProfileId !== bgvPassiveSetupProfileId ||
        bindings.bridgeWitnessPrivacyProfileId !==
            bridgeWitnessPrivacyProfileId ||
        bindings.evaluationProofProfileId !== evaluationProofProfileId ||
        bindings.thresholdDecryptionProfileId !==
            thresholdDecryptionProfileId ||
        bindings.cpadProfileId !== cpadProfileId ||
        bindings.mobileProfileId !== mobileProfileId
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest must bind the fixed packed BGV bridge, evaluation-proof, threshold-decryption, CPAD, and mobile profile identifiers.',
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    const bindingFieldNames = Object.keys(bindings);
    if (
        bindingFieldNames.length !== manifestOpaqueBindingFieldCount ||
        bindingFieldNames.some(
            (fieldName) => !manifestOpaqueBindingFieldNames.has(fieldName),
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest opaque bindings must use the current encrypted-aggregate profile schema.',
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }

    const requiredDigestFields = [
        bindings.heParamDigest,
        bindings.bgvPassiveSetupPackageDigest,
        bindings.bgvSetupParameterCertificateDigest,
        bindings.bgvProfileDigest,
        bindings.rustBgvBackendProfileDigest,
        bindings.bgvPublicKeyRoot,
        bindings.collectivePublicKeyRoot,
        bindings.collectiveSecretDistributionCertificateDigest,
        bindings.errorDistributionCertificateDigest,
        bindings.keySwitchDecompositionDigest,
        bindings.canonicalCiphertextConventionDigest,
        bindings.encryptedAggregateBridgeDigest,
        bindings.bridgeWitnessPrivacyProfileDigest,
        bindings.bgvBatchEncoderDigest,
        bindings.bridgeLayoutDigest,
        bindings.encryptedAggregateInputRoot,
        bindings.encryptedAggregateShareCiphertextRoot,
        bindings.encryptedAggregateReconstructionDigest,
        bindings.scoreBitDerivationCircuitDigest,
        bindings.encryptedScoreBitInputDigest,
        bindings.comparisonInputDerivationCircuitDigest,
        bindings.encryptedComparisonInputDigest,
        bindings.evaluationNoiseProfileDigest,
        bindings.heEvaluationNoiseCertDigest,
        bindings.allowedEvaluatorOpsDigest,
        bindings.rotSetDigest,
        bindings.evaluationKeyRoot,
        bindings.evaluationKeySizeProfileDigest,
        bindings.thresholdShareVerificationKeyRoot,
        bindings.thresholdShareVerificationKeyDigest,
        bindings.evaluationProofProfileDigest,
        bindings.thresholdDecryptionProfileDigest,
        bindings.kllpsTargetDecryptionProfileDigest,
        bindings.cpadProfileDigest,
        bindings.targetBasisDigest,
        bindings.bridgeBenchmarkReportPolicyDigest,
    ];

    if (
        requiredDigestFields.some(
            (digestField) => !isProtocolDigestString(digestField),
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest opaque bindings must include canonical downstream profile and certificate digests.',
                manifest.electionManifestDigest,
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
    const expectedDigest = deriveRegistrationEntryDigest({
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantIdentity: entry.participantIdentity,
        recoveryEpoch: entry.recoveryEpoch,
        signingPublicKeyDigest: entry.signingPublicKeyDigest,
    });

    if (entry.registrationEntryDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Registration entry digest does not match its canonical payload.',
                entry.registrationEntryDigest,
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
                entry.registrationEntryDigest,
                'RegistrationEntry',
            ),
        );
    }
    if (entry.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Registration entry ceremony does not match the transcript.',
                entry.registrationEntryDigest,
                'RegistrationEntry',
            ),
        );
    }
    if (entry.boardSequence >= input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Registration entry must appear before the roster freeze board sequence.',
                entry.registrationEntryDigest,
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
        manifestDigest: null,
        objectRoot: entry.registrationEntryDigest,
        boardHeadDigest: null,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: entry.recoveryEpoch,
        deviceEpoch: entry.deviceEpoch,
        contextDigest: defaultSignedRootContextDigest,
        publicKeyDigest: entry.signingPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const verifyReceiverKeyRegistration = (
    input: RosterManifestTranscriptInput,
    entry: ReceiverKeyRegistration,
    expectedPublicKeyDigest: ProtocolDigest | undefined,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveReceiverKeyRegistrationDigest({
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantIdentity: entry.participantIdentity,
        receiverKeyRoot: entry.receiverKeyRoot,
        recoveryEpoch: entry.recoveryEpoch,
    });

    if (entry.receiverKeyRegistrationDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Receiver-key registration digest does not match its canonical payload.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }
    if (
        entry.objectType !== 'ReceiverKeyRegistration' ||
        entry.objectVersion !== 1 ||
        !isNonNegativeInteger(entry.boardSequence) ||
        !isNonNegativeInteger(entry.boardPosition) ||
        !isNonNegativeInteger(entry.recoveryEpoch) ||
        !isNonNegativeInteger(entry.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Receiver-key registration object shape is not canonical.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }
    if (entry.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Receiver-key registration ceremony does not match the transcript.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }
    if (entry.boardSequence >= input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Receiver-key registration must appear before the roster freeze board sequence.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }
    if (expectedPublicKeyDigest === undefined) {
        refusedObjects.push(
            createRefusal(
                'RosterDigestMismatch',
                'Receiver-key registration identity is not in the frozen roster.',
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(entry.signature, {
        objectType: 'ReceiverKeyRegistration',
        objectVersion: 1,
        signerRole: 'Participant',
        signerIdentity: entry.participantIdentity,
        ceremonyId: input.ceremonyId,
        manifestDigest: null,
        objectRoot: entry.receiverKeyRegistrationDigest,
        boardHeadDigest: null,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: entry.recoveryEpoch,
        deviceEpoch: entry.deviceEpoch,
        contextDigest: defaultSignedRootContextDigest,
        publicKeyDigest: expectedPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const verifyTrusteeSetupEntry = (
    input: RosterManifestTranscriptInput,
    entry: TrusteeSetupEntry,
    expectedPublicKeyDigest: ProtocolDigest | undefined,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveTrusteeSetupEntryDigest({
        boardPosition: entry.boardPosition,
        boardSequence: entry.boardSequence,
        bgvProfileDigest: entry.bgvProfileDigest,
        collectivePublicKeyRoot: entry.collectivePublicKeyRoot,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        evaluationKeyRoot: entry.evaluationKeyRoot,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantSetupRecordDigest: entry.participantSetupRecordDigest,
        publicKeyShareRoot: entry.publicKeyShareRoot,
        recoveryEpoch: entry.recoveryEpoch,
        rotSetDigest: entry.rotSetDigest,
        rustBgvBackendProfileDigest: entry.rustBgvBackendProfileDigest,
        setupProfileId: entry.setupProfileId,
        thresholdDecryptionProfileId: entry.thresholdDecryptionProfileId,
        thresholdShareVerificationKeyRoot:
            entry.thresholdShareVerificationKeyRoot,
        trusteeThresholdVerificationKeyDigest:
            entry.trusteeThresholdVerificationKeyDigest,
        trusteeIdentity: entry.trusteeIdentity,
        trusteeSetupRoot: entry.trusteeSetupRoot,
    });

    if (entry.trusteeSetupEntryDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry digest does not match its canonical payload.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (
        entry.objectType !== 'TrusteeSetupEntry' ||
        entry.objectVersion !== 1 ||
        entry.setupProfileId !== bgvPassiveSetupProfileId ||
        entry.thresholdDecryptionProfileId !== thresholdDecryptionProfileId ||
        !isNonNegativeInteger(entry.boardSequence) ||
        !isNonNegativeInteger(entry.boardPosition) ||
        !isNonNegativeInteger(entry.recoveryEpoch) ||
        !isNonNegativeInteger(entry.deviceEpoch)
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry object shape is not canonical.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    const requiredSetupDigests = [
        entry.trusteeSetupRoot,
        entry.bgvProfileDigest,
        entry.rustBgvBackendProfileDigest,
        entry.participantSetupRecordDigest,
        entry.publicKeyShareRoot,
        entry.collectivePublicKeyRoot,
        entry.trusteeThresholdVerificationKeyDigest,
        entry.thresholdShareVerificationKeyRoot,
        entry.evaluationKeyRoot,
        entry.rotSetDigest,
    ];
    if (
        requiredSetupDigests.some(
            (digestField) => !isProtocolDigestString(digestField),
        )
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry must bind complete M8 setup roots and digests.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    const manifestBindings = input.electionManifest.manifestOpaqueBindings;
    if (
        entry.bgvProfileDigest !== manifestBindings.bgvProfileDigest ||
        entry.rustBgvBackendProfileDigest !==
            manifestBindings.rustBgvBackendProfileDigest ||
        entry.collectivePublicKeyRoot !==
            manifestBindings.collectivePublicKeyRoot ||
        entry.thresholdShareVerificationKeyRoot !==
            manifestBindings.thresholdShareVerificationKeyRoot ||
        entry.evaluationKeyRoot !== manifestBindings.evaluationKeyRoot ||
        entry.rotSetDigest !== manifestBindings.rotSetDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InvalidSignedRoot',
                'Trustee setup entry M8 roots must match the election manifest setup bindings.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (entry.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Trustee setup entry ceremony does not match the transcript.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (entry.boardSequence >= input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Trustee setup entry must appear before the roster freeze board sequence.',
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
            ),
        );
    }
    if (expectedPublicKeyDigest === undefined) {
        refusedObjects.push(
            createRefusal(
                'RosterDigestMismatch',
                'Trustee setup identity is not in the frozen roster.',
                entry.trusteeSetupEntryDigest,
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
        manifestDigest: null,
        objectRoot: entry.trusteeSetupEntryDigest,
        boardHeadDigest: null,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: entry.recoveryEpoch,
        deviceEpoch: entry.deviceEpoch,
        contextDigest: defaultSignedRootContextDigest,
        publicKeyDigest: expectedPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

export const verifyManifest = (
    input: RosterManifestTranscriptInput,
    rosterDigest: ProtocolDigest | undefined,
    manifest: ElectionManifest = input.electionManifest,
    manifestInclusionProof: InclusionProof = input.manifestInclusionProof,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveElectionManifestDigest({
        boardPosition: manifest.boardPosition,
        boardSequence: manifest.boardSequence,
        ceremonyId: manifest.ceremonyId,
        manifestOpaqueBindings: manifest.manifestOpaqueBindings,
        manifestPolicyDigests: manifest.manifestPolicyDigests,
        objectType: manifest.objectType,
        objectVersion: manifest.objectVersion,
        pollSpecDigest: manifest.pollSpecDigest,
        rosterDigest: manifest.rosterDigest,
        thresholdProfileDigest: manifest.thresholdProfileDigest,
    });

    if (manifest.electionManifestDigest !== expectedDigest) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest digest does not match its canonical payload.',
                manifest.electionManifestDigest,
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
                'ManifestDigestMismatch',
                'Election manifest object shape is not canonical.',
                manifest.electionManifestDigest,
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
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    if (rosterDigest !== undefined && manifest.rosterDigest !== rosterDigest) {
        refusedObjects.push(
            createRefusal(
                'RosterDigestMismatch',
                'Election manifest roster digest does not match the frozen roster.',
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    if (manifest.boardSequence < input.rosterFreezeBoardSequence) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest must not precede the roster freeze board sequence.',
                manifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }
    if (
        manifestInclusionProof.includedObjectType !== 'ElectionManifest' ||
        manifestInclusionProof.includedObjectDigest !==
            manifest.electionManifestDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Manifest inclusion proof does not bind the election manifest digest.',
                manifestInclusionProof.inclusionProofDigest,
            ),
        );
    }

    const signatureResult = verifySignedObjectSignature(manifest.signature, {
        objectType: 'ElectionManifest',
        objectVersion: 1,
        signerRole: 'Organizer',
        signerIdentity: input.organizerIdentity,
        ceremonyId: input.ceremonyId,
        manifestDigest: null,
        objectRoot: manifest.electionManifestDigest,
        boardHeadDigest: null,
        byteLength: signedObjectRootByteLength,
        recoveryEpoch: 0,
        deviceEpoch: 0,
        contextDigest: defaultSignedRootContextDigest,
        publicKeyDigest: input.organizerPublicKeyDigest,
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
        const expectedDigest = deriveRosterExternalAcceptanceDigest({
            acceptedBoardHeadDigest: acceptance.acceptedBoardHeadDigest,
            ceremonyId: acceptance.ceremonyId,
            electionManifestDigest: acceptance.electionManifestDigest,
            objectType: acceptance.objectType,
            objectVersion: acceptance.objectVersion,
            participantIdentity: acceptance.participantIdentity,
            rosterDigest: acceptance.rosterDigest,
            warningTextVersion: acceptance.warningTextVersion,
        });

        if (acceptance.rosterExternalAcceptanceDigest !== expectedDigest) {
            refusedObjects.push(
                createRefusal(
                    'RosterExternalAcceptanceInvalid',
                    'Roster external acceptance digest does not match its canonical payload.',
                    acceptance.rosterExternalAcceptanceDigest,
                    'RosterExternalAcceptance',
                ),
            );
        }
        if (
            acceptance.objectType !== 'RosterExternalAcceptance' ||
            acceptance.objectVersion !== 1 ||
            acceptance.ceremonyId !== input.expectedCeremonyId ||
            acceptance.rosterDigest !== input.expectedRosterDigest ||
            acceptance.electionManifestDigest !==
                input.expectedElectionManifestDigest ||
            acceptance.acceptedBoardHeadDigest !==
                input.expectedAcceptedBoardHeadDigest ||
            acceptance.warningTextVersion.trim().length === 0
        ) {
            refusedObjects.push(
                createRefusal(
                    'RosterExternalAcceptanceInvalid',
                    'Roster external acceptance does not bind the expected frozen roster view.',
                    acceptance.rosterExternalAcceptanceDigest,
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
                manifestDigest: acceptance.electionManifestDigest,
                objectRoot: acceptance.rosterExternalAcceptanceDigest,
                boardHeadDigest: acceptance.acceptedBoardHeadDigest,
                byteLength: signedObjectRootByteLength,
                recoveryEpoch: 0,
                deviceEpoch: 0,
                contextDigest: defaultSignedRootContextDigest,
                publicKeyDigest: input.expectedParticipantPublicKeyDigest,
            },
        );
        refusedObjects.push(...signatureResult.refusedObjects);

        return {
            ok: refusedObjects.length === 0,
            statusLabels: refusedObjects.length === 0 ? ['rosterFrozen'] : [],
            acceptedDigests:
                refusedObjects.length === 0
                    ? [acceptance.rosterExternalAcceptanceDigest]
                    : [],
            refusedObjects,
            rosterExternalAcceptanceDigest:
                refusedObjects.length === 0
                    ? acceptance.rosterExternalAcceptanceDigest
                    : undefined,
        };
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
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
