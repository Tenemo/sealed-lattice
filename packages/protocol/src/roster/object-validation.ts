import { verifySignedObjectSignature } from '@sealed-lattice/crypto';
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
} from '../common/verification-helpers.js';

import {
    deriveElectionManifestHash,
    deriveRegistrationEntryHash,
    deriveRosterExternalAcceptanceHash,
    deriveTrusteeSetupEntryHash,
} from './hashes.js';

const requiredManifestOpaqueBindingFieldNames = [
    'bgvParametersHash',
    'collectivePublicKeyRoot',
    'targetLayoutHash',
    'rotSetHash',
    'evaluationKeyRoot',
    'thresholdShareVerificationKeyRoot',
] as const;

const collectManifestOpaqueBindingRefusals = (
    manifest: ElectionManifest,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const bindings = manifest.manifestOpaqueBindings;
    const requiredHashFields = requiredManifestOpaqueBindingFieldNames.map(
        (fieldName) => bindings[fieldName],
    );

    if (
        requiredHashFields.some((HashField) => !isProtocolHashString(HashField))
    ) {
        refusedObjects.push(
            createRefusal(
                'ManifestHashMismatch',
                'Election manifest opaque bindings must include canonical setup and target bindings.',
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
        signerRole: 'Participant',
        signerIdentity: entry.participantIdentity,
        ceremonyId: input.ceremonyId,
        manifestHash: null,
        objectRoot: entry.registrationEntryHash,
        boardHeadHash: null,
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
        bgvParametersHash: entry.bgvParametersHash,
        collectivePublicKeyRoot: entry.collectivePublicKeyRoot,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        evaluationKeyRoot: entry.evaluationKeyRoot,
        objectType: entry.objectType,
        participantSetupRecordHash: entry.participantSetupRecordHash,
        publicKeyShareRoot: entry.publicKeyShareRoot,
        recoveryEpoch: entry.recoveryEpoch,
        rotSetHash: entry.rotSetHash,
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
        entry.bgvParametersHash,
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
        entry.bgvParametersHash !== manifestBindings.bgvParametersHash ||
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
        signerRole: 'Trustee',
        signerIdentity: entry.trusteeIdentity,
        ceremonyId: input.ceremonyId,
        manifestHash: null,
        objectRoot: entry.trusteeSetupEntryHash,
        boardHeadHash: null,
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
        pollSpecHash: manifest.pollSpecHash,
        rosterHash: manifest.rosterHash,
        thresholdParametersHash: manifest.thresholdParametersHash,
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
        signerRole: 'Organizer',
        signerIdentity: input.organizerIdentity,
        ceremonyId: input.ceremonyId,
        manifestHash: null,
        objectRoot: manifest.electionManifestHash,
        boardHeadHash: null,
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
                signerRole: 'Participant',
                signerIdentity: acceptance.participantIdentity,
                ceremonyId: acceptance.ceremonyId,
                manifestHash: acceptance.electionManifestHash,
                objectRoot: acceptance.rosterExternalAcceptanceHash,
                boardHeadHash: acceptance.acceptedBoardHeadHash,
                recoveryEpoch: 0,
                deviceEpoch: 0,
                contextHash: defaultSignedRootContextHash,
                publicKeyHash: input.expectedParticipantPublicKeyHash,
            },
        );
        refusedObjects.push(...signatureResult.refusedObjects);

        return {
            isValid: refusedObjects.length === 0,
            refusedObjects,
            rosterExternalAcceptanceHash:
                refusedObjects.length === 0
                    ? acceptance.rosterExternalAcceptanceHash
                    : undefined,
        };
    } catch {
        return {
            isValid: false,
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
