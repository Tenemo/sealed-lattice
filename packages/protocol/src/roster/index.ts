import type {
    ElectionManifest,
    InclusionProof,
    ProtocolDigest,
    ProtocolVerificationStatusLabel,
    ReceiverKeyRegistration,
    RefusalRecord,
    RegistrationEntry,
    RosterManifestTranscriptInput,
    RosterManifestTranscriptVerification,
    SignedBoardHead,
    TrusteeSetupEntry,
} from '@sealed-lattice/types';

import {
    verifyBoardConsistency,
    verifyInclusionProof,
} from '../board/index.js';
import { deriveProtocolDigest } from '../common/digests.js';
import { verifySignedObjectSignature } from '../common/signatures.js';
import {
    createRefusal,
    uniqueStrings,
} from '../common/verification-helpers.js';

const isNonNegativeInteger = (value: number): boolean =>
    Number.isInteger(value) && value >= 0;

const buildHeadMap = (
    heads: readonly SignedBoardHead[],
): Map<ProtocolDigest, SignedBoardHead> =>
    new Map(heads.map((head) => [head.headDigest, head]));

const mapInclusionProofsByObjectDigest = (
    inclusionProofs: readonly InclusionProof[],
): Map<ProtocolDigest, InclusionProof> =>
    new Map(
        inclusionProofs.map((proof) => [proof.includedObjectDigest, proof]),
    );

export const deriveRegistrationEntryDigest = (
    entry: Omit<RegistrationEntry, 'registrationEntryDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('RegistrationEntryDigest', {
        boardPosition: entry.boardPosition,
        boardSeq: entry.boardSeq,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantIdentity: entry.participantIdentity,
        recoveryEpoch: entry.recoveryEpoch,
        signingPublicKeyDigest: entry.signingPublicKeyDigest,
    });

export const deriveReceiverKeyRegistrationDigest = (
    entry: Omit<
        ReceiverKeyRegistration,
        'receiverKeyRegistrationDigest' | 'signature'
    >,
): ProtocolDigest =>
    deriveProtocolDigest('ReceiverKeyRegistrationDigest', {
        boardPosition: entry.boardPosition,
        boardSeq: entry.boardSeq,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        participantIdentity: entry.participantIdentity,
        receiverKeyRoot: entry.receiverKeyRoot,
        recoveryEpoch: entry.recoveryEpoch,
    });

export const deriveTrusteeSetupEntryDigest = (
    entry: Omit<TrusteeSetupEntry, 'trusteeSetupEntryDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('TrusteeSetupEntryDigest', {
        boardPosition: entry.boardPosition,
        boardSeq: entry.boardSeq,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        recoveryEpoch: entry.recoveryEpoch,
        trusteeIdentity: entry.trusteeIdentity,
        trusteeSetupRoot: entry.trusteeSetupRoot,
    });

export const deriveRosterDigest = (
    entries: readonly RegistrationEntry[],
): ProtocolDigest =>
    deriveProtocolDigest(
        'RosterDigest',
        entries
            .map((entry) => ({
                participantIdentity: entry.participantIdentity,
                registrationEntryDigest: entry.registrationEntryDigest,
                signingPublicKeyDigest: entry.signingPublicKeyDigest,
            }))
            .sort((left, right) =>
                left.participantIdentity.localeCompare(
                    right.participantIdentity,
                ),
            ),
    );

export const deriveElectionManifestDigest = (
    manifest: Omit<ElectionManifest, 'electionManifestDigest' | 'signature'>,
): ProtocolDigest =>
    deriveProtocolDigest('ElectionManifestDigest', {
        boardPosition: manifest.boardPosition,
        boardSeq: manifest.boardSeq,
        ceremonyId: manifest.ceremonyId,
        manifestOpaqueBindings: manifest.manifestOpaqueBindings,
        manifestPolicyDigests: manifest.manifestPolicyDigests,
        objectType: manifest.objectType,
        objectVersion: manifest.objectVersion,
        pollSpecDigest: manifest.pollSpecDigest,
        rosterDigest: manifest.rosterDigest,
        thresholdProfileDigest: manifest.thresholdProfileDigest,
    });

const verifyRegistrationEntry = (
    input: RosterManifestTranscriptInput,
    entry: RegistrationEntry,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveRegistrationEntryDigest({
        boardPosition: entry.boardPosition,
        boardSeq: entry.boardSeq,
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
        !isNonNegativeInteger(entry.boardSeq) ||
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
    if (entry.boardSeq >= input.rosterFreezeBoardSeq) {
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
        manifestHash: null,
        objectRoot: entry.registrationEntryDigest,
        boardHeadHash: null,
        publicKeyDigest: entry.signingPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

const verifyReceiverKeyRegistration = (
    input: RosterManifestTranscriptInput,
    entry: ReceiverKeyRegistration,
    expectedPublicKeyDigest: ProtocolDigest | undefined,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveReceiverKeyRegistrationDigest({
        boardPosition: entry.boardPosition,
        boardSeq: entry.boardSeq,
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
        !isNonNegativeInteger(entry.boardSeq) ||
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
    if (entry.boardSeq >= input.rosterFreezeBoardSeq) {
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
        manifestHash: null,
        objectRoot: entry.receiverKeyRegistrationDigest,
        boardHeadHash: null,
        publicKeyDigest: expectedPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

const verifyTrusteeSetupEntry = (
    input: RosterManifestTranscriptInput,
    entry: TrusteeSetupEntry,
    expectedPublicKeyDigest: ProtocolDigest | undefined,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveTrusteeSetupEntryDigest({
        boardPosition: entry.boardPosition,
        boardSeq: entry.boardSeq,
        ceremonyId: entry.ceremonyId,
        deviceEpoch: entry.deviceEpoch,
        objectType: entry.objectType,
        objectVersion: entry.objectVersion,
        recoveryEpoch: entry.recoveryEpoch,
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
        !isNonNegativeInteger(entry.boardSeq) ||
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
    if (entry.boardSeq >= input.rosterFreezeBoardSeq) {
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
        manifestHash: null,
        objectRoot: entry.trusteeSetupEntryDigest,
        boardHeadHash: null,
        publicKeyDigest: expectedPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

const verifyManifest = (
    input: RosterManifestTranscriptInput,
    rosterDigest: ProtocolDigest | undefined,
    manifest: ElectionManifest = input.electionManifest,
    manifestInclusionProof: InclusionProof = input.manifestInclusionProof,
): readonly RefusalRecord[] => {
    const refusedObjects: RefusalRecord[] = [];
    const expectedDigest = deriveElectionManifestDigest({
        boardPosition: manifest.boardPosition,
        boardSeq: manifest.boardSeq,
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
        !isNonNegativeInteger(manifest.boardSeq) ||
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
    if (manifest.boardSeq < input.rosterFreezeBoardSeq) {
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
        manifestHash: null,
        objectRoot: manifest.electionManifestDigest,
        boardHeadHash: null,
        publicKeyDigest: input.organizerPublicKeyDigest,
    });
    refusedObjects.push(...signatureResult.refusedObjects);

    return refusedObjects;
};

const verifyRequiredInclusionProof = (
    proofByDigest: ReadonlyMap<ProtocolDigest, InclusionProof>,
    objectDigest: ProtocolDigest,
    expectedObjectType: InclusionProof['includedObjectType'],
    headsByDigest: ReadonlyMap<ProtocolDigest, SignedBoardHead>,
): readonly RefusalRecord[] => {
    const proof = proofByDigest.get(objectDigest);
    if (proof === undefined) {
        return [
            createRefusal(
                'InclusionProofInvalid',
                'Required transcript object has no supplied board inclusion proof.',
                objectDigest,
                expectedObjectType,
            ),
        ];
    }
    const refusedObjects: RefusalRecord[] = [];
    if (
        proof.includedObjectType !== expectedObjectType ||
        proof.includedObjectDigest !== objectDigest
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Board inclusion proof does not bind the expected object.',
                proof.inclusionProofDigest,
                expectedObjectType,
            ),
        );
    }
    refusedObjects.push(...verifyInclusionProof(proof, headsByDigest));

    return refusedObjects;
};

const verifyIncludedBoardPlacement = (
    proofByDigest: ReadonlyMap<ProtocolDigest, InclusionProof>,
    objectDigest: ProtocolDigest,
    expectedObjectType: InclusionProof['includedObjectType'],
    objectBoardSeq: number,
    objectBoardPosition: number,
    rosterFreezeBoardSeq: number | undefined,
): readonly RefusalRecord[] => {
    const proof = proofByDigest.get(objectDigest);
    if (proof === undefined) {
        return [];
    }
    const refusedObjects: RefusalRecord[] = [];

    if (
        proof.includedObjectType !== expectedObjectType ||
        proof.includedObjectDigest !== objectDigest
    ) {
        return refusedObjects;
    }
    if (
        proof.boardSeq !== objectBoardSeq ||
        proof.boardPosition !== objectBoardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Transcript object board position must match its inclusion proof.',
                objectDigest,
                expectedObjectType,
            ),
        );
    }
    if (
        rosterFreezeBoardSeq !== undefined &&
        proof.boardSeq >= rosterFreezeBoardSeq
    ) {
        refusedObjects.push(
            createRefusal(
                'LateRegistration',
                'Roster object inclusion must appear before the roster freeze board sequence.',
                objectDigest,
                expectedObjectType,
            ),
        );
    }

    return refusedObjects;
};

const findConflictingRawManifest = (
    input: RosterManifestTranscriptInput,
): ElectionManifest | undefined => {
    const acceptedManifest = input.electionManifest;

    return input.suppliedElectionManifests?.find(
        (manifest) =>
            manifest.ceremonyId === acceptedManifest.ceremonyId &&
            manifest.pollSpecDigest === acceptedManifest.pollSpecDigest &&
            manifest.electionManifestDigest !==
                acceptedManifest.electionManifestDigest,
    );
};

const verifyRosterManifestTranscriptUnchecked = (
    input: RosterManifestTranscriptInput,
): RosterManifestTranscriptVerification => {
    const refusedObjects: RefusalRecord[] = [];
    const boardResult = verifyBoardConsistency(input.boardEvidence);
    const headsByDigest = buildHeadMap(input.boardEvidence.signedBoardHeads);
    const registrationProofsByDigest = mapInclusionProofsByObjectDigest(
        input.registrationInclusionProofs,
    );
    const receiverProofsByDigest = mapInclusionProofsByObjectDigest(
        input.receiverKeyRegistrationInclusionProofs,
    );
    const trusteeProofsByDigest = mapInclusionProofsByObjectDigest(
        input.trusteeSetupInclusionProofs,
    );
    const participantIdentities: string[] = [];
    const participantPublicKeys = new Map<string, ProtocolDigest>();
    const seenParticipantIdentities = new Set<string>();

    refusedObjects.push(...boardResult.refusedObjects);
    if (input.boardEvidence.ceremonyId !== input.ceremonyId) {
        refusedObjects.push(
            createRefusal(
                'WrongCeremony',
                'Roster-manifest board evidence ceremony does not match the transcript.',
            ),
        );
    }

    for (const entry of input.registrationEntries) {
        refusedObjects.push(...verifyRegistrationEntry(input, entry));
        refusedObjects.push(
            ...verifyRequiredInclusionProof(
                registrationProofsByDigest,
                entry.registrationEntryDigest,
                'RegistrationEntry',
                headsByDigest,
            ),
            ...verifyIncludedBoardPlacement(
                registrationProofsByDigest,
                entry.registrationEntryDigest,
                'RegistrationEntry',
                entry.boardSeq,
                entry.boardPosition,
                input.rosterFreezeBoardSeq,
            ),
        );

        if (seenParticipantIdentities.has(entry.participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateRegistration',
                    'Roster freeze rejects duplicate participant registrations.',
                    entry.registrationEntryDigest,
                    'RegistrationEntry',
                ),
            );
            continue;
        }

        seenParticipantIdentities.add(entry.participantIdentity);
        participantPublicKeys.set(
            entry.participantIdentity,
            entry.signingPublicKeyDigest,
        );
        participantIdentities.push(entry.participantIdentity);
    }

    const organizerPublicKeyDigest = participantPublicKeys.get(
        input.organizerIdentity,
    );
    if (organizerPublicKeyDigest === undefined) {
        refusedObjects.push(
            createRefusal(
                'RosterDigestMismatch',
                'Organizer identity must be part of the frozen all-trustee roster.',
            ),
        );
    } else if (organizerPublicKeyDigest !== input.organizerPublicKeyDigest) {
        refusedObjects.push(
            createRefusal(
                'WrongPublicKey',
                'Organizer public key must match the organizer roster registration.',
            ),
        );
    }

    const receiverIdentities = new Set<string>();
    for (const entry of input.receiverKeyRegistrations) {
        if (receiverIdentities.has(entry.participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateReceiverKeyRegistration',
                    'Roster freeze rejects duplicate receiver-key registrations.',
                    entry.receiverKeyRegistrationDigest,
                    'ReceiverKeyRegistration',
                ),
            );
        }
        receiverIdentities.add(entry.participantIdentity);
        refusedObjects.push(
            ...verifyReceiverKeyRegistration(
                input,
                entry,
                participantPublicKeys.get(entry.participantIdentity),
            ),
        );
        refusedObjects.push(
            ...verifyRequiredInclusionProof(
                receiverProofsByDigest,
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
                headsByDigest,
            ),
            ...verifyIncludedBoardPlacement(
                receiverProofsByDigest,
                entry.receiverKeyRegistrationDigest,
                'ReceiverKeyRegistration',
                entry.boardSeq,
                entry.boardPosition,
                input.rosterFreezeBoardSeq,
            ),
        );
    }

    const trusteeIdentities = new Set<string>();
    for (const entry of input.trusteeSetupEntries) {
        if (trusteeIdentities.has(entry.trusteeIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'DuplicateTrusteeSetupEntry',
                    'Roster freeze rejects duplicate trustee setup entries.',
                    entry.trusteeSetupEntryDigest,
                    'TrusteeSetupEntry',
                ),
            );
        }
        trusteeIdentities.add(entry.trusteeIdentity);
        refusedObjects.push(
            ...verifyTrusteeSetupEntry(
                input,
                entry,
                participantPublicKeys.get(entry.trusteeIdentity),
            ),
        );
        refusedObjects.push(
            ...verifyRequiredInclusionProof(
                trusteeProofsByDigest,
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
                headsByDigest,
            ),
            ...verifyIncludedBoardPlacement(
                trusteeProofsByDigest,
                entry.trusteeSetupEntryDigest,
                'TrusteeSetupEntry',
                entry.boardSeq,
                entry.boardPosition,
                input.rosterFreezeBoardSeq,
            ),
        );
    }

    for (const participantIdentity of participantIdentities) {
        if (!receiverIdentities.has(participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'MissingReceiverKeyRegistration',
                    'Every roster identity must have a receiver-key registration shell.',
                ),
            );
        }
        if (!trusteeIdentities.has(participantIdentity)) {
            refusedObjects.push(
                createRefusal(
                    'MissingTrusteeSetupEntry',
                    'Every roster identity must have a trustee setup entry shell.',
                ),
            );
        }
    }

    const rosterDigest = deriveRosterDigest(input.registrationEntries);
    refusedObjects.push(...verifyManifest(input, rosterDigest));
    refusedObjects.push(
        ...verifyRequiredInclusionProof(
            new Map([
                [
                    input.manifestInclusionProof.includedObjectDigest,
                    input.manifestInclusionProof,
                ],
            ]),
            input.electionManifest.electionManifestDigest,
            'ElectionManifest',
            headsByDigest,
        ),
    );
    if (
        input.manifestInclusionProof.boardSeq !==
            input.electionManifest.boardSeq ||
        input.manifestInclusionProof.boardPosition !==
            input.electionManifest.boardPosition
    ) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Election manifest board position must match its inclusion proof.',
                input.manifestInclusionProof.inclusionProofDigest,
                'ElectionManifest',
            ),
        );
    }
    if (input.manifestInclusionProof.boardSeq < input.rosterFreezeBoardSeq) {
        refusedObjects.push(
            createRefusal(
                'ManifestDigestMismatch',
                'Election manifest inclusion must not precede the roster freeze board sequence.',
                input.manifestInclusionProof.inclusionProofDigest,
                'ElectionManifest',
            ),
        );
    }

    let conflictingManifest: ElectionManifest | undefined;
    const acceptedConflictingManifestEvidenceDigests: ProtocolDigest[] = [];
    for (const evidence of input.conflictingManifestEvidence ?? []) {
        const evidenceRefusals: RefusalRecord[] = [
            ...verifyManifest(
                input,
                undefined,
                evidence.manifest,
                evidence.manifestInclusionProof,
            ),
            ...verifyInclusionProof(
                evidence.manifestInclusionProof,
                headsByDigest,
            ),
        ];
        if (
            evidence.manifestInclusionProof.boardSeq !==
                evidence.manifest.boardSeq ||
            evidence.manifestInclusionProof.boardPosition !==
                evidence.manifest.boardPosition
        ) {
            evidenceRefusals.push(
                createRefusal(
                    'InclusionProofInvalid',
                    'Conflicting manifest board position must match its inclusion proof.',
                    evidence.manifestInclusionProof.inclusionProofDigest,
                    'ElectionManifest',
                ),
            );
        }
        refusedObjects.push(...evidenceRefusals);
        if (evidenceRefusals.length > 0) {
            continue;
        }
        acceptedConflictingManifestEvidenceDigests.push(
            evidence.manifest.electionManifestDigest,
            evidence.manifestInclusionProof.inclusionProofDigest,
        );
        if (
            evidence.manifest.ceremonyId ===
                input.electionManifest.ceremonyId &&
            evidence.manifest.pollSpecDigest ===
                input.electionManifest.pollSpecDigest &&
            evidence.manifest.electionManifestDigest !==
                input.electionManifest.electionManifestDigest
        ) {
            conflictingManifest ??= evidence.manifest;
        }
    }

    const rawConflictingManifest = findConflictingRawManifest(input);
    if (rawConflictingManifest !== undefined) {
        refusedObjects.push(
            createRefusal(
                'InclusionProofInvalid',
                'Conflicting manifest evidence must include a board inclusion proof.',
                rawConflictingManifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }

    const forkEvidence = boardResult.forkEvidence;
    const statusLabels: readonly ProtocolVerificationStatusLabel[] =
        conflictingManifest === undefined && forkEvidence === undefined
            ? []
            : [
                  'BoardForkSuspected',
                  'BoardEvidencePublished',
                  'ForkedElection',
              ];
    if (conflictingManifest !== undefined) {
        refusedObjects.push(
            createRefusal(
                'ConflictingManifest',
                'Supplied board view contains conflicting manifests for the same ceremony and poll spec.',
                conflictingManifest.electionManifestDigest,
                'ElectionManifest',
            ),
        );
    }

    return {
        ok: refusedObjects.length === 0 && forkEvidence === undefined,
        statusLabels,
        acceptedDigests: uniqueStrings([
            ...boardResult.acceptedDigests,
            ...input.registrationEntries.map(
                (entry) => entry.registrationEntryDigest,
            ),
            ...input.receiverKeyRegistrations.map(
                (entry) => entry.receiverKeyRegistrationDigest,
            ),
            ...input.trusteeSetupEntries.map(
                (entry) => entry.trusteeSetupEntryDigest,
            ),
            rosterDigest,
            input.electionManifest.electionManifestDigest,
            input.manifestInclusionProof.inclusionProofDigest,
            ...acceptedConflictingManifestEvidenceDigests,
        ]),
        refusedObjects,
        forkEvidence,
        electionManifestDigest:
            refusedObjects.length === 0 && forkEvidence === undefined
                ? input.electionManifest.electionManifestDigest
                : undefined,
        rosterDigest:
            refusedObjects.length === 0 && forkEvidence === undefined
                ? rosterDigest
                : undefined,
        participantIdentities,
    };
};

export const verifyRosterManifestTranscript = (
    input: RosterManifestTranscriptInput,
): RosterManifestTranscriptVerification => {
    try {
        return verifyRosterManifestTranscriptUnchecked(input);
    } catch {
        return {
            ok: false,
            statusLabels: [],
            acceptedDigests: [],
            refusedObjects: [
                createRefusal(
                    'RosterDigestMismatch',
                    'Roster-manifest transcript could not be canonicalized or validated.',
                ),
            ],
            participantIdentities: [],
        };
    }
};
