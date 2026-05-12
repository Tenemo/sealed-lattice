import {
    deriveBoardEntryDigest,
    deriveCastReceiptDigest,
    deriveCloseRecordDigest,
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveActionContextDigest,
    deriveBoardHeadDigest,
    deriveBoardRootDigest,
    deriveConflictingHeadEvidenceDigest,
    deriveElectionManifestDigest,
    deriveEvaluationReplayAttestationDigest,
    deriveInclusionProofDigest,
    derivePostVotingClosedContextDigest,
    deriveProtocolDigest,
    deriveProtocolSignatureDigest,
    deriveReceiverKeyRegistrationDigest,
    deriveRecoveryEpochUpdateDigest,
    deriveRegistrationEntryDigest,
    deriveRosterDigest,
    deriveTargetFinalityPolicyDigest,
    deriveTargetFinalityRecordDigest,
    deriveTargetAcceptedRecordDigest,
    deriveTrusteeSetupEntryDigest,
    deriveTopKDecryptionShareDigest,
    deriveValidatedFirstComeOrder,
    deriveWitnessCheckpointDigest,
    deriveWitnessPolicyDigest,
    isActionCurrentForRecoveryEpoch,
    verifyBoardConsistency,
    verifyCastReceiptShell,
    verifyCloseRecordShell,
    verifyEvaluationReplayAttestationShell,
    verifyRecoveryEpochUpdate,
    verifyRosterManifestTranscript,
    verifySignedObjectSignature,
    verifyTargetAcceptedRecordShell,
    verifyTargetFinality,
    verifyTopKDecryptionShareShell,
} from '../../src/index';
import type {
    ActionContext,
    BoardConsistencyInput,
    CanonicalSignedRootObject,
    CastReceipt,
    CloseRecord,
    ElectionManifest,
    EvaluationReplayAttestation,
    FirstComeOrderingInput,
    InclusionProof,
    ManifestOpaqueBindings,
    ManifestPolicyDigests,
    ProtocolSignatureEnvelope,
    ReceiverKeyRegistration,
    RecoveryEpochMapEntry,
    RecoveryEpochUpdate,
    RegistrationEntry,
    RosterManifestTranscriptInput,
    SignedBoardHead,
    SignedObjectType,
    SignerRole,
    TargetAcceptedRecord,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TopKDecryptionShareShell,
    TrusteeSetupEntry,
    ValidatedFirstComeCandidate,
    WitnessCheckpoint,
    WitnessPolicy,
} from '../../src/index';

const ceremonyId = 'ceremony-main';
const boardPolicyDigest = deriveProtocolDigest('BoardPolicyDigest', {
    policy: 'signed-head-chain-v1',
});
const contextDigest = deriveProtocolDigest('ActionContextDigest', {
    context: 'default',
});
const profile = createMlDsaSignatureProfileFixture();

const keyFixturesByDigest = new Map<
    string,
    ReturnType<typeof createMlDsaKeyPairFixture>
>();
const createKeyFixture = (
    seedLabel: string,
): ReturnType<typeof createMlDsaKeyPairFixture> => {
    const keyFixture = createMlDsaKeyPairFixture(seedLabel);
    keyFixturesByDigest.set(keyFixture.publicKeyDigest, keyFixture);

    return keyFixture;
};
const boardKeyFixture = createKeyFixture('board');
const organizerKeyFixture = createKeyFixture('organizer');
const recoveryRootKeyFixture = createKeyFixture('recovery-root:participant-1');
const getParticipantKeyFixture = (
    participantIdentity: string,
): ReturnType<typeof createMlDsaKeyPairFixture> =>
    createKeyFixture(`participant:${participantIdentity}`);
const getWitnessKeyFixture = (
    witnessIdentity: string,
): ReturnType<typeof createMlDsaKeyPairFixture> =>
    createKeyFixture(`witness:${witnessIdentity}`);
const boardPublicKeyDigest = boardKeyFixture.publicKeyDigest;
const organizerPublicKeyDigest = organizerKeyFixture.publicKeyDigest;
const getParticipantSigningPublicKeyDigest = (
    participantIdentity: string,
): string =>
    participantIdentity === 'organizer'
        ? organizerPublicKeyDigest
        : getParticipantKeyFixture(participantIdentity).publicKeyDigest;
const witnessIdentities = [
    'witness-1',
    'witness-2',
    'witness-3',
    'witness-4',
    'witness-5',
    'witness-6',
    'witness-7',
] as const;
const witnessPolicyDigest = deriveWitnessPolicyDigest({
    witnessIdentities,
    witnessQuorum: 5,
    totalWitnesses: 7,
});
const targetFinalityPolicyDigest = deriveTargetFinalityPolicyDigest({
    targetPhase: 'target',
    witnessQuorum: 5,
    totalWitnesses: 7,
});
const defaultTopKEvaluationRecordDigest = deriveProtocolDigest(
    'TopKEvaluationRecordDigest',
    { proposal: 'top-k' },
);
const witnessPublicKeyDigests = Object.fromEntries(
    witnessIdentities.map((witnessIdentity) => [
        witnessIdentity,
        getWitnessKeyFixture(witnessIdentity).publicKeyDigest,
    ]),
);
const witnessPolicy: WitnessPolicy = {
    witnessPolicyDigest,
    witnessIdentities,
    witnessQuorum: 5,
    totalWitnesses: 7,
};
const targetFinalityPolicy = {
    targetFinalityPolicyDigest,
    targetPhase: 'target',
    witnessQuorum: 5,
    totalWitnesses: 7,
};

const manifestPolicyDigests: ManifestPolicyDigests = {
    aggregateSelectionPolicyDigest: deriveProtocolDigest(
        'AggregateSelectionPolicyDigest',
        { policy: 'first-valid-aggregate-contributors' },
    ),
    duplicateBallotPolicyDigest: deriveProtocolDigest(
        'DuplicateBallotPolicyDigest',
        { policy: 'last-valid-before-close' },
    ),
    firstComePolicyDigest: deriveProtocolDigest('FirstComePolicyDigest', {
        policy: 'board-order-current-epoch',
    }),
    recoveryPolicyDigest: deriveProtocolDigest('RecoveryPolicyDigest', {
        policy: 'same-slot-recovery-v1',
    }),
    targetFinalityPolicyDigest,
    witnessPolicyDigest,
};
const manifestOpaqueBindings: ManifestOpaqueBindings = {
    bridgeProofProfileId: 'CommittedAggregateShare-HwangPiEnc-v1',
    proofPrimeParamId: 'proof-prime-param-v1',
    proofPrimePublicKeyRoot: deriveProtocolDigest('ProofPrimePublicKeyRoot', {
        key: 'proof-prime',
    }),
    proofPrimeToQDataKeyConsistencyDigest: deriveProtocolDigest(
        'ProofPrimeToQDataKeyConsistencyDigest',
        { rule: 'same-setup' },
    ),
    proofPrimeToQDataKeyConsistencyEvidence: deriveProtocolDigest(
        'ProofPrimeToQDataKeyConsistencyDigest',
        { evidence: 'same-setup' },
    ),
    canonicalCiphertextConventionDigest: deriveProtocolDigest(
        'CanonicalCiphertextConventionDigest',
        { convention: 'bfv-c0-plus-c1-s' },
    ),
    bfvBatchEncoderDigest: deriveProtocolDigest('BFVBatchEncoderDigest', {
        layout: 'WinnerRankTopK-v1',
    }),
    bridgeLayoutDigest: deriveProtocolDigest('BridgeLayoutDigest', {
        layout: 'aggregate-share-layout-v1',
    }),
    brakerskiBackendProfileId: 'Brakerski25-PQAsync-RingShamir-BFVHPS-RNS-v1',
    brakerskiShareVerificationKeyRoot: deriveProtocolDigest(
        'BrakerskiShareVerificationKeyRoot',
        { root: 'share-verification' },
    ),
    mobileProfileId: 'mobile-flagship-profile-v1',
    bridgeMobileCertificatePolicyDigest: deriveProtocolDigest(
        'BridgeMobileCertDigest',
        { policy: 'mobile-bridge-cert' },
    ),
};

const createSignature = (
    objectType: SignedObjectType,
    signerRole: SignerRole,
    signerIdentity: string,
    publicKeyDigest: string,
    objectRoot: string,
    overrides: Partial<CanonicalSignedRootObject> = {},
): ProtocolSignatureEnvelope => {
    const keyFixture = keyFixturesByDigest.get(publicKeyDigest);
    if (keyFixture === undefined) {
        throw new Error(`Missing ML-DSA test key for ${publicKeyDigest}.`);
    }

    return createProtocolSignatureFixture({
        profile,
        publicKeyDigest,
        publicKeyBytesHex: keyFixture.publicKeyBytesHex,
        secretKeyBytesHex: keyFixture.secretKeyBytesHex,
        signedRoot: {
            objectType,
            objectVersion: 1,
            ceremonyId,
            manifestHash: null,
            boardHeadHash: null,
            objectRoot,
            chunkMerkleRoot: null,
            byteLength: 64,
            signerRole,
            signerIdentity,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            contextDigest,
            ...overrides,
        },
    });
};

const replaceSignatureBytes = (
    signature: ProtocolSignatureEnvelope,
    signatureBytesHex: string,
): ProtocolSignatureEnvelope => {
    const payload = {
        profile: signature.profile,
        publicKeyBytesHex: signature.publicKeyBytesHex,
        publicKeyDigest: signature.publicKeyDigest,
        signatureBytesHex,
        signedRoot: signature.signedRoot,
    };

    return {
        ...payload,
        signatureDigest: deriveProtocolSignatureDigest(payload),
    };
};

const replaceSignaturePublicKeyBytes = (
    signature: ProtocolSignatureEnvelope,
    publicKeyBytesHex: string,
): ProtocolSignatureEnvelope => {
    const payload = {
        profile: signature.profile,
        publicKeyBytesHex,
        publicKeyDigest: signature.publicKeyDigest,
        signatureBytesHex: signature.signatureBytesHex,
        signedRoot: signature.signedRoot,
    };

    return {
        ...payload,
        signatureDigest: deriveProtocolSignatureDigest(payload),
    };
};

const replaceSignatureProfile = (
    signature: ProtocolSignatureEnvelope,
    profileOverride: ProtocolSignatureEnvelope['profile'],
): ProtocolSignatureEnvelope => {
    const payload = {
        profile: profileOverride,
        publicKeyBytesHex: signature.publicKeyBytesHex,
        publicKeyDigest: signature.publicKeyDigest,
        signatureBytesHex: signature.signatureBytesHex,
        signedRoot: signature.signedRoot,
    };

    return {
        ...payload,
        signatureDigest: deriveProtocolSignatureDigest(payload),
    };
};

const createBoardHead = (
    boardSeq: number,
    previousHeadDigest: string | null,
    branchName = 'main',
    boardEntryDigests?: readonly string[],
): SignedBoardHead => {
    const resolvedBoardEntryDigests = boardEntryDigests ?? [
        deriveProtocolDigest('BoardEntryDigest', {
            branchName,
            marker: 'empty-board-head',
            boardSeq,
        }),
    ];
    const unsignedHead: SignedBoardHead = {
        objectType: 'BoardHead',
        objectVersion: 1,
        headDigest: '',
        ceremonyId,
        boardSeq,
        boardRoot: deriveBoardRootDigest(resolvedBoardEntryDigests),
        previousHeadDigest,
        boardPolicyDigest,
        signature: createSignature(
            'BoardHead',
            'Board',
            'board',
            boardPublicKeyDigest,
            'placeholder',
        ),
    };
    const headDigest = deriveBoardHeadDigest(unsignedHead);

    return {
        ...unsignedHead,
        headDigest,
        signature: createSignature(
            'BoardHead',
            'Board',
            'board',
            boardPublicKeyDigest,
            headDigest,
        ),
    };
};

const createInclusionProof = (
    head: SignedBoardHead,
    includedObjectType: InclusionProof['includedObjectType'],
    includedObjectDigest: string,
    boardPosition = 0,
    boardEntryDigests?: readonly string[],
): InclusionProof => {
    const boardEntryDigest = deriveBoardEntryDigest({
        boardPosition,
        includedObjectDigest,
        includedObjectType,
    });
    const resolvedBoardEntryDigests =
        boardEntryDigests ??
        Array.from({ length: boardPosition + 1 }, (_, index) =>
            index === boardPosition
                ? boardEntryDigest
                : deriveProtocolDigest('BoardEntryDigest', {
                      filler: index,
                      headDigest: head.headDigest,
                  }),
        );
    const payload = {
        boardHeadDigest: head.headDigest,
        boardSeq: head.boardSeq,
        boardPosition,
        includedObjectType,
        includedObjectDigest,
        boardEntryDigest,
        boardRoot: deriveBoardRootDigest(resolvedBoardEntryDigests),
        boardEntryDigests: resolvedBoardEntryDigests,
    };

    return {
        ...payload,
        inclusionProofDigest: deriveInclusionProofDigest(payload),
    };
};

const createBoardHeadWithObjects = (
    boardSeq: number,
    previousHeadDigest: string | null,
    objects: readonly {
        readonly objectType: InclusionProof['includedObjectType'];
        readonly objectDigest: string;
        readonly boardPosition: number;
    }[],
    branchName = 'main',
): {
    readonly head: SignedBoardHead;
    readonly inclusionProofs: readonly InclusionProof[];
} => {
    const maximumBoardPosition = Math.max(
        0,
        ...objects.map((object) => object.boardPosition),
    );
    const boardEntryDigests = Array.from(
        { length: maximumBoardPosition + 1 },
        (_, boardPosition) => {
            const object = objects.find(
                (entry) => entry.boardPosition === boardPosition,
            );

            return object === undefined
                ? deriveProtocolDigest('BoardEntryDigest', {
                      filler: boardPosition,
                      branchName,
                      boardSeq,
                  })
                : deriveBoardEntryDigest({
                      boardPosition: object.boardPosition,
                      includedObjectDigest: object.objectDigest,
                      includedObjectType: object.objectType,
                  });
        },
    );
    const head = createBoardHead(
        boardSeq,
        previousHeadDigest,
        branchName,
        boardEntryDigests,
    );
    const inclusionProofs = objects.map((object) =>
        createInclusionProof(
            head,
            object.objectType,
            object.objectDigest,
            object.boardPosition,
            boardEntryDigests,
        ),
    );

    return { head, inclusionProofs };
};

const createTargetProposalHead = (
    boardSeq: number,
    previousHeadDigest: string | null,
    branchName = 'main',
    topKEvaluationRecordDigest = defaultTopKEvaluationRecordDigest,
): SignedBoardHead =>
    createBoardHeadWithObjects(
        boardSeq,
        previousHeadDigest,
        [
            {
                objectType: 'TopKEvaluationRecord',
                objectDigest: topKEvaluationRecordDigest,
                boardPosition: 0,
            },
        ],
        branchName,
    ).head;

const createWitnessCheckpoint = (
    witnessIdentity: string,
    finalizedBoardHeadDigest: string,
    overrides: Partial<WitnessCheckpoint> = {},
): WitnessCheckpoint => {
    const checkpointPayload = {
        objectType: 'WitnessCheckpoint',
        objectVersion: 1,
        ceremonyId,
        targetPhase: 'target',
        finalizedBoardHeadDigest,
        witnessPolicyDigest,
        targetFinalityPolicyDigest,
        witnessIdentity,
        ...overrides,
    } satisfies Omit<WitnessCheckpoint, 'checkpointDigest' | 'signature'>;
    const checkpointDigest = deriveWitnessCheckpointDigest(checkpointPayload);

    return {
        ...checkpointPayload,
        checkpointDigest,
        signature: createSignature(
            'WitnessCheckpoint',
            'Witness',
            witnessIdentity,
            witnessPublicKeyDigests[witnessIdentity] ??
                createKeyFixture(`unknown-witness:${witnessIdentity}`)
                    .publicKeyDigest,
            checkpointDigest,
            {
                boardHeadHash: finalizedBoardHeadDigest,
            },
        ),
    };
};

const createTargetFinalityRecord = (
    finalizedHead: SignedBoardHead,
    topKEvaluationRecordDigest = defaultTopKEvaluationRecordDigest,
    witnessCount = 5,
): TargetFinalityRecord => {
    const inclusionProof = createInclusionProof(
        finalizedHead,
        'TopKEvaluationRecord',
        topKEvaluationRecordDigest,
    );
    const witnessCheckpoints = witnessIdentities
        .slice(0, witnessCount)
        .map((witnessIdentity) =>
            createWitnessCheckpoint(witnessIdentity, finalizedHead.headDigest),
        );
    const payload = {
        objectType: 'TargetFinalityRecord',
        objectVersion: 1,
        ceremonyId,
        targetPhase: 'target',
        finalizedBoardHeadDigest: finalizedHead.headDigest,
        topKEvaluationRecordDigest,
        witnessPolicyDigest,
        targetFinalityPolicyDigest,
        inclusionProof,
        witnessCheckpoints,
    } satisfies Omit<TargetFinalityRecord, 'targetFinalityRecordDigest'>;

    return {
        ...payload,
        targetFinalityRecordDigest: deriveTargetFinalityRecordDigest(payload),
    };
};

const createBoardEvidence = (
    heads: readonly SignedBoardHead[],
): BoardConsistencyInput => ({
    ceremonyId,
    boardPolicyDigest,
    signedBoardHeads: heads,
    expectedBoardPublicKeyDigest: boardPublicKeyDigest,
});

const createRegistrationEntry = (
    participantIdentity: string,
    boardSeq: number,
    boardPosition: number,
): RegistrationEntry => {
    const signingPublicKeyDigest =
        getParticipantSigningPublicKeyDigest(participantIdentity);
    const payload = {
        objectType: 'RegistrationEntry',
        objectVersion: 1,
        ceremonyId,
        participantIdentity,
        signingPublicKeyDigest,
        boardSeq,
        boardPosition,
        recoveryEpoch: 0,
        deviceEpoch: 0,
    } satisfies Omit<
        RegistrationEntry,
        'registrationEntryDigest' | 'signature'
    >;
    const registrationEntryDigest = deriveRegistrationEntryDigest(payload);

    return {
        ...payload,
        registrationEntryDigest,
        signature: createSignature(
            'RegistrationEntry',
            'Participant',
            participantIdentity,
            signingPublicKeyDigest,
            registrationEntryDigest,
        ),
    };
};

const createReceiverKeyRegistration = (
    participantIdentity: string,
    boardSeq: number,
    boardPosition: number,
): ReceiverKeyRegistration => {
    const signingPublicKeyDigest =
        getParticipantSigningPublicKeyDigest(participantIdentity);
    const payload = {
        objectType: 'ReceiverKeyRegistration',
        objectVersion: 1,
        ceremonyId,
        participantIdentity,
        receiverKeyRoot: deriveProtocolDigest('ReceiverKeyRoot', {
            participantIdentity,
        }),
        boardSeq,
        boardPosition,
        recoveryEpoch: 0,
        deviceEpoch: 0,
    } satisfies Omit<
        ReceiverKeyRegistration,
        'receiverKeyRegistrationDigest' | 'signature'
    >;
    const receiverKeyRegistrationDigest =
        deriveReceiverKeyRegistrationDigest(payload);

    return {
        ...payload,
        receiverKeyRegistrationDigest,
        signature: createSignature(
            'ReceiverKeyRegistration',
            'Participant',
            participantIdentity,
            signingPublicKeyDigest,
            receiverKeyRegistrationDigest,
        ),
    };
};

const createTrusteeSetupEntry = (
    trusteeIdentity: string,
    boardSeq: number,
    boardPosition: number,
): TrusteeSetupEntry => {
    const signingPublicKeyDigest =
        getParticipantSigningPublicKeyDigest(trusteeIdentity);
    const payload = {
        objectType: 'TrusteeSetupEntry',
        objectVersion: 1,
        ceremonyId,
        trusteeIdentity,
        trusteeSetupRoot: deriveProtocolDigest('TrusteeSetupRoot', {
            trusteeIdentity,
        }),
        boardSeq,
        boardPosition,
        recoveryEpoch: 0,
        deviceEpoch: 0,
    } satisfies Omit<
        TrusteeSetupEntry,
        'trusteeSetupEntryDigest' | 'signature'
    >;
    const trusteeSetupEntryDigest = deriveTrusteeSetupEntryDigest(payload);

    return {
        ...payload,
        trusteeSetupEntryDigest,
        signature: createSignature(
            'TrusteeSetupEntry',
            'Trustee',
            trusteeIdentity,
            signingPublicKeyDigest,
            trusteeSetupEntryDigest,
        ),
    };
};

const createElectionManifest = (
    registrations: readonly RegistrationEntry[],
    overrides: Partial<ElectionManifest> = {},
): ElectionManifest => {
    const rosterDigest = deriveRosterDigest(registrations);
    const payload = {
        objectType: 'ElectionManifest',
        objectVersion: 1,
        ceremonyId,
        pollSpecDigest: deriveProtocolDigest('PollSpecDigest', {
            poll: 'main',
        }),
        rosterDigest,
        thresholdProfileDigest: deriveProtocolDigest('ThresholdProfileDigest', {
            rosterSize: registrations.length,
        }),
        manifestPolicyDigests,
        manifestOpaqueBindings,
        boardSeq: 3,
        boardPosition: 0,
        ...overrides,
    } satisfies Omit<ElectionManifest, 'electionManifestDigest' | 'signature'>;
    const electionManifestDigest = deriveElectionManifestDigest(payload);

    return {
        ...payload,
        electionManifestDigest,
        signature: createSignature(
            'ElectionManifest',
            'Organizer',
            'organizer',
            organizerPublicKeyDigest,
            electionManifestDigest,
        ),
    };
};

const createRosterManifestTranscriptInput = (
    registrations: readonly RegistrationEntry[],
    manifestOverrides: Partial<ElectionManifest> = {},
    options: { readonly includeOrganizer?: boolean } = {},
): RosterManifestTranscriptInput => {
    const rosterRegistrations =
        options.includeOrganizer === false ||
        registrations.some((entry) => entry.participantIdentity === 'organizer')
            ? registrations
            : [
                  ...registrations,
                  createRegistrationEntry('organizer', 1, registrations.length),
              ];
    const receiverKeyRegistrations = rosterRegistrations.map((entry, index) =>
        createReceiverKeyRegistration(
            entry.participantIdentity,
            1,
            rosterRegistrations.length + index,
        ),
    );
    const trusteeSetupEntries = rosterRegistrations.map((entry, index) =>
        createTrusteeSetupEntry(
            entry.participantIdentity,
            1,
            rosterRegistrations.length * 2 + index,
        ),
    );
    const setupObjects = [
        ...rosterRegistrations.map((entry) => ({
            objectType: 'RegistrationEntry' as const,
            objectDigest: entry.registrationEntryDigest,
            boardPosition: entry.boardPosition,
        })),
        ...receiverKeyRegistrations.map((entry) => ({
            objectType: 'ReceiverKeyRegistration' as const,
            objectDigest: entry.receiverKeyRegistrationDigest,
            boardPosition: entry.boardPosition,
        })),
        ...trusteeSetupEntries.map((entry) => ({
            objectType: 'TrusteeSetupEntry' as const,
            objectDigest: entry.trusteeSetupEntryDigest,
            boardPosition: entry.boardPosition,
        })),
    ];
    const genesisHead = createBoardHead(0, null);
    const { head: setupHead, inclusionProofs: setupInclusionProofs } =
        createBoardHeadWithObjects(1, genesisHead.headDigest, setupObjects);
    const freezeHead = createBoardHead(2, setupHead.headDigest);
    const manifest = createElectionManifest(
        rosterRegistrations,
        manifestOverrides,
    );
    const { head: manifestHead, inclusionProofs: manifestInclusionProofs } =
        createBoardHeadWithObjects(3, freezeHead.headDigest, [
            {
                objectType: 'ElectionManifest',
                objectDigest: manifest.electionManifestDigest,
                boardPosition: manifest.boardPosition,
            },
        ]);
    const registrationInclusionProofs = rosterRegistrations.map(
        (entry) =>
            setupInclusionProofs.find(
                (proof) =>
                    proof.includedObjectDigest ===
                    entry.registrationEntryDigest,
            ) ?? setupInclusionProofs[0],
    );
    const receiverKeyRegistrationInclusionProofs = receiverKeyRegistrations.map(
        (entry) =>
            setupInclusionProofs.find(
                (proof) =>
                    proof.includedObjectDigest ===
                    entry.receiverKeyRegistrationDigest,
            ) ?? setupInclusionProofs[0],
    );
    const trusteeSetupInclusionProofs = trusteeSetupEntries.map(
        (entry) =>
            setupInclusionProofs.find(
                (proof) =>
                    proof.includedObjectDigest ===
                    entry.trusteeSetupEntryDigest,
            ) ?? setupInclusionProofs[0],
    );

    return {
        ceremonyId,
        boardEvidence: createBoardEvidence([
            genesisHead,
            setupHead,
            freezeHead,
            manifestHead,
        ]),
        registrationEntries: rosterRegistrations,
        registrationInclusionProofs,
        receiverKeyRegistrations,
        receiverKeyRegistrationInclusionProofs,
        trusteeSetupEntries,
        trusteeSetupInclusionProofs,
        electionManifest: manifest,
        organizerPublicKeyDigest,
        organizerIdentity: 'organizer',
        rosterFreezeBoardSeq: 2,
        manifestInclusionProof: manifestInclusionProofs[0],
    };
};

export {
    boardKeyFixture,
    boardPolicyDigest,
    boardPublicKeyDigest,
    ceremonyId,
    contextDigest,
    createBoardEvidence,
    createBoardHead,
    createBoardHeadWithObjects,
    createElectionManifest,
    createInclusionProof,
    createKeyFixture,
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    createReceiverKeyRegistration,
    createRegistrationEntry,
    createRosterManifestTranscriptInput,
    createSignature,
    createTargetFinalityRecord,
    createTargetProposalHead,
    createTrusteeSetupEntry,
    createWitnessCheckpoint,
    defaultTopKEvaluationRecordDigest,
    deriveActionContextDigest,
    deriveBoardEntryDigest,
    deriveBoardHeadDigest,
    deriveBoardRootDigest,
    deriveCastReceiptDigest,
    deriveCloseRecordDigest,
    deriveConflictingHeadEvidenceDigest,
    deriveElectionManifestDigest,
    deriveEvaluationReplayAttestationDigest,
    deriveInclusionProofDigest,
    derivePostVotingClosedContextDigest,
    deriveProtocolDigest,
    deriveProtocolSignatureDigest,
    deriveReceiverKeyRegistrationDigest,
    deriveRecoveryEpochUpdateDigest,
    deriveRegistrationEntryDigest,
    deriveRosterDigest,
    deriveTargetAcceptedRecordDigest,
    deriveTargetFinalityPolicyDigest,
    deriveTargetFinalityRecordDigest,
    deriveTopKDecryptionShareDigest,
    deriveTrusteeSetupEntryDigest,
    deriveValidatedFirstComeOrder,
    deriveWitnessCheckpointDigest,
    deriveWitnessPolicyDigest,
    getParticipantKeyFixture,
    getParticipantSigningPublicKeyDigest,
    getWitnessKeyFixture,
    isActionCurrentForRecoveryEpoch,
    keyFixturesByDigest,
    manifestOpaqueBindings,
    manifestPolicyDigests,
    organizerKeyFixture,
    organizerPublicKeyDigest,
    profile,
    recoveryRootKeyFixture,
    replaceSignatureBytes,
    replaceSignatureProfile,
    replaceSignaturePublicKeyBytes,
    targetFinalityPolicy,
    targetFinalityPolicyDigest,
    verifyBoardConsistency,
    verifyCastReceiptShell,
    verifyCloseRecordShell,
    verifyEvaluationReplayAttestationShell,
    verifyRecoveryEpochUpdate,
    verifyRosterManifestTranscript,
    verifySignedObjectSignature,
    verifyTargetAcceptedRecordShell,
    verifyTargetFinality,
    verifyTopKDecryptionShareShell,
    witnessIdentities,
    witnessPolicy,
    witnessPolicyDigest,
    witnessPublicKeyDigests,
};

export type {
    ActionContext,
    BoardConsistencyInput,
    CanonicalSignedRootObject,
    CastReceipt,
    CloseRecord,
    ElectionManifest,
    EvaluationReplayAttestation,
    FirstComeOrderingInput,
    InclusionProof,
    ManifestOpaqueBindings,
    ManifestPolicyDigests,
    ProtocolSignatureEnvelope,
    ReceiverKeyRegistration,
    RecoveryEpochMapEntry,
    RecoveryEpochUpdate,
    RegistrationEntry,
    RosterManifestTranscriptInput,
    SignedBoardHead,
    SignedObjectType,
    SignerRole,
    TargetAcceptedRecord,
    TargetFinalityRecord,
    TargetFinalityVerification,
    TopKDecryptionShareShell,
    TrusteeSetupEntry,
    ValidatedFirstComeCandidate,
    WitnessCheckpoint,
    WitnessPolicy,
};
