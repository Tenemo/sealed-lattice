import { describe, expect, it } from 'vitest';

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
        getParticipantKeyFixture(participantIdentity).publicKeyDigest;
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
        getParticipantKeyFixture(participantIdentity).publicKeyDigest;
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
        getParticipantKeyFixture(trusteeIdentity).publicKeyDigest;
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
): RosterManifestTranscriptInput => {
    const receiverKeyRegistrations = registrations.map((entry, index) =>
        createReceiverKeyRegistration(
            entry.participantIdentity,
            1,
            registrations.length + index,
        ),
    );
    const trusteeSetupEntries = registrations.map((entry, index) =>
        createTrusteeSetupEntry(
            entry.participantIdentity,
            1,
            registrations.length * 2 + index,
        ),
    );
    const setupObjects = [
        ...registrations.map((entry) => ({
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
    const manifest = createElectionManifest(registrations, manifestOverrides);
    const { head: manifestHead, inclusionProofs: manifestInclusionProofs } =
        createBoardHeadWithObjects(3, freezeHead.headDigest, [
            {
                objectType: 'ElectionManifest',
                objectDigest: manifest.electionManifestDigest,
                boardPosition: manifest.boardPosition,
            },
        ]);
    const registrationInclusionProofs = registrations.map(
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
        registrationEntries: registrations,
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

describe('board consistency and target finality', () => {
    it('accepts an honest board chain with inclusion evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headDigest);
        const topKEvaluationRecordDigest = deriveProtocolDigest(
            'TopKEvaluationRecordDigest',
            {
                proposal: 'target',
            },
        );
        const { head: head2, inclusionProofs } = createBoardHeadWithObjects(
            2,
            head1.headDigest,
            [
                {
                    objectType: 'TopKEvaluationRecord',
                    objectDigest: topKEvaluationRecordDigest,
                    boardPosition: 2,
                },
            ],
        );
        const inclusionProof = inclusionProofs[0];

        const result = verifyBoardConsistency({
            ...createBoardEvidence([head0, head1, head2]),
            inclusionProofs: [inclusionProof],
            consistencyProofs: [
                {
                    proofType: 'SignedHeadChain',
                    fromBoardHeadDigest: head0.headDigest,
                    toBoardHeadDigest: head2.headDigest,
                    signedBoardHeads: [head0, head1, head2],
                },
            ],
        });

        expect(result.ok).toBe(true);
        expect(result.verifiedHeadDigests).toEqual([
            head0.headDigest,
            head1.headDigest,
            head2.headDigest,
        ]);
        expect(result.acceptedDigests).toContain(
            inclusionProof.inclusionProofDigest,
        );
    });

    it('rejects board evidence without a trusted expected board key', () => {
        const head0 = createBoardHead(0, null);
        const { expectedBoardPublicKeyDigest, ...untrustedBoardEvidence } =
            createBoardEvidence([head0]);

        expect(expectedBoardPublicKeyDigest).toBe(boardPublicKeyDigest);
        expect(
            verifyBoardConsistency(
                untrustedBoardEvidence as unknown as BoardConsistencyInput,
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
    });

    it('rejects fabricated inclusion and non-ancestor consistency evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headDigest);
        const fabricatedInclusionProof = createInclusionProof(
            head1,
            'TopKEvaluationRecord',
            deriveProtocolDigest('TopKEvaluationRecordDigest', {
                proposal: 'not-in-head',
            }),
        );

        expect(
            verifyBoardConsistency({
                ...createBoardEvidence([head0, head1]),
                inclusionProofs: [fabricatedInclusionProof],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InclusionProofInvalid' }),
            ]),
        );

        expect(
            verifyBoardConsistency({
                ...createBoardEvidence([head0, head1]),
                consistencyProofs: [
                    {
                        proofType: 'SignedHeadChain',
                        fromBoardHeadDigest: head1.headDigest,
                        toBoardHeadDigest: head0.headDigest,
                        signedBoardHeads: [head0, head1],
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
    });

    it('rejects hidden prefixes, forks, and signature substitution', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headDigest);
        const nonGenesisRestart = createBoardHead(5, null);
        const skippedSequence = createBoardHead(3, head1.headDigest);
        const orphan = createBoardHead(
            2,
            deriveProtocolDigest('BoardHeadDigest', {
                hidden: true,
            }),
        );
        const fork = createBoardHead(1, head0.headDigest, 'fork');
        const wrongRoleSignatureHead = {
            ...head1,
            signature: createSignature(
                'BoardHead',
                'Witness',
                'board',
                boardPublicKeyDigest,
                head1.headDigest,
            ),
        };

        expect(
            verifyBoardConsistency(createBoardEvidence([head1, orphan]))
                .refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        expect(
            verifyBoardConsistency(createBoardEvidence([nonGenesisRestart]))
                .refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, head1, skippedSequence]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        expect(
            verifyBoardConsistency(createBoardEvidence([head0, head1, fork]))
                .refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardForkDetected' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, wrongRoleSignatureHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongSignerRole' }),
            ]),
        );
    });

    it('rejects malformed supplied fork evidence and malformed ML-DSA signatures', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headDigest);
        const compatibleEvidencePayload = {
            ceremonyId,
            boardPolicyDigest,
            leftBoardHeadDigest: head0.headDigest,
            rightBoardHeadDigest: head1.headDigest,
        };
        const wrongDigestForkEvidence = {
            ...compatibleEvidencePayload,
            evidenceDigest: deriveProtocolDigest(
                'ConflictingHeadEvidenceDigest',
                { wrong: true },
            ),
        };
        const compatibleForkEvidence = {
            ...compatibleEvidencePayload,
            evidenceDigest: deriveConflictingHeadEvidenceDigest(
                compatibleEvidencePayload,
            ),
        };
        const tamperedSignatureHead = {
            ...head1,
            signature: replaceSignatureBytes(
                head1.signature,
                `${head1.signature.signatureBytesHex.startsWith('00') ? 'ff' : '00'}${head1.signature.signatureBytesHex.slice(2)}`,
            ),
        };
        const replacementKey = createKeyFixture('board:replacement-key');
        const wrongPublicKeyHead = {
            ...head1,
            signature: replaceSignaturePublicKeyBytes(
                head1.signature,
                replacementKey.publicKeyBytesHex,
            ),
        };
        const validWrongPublicKeyHead = {
            ...head1,
            signature: createProtocolSignatureFixture({
                profile,
                publicKeyBytesHex: replacementKey.publicKeyBytesHex,
                publicKeyDigest: replacementKey.publicKeyDigest,
                secretKeyBytesHex: replacementKey.secretKeyBytesHex,
                signedRoot: head1.signature.signedRoot,
            }),
        };
        const unsupportedModeHead = {
            ...head1,
            signature: createProtocolSignatureFixture({
                profile: createMlDsaSignatureProfileFixture({
                    mode: 'HashMLDSA',
                }),
                publicKeyBytesHex: boardKeyFixture.publicKeyBytesHex,
                publicKeyDigest: boardPublicKeyDigest,
                secretKeyBytesHex: boardKeyFixture.secretKeyBytesHex,
                signedRoot: {
                    ...head1.signature.signedRoot,
                    objectRoot: head1.headDigest,
                },
            }),
        };
        const wrongCeremonySignatureHead = {
            ...head1,
            signature: createSignature(
                'BoardHead',
                'Board',
                'board',
                boardPublicKeyDigest,
                head1.headDigest,
                { ceremonyId: 'ceremony-other' },
            ),
        };
        const wrongContextHead = {
            ...head1,
            signature: createProtocolSignatureFixture({
                profile: createMlDsaSignatureProfileFixture({
                    contextString: 'sealed-lattice:wrong-context',
                }),
                publicKeyBytesHex: boardKeyFixture.publicKeyBytesHex,
                publicKeyDigest: boardPublicKeyDigest,
                secretKeyBytesHex: boardKeyFixture.secretKeyBytesHex,
                signedRoot: head1.signature.signedRoot,
            }),
        };
        const oversizedContextHead = {
            ...head1,
            signature: replaceSignatureProfile(
                head1.signature,
                createMlDsaSignatureProfileFixture({
                    contextString: 'x'.repeat(256),
                }),
            ),
        };

        expect(
            verifyBoardConsistency({
                ...createBoardEvidence([head0, head1]),
                conflictingHeadEvidence: [wrongDigestForkEvidence],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        expect(
            verifyBoardConsistency({
                ...createBoardEvidence([head0, head1]),
                conflictingHeadEvidence: [compatibleForkEvidence],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardConsistencyFailure' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, tamperedSignatureHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidSignature' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, wrongPublicKeyHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, validWrongPublicKeyHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, unsupportedModeHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidSignature' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, wrongCeremonySignatureHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongCeremony' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, wrongContextHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidMlDsaContext' }),
            ]),
        );
        expect(
            verifyBoardConsistency(
                createBoardEvidence([head0, oversizedContextHead]),
            ).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InvalidMlDsaContext' }),
            ]),
        );
    });

    it('rejects signed roots missing required envelope fields', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createBoardHead(1, head0.headDigest);
        const createHeadWithSignedRoot = (
            signedRoot: CanonicalSignedRootObject,
        ): SignedBoardHead => ({
            ...head1,
            signature: createProtocolSignatureFixture({
                profile,
                publicKeyBytesHex: boardKeyFixture.publicKeyBytesHex,
                publicKeyDigest: boardPublicKeyDigest,
                secretKeyBytesHex: boardKeyFixture.secretKeyBytesHex,
                signedRoot,
            }),
        });
        const omitSignedRootField = (
            fieldName: keyof CanonicalSignedRootObject,
        ): CanonicalSignedRootObject => {
            const signedRoot = {
                ...head1.signature.signedRoot,
            } as Record<string, unknown>;
            delete signedRoot[fieldName];

            return signedRoot as CanonicalSignedRootObject;
        };
        const malformedHeads = [
            createHeadWithSignedRoot(omitSignedRootField('manifestHash')),
            createHeadWithSignedRoot(omitSignedRootField('boardHeadHash')),
            createHeadWithSignedRoot(omitSignedRootField('byteLength')),
            createHeadWithSignedRoot(omitSignedRootField('contextDigest')),
            createHeadWithSignedRoot({
                ...head1.signature.signedRoot,
                objectRoot: null,
                chunkMerkleRoot: null,
            }),
            createHeadWithSignedRoot({
                ...head1.signature.signedRoot,
                chunkMerkleRoot: deriveProtocolDigest('BoardRootDigest', {
                    chunkRoot: 'ambiguous',
                }),
            }),
        ];

        for (const malformedHead of malformedHeads) {
            expect(
                verifyBoardConsistency(
                    createBoardEvidence([head0, malformedHead]),
                ).refusedObjects,
            ).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({ code: 'InvalidSignedRoot' }),
                ]),
            );
        }
    });

    it('verifies 5-of-7 target finality and rejects weak witness evidence', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headDigest);
        const record = createTargetFinalityRecord(head1);
        const boardEvidence = createBoardEvidence([head0, head1]);

        expect(
            verifyTargetFinality({
                boardEvidence,
                record,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }),
        ).toMatchObject({
            ok: true,
            validWitnessIdentities: witnessIdentities.slice(0, 5),
        });

        const tooFewWitnesses = createTargetFinalityRecord(head1, undefined, 4);
        expect(
            verifyTargetFinality({
                boardEvidence,
                record: tooFewWitnesses,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WitnessQuorumNotReached' }),
            ]),
        );

        const duplicateWitnessRecord = {
            ...record,
            witnessCheckpoints: [
                record.witnessCheckpoints[0],
                record.witnessCheckpoints[0],
                ...record.witnessCheckpoints.slice(1),
            ],
        };
        const digestFixedDuplicateRecord = {
            ...duplicateWitnessRecord,
            targetFinalityRecordDigest: deriveTargetFinalityRecordDigest({
                ceremonyId: duplicateWitnessRecord.ceremonyId,
                finalizedBoardHeadDigest:
                    duplicateWitnessRecord.finalizedBoardHeadDigest,
                inclusionProof: duplicateWitnessRecord.inclusionProof,
                objectType: duplicateWitnessRecord.objectType,
                objectVersion: duplicateWitnessRecord.objectVersion,
                targetFinalityPolicyDigest:
                    duplicateWitnessRecord.targetFinalityPolicyDigest,
                targetPhase: duplicateWitnessRecord.targetPhase,
                topKEvaluationRecordDigest:
                    duplicateWitnessRecord.topKEvaluationRecordDigest,
                witnessCheckpoints: duplicateWitnessRecord.witnessCheckpoints,
                witnessPolicyDigest: duplicateWitnessRecord.witnessPolicyDigest,
            }),
        };

        expect(
            verifyTargetFinality({
                boardEvidence,
                record: digestFixedDuplicateRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DuplicateWitness' }),
            ]),
        );
    });

    it('rejects wrong top-k inclusion, unknown witnesses, and conflicting finalized targets', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headDigest, 'left');
        const forkTopKEvaluationRecordDigest = deriveProtocolDigest(
            'TopKEvaluationRecordDigest',
            { proposal: 'fork' },
        );
        const head1Fork = createTargetProposalHead(
            1,
            head0.headDigest,
            'right',
            forkTopKEvaluationRecordDigest,
        );
        const boardEvidence = createBoardEvidence([head0, head1, head1Fork]);
        const record = createTargetFinalityRecord(head1);
        const wrongInclusionRecord = {
            ...record,
            inclusionProof: createInclusionProof(
                head1,
                'ElectionManifest',
                record.topKEvaluationRecordDigest,
            ),
        };
        const unknownWitnessRecord = {
            ...record,
            witnessCheckpoints: [
                ...record.witnessCheckpoints.slice(0, 4),
                createWitnessCheckpoint('unknown-witness', head1.headDigest),
            ],
        };
        const forkRecord = createTargetFinalityRecord(
            head1Fork,
            forkTopKEvaluationRecordDigest,
        );

        expect(
            verifyTargetFinality({
                boardEvidence: createBoardEvidence([head0, head1]),
                record: wrongInclusionRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'TopKEvaluationRecordNotIncluded',
                }),
            ]),
        );
        expect(
            verifyTargetFinality({
                boardEvidence: createBoardEvidence([head0, head1]),
                record: unknownWitnessRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'UnknownWitness' }),
            ]),
        );
        const forkedVerification = verifyTargetFinality({
            boardEvidence,
            record,
            witnessPolicy,
            targetFinalityPolicy,
            witnessPublicKeyDigests,
            conflictingRecords: [forkRecord],
        });

        expect(forkedVerification.ok).toBe(false);
        expect(forkedVerification.targetFinalityRecordDigest).toBeUndefined();
        expect(forkedVerification.equivocatingWitnessIdentities).toEqual(
            witnessIdentities.slice(0, 5),
        );
        expect(forkedVerification.forkEvidence).toMatchObject({
            targetPhase: 'target',
            equivocatingWitnessIdentities: witnessIdentities.slice(0, 5),
        });
        expect(forkedVerification.refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'BoardForkDetected' }),
            ]),
        );
    });

    it('rejects witness signature substitution and wrong finalized head binding', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headDigest);
        const otherHead = createTargetProposalHead(
            2,
            head1.headDigest,
            'other-finalized-head',
        );
        const record = createTargetFinalityRecord(head1);
        const boardEvidence = createBoardEvidence([head0, head1, otherHead]);
        const boardSignatureAsWitnessRecord = {
            ...record,
            witnessCheckpoints: [
                {
                    ...record.witnessCheckpoints[0],
                    signature: head1.signature,
                },
                ...record.witnessCheckpoints.slice(1),
            ],
        };
        const wrongHeadWitnessRecordPayload = {
            ceremonyId: record.ceremonyId,
            finalizedBoardHeadDigest: record.finalizedBoardHeadDigest,
            inclusionProof: record.inclusionProof,
            objectType: record.objectType,
            objectVersion: record.objectVersion,
            targetFinalityPolicyDigest: record.targetFinalityPolicyDigest,
            targetPhase: record.targetPhase,
            topKEvaluationRecordDigest: record.topKEvaluationRecordDigest,
            witnessCheckpoints: [
                createWitnessCheckpoint(
                    witnessIdentities[0],
                    otherHead.headDigest,
                ),
                ...record.witnessCheckpoints.slice(1),
            ],
            witnessPolicyDigest: record.witnessPolicyDigest,
        } satisfies Omit<TargetFinalityRecord, 'targetFinalityRecordDigest'>;
        const wrongHeadWitnessRecord = {
            ...wrongHeadWitnessRecordPayload,
            targetFinalityRecordDigest: deriveTargetFinalityRecordDigest(
                wrongHeadWitnessRecordPayload,
            ),
        };

        expect(
            verifyTargetFinality({
                boardEvidence,
                record: boardSignatureAsWitnessRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongObjectType' }),
            ]),
        );
        expect(
            verifyTargetFinality({
                boardEvidence,
                record: wrongHeadWitnessRecord,
                witnessPolicy,
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'TargetFinalityPolicyMismatch',
                }),
            ]),
        );
    });

    it('rejects malformed witness policies', () => {
        const head0 = createBoardHead(0, null);
        const head1 = createTargetProposalHead(1, head0.headDigest);
        const record = createTargetFinalityRecord(head1);

        expect(
            verifyTargetFinality({
                boardEvidence: createBoardEvidence([head0, head1]),
                record,
                witnessPolicy: {
                    ...witnessPolicy,
                    witnessIdentities: [
                        ...witnessIdentities.slice(0, 6),
                        witnessIdentities[0],
                    ],
                    witnessPolicyDigest: deriveWitnessPolicyDigest({
                        witnessIdentities: [
                            ...witnessIdentities.slice(0, 6),
                            witnessIdentities[0],
                        ],
                        witnessQuorum: 5,
                        totalWitnesses: 7,
                    }),
                },
                targetFinalityPolicy,
                witnessPublicKeyDigests,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WitnessPolicyMismatch' }),
            ]),
        );
    });
});

describe('cast, close, and target-phase shells', () => {
    it('verifies cast receipt and voting-close shells', () => {
        const electionManifestDigest = deriveProtocolDigest(
            'ElectionManifestDigest',
            { manifest: 'shell' },
        );
        const voterKey = getParticipantKeyFixture('participant-1');
        const head0 = createBoardHead(0, null);
        const castReceiptPayload = {
            objectType: 'CastReceipt',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            voterIdentity: 'participant-1',
            ballotPackageDigest: deriveProtocolDigest('BallotPackageDigest', {
                ballot: 'participant-1',
            }),
            boardSeq: 1,
            boardPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            contextDigest,
        } satisfies Omit<CastReceipt, 'castReceiptDigest' | 'signature'>;
        const castReceiptDigest = deriveCastReceiptDigest(castReceiptPayload);
        const { head: castHead, inclusionProofs: castInclusionProofs } =
            createBoardHeadWithObjects(1, head0.headDigest, [
                {
                    objectType: 'CastReceipt',
                    objectDigest: castReceiptDigest,
                    boardPosition: 0,
                },
            ]);
        const castReceipt: CastReceipt = {
            ...castReceiptPayload,
            castReceiptDigest,
            signature: createSignature(
                'CastReceipt',
                'Voter',
                'participant-1',
                voterKey.publicKeyDigest,
                castReceiptDigest,
                {
                    boardHeadHash: castHead.headDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };

        expect(
            verifyCastReceiptShell({
                boardEvidence: createBoardEvidence([head0, castHead]),
                receipt: castReceipt,
                receiptInclusionProof: castInclusionProofs[0],
                expectedElectionManifestDigest: electionManifestDigest,
                expectedVoterPublicKeyDigest: voterKey.publicKeyDigest,
            }).ok,
        ).toBe(true);

        const closeRecordPayload = {
            objectType: 'CloseRecord',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            closeKind: 'VotingClosed',
            closedBoardHeadDigest: castHead.headDigest,
            postVotingClosedContextDigest: null,
            boardSeq: 2,
            boardPosition: 0,
            organizerIdentity: 'organizer',
        } satisfies Omit<CloseRecord, 'closeRecordDigest' | 'signature'>;
        const closeRecordDigest = deriveCloseRecordDigest(closeRecordPayload);
        const { head: closeHead, inclusionProofs: closeInclusionProofs } =
            createBoardHeadWithObjects(2, castHead.headDigest, [
                {
                    objectType: 'CloseRecord',
                    objectDigest: closeRecordDigest,
                    boardPosition: 0,
                },
            ]);
        const postVotingClosedContextDigest =
            derivePostVotingClosedContextDigest({
                ceremonyId,
                closeRecordDigest,
                electionManifestDigest,
                votingClosedBoardHeadDigest: closeHead.headDigest,
            });
        const closeRecord: CloseRecord = {
            ...closeRecordPayload,
            postVotingClosedContextDigest,
            closeRecordDigest,
            signature: createSignature(
                'CloseRecord',
                'Organizer',
                'organizer',
                organizerPublicKeyDigest,
                closeRecordDigest,
                {
                    boardHeadHash: closeHead.headDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };
        const closeVerification = verifyCloseRecordShell({
            boardEvidence: createBoardEvidence([head0, castHead, closeHead]),
            closeRecord,
            closeRecordInclusionProof: closeInclusionProofs[0],
            expectedElectionManifestDigest: electionManifestDigest,
            expectedOrganizerIdentity: 'organizer',
            expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
        });

        expect(closeVerification).toMatchObject({
            ok: true,
            postVotingClosedContextDigest,
        });
        expect(
            verifyCloseRecordShell({
                boardEvidence: createBoardEvidence([
                    head0,
                    castHead,
                    closeHead,
                ]),
                closeRecord: {
                    ...closeRecord,
                    postVotingClosedContextDigest: deriveProtocolDigest(
                        'PostVotingClosedContextDigest',
                        { wrong: true },
                    ),
                },
                closeRecordInclusionProof: closeInclusionProofs[0],
                expectedElectionManifestDigest: electionManifestDigest,
                expectedOrganizerIdentity: 'organizer',
                expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'CloseRecordInvalid' }),
            ]),
        );
    });

    it('binds replay attestation, target acceptance, and decryption-share shells to target finality', () => {
        const electionManifestDigest = deriveProtocolDigest(
            'ElectionManifestDigest',
            { manifest: 'target-phase-shell' },
        );
        const participantKey = getParticipantKeyFixture('participant-1');
        const head0 = createBoardHead(0, null);
        const targetHead = createTargetProposalHead(1, head0.headDigest);
        const targetFinalityRecord = createTargetFinalityRecord(targetHead);
        const targetFinalityVerification = verifyTargetFinality({
            boardEvidence: createBoardEvidence([head0, targetHead]),
            record: targetFinalityRecord,
            witnessPolicy,
            targetFinalityPolicy,
            witnessPublicKeyDigests,
        });
        const replayPayload = {
            objectType: 'EvaluationReplayAttestation',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            signerIdentity: 'participant-1',
            topKEvaluationRecordDigest:
                targetFinalityRecord.topKEvaluationRecordDigest,
            targetFinalityRecordDigest:
                targetFinalityRecord.targetFinalityRecordDigest,
            finalizedBoardHeadDigest:
                targetFinalityRecord.finalizedBoardHeadDigest,
            replayContextDigest: contextDigest,
            boardSeq: 2,
            boardPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 0,
        } satisfies Omit<
            EvaluationReplayAttestation,
            'evaluationReplayAttestationDigest' | 'signature'
        >;
        const replayDigest =
            deriveEvaluationReplayAttestationDigest(replayPayload);
        const { head: replayHead, inclusionProofs: replayProofs } =
            createBoardHeadWithObjects(2, targetHead.headDigest, [
                {
                    objectType: 'EvaluationReplayAttestation',
                    objectDigest: replayDigest,
                    boardPosition: 0,
                },
            ]);
        const replayAttestation: EvaluationReplayAttestation = {
            ...replayPayload,
            evaluationReplayAttestationDigest: replayDigest,
            signature: createSignature(
                'EvaluationReplayAttestation',
                'Participant',
                'participant-1',
                participantKey.publicKeyDigest,
                replayDigest,
                {
                    boardHeadHash: replayHead.headDigest,
                    contextDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };
        const replayVerification = verifyEvaluationReplayAttestationShell({
            boardEvidence: createBoardEvidence([head0, targetHead, replayHead]),
            attestation: replayAttestation,
            attestationInclusionProof: replayProofs[0],
            targetFinalityRecord,
            targetFinalityVerification,
            expectedSignerPublicKeyDigest: participantKey.publicKeyDigest,
        });

        expect(replayVerification.ok).toBe(true);
        expect(
            verifyEvaluationReplayAttestationShell({
                boardEvidence: createBoardEvidence([
                    head0,
                    targetHead,
                    replayHead,
                ]),
                attestation: replayAttestation,
                attestationInclusionProof: replayProofs[0],
                targetFinalityRecord,
                targetFinalityVerification: {
                    ...targetFinalityVerification,
                    ok: false,
                    acceptedDigests: [],
                    targetFinalityRecordDigest: undefined,
                    finalizedBoardHeadDigest: undefined,
                } satisfies TargetFinalityVerification,
                expectedSignerPublicKeyDigest: participantKey.publicKeyDigest,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'TargetPhaseAuthorizationFailure',
                }),
            ]),
        );

        const targetAcceptedPayload = {
            objectType: 'TargetAcceptedRecord',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            targetPhase: targetFinalityRecord.targetPhase,
            topKEvaluationRecordDigest:
                targetFinalityRecord.topKEvaluationRecordDigest,
            targetFinalityRecordDigest:
                targetFinalityRecord.targetFinalityRecordDigest,
            replayAttestationDigests: [replayDigest],
            optionalEvaluationProofRoot: null,
            boardSeq: 3,
            boardPosition: 0,
            organizerIdentity: 'organizer',
        } satisfies Omit<
            TargetAcceptedRecord,
            'targetAcceptedRecordDigest' | 'signature'
        >;
        const targetAcceptedRecordDigest = deriveTargetAcceptedRecordDigest(
            targetAcceptedPayload,
        );
        const { head: acceptedHead, inclusionProofs: acceptedProofs } =
            createBoardHeadWithObjects(3, replayHead.headDigest, [
                {
                    objectType: 'TargetAcceptedRecord',
                    objectDigest: targetAcceptedRecordDigest,
                    boardPosition: 0,
                },
            ]);
        const targetAcceptedRecord: TargetAcceptedRecord = {
            ...targetAcceptedPayload,
            targetAcceptedRecordDigest,
            signature: createSignature(
                'TargetAcceptedRecord',
                'Organizer',
                'organizer',
                organizerPublicKeyDigest,
                targetAcceptedRecordDigest,
                {
                    boardHeadHash: acceptedHead.headDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };
        const targetAcceptedVerification = verifyTargetAcceptedRecordShell({
            boardEvidence: createBoardEvidence([
                head0,
                targetHead,
                replayHead,
                acceptedHead,
            ]),
            targetAcceptedRecord,
            targetAcceptedRecordInclusionProof: acceptedProofs[0],
            targetFinalityRecord,
            targetFinalityVerification,
            acceptedReplayAttestationDigests: [
                replayVerification.evaluationReplayAttestationDigest ?? '',
            ],
            expectedOrganizerPublicKeyDigest: organizerPublicKeyDigest,
        });

        expect(targetAcceptedVerification.ok).toBe(true);

        const decryptionSharePayload = {
            objectType: 'TopKDecryptionShare',
            objectVersion: 1,
            ceremonyId,
            electionManifestDigest,
            trusteeIdentity: 'participant-1',
            targetAcceptedRecordDigest,
            targetFinalityRecordDigest:
                targetFinalityRecord.targetFinalityRecordDigest,
            topKEvaluationRecordDigest:
                targetFinalityRecord.topKEvaluationRecordDigest,
            boardSeq: 4,
            boardPosition: 0,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            shareRoot: deriveProtocolDigest('TopKDecryptionShareDigest', {
                share: 'placeholder',
            }),
        } satisfies Omit<
            TopKDecryptionShareShell,
            'topKDecryptionShareDigest' | 'signature'
        >;
        const decryptionShareDigest = deriveTopKDecryptionShareDigest(
            decryptionSharePayload,
        );
        const { head: shareHead, inclusionProofs: shareProofs } =
            createBoardHeadWithObjects(4, acceptedHead.headDigest, [
                {
                    objectType: 'TopKDecryptionShare',
                    objectDigest: decryptionShareDigest,
                    boardPosition: 0,
                },
            ]);
        const decryptionShare: TopKDecryptionShareShell = {
            ...decryptionSharePayload,
            topKDecryptionShareDigest: decryptionShareDigest,
            signature: createSignature(
                'TopKDecryptionShare',
                'Trustee',
                'participant-1',
                participantKey.publicKeyDigest,
                decryptionShareDigest,
                {
                    boardHeadHash: shareHead.headDigest,
                    manifestHash: electionManifestDigest,
                },
            ),
        };

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence: createBoardEvidence([
                    head0,
                    targetHead,
                    replayHead,
                    acceptedHead,
                    shareHead,
                ]),
                decryptionShare,
                decryptionShareInclusionProof: shareProofs[0],
                targetAcceptedRecord,
                targetAcceptedRecordVerification: targetAcceptedVerification,
                expectedTrusteePublicKeyDigest: participantKey.publicKeyDigest,
            }).ok,
        ).toBe(true);

        const wrongFinalitySharePayload = {
            ...decryptionSharePayload,
            targetFinalityRecordDigest: deriveProtocolDigest(
                'TargetFinalityRecordDigest',
                { wrong: true },
            ),
        };
        const wrongFinalityShareDigest = deriveTopKDecryptionShareDigest(
            wrongFinalitySharePayload,
        );
        const { head: wrongShareHead, inclusionProofs: wrongShareProofs } =
            createBoardHeadWithObjects(4, acceptedHead.headDigest, [
                {
                    objectType: 'TopKDecryptionShare',
                    objectDigest: wrongFinalityShareDigest,
                    boardPosition: 0,
                },
            ]);

        expect(
            verifyTopKDecryptionShareShell({
                boardEvidence: createBoardEvidence([
                    head0,
                    targetHead,
                    replayHead,
                    acceptedHead,
                    wrongShareHead,
                ]),
                decryptionShare: {
                    ...wrongFinalitySharePayload,
                    topKDecryptionShareDigest: wrongFinalityShareDigest,
                    signature: createSignature(
                        'TopKDecryptionShare',
                        'Trustee',
                        'participant-1',
                        participantKey.publicKeyDigest,
                        wrongFinalityShareDigest,
                        {
                            boardHeadHash: wrongShareHead.headDigest,
                            manifestHash: electionManifestDigest,
                        },
                    ),
                },
                decryptionShareInclusionProof: wrongShareProofs[0],
                targetAcceptedRecord,
                targetAcceptedRecordVerification: targetAcceptedVerification,
                expectedTrusteePublicKeyDigest: participantKey.publicKeyDigest,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DecryptionShareInvalid' }),
            ]),
        );
    });
});

describe('roster, manifest, first-come, and recovery shells', () => {
    it('accepts an honest registration to manifest transcript', () => {
        const registrations = [
            createRegistrationEntry('participant-1', 1, 0),
            createRegistrationEntry('participant-2', 1, 1),
            createRegistrationEntry('participant-3', 1, 2),
        ];
        const input = createRosterManifestTranscriptInput(registrations);

        const result = verifyRosterManifestTranscript(input);

        expect(result.ok).toBe(true);
        expect(result.participantIdentities).toEqual([
            'participant-1',
            'participant-2',
            'participant-3',
        ]);
        expect(result.rosterDigest).toBe(deriveRosterDigest(registrations));
    });

    it('rejects duplicate, late, conflicting, and changed manifest inputs', () => {
        const firstRegistration = createRegistrationEntry(
            'participant-1',
            1,
            0,
        );
        const duplicateRegistration = createRegistrationEntry(
            'participant-1',
            1,
            1,
        );
        const lateRegistration = createRegistrationEntry('participant-2', 5, 0);
        const registrations = [firstRegistration, duplicateRegistration];
        const input = createRosterManifestTranscriptInput([
            firstRegistration,
            duplicateRegistration,
            lateRegistration,
        ]);
        const changedManifest = createElectionManifest(registrations, {
            boardSeq: 4,
            manifestOpaqueBindings: {
                ...manifestOpaqueBindings,
                mobileProfileId: 'different-mobile-profile',
            },
        });
        const changedPollSpecManifest = createElectionManifest(registrations, {
            boardSeq: 4,
            pollSpecDigest: deriveProtocolDigest('PollSpecDigest', {
                poll: 'different',
            }),
        });
        const lastHead =
            input.boardEvidence.signedBoardHeads[
                input.boardEvidence.signedBoardHeads.length - 1
            ];
        if (lastHead === undefined) {
            throw new Error('Expected roster fixture to include board heads.');
        }
        const { head: conflictHead, inclusionProofs: conflictProofs } =
            createBoardHeadWithObjects(4, lastHead.headDigest, [
                {
                    objectType: 'ElectionManifest',
                    objectDigest: changedManifest.electionManifestDigest,
                    boardPosition: changedManifest.boardPosition,
                },
            ]);
        const {
            head: differentPollSpecHead,
            inclusionProofs: differentPollSpecProofs,
        } = createBoardHeadWithObjects(4, lastHead.headDigest, [
            {
                objectType: 'ElectionManifest',
                objectDigest: changedPollSpecManifest.electionManifestDigest,
                boardPosition: changedPollSpecManifest.boardPosition,
            },
        ]);

        expect(
            verifyRosterManifestTranscript({
                ...input,
                electionManifest: createElectionManifest(registrations),
                boardEvidence: createBoardEvidence([
                    ...input.boardEvidence.signedBoardHeads,
                    conflictHead,
                ]),
                conflictingManifestEvidence: [
                    {
                        manifest: changedManifest,
                        manifestInclusionProof: conflictProofs[0],
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'DuplicateRegistration' }),
                expect.objectContaining({ code: 'LateRegistration' }),
                expect.objectContaining({ code: 'RosterDigestMismatch' }),
                expect.objectContaining({ code: 'ConflictingManifest' }),
            ]),
        );
        expect(
            verifyRosterManifestTranscript({
                ...input,
                boardEvidence: createBoardEvidence([
                    ...input.boardEvidence.signedBoardHeads,
                    differentPollSpecHead,
                ]),
                conflictingManifestEvidence: [
                    {
                        manifest: changedPollSpecManifest,
                        manifestInclusionProof: differentPollSpecProofs[0],
                    },
                ],
            }).refusedObjects,
        ).not.toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'ConflictingManifest' }),
            ]),
        );
        expect(
            verifyRosterManifestTranscript({
                ...input,
                suppliedElectionManifests: [changedManifest],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InclusionProofInvalid' }),
            ]),
        );
    });

    it('rejects roster objects included after freeze even if their signed payload claims an earlier position', () => {
        const registration = createRegistrationEntry('participant-1', 1, 0);
        const input = createRosterManifestTranscriptInput([registration]);
        const lastHead =
            input.boardEvidence.signedBoardHeads[
                input.boardEvidence.signedBoardHeads.length - 1
            ];
        if (lastHead === undefined) {
            throw new Error('Expected roster fixture to include board heads.');
        }
        const { head: lateHead, inclusionProofs } = createBoardHeadWithObjects(
            4,
            lastHead.headDigest,
            [
                {
                    objectType: 'RegistrationEntry',
                    objectDigest: registration.registrationEntryDigest,
                    boardPosition: 0,
                },
            ],
        );

        expect(
            verifyRosterManifestTranscript({
                ...input,
                boardEvidence: createBoardEvidence([
                    ...input.boardEvidence.signedBoardHeads,
                    lateHead,
                ]),
                registrationInclusionProofs: [inclusionProofs[0]],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'InclusionProofInvalid' }),
                expect.objectContaining({ code: 'LateRegistration' }),
            ]),
        );
    });

    it('rejects signed registration reuse as trustee setup evidence', () => {
        const registration = createRegistrationEntry('participant-1', 1, 0);
        const input = createRosterManifestTranscriptInput([registration]);

        expect(
            verifyRosterManifestTranscript({
                ...input,
                trusteeSetupEntries: [
                    {
                        ...input.trusteeSetupEntries[0],
                        signature: registration.signature,
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongObjectType' }),
            ]),
        );
    });

    it('orders validated first-come candidates and deduplicates retransmission', () => {
        const recoveryEpochState: RecoveryEpochMapEntry = {
            signerIdentity: 'participant-1',
            currentRecoveryEpoch: 0,
            currentDeviceEpoch: 0,
        };
        const candidates: ValidatedFirstComeCandidate[] = [
            {
                objectDigest: 'object-b',
                objectType: 'TargetFinalityRecord',
                boardSeq: 2,
                boardPosition: 1,
                signerIdentity: 'participant-2',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest,
                isByteIdenticalRetransmission: false,
            },
            {
                objectDigest: 'object-a',
                objectType: 'TargetFinalityRecord',
                boardSeq: 1,
                boardPosition: 0,
                signerIdentity: 'participant-1',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest,
                isByteIdenticalRetransmission: false,
            },
            {
                objectDigest: 'object-a',
                objectType: 'TargetFinalityRecord',
                boardSeq: 3,
                boardPosition: 0,
                signerIdentity: 'participant-1',
                recoveryEpoch: 0,
                deviceEpoch: 0,
                actionSequence: 0,
                contextDigest,
                isByteIdenticalRetransmission: true,
            },
        ];
        const input: FirstComeOrderingInput = {
            candidates,
            requiredContextDigest: contextDigest,
            selectionPolicyDigest: manifestPolicyDigests.firstComePolicyDigest,
            expectedSelectionPolicyDigest:
                manifestPolicyDigests.firstComePolicyDigest,
            currentRecoveryEpochMap: {
                'participant-1': recoveryEpochState,
                'participant-2': {
                    signerIdentity: 'participant-2',
                    currentRecoveryEpoch: 0,
                    currentDeviceEpoch: 0,
                },
            },
        };

        expect(deriveValidatedFirstComeOrder(input)).toMatchObject({
            ok: true,
            orderedCandidates: [
                expect.objectContaining({ objectDigest: 'object-a' }),
                expect.objectContaining({ objectDigest: 'object-b' }),
            ],
        });

        const badInput: FirstComeOrderingInput = {
            ...input,
            selectionPolicyDigest: deriveProtocolDigest(
                'FirstComePolicyDigest',
                { policy: 'wrong' },
            ),
            candidates: [
                {
                    ...candidates[0],
                    contextDigest: deriveProtocolDigest('ActionContextDigest', {
                        context: 'wrong',
                    }),
                },
                candidates[1],
                {
                    ...candidates[1],
                    objectDigest: 'object-stale',
                    recoveryEpoch: 9,
                    actionSequence: 1,
                },
                {
                    ...candidates[1],
                    objectDigest: 'object-c',
                },
            ],
        };

        expect(deriveValidatedFirstComeOrder(badInput).refusedObjects).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'FirstComePolicyMismatch' }),
                expect.objectContaining({ code: 'FirstComeContextMismatch' }),
                expect.objectContaining({ code: 'StaleRecoveryEpoch' }),
                expect.objectContaining({
                    code: 'ConflictingFirstComeCandidate',
                }),
            ]),
        );
    });

    it('rejects same-identity first-come conflicts across action sequences', () => {
        expect(
            deriveValidatedFirstComeOrder({
                requiredContextDigest: contextDigest,
                selectionPolicyDigest:
                    manifestPolicyDigests.firstComePolicyDigest,
                expectedSelectionPolicyDigest:
                    manifestPolicyDigests.firstComePolicyDigest,
                currentRecoveryEpochMap: {
                    'participant-1': {
                        signerIdentity: 'participant-1',
                        currentRecoveryEpoch: 0,
                        currentDeviceEpoch: 0,
                    },
                },
                candidates: [
                    {
                        objectDigest: 'object-a',
                        objectType: 'TargetFinalityRecord',
                        boardSeq: 1,
                        boardPosition: 0,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 0,
                        contextDigest,
                        isByteIdenticalRetransmission: false,
                    },
                    {
                        objectDigest: 'object-b',
                        objectType: 'TargetFinalityRecord',
                        boardSeq: 1,
                        boardPosition: 1,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 0,
                        actionSequence: 1,
                        contextDigest,
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    code: 'ConflictingFirstComeCandidate',
                }),
            ]),
        );
    });

    it('rejects mixed stale recovery and current device epochs before the old-action cutoff', () => {
        expect(
            deriveValidatedFirstComeOrder({
                requiredContextDigest: contextDigest,
                selectionPolicyDigest:
                    manifestPolicyDigests.firstComePolicyDigest,
                expectedSelectionPolicyDigest:
                    manifestPolicyDigests.firstComePolicyDigest,
                currentRecoveryEpochMap: {
                    'participant-1': {
                        signerIdentity: 'participant-1',
                        currentRecoveryEpoch: 1,
                        currentDeviceEpoch: 1,
                        oldActionCutoffBoardSeq: 10,
                    },
                },
                candidates: [
                    {
                        objectDigest: 'object-mixed-epoch',
                        objectType: 'TargetFinalityRecord',
                        boardSeq: 9,
                        boardPosition: 0,
                        signerIdentity: 'participant-1',
                        recoveryEpoch: 0,
                        deviceEpoch: 1,
                        actionSequence: 0,
                        contextDigest,
                        isByteIdenticalRetransmission: false,
                    },
                ],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'StaleRecoveryEpoch' }),
            ]),
        );
    });

    it('verifies recovery updates and refuses stale action contexts', () => {
        const currentEntry: RecoveryEpochMapEntry = {
            signerIdentity: 'participant-1',
            currentRecoveryEpoch: 0,
            currentDeviceEpoch: 0,
        };
        const recoveryGenesisHead = createBoardHead(0, null);
        const recoveryHead1 = createBoardHead(
            1,
            recoveryGenesisHead.headDigest,
        );
        const recoveryHead2 = createBoardHead(2, recoveryHead1.headDigest);
        const recoveryHead3 = createBoardHead(3, recoveryHead2.headDigest);
        const recoveryContextHead = createBoardHead(
            4,
            recoveryHead3.headDigest,
        );
        const newSigningKeyFixture = createKeyFixture(
            'participant:participant-1:new-signing',
        );
        const payload = {
            objectType: 'RecoveryEpochUpdate',
            objectVersion: 1,
            ceremonyId,
            signerIdentity: 'participant-1',
            recoveryRootPublicKeyDigest: recoveryRootKeyFixture.publicKeyDigest,
            recoveryPolicyDigest: manifestPolicyDigests.recoveryPolicyDigest,
            previousRecoveryEpoch: 0,
            newRecoveryEpoch: 1,
            previousDeviceEpoch: 0,
            newDeviceEpoch: 1,
            oldActionCutoffBoardSeq: 5,
            boardHeadDigest: recoveryContextHead.headDigest,
            newSigningPublicKeyDigest: newSigningKeyFixture.publicKeyDigest,
            restoredFrozenReceiverStateCommitment: deriveProtocolDigest(
                'EncryptedEnvelopeRoot',
                { receiverState: 'restored' },
            ),
            newTrusteeSetupCommitment: deriveProtocolDigest(
                'TrusteeSetupRoot',
                { trusteeSetup: 'new' },
            ),
        } satisfies Omit<
            RecoveryEpochUpdate,
            'recoveryEpochUpdateDigest' | 'signature'
        >;
        const recoveryEpochUpdateDigest =
            deriveRecoveryEpochUpdateDigest(payload);
        const update: RecoveryEpochUpdate = {
            ...payload,
            recoveryEpochUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                recoveryEpochUpdateDigest,
                { boardHeadHash: payload.boardHeadDigest },
            ),
        };
        const { head: recoveryUpdateHead, inclusionProofs } =
            createBoardHeadWithObjects(5, recoveryContextHead.headDigest, [
                {
                    objectType: 'RecoveryEpochUpdate',
                    objectDigest: recoveryEpochUpdateDigest,
                    boardPosition: 0,
                },
            ]);
        const recoveryUpdateInclusionProof = inclusionProofs[0];
        const verification = verifyRecoveryEpochUpdate({
            update,
            currentEntry,
            expectedRecoveryRootPublicKeyDigest:
                recoveryRootKeyFixture.publicKeyDigest,
            expectedRecoveryPolicyDigest:
                manifestPolicyDigests.recoveryPolicyDigest,
            boardEvidence: createBoardEvidence([
                recoveryGenesisHead,
                recoveryHead1,
                recoveryHead2,
                recoveryHead3,
                recoveryContextHead,
                recoveryUpdateHead,
            ]),
            updateInclusionProof: recoveryUpdateInclusionProof,
        });

        expect(verification.ok).toBe(true);
        expect(verification.updatedEntry).toMatchObject({
            currentRecoveryEpoch: 1,
            currentDeviceEpoch: 1,
        });
        const conflictingPayload = {
            ...payload,
            newSigningPublicKeyDigest: createKeyFixture(
                'participant:participant-1:different-new-signing',
            ).publicKeyDigest,
        };
        const conflictingRecoveryEpochUpdateDigest =
            deriveRecoveryEpochUpdateDigest(conflictingPayload);
        const conflictingUpdate: RecoveryEpochUpdate = {
            ...conflictingPayload,
            recoveryEpochUpdateDigest: conflictingRecoveryEpochUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                conflictingRecoveryEpochUpdateDigest,
                { boardHeadHash: payload.boardHeadDigest },
            ),
        };

        expect(
            verifyRecoveryEpochUpdate({
                update,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest:
                    recoveryRootKeyFixture.publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    recoveryUpdateHead,
                ]),
                updateInclusionProof: recoveryUpdateInclusionProof,
                conflictingUpdates: [conflictingUpdate],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RecoveryUpdateConflict' }),
            ]),
        );
        expect(
            verifyRecoveryEpochUpdate({
                update,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest: createKeyFixture(
                    'recovery-root:wrong',
                ).publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    recoveryUpdateHead,
                ]),
                updateInclusionProof: recoveryUpdateInclusionProof,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongPublicKey' }),
            ]),
        );
        const wrongRecoveryPolicyPayload = {
            ...payload,
            recoveryPolicyDigest: deriveProtocolDigest('RecoveryPolicyDigest', {
                policy: 'wrong-recovery-policy',
            }),
        };
        const wrongRecoveryPolicyUpdateDigest = deriveRecoveryEpochUpdateDigest(
            wrongRecoveryPolicyPayload,
        );
        const wrongRecoveryPolicyUpdate: RecoveryEpochUpdate = {
            ...wrongRecoveryPolicyPayload,
            recoveryEpochUpdateDigest: wrongRecoveryPolicyUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                wrongRecoveryPolicyUpdateDigest,
                { boardHeadHash: payload.boardHeadDigest },
            ),
        };
        const {
            head: wrongPolicyUpdateHead,
            inclusionProofs: wrongPolicyProofs,
        } = createBoardHeadWithObjects(5, recoveryContextHead.headDigest, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectDigest: wrongRecoveryPolicyUpdateDigest,
                boardPosition: 0,
            },
        ]);

        expect(
            verifyRecoveryEpochUpdate({
                update: wrongRecoveryPolicyUpdate,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest:
                    recoveryRootKeyFixture.publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    wrongPolicyUpdateHead,
                ]),
                updateInclusionProof: wrongPolicyProofs[0],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'RecoveryUpdateInvalid' }),
            ]),
        );
        const wrongCeremonyPayload = {
            ...payload,
            ceremonyId: 'ceremony-other',
        };
        const wrongCeremonyRecoveryUpdateDigest =
            deriveRecoveryEpochUpdateDigest(wrongCeremonyPayload);
        const wrongCeremonyUpdate: RecoveryEpochUpdate = {
            ...wrongCeremonyPayload,
            recoveryEpochUpdateDigest: wrongCeremonyRecoveryUpdateDigest,
            signature: createSignature(
                'RecoveryEpochUpdate',
                'RecoveryRoot',
                'participant-1',
                recoveryRootKeyFixture.publicKeyDigest,
                wrongCeremonyRecoveryUpdateDigest,
                {
                    boardHeadHash: payload.boardHeadDigest,
                    ceremonyId: 'ceremony-other',
                },
            ),
        };
        const {
            head: wrongCeremonyUpdateHead,
            inclusionProofs: wrongCeremonyProofs,
        } = createBoardHeadWithObjects(5, recoveryContextHead.headDigest, [
            {
                objectType: 'RecoveryEpochUpdate',
                objectDigest: wrongCeremonyRecoveryUpdateDigest,
                boardPosition: 0,
            },
        ]);

        expect(
            verifyRecoveryEpochUpdate({
                update: wrongCeremonyUpdate,
                currentEntry,
                expectedRecoveryRootPublicKeyDigest:
                    recoveryRootKeyFixture.publicKeyDigest,
                expectedRecoveryPolicyDigest:
                    manifestPolicyDigests.recoveryPolicyDigest,
                boardEvidence: createBoardEvidence([
                    recoveryGenesisHead,
                    recoveryHead1,
                    recoveryHead2,
                    recoveryHead3,
                    recoveryContextHead,
                    wrongCeremonyUpdateHead,
                ]),
                updateInclusionProof: wrongCeremonyProofs[0],
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'WrongCeremony' }),
            ]),
        );

        const staleActionPayload = {
            ceremonyId,
            electionManifestDigest: deriveProtocolDigest(
                'ElectionManifestDigest',
                { manifest: 'main' },
            ),
            signerIdentity: 'participant-1',
            boardHeadDigest: payload.boardHeadDigest,
            boardSeq: 6,
            recoveryEpoch: 0,
            deviceEpoch: 0,
            actionSequence: 1,
            recoveryPolicyDigest: manifestPolicyDigests.recoveryPolicyDigest,
            acceptedRecoveryEpochUpdateDigest: recoveryEpochUpdateDigest,
            contextDigest,
        };
        const staleActionContext: ActionContext = {
            ...staleActionPayload,
            actionContextDigest: deriveActionContextDigest(staleActionPayload),
        };

        expect(
            isActionCurrentForRecoveryEpoch({
                actionContext: staleActionContext,
                recoveryEpochState: verification.updatedEntry ?? currentEntry,
            }).refusedObjects,
        ).toEqual(
            expect.arrayContaining([
                expect.objectContaining({ code: 'StaleRecoveryEpoch' }),
            ]),
        );
    });
});
