import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveProtocolDigest,
    deriveProtocolSignatureDigest,
} from '@sealed-lattice/crypto';
import type {
    CanonicalSignedRootObject,
    ManifestOpaqueBindings,
    ManifestPolicyDigests,
    ProtocolSignatureEnvelope,
    SignedObjectType,
    SignerRole,
    WitnessPolicy,
} from '@sealed-lattice/types';

import {
    deriveTargetFinalityPolicyDigest,
    deriveWitnessPolicyDigest,
} from '../../src/finality/index';

export const ceremonyId = 'ceremony-main';
export const boardPolicyDigest = deriveProtocolDigest('BoardPolicyDigest', {
    policy: 'signed-head-chain-v1',
});
export const contextDigest = deriveProtocolDigest('ActionContextDigest', {
    context: 'default',
});
export const profile = createMlDsaSignatureProfileFixture();

export const keyFixturesByDigest = new Map<
    string,
    ReturnType<typeof createMlDsaKeyPairFixture>
>();
export const createKeyFixture = (
    seedLabel: string,
): ReturnType<typeof createMlDsaKeyPairFixture> => {
    const keyFixture = createMlDsaKeyPairFixture(seedLabel);
    keyFixturesByDigest.set(keyFixture.publicKeyDigest, keyFixture);

    return keyFixture;
};
export const boardKeyFixture = createKeyFixture('board');
export const organizerKeyFixture = createKeyFixture('organizer');
export const recoveryRootKeyFixture = createKeyFixture(
    'recovery-root:participant-1',
);
export const getParticipantKeyFixture = (
    participantIdentity: string,
): ReturnType<typeof createMlDsaKeyPairFixture> =>
    createKeyFixture(`participant:${participantIdentity}`);
export const getWitnessKeyFixture = (
    witnessIdentity: string,
): ReturnType<typeof createMlDsaKeyPairFixture> =>
    createKeyFixture(`witness:${witnessIdentity}`);
export const boardPublicKeyDigest = boardKeyFixture.publicKeyDigest;
export const organizerPublicKeyDigest = organizerKeyFixture.publicKeyDigest;
export const getParticipantSigningPublicKeyDigest = (
    participantIdentity: string,
): string =>
    participantIdentity === 'organizer'
        ? organizerPublicKeyDigest
        : getParticipantKeyFixture(participantIdentity).publicKeyDigest;
export const witnessIdentities = [
    'witness-1',
    'witness-2',
    'witness-3',
    'witness-4',
    'witness-5',
    'witness-6',
    'witness-7',
] as const;
export const witnessPolicyDigest = deriveWitnessPolicyDigest({
    witnessIdentities,
    witnessQuorum: 5,
    totalWitnesses: 7,
});
export const targetFinalityPolicyDigest = deriveTargetFinalityPolicyDigest({
    targetPhase: 'target',
    witnessQuorum: 5,
    totalWitnesses: 7,
});
export const defaultTopKEvaluationRecordDigest = deriveProtocolDigest(
    'TopKEvaluationRecordDigest',
    { proposal: 'top-k' },
);
export const witnessPublicKeyDigests = Object.fromEntries(
    witnessIdentities.map((witnessIdentity) => [
        witnessIdentity,
        getWitnessKeyFixture(witnessIdentity).publicKeyDigest,
    ]),
);
export const witnessPolicy: WitnessPolicy = {
    witnessPolicyDigest,
    witnessIdentities,
    witnessQuorum: 5,
    totalWitnesses: 7,
};
export const targetFinalityPolicy = {
    targetFinalityPolicyDigest,
    targetPhase: 'target',
    witnessQuorum: 5,
    totalWitnesses: 7,
};

export const manifestPolicyDigests: ManifestPolicyDigests = {
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
export const manifestOpaqueBindings: ManifestOpaqueBindings = {
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

export const createSignature = (
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
            manifestDigest: null,
            boardHeadDigest: null,
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

export const replaceSignatureBytes = (
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

export const replaceSignaturePublicKeyBytes = (
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

export const replaceSignatureProfile = (
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
