import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveProtocolDigest,
    deriveProtocolSignatureDigest,
} from '@sealed-lattice/crypto';
import {
    bridgeWitnessPrivacyProfileId,
    cpadProfileId,
    encryptedAggregateBridgeProfileId,
    evaluationNoiseProfileId,
    evaluationProofProfileId,
    mobileProfileId,
    thresholdDecryptionProfileId,
} from '@sealed-lattice/types';
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
    targetFinalityScope: 'target',
    witnessQuorum: 5,
    totalWitnesses: 7,
});
export const defaultTopKEvaluationRecordDigest = deriveProtocolDigest(
    'TopKEvaluationRecordDigest',
    { proposal: 'top-k' },
);
export const defaultThresholdProfileDigest = deriveProtocolDigest(
    'ThresholdProfileDigest',
    { profile: 'default-target-finality-threshold-profile' },
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
    targetFinalityScope: 'target',
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
    firstValidPolicyDigest: deriveProtocolDigest('FirstValidPolicyDigest', {
        policy: 'canonical-signed-board-order-current-epoch',
    }),
    recoveryPolicyDigest: deriveProtocolDigest('RecoveryPolicyDigest', {
        policy: 'same-slot-recovery-v1',
    }),
    targetFinalityPolicyDigest,
    witnessPolicyDigest,
};
export const manifestOpaqueBindings: ManifestOpaqueBindings = {
    encryptedAggregateBridgeProfileId,
    bridgeWitnessPrivacyProfileId,
    heParamDigest: deriveProtocolDigest('HEParamDigest', {
        profile: 'BGV-RNS-v1',
    }),
    bgvProfileDigest: deriveProtocolDigest('BGVProfileDigest', {
        profile: 'BGV-RNS-v1',
    }),
    rustBgvBackendProfileDigest: deriveProtocolDigest(
        'RustBgvBackendProfileDigest',
        {
            backend: 'sealed-lattice-rust-wasm-bgv-rns-v1',
        },
    ),
    bgvPublicKeyRoot: deriveProtocolDigest('BGVPublicKeyRoot', {
        key: 'bgv-collective',
    }),
    collectivePublicKeyRoot: deriveProtocolDigest('CollectivePublicKeyRoot', {
        key: 'bgv-collective',
    }),
    canonicalCiphertextConventionDigest: deriveProtocolDigest(
        'CanonicalCiphertextConventionDigest',
        { convention: 'bgv-rns-coefficient-domain-c0-plus-c1-s' },
    ),
    encryptedAggregateBridgeDigest: deriveProtocolDigest(
        'EncryptedAggregateBridgeDigest',
        {
            profile: encryptedAggregateBridgeProfileId,
        },
    ),
    bridgeWitnessPrivacyProfileDigest: deriveProtocolDigest(
        'BridgeWitnessPrivacyProfileDigest',
        {
            profile: bridgeWitnessPrivacyProfileId,
        },
    ),
    bgvBatchEncoderDigest: deriveProtocolDigest('BGVBatchEncoderDigest', {
        layout: 'WinnerRankTopK-v1',
    }),
    bridgeLayoutDigest: deriveProtocolDigest('BridgeLayoutDigest', {
        layout: 'encrypted-aggregate-target-basis-data-layout-v1',
    }),
    encryptedAggregateTargetBasisDataRoot: deriveProtocolDigest(
        'EncryptedAggregateTargetBasisDataRoot',
        {
            layout: 'encrypted-aggregate-target-basis-data-v1',
        },
    ),
    encryptedAggregateShareCiphertextRoot: deriveProtocolDigest(
        'EncryptedAggregateShareCiphertextRoot',
        {
            layout: 'encrypted-aggregate-share-ciphertexts-v1',
        },
    ),
    encryptedAggregateReconstructionDigest: deriveProtocolDigest(
        'EncryptedAggregateReconstructionDigest',
        {
            circuit: 'encrypted-aggregate-reconstruction-v1',
        },
    ),
    scoreBitDerivationCircuitDigest: deriveProtocolDigest(
        'ScoreBitDerivationCircuitDigest',
        {
            circuit: 'score-bit-derivation-circuit-v1',
        },
    ),
    comparisonInputDerivationCircuitDigest: deriveProtocolDigest(
        'ComparisonInputDerivationCircuitDigest',
        {
            circuit: 'comparison-input-derivation-circuit-v1',
        },
    ),
    encryptedComparisonInputDigest: deriveProtocolDigest(
        'EncryptedComparisonInputDigest',
        {
            layout: 'encrypted-comparison-inputs-v1',
        },
    ),
    evaluationNoiseProfileDigest: deriveProtocolDigest(
        'EvaluationNoiseProfileDigest',
        {
            profile: evaluationNoiseProfileId,
        },
    ),
    heEvaluationNoiseCertDigest: deriveProtocolDigest(
        'HEEvaluationNoiseCertDigest',
        { certificate: 'he-evaluation-noise-v1' },
    ),
    allowedEvaluatorOpsDigest: deriveProtocolDigest(
        'AllowedEvaluatorOpsDigest',
        { operations: 'packed-bit-sliced-bgv-top-k-v1' },
    ),
    evaluationProofProfileId,
    evaluationProofProfileDigest: deriveProtocolDigest(
        'EvaluationProofProfileDigest',
        { profile: evaluationProofProfileId },
    ),
    thresholdDecryptionProfileId,
    thresholdDecryptionProfileDigest: deriveProtocolDigest(
        'ThresholdDecryptionProfileDigest',
        { profile: thresholdDecryptionProfileId },
    ),
    bgvAsyncThresholdCPADProfileDigest: deriveProtocolDigest(
        'BGVAsyncThresholdCPADProfileDigest',
        { profile: thresholdDecryptionProfileId },
    ),
    cpadProfileId,
    cpadProfileDigest: deriveProtocolDigest('CPADProfileDigest', {
        profile: cpadProfileId,
    }),
    targetBasisDigest: deriveProtocolDigest('TargetBasisDigest', {
        profile: 'target-basis-v1',
    }),
    mobileProfileId,
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
