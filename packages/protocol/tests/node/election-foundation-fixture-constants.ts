import {
    deriveCanonicalObjectHash,
    deriveProtocolSignatureHash,
} from '@sealed-lattice/crypto';
import {
    ballotValidityProofId,
    evaluatorReplayId,
    mobileRuntimeId,
    targetDecryptionId,
} from '@sealed-lattice/types';
import type {
    CanonicalSignedRootObject,
    ManifestOpaqueBindings,
    ManifestPolicyHashes,
    ProtocolSignatureEnvelope,
    SignedObjectType,
    SignerRole,
    WitnessPolicy,
} from '@sealed-lattice/types';

import {
    deriveTargetFinalityPolicyHash,
    deriveWitnessPolicyHash,
} from '#packages/protocol/src/finality/index';
import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
} from '#tests/support/protocol-signature-fixtures';

export const deriveFixtureHash = (
    purpose: string,
    payload: Record<string, unknown>,
): string =>
    deriveCanonicalObjectHash({
        objectType: 'FixtureChallenge',
        payload,
        purpose,
    });

export const ceremonyId = 'ceremony-main';
// The single canonical BGV parameter-set identity. This is the value returned by
// the kernel's describeBgvRnsParameters().bgvParametersHash (namespace
// "BGVParametersHash" over the full fixed BGV configuration). The manifest binds
// it opaquely and the trustee setup entry cross-binds the same value, so the
// fixture pins the kernel-computed hash rather than re-deriving the large
// parameter value object here.
export const bgvParametersHash =
    '7cf571a7d33b4d60410ad58ce7545a50b71f501a6f8d2e15ad31c3e646ba2cc5419daf36ce22413d31e1318474188f69ac90e300f71a9d5b90648d265f30deb0';
export const boardPolicyHash = deriveFixtureHash('fixture-board-policy-v1', {
    policy: 'signed-head-chain-v1',
});
export const contextHash = deriveCanonicalObjectHash({
    objectType: 'ActionContext',
    context: 'default',
});
export const profile = createMlDsaSignatureProfileFixture();

export const keyFixturesByHash = new Map<
    string,
    ReturnType<typeof createMlDsaKeyPairFixture>
>();
export const createKeyFixture = (
    seedLabel: string,
): ReturnType<typeof createMlDsaKeyPairFixture> => {
    const keyFixture = createMlDsaKeyPairFixture(seedLabel);
    keyFixturesByHash.set(keyFixture.publicKeyHash, keyFixture);

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
export const boardPublicKeyHash = boardKeyFixture.publicKeyHash;
export const organizerPublicKeyHash = organizerKeyFixture.publicKeyHash;
export const getParticipantSigningPublicKeyHash = (
    participantIdentity: string,
): string =>
    participantIdentity === 'organizer'
        ? organizerPublicKeyHash
        : getParticipantKeyFixture(participantIdentity).publicKeyHash;
export const witnessIdentities = [
    'witness-1',
    'witness-2',
    'witness-3',
    'witness-4',
    'witness-5',
    'witness-6',
    'witness-7',
] as const;
export const witnessPolicyHash = deriveWitnessPolicyHash({
    witnessIdentities,
    witnessQuorum: 5,
    totalWitnesses: 7,
});
export const targetFinalityPolicyHash = deriveTargetFinalityPolicyHash({
    targetFinalityScope: 'target',
    witnessQuorum: 5,
    totalWitnesses: 7,
});
export const defaultEvaluatorReplayRecordHash = deriveFixtureHash(
    'fixture-evaluator-replay-record-v1',
    { proposal: 'direct-evaluator-replay' },
);
export const defaultThresholdParametersHash = deriveCanonicalObjectHash({
    objectType: 'ThresholdParametersHash',
    parameters: 'default-target-finality-threshold-parameters',
});
export const dynamicRosterParametersCertificateHash = 'a'.repeat(128);
export const targetBoundShareSelectionParameters = {
    certificateHash: 'target-bound-certificate-hash',
    targetBasisHash: 'target-basis-hash',
    decryptionShareQuorum: 9,
    minimumSharesForInterpolation: 7,
    minimumArrivalsForRobustDecode: 9,
    invalidShareFilteringMode: 'ProofVerifiedSharesOnly',
} as const;
export const witnessPublicKeyHashes = Object.fromEntries(
    witnessIdentities.map((witnessIdentity) => [
        witnessIdentity,
        getWitnessKeyFixture(witnessIdentity).publicKeyHash,
    ]),
);
export const witnessPolicy: WitnessPolicy = {
    witnessPolicyHash,
    witnessIdentities,
    witnessQuorum: 5,
    totalWitnesses: 7,
};
export const targetFinalityPolicy = {
    targetFinalityPolicyHash,
    targetFinalityScope: 'target',
    witnessQuorum: 5,
    totalWitnesses: 7,
};

export const manifestPolicyHashes: ManifestPolicyHashes = {
    aggregateSelectionPolicyHash: deriveFixtureHash(
        'fixture-aggregate-selection-policy-v1',
        { policy: 'first-valid-aggregate-contributors' },
    ),
    duplicateBallotPolicyHash: deriveFixtureHash(
        'fixture-duplicate-ballot-policy-v1',
        {
            policy: 'first-valid-before-close',
        },
    ),
    firstValidPolicyHash: deriveFixtureHash('fixture-first-valid-policy-v1', {
        policy: 'canonical-signed-board-order-current-epoch',
    }),
    recoveryPolicyHash: deriveFixtureHash('fixture-recovery-policy-v1', {
        policy: 'same-slot-recovery-v1',
    }),
    targetFinalityPolicyHash,
    witnessPolicyHash,
};
export const manifestOpaqueBindings: ManifestOpaqueBindings = {
    heParamHash: deriveFixtureHash('fixture-he-parameter-set-v1', {
        parameters: 'BGV-RNS-v1',
    }),
    bgvPassiveSetupPackageHash: deriveCanonicalObjectHash({
        objectType: 'BGVPassiveSetupPackageHash',
        setup: 'passive-full-roster-bgv',
    }),
    bgvParametersHash,
    bgvPublicKeyRoot: deriveCanonicalObjectHash({
        objectType: 'BGVPublicKeyRoot',
        key: 'bgv-collective',
    }),
    collectivePublicKeyRoot: deriveCanonicalObjectHash({
        objectType: 'CollectivePublicKeyRoot',
        key: 'bgv-collective',
    }),
    keySwitchDecompositionHash: deriveCanonicalObjectHash({
        objectType: 'KeySwitchDecompositionHash',
        parameters: 'key-switch-decomposition',
    }),
    ballotValidityProofParametersHash: deriveFixtureHash(
        'fixture-ballot-validity-proof-v1',
        { parameters: ballotValidityProofId },
    ),
    comparisonInputDerivationCircuitHash: deriveCanonicalObjectHash({
        objectType: 'ComparisonInputDerivationCircuitHash',
        circuit: 'comparison-input-derivation-circuit-v1',
        selectedEvaluatorPath: 'direct-encrypted-score-comparison-v1',
    }),
    encryptedComparisonInputHash: deriveCanonicalObjectHash({
        objectType: 'EncryptedComparisonInputHash',
        layout: 'encrypted-comparison-inputs-v1',
        selectedEvaluatorPath: 'direct-encrypted-score-comparison-v1',
    }),
    encryptedSparseTargetProjectionHash: deriveCanonicalObjectHash({
        objectType: 'EncryptedSparseTargetProjectionHash',
        circuit: 'encrypted-sparse-target-projection-v1',
    }),
    targetLayoutHash: deriveCanonicalObjectHash({
        objectType: 'TargetLayoutHash',
        layout: 'direct-sparse-target-layout-v1',
    }),
    evaluatorReplayParametersHash: deriveFixtureHash(
        'fixture-evaluator-replay-v1',
        { parameters: evaluatorReplayId },
    ),
    evaluationNoiseParametersHash: deriveFixtureHash(
        'fixture-direct-evaluator-noise-v1',
        { parameters: 'direct-evaluator-noise-v1' },
    ),
    heEvaluationNoiseCertHash: deriveFixtureHash('fixture-he-noise-cert-v1', {
        certificate: 'direct-evaluator-noise-v1',
    }),
    rotSetHash: deriveCanonicalObjectHash({
        objectType: 'RotSetHash',
        rotations: 'direct-encrypted-ballot-evaluator-replay',
    }),
    evaluationKeyRoot: deriveCanonicalObjectHash({
        objectType: 'EvalKeyRoot',
        keys: 'direct-encrypted-ballot-evaluator-replay',
    }),
    evaluationKeySizeParametersHash: deriveCanonicalObjectHash({
        objectType: 'EvaluationKeySizeParametersHash',
        parameters: 'passive-bgv-setup-evaluation-key-size',
    }),
    thresholdShareVerificationKeyRoot: deriveCanonicalObjectHash({
        objectType: 'ThresholdShareVerificationKeyRoot',
        setup: 'threshold-share-verification-key-set',
    }),
    thresholdShareVerificationKeyHash: deriveCanonicalObjectHash({
        objectType: 'ThresholdShareVerificationKeyHash',
        setup: 'threshold-share-verification-key-set',
    }),
    trusteeThresholdVerificationKeyHash: deriveCanonicalObjectHash({
        objectType: 'TrusteeThresholdVerificationKeyHash',
        setup: 'trustee-threshold-verification-key-set',
    }),
    targetDecryptionParametersHash: deriveCanonicalObjectHash({
        objectType: 'TargetDecryptionParametersHash',
        parameters: targetDecryptionId,
    }),
    targetBasisHash: deriveFixtureHash('fixture-target-basis-v1', {
        parameters: 'direct-target-basis-v1',
    }),
    mobileRuntimeParametersHash: deriveFixtureHash(
        'fixture-mobile-runtime-v1',
        {
            parameters: mobileRuntimeId,
        },
    ),
};

export const createSignature = (
    objectType: SignedObjectType,
    signerRole: SignerRole,
    signerIdentity: string,
    publicKeyHash: string,
    objectRoot: string,
    overrides: Partial<CanonicalSignedRootObject> = {},
): ProtocolSignatureEnvelope => {
    const keyFixture = keyFixturesByHash.get(publicKeyHash);
    if (keyFixture === undefined) {
        throw new Error(`Missing ML-DSA test key for ${publicKeyHash}.`);
    }

    return createProtocolSignatureFixture({
        profile,
        publicKeyHash,
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
            contextHash,
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
        publicKeyHash: signature.publicKeyHash,
        signatureBytesHex,
        signedRoot: signature.signedRoot,
    };

    return {
        ...payload,
        signatureHash: deriveProtocolSignatureHash(payload),
    };
};

export const replaceSignaturePublicKeyBytes = (
    signature: ProtocolSignatureEnvelope,
    publicKeyBytesHex: string,
): ProtocolSignatureEnvelope => {
    const payload = {
        profile: signature.profile,
        publicKeyBytesHex,
        publicKeyHash: signature.publicKeyHash,
        signatureBytesHex: signature.signatureBytesHex,
        signedRoot: signature.signedRoot,
    };

    return {
        ...payload,
        signatureHash: deriveProtocolSignatureHash(payload),
    };
};

export const replaceSignatureProfile = (
    signature: ProtocolSignatureEnvelope,
    profileOverride: ProtocolSignatureEnvelope['profile'],
): ProtocolSignatureEnvelope => {
    const payload = {
        profile: profileOverride,
        publicKeyBytesHex: signature.publicKeyBytesHex,
        publicKeyHash: signature.publicKeyHash,
        signatureBytesHex: signature.signatureBytesHex,
        signedRoot: signature.signedRoot,
    };

    return {
        ...payload,
        signatureHash: deriveProtocolSignatureHash(payload),
    };
};
