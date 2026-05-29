import {
    createMlDsaKeyPairFixture,
    createMlDsaSignatureProfileFixture,
    createProtocolSignatureFixture,
    deriveProtocolHash,
    deriveProtocolSignatureHash,
} from '@sealed-lattice/crypto';
import {
    bgvPassiveSetupProfileId,
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

const deriveFixtureHash = (
    purpose: string,
    payload: Record<string, unknown>,
): string =>
    deriveProtocolHash('ChallengeDomainHash', {
        payload,
        purpose,
    });

export const ceremonyId = 'ceremony-main';
export const boardPolicyHash = deriveFixtureHash('fixture-board-policy-v1', {
    policy: 'signed-head-chain-v1',
});
export const contextHash = deriveProtocolHash('ActionContextHash', {
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
export const defaultTopKEvaluationRecordHash = deriveFixtureHash(
    'fixture-top-k-evaluation-record-v1',
    { proposal: 'top-k' },
);
export const defaultThresholdProfileHash = deriveProtocolHash(
    'ThresholdProfileHash',
    { profile: 'default-target-finality-threshold-profile' },
);
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
    encryptedAggregateBridgeProfileId,
    bgvPassiveSetupProfileId,
    bridgeWitnessPrivacyProfileId,
    heParamHash: deriveFixtureHash('fixture-he-parameter-profile-v1', {
        profile: 'BGV-RNS-v1',
    }),
    bgvPassiveSetupPackageHash: deriveProtocolHash(
        'BGVPassiveSetupPackageHash',
        {
            setup: 'passive-full-roster-bgv',
        },
    ),
    bgvSetupParameterCertificateHash: deriveProtocolHash(
        'BGVSetupParameterCertificateHash',
        {
            setup: 'parameter-certificate',
        },
    ),
    bgvProfileHash: deriveProtocolHash('BGVProfileHash', {
        profile: 'BGV-RNS-v1',
    }),
    rustBgvBackendProfileHash: deriveProtocolHash('RustBgvBackendProfileHash', {
        backend: 'sealed-lattice-rust-wasm-bgv-rns-v1',
    }),
    bgvPublicKeyRoot: deriveProtocolHash('BGVPublicKeyRoot', {
        key: 'bgv-collective',
    }),
    collectivePublicKeyRoot: deriveProtocolHash('CollectivePublicKeyRoot', {
        key: 'bgv-collective',
    }),
    collectiveSecretDistributionCertificateHash: deriveProtocolHash(
        'CollectiveSecretDistributionCertificateHash',
        {
            setup: 'secret-distribution',
        },
    ),
    errorDistributionCertificateHash: deriveProtocolHash(
        'ErrorDistributionCertificateHash',
        {
            setup: 'error-distribution',
        },
    ),
    keySwitchDecompositionHash: deriveProtocolHash(
        'KeySwitchDecompositionHash',
        {
            profile: 'key-switch-decomposition',
        },
    ),
    canonicalCiphertextConventionHash: deriveProtocolHash(
        'CanonicalCiphertextConventionHash',
        { convention: 'bgv-rns-coefficient-domain-c0-plus-c1-s' },
    ),
    encryptedAggregateBridgeHash: deriveProtocolHash(
        'EncryptedAggregateBridgeHash',
        {
            profile: encryptedAggregateBridgeProfileId,
        },
    ),
    bridgeWitnessPrivacyProfileHash: deriveFixtureHash(
        'fixture-bridge-witness-privacy-profile-v1',
        { profile: bridgeWitnessPrivacyProfileId },
    ),
    bgvBatchEncoderHash: deriveProtocolHash('BGVBatchEncoderHash', {
        layout: 'WinnerRankTopK-v1',
    }),
    bridgeLayoutHash: deriveFixtureHash('fixture-bridge-layout-v1', {
        layout: 'encrypted-aggregate-input-layout-v1',
    }),
    encryptedAggregateInputRoot: deriveFixtureHash(
        'fixture-encrypted-aggregate-input-root-v1',
        { layout: 'encrypted-aggregate-input-v1' },
    ),
    encryptedAggregateShareCiphertextRoot: deriveProtocolHash(
        'EncryptedAggregateShareCiphertextRoot',
        {
            layout: 'encrypted-aggregate-share-ciphertexts-v1',
        },
    ),
    encryptedAggregateReconstructionHash: deriveProtocolHash(
        'EncryptedAggregateReconstructionHash',
        {
            circuit: 'encrypted-aggregate-reconstruction-v1',
        },
    ),
    scoreBitDerivationCircuitHash: deriveProtocolHash(
        'ScoreBitDerivationCircuitHash',
        {
            circuit: 'score-bit-derivation-circuit-v1',
            selectedEvaluatorPath:
                'encrypted-aggregate-score-bit-derivation-v1',
        },
    ),
    encryptedScoreBitInputHash: deriveProtocolHash(
        'EncryptedScoreBitInputHash',
        {
            layout: 'encrypted-score-bit-inputs-v1',
            selectedEvaluatorPath:
                'encrypted-aggregate-score-bit-derivation-v1',
        },
    ),
    comparisonInputDerivationCircuitHash: deriveProtocolHash(
        'ComparisonInputDerivationCircuitHash',
        {
            circuit: 'comparison-input-derivation-circuit-v1',
            futureDesignNoteRequired: true,
            selectedEvaluatorPath:
                'inactive-future-direct-comparison-input-profile',
        },
    ),
    encryptedComparisonInputHash: deriveProtocolHash(
        'EncryptedComparisonInputHash',
        {
            futureDesignNoteRequired: true,
            layout: 'encrypted-comparison-inputs-v1',
            selectedEvaluatorPath:
                'inactive-future-direct-comparison-input-profile',
        },
    ),
    evaluationNoiseProfileHash: deriveFixtureHash(
        'fixture-evaluation-noise-profile-v1',
        {
            profile: evaluationNoiseProfileId,
        },
    ),
    heEvaluationNoiseCertHash: deriveFixtureHash('fixture-he-noise-cert-v1', {
        certificate: 'he-evaluation-noise-v1',
    }),
    allowedEvaluatorOpsHash: deriveProtocolHash('AllowedEvaluatorOpsHash', {
        operations: 'packed-bit-sliced-bgv-top-k-v1',
    }),
    rotSetHash: deriveProtocolHash('RotSetHash', {
        rotations: 'provisional-encrypted-aggregate-evaluator-top-k',
    }),
    evaluationKeyRoot: deriveProtocolHash('EvalKeyRoot', {
        keys: 'provisional-encrypted-aggregate-evaluator-top-k',
    }),
    evaluationKeySizeProfileHash: deriveProtocolHash(
        'EvaluationKeySizeProfileHash',
        {
            profile: 'passive-bgv-setup-evaluation-key-size',
        },
    ),
    thresholdShareVerificationKeyRoot: deriveProtocolHash(
        'ThresholdShareVerificationKeyRoot',
        {
            setup: 'threshold-share-verification-key-set',
        },
    ),
    thresholdShareVerificationKeyHash: deriveProtocolHash(
        'ThresholdShareVerificationKeyHash',
        {
            setup: 'threshold-share-verification-key-set',
        },
    ),
    evaluationProofProfileId,
    evaluationProofProfileHash: deriveFixtureHash(
        'fixture-evaluation-proof-profile-v1',
        { profile: evaluationProofProfileId },
    ),
    thresholdDecryptionProfileId,
    thresholdDecryptionProfileHash: deriveProtocolHash(
        'ThresholdDecryptionProfileHash',
        { profile: thresholdDecryptionProfileId },
    ),
    kllpsTargetDecryptionProfileHash: deriveProtocolHash(
        'KllpsTargetDecryptionProfileHash',
        { profile: thresholdDecryptionProfileId },
    ),
    cpadProfileId,
    cpadProfileHash: deriveFixtureHash('fixture-cpad-profile-v1', {
        profile: cpadProfileId,
    }),
    targetBasisHash: deriveProtocolHash('TargetBasisHash', {
        profile: 'target-basis-v1',
    }),
    mobileProfileId,
    bridgeBenchmarkReportPolicyHash: deriveFixtureHash(
        'fixture-bridge-benchmark-report-policy-v1',
        { policy: 'bridge-benchmark-report' },
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
