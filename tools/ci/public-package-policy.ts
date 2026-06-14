export type VendoredProtocolRuntimeEntryExport = {
    readonly exports: readonly string[];
    readonly runtimeFacadeExports?: readonly string[];
    readonly source: string;
};

export type PublicPackagePolicy = {
    readonly forbiddenRuntimeExports: readonly string[];
    readonly forbiddenTypeExports: readonly string[];
    readonly vendoredCryptoRuntimeModules: readonly string[];
    readonly vendoredProtocolRuntimeEntryExports: readonly VendoredProtocolRuntimeEntryExport[];
    readonly vendoredProtocolRuntimeModules: readonly string[];
};

export const forbiddenTypeExports = [
    'BallotEncryptionRandomness',
    'BallotProofRandomness',
    'BgvBatchPlaintextEncoding',
    'BgvCanonicalObjectAnalysis',
    'BgvObjectValidation',
    'BgvPassiveSetupPackage',
    'BgvPassiveSetupParticipantInput',
    'BgvPassiveSetupVerification',
    'BgvPublicEvaluationKeyMaterial',
    'BgvReferenceOracleRejection',
    'DirectEncryptedBallotProofWitness',
    'DirectEncryptedBallotWitness',
    'EvaluationKeyProofCommonInput',
    'EvaluationKeyShareProofGenerationBase',
    'EvaluationKeyShareProofGenerationOutput',
    'EvaluationKeyShareProofGenerator',
    'GaloisKeyShareProofGeneration',
    'PreparedBgvPublicEvaluationKeyMaterial',
    'RawBgvCiphertext',
    'RawBgvSecretKey',
    'RelinearizationKeyShareProofGeneration',
    'SparseTargetProjectionWitness',
    'TopKEvaluatorDevelopmentEvaluation',
    'TopKEvaluatorDevelopmentEvaluationInput',
    'TopKEvaluatorDirectAggregateEvaluation',
    'TopKEvaluatorDirectAggregateEvaluationInput',
    'TopKEvaluatorDirectAggregateInput',
] as const;

export const forbiddenRuntimeExports = [
    'bootstrap',
    'createShamirPolynomial',
    'analyzeBgvCanonicalObject',
    'decodeBgvCanonicalObject',
    'decodeSparseTopKTarget',
    'decryptAggregateHistogram',
    'decryptAggregateScore',
    'decryptAggregateScoreBits',
    'decryptComparisonInput',
    'decryptComparisonBit',
    'decryptDirectAggregate',
    'decryptExactSum',
    'decryptIntermediateWire',
    'decryptRank',
    'decryptTopKCiphertext',
    'decryptToFile',
    'decryptToString',
    'deriveDirectEncryptedBallotHash',
    'derivePlaintextTopKOracle',
    'describeBgvOperationRegistry',
    'describeBgvRnsProfile',
    'dockerOracle',
    'encodeBgvBatchPlaintext',
    'exportDirectBallotWitness',
    'exportProofWitness',
    'exportSecretKey',
    'exportShare',
    'fieldModulus',
    'generateBgvBaseConversionFixture',
    'generateBgvCiphertextConventionFixture',
    'generateBgvPassiveSetupPackage',
    'generateDirectEncryptedBallot',
    'generateDirectEncryptedBallotProofWitness',
    'getShare',
    'importSecretKey',
    'lattigoOracle',
    'oracleSerializer',
    'oracleVectorGenerator',
    'partialDecrypt',
    'partialDecryptWithoutTarget',
    'publishDirectAggregateOpening',
    'rawDirectBallotWitness',
    'rawHEAdd',
    'rawHEMul',
    'rawHENoiseBudget',
    'rawHERelin',
    'rawHERotate',
    'rawNTT',
    'rawRNSLimbAccess',
    'setNoiseFloodSigma',
    'setSecretKey',
    'setSmudgingDistribution',
    'thresholdDecrypt',
    'verifyBgvCiphertextObject',
    'verifyBgvLattigoOracle',
    'verifyBgvPlaintextObject',
    'verifyDirectEncryptedBallotProofWitness',
    'verifyDirectEncryptedBallotWitness',
    'verifyLattigoOracle',
    'verifyTargetAcceptedRecord',
    'verifyTestShareCommitmentOpening',
    'verifyTopKDecryptionShareShell',
] as const;

export const vendoredProtocolRuntimeModules = [
    'board/consistency.ts',
    'board/hashes.ts',
    'board/head-chain.ts',
    'board/inclusion-proof.ts',
    'board/index.ts',
    'board/shell-evidence.ts',
    'closing/index.ts',
    'common/verification-helpers.ts',
    'finality/hashes.ts',
    'finality/index.ts',
    'foundation/index.ts',
    'lifecycle/capabilities.ts',
    'lifecycle/labels.ts',
    'lifecycle/lifecycle.ts',
    'lifecycle/poll-spec.ts',
    'lifecycle/profiles.ts',
    'lifecycle/refusal.ts',
    'lifecycle/thresholds.ts',
    'ordering/index.ts',
    'recovery/index.ts',
    'roster/hashes.ts',
    'roster/inclusion.ts',
    'roster/index.ts',
    'roster/object-validation.ts',
    'roster/verification.ts',
    'setup/common-randomness-records.ts',
    'setup/binary-chunk-writer.ts',
    'setup/evaluation-key-proof-records.ts',
    'setup/evaluator-key-schedule.ts',
    'setup/local-trustee-setup-state.ts',
    'setup/private-vss-mailbox-delivery.ts',
    'setup/public-key-share-records.ts',
    'setup/same-secret-consistency-records.ts',
    'setup/setup-proof-material-transport.ts',
    'setup/setup-contribution-orchestration.ts',
    'setup/setup-certificates.ts',
    'setup/setup-package-assembly.ts',
    'setup/setup-phase-records.ts',
    'setup/threshold-share-commitments.ts',
    'setup/vss-coefficient-commitments.ts',
    'setup/vss-share-verification-records.ts',
] as const;

export const vendoredCryptoRuntimeModules = [
    'canonical-json.ts',
    'hashes.ts',
    'index.ts',
    'local-trustee-state-storage.ts',
    'private-vss-mailbox.ts',
    'signatures.ts',
] as const;

export const vendoredProtocolRuntimeEntryExports = [
    {
        source: 'board/index.js',
        exports: ['verifyBoardConsistency'],
    },
    {
        source: 'closing/index.js',
        exports: ['verifyCastReceiptShell', 'verifyCloseRecordShell'],
    },
    {
        source: 'finality/index.js',
        exports: ['verifyTargetFinality'],
    },
    {
        source: 'foundation/index.js',
        exports: ['verifyFoundationTranscript'],
    },
    {
        source: 'lifecycle/capabilities.js',
        exports: ['evaluateActionCapability'],
    },
    {
        source: 'lifecycle/labels.js',
        exports: ['deriveLifecycleLabels'],
    },
    {
        source: 'lifecycle/lifecycle.js',
        exports: ['isValidLifecycleTransition'],
    },
    {
        source: 'lifecycle/poll-spec.js',
        exports: ['derivePollSpecHash', 'validatePollSpec'],
    },
    {
        source: 'lifecycle/thresholds.js',
        exports: [
            'deriveFrozenRosterProfile',
            'deriveThresholdProfile',
            'deriveThresholdProfileHash',
        ],
    },
    {
        source: 'ordering/index.js',
        exports: ['deriveValidatedFirstValidOrder'],
    },
    {
        source: 'recovery/index.js',
        exports: [
            'isActionCurrentForRecoveryEpoch',
            'verifyRecoveryEpochUpdate',
        ],
    },
    {
        source: 'roster/index.js',
        exports: [
            'verifyRosterExternalAcceptance',
            'verifyRosterManifestTranscript',
        ],
    },
    {
        source: 'setup/local-trustee-setup-state.js',
        exports: [
            'createEncryptedLocalTrusteeSetupStateFromVerifiedShares',
            'decryptLocalTrusteeSetupState',
        ],
        runtimeFacadeExports: [
            'exportEncryptedLocalTrusteeSetupState',
            'restoreLocalTrusteeSetupState',
        ],
    },
    {
        source: 'setup/common-randomness-records.js',
        exports: [
            'createCommonRandomnessCommit',
            'createCommonRandomnessReveal',
            'createSetupCommonRandomness',
        ],
    },
    {
        source: 'setup/public-key-share-records.js',
        exports: [
            'createBinaryChunkedPublicKeyShareMaterialTransport',
            'createBinaryChunkedPublicKeyShareProofMaterialTransport',
            'createPublicKeyShareMaterialSet',
            'createPublicKeyShareProofSet',
            'createPublicKeyShareSet',
            'createPublicKeyShareSuccinctProofSet',
        ],
    },
    {
        source: 'setup/same-secret-consistency-records.js',
        exports: [
            'createBinaryChunkedSameSecretProofMaterialTransport',
            'createSameSecretProofSet',
        ],
    },
    {
        source: 'setup/evaluator-key-schedule.js',
        exports: ['createEvaluatorKeySchedule'],
    },
    {
        source: 'setup/evaluation-key-proof-records.js',
        exports: [
            'createBinaryChunkedEvaluationKeyShareMaterialTransport',
            'createBinaryChunkedPublicEvaluationKeyMaterialTransport',
            'createGaloisKeyShareBatches',
            'createPublicEvaluationKeySet',
            'createRelinearizationKeyShareRounds',
        ],
    },
    {
        source: 'setup/setup-contribution-orchestration.js',
        exports: ['createSetupContributionAssembly'],
        runtimeFacadeExports: ['createSetupContribution'],
    },
    {
        source: 'setup/setup-certificates.js',
        exports: ['createSetupCertificates'],
    },
    {
        source: 'setup/setup-package-assembly.js',
        exports: ['createSetupPackage', 'createSetupPackageVerificationInput'],
    },
    {
        source: 'setup/setup-phase-records.js',
        exports: [
            'createSetupPhaseParticipantObject',
            'createSetupPhaseRecord',
        ],
        runtimeFacadeExports: ['createSetupIntent', 'createSetupPhaseRecord'],
    },
    {
        source: 'setup/vss-share-verification-records.js',
        exports: [
            'createVssShareAcceptanceRecord',
            'createVssShareComplaintRecordFromLocalVerification',
        ],
        runtimeFacadeExports: [
            'createVssShareAcceptance',
            'createVssComplaint',
        ],
    },
] as const satisfies readonly VendoredProtocolRuntimeEntryExport[];

export const publicPackagePolicy = {
    forbiddenTypeExports,
    forbiddenRuntimeExports,
    vendoredCryptoRuntimeModules,
    vendoredProtocolRuntimeEntryExports,
    vendoredProtocolRuntimeModules,
} satisfies PublicPackagePolicy;
