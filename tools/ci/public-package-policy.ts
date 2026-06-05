export type VendoredProtocolRuntimeEntryExport = {
    readonly exports: readonly string[];
    readonly source: string;
};

export type PublicPackagePolicy = {
    readonly forbiddenRuntimeExports: readonly string[];
    readonly forbiddenTypeExports: readonly string[];
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
    'PreparedBgvPublicEvaluationKeyMaterial',
    'RawBgvCiphertext',
    'RawBgvSecretKey',
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
    'verifyLocalReplayRecordShell',
    'verifyTargetAcceptedRecordShell',
    'verifyDirectAggregateOpening',
    'verifyTestShareCommitmentOpening',
    'verifyTopKDecryptionShareShell',
] as const;

export const vendoredProtocolRuntimeModules = [
    'board/hashes.ts',
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
        exports: ['deriveValidatedFirstValidOrder', 'verifyFirstValidPolicy'],
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
] as const satisfies readonly VendoredProtocolRuntimeEntryExport[];

export const publicPackagePolicy = {
    forbiddenTypeExports,
    forbiddenRuntimeExports,
    vendoredProtocolRuntimeEntryExports,
    vendoredProtocolRuntimeModules,
} satisfies PublicPackagePolicy;
