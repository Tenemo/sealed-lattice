export type VendoredProtocolRuntimeEntryExport = {
    readonly exports: readonly string[];
    readonly source: string;
};

export type PublicPackagePolicy = {
    readonly vendoredCryptoRuntimeModules: readonly string[];
    readonly vendoredProtocolRuntimeEntryExports: readonly VendoredProtocolRuntimeEntryExport[];
    readonly vendoredProtocolRuntimeModules: readonly string[];
};

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
    'lifecycle/lifecycle.ts',
    'lifecycle/poll-spec.ts',
    'lifecycle/refusal.ts',
    'lifecycle/roster-policy.ts',
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
    'setup/chunked-binary-reader.ts',
    'setup/common-fields.ts',
    'setup/varuint-encoding.ts',
    'setup/evaluation-key-proof-records.ts',
    'setup/evaluation-key-proof-records/constants-and-types.ts',
    'setup/evaluation-key-proof-records/encoding.ts',
    'setup/evaluation-key-proof-records/share-records.ts',
    'setup/evaluation-key-proof-records/trustee-proofs.ts',
    'setup/evaluation-key-proof-records/component-material-transport.ts',
    'setup/evaluation-key-proof-records/public-evaluation-key.ts',
    'setup/evaluator-key-schedule.ts',
    'setup/private-vss-mailbox-delivery.ts',
    'setup/proof-byte-encoding.ts',
    'setup/public-key-share-records.ts',
    'setup/public-key-share-records/constants-and-types.ts',
    'setup/public-key-share-records/encoding.ts',
    'setup/public-key-share-records/share-statement-records.ts',
    'setup/public-key-share-records/embedded-material-records.ts',
    'setup/public-key-share-records/binary-material-transport.ts',
    'setup/public-key-share-records/collective-public-key.ts',
    'setup/public-key-share-records/succinct-proofs.ts',
    'setup/same-secret-consistency-records.ts',
    'setup/setup-proof-material-transport.ts',
    'setup/setup-certificates.ts',
    'setup/setup-certificates/types.ts',
    'setup/setup-certificates/constants.ts',
    'setup/setup-certificates/field-helpers.ts',
    'setup/setup-certificates/parameter-derivations.ts',
    'setup/setup-certificates/transport-certificate.ts',
    'setup/setup-certificates/assembly.ts',
    'setup/setup-package-assembly.ts',
    'setup/setup-package-assembly/types.ts',
    'setup/setup-package-assembly/constants-and-assertions.ts',
    'setup/setup-package-assembly/verification-input.ts',
    'setup/setup-package-assembly/bindings.ts',
    'setup/setup-package-assembly/transported-material.ts',
    'setup/setup-package-assembly/certificates.ts',
    'setup/setup-package-assembly/assembly.ts',
    'setup/setup-phase-records.ts',
    'setup/vss-commitments.ts',
    'setup/vss-commitments/commitment-sets.ts',
    'setup/vss-commitments/linkage-and-bridge.ts',
    'setup/vss-commitments/proof-material-transport.ts',
    'setup/vss-coefficient-commitments.ts',
    'setup/vss-coefficient-commitments/constants-and-types.ts',
    'setup/vss-coefficient-commitments/encoding.ts',
    'setup/vss-coefficient-commitments/opening-state.ts',
    'setup/vss-coefficient-commitments/commitment-values.ts',
    'setup/vss-coefficient-commitments/commitment-bundles.ts',
    'setup/vss-share-verification-records.ts',
] as const;

export const vendoredCryptoRuntimeModules = [
    'canonical-json.ts',
    'hashes.ts',
    'index.ts',
    'local-trustee-state-storage.ts',
    'local-trustee-state-storage/aes-gcm.ts',
    'local-trustee-state-storage/constants-and-types.ts',
    'local-trustee-state-storage/envelope-validation.ts',
    'local-trustee-state-storage/operations.ts',
    'local-trustee-state-storage/validation.ts',
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
            'deriveFrozenRosterParameters',
            'deriveThresholdParameters',
            'deriveThresholdParametersHash',
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
            'deriveCollectiveBgvSetupRosterHash',
            'verifyRosterExternalAcceptance',
            'verifyRosterManifestTranscript',
        ],
    },
    {
        source: 'setup/setup-package-assembly.js',
        exports: ['createSetupPackageVerificationInput'],
    },
] as const satisfies readonly VendoredProtocolRuntimeEntryExport[];

export const publicPackagePolicy = {
    vendoredCryptoRuntimeModules,
    vendoredProtocolRuntimeEntryExports,
    vendoredProtocolRuntimeModules,
} satisfies PublicPackagePolicy;
