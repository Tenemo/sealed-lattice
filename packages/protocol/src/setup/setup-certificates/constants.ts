export const setupProfileId = 'CollectiveBgvSetup-v1';
export const setupCommitmentProfileId = 'SealedLattice-BDLOP-Commitment-v1';
export const setupProofProfileId = 'SealedLattice-SetupProof-v1';
export const setupProofBytesDomain =
    'sealed-lattice/collective-bgv-setup/succinct-proof-bytes-v1';
export const setupProofSerialization = 'binary';
export const setupProofByteDecoder =
    'sealed-lattice-succinct-setup-proof-byte-decoder-v1';
export const setupProofFamilies = ['vss-opening-carry'] as const;
export const succinctSameSecretLinkageAnchorAccountingHashNamespace =
    'SuccinctSameSecretLinkageAnchorAccountingHash';
export const succinctPrivateVssShareAccountingHashNamespace =
    'SuccinctPrivateVssShareAccountingHash';
export const succinctPublicKeyShareAccountingHashNamespace =
    'SuccinctPublicKeyShareAccountingHash';
export const succinctEvaluationKeyProofAccountingHashNamespace =
    'SuccinctEvaluationKeyProofAccountingHash';
export const setupTransportProfileId =
    'sealed-lattice-setup-binary-chunked-transport-v1';
export const setupTransportChunkSizeBytes = 1_048_576;
export const setupTransportStorageQuotaBytes = 2_147_483_648;
export const setupTransportLargestSingleBufferBytes = 1_572_864;
export const setupTransportCopyCountLimit = 2;
export const setupTransportStreamOrder = 'ascending-chunk-index';
export const setupTransportResumePolicy = 'chunk-index-checkpointed-by-hash';
export const setupTransportLazyLoadingPolicy =
    'root-addressed-large-object-loading';
export const setupTransportedObjectLoadingPolicy =
    'stream-verified-before-object-use';
export const targetDecryptionProfileId = 'BGV-RNS-AsyncTargetDecryption-v1';
export const protocolHashPattern = /^[0-9a-f]{128}$/u;
