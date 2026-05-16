/** Target-bound share-selection profile required before decryption shares are accepted. */
export const targetBoundShareSelectionProfileId =
    'target-bound-first-valid-share-selection-v1';

/** CPAD profile required by the target-bound decryption path. */
export const cpadProfileId = 'CPAD-BGV-AsyncThreshold-v1';

/** Bridge proof profile required by accepted manifests. */
export const bridgeProofProfileId =
    'CommittedAggregateShare-TargetBasisData-HwangPiEnc-BGV-v1';

/** Direct target-basis data bridge profile required by accepted manifests. */
export const directTargetBasisDataBridgeProfileId =
    'CommittedAggregateShare-TargetBasisData-BGV-v1';

/** Evaluation proof profile required by accepted manifests. */
export const evaluationProofProfileId = 'PQEvalProof-STARK-BGVReplay-v1';

/** Fully verified result profile emitted by transcript-core fixtures. */
export const fullyVerifiedResultProfileId =
    'transcript-core-fully-verified-result-profile-v1';

/** Passive MHE prototype profile emitted by transcript-core fixtures. */
export const passiveMhePrototypeProfileId =
    'transcript-core-passive-mhe-prototype-profile-v1';

/** Active malicious MHE profile emitted by transcript-core fixtures. */
export const activeMaliciousMheProfileId =
    'transcript-core-active-malicious-mhe-profile-v1';

/** HE setup proof placeholder profile emitted by transcript-core fixtures. */
export const noHeSetupProofProfileId = 'transcript-core-no-he-setup-proof-v1';

/** Decryption proof placeholder profile emitted by transcript-core fixtures. */
export const noDecryptionProofProfileId =
    'transcript-core-no-decryption-proof-v1';

/** Threshold decryption profile required by accepted manifests. */
export const thresholdDecryptionProfileId =
    'BGV-RNS-AsyncThresholdDecryption-CPAD-v1';

/** Evaluation noise profile required by accepted manifests. */
export const evaluationNoiseProfileId = 'he-evaluation-noise-profile-v1';

/** Mobile profile required by accepted manifests. */
export const mobileProfileId = 'mobile-flagship-profile-v1';
