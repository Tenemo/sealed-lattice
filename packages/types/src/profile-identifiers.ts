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

/** Receiver encryption profile used by claim-bearing ballot privacy proofs. */
export const receiverEncryptionProfileId =
    'linear-module-lwe-receiver-encryption-v1';

/** Share commitment profile used by ballot and aggregate privacy proofs. */
export const shareCommitmentProfileId =
    'module-sis-additive-share-commitment-v1';

/** Ballot privacy proof profile used for the local lattice relation. */
export const ballotProofProfileId = 'lazer-linear-ballot-privacy-proof-v1';

/** Score membership profile for score values in the supported score domain. */
export const scoreMembershipProfileId = 'one-hot-score-membership-v1';

/** Field encoding profile for canonical GF(65537) representatives. */
export const fieldEncodingProfileId =
    'gf65537-canonical-representative-quotient-v1';

/** Share commitment message-bound certificate profile. */
export const shareCommitmentMessageBoundProfileId =
    'share-commitment-message-bound-v1';
