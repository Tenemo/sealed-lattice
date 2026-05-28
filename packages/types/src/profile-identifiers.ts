/** Target-bound share-selection profile required before decryption shares are accepted. */
export const targetBoundShareSelectionProfileId =
    'target-bound-first-valid-share-selection-v1';

/** CPAD profile required by the target-bound decryption path. */
export const cpadProfileId = 'CPAD-BGV-AsyncThreshold-v1';

/** Encrypted aggregate bridge profile required by accepted manifests. */
export const encryptedAggregateBridgeProfileId = 'EncryptedAggregateBridge-v1';

/** Passive BGV setup profile required by accepted manifests. */
export const bgvPassiveSetupProfileId =
    'sealed-lattice-bgv-rns-passive-full-roster-setup-v1';

/** Bridge witness privacy profile required by accepted manifests. */
export const bridgeWitnessPrivacyProfileId = 'BridgeWitnessPrivacy-v1';

/** Evaluation proof profile required by accepted manifests. */
export const evaluationProofProfileId = 'PQEvalProof-STARK-BGVReplay-v1';

/** Fully verified result profile emitted by transcript-core fixtures. */
export const fullyVerifiedResultProfileId =
    'transcript-core-fully-verified-result-profile-v1';

/** Development integration MHE profile emitted by transcript-core fixtures. */
export const developmentIntegrationProfileId =
    'transcript-core-development-integration-profile-v1';

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

/** Receiver encryption profile used by scoped relation-bearing ballot privacy proofs. */
export const receiverEncryptionProfileId =
    'linear-module-lwe-receiver-encryption-v1';

/** Share commitment profile used by ballot and aggregate privacy proofs. */
export const shareCommitmentProfileId =
    'module-sis-additive-share-commitment-v1';

/** Ballot privacy proof profile used for the local lattice relation. */
export const ballotProofProfileId = 'linear-lattice-ballot-privacy-proof-v1';

/** Aggregate derivation proof profile used for post-close contribution proofs. */
export const aggregateDerivationProofProfileId =
    'aggregate-derivation-linear-proof-v1';

/** Aggregate derivation sparse proof parameter profile. */
export const aggregateDerivationProofParameterProfileId =
    'aggregate-derivation-linear-compatibility-v1';

/** Aggregate derivation sparse proof encoding profile. */
export const aggregateDerivationProofEncodingProfileId =
    'aggregate-derivation-linear-proof-encoding-v1';

/** Score membership profile for score values in the supported score domain. */
export const scoreMembershipProfileId = 'one-hot-score-membership-v1';

/** Ballot score encoding profile for scalar plus score-bucket coordinates. */
export const ballotScoreEncodingProfileId = 'ScoreOneHotShares-v1';

/** Ballot share layout profile for receiver share-vector coordinates. */
export const ballotShareLayoutProfileId = 'ScalarScoreAndOneHotScoreShares-v1';

/** Aggregate input encoding profile for later committed bridge inputs. */
export const aggregateInputEncodingProfileId = 'AggregatedScoreHistogram-v1';

/** Encoded receiver share-vector layout profile. */
export const encodedShareVectorLayoutProfileId =
    'encoded-share-vector-layout-scalar-score-and-one-hot-v1';

/** Encoded aggregate layout profile. */
export const encodedAggregateLayoutProfileId =
    'encoded-aggregate-layout-score-histogram-v1';

/** Field encoding profile for canonical GF(65537) representatives. */
export const fieldEncodingProfileId =
    'gf65537-canonical-representative-quotient-v1';

/** Share commitment message-bound certificate profile. */
export const shareCommitmentMessageBoundProfileId =
    'share-commitment-message-bound-v1';
