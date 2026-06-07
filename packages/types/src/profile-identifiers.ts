/** Target-bound share-selection profile required before decryption shares are accepted. */
export const targetBoundShareSelectionProfileId =
    'target-bound-first-valid-share-selection-v1';

/** Target decryption profile required by accepted manifests. */
export const targetDecryptionProfileId = 'BGV-RNS-AsyncTargetDecryption-v1';

/** Passive BGV setup profile required by accepted manifests. */
export const bgvPassiveSetupProfileId =
    'sealed-lattice-bgv-rns-passive-full-roster-setup-v1';

/** Direct encrypted ballot layout profile required by accepted manifests. */
export const encryptedBallotLayoutProfileId =
    'direct-encrypted-ballot-layout-v1';

/** Direct ballot validity proof profile required by accepted manifests. */
export const ballotValidityProofProfileId =
    'direct-encrypted-ballot-validity-proof-v1';

/** Direct encrypted ballot aggregate profile required by accepted manifests. */
export const encryptedBallotAggregateProfileId =
    'direct-encrypted-ballot-aggregate-v1';

/** Mandatory evaluator replay profile required by accepted manifests. */
export const evaluatorReplayProfileId =
    'direct-encrypted-ballot-evaluator-replay-v1';

/** Direct encrypted comparison profile required by accepted manifests. */
export const directComparisonProfileId =
    'direct-encrypted-ballot-comparison-v1';

/** Foundation transcript profile emitted by transcript-core fixtures. */
export const foundationTranscriptProfileId =
    'transcript-core-foundation-transcript-profile-v1';

/** Foundation-only profile emitted by transcript-core fixtures. */
export const foundationOnlyProfileId =
    'transcript-core-foundation-only-profile-v1';

/** HE setup proof placeholder profile emitted by transcript-core fixtures. */
export const noHeSetupProofProfileId = 'transcript-core-no-he-setup-proof-v1';

/** Evaluator replay placeholder profile emitted by transcript-core fixtures. */
export const noEvaluatorReplayProfileId =
    'transcript-core-no-evaluator-replay-proof-v1';

/** Decryption proof placeholder profile emitted by transcript-core fixtures. */
export const noDecryptionProofProfileId =
    'transcript-core-no-decryption-proof-v1';

/** Mobile replay profile required by accepted manifests. */
export const mobileProfileId = 'mobile-flagship-profile-v1';

/** Ballot score encoding profile for direct encrypted score coordinates. */
export const ballotScoreEncodingProfileId = 'DirectEncryptedScoreSlots-v1';
