/**
 * Documented public package facade for the current release boundary.
 *
 * The generated documentation covers the current development package boundary.
 * Complete direct encrypted ballot voting entry points remain unpublished until
 * setup, VSS, ballot proofs, bounded-domain replay, finality, target
 * decryption, and supported-phone evidence are implemented and verified.
 *
 * @packageDocumentation
 */
export {
    deriveThresholdParameters,
    validatePollSpec,
    verifyBoardConsistency,
    verifyTargetFinality,
    verifyTranscriptCoreFixture,
} from '#packages/sdk/src/index.js';
