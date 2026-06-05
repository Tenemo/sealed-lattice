/**
 * Documented public package facade for the current release boundary.
 *
 * The generated documentation intentionally covers the current direct-path
 * development boundary. Complete direct encrypted ballot voting entry points
 * remain unpublished until their proof, replay, finality, decryption, and
 * mobile evidence gates close.
 *
 * @packageDocumentation
 */
export {
    deriveThresholdProfile,
    validatePollSpec,
    verifyBoardConsistency,
    verifyTargetFinality,
    verifyTranscriptCoreFixture,
} from '#packages/sdk/src/index.js';
