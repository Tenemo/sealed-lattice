/**
 * Documented public package facade for the current release boundary.
 *
 * The generated documentation intentionally covers the current active-static
 * direct-path development boundary. Complete active-static direct encrypted
 * ballot voting entry points remain unpublished until their setup, VSS, proof,
 * bounded-domain replay, finality, and mobile evidence gates close. The exposed
 * target-result helper is verifier-only and remains scoped by the development
 * proof evidence documented in the package ledger.
 *
 * @packageDocumentation
 */
export {
    deriveThresholdProfile,
    validatePollSpec,
    verifyBoardConsistency,
    verifyTargetDecryptionResult,
    verifyTargetFinality,
    verifyTranscriptCoreFixture,
} from '#packages/sdk/src/index.js';

export type { TargetDecryptionResultVerification } from '#packages/sdk/src/index.js';
