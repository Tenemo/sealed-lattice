// Public entry point for ballot privacy relation lowering.
export type {
    BallotPrivacyRelationBackendPublicContext,
    BallotPrivacyBackendProofComponentId,
    BallotPrivacyBackendProofComponent,
    BallotPrivacyLoweredLinearRelationStatement,
    BallotPrivacyRelationBackendLoweringResult,
} from './relation-backend-lowering/backend-contracts.js';
export { ballotPrivacyBackendProofComponentOrder } from './relation-backend-lowering/backend-proof-components.js';
export { lowerBallotPrivacyRelationToBackendStatement } from './relation-backend-lowering/relation-lowering.js';
