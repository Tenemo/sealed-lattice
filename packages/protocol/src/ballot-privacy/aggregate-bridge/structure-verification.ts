export type { PendingBridgeProofRecordFromEvidenceInput } from './structure-verification/shared.js';
export { createPendingBridgeProofRecordFromBridgeEvidence } from './structure-verification/pending-bridge-proof-record.js';
export {
    createAggregateContributionFromBridgeProofRecord,
    verifyAggregateContributionStructure,
} from './structure-verification/aggregate-contribution.js';
export { selectFirstValidAggregateContributions } from './structure-verification/selection.js';
export {
    createAggregateReadyRecord,
    verifyAggregateReadyRecordStructure,
} from './structure-verification/ready-record.js';
