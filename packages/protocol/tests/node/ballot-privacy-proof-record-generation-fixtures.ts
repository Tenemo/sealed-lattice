// Public entry point for ballot proof record generation fixtures.
export {
    cloneJsonValue,
    casualMicroRosterRelationInput,
    mandatoryProfileRelationInput,
    variantRelationInput,
} from './ballot-privacy-proof-record-generation-fixtures/fixture-inputs.js';
export type { BallotProofRecordGenerationFixture } from './ballot-privacy-proof-record-generation-fixtures/fixture-inputs.js';
export {
    createBallotProofRecordGenerationFixture,
    createMandatoryProfileBallotProofRecordGenerationFixture,
    createMandatoryProfileBallotProofRecordBenchmarkFixture,
    createMicroRosterBallotProofRecordGenerationFixture,
    createVariantBallotProofRecordGenerationFixture,
    createWasmBallotProofRecordGenerationFixture,
} from './ballot-privacy-proof-record-generation-fixtures/fixture-assembly.js';
