import { describe, expect, it } from 'vitest';

import type * as publicTypes from '#packages/sdk/src/index.js';

type BlockedTargetAcceptanceTypes = [
    // @ts-expect-error target-acceptance shell types are intentionally not public.
    publicTypes.LocalReplayRecord,
    // @ts-expect-error target-acceptance shell types are intentionally not public.
    publicTypes.TargetAcceptedRecord,
    // @ts-expect-error target-acceptance shell types are intentionally not public.
    publicTypes.TopKDecryptionShareShell,
];

type BlockedPlaintextOracleTypes = [
    // @ts-expect-error field arithmetic types are intentionally not public.
    publicTypes.FieldElement,
    // @ts-expect-error Shamir helper types are intentionally not public.
    publicTypes.ShamirPolynomial,
    // @ts-expect-error plaintext oracle types are intentionally not public.
    publicTypes.PlaintextTopKOracle,
    // @ts-expect-error sparse target oracle types are intentionally not public.
    publicTypes.SparseTopKTarget,
];

type BlockedPvssBallotTypes = [
    // @ts-expect-error ballot package shells are intentionally not public.
    publicTypes.BallotPackageShell,
    // @ts-expect-error ballot privacy proof profiles are intentionally not public.
    publicTypes.BallotProofProfile,
    // @ts-expect-error internal ballot-set types are intentionally not public.
    publicTypes.CanonicalBallotSet,
    // @ts-expect-error receiver encryption profiles are intentionally not public.
    publicTypes.ReceiverEncryptionProfile,
    // @ts-expect-error share commitment bound certificates are intentionally not public.
    publicTypes.ShareCommitmentMessageBoundCert,
    // @ts-expect-error share commitment profiles are intentionally not public.
    publicTypes.ShareCommitmentProfile,
    // @ts-expect-error test commitments are intentionally not public.
    publicTypes.TestShareCommitment,
    // @ts-expect-error aggregate share witnesses are intentionally not public.
    publicTypes.TestAggregateShare,
];

type BlockedEncryptedAggregateBridgeTypes = [
    // @ts-expect-error encrypted aggregate bridge proof records remain internal until claim-bearing verification exists.
    publicTypes.BridgeProofRecord,
    // @ts-expect-error encrypted aggregate bridge aggregate contributions remain internal until claim-bearing verification exists.
    publicTypes.AggregateContribution,
    // @ts-expect-error encrypted aggregate bridge aggregate-ready handoff records remain internal until claim-bearing verification exists.
    publicTypes.AggregateReadyRecord,
    // @ts-expect-error encrypted aggregate bridge aggregate selection inputs remain internal until claim-bearing verification exists.
    publicTypes.AggregateContributionSelectionInput,
    // @ts-expect-error encrypted aggregate bridge aggregate selection outputs remain internal until claim-bearing verification exists.
    publicTypes.AggregateContributionSelection,
    // @ts-expect-error encrypted aggregate bridge aggregate-ready build inputs remain internal until claim-bearing verification exists.
    publicTypes.AggregateReadyRecordBuildInput,
];

type PublicFoundationTypes = [
    publicTypes.BallotProofRecord,
    publicTypes.BallotProofStatement,
    publicTypes.BoardConsistencyInput,
    publicTypes.BridgeProofVerification,
    publicTypes.BridgeProofVerificationInput,
    publicTypes.ClaimBearingBallotPackage,
    publicTypes.PollSpecInput,
    publicTypes.ReceiverKeyProof,
    publicTypes.ReceiverKeyProofRootEvidence,
    publicTypes.RosterManifestTranscriptInput,
    publicTypes.TargetFinalityVerificationInput,
];

type PublicTypeSurfaceProbe = {
    readonly blockedPlaintextOracleTypes: BlockedPlaintextOracleTypes;
    readonly blockedPvssBallotTypes: BlockedPvssBallotTypes;
    readonly blockedEncryptedAggregateBridgeTypes: BlockedEncryptedAggregateBridgeTypes;
    readonly blockedTargetAcceptanceTypes: BlockedTargetAcceptanceTypes;
    readonly publicFoundationTypes: PublicFoundationTypes;
};

type PublicFoundationTypeNames = readonly string[] & {
    readonly length: PublicTypeSurfaceProbe['publicFoundationTypes']['length'];
};

const publicFoundationTypeNames = [
    'BallotProofRecord',
    'BallotProofStatement',
    'BoardConsistencyInput',
    'BridgeProofVerification',
    'BridgeProofVerificationInput',
    'ClaimBearingBallotPackage',
    'PollSpecInput',
    'ReceiverKeyProof',
    'ReceiverKeyProofRootEvidence',
    'RosterManifestTranscriptInput',
    'TargetFinalityVerificationInput',
] as const satisfies PublicFoundationTypeNames;

describe('election foundation public type surface', () => {
    it('keeps safe election foundation types available', () => {
        expect(publicFoundationTypeNames).toHaveLength(11);
    });
});
