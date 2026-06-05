import { describe, expect, it } from 'vitest';

import type * as publicTypes from '#packages/sdk/src/index.js';

type BlockedTargetOpeningTypes = [
    // @ts-expect-error evaluator replay records are intentionally not public.
    publicTypes.EvaluatorReplayRecord,
    // @ts-expect-error accepted target records are intentionally not public.
    publicTypes.LocalReplayRecord,
    // @ts-expect-error accepted target records are intentionally not public.
    publicTypes.TargetAcceptedRecord,
    // @ts-expect-error target decryption share shells are intentionally not public.
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

type BlockedDirectInternalTypes = [
    // @ts-expect-error BGV setup packages are intentionally not public.
    publicTypes.BgvPassiveSetupPackage,
    // @ts-expect-error direct ballot witness material is intentionally not public.
    publicTypes.DirectEncryptedBallotWitness,
    // @ts-expect-error direct aggregate evaluator inputs are intentionally not public.
    publicTypes.TopKEvaluatorDirectAggregateInput,
];

type PublicFoundationTypes = [
    publicTypes.AcceptedTargetFinalityCheckpoint,
    publicTypes.BoardConsistencyInput,
    publicTypes.CastReceipt,
    publicTypes.ElectionManifest,
    publicTypes.FoundationTranscriptInput,
    publicTypes.FoundationTranscriptVerification,
    publicTypes.PollSpecInput,
    publicTypes.RegistrationEntry,
    publicTypes.RosterManifestTranscriptInput,
    publicTypes.TargetBoundShareSelectionProfile,
    publicTypes.TargetFinalityCheckpoint,
    publicTypes.TargetFinalityRecord,
    publicTypes.TargetFinalityVerificationInput,
    publicTypes.TargetProposal,
    publicTypes.ThresholdProfile,
    publicTypes.TrusteeSetupEntry,
];

type PublicTypeSurfaceProbe = {
    readonly blockedPlaintextOracleTypes: BlockedPlaintextOracleTypes;
    readonly blockedDirectInternalTypes: BlockedDirectInternalTypes;
    readonly blockedTargetOpeningTypes: BlockedTargetOpeningTypes;
    readonly publicFoundationTypes: PublicFoundationTypes;
};

type PublicFoundationTypeNames = readonly string[] & {
    readonly length: PublicTypeSurfaceProbe['publicFoundationTypes']['length'];
};

const publicFoundationTypeNames = [
    'AcceptedTargetFinalityCheckpoint',
    'BoardConsistencyInput',
    'CastReceipt',
    'ElectionManifest',
    'FoundationTranscriptInput',
    'FoundationTranscriptVerification',
    'PollSpecInput',
    'RegistrationEntry',
    'RosterManifestTranscriptInput',
    'TargetBoundShareSelectionProfile',
    'TargetFinalityCheckpoint',
    'TargetFinalityRecord',
    'TargetFinalityVerificationInput',
    'TargetProposal',
    'ThresholdProfile',
    'TrusteeSetupEntry',
] as const satisfies PublicFoundationTypeNames;

describe('election foundation public type surface', () => {
    it('keeps safe election foundation types available', () => {
        expect(publicFoundationTypeNames).toHaveLength(16);
    });
});
