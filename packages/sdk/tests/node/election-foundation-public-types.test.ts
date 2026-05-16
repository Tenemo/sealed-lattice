import { describe, expect, it } from 'vitest';

import publicSurface from '../../public-surface.json' with { type: 'json' };
import type * as publicTypes from '../../src/index.js';

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

type PublicFoundationTypes = [
    publicTypes.BoardConsistencyInput,
    publicTypes.PollSpecInput,
    publicTypes.RosterManifestTranscriptInput,
    publicTypes.TargetFinalityVerificationInput,
];

type PublicTypeSurfaceProbe = {
    readonly blockedPlaintextOracleTypes: BlockedPlaintextOracleTypes;
    readonly blockedPvssBallotTypes: BlockedPvssBallotTypes;
    readonly blockedTargetAcceptanceTypes: BlockedTargetAcceptanceTypes;
    readonly publicFoundationTypes: PublicFoundationTypes;
};

type PublicFoundationTypeNames = readonly string[] & {
    readonly length: PublicTypeSurfaceProbe['publicFoundationTypes']['length'];
};

const publicFoundationTypeNames = [
    'BoardConsistencyInput',
    'PollSpecInput',
    'RosterManifestTranscriptInput',
    'TargetFinalityVerificationInput',
] as const satisfies PublicFoundationTypeNames;

describe('election foundation public type surface', () => {
    it('keeps safe election foundation types available', () => {
        expect(publicFoundationTypeNames).toHaveLength(4);
        for (const publicTypeName of publicFoundationTypeNames) {
            expect(publicSurface.publicTypeExports).toContain(publicTypeName);
        }
    });

    it('keeps runtime and type export manifests disjoint and deterministic', () => {
        const runtimeExports = new Set(publicSurface.runtimeExports);
        const typeExports = new Set(publicSurface.publicTypeExports);
        const overlap = [...runtimeExports].filter((exportName) =>
            typeExports.has(exportName),
        );

        expect(overlap).toEqual([]);
        expect(publicSurface.runtimeExports).toEqual(
            [...publicSurface.runtimeExports].sort(),
        );
        expect(publicSurface.publicTypeExports).toEqual(
            [...publicSurface.publicTypeExports].sort(),
        );
    });
});
