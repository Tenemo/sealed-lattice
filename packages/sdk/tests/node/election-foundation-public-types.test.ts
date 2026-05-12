import { describe, expect, it } from 'vitest';

import type * as publicTypes from '../../src/index.js';

type BlockedTargetPhaseTypes = [
    // @ts-expect-error target-phase shell types are intentionally not public.
    publicTypes.EvaluationReplayAttestation,
    // @ts-expect-error target-phase shell types are intentionally not public.
    publicTypes.TargetAcceptedRecord,
    // @ts-expect-error target-phase shell types are intentionally not public.
    publicTypes.TopKDecryptionShareShell,
];

type PublicFoundationTypes = [
    publicTypes.BoardConsistencyInput,
    publicTypes.PollSpecInput,
    publicTypes.RosterManifestTranscriptInput,
    publicTypes.TargetFinalityVerificationInput,
];

type PublicTypeSurfaceProbe = {
    readonly blockedTargetPhaseTypes: BlockedTargetPhaseTypes;
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
    });
});
