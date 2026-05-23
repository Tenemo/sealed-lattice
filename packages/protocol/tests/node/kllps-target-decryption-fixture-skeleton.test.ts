import { describe, expect, it } from 'vitest';

type KllpsProfileFixture = {
    readonly cDec: number;
    readonly cSim: number;
    readonly qDec: number;
    readonly qTarget: number;
    readonly sDec: readonly string[];
    readonly targetContextDigest: string;
};

type KllpsShareFixture = {
    readonly trusteeIdentity: string;
    readonly boardSequence: number;
    readonly cDec: number;
    readonly cSim: number;
    readonly qTarget: number;
    readonly sDec: readonly string[];
    readonly targetContextDigest: string;
    readonly certifiedBound: number;
    readonly shareValue: number;
    readonly equationValid: boolean;
    readonly proofValid: boolean;
    readonly smudgeSamplingClaim: 'assumed' | 'notProven';
    readonly targetKind: 'acceptedTarget' | 'topKOutputBundle' | 'intermediate';
};

type KllpsShareFixtureResult =
    | {
          readonly ok: true;
          readonly entropyAssumption: 'honestSmudgeSamplingAssumed';
      }
    | {
          readonly ok: false;
          readonly reason:
              | 'wrongCDec'
              | 'wrongCSim'
              | 'wrongSDec'
              | 'wrongQTarget'
              | 'wrongTargetContext'
              | 'wrongBound'
              | 'shareEquationInvalid'
              | 'proofRelationInvalid'
              | 'notAcceptedTarget';
      };

const profile = {
    cDec: 3,
    cSim: 5,
    qDec: 3,
    qTarget: 65_537,
    sDec: ['trustee-1', 'trustee-2', 'trustee-3'],
    targetContextDigest: 'target-context',
} as const satisfies KllpsProfileFixture;

const validShare = (
    overrides: Partial<KllpsShareFixture> = {},
): KllpsShareFixture => ({
    trusteeIdentity: 'trustee-1',
    boardSequence: 1,
    cDec: profile.cDec,
    cSim: profile.cSim,
    qTarget: profile.qTarget,
    sDec: profile.sDec,
    targetContextDigest: profile.targetContextDigest,
    certifiedBound: 100,
    shareValue: 37,
    equationValid: true,
    proofValid: true,
    smudgeSamplingClaim: 'assumed',
    targetKind: 'acceptedTarget',
    ...overrides,
});

const verifyKllpsShareFixture = (
    share: KllpsShareFixture,
    expectedProfile: KllpsProfileFixture,
): KllpsShareFixtureResult => {
    if (share.targetKind !== 'acceptedTarget') {
        return { ok: false, reason: 'notAcceptedTarget' };
    }
    if (share.cDec !== expectedProfile.cDec) {
        return { ok: false, reason: 'wrongCDec' };
    }
    if (share.cSim !== expectedProfile.cSim) {
        return { ok: false, reason: 'wrongCSim' };
    }
    if (share.sDec.join('\0') !== expectedProfile.sDec.join('\0')) {
        return { ok: false, reason: 'wrongSDec' };
    }
    if (share.qTarget !== expectedProfile.qTarget) {
        return { ok: false, reason: 'wrongQTarget' };
    }
    if (share.targetContextDigest !== expectedProfile.targetContextDigest) {
        return { ok: false, reason: 'wrongTargetContext' };
    }
    if (Math.abs(share.shareValue) > share.certifiedBound) {
        return { ok: false, reason: 'wrongBound' };
    }
    if (!share.equationValid) {
        return { ok: false, reason: 'shareEquationInvalid' };
    }
    if (!share.proofValid) {
        return { ok: false, reason: 'proofRelationInvalid' };
    }

    return { ok: true, entropyAssumption: 'honestSmudgeSamplingAssumed' };
};

const selectCanonicalSDec = (
    shares: readonly KllpsShareFixture[],
    expectedProfile: KllpsProfileFixture,
):
    | {
          readonly status: 'ready';
          readonly sDec: readonly string[];
      }
    | {
          readonly status: 'pending';
          readonly reason: 'missingDecryptionShares';
      }
    | {
          readonly status: 'conflict';
          readonly reason: 'duplicateNonIdenticalShare';
      } => {
    const byTrustee = new Map<string, KllpsShareFixture>();

    for (const share of shares) {
        const previous = byTrustee.get(share.trusteeIdentity);
        if (
            previous !== undefined &&
            JSON.stringify(previous) !== JSON.stringify(share)
        ) {
            return { status: 'conflict', reason: 'duplicateNonIdenticalShare' };
        }
        byTrustee.set(share.trusteeIdentity, share);
    }

    const verifiedShares = [...byTrustee.values()]
        .filter((share) => verifyKllpsShareFixture(share, expectedProfile).ok)
        .sort(
            (left, right) =>
                left.boardSequence - right.boardSequence ||
                left.trusteeIdentity.localeCompare(right.trusteeIdentity),
        );

    if (verifiedShares.length < expectedProfile.qDec) {
        return { status: 'pending', reason: 'missingDecryptionShares' };
    }

    return {
        status: 'ready',
        sDec: verifiedShares
            .slice(0, expectedProfile.qDec)
            .map((share) => share.trusteeIdentity),
    };
};

describe('KLLPS target decryption fixture skeletons', () => {
    it('accepts a share only when the KLLPS C1-C4 bindings match', () => {
        expect(verifyKllpsShareFixture(validShare(), profile)).toEqual({
            ok: true,
            entropyAssumption: 'honestSmudgeSamplingAssumed',
        });

        expect(
            verifyKllpsShareFixture(validShare({ cDec: 4 }), profile),
        ).toEqual({ ok: false, reason: 'wrongCDec' });
        expect(
            verifyKllpsShareFixture(validShare({ cSim: 7 }), profile),
        ).toEqual({ ok: false, reason: 'wrongCSim' });
        expect(
            verifyKllpsShareFixture(
                validShare({ sDec: ['trustee-1', 'trustee-3'] }),
                profile,
            ),
        ).toEqual({ ok: false, reason: 'wrongSDec' });
        expect(
            verifyKllpsShareFixture(validShare({ qTarget: 17 }), profile),
        ).toEqual({ ok: false, reason: 'wrongQTarget' });
        expect(
            verifyKllpsShareFixture(
                validShare({ targetContextDigest: 'wrong-target' }),
                profile,
            ),
        ).toEqual({ ok: false, reason: 'wrongTargetContext' });
        expect(
            verifyKllpsShareFixture(
                validShare({ certifiedBound: 10, shareValue: 11 }),
                profile,
            ),
        ).toEqual({ ok: false, reason: 'wrongBound' });
        expect(
            verifyKllpsShareFixture(
                validShare({ equationValid: false }),
                profile,
            ),
        ).toEqual({ ok: false, reason: 'shareEquationInvalid' });
        expect(
            verifyKllpsShareFixture(validShare({ proofValid: false }), profile),
        ).toEqual({ ok: false, reason: 'proofRelationInvalid' });
    });

    it('keeps share selection pending until q_dec first valid shares arrive', () => {
        expect(
            selectCanonicalSDec(
                [
                    validShare({
                        trusteeIdentity: 'trustee-2',
                        boardSequence: 2,
                    }),
                    validShare({
                        trusteeIdentity: 'trustee-1',
                        boardSequence: 1,
                    }),
                ],
                profile,
            ),
        ).toEqual({ status: 'pending', reason: 'missingDecryptionShares' });
        expect(
            selectCanonicalSDec(
                [
                    validShare({
                        trusteeIdentity: 'trustee-2',
                        boardSequence: 2,
                    }),
                    validShare({
                        trusteeIdentity: 'trustee-1',
                        boardSequence: 1,
                    }),
                    validShare({
                        trusteeIdentity: 'trustee-3',
                        boardSequence: 3,
                    }),
                    validShare({
                        trusteeIdentity: 'trustee-4',
                        boardSequence: 0,
                    }),
                ],
                profile,
            ),
        ).toEqual({
            status: 'ready',
            sDec: ['trustee-4', 'trustee-1', 'trustee-2'],
        });
    });

    it('reports duplicate non-identical shares as conflict evidence', () => {
        expect(
            selectCanonicalSDec(
                [
                    validShare({
                        trusteeIdentity: 'trustee-1',
                        shareValue: 37,
                    }),
                    validShare({
                        trusteeIdentity: 'trustee-1',
                        shareValue: 38,
                    }),
                ],
                profile,
            ),
        ).toEqual({
            status: 'conflict',
            reason: 'duplicateNonIdenticalShare',
        });
    });

    it('refuses C_topK and intermediate ciphertexts as decryption targets', () => {
        for (const targetKind of [
            'topKOutputBundle',
            'intermediate',
        ] as const) {
            expect(
                verifyKllpsShareFixture(validShare({ targetKind }), profile),
            ).toEqual({ ok: false, reason: 'notAcceptedTarget' });
        }
    });

    it('keeps smudge entropy as a theorem assumption, not a proof output', () => {
        const proofValidBoundedShare = validShare({
            proofValid: true,
            smudgeSamplingClaim: 'notProven',
        });

        expect(
            verifyKllpsShareFixture(proofValidBoundedShare, profile),
        ).toEqual({
            ok: true,
            entropyAssumption: 'honestSmudgeSamplingAssumed',
        });
    });
});
