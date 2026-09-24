import { describe, expect, it } from 'vitest';

import {
    compileAuthenticationFrameWork,
    compileCompleteAuthenticationFrameWork,
    compileCompleteCredentialIntentBounds,
    compileCurrentCredentialIntentBounds,
    compileCurrentSignatureHashInputs,
    pureSignatureFrame,
} from '#tests/authentication-work-model.js';

describe('complete participant authentication accounting', () => {
    it('keeps all actual signature purposes in the current hash-input inventory', () => {
        expect(
            compileCurrentSignatureHashInputs()
                .rows.slice(8)
                .map((row) => row.purpose),
        ).toEqual([
            'poll-definition',
            'registration',
            'roster-proposal',
            'roster-confirmation',
            'setup-opening',
            'ballot-envelope',
            'close-intent',
            'close-response',
            'close-proposal',
            'target-certification',
            'release-envelope',
        ]);
    });

    it('frames the complete release envelope and the other late purpose identities', () => {
        const roles = compileCompleteAuthenticationFrameWork();
        expect(roles.map((role) => role.messageBytes)).toEqual([
            64n,
            64n,
            64n,
            64n,
            64n,
            214n,
            64n,
            64n,
            64n,
            64n,
            270n,
        ]);
        for (const role of roles.slice(6)) {
            const context = Buffer.from(role.context);
            const message = Buffer.alloc(
                role.purpose === 'release-envelope' ? 270 : 64,
                7,
            );
            const expected = Buffer.concat([
                Buffer.from([0, context.length]),
                context,
                message,
            ]);
            expect(pureSignatureFrame(context, message)).toEqual(expected);
            expect(role.frameBytes).toBe(BigInt(expected.length));
            expect(role.representativeInputBytes).toBe(
                BigInt(64 + expected.length),
            );
            let permutations = 1n;
            for (
                let remaining = 64 + expected.length;
                remaining >= 136;
                remaining -= 136
            )
                permutations++;
            expect(role.representativePermutations).toBe(permutations);
        }
    });

    it('counts an optional ballot and one close response under the retained-state locks', () => {
        const rows = compileCompleteCredentialIntentBounds();
        // Organizer: five setup purposes, three close purposes, then target
        // and release as the branch allows. Others: three setup purposes and
        // one close response. Each row adds the optional ballot.
        expect(rows.map((row) => row.firstEvaluatedIntentBound)).toEqual([
            11n,
            7n,
            10n,
            6n,
            10n,
            6n,
        ]);
        for (const row of rows) {
            expect(row.participantCount).toBe(10);
            expect(row.optionalPurposes).toEqual(['ballot-envelope']);
            expect(row.fixedPurposes).not.toContain('ballot-envelope');
            expect(
                row.fixedPurposes.filter(
                    (purpose) => purpose === 'close-response',
                ),
            ).toHaveLength(1);
            for (const purpose of ['close-intent', 'close-proposal'] as const)
                expect(row.fixedPurposes.includes(purpose)).toBe(
                    row.role === 'organizer',
                );
            expect(new Set(row.fixedPurposes).size).toBe(
                row.fixedPurposes.length,
            );
        }
    });

    it('omits release for no result and permits release without an own target vote', () => {
        const rows = compileCompleteCredentialIntentBounds();
        for (const row of rows.filter(
            (candidate) => candidate.branch === 'No result',
        )) {
            expect(row.fixedPurposes).not.toContain('release-envelope');
            expect(row.fixedPurposes).toContain('target-certification');
        }
        for (const row of rows.filter(
            (candidate) =>
                candidate.branch ===
                'Encrypted release without own target vote',
        )) {
            expect(row.fixedPurposes).not.toContain('target-certification');
            expect(row.fixedPurposes).toContain('release-envelope');
        }
    });

    it('preserves the separate through-ballot census used by retained prefix evidence', () => {
        expect(compileAuthenticationFrameWork()).toHaveLength(6);
        expect(
            compileCurrentCredentialIntentBounds().map(
                (row) => row.firstEvaluatedIntentBound,
            ),
        ).toEqual([6n, 4n]);
    });
});
