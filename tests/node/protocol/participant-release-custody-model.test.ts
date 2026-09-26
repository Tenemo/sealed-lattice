import { describe, expect, it } from 'vitest';

import { compileParticipantReleaseCustody } from '#tests/participant-release-custody-model.js';
import { completionProfile } from '#tests/supported-profile-model.js';

describe('finite original-key release randomness', () => {
    it('covers the actual noise, tree-salt and buffered field-mask schedule', () => {
        const budget = compileParticipantReleaseCustody(completionProfile());
        // Independent expansion of the current Rust release parameters and
        // FirstOracle, SecondOracle and Tree allocation schedules: 144-bit
        // release noise, and one mask more than the 61 release columns and
        // the 68 lookups.
        const readBytes = 65_536n;
        const roundedFields = (count: bigint) =>
            ((count * 16n + readBytes - 1n) / readBytes) * readBytes;
        const minimumProof =
            (4n * 262_144n - 4n) * 128n +
            20n * 128n +
            62n * roundedFields(1409n) +
            roundedFields(3n * 131_072n) +
            69n * roundedFields(3n * 1409n) +
            roundedFields(3n * 66_945n);
        expect(budget.noiseBytes).toBe(65_536n * 18n);
        expect(budget.roundedNoiseBytes).toBe(budget.noiseBytes);
        expect(budget.extraProofReads).toBe(3n);
        expect(budget.maximumProofRandomBytes).toBe(
            minimumProof + 3n * readBytes,
        );
        expect(budget.totalRandomBytes).toBe(
            65_536n * 18n + minimumProof + 3n * readBytes,
        );
    });

    it('bounds every participant and rejects one fewer reserve block at the chosen allocation', () => {
        const budget = compileParticipantReleaseCustody(completionProfile());
        // Rejection words for p = (2^64 - 133) * 2^64 + 1.
        const rejectedWords = 133n * (1n << 64n) - 1n;
        const upper = (extraReads: bigint) => {
            const minimumProof = 156_895_232n;
            const candidates = (minimumProof + extraReads * 65_536n) / 16n;
            const failures = extraReads + 1n;
            let falling = 1n;
            let factorial = 1n;
            for (let index = 0n; index < failures; index++) {
                falling *= candidates - index;
                factorial *= index + 1n;
            }
            return {
                numerator:
                    (10n * falling * rejectedWords ** failures) / factorial,
                denominatorBits: 128n * failures,
            };
        };
        expect(budget.exhaustionBound).toEqual(upper(3n));
        expect(budget.exhaustionBound.numerator << 128n).toBeLessThanOrEqual(
            1n << budget.exhaustionBound.denominatorBits,
        );
        const insufficient = upper(2n);
        expect(insufficient.numerator << 128n).toBeGreaterThan(
            1n << insufficient.denominatorBits,
        );
    });
});
