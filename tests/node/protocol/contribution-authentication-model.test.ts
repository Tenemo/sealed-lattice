import { describe, expect, it } from 'vitest';

import { compileContributionAuthenticationCensus } from '#tests/contribution-authentication-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';

describe('contribution confirmation and opening payloads', () => {
    it('keeps each signed carrier bounded across every supported roster size', () => {
        for (let participants = 3; participants <= 20; participants++) {
            const value = compileContributionAuthenticationCensus(participants);
            expect(value.confirmationBodyBytes).toBeLessThanOrEqual(1024n);
            expect(value.openingBodyBytes).toBeLessThanOrEqual(1024n);
            expect(value.inventoryBodyBytes).toBeLessThanOrEqual(2048n);
            expect(value.allConfirmationPayloadBytes).toBeLessThan(
                128n * 1024n,
            );
            expect(value.allOpeningHeaderPayloadBytes).toBeLessThan(
                128n * 1024n,
            );
        }
    });

    it('charges one confirmation per participant and one commitment and opening per setup contributor', () => {
        // Only the first max(f + 1, 2) roster positions contribute, with
        // f = floor((n - 1) / 3).
        const contributors = (participants: number) =>
            BigInt(Math.max(Math.floor((participants - 1) / 3) + 1, 2));
        let grown = 0;
        for (let participants = 3; participants < 20; participants++) {
            const before =
                compileContributionAuthenticationCensus(participants);
            const after = compileContributionAuthenticationCensus(
                participants + 1,
            );
            const added =
                contributors(participants + 1) - contributors(participants);
            if (added > 0n) grown++;
            expect(after.contributors).toBe(contributors(participants + 1));
            expect(after.inventoryBodyBytes - before.inventoryBodyBytes).toBe(
                64n * added,
            );
            // Every added participant signs one roster confirmation.
            expect(
                after.allConfirmationPayloadBytes -
                    before.allConfirmationPayloadBytes,
            ).toBe(before.confirmationBodyBytes + 3309n);
            expect(
                after.allOpeningHeaderPayloadBytes -
                    before.allOpeningHeaderPayloadBytes,
            ).toBe(added * (before.openingBodyBytes + 3309n));
        }
        // A contributor joins at 7, 10, 13, 16 and 19 participants.
        expect(grown).toBe(5);
    });

    it('fits every signing command inside the existing original-key restore input allocation', () => {
        const inputBytes =
            compileRegistrationEnrollmentCensus().maximumRestoreInputBytes;
        const value = compileContributionAuthenticationCensus(10);
        for (const length of [
            value.bodyControlBytes,
            value.signingControlBytes,
            value.confirmationPacketBytes,
            value.openingPacketBytes,
            value.maximumPolynomialCommandBytes,
        ])
            expect(length).toBeLessThan(inputBytes);
    });

    it('rejects unsupported and nonintegral roster counts before deriving sizes', () => {
        for (const participants of [0, 2, 21, 3.5, NaN, Infinity])
            expect(() =>
                compileContributionAuthenticationCensus(participants),
            ).toThrow(RangeError);
    });
});
