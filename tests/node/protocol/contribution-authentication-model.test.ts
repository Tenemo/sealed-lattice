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

    it('charges one additional commitment and signed carrier for each added participant', () => {
        for (let participants = 3; participants < 20; participants++) {
            const before =
                compileContributionAuthenticationCensus(participants);
            const after = compileContributionAuthenticationCensus(
                participants + 1,
            );
            expect(after.inventoryBodyBytes - before.inventoryBodyBytes).toBe(
                64n,
            );
            expect(
                after.allConfirmationPayloadBytes -
                    before.allConfirmationPayloadBytes,
            ).toBe(before.confirmationBodyBytes + 3309n);
            expect(
                after.allOpeningHeaderPayloadBytes -
                    before.allOpeningHeaderPayloadBytes,
            ).toBe(before.openingBodyBytes + 3309n);
        }
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
