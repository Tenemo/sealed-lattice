import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';

export const compileContributionAuthenticationCensus = (
    participants: number,
) => {
    if (
        !Number.isSafeInteger(participants) ||
        participants < 3 ||
        participants > 20
    )
        throw new RangeError('Unsupported participant count.');
    const signatureBytes = compileRegistrationEnrollmentCensus().signatureBytes;
    const text = (value: string) => BigInt(Buffer.byteLength(value));
    const confirmationBodyBytes =
        8n +
        4n * 6n +
        4n +
        text('sealed-lattice/roster-confirmation/v1') +
        64n +
        2n +
        64n;
    const openingBodyBytes =
        8n +
        4n * 6n +
        4n +
        text('sealed-lattice/setup-opening/v1') +
        64n +
        2n +
        64n;
    const inventoryBodyBytes =
        8n +
        3n * 6n +
        4n +
        text('sealed-lattice/commitment-inventory/v1') +
        64n +
        4n +
        4n +
        BigInt(participants) * 64n;
    return {
        participants,
        confirmationBodyBytes,
        openingBodyBytes,
        inventoryBodyBytes,
        signatureBytes,
        allConfirmationPayloadBytes:
            BigInt(participants) * (confirmationBodyBytes + signatureBytes),
        allOpeningHeaderPayloadBytes:
            BigInt(participants) * (openingBodyBytes + signatureBytes),
    };
};
