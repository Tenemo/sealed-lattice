import { compileCommitmentEquivocationBound } from '#tests/commitment-equivocation-model.js';
import { contributionBodyHeaderBytes } from '#tests/contribution-body-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';
import { compileThresholdCompletionProfile } from '#tests/threshold-completion-model.js';

export const compileContributionAuthenticationCensus = (
    participants: number,
) => {
    if (
        !Number.isSafeInteger(participants) ||
        participants < 3 ||
        participants > 20
    )
        throw new RangeError('Unsupported participant count.');
    // Every participant confirms the roster; only the setup contributors'
    // confirmations carry a commitment, which they open.
    const contributors = BigInt(
        compileThresholdCompletionProfile(participants).setupContributorCount,
    );
    const signatureBytes = compileRegistrationEnrollmentCensus().signatureBytes;
    const saltBytes =
        compileCommitmentEquivocationBound(participants).saltBitLength / 8n;
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
        contributors * 64n;
    return {
        participants,
        contributors,
        confirmationBodyBytes,
        openingBodyBytes,
        inventoryBodyBytes,
        signatureBytes,
        bodyControlBytes: 2n + saltBytes + contributionBodyHeaderBytes,
        signingControlBytes: 64n + 32n,
        confirmationPacketBytes: 4n + confirmationBodyBytes + signatureBytes,
        openingPacketBytes: 4n + openingBodyBytes + signatureBytes,
        maximumPolynomialCommandBytes: 4n + (1n << 20n),
        allConfirmationPayloadBytes:
            BigInt(participants) * (confirmationBodyBytes + signatureBytes),
        allOpeningHeaderPayloadBytes:
            contributors * (openingBodyBytes + signatureBytes),
    };
};
