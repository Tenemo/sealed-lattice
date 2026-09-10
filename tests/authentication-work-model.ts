import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import { byteAlignedSpongePermutations } from '#tests/proof-hash-work-model.js';
import { compileRegistrationEnrollmentCensus } from '#tests/registration-enrollment-model.js';

const envelopeBytes = compileBallotBodyCensus().envelopeBytes;
const signatureBytes = compileRegistrationEnrollmentCensus().signatureBytes;

export const authenticationPurposes = [
    'poll-definition',
    'registration',
    'roster-proposal',
    'roster-confirmation',
    'setup-opening',
    'ballot-envelope',
] as const;
export type AuthenticationPurpose = (typeof authenticationPurposes)[number];

export const authenticationContext = (purpose: AuthenticationPurpose) =>
    `sealed-lattice/${purpose}/v1`;

// FIPS 204 Algorithms 2 and 3 use the pure interface, even when the
// application's message is already a foundation digest. This is not HashML-DSA.
export const pureSignatureFrame = (
    context: Uint8Array,
    message: Uint8Array,
) => {
    if (context.length > 255)
        throw new RangeError('Signature context too long.');
    return Buffer.concat([Buffer.from([0, context.length]), context, message]);
};

export const compileAuthenticationFrameWork = () =>
    authenticationPurposes.map((purpose) => {
        const context = authenticationContext(purpose);
        const messageBytes =
            purpose === 'ballot-envelope' ? envelopeBytes : 64n;
        const frameBytes =
            2n + BigInt(Buffer.byteLength(context)) + messageBytes;
        // Sign_internal and Verify_internal hash tr || M'. Other ML-DSA
        // hashes, key expansion and rejection-loop work are separate operands.
        const representativeInputBytes = 64n + frameBytes;
        return {
            purpose,
            context,
            messageBytes,
            frameBytes,
            representativeInputBytes,
            representativePermutations: byteAlignedSpongePermutations(
                representativeInputBytes,
                64n,
                136n,
            ),
        };
    });

// One completed, all-cooperating prefix through ballot signing. Enrollment
// records outside the eventual roster are explicit. This is neither a lifetime
// signing-oracle bound nor a count of repeated verification or recovery work.
export const compileCompletedAuthenticationCensus = (
    participantCount: number,
    registrationCount: bigint,
    ballotCount: number,
) => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount < 3 ||
        participantCount > 20 ||
        registrationCount < BigInt(participantCount) ||
        !Number.isSafeInteger(ballotCount) ||
        ballotCount < 0 ||
        ballotCount > participantCount
    )
        throw new RangeError('Invalid completed authentication population.');
    const participants = BigInt(participantCount);
    const counts: Record<AuthenticationPurpose, bigint> = {
        'poll-definition': 1n,
        registration: registrationCount,
        'roster-proposal': 1n,
        'roster-confirmation': participants,
        'setup-opening': participants,
        'ballot-envelope': BigInt(ballotCount),
    };
    const roles = compileAuthenticationFrameWork().map((role) => ({
        ...role,
        messages: counts[role.purpose],
    }));
    const sum = (value: (role: (typeof roles)[number]) => bigint) =>
        roles.reduce((total, role) => total + role.messages * value(role), 0n);
    const signatures = sum(() => 1n);
    return {
        participantCount,
        registrationCount,
        ballotCount,
        roles,
        signatures,
        signatureBytes: signatures * signatureBytes,
        signingMessageBytes: sum((role) => role.messageBytes),
        signingFrameBytes: sum((role) => role.frameBytes),
        representativeInputBytes: sum((role) => role.representativeInputBytes),
        representativePermutations: sum(
            (role) => role.representativePermutations,
        ),
    };
};
