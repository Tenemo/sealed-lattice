import { compileBallotBodyCensus } from '#tests/ballot-body-model.js';
import {
    mlDsa65ChallengeSeedBytes,
    mlDsa65Parameters,
} from '#tests/ml-dsa-theorem-screen-model.js';
import { byteAlignedSpongePermutations } from '#tests/proof-hash-work-model.js';
import { rejectionSubsetBound } from '#tests/proof-randomness-budget-model.js';
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

// One original credential through ballot completion, under the original-state
// invariant. Each purpose has one fixed first-evaluated intent; repeated
// evaluation of its retained coins is still work, but not another oracle query.
// Closing/release purposes and the population of credential creations are absent.
export const compileCurrentCredentialIntentBounds = () => {
    const owners: Record<AuthenticationPurpose, 'organizer' | 'everyone'> = {
        'poll-definition': 'organizer',
        registration: 'everyone',
        'roster-proposal': 'organizer',
        'roster-confirmation': 'everyone',
        'setup-opening': 'everyone',
        'ballot-envelope': 'everyone',
    };
    return (['organizer', 'other participant'] as const).map((role) => {
        const purposes = authenticationPurposes.filter(
            (purpose) => role === 'organizer' || owners[purpose] === 'everyone',
        );
        return {
            role,
            purposes,
            firstEvaluatedIntentBound: BigInt(purposes.length),
        };
    });
};

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

// Complete hash input shapes of the current pure ML-DSA-65 callers. A null
// output length denotes a source-level rejection sampler, not zero work.
export const compileCurrentSignatureHashInputs = () => {
    const parameters = mlDsa65Parameters;
    const highBitAlphabet =
        (parameters.modulus - 1n) / (2n * parameters.roundingBound);
    const highBitWidth = BigInt((highBitAlphabet - 1n).toString(2).length);
    const highBitEncodingBytes =
        (parameters.rowCount * parameters.polynomialDegree * highBitWidth) / 8n;
    const maskBits =
        1n + BigInt((parameters.maskingBound - 1n).toString(2).length);
    const rows = [
        {
            purpose: 'Key expansion',
            family: 'SHAKE256',
            inputBytes: 32n + 2n,
            outputBytes: 128n,
        },
        {
            purpose: 'Public key digest',
            family: 'SHAKE256',
            inputBytes:
                compileRegistrationEnrollmentCensus().signingPublicKeyBytes,
            outputBytes: 64n,
        },
        {
            purpose: 'Private mask seed',
            family: 'SHAKE256',
            inputBytes: 32n + 32n + 64n,
            outputBytes: 64n,
        },
        {
            purpose: 'Challenge digest',
            family: 'SHAKE256',
            inputBytes: 64n + highBitEncodingBytes,
            outputBytes: mlDsa65ChallengeSeedBytes,
        },
        {
            purpose: 'Challenge polynomial sampling',
            family: 'SHAKE256',
            inputBytes: mlDsa65ChallengeSeedBytes,
            outputBytes: null,
        },
        {
            purpose: 'Secret polynomial sampling',
            family: 'SHAKE256',
            inputBytes: 64n + 2n,
            outputBytes: null,
        },
        {
            purpose: 'Mask expansion',
            family: 'SHAKE256',
            inputBytes: 64n + 2n,
            outputBytes: 32n * maskBits,
        },
        {
            purpose: 'Matrix polynomial sampling',
            family: 'SHAKE128',
            inputBytes: 32n + 2n,
            outputBytes: null,
        },
        ...compileAuthenticationFrameWork().map((frame) => ({
            purpose: frame.purpose,
            family: 'SHAKE256',
            inputBytes: frame.representativeInputBytes,
            outputBytes: 64n,
        })),
    ];
    return {
        highBitEncodingBytes,
        rows,
        maximumInputBytes: rows.reduce(
            (maximum, row) =>
                row.inputBytes > maximum ? row.inputBytes : maximum,
            0n,
        ),
    };
};

// An ideal-XOF property of every possible sampler seed, established before
// adaptive input selection. These analytical caps do not alter the library.
export const compileCurrentSignatureSamplingBounds = () => {
    const parameters = mlDsa65Parameters;
    return [
        {
            purpose: 'Matrix polynomial sampling',
            family: 'SHAKE128',
            inputBytes: 34n,
            sampleBits: 23n,
            rejectedValues: (1n << 23n) - parameters.modulus,
            candidatePositions: 2n * parameters.polynomialDegree,
            requiredSuccesses: parameters.polynomialDegree,
            outputBytes: 6n * parameters.polynomialDegree,
        },
        {
            purpose: 'Secret polynomial sampling',
            family: 'SHAKE256',
            inputBytes: 66n,
            sampleBits: 4n,
            rejectedValues: 16n - (2n * parameters.secretCoefficientBound + 1n),
            candidatePositions: 8n * parameters.polynomialDegree,
            requiredSuccesses: parameters.polynomialDegree,
            outputBytes: 4n * parameters.polynomialDegree,
        },
        {
            purpose: 'Challenge polynomial sampling',
            family: 'SHAKE256',
            inputBytes: mlDsa65ChallengeSeedBytes,
            sampleBits: 8n,
            rejectedValues: parameters.challengeWeight - 1n,
            candidatePositions: 2n * parameters.polynomialDegree,
            requiredSuccesses: parameters.challengeWeight,
            outputBytes: 8n + 2n * parameters.polynomialDegree,
        },
    ].map((row) => {
        const requiredRejections =
                row.candidatePositions - row.requiredSuccesses + 1n,
            inputCount = 1n << (8n * row.inputBytes),
            failure = rejectionSubsetBound({
                ...row,
                requiredRejections,
                inputCount,
            });
        let failureExponent = 0n;
        while (
            failure.numerator << (failureExponent + 1n) <=
            1n << failure.denominatorBits
        )
            failureExponent++;
        return {
            ...row,
            requiredRejections,
            inputCount,
            ...failure,
            failureExponent,
        };
    });
};

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
