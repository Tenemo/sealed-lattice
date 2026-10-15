import { ballotEnvelopeBytes } from '#tests/ballot-body-model.js';
import { participantReleaseEnvelopeBytes } from '#tests/participant-release-custody-model.js';
import { byteAlignedSpongePermutations } from '#tests/proof-hash-work-model.js';
import { purposeSignatureSizes } from '#tests/purpose-signature-parameters.js';
import { compileSetupSelectionCensus } from '#tests/setup-selection-model.js';

const authenticationPurposes = [
    'poll-definition',
    'registration',
    'roster-proposal',
    'contribution-offer',
    'setup-selection-proposal',
    'setup-selection-endorsement',
    'ballot-envelope',
] as const;
type AuthenticationPurpose = (typeof authenticationPurposes)[number];
export const completeAuthenticationPurposes = [
    ...authenticationPurposes,
    'close-intent',
    'close-response',
    'close-proposal',
    'target-certification',
    'release-envelope',
] as const;
type CompleteAuthenticationPurpose =
    (typeof completeAuthenticationPurposes)[number];
const authenticationContext = (purpose: CompleteAuthenticationPurpose) =>
    `sealed-lattice/${purpose}`;
export const purposeSignatureParameters = {
    digestBits: 512n,
    radix: 16n,
    messageDigits: 128n,
    checksumDigits: 3n,
    chains: 131n,
    activePurposes: BigInt(completeAuthenticationPurposes.length),
    treeLeaves: 16n,
    treeHeight: 4n,
    seedBytes: 64n,
} as const;

export const purposeSignatureFrame = (
    root: Uint8Array,
    purpose: number,
    message: Uint8Array,
) => {
    if (
        root.length !== 64 ||
        !Number.isInteger(purpose) ||
        purpose < 0 ||
        purpose >= completeAuthenticationPurposes.length
    )
        throw new RangeError('Invalid purpose signature frame.');
    const prefix = Buffer.alloc(64);
    prefix.write('sealed-lattice/fixed-hash');
    const length = Buffer.alloc(8);
    length.writeBigUInt64LE(BigInt(message.length));
    return Buffer.concat([
        prefix,
        Buffer.from('purpose-wots/message/v1'),
        root,
        Uint8Array.of(purpose),
        length,
        message,
    ]);
};

const frameWork = <Purpose extends CompleteAuthenticationPurpose>(
    purpose: Purpose,
) => {
    const messageBytes =
        purpose === 'ballot-envelope'
            ? ballotEnvelopeBytes
            : purpose === 'release-envelope'
              ? participantReleaseEnvelopeBytes
              : 64n;
    const frameBytes = 64n + 1n + 8n + messageBytes;
    const representativeInputBytes =
        64n + BigInt(Buffer.byteLength('purpose-wots/message/v1')) + frameBytes;
    return {
        purpose,
        context: authenticationContext(purpose),
        messageBytes,
        frameBytes,
        representativeInputBytes,
        representativePermutations: byteAlignedSpongePermutations(
            representativeInputBytes,
            64n,
            136n,
        ),
    };
};
const compileAuthenticationFrameWork = () =>
    authenticationPurposes.map(frameWork);
export const compileCompleteAuthenticationFrameWork = () =>
    completeAuthenticationPurposes.map(frameWork);

export const compileCredentialIntentBoundsThroughBallot = () => {
    const organizerOnly: readonly AuthenticationPurpose[] = [
        'poll-definition',
        'roster-proposal',
        'setup-selection-proposal',
    ];
    return (['organizer', 'other participant'] as const).map((role) => {
        const purposes = authenticationPurposes.filter(
            (purpose) =>
                role === 'organizer' || !organizerOnly.includes(purpose),
        );
        return {
            role,
            purposes,
            firstEvaluatedIntentBound: BigInt(purposes.length),
        };
    });
};

export const compileCompleteCredentialIntentBounds = (
    participantCount: number,
) =>
    [
        {
            name: 'Encrypted result with own target vote',
            target: true,
            release: true,
        },
        { name: 'No result', target: true, release: false },
        {
            name: 'Encrypted release without own target vote',
            target: false,
            release: true,
        },
    ].flatMap((branch) =>
        compileCredentialIntentBoundsThroughBallot().map((participant) => {
            const fixedPurposes: CompleteAuthenticationPurpose[] = [
                ...participant.purposes.filter(
                    (purpose) => purpose !== 'ballot-envelope',
                ),
                ...(participant.role === 'organizer'
                    ? ([
                          'close-intent',
                          'close-response',
                          'close-proposal',
                      ] as const)
                    : (['close-response'] as const)),
                ...(branch.target ? (['target-certification'] as const) : []),
                ...(branch.release ? (['release-envelope'] as const) : []),
            ];
            return {
                participantCount,
                branch: branch.name,
                role: participant.role,
                fixedPurposes,
                optionalPurposes: ['ballot-envelope'] as const,
                firstEvaluatedIntentBound: BigInt(fixedPurposes.length) + 1n,
            };
        }),
    );

export const compileSignatureHashInputs = () => {
    const payloads = {
        secret: 67n,
        chain: 64n,
        leaf: 1n + 131n * 64n,
        unused: 1n,
        node: 129n,
    };
    const rows = Object.entries(payloads).map(([purpose, bytes]) => {
        const inputBytes =
            64n +
            BigInt(Buffer.byteLength(`purpose-wots/${purpose}/v1`)) +
            bytes;
        return {
            purpose,
            family: 'SHAKE256',
            inputBytes,
            outputBytes: 64n,
            permutations: byteAlignedSpongePermutations(inputBytes, 64n, 136n),
        };
    });
    return { rows };
};

export const compilePurposeSignatureWork = () => {
    const { chains, activePurposes, treeLeaves, treeHeight } =
        purposeSignatureParameters;
    const hashes = new Map(
        compileSignatureHashInputs().rows.map((row) => [row.purpose, row]),
    );
    const keyCounts = {
        secret: activePurposes * chains,
        chain: activePurposes * chains * 15n,
        leaf: activePurposes,
        unused: treeLeaves - activePurposes,
        node: treeLeaves - 1n,
    };
    const keyHashCalls = Object.values(keyCounts).reduce(
        (sum, value) => sum + value,
        0n,
    );
    const keyPermutations = Object.entries(keyCounts).reduce(
        (sum, [name, count]) => sum + count * hashes.get(name)!.permutations,
        0n,
    );
    const chainPermutations = hashes.get('chain')!.permutations;
    return {
        keyCounts,
        keyHashCalls,
        keyPermutations,
        maximumSignatureHashCalls: 1n + chains * 16n,
        maximumVerificationHashCalls: chains * 15n + 2n + treeHeight,
        credentialPredecessorGates:
            activePurposes * chains * 15n * chainPermutations * 38400n,
        maximumKnownBankCallsPerCredential:
            keyHashCalls + 12n * (1n + chains * 16n),
    };
};

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
        'contribution-offer': BigInt(
            compileSetupSelectionCensus(participantCount)
                .eligibleContributorCount,
        ),
        'setup-selection-proposal': 1n,
        'setup-selection-endorsement': participants,
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
        signatureBytes: signatures * purposeSignatureSizes.signatureBytes,
        signingMessageBytes: sum((role) => role.messageBytes),
        signingFrameBytes: sum((role) => role.frameBytes),
        representativeInputBytes: sum((role) => role.representativeInputBytes),
        representativePermutations: sum(
            (role) => role.representativePermutations,
        ),
    };
};
