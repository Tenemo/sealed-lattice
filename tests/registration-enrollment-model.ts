import { compileRecipientKeyCensus } from '#tests/recipient-key-model.js';
import { compileRegistrationSetupBindingScreen } from '#tests/registration-setup-binding-model.js';
import {
    deriveSupportedProfile,
    supportedProfileRanges,
} from '#tests/supported-profile-model.js';

export const registrationSigningPublicKeyBytes = 1952n;
// ParticipantIdentity renders its foundation Hash512 as lowercase hex.
export const participantIdentityAsciiBytes = 2n * 64n;

// The verified poll fixes this ordered family inventory before any roster.
// The existing independent screen groups exact modulus/sampler pairs.
export const compileRegistrationSourceCustody = (
    maximumParticipants: number,
    optionCount: number,
) => {
    const source = compileRegistrationSetupBindingScreen(
        maximumParticipants,
        optionCount,
    );
    return {
        familyCount: source.coordinateCount,
        commitmentListBytes: 2n + 4n + source.commitmentDigestPayloadBytes,
        capsulePlaintextBytes: 4n + source.privateSeedAndSaltPayloadBytes,
        capsuleBytes: 4n + source.privateSeedAndSaltPayloadBytes + 16n,
    };
};

let sourceMaximums:
    | { familyCount: bigint; capsuleBytes: bigint; retainedSetupBytes: bigint }
    | undefined;
const maximumSourceInventory = () => {
    if (sourceMaximums !== undefined) return sourceMaximums;
    const { participants, options } = supportedProfileRanges();
    let familyCount = 0n;
    let retainedSetupBytes = 0n;
    for (let option = options.minimum; option <= options.maximum; option++) {
        const source = compileRegistrationSourceCustody(
            participants.maximum,
            option,
        );
        if (source.familyCount > familyCount) familyCount = source.familyCount;
        for (
            let count = participants.minimum;
            count <= participants.maximum;
            count++
        ) {
            const profile = deriveSupportedProfile(count, option);
            const polynomials = 4n * profile.gadgetLength + 2n * BigInt(count);
            const bytes = 4n + 64n + 64n * polynomials + 64n;
            if (bytes > retainedSetupBytes) retainedSetupBytes = bytes;
        }
    }
    sourceMaximums = {
        familyCount,
        capsuleBytes: 4n + familyCount * 128n + 16n,
        retainedSetupBytes,
    };
    return sourceMaximums;
};

const registrationEnrollmentInputs = {
    signingPublicKeyBytes: registrationSigningPublicKeyBytes,
    signatureBytes: 3309n,
    maximumUsernameBytes: 128n,
    maximumUsernameIngressBytes: 512n,
    maximumHeaderInputBytes: 4096n,
    maximumPollDefinitionBytes: 1_048_576n,
    // A retained roster proposal is at most this long.
    maximumProposalBytes: 2048n,
} as const;

export const compileRegistrationEnrollmentCensus = () => {
    const key = compileRecipientKeyCensus();
    const inputs = registrationEnrollmentInputs;
    const source = maximumSourceInventory();
    const ceiling = (value: bigint, divisor: bigint) =>
        (value + divisor - 1n) / divisor;
    const bytes = (value: string) => BigInt(Buffer.byteLength(value, 'utf8'));
    const maximumHeaderBytes =
        8n +
        7n * 6n +
        4n +
        bytes('sealed-lattice/registration-header/v5') +
        3n * 64n +
        inputs.signingPublicKeyBytes +
        4n +
        inputs.maximumUsernameBytes +
        2n +
        4n +
        64n * source.familyCount;
    const recipientCapsuleBytes = 4n + key.support * 2n + 16n;
    const signingCapsuleBytes = 4n + 32n + 16n;
    const maximumEnrollmentRecords =
        ceiling(key.publicKeyBytes, 1_048_576n) + 7n;
    // The proposal and its signature.
    const maximumRecords = maximumEnrollmentRecords + 2n;
    const manifestPrefixBytes = 4n + 3n * 32n + 64n + 4n;
    const preparedManifestPrefixBytes = manifestPrefixBytes - 32n;
    const maximumEnrollmentManifestBytes =
        manifestPrefixBytes + maximumEnrollmentRecords * 73n;
    const maximumProposalIntentManifestBytes =
        manifestPrefixBytes + (maximumEnrollmentRecords + 1n) * 73n;
    const maximumManifestBytes = manifestPrefixBytes + maximumRecords * 73n;
    const maximumRootBytes = maximumManifestBytes + 16n;
    // Seven items: the purpose, runtime, nonce, organizer key, manifest,
    // result length and participant maximum.
    const pollDefinitionOverheadBytes =
        8n +
        7n * 6n +
        4n +
        bytes('sealed-lattice/poll-definition/v2') +
        64n +
        32n +
        inputs.signingPublicKeyBytes +
        4n +
        2n +
        2n;
    // The canonical manifest inside the poll definition frames the question
    // and labels: its eight-byte tuple header, two six-byte item headers, the
    // question's four-byte length and the option list's two-byte element type
    // and four-byte count, then per option its own tuple header, three item
    // headers, its two-byte index and the four-byte lengths of its identifier
    // `option-i` and its label.
    const manifestFramingBytes = (options: bigint) => {
        let identifierBytes = 0n;
        for (let index = 0n; index < options; index++)
            identifierBytes += bytes(`option-${String(index)}`);
        return 30n + 36n * options + identifierBytes;
    };
    // The organizer input carries the runtime, the result length, the
    // participant maximum, the question, the option count, each label and
    // the username, each text after its four-byte length, then the three data
    // keys. The texts fill what the poll definition leaves beside its own
    // framing and the manifest's, which grows faster with the option count
    // than the input's framing, so the fewest options give the longest input.
    const organizerInputBytes = (options: bigint) =>
        64n +
        2n +
        2n +
        4n +
        2n +
        4n * options +
        inputs.maximumPollDefinitionBytes -
        pollDefinitionOverheadBytes -
        manifestFramingBytes(options) +
        4n +
        inputs.maximumUsernameIngressBytes +
        96n;
    const { options } = supportedProfileRanges();
    let maximumOrganizerInputBytes = 0n;
    for (let count = options.minimum; count <= options.maximum; count++) {
        const value = organizerInputBytes(BigInt(count));
        if (value > maximumOrganizerInputBytes)
            maximumOrganizerInputBytes = value;
    }
    return {
        ...inputs,
        maximumHeaderBytes,
        recipientCapsuleBytes,
        signingCapsuleBytes,
        maximumSourceFamilyCount: source.familyCount,
        maximumSourceCapsuleBytes: source.capsuleBytes,
        maximumRecords,
        maximumEnrollmentRecords,
        maximumEnrollmentManifestBytes,
        maximumProposalIntentManifestBytes,
        manifestPrefixBytes,
        preparedManifestPrefixBytes,
        maximumManifestBytes,
        maximumRootBytes,
        pollDefinitionOverheadBytes,
        maximumOrganizerInputBytes,
        maximumJoinInputBytes:
            128n +
            4n +
            inputs.maximumPollDefinitionBytes +
            inputs.signatureBytes +
            4n +
            inputs.maximumUsernameIngressBytes +
            96n,
        recipientAssociatedBytes:
            bytes('sealed-lattice/recipient-key-custody/v1') + 64n,
        signingAssociatedBytes: bytes('registration-signing-seed/1') + 64n,
        sourceAssociatedBytes:
            8n +
            2n * 6n +
            4n +
            bytes('sealed-lattice/fhe-source-custody/v1') +
            64n,
        rootAssociatedBytes: 4n + 64n,
        // The restore control ends with the two-byte mask of signing
        // purposes that the authenticated root shows unused.
        maximumRestoreInputBytes:
            128n +
            4n +
            maximumHeaderBytes +
            64n +
            key.publicKeyBytes +
            recipientCapsuleBytes +
            signingCapsuleBytes +
            (96n + source.capsuleBytes > 64n + 4n + source.retainedSetupBytes
                ? 96n + source.capsuleBytes
                : 64n + 4n + source.retainedSetupBytes) +
            2n,
        maximumRetainedPayloadBytes:
            key.publicKeyBytes +
            maximumHeaderBytes +
            inputs.signatureBytes +
            recipientCapsuleBytes +
            signingCapsuleBytes +
            source.capsuleBytes +
            maximumRootBytes +
            inputs.maximumPollDefinitionBytes +
            inputs.signatureBytes +
            inputs.maximumProposalBytes +
            inputs.signatureBytes,
        initialRootDistinctBlockInputs:
            1n +
            2n +
            ceiling(68n, 16n) +
            ceiling(maximumEnrollmentManifestBytes, 16n),
        // Proposal transitions each use a fresh root key for one encryption.
        rootDistinctBlockInputs: 2n + ceiling(maximumManifestBytes, 16n),
        signingDistinctBlockInputs:
            1n + 1n + ceiling(signingCapsuleBytes - 16n, 16n),
        sourceDistinctBlockInputs:
            1n + 1n + ceiling(source.capsuleBytes - 16n, 16n),
    };
};
