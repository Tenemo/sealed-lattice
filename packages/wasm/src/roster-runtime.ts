import {
    actionSignatureSecretKeyByteLength,
    actionSignatureVerificationKeyByteLength,
} from './action-signature-runtime.js';
import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import {
    pairDecryptionKeyByteLength,
    pairEncryptionKeyByteLength,
} from './pair-encryption-runtime.js';

const encodeCompletionRosterCommand = 8;
const verifyCompletionRosterCommand = 9;
const resolveRosterMailboxKeyCommand = 17;
const verifyRosterCredentialsCommand = 41;
const identityByteLength = 64;
const completionParticipantCount = 10;

export const completionRosterByteLength = 31_660;

type RosterPublicKeys = Readonly<{
    signingVerificationKey: Uint8Array;
    mailboxEncapsulationKey: Uint8Array;
}>;

type CanonicalCompletionRoster = Readonly<{
    canonicalBytes: Uint8Array;
    rosterIdentity: Uint8Array;
}>;

export type RosterRuntime = Readonly<{
    encode(publicKeys: readonly RosterPublicKeys[]): CanonicalCompletionRoster;
    verify(canonicalRosterBytes: Uint8Array): Uint8Array;
    verifyCredentials(
        canonicalRosterBytes: Uint8Array,
        rosterPosition: number,
        signingSecretKey: Uint8Array,
        mailboxDecapsulationKey: Uint8Array,
    ): Uint8Array;
    resolveMailboxKey(
        expectedRosterIdentity: Uint8Array,
        senderPosition: number,
        recipientPosition: number,
        canonicalRosterBytes: Uint8Array,
    ): Uint8Array;
}>;

const requirePosition = (position: number, name: string): void => {
    if (
        !Number.isSafeInteger(position) ||
        position < 0 ||
        position >= completionParticipantCount
    ) {
        throw new RangeError(`${name} is not a completion-roster position.`);
    }
};

const copyIdentity = (identity: Uint8Array, name: string): Uint8Array => {
    requireExactConstructionBytes(identity, identityByteLength, name);
    return Uint8Array.from(identity);
};

export const openRosterRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): RosterRuntime => ({
    encode: (publicKeys) => {
        if (publicKeys.length !== completionParticipantCount) {
            throw new TypeError(
                'publicKeys must contain the complete ten-participant roster.',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeCompletionRosterCommand);
        request.writeU16(completionParticipantCount);
        for (const [position, keys] of publicKeys.entries()) {
            requireExactConstructionBytes(
                keys.signingVerificationKey,
                actionSignatureVerificationKeyByteLength,
                `publicKeys[${String(position)}].signingVerificationKey`,
            );
            requireExactConstructionBytes(
                keys.mailboxEncapsulationKey,
                pairEncryptionKeyByteLength,
                `publicKeys[${String(position)}].mailboxEncapsulationKey`,
            );
            request.writeBytes(keys.signingVerificationKey);
            request.writeBytes(keys.mailboxEncapsulationKey);
        }
        return executeConstructionCommand(kernel, request, (reader) => ({
            canonicalBytes: copyRosterBytes(reader.readBytes()),
            rosterIdentity: copyIdentity(
                reader.readFixed(identityByteLength),
                'rosterIdentity',
            ),
        }));
    },
    verify: (canonicalRosterBytes) => {
        requireExactConstructionBytes(
            canonicalRosterBytes,
            completionRosterByteLength,
            'canonicalRosterBytes',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyCompletionRosterCommand);
        request.writeBytes(canonicalRosterBytes);
        return executeConstructionCommand(kernel, request, (reader) =>
            copyIdentity(
                reader.readFixed(identityByteLength),
                'rosterIdentity',
            ),
        );
    },
    verifyCredentials: (
        canonicalRosterBytes,
        rosterPosition,
        signingSecretKey,
        mailboxDecapsulationKey,
    ) => {
        requirePosition(rosterPosition, 'rosterPosition');
        requireExactConstructionBytes(
            canonicalRosterBytes,
            completionRosterByteLength,
            'canonicalRosterBytes',
        );
        requireExactConstructionBytes(
            signingSecretKey,
            actionSignatureSecretKeyByteLength,
            'signingSecretKey',
        );
        requireExactConstructionBytes(
            mailboxDecapsulationKey,
            pairDecryptionKeyByteLength,
            'mailboxDecapsulationKey',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyRosterCredentialsCommand);
        request.writeU16(completionParticipantCount);
        request.writeU16(rosterPosition);
        request.writeBytes(canonicalRosterBytes);
        request.writeBytes(signingSecretKey);
        request.writeBytes(mailboxDecapsulationKey);
        return executeConstructionCommand(kernel, request, (reader) =>
            copyIdentity(
                reader.readFixed(identityByteLength),
                'rosterIdentity',
            ),
        );
    },
    resolveMailboxKey: (
        expectedRosterIdentity,
        senderPosition,
        recipientPosition,
        canonicalRosterBytes,
    ) => {
        copyIdentity(expectedRosterIdentity, 'expectedRosterIdentity');
        requirePosition(senderPosition, 'senderPosition');
        requirePosition(recipientPosition, 'recipientPosition');
        if (senderPosition === recipientPosition) {
            throw new RangeError(
                'senderPosition and recipientPosition must differ.',
            );
        }
        requireExactConstructionBytes(
            canonicalRosterBytes,
            completionRosterByteLength,
            'canonicalRosterBytes',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(resolveRosterMailboxKeyCommand);
        request.writeU16(completionParticipantCount);
        request.writeFixed(expectedRosterIdentity);
        request.writeU16(senderPosition);
        request.writeU16(recipientPosition);
        request.writeBytes(canonicalRosterBytes);
        return executeConstructionCommand(kernel, request, (reader) =>
            copyMailboxKey(reader.readFixed(pairEncryptionKeyByteLength)),
        );
    },
});

const copyRosterBytes = (bytes: Uint8Array): Uint8Array => {
    requireExactConstructionBytes(
        bytes,
        completionRosterByteLength,
        'canonicalRosterBytes',
    );
    return Uint8Array.from(bytes);
};

const copyMailboxKey = (bytes: Uint8Array): Uint8Array => {
    requireExactConstructionBytes(
        bytes,
        pairEncryptionKeyByteLength,
        'mailboxEncapsulationKey',
    );
    return Uint8Array.from(bytes);
};
