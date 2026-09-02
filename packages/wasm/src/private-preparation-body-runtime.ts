import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import {
    pairDecryptionKeyByteLength,
    pairEncryptionKeyByteLength,
    pairEncryptionRandomnessByteLength,
} from './pair-encryption-runtime.js';
import { preparationPlaintextByteLength } from './preparation-material-runtime.js';

const sealPrivatePreparationBodyCommand = 10;
const openPrivatePreparationBodyCommand = 11;
const completionProfileParticipantCount = 10;
const identityByteLength = 64;

export const privatePreparationPlaintextByteLength =
    preparationPlaintextByteLength;
export const privatePreparationBodyByteLength = 8_252;
export const privatePreparationRecordKeyByteLength = 32;

export type PrivatePreparationContextInput = Readonly<{
    participantCount: number;
    actionProposalIdentity: Uint8Array;
    actionKeySetRosterIdentity: Uint8Array;
    preparationAttempt: number;
    predecessorIdentity: Uint8Array;
    senderPosition: number;
    recipientPosition: number;
}>;

type SealedPrivatePreparationBody = Readonly<{
    body: Uint8Array;
    identity: Uint8Array;
}>;

export type PrivatePreparationBodyRuntime = Readonly<{
    seal(
        context: PrivatePreparationContextInput,
        pairEncryptionKey: Uint8Array,
        recordKey: Uint8Array,
        pairEncryptionRandomness: Uint8Array,
        plaintext: Uint8Array,
    ): SealedPrivatePreparationBody;
    open(
        context: PrivatePreparationContextInput,
        pairEncryptionKey: Uint8Array,
        pairDecryptionKey: Uint8Array,
        body: Uint8Array,
    ): Uint8Array;
}>;

const requireUnsigned16 = (value: number, name: string): void => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new RangeError(`${name} must be an unsigned 16-bit integer.`);
    }
};

const validateContext = (context: PrivatePreparationContextInput): void => {
    if (
        !Number.isSafeInteger(context.participantCount) ||
        context.participantCount !== completionProfileParticipantCount
    ) {
        throw new RangeError(
            'participantCount must select the completion profile.',
        );
    }
    requireExactConstructionBytes(
        context.actionProposalIdentity,
        identityByteLength,
        'actionProposalIdentity',
    );
    requireExactConstructionBytes(
        context.actionKeySetRosterIdentity,
        identityByteLength,
        'actionKeySetRosterIdentity',
    );
    requireUnsigned16(context.preparationAttempt, 'preparationAttempt');
    requireExactConstructionBytes(
        context.predecessorIdentity,
        identityByteLength,
        'predecessorIdentity',
    );
    requireUnsigned16(context.senderPosition, 'senderPosition');
    requireUnsigned16(context.recipientPosition, 'recipientPosition');
    if (
        context.senderPosition >= context.participantCount ||
        context.recipientPosition >= context.participantCount ||
        context.senderPosition === context.recipientPosition
    ) {
        throw new RangeError(
            'senderPosition and recipientPosition must be distinct roster positions.',
        );
    }
};

const writeContext = (
    request: ConstructionCommandWriter,
    context: PrivatePreparationContextInput,
): void => {
    validateContext(context);
    request.writeU16(context.participantCount);
    request.writeFixed(context.actionProposalIdentity);
    request.writeFixed(context.actionKeySetRosterIdentity);
    request.writeU16(context.preparationAttempt);
    request.writeFixed(context.predecessorIdentity);
    request.writeU16(context.senderPosition);
    request.writeU16(context.recipientPosition);
};

const copyExactResponse = (
    bytes: Uint8Array,
    expectedLength: number,
    name: string,
): Uint8Array => {
    requireExactConstructionBytes(bytes, expectedLength, name);
    return Uint8Array.from(bytes);
};

export const openPrivatePreparationBodyRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): PrivatePreparationBodyRuntime => ({
    seal: (
        context,
        pairEncryptionKey,
        recordKey,
        pairEncryptionRandomness,
        plaintext,
    ) => {
        requireExactConstructionBytes(
            pairEncryptionKey,
            pairEncryptionKeyByteLength,
            'pairEncryptionKey',
        );
        requireExactConstructionBytes(
            recordKey,
            privatePreparationRecordKeyByteLength,
            'recordKey',
        );
        requireExactConstructionBytes(
            pairEncryptionRandomness,
            pairEncryptionRandomnessByteLength,
            'pairEncryptionRandomness',
        );
        requireExactConstructionBytes(
            plaintext,
            privatePreparationPlaintextByteLength,
            'plaintext',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(sealPrivatePreparationBodyCommand);
        writeContext(request, context);
        request.writeBytes(pairEncryptionKey);
        request.writeBytes(recordKey);
        request.writeBytes(pairEncryptionRandomness);
        request.writeBytes(plaintext);
        return executeConstructionCommand(kernel, request, (reader) => ({
            body: copyExactResponse(
                reader.readBytes(),
                privatePreparationBodyByteLength,
                'body',
            ),
            identity: copyExactResponse(
                reader.readFixed(identityByteLength),
                identityByteLength,
                'identity',
            ),
        }));
    },
    open: (context, pairEncryptionKey, pairDecryptionKey, body) => {
        requireExactConstructionBytes(
            pairEncryptionKey,
            pairEncryptionKeyByteLength,
            'pairEncryptionKey',
        );
        requireExactConstructionBytes(
            pairDecryptionKey,
            pairDecryptionKeyByteLength,
            'pairDecryptionKey',
        );
        requireExactConstructionBytes(
            body,
            privatePreparationBodyByteLength,
            'body',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(openPrivatePreparationBodyCommand);
        writeContext(request, context);
        request.writeBytes(pairEncryptionKey);
        request.writeBytes(pairDecryptionKey);
        request.writeBytes(body);
        return executeConstructionCommand(kernel, request, (reader) =>
            copyExactResponse(
                reader.readBytes(),
                privatePreparationPlaintextByteLength,
                'plaintext',
            ),
        );
    },
});
