import { actionKeySetBodyByteLength } from './action-key-set-runtime.js';
import { actionSignatureKeyByteLength } from './action-signature-runtime.js';
import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import {
    privatePreparationBodyByteLength,
    type PrivatePreparationContextInput,
} from './private-preparation-body-runtime.js';

const encodePreparationParentCommand = 12;
const encodePreparationSignatureCarrierCommand = 13;
const verifyPrivatePreparationCarrierCommand = 14;
const completionProfileParticipantCount = 10;
const identityByteLength = 64;
const subsetCommitmentCount = 120;
const subsetCommitmentByteLength = 64;

export const preparationParentBodyByteLength = (
    participantCount: number,
): number => {
    requireParticipantCount(participantCount);
    return 8_502;
};

export const actionSignatureCarrierByteLength = 6_388;

type PreparationParentInput = Readonly<{
    participantCount: number;
    actionProposalIdentity: Uint8Array;
    actionKeySetRosterIdentity: Uint8Array;
    preparationAttempt: number;
    predecessorIdentity: Uint8Array;
    senderPosition: number;
    subsetCommitments: Uint8Array;
    privateBodyIdentities: readonly Uint8Array[];
}>;

type VerifiedPrivatePreparationCarrier = Readonly<{
    senderPosition: number;
    recipientPosition: number;
    parentIdentity: Uint8Array;
    bodyIdentity: Uint8Array;
}>;

type PrivatePreparationCarrierContextInput = Omit<
    PrivatePreparationContextInput,
    'senderPosition'
>;

export type PreparationParentRuntime = Readonly<{
    encode(input: PreparationParentInput): Readonly<{
        body: Uint8Array;
        identity: Uint8Array;
    }>;
    encodeSignature(
        participantCount: number,
        signerPosition: number,
        bodyIdentity: Uint8Array,
        signature: Uint8Array,
    ): Uint8Array;
    verifyPrivateCarrier(
        context: PrivatePreparationCarrierContextInput,
        actionKeySetBodies: readonly Uint8Array[],
        parentBody: Uint8Array,
        signatureCarrier: Uint8Array,
        privateBody: Uint8Array,
    ): VerifiedPrivatePreparationCarrier;
}>;

const requireParticipantCount = (participantCount: number): void => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount !== completionProfileParticipantCount
    ) {
        throw new RangeError(
            'participantCount must select the completion profile.',
        );
    }
};

const requirePosition = (
    position: number,
    participantCount: number,
    name: string,
): void => {
    if (
        !Number.isSafeInteger(position) ||
        position < 0 ||
        position >= participantCount
    ) {
        throw new RangeError(`${name} is not a roster position.`);
    }
};

const requireUnsigned16 = (value: number, name: string): void => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new RangeError(`${name} must be an unsigned 16-bit integer.`);
    }
};

const copyIdentity = (bytes: Uint8Array): Uint8Array => {
    requireExactConstructionBytes(bytes, identityByteLength, 'identity');
    return Uint8Array.from(bytes);
};

const validateExpectedContext = (
    context: PrivatePreparationCarrierContextInput,
): void => {
    requireParticipantCount(context.participantCount);
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
    requirePosition(
        context.recipientPosition,
        context.participantCount,
        'recipientPosition',
    );
};

const writeExpectedContext = (
    request: ConstructionCommandWriter,
    context: PrivatePreparationCarrierContextInput,
): void => {
    validateExpectedContext(context);
    request.writeU16(context.participantCount);
    request.writeFixed(context.actionProposalIdentity);
    request.writeFixed(context.actionKeySetRosterIdentity);
    request.writeU16(context.preparationAttempt);
    request.writeFixed(context.predecessorIdentity);
    request.writeU16(context.recipientPosition);
};

export const openPreparationParentRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): PreparationParentRuntime => ({
    encode: (input) => {
        requireParticipantCount(input.participantCount);
        requireExactConstructionBytes(
            input.actionProposalIdentity,
            identityByteLength,
            'actionProposalIdentity',
        );
        requireExactConstructionBytes(
            input.actionKeySetRosterIdentity,
            identityByteLength,
            'actionKeySetRosterIdentity',
        );
        requireUnsigned16(input.preparationAttempt, 'preparationAttempt');
        requireExactConstructionBytes(
            input.predecessorIdentity,
            identityByteLength,
            'predecessorIdentity',
        );
        requirePosition(
            input.senderPosition,
            input.participantCount,
            'senderPosition',
        );
        requireExactConstructionBytes(
            input.subsetCommitments,
            subsetCommitmentCount * subsetCommitmentByteLength,
            'subsetCommitments',
        );
        if (input.privateBodyIdentities.length !== input.participantCount - 1) {
            throw new TypeError(
                'privateBodyIdentities must contain one identity per remote recipient.',
            );
        }
        const privateBodyIdentities = new Uint8Array(
            input.privateBodyIdentities.length * identityByteLength,
        );
        for (const [index, identity] of input.privateBodyIdentities.entries()) {
            requireExactConstructionBytes(
                identity,
                identityByteLength,
                `privateBodyIdentities[${String(index)}]`,
            );
            privateBodyIdentities.set(identity, index * identityByteLength);
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(encodePreparationParentCommand);
        request.writeU16(input.participantCount);
        request.writeFixed(input.actionProposalIdentity);
        request.writeFixed(input.actionKeySetRosterIdentity);
        request.writeU16(input.preparationAttempt);
        request.writeFixed(input.predecessorIdentity);
        request.writeU16(input.senderPosition);
        request.writeBytes(input.subsetCommitments);
        request.writeBytes(privateBodyIdentities);
        return executeConstructionCommand(kernel, request, (reader) => {
            const body = reader.readBytes();
            requireExactConstructionBytes(
                body,
                preparationParentBodyByteLength(input.participantCount),
                'body',
            );
            return {
                body: Uint8Array.from(body),
                identity: copyIdentity(reader.readFixed(identityByteLength)),
            };
        });
    },
    encodeSignature: (
        participantCount,
        signerPosition,
        bodyIdentity,
        signature,
    ) => {
        requireParticipantCount(participantCount);
        requirePosition(signerPosition, participantCount, 'signerPosition');
        requireExactConstructionBytes(
            bodyIdentity,
            identityByteLength,
            'bodyIdentity',
        );
        requireExactConstructionBytes(
            signature,
            actionSignatureKeyByteLength,
            'signature',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(encodePreparationSignatureCarrierCommand);
        request.writeU16(participantCount);
        request.writeU16(signerPosition);
        request.writeFixed(bodyIdentity);
        request.writeBytes(signature);
        return executeConstructionCommand(kernel, request, (reader) => {
            const carrier = reader.readBytes();
            requireExactConstructionBytes(
                carrier,
                actionSignatureCarrierByteLength,
                'signatureCarrier',
            );
            return Uint8Array.from(carrier);
        });
    },
    verifyPrivateCarrier: (
        context,
        actionKeySetBodies,
        parentBody,
        signatureCarrier,
        privateBody,
    ) => {
        validateExpectedContext(context);
        if (actionKeySetBodies.length !== context.participantCount) {
            throw new TypeError(
                'actionKeySetBodies must contain the complete ordered roster.',
            );
        }
        requireExactConstructionBytes(
            parentBody,
            preparationParentBodyByteLength(context.participantCount),
            'parentBody',
        );
        requireExactConstructionBytes(
            signatureCarrier,
            actionSignatureCarrierByteLength,
            'signatureCarrier',
        );
        requireExactConstructionBytes(
            privateBody,
            privatePreparationBodyByteLength,
            'privateBody',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyPrivatePreparationCarrierCommand);
        writeExpectedContext(request, context);
        for (const [position, keySetBody] of actionKeySetBodies.entries()) {
            requireExactConstructionBytes(
                keySetBody,
                actionKeySetBodyByteLength(context.participantCount),
                `actionKeySetBodies[${String(position)}]`,
            );
            request.writeBytes(keySetBody);
        }
        request.writeBytes(parentBody);
        request.writeBytes(signatureCarrier);
        request.writeBytes(privateBody);
        return executeConstructionCommand(kernel, request, (reader) => ({
            senderPosition: reader.readU16(),
            recipientPosition: reader.readU16(),
            parentIdentity: copyIdentity(reader.readFixed(identityByteLength)),
            bodyIdentity: copyIdentity(reader.readFixed(identityByteLength)),
        }));
    },
});
