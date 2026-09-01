import { actionSignatureKeyByteLength } from './action-signature-runtime.js';
import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import { pairEncryptionKeyByteLength } from './pair-encryption-runtime.js';

const encodeActionKeySetCommand = 7;
const verifyActionKeySetCommand = 8;
const verifyActionKeySetRosterCommand = 9;
const resolvePairEncryptionKeyCommand = 17;
const minimumParticipantCount = 3;
const maximumParticipantCount = 20;
const actionSignaturePurposeCount = 4;
const proposalIdentityByteLength = 64;
const actionKeySetNonceByteLength = 32;
const nestedTupleListHeaderByteLength = 6;
const tupleHeaderByteLength = 8;
const tupleItemHeaderByteLength = 6;

export type ActionKeySetInput = Readonly<{
    participantCount: number;
    proposalIdentity: Uint8Array;
    rosterPosition: number;
    nonce: Uint8Array;
    actionSignatureVerificationKeys: readonly Uint8Array[];
    pairEncryptionKeys: readonly Uint8Array[];
}>;

export type EncodedActionKeySet = Readonly<{
    body: Uint8Array;
    identity: Uint8Array;
}>;

export type ActionKeySetRuntime = Readonly<{
    encode(input: ActionKeySetInput): EncodedActionKeySet;
    verify(
        participantCount: number,
        expectedProposalIdentity: Uint8Array,
        expectedRosterPosition: number,
        body: Uint8Array,
    ): Uint8Array;
    verifyCompleteRoster(
        participantCount: number,
        bodies: readonly Uint8Array[],
    ): Uint8Array;
    resolvePairEncryptionKey(
        participantCount: number,
        expectedProposalIdentity: Uint8Array,
        expectedRosterIdentity: Uint8Array,
        senderPosition: number,
        recipientPosition: number,
        bodies: readonly Uint8Array[],
    ): Uint8Array;
}>;

const requireParticipantCount = (participantCount: number): void => {
    if (
        !Number.isSafeInteger(participantCount) ||
        participantCount < minimumParticipantCount ||
        participantCount > maximumParticipantCount
    ) {
        throw new RangeError(
            'participantCount is outside the supported profile.',
        );
    }
};

const requireRosterPosition = (
    rosterPosition: number,
    participantCount: number,
): void => {
    if (
        !Number.isSafeInteger(rosterPosition) ||
        rosterPosition < 0 ||
        rosterPosition >= participantCount
    ) {
        throw new RangeError('rosterPosition is invalid.');
    }
};

const concatenateExactKeys = (
    keys: readonly Uint8Array[],
    expectedCount: number,
    keyByteLength: number,
    name: string,
): Uint8Array => {
    if (keys.length !== expectedCount) {
        throw new TypeError(
            `${name} must contain ${String(expectedCount)} keys.`,
        );
    }
    const output = new Uint8Array(expectedCount * keyByteLength);
    for (const [index, key] of keys.entries()) {
        requireExactConstructionBytes(
            key,
            keyByteLength,
            `${name}[${String(index)}]`,
        );
        output.set(key, index * keyByteLength);
    }
    return output;
};

const keyTupleByteLength = (keyByteLength: number): number =>
    tupleHeaderByteLength + tupleItemHeaderByteLength + keyByteLength;

export const actionKeySetBodyByteLength = (
    participantCount: number,
): number => {
    requireParticipantCount(participantCount);
    const signatureKeyVectorByteLength =
        nestedTupleListHeaderByteLength +
        actionSignaturePurposeCount *
            keyTupleByteLength(actionSignatureKeyByteLength);
    const pairKeyVectorByteLength =
        nestedTupleListHeaderByteLength +
        (participantCount - 1) *
            keyTupleByteLength(pairEncryptionKeyByteLength);
    return (
        tupleHeaderByteLength +
        tupleItemHeaderByteLength * 5 +
        proposalIdentityByteLength +
        2 +
        actionKeySetNonceByteLength +
        signatureKeyVectorByteLength +
        pairKeyVectorByteLength
    );
};

const copyIdentity = (identity: Uint8Array): Uint8Array => {
    requireExactConstructionBytes(
        identity,
        proposalIdentityByteLength,
        'identity',
    );
    return Uint8Array.from(identity);
};

export const openActionKeySetRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): ActionKeySetRuntime => ({
    encode: (input) => {
        requireParticipantCount(input.participantCount);
        requireRosterPosition(input.rosterPosition, input.participantCount);
        requireExactConstructionBytes(
            input.proposalIdentity,
            proposalIdentityByteLength,
            'proposalIdentity',
        );
        requireExactConstructionBytes(
            input.nonce,
            actionKeySetNonceByteLength,
            'nonce',
        );
        const signatureKeys = concatenateExactKeys(
            input.actionSignatureVerificationKeys,
            actionSignaturePurposeCount,
            actionSignatureKeyByteLength,
            'actionSignatureVerificationKeys',
        );
        const pairKeys = concatenateExactKeys(
            input.pairEncryptionKeys,
            input.participantCount - 1,
            pairEncryptionKeyByteLength,
            'pairEncryptionKeys',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeActionKeySetCommand);
        request.writeU16(input.participantCount);
        request.writeFixed(input.proposalIdentity);
        request.writeU16(input.rosterPosition);
        request.writeBytes(input.nonce);
        request.writeBytes(signatureKeys);
        request.writeBytes(pairKeys);
        return executeConstructionCommand(kernel, request, (reader) => {
            const body = reader.readBytes();
            requireExactConstructionBytes(
                body,
                actionKeySetBodyByteLength(input.participantCount),
                'body',
            );
            return {
                body: Uint8Array.from(body),
                identity: copyIdentity(reader.readFixed(64)),
            };
        });
    },
    verify: (
        participantCount,
        expectedProposalIdentity,
        expectedRosterPosition,
        body,
    ) => {
        requireParticipantCount(participantCount);
        requireRosterPosition(expectedRosterPosition, participantCount);
        requireExactConstructionBytes(
            expectedProposalIdentity,
            proposalIdentityByteLength,
            'expectedProposalIdentity',
        );
        requireExactConstructionBytes(
            body,
            actionKeySetBodyByteLength(participantCount),
            'body',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyActionKeySetCommand);
        request.writeU16(participantCount);
        request.writeFixed(expectedProposalIdentity);
        request.writeU16(expectedRosterPosition);
        request.writeBytes(body);
        return executeConstructionCommand(kernel, request, (reader) =>
            copyIdentity(reader.readFixed(64)),
        );
    },
    verifyCompleteRoster: (participantCount, bodies) => {
        requireParticipantCount(participantCount);
        if (bodies.length !== participantCount) {
            throw new TypeError(
                'bodies must contain one action key set for every participant.',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyActionKeySetRosterCommand);
        request.writeU16(participantCount);
        for (const [position, body] of bodies.entries()) {
            requireExactConstructionBytes(
                body,
                actionKeySetBodyByteLength(participantCount),
                `bodies[${String(position)}]`,
            );
            request.writeBytes(body);
        }
        return executeConstructionCommand(kernel, request, (reader) =>
            copyIdentity(reader.readFixed(64)),
        );
    },
    resolvePairEncryptionKey: (
        participantCount,
        expectedProposalIdentity,
        expectedRosterIdentity,
        senderPosition,
        recipientPosition,
        bodies,
    ) => {
        requireParticipantCount(participantCount);
        requireExactConstructionBytes(
            expectedProposalIdentity,
            proposalIdentityByteLength,
            'expectedProposalIdentity',
        );
        requireExactConstructionBytes(
            expectedRosterIdentity,
            proposalIdentityByteLength,
            'expectedRosterIdentity',
        );
        requireRosterPosition(senderPosition, participantCount);
        requireRosterPosition(recipientPosition, participantCount);
        if (senderPosition === recipientPosition) {
            throw new RangeError(
                'senderPosition and recipientPosition must differ.',
            );
        }
        if (bodies.length !== participantCount) {
            throw new TypeError(
                'bodies must contain one action key set for every participant.',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(resolvePairEncryptionKeyCommand);
        request.writeU16(participantCount);
        request.writeFixed(expectedProposalIdentity);
        request.writeFixed(expectedRosterIdentity);
        request.writeU16(senderPosition);
        request.writeU16(recipientPosition);
        for (const [position, body] of bodies.entries()) {
            requireExactConstructionBytes(
                body,
                actionKeySetBodyByteLength(participantCount),
                `bodies[${String(position)}]`,
            );
            request.writeBytes(body);
        }
        return executeConstructionCommand(kernel, request, (reader) => {
            const encryptionKey = reader.readFixed(pairEncryptionKeyByteLength);
            requireExactConstructionBytes(
                encryptionKey,
                pairEncryptionKeyByteLength,
                'pairEncryptionKey',
            );
            return Uint8Array.from(encryptionKey);
        });
    },
});
