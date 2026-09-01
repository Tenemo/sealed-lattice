import { actionKeySetBodyByteLength } from './action-key-set-runtime.js';
import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import {
    preparationAffineCoefficientByteLength,
    preparationContributionOpeningVectorByteLength,
    preparationPlaintextByteLength,
} from './preparation-material-runtime.js';
import { actionSignatureCarrierByteLength } from './preparation-parent-runtime.js';

const verifyCompletePreparationCommand = 18;
const deriveHonestSourceCorrectionCommand = 19;
const encodeSourceBodyCommand = 20;
const encodeSourceSignatureCarrierCommand = 21;
const verifySourceCarrierCommand = 22;

const completionProfileParticipantCount = 10;
const preparationParentBodyByteLength = 8_502;
export const heldSubsetKeyVectorByteLength = 3_840;
export const preparationParentIdentityVectorByteLength = 640;
export const abstentionSourceBodyByteLength = 326;
export const submittedSourceBodyByteLength = 333;
const identityByteLength = 64;

export type SourceDeclaration = 'abstain' | 'submit';

export type SourcePreparationContext = Readonly<{
    participantCount: number;
    actionProposalIdentity: Uint8Array;
    actionKeySetRosterIdentity: Uint8Array;
    preparationAttempt: number;
    predecessorIdentity: Uint8Array;
}>;

export type SourceContext = SourcePreparationContext &
    Readonly<{
        verifiedPreparationRoot: Uint8Array;
        senderPosition: number;
    }>;

export type PreparationParentCarrier = Readonly<{
    body: Uint8Array;
    signature: Uint8Array;
}>;

export type VerifiedCompletePreparation = Readonly<{
    root: Uint8Array;
    parentIdentities: Uint8Array;
    heldSubsetKeys: Uint8Array;
}>;

export type EncodedSourceBody = Readonly<{
    body: Uint8Array;
    identity: Uint8Array;
}>;

export type VerifiedSource = Readonly<{
    senderPosition: number;
    declaration: SourceDeclaration;
    correction: number | undefined;
    bodyIdentity: Uint8Array;
    verifiedPreparationRoot: Uint8Array;
}>;

export type SourceRuntime = Readonly<{
    verifyCompletePreparation(
        context: SourcePreparationContext,
        localPosition: number,
        actionKeySetBodies: readonly Uint8Array[],
        preparationParents: readonly PreparationParentCarrier[],
        ownContributionOpenings: Uint8Array,
        ownAffineCoefficients: Uint8Array,
        remotePlaintexts: readonly Uint8Array[],
    ): VerifiedCompletePreparation;
    deriveHonestCorrection(
        sourcePosition: number,
        inputBit: number,
        heldSubsetKeys: Uint8Array,
    ): number;
    encodeBody(
        context: SourceContext,
        declaration: SourceDeclaration,
        correction?: number,
    ): EncodedSourceBody;
    encodeSignature(
        signerPosition: number,
        bodyIdentity: Uint8Array,
        signature: Uint8Array,
    ): Uint8Array;
    verify(
        context: SourceContext,
        expectedDeclaration: SourceDeclaration,
        actionKeySetBodies: readonly Uint8Array[],
        body: Uint8Array,
        signature: Uint8Array,
    ): VerifiedSource;
}>;

const requireUnsigned16 = (value: number, name: string): void => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new RangeError(`${name} must be an unsigned 16-bit integer.`);
    }
};

const requirePosition = (position: number, name: string): void => {
    requireUnsigned16(position, name);
    if (position >= completionProfileParticipantCount) {
        throw new RangeError(`${name} is not a completion-profile position.`);
    }
};

const declarationCode = (declaration: SourceDeclaration): number => {
    switch (declaration) {
        case 'abstain':
            return 1;
        case 'submit':
            return 2;
    }
};

const declarationFromCode = (value: number): SourceDeclaration => {
    switch (value) {
        case 1:
            return 'abstain';
        case 2:
            return 'submit';
        default:
            throw new Error(
                'The construction kernel returned an invalid source declaration.',
            );
    }
};

const validatePreparationContext = (
    context: SourcePreparationContext,
): void => {
    if (context.participantCount !== completionProfileParticipantCount) {
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
};

const writePreparationContext = (
    request: ConstructionCommandWriter,
    context: SourcePreparationContext,
): void => {
    validatePreparationContext(context);
    request.writeFixed(context.actionProposalIdentity);
    request.writeFixed(context.actionKeySetRosterIdentity);
    request.writeU16(context.preparationAttempt);
    request.writeFixed(context.predecessorIdentity);
};

const validateActionKeySetBodies = (
    actionKeySetBodies: readonly Uint8Array[],
): void => {
    if (actionKeySetBodies.length !== completionProfileParticipantCount) {
        throw new RangeError(
            'actionKeySetBodies must contain the complete roster.',
        );
    }
    for (const body of actionKeySetBodies) {
        requireExactConstructionBytes(
            body,
            actionKeySetBodyByteLength(completionProfileParticipantCount),
            'actionKeySetBody',
        );
    }
};

export const openSourceRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): SourceRuntime => ({
    verifyCompletePreparation: (
        context,
        localPosition,
        actionKeySetBodies,
        preparationParents,
        ownContributionOpenings,
        ownAffineCoefficients,
        remotePlaintexts,
    ) => {
        validatePreparationContext(context);
        requirePosition(localPosition, 'localPosition');
        validateActionKeySetBodies(actionKeySetBodies);
        if (preparationParents.length !== completionProfileParticipantCount) {
            throw new RangeError(
                'preparationParents must contain one carrier per roster position.',
            );
        }
        for (const parent of preparationParents) {
            requireExactConstructionBytes(
                parent.body,
                preparationParentBodyByteLength,
                'preparationParentBody',
            );
            requireExactConstructionBytes(
                parent.signature,
                actionSignatureCarrierByteLength,
                'preparationParentSignature',
            );
        }
        requireExactConstructionBytes(
            ownContributionOpenings,
            preparationContributionOpeningVectorByteLength,
            'ownContributionOpenings',
        );
        requireExactConstructionBytes(
            ownAffineCoefficients,
            preparationAffineCoefficientByteLength,
            'ownAffineCoefficients',
        );
        if (remotePlaintexts.length !== completionProfileParticipantCount - 1) {
            throw new RangeError(
                'remotePlaintexts must contain every remote sender in roster order.',
            );
        }
        for (const plaintext of remotePlaintexts) {
            requireExactConstructionBytes(
                plaintext,
                preparationPlaintextByteLength,
                'remotePlaintext',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyCompletePreparationCommand);
        request.writeU16(context.participantCount);
        writePreparationContext(request, context);
        request.writeU16(localPosition);
        for (const body of actionKeySetBodies) {
            request.writeBytes(body);
        }
        for (const parent of preparationParents) {
            request.writeBytes(parent.body);
            request.writeBytes(parent.signature);
        }
        request.writeBytes(ownContributionOpenings);
        request.writeBytes(ownAffineCoefficients);
        for (const plaintext of remotePlaintexts) {
            request.writeBytes(plaintext);
        }
        return executeConstructionCommand(kernel, request, (reader) => {
            const root = Uint8Array.from(reader.readFixed(identityByteLength));
            const parentIdentities = Uint8Array.from(
                reader.readFixed(preparationParentIdentityVectorByteLength),
            );
            const heldSubsetKeys = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                heldSubsetKeys,
                heldSubsetKeyVectorByteLength,
                'heldSubsetKeys',
            );
            return { root, parentIdentities, heldSubsetKeys };
        });
    },
    deriveHonestCorrection: (sourcePosition, inputBit, heldSubsetKeys) => {
        requirePosition(sourcePosition, 'sourcePosition');
        if (inputBit !== 0 && inputBit !== 1) {
            throw new RangeError('inputBit must be zero or one.');
        }
        requireExactConstructionBytes(
            heldSubsetKeys,
            heldSubsetKeyVectorByteLength,
            'heldSubsetKeys',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(deriveHonestSourceCorrectionCommand);
        request.writeU16(sourcePosition);
        request.writeU8(inputBit);
        request.writeBytes(heldSubsetKeys);
        return executeConstructionCommand(kernel, request, (reader) => {
            const correction = reader.readU8();
            if (correction > 0b11) {
                throw new Error(
                    'The construction kernel returned a noncanonical source correction.',
                );
            }
            return correction;
        });
    },
    encodeBody: (context, declaration, correction) => {
        validatePreparationContext(context);
        requireExactConstructionBytes(
            context.verifiedPreparationRoot,
            identityByteLength,
            'verifiedPreparationRoot',
        );
        requirePosition(context.senderPosition, 'senderPosition');
        if (
            (declaration === 'abstain' && correction !== undefined) ||
            (declaration === 'submit' &&
                (!Number.isSafeInteger(correction) ||
                    correction === undefined ||
                    correction < 0 ||
                    correction > 0b11))
        ) {
            throw new RangeError(
                'The source declaration and correction are inconsistent.',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeSourceBodyCommand);
        request.writeU16(context.participantCount);
        writePreparationContext(request, context);
        request.writeFixed(context.verifiedPreparationRoot);
        request.writeU16(context.senderPosition);
        request.writeU16(declarationCode(declaration));
        request.writeBytes(
            correction === undefined
                ? new Uint8Array()
                : Uint8Array.of(correction),
        );
        return executeConstructionCommand(kernel, request, (reader) => {
            const body = Uint8Array.from(reader.readBytes());
            const expectedLength =
                declaration === 'submit'
                    ? submittedSourceBodyByteLength
                    : abstentionSourceBodyByteLength;
            requireExactConstructionBytes(body, expectedLength, 'sourceBody');
            const identity = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            return { body, identity };
        });
    },
    encodeSignature: (signerPosition, bodyIdentity, signature) => {
        requirePosition(signerPosition, 'signerPosition');
        requireExactConstructionBytes(
            bodyIdentity,
            identityByteLength,
            'bodyIdentity',
        );
        requireExactConstructionBytes(signature, 6_288, 'actionSignature');
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeSourceSignatureCarrierCommand);
        request.writeU16(completionProfileParticipantCount);
        request.writeU16(signerPosition);
        request.writeFixed(bodyIdentity);
        request.writeBytes(signature);
        return executeConstructionCommand(kernel, request, (reader) => {
            const carrier = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                carrier,
                actionSignatureCarrierByteLength,
                'sourceSignatureCarrier',
            );
            return carrier;
        });
    },
    verify: (
        context,
        expectedDeclaration,
        actionKeySetBodies,
        body,
        signature,
    ) => {
        validatePreparationContext(context);
        requireExactConstructionBytes(
            context.verifiedPreparationRoot,
            identityByteLength,
            'verifiedPreparationRoot',
        );
        requirePosition(context.senderPosition, 'senderPosition');
        validateActionKeySetBodies(actionKeySetBodies);
        requireExactConstructionBytes(
            body,
            expectedDeclaration === 'submit'
                ? submittedSourceBodyByteLength
                : abstentionSourceBodyByteLength,
            'sourceBody',
        );
        requireExactConstructionBytes(
            signature,
            actionSignatureCarrierByteLength,
            'sourceSignatureCarrier',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(verifySourceCarrierCommand);
        request.writeU16(context.participantCount);
        writePreparationContext(request, context);
        request.writeFixed(context.verifiedPreparationRoot);
        request.writeU16(context.senderPosition);
        request.writeU16(declarationCode(expectedDeclaration));
        for (const keySetBody of actionKeySetBodies) {
            request.writeBytes(keySetBody);
        }
        request.writeBytes(body);
        request.writeBytes(signature);
        return executeConstructionCommand(kernel, request, (reader) => {
            const senderPosition = reader.readU16();
            const declaration = declarationFromCode(reader.readU16());
            const correctionByte = reader.readU8();
            const correction =
                correctionByte === 0xff ? undefined : correctionByte;
            if (
                senderPosition !== context.senderPosition ||
                declaration !== expectedDeclaration ||
                (declaration === 'submit' &&
                    (correction === undefined || correction > 0b11)) ||
                (declaration === 'abstain' && correction !== undefined)
            ) {
                throw new Error(
                    'The construction kernel returned inconsistent source metadata.',
                );
            }
            return {
                senderPosition,
                declaration,
                correction,
                bodyIdentity: Uint8Array.from(
                    reader.readFixed(identityByteLength),
                ),
                verifiedPreparationRoot: Uint8Array.from(
                    reader.readFixed(identityByteLength),
                ),
            };
        });
    },
});
