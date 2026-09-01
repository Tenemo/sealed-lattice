import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';

const generatePreparationMaterialCommand = 15;
const verifyPreparationPlaintextCommand = 16;
const completionProfileParticipantCount = 10;
const identityByteLength = 64;
const preparationParentBodyByteLength = 8_502;

const preparationContributionOpeningByteLength = 80;
const preparationContributionCount = 120;
export const preparationAffineModuleValueByteLength = 48;
export const preparationLowAffineCoefficientCount = 10;
export const preparationContributionOpeningVectorByteLength =
    preparationContributionOpeningByteLength * preparationContributionCount;
export const preparationAffineCoefficientByteLength = 672;
export const preparationPlaintextByteLength = 6_836;
export const preparationSubsetCommitmentVectorByteLength =
    preparationContributionCount * identityByteLength;

export type PreparationMaterialContextInput = Readonly<{
    participantCount: number;
    actionProposalIdentity: Uint8Array;
    actionKeySetRosterIdentity: Uint8Array;
    preparationAttempt: number;
    predecessorIdentity: Uint8Array;
    senderPosition: number;
}>;

export type GeneratedPreparationMaterial = Readonly<{
    subsetCommitments: Uint8Array;
    recipientPlaintexts: readonly Uint8Array[];
}>;

export type PreparationMaterialRuntime = Readonly<{
    generate(
        context: PreparationMaterialContextInput,
        contributionOpenings: Uint8Array,
        affineCoefficients: Uint8Array,
    ): GeneratedPreparationMaterial;
    verifyPlaintext(
        context: PreparationMaterialContextInput,
        recipientPosition: number,
        parentBody: Uint8Array,
        plaintext: Uint8Array,
    ): Uint8Array;
}>;

const requireUnsigned16 = (value: number, name: string): void => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new RangeError(`${name} must be an unsigned 16-bit integer.`);
    }
};

const validatePosition = (position: number, name: string): void => {
    requireUnsigned16(position, name);
    if (position >= completionProfileParticipantCount) {
        throw new RangeError(`${name} is not a completion-profile position.`);
    }
};

const validateContext = (context: PreparationMaterialContextInput): void => {
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
    validatePosition(context.senderPosition, 'senderPosition');
};

const writeContext = (
    request: ConstructionCommandWriter,
    context: PreparationMaterialContextInput,
): void => {
    validateContext(context);
    request.writeFixed(context.actionProposalIdentity);
    request.writeFixed(context.actionKeySetRosterIdentity);
    request.writeU16(context.preparationAttempt);
    request.writeFixed(context.predecessorIdentity);
    request.writeU16(context.senderPosition);
};

export const openPreparationMaterialRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): PreparationMaterialRuntime => ({
    generate: (context, contributionOpenings, affineCoefficients) => {
        requireExactConstructionBytes(
            contributionOpenings,
            preparationContributionOpeningVectorByteLength,
            'contributionOpenings',
        );
        requireExactConstructionBytes(
            affineCoefficients,
            preparationAffineCoefficientByteLength,
            'affineCoefficients',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(generatePreparationMaterialCommand);
        writeContext(request, context);
        request.writeBytes(contributionOpenings);
        request.writeBytes(affineCoefficients);
        return executeConstructionCommand(kernel, request, (reader) => {
            const subsetCommitments = Uint8Array.from(
                reader.readFixed(preparationSubsetCommitmentVectorByteLength),
            );
            const recipientPlaintexts = Array.from(
                { length: completionProfileParticipantCount - 1 },
                () => {
                    const plaintext = reader.readBytes();
                    requireExactConstructionBytes(
                        plaintext,
                        preparationPlaintextByteLength,
                        'recipientPlaintext',
                    );
                    return Uint8Array.from(plaintext);
                },
            );
            return { subsetCommitments, recipientPlaintexts };
        });
    },
    verifyPlaintext: (context, recipientPosition, parentBody, plaintext) => {
        validateContext(context);
        validatePosition(recipientPosition, 'recipientPosition');
        if (recipientPosition === context.senderPosition) {
            throw new RangeError(
                'recipientPosition must differ from senderPosition.',
            );
        }
        requireExactConstructionBytes(
            parentBody,
            preparationParentBodyByteLength,
            'parentBody',
        );
        requireExactConstructionBytes(
            plaintext,
            preparationPlaintextByteLength,
            'plaintext',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyPreparationPlaintextCommand);
        request.writeU16(context.participantCount);
        writeContext(request, context);
        request.writeU16(recipientPosition);
        request.writeBytes(parentBody);
        request.writeBytes(plaintext);
        return executeConstructionCommand(kernel, request, (reader) => {
            const identity = reader.readFixed(identityByteLength);
            requireExactConstructionBytes(
                identity,
                identityByteLength,
                'verifiedPlaintextIdentity',
            );
            return Uint8Array.from(identity);
        });
    },
});
