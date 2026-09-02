import { actionSignatureByteLength } from './action-signature-runtime.js';
import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import { actionSignatureCarrierByteLength } from './preparation-parent-runtime.js';
import { completionRosterByteLength } from './roster-runtime.js';
import {
    abstentionSourceBodyByteLength,
    submittedSourceBodyByteLength,
    type SourceDeclaration,
} from './source-runtime.js';

const deriveFinalityTargetCommand = 23;
const encodeFinalitySignatureCarrierCommand = 24;
const verifyFinalityCertificateCommand = 25;
const verifyFinalitySignatureCommand = 26;
const completionProfileParticipantCount = 10;
const identityByteLength = 64;

export const finalityTargetBodyByteLength = 1_058;
export const sourceBodyIdentityVectorByteLength = 640;
export const completionProfileFinalityQuorum = 8;

type FinalityTargetKind = 'computation' | 'no-result';

type FinalityDerivationContext = Readonly<{
    participantCount: number;
    runtimeIdentity: Uint8Array;
    candidateBuildIdentity: Uint8Array;
    actionProposalIdentity: Uint8Array;
    actionDefinitionIdentity: Uint8Array;
    rosterIdentity: Uint8Array;
    preparationAttempt: number;
    predecessorIdentity: Uint8Array;
    verifiedPreparationRoot: Uint8Array;
    topCount: number;
}>;

export type SourceCarrier = Readonly<{
    declaration: SourceDeclaration;
    body: Uint8Array;
    signature: Uint8Array;
}>;

type DerivedFinalityTarget = Readonly<{
    targetBody: Uint8Array;
    targetIdentity: Uint8Array;
    sourceInventoryRoot: Uint8Array;
    sourceBodyIdentities: Uint8Array;
    sourceSubmissionBitmap: number;
    topCount: number;
    targetKind: FinalityTargetKind;
    quorum: number;
}>;

export type FinalitySignatureCarrier = Readonly<{
    signerPosition: number;
    signature: Uint8Array;
}>;

const verifiedFinalityCapabilityBrand: unique symbol = Symbol(
    'verified-finality-capability',
);

type VerifiedFinalityCapability = Readonly<{
    [verifiedFinalityCapabilityBrand]: true;
    quorum: number;
    targetKind: FinalityTargetKind;
    sourceSubmissionBitmap: number;
    topCount: number;
    targetIdentity: Uint8Array;
}>;

type FinalityRuntime = Readonly<{
    deriveTarget(
        context: FinalityDerivationContext,
        canonicalRosterBytes: Uint8Array,
        sources: readonly SourceCarrier[],
    ): DerivedFinalityTarget;
    encodeSignature(
        signerPosition: number,
        targetIdentity: Uint8Array,
        signature: Uint8Array,
    ): Uint8Array;
    verifyCertificate(
        targetBody: Uint8Array,
        canonicalRosterBytes: Uint8Array,
        signatures: readonly FinalitySignatureCarrier[],
    ): VerifiedFinalityCapability;
    verifySignature(
        signerPosition: number,
        targetBody: Uint8Array,
        canonicalRosterBytes: Uint8Array,
        signature: Uint8Array,
    ): void;
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

const targetKindFromCode = (value: number): FinalityTargetKind => {
    switch (value) {
        case 1:
            return 'computation';
        case 2:
            return 'no-result';
        default:
            throw new Error(
                'The construction kernel returned an invalid finality target kind.',
            );
    }
};

const validateRoster = (canonicalRosterBytes: Uint8Array): void =>
    requireExactConstructionBytes(
        canonicalRosterBytes,
        completionRosterByteLength,
        'canonicalRosterBytes',
    );

const validateDerivationContext = (
    context: FinalityDerivationContext,
): void => {
    if (context.participantCount !== completionProfileParticipantCount) {
        throw new RangeError(
            'participantCount must select the completion profile.',
        );
    }
    requireExactConstructionBytes(
        context.runtimeIdentity,
        identityByteLength,
        'runtimeIdentity',
    );
    requireExactConstructionBytes(
        context.candidateBuildIdentity,
        identityByteLength,
        'candidateBuildIdentity',
    );
    requireExactConstructionBytes(
        context.actionProposalIdentity,
        identityByteLength,
        'actionProposalIdentity',
    );
    requireExactConstructionBytes(
        context.actionDefinitionIdentity,
        identityByteLength,
        'actionDefinitionIdentity',
    );
    requireExactConstructionBytes(
        context.rosterIdentity,
        identityByteLength,
        'rosterIdentity',
    );
    requireUnsigned16(context.preparationAttempt, 'preparationAttempt');
    requireExactConstructionBytes(
        context.predecessorIdentity,
        identityByteLength,
        'predecessorIdentity',
    );
    requireExactConstructionBytes(
        context.verifiedPreparationRoot,
        identityByteLength,
        'verifiedPreparationRoot',
    );
    requireUnsigned16(context.topCount, 'topCount');
    if (
        context.topCount === 0 ||
        context.topCount > completionProfileParticipantCount
    ) {
        throw new RangeError(
            'topCount must be admitted by the completion profile.',
        );
    }
};

export const openFinalityRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): FinalityRuntime => ({
    deriveTarget: (context, canonicalRosterBytes, sources) => {
        validateDerivationContext(context);
        validateRoster(canonicalRosterBytes);
        if (sources.length !== completionProfileParticipantCount) {
            throw new RangeError(
                'sources must contain one carrier per roster position.',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(deriveFinalityTargetCommand);
        request.writeU16(context.participantCount);
        request.writeFixed(context.runtimeIdentity);
        request.writeFixed(context.candidateBuildIdentity);
        request.writeFixed(context.actionProposalIdentity);
        request.writeFixed(context.actionDefinitionIdentity);
        request.writeFixed(context.rosterIdentity);
        request.writeU16(context.preparationAttempt);
        request.writeFixed(context.predecessorIdentity);
        request.writeFixed(context.verifiedPreparationRoot);
        request.writeU16(context.topCount);
        request.writeBytes(canonicalRosterBytes);
        for (const [position, source] of sources.entries()) {
            const expectedBodyByteLength =
                source.declaration === 'submit'
                    ? submittedSourceBodyByteLength
                    : abstentionSourceBodyByteLength;
            requireExactConstructionBytes(
                source.body,
                expectedBodyByteLength,
                `sources[${String(position)}].body`,
            );
            requireExactConstructionBytes(
                source.signature,
                actionSignatureCarrierByteLength,
                `sources[${String(position)}].signature`,
            );
            request.writeU16(declarationCode(source.declaration));
            request.writeBytes(source.body);
            request.writeBytes(source.signature);
        }
        return executeConstructionCommand(kernel, request, (reader) => {
            const targetBody = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                targetBody,
                finalityTargetBodyByteLength,
                'finalityTargetBody',
            );
            const targetIdentity = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            const sourceInventoryRoot = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            const sourceBodyIdentities = Uint8Array.from(
                reader.readFixed(sourceBodyIdentityVectorByteLength),
            );
            const sourceSubmissionBitmap = reader.readU16();
            const topCount = reader.readU16();
            const targetKind = targetKindFromCode(reader.readU16());
            const quorum = reader.readU16();
            if (
                quorum !== completionProfileFinalityQuorum ||
                topCount !== context.topCount ||
                (targetKind === 'no-result' && sourceSubmissionBitmap !== 0) ||
                (targetKind === 'computation' &&
                    sourceSubmissionBitmap === 0) ||
                sourceSubmissionBitmap >= 1 << completionProfileParticipantCount
            ) {
                throw new Error(
                    'The construction kernel returned inconsistent finality metadata.',
                );
            }
            return {
                targetBody,
                targetIdentity,
                sourceInventoryRoot,
                sourceBodyIdentities,
                sourceSubmissionBitmap,
                topCount,
                targetKind,
                quorum,
            };
        });
    },
    encodeSignature: (signerPosition, targetIdentity, signature) => {
        requirePosition(signerPosition, 'signerPosition');
        requireExactConstructionBytes(
            targetIdentity,
            identityByteLength,
            'targetIdentity',
        );
        requireExactConstructionBytes(
            signature,
            actionSignatureByteLength,
            'actionSignature',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeFinalitySignatureCarrierCommand);
        request.writeU16(completionProfileParticipantCount);
        request.writeU16(signerPosition);
        request.writeFixed(targetIdentity);
        request.writeBytes(signature);
        return executeConstructionCommand(kernel, request, (reader) => {
            const carrier = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                carrier,
                actionSignatureCarrierByteLength,
                'finalitySignatureCarrier',
            );
            return carrier;
        });
    },
    verifyCertificate: (targetBody, canonicalRosterBytes, signatures) => {
        requireExactConstructionBytes(
            targetBody,
            finalityTargetBodyByteLength,
            'finalityTargetBody',
        );
        validateRoster(canonicalRosterBytes);
        if (
            signatures.length < completionProfileFinalityQuorum ||
            signatures.length > completionProfileParticipantCount
        ) {
            throw new RangeError(
                'signatures must contain one completion-profile finality quorum.',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyFinalityCertificateCommand);
        request.writeU16(completionProfileParticipantCount);
        request.writeBytes(targetBody);
        request.writeBytes(canonicalRosterBytes);
        request.writeU16(signatures.length);
        for (const entry of signatures) {
            requirePosition(entry.signerPosition, 'signerPosition');
            requireExactConstructionBytes(
                entry.signature,
                actionSignatureCarrierByteLength,
                'finalitySignatureCarrier',
            );
            request.writeU16(entry.signerPosition);
            request.writeBytes(entry.signature);
        }
        return executeConstructionCommand(kernel, request, (reader) => {
            const quorum = reader.readU16();
            const targetKind = targetKindFromCode(reader.readU16());
            const sourceSubmissionBitmap = reader.readU16();
            const topCount = reader.readU16();
            const targetIdentity = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            if (
                quorum !== completionProfileFinalityQuorum ||
                sourceSubmissionBitmap >=
                    1 << completionProfileParticipantCount ||
                topCount === 0 ||
                topCount > completionProfileParticipantCount ||
                (targetKind === 'no-result' && sourceSubmissionBitmap !== 0) ||
                (targetKind === 'computation' && sourceSubmissionBitmap === 0)
            ) {
                throw new Error(
                    'The construction kernel returned inconsistent certificate metadata.',
                );
            }
            return {
                [verifiedFinalityCapabilityBrand]: true,
                quorum,
                targetKind,
                sourceSubmissionBitmap,
                topCount,
                targetIdentity,
            };
        });
    },
    verifySignature: (
        signerPosition,
        targetBody,
        canonicalRosterBytes,
        signature,
    ) => {
        requirePosition(signerPosition, 'signerPosition');
        requireExactConstructionBytes(
            targetBody,
            finalityTargetBodyByteLength,
            'finalityTargetBody',
        );
        validateRoster(canonicalRosterBytes);
        requireExactConstructionBytes(
            signature,
            actionSignatureCarrierByteLength,
            'finalitySignatureCarrier',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyFinalitySignatureCommand);
        request.writeU16(completionProfileParticipantCount);
        request.writeU16(signerPosition);
        request.writeBytes(targetBody);
        request.writeBytes(canonicalRosterBytes);
        request.writeBytes(signature);
        executeConstructionCommand(kernel, request, () => undefined);
    },
});
