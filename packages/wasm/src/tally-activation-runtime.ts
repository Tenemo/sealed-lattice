import { actionKeySetBodyByteLength } from './action-key-set-runtime.js';
import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import { actionSignatureCarrierByteLength } from './preparation-parent-runtime.js';
import {
    heldAffineEvaluationVectorByteLength,
    heldSubsetKeyVectorByteLength,
    localAffineConstantVectorByteLength,
    sourceCorrectionByteLength,
} from './source-runtime.js';

const planTallyActivationCommand = 27;
const generateTallyActivationChunkCommand = 28;
const advanceTallyActivationCommand = 29;
const identifyTallyActivationChunkCommand = 30;
const encodeTallyActivationManifestCommand = 31;
const encodeTallyActivationSignatureCarrierCommand = 32;
const verifyTallyActivationManifestCommand = 33;
const completionProfileParticipantCount = 10;
const identityByteLength = 64;
const activationSeedByteLength = 32;
const maximumParticipantActivationChunkByteLength = 480_000;

export type ActivationChunkRange = Readonly<{
    firstOperation: number;
    operationEnd: number;
    includesTerminalRekey: boolean;
}>;

type TallyActivationPlan = Readonly<{
    operationCount: number;
    conjunctionCount: number;
    outputBitCount: number;
    ranges: readonly ActivationChunkRange[];
}>;

export type ActivationChunkDescriptor = ActivationChunkRange &
    Readonly<{
        byteLength: number;
        identity: Uint8Array;
    }>;

type EncodedActivationManifest = Readonly<{
    body: Uint8Array;
    identity: Uint8Array;
}>;

export type SignedActivationManifest = Readonly<{
    body: Uint8Array;
    signature: Uint8Array;
}>;

type VerifiedActivationManifest = Readonly<{
    targetIdentity: Uint8Array;
    topCount: number;
    sourceSubmissionBitmap: number;
    participantPosition: number;
    chunks: readonly ActivationChunkDescriptor[];
}>;

type TallyActivationContext = Readonly<{
    targetIdentity: Uint8Array;
    topCount: number;
    sourceSubmissionBitmap: number;
    sourceCorrections: readonly (Uint8Array | undefined)[];
}>;

type LocalTallyActivationMaterial = Readonly<{
    participantPosition: number;
    activationSeed: Uint8Array;
    heldSubsetKeys: Uint8Array;
    heldAffineEvaluations: Uint8Array;
    localAffineConstants: Uint8Array;
}>;

type TallyActivationAdvance =
    | Readonly<{ kind: 'pending'; checkpoint: Uint8Array }>
    | Readonly<{
          kind: 'no-result';
          acceptedBallotAuthorshipBitmap: number;
      }>
    | Readonly<{
          kind: 'result';
          acceptedBallotAuthorshipBitmap: number;
          orderedOptionPositions: readonly number[];
      }>;

type TallyActivationRuntime = Readonly<{
    plan(topCount: number): TallyActivationPlan;
    generateChunk(
        context: TallyActivationContext,
        material: LocalTallyActivationMaterial,
        range: ActivationChunkRange,
    ): Uint8Array;
    identifyChunk(chunk: Uint8Array): Uint8Array;
    encodeManifest(
        context: TallyActivationContext,
        participantPosition: number,
        chunks: readonly ActivationChunkDescriptor[],
    ): EncodedActivationManifest;
    encodeSignature(
        participantPosition: number,
        bodyIdentity: Uint8Array,
        signature: Uint8Array,
    ): Uint8Array;
    verifyManifest(
        actionKeySetBodies: readonly Uint8Array[],
        body: Uint8Array,
        signature: Uint8Array,
    ): VerifiedActivationManifest;
    advance(
        context: TallyActivationContext,
        checkpoint: Uint8Array | undefined,
        range: ActivationChunkRange,
        actionKeySetBodies: readonly Uint8Array[],
        manifests: readonly SignedActivationManifest[],
        chunks: readonly Uint8Array[],
    ): TallyActivationAdvance;
}>;

const requireUnsigned16 = (value: number, name: string): void => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff) {
        throw new RangeError(`${name} must be an unsigned 16-bit integer.`);
    }
};

const requireUnsigned32 = (value: number, name: string): void => {
    if (!Number.isSafeInteger(value) || value < 0 || value > 0xffff_ffff) {
        throw new RangeError(`${name} must be an unsigned 32-bit integer.`);
    }
};

const validateTopCount = (topCount: number): void => {
    requireUnsigned16(topCount, 'topCount');
    if (topCount < 1 || topCount > 10) {
        throw new RangeError(
            'topCount must be in the completion range 1..=10.',
        );
    }
};

const validateContext = (context: TallyActivationContext): void => {
    requireExactConstructionBytes(
        context.targetIdentity,
        identityByteLength,
        'targetIdentity',
    );
    validateTopCount(context.topCount);
    requireUnsigned16(context.sourceSubmissionBitmap, 'sourceSubmissionBitmap');
    if (
        context.sourceSubmissionBitmap === 0 ||
        context.sourceSubmissionBitmap >=
            1 << completionProfileParticipantCount ||
        context.sourceCorrections.length !== completionProfileParticipantCount
    ) {
        throw new RangeError(
            'The activation context must contain one nonempty completion-profile source inventory.',
        );
    }
    for (const [position, correction] of context.sourceCorrections.entries()) {
        const isSubmitted =
            (context.sourceSubmissionBitmap & (1 << position)) !== 0;
        if (isSubmitted !== (correction !== undefined)) {
            throw new RangeError(
                'The source corrections do not match the finalized submission bitmap.',
            );
        }
        if (correction !== undefined) {
            requireExactConstructionBytes(
                correction,
                sourceCorrectionByteLength,
                'sourceCorrection',
            );
        }
    }
};

const validateRange = (range: ActivationChunkRange): void => {
    requireUnsigned32(range.firstOperation, 'firstOperation');
    requireUnsigned32(range.operationEnd, 'operationEnd');
    if (range.firstOperation > range.operationEnd) {
        throw new RangeError('The activation chunk range is reversed.');
    }
};

const writeContext = (
    writer: ConstructionCommandWriter,
    context: TallyActivationContext,
): void => {
    validateContext(context);
    writer.writeFixed(context.targetIdentity);
    writer.writeU16(context.topCount);
    writer.writeU16(context.sourceSubmissionBitmap);
    for (const correction of context.sourceCorrections) {
        writer.writeU8(correction === undefined ? 0 : 1);
        writer.writeFixed(
            correction ?? new Uint8Array(sourceCorrectionByteLength),
        );
    }
};

const writeRange = (
    writer: ConstructionCommandWriter,
    range: ActivationChunkRange,
): void => {
    validateRange(range);
    writer.writeU32(range.firstOperation);
    writer.writeU32(range.operationEnd);
    writer.writeU8(range.includesTerminalRekey ? 1 : 0);
};

const writeDescriptor = (
    writer: ConstructionCommandWriter,
    descriptor: ActivationChunkDescriptor,
): void => {
    writeRange(writer, descriptor);
    requireUnsigned32(descriptor.byteLength, 'activationChunkByteLength');
    requireExactConstructionBytes(
        descriptor.identity,
        identityByteLength,
        'activationChunkIdentity',
    );
    writer.writeU32(descriptor.byteLength);
    writer.writeFixed(descriptor.identity);
};

const readDescriptor = (reader: {
    readU8(): number;
    readU32(): number;
    readFixed(length: number): Uint8Array;
}): ActivationChunkDescriptor => ({
    firstOperation: reader.readU32(),
    operationEnd: reader.readU32(),
    includesTerminalRekey: reader.readU8() === 1,
    byteLength: reader.readU32(),
    identity: Uint8Array.from(reader.readFixed(identityByteLength)),
});

export const openTallyActivationRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): TallyActivationRuntime => ({
    plan: (topCount) => {
        validateTopCount(topCount);
        const request = new ConstructionCommandWriter();
        request.writeU8(planTallyActivationCommand);
        request.writeU16(topCount);
        return executeConstructionCommand(kernel, request, (reader) => {
            const operationCount = reader.readU32();
            const conjunctionCount = reader.readU32();
            const outputBitCount = reader.readU16();
            const rangeCount = reader.readU16();
            const ranges = Array.from({ length: rangeCount }, () => ({
                firstOperation: reader.readU32(),
                operationEnd: reader.readU32(),
                includesTerminalRekey: reader.readU8() === 1,
            }));
            const lastRange = ranges[ranges.length - 1];
            if (
                ranges.length === 0 ||
                ranges[0]?.firstOperation !== 0 ||
                lastRange?.operationEnd !== operationCount ||
                !lastRange.includesTerminalRekey ||
                ranges.some(
                    (range, index) =>
                        range.firstOperation > range.operationEnd ||
                        (index > 0 &&
                            ranges[index - 1]?.operationEnd !==
                                range.firstOperation),
                ) ||
                outputBitCount !== 11 + 4 * topCount
            ) {
                throw new Error(
                    'The construction kernel returned an inconsistent activation plan.',
                );
            }
            return {
                operationCount,
                conjunctionCount,
                outputBitCount,
                ranges,
            };
        });
    },
    generateChunk: (context, material, range) => {
        requireUnsigned16(material.participantPosition, 'participantPosition');
        if (material.participantPosition >= completionProfileParticipantCount) {
            throw new RangeError(
                'participantPosition is not a completion-profile position.',
            );
        }
        requireExactConstructionBytes(
            material.activationSeed,
            activationSeedByteLength,
            'activationSeed',
        );
        requireExactConstructionBytes(
            material.heldSubsetKeys,
            heldSubsetKeyVectorByteLength,
            'heldSubsetKeys',
        );
        requireExactConstructionBytes(
            material.heldAffineEvaluations,
            heldAffineEvaluationVectorByteLength,
            'heldAffineEvaluations',
        );
        requireExactConstructionBytes(
            material.localAffineConstants,
            localAffineConstantVectorByteLength,
            'localAffineConstants',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(generateTallyActivationChunkCommand);
        writeContext(request, context);
        request.writeU16(material.participantPosition);
        request.writeFixed(material.activationSeed);
        request.writeBytes(material.heldSubsetKeys);
        request.writeBytes(material.heldAffineEvaluations);
        request.writeFixed(material.localAffineConstants);
        writeRange(request, range);
        return executeConstructionCommand(kernel, request, (reader) => {
            const chunk = Uint8Array.from(reader.readBytes());
            if (
                chunk.byteLength === 0 ||
                chunk.byteLength > maximumParticipantActivationChunkByteLength
            ) {
                throw new Error(
                    'The construction kernel returned an invalid activation chunk length.',
                );
            }
            return chunk;
        });
    },
    identifyChunk: (chunk) => {
        if (
            !(chunk instanceof Uint8Array) ||
            chunk.byteLength === 0 ||
            chunk.byteLength > maximumParticipantActivationChunkByteLength
        ) {
            throw new TypeError(
                'chunk must be a bounded nonempty activation chunk.',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(identifyTallyActivationChunkCommand);
        request.writeBytes(chunk);
        return executeConstructionCommand(kernel, request, (reader) =>
            Uint8Array.from(reader.readFixed(identityByteLength)),
        );
    },
    encodeManifest: (context, participantPosition, chunks) => {
        requireUnsigned16(participantPosition, 'participantPosition');
        if (participantPosition >= completionProfileParticipantCount) {
            throw new RangeError(
                'participantPosition is not a completion-profile position.',
            );
        }
        requireUnsigned16(chunks.length, 'activationChunkCount');
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeTallyActivationManifestCommand);
        writeContext(request, context);
        request.writeU16(participantPosition);
        request.writeU16(chunks.length);
        for (const chunk of chunks) {
            writeDescriptor(request, chunk);
        }
        return executeConstructionCommand(kernel, request, (reader) => ({
            body: Uint8Array.from(reader.readBytes()),
            identity: Uint8Array.from(reader.readFixed(identityByteLength)),
        }));
    },
    encodeSignature: (participantPosition, bodyIdentity, signature) => {
        requireUnsigned16(participantPosition, 'participantPosition');
        if (participantPosition >= completionProfileParticipantCount) {
            throw new RangeError(
                'participantPosition is not a completion-profile position.',
            );
        }
        requireExactConstructionBytes(
            bodyIdentity,
            identityByteLength,
            'activationManifestIdentity',
        );
        requireExactConstructionBytes(signature, 6_288, 'actionSignature');
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeTallyActivationSignatureCarrierCommand);
        request.writeU16(participantPosition);
        request.writeFixed(bodyIdentity);
        request.writeBytes(signature);
        return executeConstructionCommand(kernel, request, (reader) => {
            const carrier = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                carrier,
                actionSignatureCarrierByteLength,
                'activationSignatureCarrier',
            );
            return carrier;
        });
    },
    verifyManifest: (actionKeySetBodies, body, signature) => {
        if (actionKeySetBodies.length !== completionProfileParticipantCount) {
            throw new RangeError(
                'actionKeySetBodies must contain the complete roster.',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(verifyTallyActivationManifestCommand);
        for (const keySetBody of actionKeySetBodies) {
            requireExactConstructionBytes(
                keySetBody,
                actionKeySetBodyByteLength(completionProfileParticipantCount),
                'actionKeySetBody',
            );
            request.writeBytes(keySetBody);
        }
        request.writeBytes(body);
        requireExactConstructionBytes(
            signature,
            actionSignatureCarrierByteLength,
            'activationSignatureCarrier',
        );
        request.writeBytes(signature);
        return executeConstructionCommand(kernel, request, (reader) => {
            const targetIdentity = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            const topCount = reader.readU16();
            const sourceSubmissionBitmap = reader.readU16();
            const participantPosition = reader.readU16();
            const chunkCount = reader.readU16();
            const chunks = Array.from({ length: chunkCount }, () =>
                readDescriptor(reader),
            );
            return {
                targetIdentity,
                topCount,
                sourceSubmissionBitmap,
                participantPosition,
                chunks,
            };
        });
    },
    advance: (
        context,
        checkpoint,
        range,
        actionKeySetBodies,
        manifests,
        chunks,
    ) => {
        if (
            chunks.length !== completionProfileParticipantCount ||
            manifests.length !== completionProfileParticipantCount ||
            actionKeySetBodies.length !== completionProfileParticipantCount
        ) {
            throw new RangeError(
                'The activation advance must contain the complete key, manifest, and chunk rosters.',
            );
        }
        for (const chunk of chunks) {
            if (
                !(chunk instanceof Uint8Array) ||
                chunk.byteLength === 0 ||
                chunk.byteLength > maximumParticipantActivationChunkByteLength
            ) {
                throw new TypeError(
                    'Every activation chunk must be a bounded nonempty Uint8Array.',
                );
            }
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(advanceTallyActivationCommand);
        writeContext(request, context);
        request.writeBytes(checkpoint ?? new Uint8Array());
        writeRange(request, range);
        for (const keySetBody of actionKeySetBodies) {
            requireExactConstructionBytes(
                keySetBody,
                actionKeySetBodyByteLength(completionProfileParticipantCount),
                'actionKeySetBody',
            );
            request.writeBytes(keySetBody);
        }
        for (const manifest of manifests) {
            requireExactConstructionBytes(
                manifest.signature,
                actionSignatureCarrierByteLength,
                'activationSignatureCarrier',
            );
            request.writeBytes(manifest.body);
            request.writeBytes(manifest.signature);
        }
        for (const chunk of chunks) {
            request.writeBytes(chunk);
        }
        return executeConstructionCommand(kernel, request, (reader) => {
            const status = reader.readU8();
            if (status === 1) {
                const nextCheckpoint = Uint8Array.from(reader.readBytes());
                if (nextCheckpoint.byteLength === 0) {
                    throw new Error(
                        'The construction kernel returned an empty activation checkpoint.',
                    );
                }
                return { kind: 'pending' as const, checkpoint: nextCheckpoint };
            }
            const acceptedBallotAuthorshipBitmap = reader.readU16();
            if (
                acceptedBallotAuthorshipBitmap >=
                1 << completionProfileParticipantCount
            ) {
                throw new Error(
                    'The construction kernel returned an invalid authorship bitmap.',
                );
            }
            if (status === 2) {
                return {
                    kind: 'no-result' as const,
                    acceptedBallotAuthorshipBitmap,
                };
            }
            if (status === 3) {
                const resultCount = reader.readU16();
                const orderedOptionPositions = Array.from(
                    { length: resultCount },
                    () => reader.readU16(),
                );
                if (
                    resultCount !== context.topCount ||
                    new Set(orderedOptionPositions).size !== resultCount ||
                    orderedOptionPositions.some((position) => position >= 10)
                ) {
                    throw new Error(
                        'The construction kernel returned an invalid ordered result.',
                    );
                }
                return {
                    kind: 'result' as const,
                    acceptedBallotAuthorshipBitmap,
                    orderedOptionPositions,
                };
            }
            throw new Error(
                'The construction kernel returned an invalid activation status.',
            );
        });
    },
});
