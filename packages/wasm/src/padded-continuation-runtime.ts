import { actionSignatureByteLength } from './action-signature-runtime.js';
import {
    ConstructionCommandWriter,
    executeConstructionCommand,
    requireExactConstructionBytes,
} from './construction-kernel-command-runtime.js';
import {
    completionProfileFinalityQuorum,
    finalityTargetBodyByteLength,
    type FinalitySignatureCarrier,
} from './finality-runtime.js';
import type { ConstructionKernelCommandRuntime } from './foundation-kernel/kernel-runtime.js';
import type { JointContinuationPlan } from './joint-continuation-runtime.js';
import {
    preparationContributionOpeningVectorByteLength,
    preparationPairwiseMasterVectorByteLength,
    preparationPlaintextByteLength,
} from './preparation-material-runtime.js';
import { actionSignatureCarrierByteLength } from './preparation-parent-runtime.js';
import { completionRosterByteLength } from './roster-runtime.js';

const generateParticipantCommand = 38;
const encodeActivationSignatureCommand = 39;
const evaluateBatchCommand = 40;

const completionProfileParticipantCount = 10;
const identityByteLength = 64;
export const paddedContinuationLabelByteLength = 40;
const labelByteLength = paddedContinuationLabelByteLength;
const moduleValueByteLength = 40;
const tokenByteLength = labelByteLength + 1;
export const paddedContinuationLabelPairEntropyByteLength =
    2 * labelByteLength + 1;
const tokenPairEntropyByteLength = paddedContinuationLabelPairEntropyByteLength;
export const paddedContinuationAllocationNonceByteLength = 32;
const fieldBitWidth = 4;
const localMultiplicationRowCount = 35 * 4;
const paddedTranslationRowCountPerGarbler =
    completionProfileParticipantCount * fieldBitWidth * 2;
const continuationRowByteLength = tokenByteLength + moduleValueByteLength;
const gatePayloadByteLength =
    localMultiplicationRowCount * tokenByteLength +
    fieldBitWidth * tokenByteLength +
    1 +
    paddedTranslationRowCountPerGarbler * moduleValueByteLength +
    2 * continuationRowByteLength +
    (fieldBitWidth - 1) * tokenByteLength;
const terminalPayloadByteLength =
    fieldBitWidth * 4 * tokenByteLength + fieldBitWidth * tokenByteLength + 1;
const preparationParentBodyByteLength = 8_502;
const chunkHeaderByteLength = 250;
export const paddedContinuationManifestByteLength = 254;

export const reviewedReducedPaddedContinuationPlan: JointContinuationPlan = {
    inputWireCount: 4,
    gates: [
        { leftWire: 0, rightWire: 1 },
        { leftWire: 2, rightWire: 3 },
        { leftWire: 4, rightWire: 2 },
        { leftWire: 4, rightWire: 3 },
        { leftWire: 6, rightWire: 7 },
        { leftWire: 5, rightWire: 0 },
        { leftWire: 8, rightWire: 9 },
    ],
    outputWires: [4, 7, 10],
};

type PaddedContinuationFinalityCertificate = Readonly<{
    targetBody: Uint8Array;
    canonicalRosterBytes: Uint8Array;
    signatures: readonly FinalitySignatureCarrier[];
}>;

type PaddedContinuationParticipantInput = Readonly<{
    participantPosition: number;
    initialWireValues: Uint8Array;
    gateMaskShares: Uint8Array;
    terminalMaskShares: Uint8Array;
    allocationNonce: Uint8Array;
    labelEntropy: Uint8Array;
    preparationParents: readonly Readonly<{
        body: Uint8Array;
        signature: Uint8Array;
    }>[];
    ownContributionOpenings: Uint8Array;
    ownPairwiseMasters: Uint8Array;
    remotePlaintexts: readonly Uint8Array[];
}>;

type GeneratedPaddedContinuationParticipant = Readonly<{
    chunk: Uint8Array;
    chunkIdentity: Uint8Array;
    manifest: Uint8Array;
    manifestIdentity: Uint8Array;
}>;

type EvaluatedPaddedContinuationBatch = Readonly<{
    batchIdentity: Uint8Array;
    terminalBits: readonly boolean[];
}>;

export type PaddedContinuationRuntime = Readonly<{
    generateParticipant(
        certificate: PaddedContinuationFinalityCertificate,
        plan: JointContinuationPlan,
        input: PaddedContinuationParticipantInput,
    ): GeneratedPaddedContinuationParticipant;
    encodeActivationSignature(
        participantPosition: number,
        manifestIdentity: Uint8Array,
        signature: Uint8Array,
    ): Uint8Array;
    evaluateBatch(
        certificate: PaddedContinuationFinalityCertificate,
        plan: JointContinuationPlan,
        manifests: readonly Uint8Array[],
        signatures: readonly Uint8Array[],
        chunks: readonly Uint8Array[],
    ): EvaluatedPaddedContinuationBatch;
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

const validateReviewedReducedPlan = (plan: JointContinuationPlan): void => {
    requireUnsigned16(plan.inputWireCount, 'inputWireCount');
    if (
        plan.inputWireCount !==
            reviewedReducedPaddedContinuationPlan.inputWireCount ||
        plan.gates.length !==
            reviewedReducedPaddedContinuationPlan.gates.length ||
        plan.outputWires.length !==
            reviewedReducedPaddedContinuationPlan.outputWires.length ||
        plan.gates.some((gate, index) => {
            const expected = reviewedReducedPaddedContinuationPlan.gates[index];
            return (
                expected === undefined ||
                gate.leftWire !== expected.leftWire ||
                gate.rightWire !== expected.rightWire
            );
        }) ||
        plan.outputWires.some(
            (wire, index) =>
                wire !==
                reviewedReducedPaddedContinuationPlan.outputWires[index],
        )
    ) {
        throw new RangeError(
            'Only the reviewed reduced padded-continuation plan is executable.',
        );
    }
};

const encodePlan = (plan: JointContinuationPlan): Uint8Array => {
    validateReviewedReducedPlan(plan);
    const bytes = new Uint8Array(
        4 + 2 + 2 + 2 + plan.gates.length * 4 + 2 + plan.outputWires.length * 2,
    );
    const view = new DataView(bytes.buffer);
    bytes.set(new TextEncoder().encode('SLJP'), 0);
    let offset = 4;
    view.setUint16(offset, 1, true);
    offset += 2;
    view.setUint16(offset, plan.inputWireCount, true);
    offset += 2;
    view.setUint16(offset, plan.gates.length, true);
    offset += 2;
    for (const gate of plan.gates) {
        requireUnsigned16(gate.leftWire, 'leftWire');
        requireUnsigned16(gate.rightWire, 'rightWire');
        view.setUint16(offset, gate.leftWire, true);
        view.setUint16(offset + 2, gate.rightWire, true);
        offset += 4;
    }
    view.setUint16(offset, plan.outputWires.length, true);
    offset += 2;
    for (const outputWire of plan.outputWires) {
        requireUnsigned16(outputWire, 'outputWire');
        view.setUint16(offset, outputWire, true);
        offset += 2;
    }
    return bytes;
};

export const paddedContinuationLabelEntropyByteLength = (
    plan: JointContinuationPlan,
): number => {
    validateReviewedReducedPlan(plan);
    return (
        (plan.inputWireCount * fieldBitWidth +
            plan.gates.length * 43 +
            plan.outputWires.length * 8) *
        tokenPairEntropyByteLength
    );
};

export const paddedContinuationChunkByteLength = (
    plan: JointContinuationPlan,
): number => {
    validateReviewedReducedPlan(plan);
    return (
        chunkHeaderByteLength +
        plan.inputWireCount * fieldBitWidth * tokenByteLength +
        plan.gates.length * gatePayloadByteLength +
        plan.outputWires.length * terminalPayloadByteLength
    );
};

const writeCertificate = (
    request: ConstructionCommandWriter,
    certificate: PaddedContinuationFinalityCertificate,
): void => {
    requireExactConstructionBytes(
        certificate.targetBody,
        finalityTargetBodyByteLength,
        'targetBody',
    );
    requireExactConstructionBytes(
        certificate.canonicalRosterBytes,
        completionRosterByteLength,
        'canonicalRosterBytes',
    );
    if (
        certificate.signatures.length < completionProfileFinalityQuorum ||
        certificate.signatures.length > completionProfileParticipantCount
    ) {
        throw new RangeError(
            'signatures must contain a completion-profile quorum.',
        );
    }
    request.writeU16(completionProfileParticipantCount);
    request.writeBytes(certificate.targetBody);
    request.writeBytes(certificate.canonicalRosterBytes);
    request.writeU16(certificate.signatures.length);
    for (const entry of certificate.signatures) {
        requirePosition(entry.signerPosition, 'signerPosition');
        requireExactConstructionBytes(
            entry.signature,
            actionSignatureCarrierByteLength,
            'finalitySignatureCarrier',
        );
        request.writeU16(entry.signerPosition);
        request.writeBytes(entry.signature);
    }
};

export const openPaddedContinuationRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): PaddedContinuationRuntime => ({
    generateParticipant: (certificate, plan, input) => {
        const planBytes = encodePlan(plan);
        requirePosition(input.participantPosition, 'participantPosition');
        requireExactConstructionBytes(
            input.initialWireValues,
            plan.inputWireCount,
            'initialWireValues',
        );
        requireExactConstructionBytes(
            input.gateMaskShares,
            plan.gates.length * 2,
            'gateMaskShares',
        );
        requireExactConstructionBytes(
            input.terminalMaskShares,
            plan.outputWires.length,
            'terminalMaskShares',
        );
        requireExactConstructionBytes(
            input.allocationNonce,
            paddedContinuationAllocationNonceByteLength,
            'allocationNonce',
        );
        requireExactConstructionBytes(
            input.labelEntropy,
            paddedContinuationLabelEntropyByteLength(plan),
            'labelEntropy',
        );
        if (
            input.preparationParents.length !==
            completionProfileParticipantCount
        ) {
            throw new RangeError(
                'preparationParents must contain the complete roster.',
            );
        }
        for (const parent of input.preparationParents) {
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
            input.ownContributionOpenings,
            preparationContributionOpeningVectorByteLength,
            'ownContributionOpenings',
        );
        requireExactConstructionBytes(
            input.ownPairwiseMasters,
            preparationPairwiseMasterVectorByteLength,
            'ownPairwiseMasters',
        );
        if (
            input.remotePlaintexts.length !==
            completionProfileParticipantCount - 1
        ) {
            throw new RangeError(
                'remotePlaintexts must contain every remote sender in roster order.',
            );
        }
        for (const plaintext of input.remotePlaintexts) {
            requireExactConstructionBytes(
                plaintext,
                preparationPlaintextByteLength,
                'remotePlaintext',
            );
        }
        const request = new ConstructionCommandWriter();
        request.writeU8(generateParticipantCommand);
        writeCertificate(request, certificate);
        request.writeBytes(planBytes);
        request.writeU16(input.participantPosition);
        request.writeBytes(input.initialWireValues);
        request.writeBytes(input.gateMaskShares);
        request.writeBytes(input.terminalMaskShares);
        request.writeBytes(input.allocationNonce);
        request.writeBytes(input.labelEntropy);
        for (const parent of input.preparationParents) {
            request.writeBytes(parent.body);
            request.writeBytes(parent.signature);
        }
        request.writeBytes(input.ownContributionOpenings);
        request.writeBytes(input.ownPairwiseMasters);
        for (const plaintext of input.remotePlaintexts) {
            request.writeBytes(plaintext);
        }
        return executeConstructionCommand(kernel, request, (reader) => {
            const chunk = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                chunk,
                paddedContinuationChunkByteLength(plan),
                'paddedContinuationChunk',
            );
            const chunkIdentity = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            const manifest = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                manifest,
                paddedContinuationManifestByteLength,
                'paddedContinuationManifest',
            );
            const manifestIdentity = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            return { chunk, chunkIdentity, manifest, manifestIdentity };
        });
    },
    encodeActivationSignature: (
        participantPosition,
        manifestIdentity,
        signature,
    ) => {
        requirePosition(participantPosition, 'participantPosition');
        requireExactConstructionBytes(
            manifestIdentity,
            identityByteLength,
            'manifestIdentity',
        );
        requireExactConstructionBytes(
            signature,
            actionSignatureByteLength,
            'actionSignature',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeActivationSignatureCommand);
        request.writeU16(participantPosition);
        request.writeFixed(manifestIdentity);
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
    evaluateBatch: (certificate, plan, manifests, signatures, chunks) => {
        const planBytes = encodePlan(plan);
        if (
            manifests.length !== completionProfileParticipantCount ||
            signatures.length !== completionProfileParticipantCount ||
            chunks.length !== completionProfileParticipantCount
        ) {
            throw new RangeError(
                'manifests, signatures, and chunks must contain the complete roster.',
            );
        }
        const expectedChunkByteLength = paddedContinuationChunkByteLength(plan);
        const request = new ConstructionCommandWriter();
        request.writeU8(evaluateBatchCommand);
        writeCertificate(request, certificate);
        request.writeBytes(planBytes);
        for (const manifest of manifests) {
            requireExactConstructionBytes(
                manifest,
                paddedContinuationManifestByteLength,
                'paddedContinuationManifest',
            );
            request.writeBytes(manifest);
        }
        for (const signature of signatures) {
            requireExactConstructionBytes(
                signature,
                actionSignatureCarrierByteLength,
                'activationSignatureCarrier',
            );
            request.writeBytes(signature);
        }
        for (const chunk of chunks) {
            requireExactConstructionBytes(
                chunk,
                expectedChunkByteLength,
                'paddedContinuationChunk',
            );
            request.writeBytes(chunk);
        }
        return executeConstructionCommand(kernel, request, (reader) => {
            const batchIdentity = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            const outputCount = reader.readU16();
            if (outputCount !== plan.outputWires.length) {
                throw new Error(
                    'The construction kernel returned the wrong terminal width.',
                );
            }
            const terminalBits: boolean[] = [];
            for (let output = 0; output < outputCount; output += 1) {
                const value = reader.readU8();
                if (value !== 0 && value !== 1) {
                    throw new Error(
                        'The construction kernel returned a nonbinary terminal.',
                    );
                }
                terminalBits.push(value === 1);
            }
            return { batchIdentity, terminalBits };
        });
    },
});
