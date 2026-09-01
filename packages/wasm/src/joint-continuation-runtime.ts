import { actionKeySetBodyByteLength } from './action-key-set-runtime.js';
import { actionSignatureKeyByteLength } from './action-signature-runtime.js';
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
import { actionSignatureCarrierByteLength } from './preparation-parent-runtime.js';

const deriveAffineMaterialCommand = 34;
const generateParticipantBodyCommand = 35;
const encodeActivationSignatureCommand = 36;
const evaluateBatchCommand = 37;

const completionProfileParticipantCount = 10;
const identityByteLength = 64;
const labelByteLength = 48;
const moduleValueByteLength = 48;
const tokenByteLength = labelByteLength + 1;
const tokenPairEntropyByteLength = 2 * labelByteLength + 1;
const fieldBitWidth = 4;
const affineEntropyByteLength = 14 * moduleValueByteLength;
const affineEvaluationByteLength = 2 * moduleValueByteLength;
const localMultiplicationRowCount = 35 * 4;
const jointRowCountPerGarbler = completionProfileParticipantCount * 16;
const continuationRowByteLength = tokenByteLength + labelByteLength;
const gatePayloadByteLength =
    localMultiplicationRowCount * tokenByteLength +
    fieldBitWidth * tokenByteLength +
    1 +
    jointRowCountPerGarbler * moduleValueByteLength +
    2 * continuationRowByteLength +
    (fieldBitWidth - 1) * tokenByteLength;
const terminalPayloadByteLength =
    fieldBitWidth * 4 * tokenByteLength + fieldBitWidth * tokenByteLength + 1;
const reviewedReducedPlan: JointContinuationPlan = {
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

export const jointContinuationAffineEntropyByteLength = affineEntropyByteLength;
type JointContinuationGate = Readonly<{
    leftWire: number;
    rightWire: number;
}>;

export type JointContinuationPlan = Readonly<{
    inputWireCount: number;
    gates: readonly JointContinuationGate[];
    outputWires: readonly number[];
}>;

type JointContinuationFinalityCertificate = Readonly<{
    targetBody: Uint8Array;
    actionKeySetBodies: readonly Uint8Array[];
    signatures: readonly FinalitySignatureCarrier[];
}>;

type JointContinuationAffineEvaluation = Readonly<{
    affineA: Uint8Array;
    affineB: Uint8Array;
}>;

type JointContinuationAffineMaterial = Readonly<{
    commitment: Uint8Array;
    constants: readonly [Uint8Array, Uint8Array];
    evaluations: readonly JointContinuationAffineEvaluation[];
}>;

export type JointContinuationParticipantInput = Readonly<{
    participantPosition: number;
    initialWireValues: Uint8Array;
    gateMaskShares: Uint8Array;
    terminalMaskShares: Uint8Array;
    labelEntropy: Uint8Array;
    ownAffineEntropy: Uint8Array;
    affineCommitments: Uint8Array;
    affineEvaluations: Uint8Array;
}>;

type JointContinuationParticipantBody = Readonly<{
    body: Uint8Array;
    bodyIdentity: Uint8Array;
}>;

type EvaluatedJointContinuationBatch = Readonly<{
    batchIdentity: Uint8Array;
    terminalBits: readonly boolean[];
}>;

export type JointContinuationRuntime = Readonly<{
    deriveAffineMaterial(entropy: Uint8Array): JointContinuationAffineMaterial;
    generateParticipantBody(
        certificate: JointContinuationFinalityCertificate,
        plan: JointContinuationPlan,
        input: JointContinuationParticipantInput,
    ): JointContinuationParticipantBody;
    encodeActivationSignature(
        participantPosition: number,
        bodyIdentity: Uint8Array,
        signature: Uint8Array,
    ): Uint8Array;
    evaluateBatch(
        certificate: JointContinuationFinalityCertificate,
        plan: JointContinuationPlan,
        bodies: readonly Uint8Array[],
        signatures: readonly Uint8Array[],
    ): EvaluatedJointContinuationBatch;
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

const validatePlan = (plan: JointContinuationPlan): void => {
    requireUnsigned16(plan.inputWireCount, 'inputWireCount');
    if (
        plan.inputWireCount === 0 ||
        plan.inputWireCount > 64 ||
        plan.gates.length === 0 ||
        plan.gates.length > 32 ||
        plan.outputWires.length === 0 ||
        plan.outputWires.length > 64
    ) {
        throw new RangeError(
            'plan dimensions are outside the reduced relation bounds.',
        );
    }
    for (const [gateIndex, gate] of plan.gates.entries()) {
        requireUnsigned16(gate.leftWire, 'leftWire');
        requireUnsigned16(gate.rightWire, 'rightWire');
        const availableWireCount = plan.inputWireCount + gateIndex;
        if (
            gate.leftWire >= availableWireCount ||
            gate.rightWire >= availableWireCount
        ) {
            throw new RangeError(
                'each gate must consume an already available wire.',
            );
        }
    }
    const wireCount = plan.inputWireCount + plan.gates.length;
    const outputWires = new Set<number>();
    for (const outputWire of plan.outputWires) {
        requireUnsigned16(outputWire, 'outputWire');
        if (outputWire >= wireCount || outputWires.has(outputWire)) {
            throw new RangeError(
                'output wires must be unique available wires.',
            );
        }
        outputWires.add(outputWire);
    }
};

const validateReviewedReducedPlan = (plan: JointContinuationPlan): void => {
    validatePlan(plan);
    if (
        plan.inputWireCount !== reviewedReducedPlan.inputWireCount ||
        plan.gates.length !== reviewedReducedPlan.gates.length ||
        plan.outputWires.length !== reviewedReducedPlan.outputWires.length ||
        plan.gates.some((gate, index) => {
            const expected = reviewedReducedPlan.gates[index];
            return (
                expected === undefined ||
                gate.leftWire !== expected.leftWire ||
                gate.rightWire !== expected.rightWire
            );
        }) ||
        plan.outputWires.some(
            (wire, index) => wire !== reviewedReducedPlan.outputWires[index],
        )
    ) {
        throw new RangeError(
            'Only the reviewed reduced joint-continuation plan is executable.',
        );
    }
};

const encodeJointContinuationPlan = (
    plan: JointContinuationPlan,
): Uint8Array => {
    validatePlan(plan);
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
        view.setUint16(offset, gate.leftWire, true);
        view.setUint16(offset + 2, gate.rightWire, true);
        offset += 4;
    }
    view.setUint16(offset, plan.outputWires.length, true);
    offset += 2;
    for (const outputWire of plan.outputWires) {
        view.setUint16(offset, outputWire, true);
        offset += 2;
    }
    return bytes;
};

export const jointContinuationLabelEntropyByteLength = (
    plan: JointContinuationPlan,
): number => {
    validatePlan(plan);
    return (
        (plan.inputWireCount * fieldBitWidth +
            plan.gates.length * 43 +
            plan.outputWires.length * 8) *
        tokenPairEntropyByteLength
    );
};

export const jointContinuationParticipantBodyByteLength = (
    plan: JointContinuationPlan,
): number => {
    validatePlan(plan);
    const headerByteLength =
        4 +
        2 +
        2 * identityByteLength +
        2 +
        2 +
        plan.gates.length * identityByteLength;
    return (
        headerByteLength +
        plan.inputWireCount * fieldBitWidth * tokenByteLength +
        plan.gates.length * gatePayloadByteLength +
        plan.outputWires.length * terminalPayloadByteLength
    );
};

const writeCertificate = (
    request: ConstructionCommandWriter,
    certificate: JointContinuationFinalityCertificate,
): void => {
    requireExactConstructionBytes(
        certificate.targetBody,
        finalityTargetBodyByteLength,
        'targetBody',
    );
    if (
        certificate.actionKeySetBodies.length !==
        completionProfileParticipantCount
    ) {
        throw new RangeError(
            'actionKeySetBodies must contain the complete roster.',
        );
    }
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
    for (const body of certificate.actionKeySetBodies) {
        requireExactConstructionBytes(
            body,
            actionKeySetBodyByteLength(completionProfileParticipantCount),
            'actionKeySetBody',
        );
        request.writeBytes(body);
    }
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

export const openJointContinuationRuntime = (
    kernel: ConstructionKernelCommandRuntime,
): JointContinuationRuntime => ({
    deriveAffineMaterial: (entropy) => {
        requireExactConstructionBytes(
            entropy,
            affineEntropyByteLength,
            'affineEntropy',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(deriveAffineMaterialCommand);
        request.writeBytes(entropy);
        return executeConstructionCommand(kernel, request, (reader) => {
            const commitment = Uint8Array.from(
                reader.readFixed(identityByteLength),
            );
            const constants = [
                Uint8Array.from(reader.readFixed(moduleValueByteLength)),
                Uint8Array.from(reader.readFixed(moduleValueByteLength)),
            ] as const;
            const evaluations: JointContinuationAffineEvaluation[] = [];
            for (
                let position = 0;
                position < completionProfileParticipantCount;
                position += 1
            ) {
                evaluations.push({
                    affineA: Uint8Array.from(
                        reader.readFixed(moduleValueByteLength),
                    ),
                    affineB: Uint8Array.from(
                        reader.readFixed(moduleValueByteLength),
                    ),
                });
            }
            return { commitment, constants, evaluations };
        });
    },
    generateParticipantBody: (certificate, plan, input) => {
        validateReviewedReducedPlan(plan);
        const planBytes = encodeJointContinuationPlan(plan);
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
            input.labelEntropy,
            jointContinuationLabelEntropyByteLength(plan),
            'labelEntropy',
        );
        requireExactConstructionBytes(
            input.ownAffineEntropy,
            plan.gates.length * affineEntropyByteLength,
            'ownAffineEntropy',
        );
        requireExactConstructionBytes(
            input.affineCommitments,
            plan.gates.length *
                completionProfileParticipantCount *
                identityByteLength,
            'affineCommitments',
        );
        requireExactConstructionBytes(
            input.affineEvaluations,
            plan.gates.length *
                completionProfileParticipantCount *
                affineEvaluationByteLength,
            'affineEvaluations',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(generateParticipantBodyCommand);
        writeCertificate(request, certificate);
        request.writeBytes(planBytes);
        request.writeU16(input.participantPosition);
        request.writeBytes(input.initialWireValues);
        request.writeBytes(input.gateMaskShares);
        request.writeBytes(input.terminalMaskShares);
        request.writeBytes(input.labelEntropy);
        request.writeBytes(input.ownAffineEntropy);
        request.writeBytes(input.affineCommitments);
        request.writeBytes(input.affineEvaluations);
        return executeConstructionCommand(kernel, request, (reader) => {
            const body = Uint8Array.from(reader.readBytes());
            requireExactConstructionBytes(
                body,
                jointContinuationParticipantBodyByteLength(plan),
                'jointContinuationParticipantBody',
            );
            return {
                body,
                bodyIdentity: Uint8Array.from(
                    reader.readFixed(identityByteLength),
                ),
            };
        });
    },
    encodeActivationSignature: (
        participantPosition,
        bodyIdentity,
        signature,
    ) => {
        requirePosition(participantPosition, 'participantPosition');
        requireExactConstructionBytes(
            bodyIdentity,
            identityByteLength,
            'bodyIdentity',
        );
        requireExactConstructionBytes(
            signature,
            actionSignatureKeyByteLength,
            'actionSignature',
        );
        const request = new ConstructionCommandWriter();
        request.writeU8(encodeActivationSignatureCommand);
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
    evaluateBatch: (certificate, plan, bodies, signatures) => {
        validateReviewedReducedPlan(plan);
        const planBytes = encodeJointContinuationPlan(plan);
        if (
            bodies.length !== completionProfileParticipantCount ||
            signatures.length !== completionProfileParticipantCount
        ) {
            throw new RangeError(
                'bodies and signatures must contain the complete roster.',
            );
        }
        const expectedBodyByteLength =
            jointContinuationParticipantBodyByteLength(plan);
        const request = new ConstructionCommandWriter();
        request.writeU8(evaluateBatchCommand);
        writeCertificate(request, certificate);
        request.writeBytes(planBytes);
        for (const body of bodies) {
            requireExactConstructionBytes(
                body,
                expectedBodyByteLength,
                'jointContinuationParticipantBody',
            );
            request.writeBytes(body);
        }
        for (const signature of signatures) {
            requireExactConstructionBytes(
                signature,
                actionSignatureCarrierByteLength,
                'activationSignatureCarrier',
            );
            request.writeBytes(signature);
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
