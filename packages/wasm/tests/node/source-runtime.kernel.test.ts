import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { openActionKeySetRuntime } from '../../src/action-key-set-runtime.js';
import {
    actionSignatureKeyByteLength,
    openActionSignatureRuntime,
} from '../../src/action-signature-runtime.js';
import {
    ConstructionCommandWriter,
    ConstructionKernelCommandError,
    executeConstructionCommand,
} from '../../src/construction-kernel-command-runtime.js';
import {
    completionProfileFinalityQuorum,
    finalityTargetBodyByteLength,
    openFinalityRuntime,
    sourceBodyIdentityVectorByteLength,
    type FinalitySignatureCarrier,
    type SourceCarrier,
} from '../../src/finality-runtime.js';
import { instantiateConstructionKernelCommandRuntime } from '../../src/foundation-kernel/kernel-runtime.js';
import {
    jointContinuationAffineEntropyByteLength,
    jointContinuationLabelEntropyByteLength,
    jointContinuationParticipantBodyByteLength,
    openJointContinuationRuntime,
    type JointContinuationParticipantInput,
    type JointContinuationPlan,
} from '../../src/joint-continuation-runtime.js';
import {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
} from '../../src/pair-encryption-runtime.js';
import {
    openPreparationMaterialRuntime,
    preparationContributionOpeningVectorByteLength,
    type GeneratedPreparationMaterial,
} from '../../src/preparation-material-runtime.js';
import { openPreparationParentRuntime } from '../../src/preparation-parent-runtime.js';
import {
    abstentionSourceBodyByteLength,
    heldSubsetKeyVectorByteLength,
    openSourceRuntime,
    preparationParentIdentityVectorByteLength,
    submittedSourceBodyByteLength,
    type PreparationParentCarrier,
    type SourcePreparationContext,
} from '../../src/source-runtime.js';

const kernelUrl = new URL(
    '../../dist/sealed-lattice-kernel.wasm',
    import.meta.url,
);
const participantCount = 10;

const deterministicBytes = (length: number, seed: bigint): Uint8Array => {
    let state = seed;
    const mask = (1n << 64n) - 1n;
    return Uint8Array.from({ length }, () => {
        state ^= (state << 13n) & mask;
        state ^= state >> 7n;
        state ^= (state << 17n) & mask;
        state &= mask;
        return Number(state & 0xffn);
    });
};

const deterministicLabelEntropy = (
    length: number,
    seed: bigint,
): Uint8Array => {
    const entropy = deterministicBytes(length, seed);
    for (let offset = 96; offset < entropy.byteLength; offset += 97) {
        entropy[offset] = (entropy[offset] ?? 0) & 1;
    }
    return entropy;
};

const multiplyFieldValues = (left: number, right: number): number => {
    let leftValue = left & 0x0f;
    let rightValue = right & 0x0f;
    let product = 0;
    for (let bit = 0; bit < 4; bit += 1) {
        if ((rightValue & 1) !== 0) product ^= leftValue;
        const highBit = leftValue >> 3;
        leftValue = (leftValue << 1) & 0x0f;
        if (highBit !== 0) leftValue ^= 0x03;
        rightValue >>= 1;
    }
    return product & 0x0f;
};

const multiplyFieldPolynomials = (
    left: readonly number[],
    right: readonly number[],
): number[] => {
    const product = Array.from(
        { length: left.length + right.length - 1 },
        () => 0,
    );
    for (const [leftDegree, leftCoefficient] of left.entries()) {
        for (const [rightDegree, rightCoefficient] of right.entries()) {
            product[leftDegree + rightDegree] =
                (product[leftDegree + rightDegree] ?? 0) ^
                multiplyFieldValues(leftCoefficient, rightCoefficient);
        }
    }
    return product;
};

const evaluateFieldPolynomial = (
    coefficients: readonly number[],
    point: number,
): number =>
    coefficients.reduceRight(
        (value, coefficient) => multiplyFieldValues(value, point) ^ coefficient,
        0,
    );

const fieldPolynomial = (
    constant: number,
    degree: number,
    domain: number,
): number[] => [
    constant & 0x0f,
    ...Array.from(
        { length: degree },
        (_, index) => (domain * 7 + (index + 1) * 5 + 3) & 0x0f,
    ),
];

const concatenateBytes = (chunks: readonly Uint8Array[]): Uint8Array => {
    const length = chunks.reduce((total, chunk) => total + chunk.byteLength, 0);
    const output = new Uint8Array(length);
    let offset = 0;
    for (const chunk of chunks) {
        output.set(chunk, offset);
        offset += chunk.byteLength;
    }
    return output;
};

const encodeJointContinuationPlanForRawCommand = (
    plan: JointContinuationPlan,
): Uint8Array => {
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

const hashJointContinuationBody = (body: Uint8Array): Uint8Array => {
    const domain = new TextEncoder().encode(
        'sealed-lattice/joint-continuation/body/v1',
    );
    const frame = new Uint8Array(
        2 + 2 + 4 + 2 + 4 + 4 + domain.byteLength + 2 + 4 + 4 + body.byteLength,
    );
    const view = new DataView(frame.buffer);
    let offset = 0;
    view.setUint16(offset, 1, true);
    offset += 2;
    view.setUint16(offset, 1, true);
    offset += 2;
    view.setUint32(offset, 2, true);
    offset += 4;
    view.setUint16(offset, 2, true);
    offset += 2;
    view.setUint32(offset, domain.byteLength + 4, true);
    offset += 4;
    view.setUint32(offset, domain.byteLength, true);
    offset += 4;
    frame.set(domain, offset);
    offset += domain.byteLength;
    view.setUint16(offset, 1, true);
    offset += 2;
    view.setUint32(offset, body.byteLength + 4, true);
    offset += 4;
    view.setUint32(offset, body.byteLength, true);
    offset += 4;
    frame.set(body, offset);
    return Uint8Array.from(
        createHash('shake256', { outputLength: 64 }).update(frame).digest(),
    );
};

describe('source fixation scalar WASM runtime', () => {
    it('derives the exact retained preparation, source correction, and signed variants', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const signatureRuntime = openActionSignatureRuntime(kernel);
        const pairRuntime = openPairEncryptionRuntime(kernel);
        const keySetRuntime = openActionKeySetRuntime(kernel);
        const materialRuntime = openPreparationMaterialRuntime(kernel);
        const parentRuntime = openPreparationParentRuntime(kernel);
        const sourceRuntime = openSourceRuntime(kernel);
        const finalityRuntime = openFinalityRuntime(kernel);
        const actionProposalIdentity = deterministicBytes(64, 0x1001n);
        const predecessorIdentity = deterministicBytes(64, 0x1002n);
        const actionKeySetBodies: Uint8Array[] = [];
        const signatureSecretKeys: Uint8Array[][] = [];
        const signatureVerificationKeysByParticipant: Uint8Array[][] = [];
        const pairEncryptionKeysByParticipant: Uint8Array[][] = [];

        for (
            let participantPosition = 0;
            participantPosition < participantCount;
            participantPosition += 1
        ) {
            const participantSignatureKeys = Array.from(
                { length: 4 },
                (_, purpose) =>
                    deterministicBytes(
                        actionSignatureKeyByteLength,
                        0x2000n + BigInt(participantPosition * 16 + purpose),
                    ),
            );
            signatureSecretKeys.push(participantSignatureKeys);
            const signatureVerificationKeys = participantSignatureKeys.map(
                (secretKey) =>
                    signatureRuntime.deriveVerificationKey(secretKey),
            );
            signatureVerificationKeysByParticipant.push(
                signatureVerificationKeys,
            );
            const pairEncryptionKeys = Array.from(
                { length: participantCount - 1 },
                (_, pairIndex) =>
                    pairRuntime.generateKeyPair(
                        deterministicBytes(
                            pairEncryptionKeyGenerationRandomnessByteLength,
                            0x4000n +
                                BigInt(participantPosition * 32 + pairIndex),
                        ),
                    ).encryptionKey,
            );
            pairEncryptionKeysByParticipant.push(pairEncryptionKeys);
            actionKeySetBodies.push(
                keySetRuntime.encode({
                    participantCount,
                    proposalIdentity: actionProposalIdentity,
                    rosterPosition: participantPosition,
                    nonce: deterministicBytes(
                        32,
                        0x6000n + BigInt(participantPosition),
                    ),
                    actionSignatureVerificationKeys: signatureVerificationKeys,
                    pairEncryptionKeys,
                }).body,
            );
        }

        const actionKeySetRosterIdentity = keySetRuntime.verifyCompleteRoster(
            participantCount,
            actionKeySetBodies,
        );
        const sourcePreparationContext: SourcePreparationContext = {
            participantCount,
            actionProposalIdentity,
            actionKeySetRosterIdentity,
            preparationAttempt: 7,
            predecessorIdentity,
        };
        const contributionOpenings: Uint8Array[] = [];
        const materials: GeneratedPreparationMaterial[] = [];
        const parents: PreparationParentCarrier[] = [];
        const parentIdentities: Uint8Array[] = [];

        for (
            let senderPosition = 0;
            senderPosition < participantCount;
            senderPosition += 1
        ) {
            const openings = deterministicBytes(
                preparationContributionOpeningVectorByteLength,
                0x8000n + BigInt(senderPosition),
            );
            contributionOpenings.push(openings);
            const material = materialRuntime.generate(
                { ...sourcePreparationContext, senderPosition },
                openings,
            );
            materials.push(material);
            const parent = parentRuntime.encode({
                ...sourcePreparationContext,
                senderPosition,
                subsetCommitments: material.subsetCommitments,
                privateBodyIdentities: Array.from(
                    { length: participantCount - 1 },
                    (_, recipientIndex) =>
                        deterministicBytes(
                            64,
                            0xa000n +
                                BigInt(senderPosition * 16 + recipientIndex),
                        ),
                ),
            });
            parentIdentities.push(parent.identity);
            const preparationSecretKey =
                signatureSecretKeys[senderPosition]?.[0];
            if (preparationSecretKey === undefined) {
                throw new Error('test preparation key is absent');
            }
            const rawSignature = signatureRuntime.signBodyIdentity(
                preparationSecretKey,
                parent.identity,
            );
            parents.push({
                body: parent.body,
                signature: parentRuntime.encodeSignature(
                    participantCount,
                    senderPosition,
                    parent.identity,
                    rawSignature,
                ),
            });
        }

        const remotePlaintextsFor = (localPosition: number): Uint8Array[] => {
            const plaintexts: Uint8Array[] = [];
            for (
                let senderPosition = 0;
                senderPosition < participantCount;
                senderPosition += 1
            ) {
                if (senderPosition === localPosition) {
                    continue;
                }
                const plaintextIndex =
                    localPosition < senderPosition
                        ? localPosition
                        : localPosition - 1;
                const plaintext =
                    materials[senderPosition]?.recipientPlaintexts[
                        plaintextIndex
                    ];
                if (plaintext === undefined) {
                    throw new Error('test preparation plaintext is absent');
                }
                plaintexts.push(plaintext);
            }
            return plaintexts;
        };

        const sourcePreparation = sourceRuntime.verifyCompletePreparation(
            sourcePreparationContext,
            0,
            actionKeySetBodies,
            parents,
            contributionOpenings[0] ?? new Uint8Array(),
            remotePlaintextsFor(0),
        );
        expect(sourcePreparation.root).toHaveLength(64);
        expect(sourcePreparation.parentIdentities).toHaveLength(
            preparationParentIdentityVectorByteLength,
        );
        for (let position = 0; position < participantCount; position += 1) {
            expect(
                sourcePreparation.parentIdentities.subarray(
                    position * 64,
                    (position + 1) * 64,
                ),
            ).toEqual(parentIdentities[position]);
        }
        expect(sourcePreparation.heldSubsetKeys).toHaveLength(
            heldSubsetKeyVectorByteLength,
        );
        const zeroScores = new Uint8Array(10);
        const submittedScores = Uint8Array.of(1, 10, 3, 9, 5, 8, 7, 6, 4, 2);
        const correctionZero = sourceRuntime.deriveHonestCorrection(
            0,
            zeroScores,
            sourcePreparation.heldSubsetKeys,
        );
        const submittedCorrection = sourceRuntime.deriveHonestCorrection(
            0,
            submittedScores,
            sourcePreparation.heldSubsetKeys,
        );
        expect(
            Uint8Array.from(
                correctionZero,
                (value, index) => value ^ (submittedCorrection[index] ?? 0),
            ),
        ).toEqual(Uint8Array.of(0xa1, 0x93, 0x85, 0x67, 0x24));

        const submittedContext = {
            ...sourcePreparationContext,
            verifiedPreparationRoot: sourcePreparation.root,
            senderPosition: 0,
        } as const;
        const submitted = sourceRuntime.encodeBody(
            submittedContext,
            'submit',
            submittedCorrection,
        );
        expect(submitted.body).toHaveLength(submittedSourceBodyByteLength);
        const sourceSecretKey = signatureSecretKeys[0]?.[1];
        if (sourceSecretKey === undefined) {
            throw new Error('test source key is absent');
        }
        const submittedSignature = sourceRuntime.encodeSignature(
            0,
            submitted.identity,
            signatureRuntime.signBodyIdentity(
                sourceSecretKey,
                submitted.identity,
            ),
        );
        expect(
            sourceRuntime.verify(
                submittedContext,
                'submit',
                actionKeySetBodies,
                submitted.body,
                submittedSignature,
            ),
        ).toEqual({
            senderPosition: 0,
            declaration: 'submit',
            correction: submittedCorrection,
            bodyIdentity: submitted.identity,
            verifiedPreparationRoot: sourcePreparation.root,
        });

        const abstainingPosition = 1;
        const abstainingPreparation = sourceRuntime.verifyCompletePreparation(
            sourcePreparationContext,
            abstainingPosition,
            actionKeySetBodies,
            parents,
            contributionOpenings[abstainingPosition] ?? new Uint8Array(),
            remotePlaintextsFor(abstainingPosition),
        );
        expect(abstainingPreparation.root).toEqual(sourcePreparation.root);
        const abstainingContext = {
            ...sourcePreparationContext,
            verifiedPreparationRoot: abstainingPreparation.root,
            senderPosition: abstainingPosition,
        } as const;
        const abstention = sourceRuntime.encodeBody(
            abstainingContext,
            'abstain',
        );
        expect(abstention.body).toHaveLength(abstentionSourceBodyByteLength);
        const abstainingSourceSecretKey =
            signatureSecretKeys[abstainingPosition]?.[1];
        if (abstainingSourceSecretKey === undefined) {
            throw new Error('test abstention key is absent');
        }
        const abstentionSignature = sourceRuntime.encodeSignature(
            abstainingPosition,
            abstention.identity,
            signatureRuntime.signBodyIdentity(
                abstainingSourceSecretKey,
                abstention.identity,
            ),
        );
        expect(
            sourceRuntime.verify(
                abstainingContext,
                'abstain',
                actionKeySetBodies,
                abstention.body,
                abstentionSignature,
            ),
        ).toMatchObject({
            senderPosition: abstainingPosition,
            declaration: 'abstain',
            correction: undefined,
        });

        const sources: SourceCarrier[] = [
            {
                declaration: 'submit',
                body: submitted.body,
                signature: submittedSignature,
            },
            {
                declaration: 'abstain',
                body: abstention.body,
                signature: abstentionSignature,
            },
        ];
        for (let position = 2; position < participantCount; position += 1) {
            const preparation = sourceRuntime.verifyCompletePreparation(
                sourcePreparationContext,
                position,
                actionKeySetBodies,
                parents,
                contributionOpenings[position] ?? new Uint8Array(),
                remotePlaintextsFor(position),
            );
            expect(preparation.root).toEqual(sourcePreparation.root);
            const sourceContext = {
                ...sourcePreparationContext,
                verifiedPreparationRoot: preparation.root,
                senderPosition: position,
            } as const;
            const body = sourceRuntime.encodeBody(sourceContext, 'abstain');
            const secretKey = signatureSecretKeys[position]?.[1];
            if (secretKey === undefined) {
                throw new Error('test source key is absent');
            }
            sources.push({
                declaration: 'abstain',
                body: body.body,
                signature: sourceRuntime.encodeSignature(
                    position,
                    body.identity,
                    signatureRuntime.signBodyIdentity(secretKey, body.identity),
                ),
            });
        }

        const finalityContext = {
            participantCount,
            runtimeIdentity: deterministicBytes(64, 0xb001n),
            candidateBuildIdentity: deterministicBytes(64, 0xb002n),
            actionProposalIdentity,
            actionDefinitionIdentity: deterministicBytes(64, 0xb003n),
            actionKeySetRosterIdentity,
            preparationAttempt: sourcePreparationContext.preparationAttempt,
            predecessorIdentity,
            verifiedPreparationRoot: sourcePreparation.root,
            topCount: 1,
        } as const;
        const target = finalityRuntime.deriveTarget(
            finalityContext,
            actionKeySetBodies,
            sources,
        );
        expect(target.targetBody).toHaveLength(finalityTargetBodyByteLength);
        expect(target.sourceBodyIdentities).toHaveLength(
            sourceBodyIdentityVectorByteLength,
        );
        expect(target.sourceSubmissionBitmap).toBe(1);
        expect(target.topCount).toBe(1);
        expect(target.targetKind).toBe('computation');
        expect(target.quorum).toBe(completionProfileFinalityQuorum);
        expect(
            finalityRuntime.deriveTarget(
                finalityContext,
                actionKeySetBodies,
                sources,
            ),
        ).toEqual(target);
        const admittedTargets = Array.from(
            { length: participantCount },
            (_, index) =>
                finalityRuntime.deriveTarget(
                    { ...finalityContext, topCount: index + 1 },
                    actionKeySetBodies,
                    sources,
                ),
        );
        expect(admittedTargets.map((entry) => entry.topCount)).toEqual(
            Array.from({ length: participantCount }, (_, index) => index + 1),
        );
        expect(
            new Set(
                admittedTargets.map((entry) => entry.targetIdentity.join(',')),
            ).size,
        ).toBe(participantCount);
        expect(() =>
            finalityRuntime.deriveTarget(
                { ...finalityContext, topCount: 0 },
                actionKeySetBodies,
                sources,
            ),
        ).toThrow(RangeError);
        expect(() =>
            finalityRuntime.deriveTarget(
                { ...finalityContext, topCount: participantCount + 1 },
                actionKeySetBodies,
                sources,
            ),
        ).toThrow(RangeError);

        const finalitySignatures: FinalitySignatureCarrier[] = [];
        for (
            let signerPosition = 0;
            signerPosition < participantCount;
            signerPosition += 1
        ) {
            const finalitySecretKey = signatureSecretKeys[signerPosition]?.[2];
            if (finalitySecretKey === undefined) {
                throw new Error('test finality key is absent');
            }
            finalitySignatures.push({
                signerPosition,
                signature: finalityRuntime.encodeSignature(
                    signerPosition,
                    target.targetIdentity,
                    signatureRuntime.signBodyIdentity(
                        finalitySecretKey,
                        target.targetIdentity,
                    ),
                ),
            });
        }
        const firstCertificate = finalityRuntime.verifyCertificate(
            target.targetBody,
            actionKeySetBodies,
            finalitySignatures.slice(0, completionProfileFinalityQuorum),
        );
        expect(firstCertificate).toMatchObject({
            quorum: completionProfileFinalityQuorum,
            targetKind: 'computation',
            sourceSubmissionBitmap: 1,
            topCount: 1,
            targetIdentity: target.targetIdentity,
        });
        finalityRuntime.verifySignature(
            0,
            target.targetBody,
            actionKeySetBodies,
            finalitySignatures[0]?.signature ?? new Uint8Array(),
        );

        expect(finalitySignatures).toHaveLength(participantCount);

        const jointContinuationRuntime = openJointContinuationRuntime(kernel);
        const jointContinuationPlan: JointContinuationPlan = {
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
        expect(
            jointContinuationLabelEntropyByteLength(jointContinuationPlan),
        ).toBe(33_077);
        expect(
            jointContinuationParticipantBodyByteLength(jointContinuationPlan),
        ).toBe(109_859);
        const jointContinuationCertificate = {
            targetBody: target.targetBody,
            actionKeySetBodies,
            signatures: finalitySignatures.slice(
                0,
                completionProfileFinalityQuorum,
            ),
        } as const;

        const initialBits = [1, 1, 1, 0] as const;
        const wirePolynomials = initialBits.map((bit, wireIndex) =>
            fieldPolynomial(bit, 3, wireIndex + 1),
        );
        const gateMaskShares = Array.from(
            { length: participantCount },
            () => [] as number[],
        );
        const maskedValues = Array.from(
            { length: jointContinuationPlan.gates.length },
            () => [] as number[],
        );
        const selectors: number[] = [];
        for (const [gateIndex, gate] of jointContinuationPlan.gates.entries()) {
            const leftPolynomial = wirePolynomials[gate.leftWire];
            const rightPolynomial = wirePolynomials[gate.rightWire];
            if (leftPolynomial === undefined || rightPolynomial === undefined) {
                throw new Error('test gate references a missing wire');
            }
            const product = multiplyFieldPolynomials(
                leftPolynomial,
                rightPolynomial,
            );
            const selector = gateIndex & 1;
            const productConstant = product[0] ?? 0;
            const maskConstant = productConstant ^ selector;
            const lowMask = fieldPolynomial(maskConstant, 3, 100 + gateIndex);
            const highMask = fieldPolynomial(maskConstant, 6, 200 + gateIndex);
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                const point = participantPosition + 1;
                gateMaskShares[participantPosition]?.push(
                    evaluateFieldPolynomial(lowMask, point),
                    evaluateFieldPolynomial(highMask, point),
                );
                maskedValues[gateIndex]?.push(
                    evaluateFieldPolynomial(product, point) ^
                        evaluateFieldPolynomial(highMask, point),
                );
            }
            const refreshed = [...lowMask];
            refreshed[0] = productConstant;
            wirePolynomials.push(refreshed);
            selectors.push(selector);
        }
        expect(new Set(selectors)).toEqual(new Set([0, 1]));

        const initialWireValues = Array.from(
            { length: participantCount },
            (_, participantPosition) =>
                Uint8Array.from(
                    wirePolynomials
                        .slice(0, initialBits.length)
                        .map((polynomial) =>
                            evaluateFieldPolynomial(
                                polynomial,
                                participantPosition + 1,
                            ),
                        ),
                ),
        );
        const terminalMaskShares = Array.from(
            { length: participantCount },
            () => [] as number[],
        );
        for (
            let outputIndex = 0;
            outputIndex < jointContinuationPlan.outputWires.length;
            outputIndex += 1
        ) {
            const mask = fieldPolynomial(0, 3, 300 + outputIndex);
            for (
                let participantPosition = 0;
                participantPosition < participantCount;
                participantPosition += 1
            ) {
                terminalMaskShares[participantPosition]?.push(
                    evaluateFieldPolynomial(mask, participantPosition + 1),
                );
            }
        }

        const affineEntropy = Array.from(
            { length: jointContinuationPlan.gates.length },
            (_unusedGateValue, gateIndex) =>
                Array.from(
                    { length: participantCount },
                    (_unusedReceiverValue, receiverPosition) =>
                        deterministicBytes(
                            jointContinuationAffineEntropyByteLength,
                            0x110_000n +
                                BigInt(
                                    gateIndex * participantCount +
                                        receiverPosition,
                                ),
                        ),
                ),
        );
        const zeroDifferenceConstant = new Uint8Array(
            jointContinuationAffineEntropyByteLength,
        );
        zeroDifferenceConstant[0] = 1;
        zeroDifferenceConstant[11 * 48] = 1;
        expect(() =>
            jointContinuationRuntime.deriveAffineMaterial(
                zeroDifferenceConstant,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation affine material is invalid$/,
        );
        const affineMaterial = affineEntropy.map((gate) =>
            gate.map((entropy) =>
                jointContinuationRuntime.deriveAffineMaterial(entropy),
            ),
        );
        const affineCommitments = concatenateBytes(
            affineMaterial.flatMap((gate) =>
                gate.map((material) => material.commitment),
            ),
        );
        const participantInputs: JointContinuationParticipantInput[] = [];
        const jointContinuationBodies: Uint8Array[] = [];
        const jointContinuationBodyIdentities: Uint8Array[] = [];
        const activationSignatures: Uint8Array[] = [];
        for (
            let participantPosition = 0;
            participantPosition < participantCount;
            participantPosition += 1
        ) {
            const input: JointContinuationParticipantInput = {
                participantPosition,
                initialWireValues:
                    initialWireValues[participantPosition] ?? new Uint8Array(),
                gateMaskShares: Uint8Array.from(
                    gateMaskShares[participantPosition] ?? [],
                ),
                terminalMaskShares: Uint8Array.from(
                    terminalMaskShares[participantPosition] ?? [],
                ),
                labelEntropy: deterministicLabelEntropy(
                    jointContinuationLabelEntropyByteLength(
                        jointContinuationPlan,
                    ),
                    0x120_000n + BigInt(participantPosition),
                ),
                ownAffineEntropy: concatenateBytes(
                    affineEntropy.map(
                        (gate) => gate[participantPosition] ?? new Uint8Array(),
                    ),
                ),
                affineCommitments,
                affineEvaluations: concatenateBytes(
                    affineMaterial.flatMap((gate) =>
                        gate.flatMap((material) => {
                            const evaluation =
                                material.evaluations[participantPosition];
                            return evaluation === undefined
                                ? []
                                : [evaluation.affineA, evaluation.affineB];
                        }),
                    ),
                ),
            };
            participantInputs.push(input);
            const generated = jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                input,
            );
            jointContinuationBodies.push(generated.body);
            jointContinuationBodyIdentities.push(generated.bodyIdentity);
            const activationSecretKey =
                signatureSecretKeys[participantPosition]?.[3];
            if (activationSecretKey === undefined) {
                throw new Error('test activation key is absent');
            }
            activationSignatures.push(
                jointContinuationRuntime.encodeActivationSignature(
                    participantPosition,
                    generated.bodyIdentity,
                    signatureRuntime.signBodyIdentity(
                        activationSecretKey,
                        generated.bodyIdentity,
                    ),
                ),
            );
        }

        const observedEvaluationRequestByteLengths: number[] = [];
        const recordingJointContinuationRuntime = openJointContinuationRuntime({
            executeCommand: (request) => {
                if (request[0] === 37) {
                    observedEvaluationRequestByteLengths.push(
                        request.byteLength,
                    );
                }
                return kernel.executeCommand(request);
            },
            measureResources: () => kernel.measureResources(),
        });
        const evaluatedJointContinuation =
            recordingJointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                jointContinuationBodies,
                activationSignatures,
            );
        expect(Array.from(jointContinuationBodyIdentities[0] ?? [])).toEqual([
            42, 251, 143, 46, 2, 58, 168, 239, 23, 158, 202, 119, 17, 1, 27, 56,
            55, 123, 203, 37, 188, 174, 90, 209, 61, 46, 200, 57, 68, 221, 194,
            50, 43, 10, 46, 71, 37, 202, 14, 201, 10, 95, 47, 136, 125, 67, 248,
            125, 228, 223, 143, 43, 113, 34, 54, 189, 251, 81, 26, 237, 89, 94,
            227, 109,
        ]);
        expect(Array.from(evaluatedJointContinuation.batchIdentity)).toEqual([
            128, 104, 94, 27, 82, 134, 138, 173, 200, 137, 132, 224, 102, 105,
            97, 231, 50, 42, 165, 29, 252, 210, 222, 135, 130, 89, 25, 48, 25,
            131, 232, 66, 206, 208, 28, 214, 221, 18, 161, 59, 30, 73, 123, 157,
            228, 37, 0, 143, 193, 189, 176, 194, 117, 122, 183, 73, 206, 112,
            184, 0, 218, 88, 25, 254,
        ]);
        expect(evaluatedJointContinuation.batchIdentity).toHaveLength(64);
        expect(evaluatedJointContinuation.terminalBits).toEqual([
            true,
            false,
            false,
        ]);
        const expectedEvaluationRequestByteLength =
            1 +
            2 +
            4 +
            target.targetBody.byteLength +
            actionKeySetBodies.reduce(
                (length, body) => length + 4 + body.byteLength,
                0,
            ) +
            2 +
            jointContinuationCertificate.signatures.reduce(
                (length, entry) => length + 2 + 4 + entry.signature.byteLength,
                0,
            ) +
            4 +
            46 +
            jointContinuationBodies.reduce(
                (length, body) => length + 4 + body.byteLength,
                0,
            ) +
            activationSignatures.reduce(
                (length, signature) => length + 4 + signature.byteLength,
                0,
            );
        expect(expectedEvaluationRequestByteLength).toBe(1_884_399);
        expect(observedEvaluationRequestByteLengths[0]).toBe(
            expectedEvaluationRequestByteLength,
        );
        expect(observedEvaluationRequestByteLengths[0]).toBeLessThanOrEqual(
            8_388_608,
        );
        expect(
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                jointContinuationBodies,
                activationSignatures,
            ),
        ).toEqual(evaluatedJointContinuation);

        const reorderedCertificate = {
            ...jointContinuationCertificate,
            signatures: [...jointContinuationCertificate.signatures].reverse(),
        };
        expect(
            jointContinuationRuntime.evaluateBatch(
                reorderedCertificate,
                jointContinuationPlan,
                jointContinuationBodies,
                activationSignatures,
            ),
        ).toEqual(evaluatedJointContinuation);
        const disjointCertificate = {
            ...jointContinuationCertificate,
            signatures: finalitySignatures.slice(
                participantCount - completionProfileFinalityQuorum,
            ),
        };
        expect(
            jointContinuationRuntime.evaluateBatch(
                disjointCertificate,
                jointContinuationPlan,
                jointContinuationBodies,
                activationSignatures,
            ),
        ).toEqual(evaluatedJointContinuation);
        const quorumPlusOneCertificate = {
            ...jointContinuationCertificate,
            signatures: finalitySignatures.slice(
                0,
                completionProfileFinalityQuorum + 1,
            ),
        };
        expect(
            recordingJointContinuationRuntime.evaluateBatch(
                quorumPlusOneCertificate,
                jointContinuationPlan,
                jointContinuationBodies,
                activationSignatures,
            ),
        ).toEqual(evaluatedJointContinuation);
        expect(observedEvaluationRequestByteLengths[1]).toBe(1_890_793);
        expect(observedEvaluationRequestByteLengths[1]).toBeLessThanOrEqual(
            8_388_608,
        );
        const superquorumCertificate = {
            ...jointContinuationCertificate,
            signatures: finalitySignatures,
        };
        const baselineParticipantInput = participantInputs[0];
        if (baselineParticipantInput === undefined) {
            throw new Error('test participant input is absent');
        }
        const minimumQuorumGenerated =
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                baselineParticipantInput,
            );
        const superquorumGenerated =
            jointContinuationRuntime.generateParticipantBody(
                superquorumCertificate,
                jointContinuationPlan,
                baselineParticipantInput,
            );
        expect(superquorumGenerated).toEqual(minimumQuorumGenerated);
        expect(superquorumGenerated.body).toEqual(jointContinuationBodies[0]);
        expect(
            recordingJointContinuationRuntime.evaluateBatch(
                superquorumCertificate,
                jointContinuationPlan,
                jointContinuationBodies,
                activationSignatures,
            ),
        ).toEqual(evaluatedJointContinuation);
        expect(observedEvaluationRequestByteLengths[2]).toBe(1_897_187);
        expect(observedEvaluationRequestByteLengths[2]).toBeLessThanOrEqual(
            8_388_608,
        );

        const invalidFinalitySignature = Uint8Array.from(
            jointContinuationCertificate.signatures[0]?.signature ??
                new Uint8Array(),
        );
        invalidFinalitySignature[invalidFinalitySignature.byteLength - 1] ^= 1;
        const invalidCertificate = {
            ...jointContinuationCertificate,
            signatures: [
                {
                    signerPosition:
                        jointContinuationCertificate.signatures[0]
                            ?.signerPosition ?? 0,
                    signature: invalidFinalitySignature,
                },
                ...jointContinuationCertificate.signatures.slice(1),
            ],
        };
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                invalidCertificate,
                jointContinuationPlan,
                baselineParticipantInput,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: finality signature is invalid$/,
        );

        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                invalidCertificate,
                jointContinuationPlan,
                jointContinuationBodies,
                activationSignatures,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: finality signature is invalid$/,
        );

        const unsignedBodyMutation = Uint8Array.from(
            jointContinuationBodies[0] ?? new Uint8Array(),
        );
        unsignedBodyMutation[unsignedBodyMutation.byteLength - 1] ^= 1;
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                [unsignedBodyMutation, ...jointContinuationBodies.slice(1)],
                activationSignatures,
            ),
        ).toThrow(ConstructionKernelCommandError);
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                invalidCertificate,
                jointContinuationPlan,
                [unsignedBodyMutation, ...jointContinuationBodies.slice(1)],
                activationSignatures,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: finality signature is invalid$/,
        );

        const invalidLastActivationSignature = Uint8Array.from(
            activationSignatures[participantCount - 1] ?? new Uint8Array(),
        );
        invalidLastActivationSignature[
            invalidLastActivationSignature.byteLength - 1
        ] ^= 1;
        const invalidLastActivationSignatures = [
            ...activationSignatures.slice(0, participantCount - 1),
            invalidLastActivationSignature,
        ];
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                jointContinuationBodies,
                invalidLastActivationSignatures,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation signature is invalid$/,
        );

        const malformedHeaderBody = Uint8Array.from(
            jointContinuationBodies[0] ?? new Uint8Array(),
        );
        malformedHeaderBody[0] ^= 1;
        expect(
            hashJointContinuationBody(
                jointContinuationBodies[0] ?? new Uint8Array(),
            ),
        ).toEqual(jointContinuationBodyIdentities[0] ?? new Uint8Array());
        const malformedHeaderIdentity =
            hashJointContinuationBody(malformedHeaderBody);
        const malformedHeaderSignature =
            jointContinuationRuntime.encodeActivationSignature(
                0,
                malformedHeaderIdentity,
                signatureRuntime.signBodyIdentity(
                    signatureSecretKeys[0]?.[3] ?? new Uint8Array(),
                    malformedHeaderIdentity,
                ),
            );
        const malformedHeaderBodies = [
            malformedHeaderBody,
            ...jointContinuationBodies.slice(1),
        ];
        const malformedHeaderSignatures = [
            malformedHeaderSignature,
            ...activationSignatures.slice(1),
        ];
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                malformedHeaderBodies,
                [
                    malformedHeaderSignature,
                    ...activationSignatures.slice(1, participantCount - 1),
                    invalidLastActivationSignature,
                ],
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation signature is invalid$/,
        );
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                malformedHeaderBodies,
                malformedHeaderSignatures,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation context is invalid$/,
        );

        for (const headerOffset of [4, 5, 70, 133, 134, 135]) {
            const mutatedHeaderBody = Uint8Array.from(
                jointContinuationBodies[0] ?? new Uint8Array(),
            );
            mutatedHeaderBody[headerOffset] ^= 1;
            const mutatedHeaderIdentity =
                hashJointContinuationBody(mutatedHeaderBody);
            const mutatedHeaderSignature =
                jointContinuationRuntime.encodeActivationSignature(
                    0,
                    mutatedHeaderIdentity,
                    signatureRuntime.signBodyIdentity(
                        signatureSecretKeys[0]?.[3] ?? new Uint8Array(),
                        mutatedHeaderIdentity,
                    ),
                );
            expect(() =>
                jointContinuationRuntime.evaluateBatch(
                    jointContinuationCertificate,
                    jointContinuationPlan,
                    [mutatedHeaderBody, ...jointContinuationBodies.slice(1)],
                    [mutatedHeaderSignature, ...activationSignatures.slice(1)],
                ),
            ).toThrowError(
                /^InvalidProtocolObject: joint continuation context is invalid$/,
            );
        }

        const noncanonicalLabelEntropy = Uint8Array.from(
            baselineParticipantInput.labelEntropy,
        );
        noncanonicalLabelEntropy[96] = 2;
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...baselineParticipantInput,
                    labelEntropy: noncanonicalLabelEntropy,
                },
            ),
        ).toThrow(ConstructionKernelCommandError);
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                invalidCertificate,
                jointContinuationPlan,
                {
                    ...baselineParticipantInput,
                    labelEntropy: noncanonicalLabelEntropy,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: finality signature is invalid$/,
        );

        const samePairDuplicateLabelEntropy = Uint8Array.from(
            baselineParticipantInput.labelEntropy,
        );
        samePairDuplicateLabelEntropy.set(
            samePairDuplicateLabelEntropy.subarray(0, 48),
            48,
        );
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...baselineParticipantInput,
                    labelEntropy: samePairDuplicateLabelEntropy,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation label entropy is invalid$/,
        );

        const crossPairDuplicateLabelEntropy = Uint8Array.from(
            baselineParticipantInput.labelEntropy,
        );
        crossPairDuplicateLabelEntropy.set(
            crossPairDuplicateLabelEntropy.subarray(0, 48),
            97,
        );
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...baselineParticipantInput,
                    labelEntropy: crossPairDuplicateLabelEntropy,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation label entropy is invalid$/,
        );

        const distantDuplicateLabelEntropy = Uint8Array.from(
            baselineParticipantInput.labelEntropy,
        );
        distantDuplicateLabelEntropy.set(
            distantDuplicateLabelEntropy.subarray(0, 48),
            distantDuplicateLabelEntropy.byteLength - 97,
        );
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...baselineParticipantInput,
                    labelEntropy: distantDuplicateLabelEntropy,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation label entropy is invalid$/,
        );

        for (const fieldName of [
            'initialWireValues',
            'gateMaskShares',
            'terminalMaskShares',
        ] as const) {
            const noncanonicalField = Uint8Array.from(
                baselineParticipantInput[fieldName],
            );
            noncanonicalField[0] = 0x10;
            expect(() =>
                jointContinuationRuntime.generateParticipantBody(
                    jointContinuationCertificate,
                    jointContinuationPlan,
                    {
                        ...baselineParticipantInput,
                        [fieldName]: noncanonicalField,
                    },
                ),
            ).toThrowError(
                /^InvalidProtocolObject: joint continuation body is invalid$/,
            );
        }

        const duplicateAffineCommitments = Uint8Array.from(
            baselineParticipantInput.affineCommitments,
        );
        duplicateAffineCommitments.copyWithin(2 * 64, 64, 2 * 64);
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...baselineParticipantInput,
                    affineCommitments: duplicateAffineCommitments,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation reuses an entropy commitment$/,
        );

        const inconsistentOwnCommitment = Uint8Array.from(
            baselineParticipantInput.affineCommitments,
        );
        inconsistentOwnCommitment[0] ^= 1;
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...baselineParticipantInput,
                    affineCommitments: inconsistentOwnCommitment,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation affine material is invalid$/,
        );

        const inconsistentOwnEvaluation = Uint8Array.from(
            baselineParticipantInput.affineEvaluations,
        );
        inconsistentOwnEvaluation[0] ^= 1;
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...baselineParticipantInput,
                    affineEvaluations: inconsistentOwnEvaluation,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation affine material is invalid$/,
        );

        const corruptParticipantInput = participantInputs[0];
        if (corruptParticipantInput === undefined) {
            throw new Error('test participant input is absent');
        }
        const corruptAffineEvaluations = Uint8Array.from(
            corruptParticipantInput.affineEvaluations,
        );
        const receiverOneEvaluationOffset = 2 * 48;
        corruptAffineEvaluations[receiverOneEvaluationOffset] ^= 1;
        const corruptTranslationBody =
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...corruptParticipantInput,
                    affineEvaluations: corruptAffineEvaluations,
                },
            );
        const corruptActivationSecretKey = signatureSecretKeys[0]?.[3];
        if (corruptActivationSecretKey === undefined) {
            throw new Error('test corrupt activation key is absent');
        }
        const corruptTranslationSignature =
            jointContinuationRuntime.encodeActivationSignature(
                0,
                corruptTranslationBody.bodyIdentity,
                signatureRuntime.signBodyIdentity(
                    corruptActivationSecretKey,
                    corruptTranslationBody.bodyIdentity,
                ),
            );
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                [
                    corruptTranslationBody.body,
                    ...jointContinuationBodies.slice(1),
                ],
                [corruptTranslationSignature, ...activationSignatures.slice(1)],
            ),
        ).toThrow(ConstructionKernelCommandError);
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                [
                    corruptTranslationBody.body,
                    ...jointContinuationBodies.slice(1),
                ],
                [
                    corruptTranslationSignature,
                    ...activationSignatures.slice(1, participantCount - 1),
                    invalidLastActivationSignature,
                ],
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation signature is invalid$/,
        );

        const corruptMaskBodies = [...jointContinuationBodies];
        const corruptMaskSignatures = [...activationSignatures];
        for (
            let corruptPosition = 0;
            corruptPosition < 3;
            corruptPosition += 1
        ) {
            const input = participantInputs[corruptPosition];
            const secretKey = signatureSecretKeys[corruptPosition]?.[3];
            if (input === undefined || secretKey === undefined) {
                throw new Error('test corrupt participant material is absent');
            }
            const changedMaskShares = Uint8Array.from(input.gateMaskShares);
            changedMaskShares[1] = (changedMaskShares[1] ?? 0) ^ 1;
            const changed = jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                { ...input, gateMaskShares: changedMaskShares },
            );
            corruptMaskBodies[corruptPosition] = changed.body;
            corruptMaskSignatures[corruptPosition] =
                jointContinuationRuntime.encodeActivationSignature(
                    corruptPosition,
                    changed.bodyIdentity,
                    signatureRuntime.signBodyIdentity(
                        secretKey,
                        changed.bodyIdentity,
                    ),
                );
        }
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                corruptMaskBodies,
                corruptMaskSignatures,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const corruptTerminalBodies = [...jointContinuationBodies];
        const corruptTerminalSignatures = [...activationSignatures];
        for (
            let corruptPosition = 0;
            corruptPosition < 3;
            corruptPosition += 1
        ) {
            const input = participantInputs[corruptPosition];
            const secretKey = signatureSecretKeys[corruptPosition]?.[3];
            if (input === undefined || secretKey === undefined) {
                throw new Error('test corrupt participant material is absent');
            }
            const changedTerminalShares = Uint8Array.from(
                input.terminalMaskShares,
            );
            changedTerminalShares[0] = (changedTerminalShares[0] ?? 0) ^ 1;
            const changed = jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                { ...input, terminalMaskShares: changedTerminalShares },
            );
            corruptTerminalBodies[corruptPosition] = changed.body;
            corruptTerminalSignatures[corruptPosition] =
                jointContinuationRuntime.encodeActivationSignature(
                    corruptPosition,
                    changed.bodyIdentity,
                    signatureRuntime.signBodyIdentity(
                        secretKey,
                        changed.bodyIdentity,
                    ),
                );
        }
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                corruptTerminalBodies,
                corruptTerminalSignatures,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const losingVariantBody =
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...corruptParticipantInput,
                    labelEntropy: deterministicLabelEntropy(
                        jointContinuationLabelEntropyByteLength(
                            jointContinuationPlan,
                        ),
                        0x130_000n,
                    ),
                },
            );
        const losingVariantSignature =
            jointContinuationRuntime.encodeActivationSignature(
                0,
                losingVariantBody.bodyIdentity,
                signatureRuntime.signBodyIdentity(
                    corruptActivationSecretKey,
                    losingVariantBody.bodyIdentity,
                ),
            );
        expect(
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                [losingVariantBody.body, ...jointContinuationBodies.slice(1)],
                [losingVariantSignature, ...activationSignatures.slice(1)],
            ).terminalBits,
        ).toEqual(evaluatedJointContinuation.terminalBits);
        const secondLosingVariantBody =
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...corruptParticipantInput,
                    labelEntropy: deterministicLabelEntropy(
                        jointContinuationLabelEntropyByteLength(
                            jointContinuationPlan,
                        ),
                        0x140_000n,
                    ),
                },
            );
        const secondLosingVariantSignature =
            jointContinuationRuntime.encodeActivationSignature(
                0,
                secondLosingVariantBody.bodyIdentity,
                signatureRuntime.signBodyIdentity(
                    corruptActivationSecretKey,
                    secondLosingVariantBody.bodyIdentity,
                ),
            );
        expect(
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                [
                    secondLosingVariantBody.body,
                    ...jointContinuationBodies.slice(1),
                ],
                [
                    secondLosingVariantSignature,
                    ...activationSignatures.slice(1),
                ],
            ).terminalBits,
        ).toEqual(evaluatedJointContinuation.terminalBits);

        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                jointContinuationCertificate,
                {
                    ...jointContinuationPlan,
                    outputWires: [7, 4, 10],
                },
                corruptParticipantInput,
            ),
        ).toThrow(RangeError);
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                {
                    ...jointContinuationPlan,
                    outputWires: [7, 4, 10],
                },
                jointContinuationBodies,
                activationSignatures,
            ),
        ).toThrow(RangeError);

        const nonReviewedPlan: JointContinuationPlan = {
            ...jointContinuationPlan,
            outputWires: [7, 4, 10],
        };
        const nonReviewedPlanBytes =
            encodeJointContinuationPlanForRawCommand(nonReviewedPlan);
        const writeRawCertificate = (
            request: ConstructionCommandWriter,
            certificate: typeof jointContinuationCertificate,
        ): void => {
            request.writeU16(participantCount);
            request.writeBytes(certificate.targetBody);
            for (const body of certificate.actionKeySetBodies) {
                request.writeBytes(body);
            }
            request.writeU16(certificate.signatures.length);
            for (const signature of certificate.signatures) {
                request.writeU16(signature.signerPosition);
                request.writeBytes(signature.signature);
            }
        };
        const invalidGenerationOrderingRequest =
            new ConstructionCommandWriter();
        invalidGenerationOrderingRequest.writeU8(35);
        writeRawCertificate(
            invalidGenerationOrderingRequest,
            invalidCertificate,
        );
        invalidGenerationOrderingRequest.writeBytes(nonReviewedPlanBytes);
        expect(() =>
            executeConstructionCommand(
                kernel,
                invalidGenerationOrderingRequest,
                () => undefined,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: finality signature is invalid$/,
        );

        const validGenerationOrderingRequest = new ConstructionCommandWriter();
        validGenerationOrderingRequest.writeU8(35);
        writeRawCertificate(
            validGenerationOrderingRequest,
            jointContinuationCertificate,
        );
        validGenerationOrderingRequest.writeBytes(nonReviewedPlanBytes);
        validGenerationOrderingRequest.writeU16(
            baselineParticipantInput.participantPosition,
        );
        validGenerationOrderingRequest.writeBytes(
            baselineParticipantInput.initialWireValues,
        );
        validGenerationOrderingRequest.writeBytes(
            baselineParticipantInput.gateMaskShares,
        );
        validGenerationOrderingRequest.writeBytes(
            baselineParticipantInput.terminalMaskShares,
        );
        validGenerationOrderingRequest.writeBytes(
            baselineParticipantInput.labelEntropy,
        );
        validGenerationOrderingRequest.writeBytes(
            baselineParticipantInput.ownAffineEntropy,
        );
        validGenerationOrderingRequest.writeBytes(
            baselineParticipantInput.affineCommitments,
        );
        validGenerationOrderingRequest.writeBytes(
            baselineParticipantInput.affineEvaluations,
        );
        expect(() =>
            executeConstructionCommand(
                kernel,
                validGenerationOrderingRequest,
                () => undefined,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation plan is invalid$/,
        );

        const invalidEvaluationOrderingRequest =
            new ConstructionCommandWriter();
        invalidEvaluationOrderingRequest.writeU8(37);
        writeRawCertificate(
            invalidEvaluationOrderingRequest,
            invalidCertificate,
        );
        invalidEvaluationOrderingRequest.writeBytes(nonReviewedPlanBytes);
        expect(() =>
            executeConstructionCommand(
                kernel,
                invalidEvaluationOrderingRequest,
                () => undefined,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: finality signature is invalid$/,
        );

        const validEvaluationOrderingRequest = new ConstructionCommandWriter();
        validEvaluationOrderingRequest.writeU8(37);
        writeRawCertificate(
            validEvaluationOrderingRequest,
            jointContinuationCertificate,
        );
        validEvaluationOrderingRequest.writeBytes(nonReviewedPlanBytes);
        for (const body of jointContinuationBodies) {
            validEvaluationOrderingRequest.writeBytes(body);
        }
        for (const signature of activationSignatures) {
            validEvaluationOrderingRequest.writeBytes(signature);
        }
        expect(() =>
            executeConstructionCommand(
                kernel,
                validEvaluationOrderingRequest,
                () => undefined,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation plan is invalid$/,
        );

        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                jointContinuationBodies.slice(0, participantCount - 1),
                activationSignatures.slice(0, participantCount - 1),
            ),
        ).toThrow(RangeError);

        const duplicateBodySignature =
            jointContinuationRuntime.encodeActivationSignature(
                1,
                jointContinuationBodyIdentities[0] ?? new Uint8Array(),
                signatureRuntime.signBodyIdentity(
                    signatureSecretKeys[1]?.[3] ?? new Uint8Array(),
                    jointContinuationBodyIdentities[0] ?? new Uint8Array(),
                ),
            );
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                [
                    jointContinuationBodies[0] ?? new Uint8Array(),
                    jointContinuationBodies[0] ?? new Uint8Array(),
                    ...jointContinuationBodies.slice(2),
                ],
                [
                    activationSignatures[0] ?? new Uint8Array(),
                    duplicateBodySignature,
                    ...activationSignatures.slice(2),
                ],
            ),
        ).toThrow(ConstructionKernelCommandError);

        expect(
            finalityRuntime.verifyCertificate(
                target.targetBody,
                actionKeySetBodies,
                finalitySignatures
                    .slice(0, completionProfileFinalityQuorum)
                    .reverse(),
            ),
        ).toEqual(firstCertificate);
        expect(
            finalityRuntime.verifyCertificate(
                target.targetBody,
                actionKeySetBodies,
                finalitySignatures.slice(
                    participantCount - completionProfileFinalityQuorum,
                ),
            ),
        ).toEqual(firstCertificate);
        expect(
            finalityRuntime.verifyCertificate(
                target.targetBody,
                actionKeySetBodies,
                finalitySignatures.slice(0, completionProfileFinalityQuorum),
            ),
        ).toEqual(firstCertificate);

        expect(() =>
            finalityRuntime.verifySignature(
                1,
                target.targetBody,
                actionKeySetBodies,
                finalitySignatures[0]?.signature ?? new Uint8Array(),
            ),
        ).toThrow(ConstructionKernelCommandError);
        expect(() =>
            finalityRuntime.verifyCertificate(
                target.targetBody,
                actionKeySetBodies,
                finalitySignatures.slice(0, 7),
            ),
        ).toThrow(RangeError);
        expect(() =>
            finalityRuntime.verifyCertificate(
                target.targetBody,
                actionKeySetBodies,
                [
                    ...finalitySignatures.slice(0, 7),
                    finalitySignatures[0] ?? {
                        signerPosition: 0,
                        signature: new Uint8Array(),
                    },
                ],
            ),
        ).toThrow(ConstructionKernelCommandError);
        const mutatedTargetBody = Uint8Array.from(target.targetBody);
        mutatedTargetBody[mutatedTargetBody.byteLength - 1] ^= 1;
        expect(() =>
            finalityRuntime.verifyCertificate(
                mutatedTargetBody,
                actionKeySetBodies,
                finalitySignatures,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const conflictingTarget = finalityRuntime.deriveTarget(
            { ...finalityContext, topCount: 2 },
            actionKeySetBodies,
            sources,
        );
        expect(() =>
            finalityRuntime.verifyCertificate(
                conflictingTarget.targetBody,
                actionKeySetBodies,
                finalitySignatures.slice(0, completionProfileFinalityQuorum),
            ),
        ).toThrow(ConstructionKernelCommandError);

        const unrelatedActionKeySetBodies = actionKeySetBodies.map(
            (_body, participantPosition) =>
                keySetRuntime.encode({
                    participantCount,
                    proposalIdentity: actionProposalIdentity,
                    rosterPosition: participantPosition,
                    nonce: deterministicBytes(
                        32,
                        0xc000n + BigInt(participantPosition),
                    ),
                    actionSignatureVerificationKeys:
                        signatureVerificationKeysByParticipant[
                            participantPosition
                        ] ?? [],
                    pairEncryptionKeys:
                        pairEncryptionKeysByParticipant[participantPosition] ??
                        [],
                }).body,
        );
        expect(() =>
            finalityRuntime.verifyCertificate(
                target.targetBody,
                unrelatedActionKeySetBodies,
                finalitySignatures.slice(0, completionProfileFinalityQuorum),
            ),
        ).toThrow(ConstructionKernelCommandError);

        const malformedCircuitTarget = Uint8Array.from(target.targetBody);
        malformedCircuitTarget[620] ^= 1;
        expect(() =>
            finalityRuntime.verifyCertificate(
                malformedCircuitTarget,
                actionKeySetBodies,
                finalitySignatures.slice(0, completionProfileFinalityQuorum),
            ),
        ).toThrow(ConstructionKernelCommandError);

        const sourceZeroAbstention = sourceRuntime.encodeBody(
            submittedContext,
            'abstain',
        );
        const allAbstainSources = sources.map((source) => ({ ...source }));
        allAbstainSources[0] = {
            declaration: 'abstain',
            body: sourceZeroAbstention.body,
            signature: sourceRuntime.encodeSignature(
                0,
                sourceZeroAbstention.identity,
                signatureRuntime.signBodyIdentity(
                    sourceSecretKey,
                    sourceZeroAbstention.identity,
                ),
            ),
        };
        const noResultTarget = finalityRuntime.deriveTarget(
            finalityContext,
            actionKeySetBodies,
            allAbstainSources,
        );
        expect(noResultTarget.targetKind).toBe('no-result');
        expect(noResultTarget.sourceSubmissionBitmap).toBe(0);
        const noResultFinalitySignatures: FinalitySignatureCarrier[] = [];
        for (
            let signerPosition = 0;
            signerPosition < participantCount;
            signerPosition += 1
        ) {
            const finalitySecretKey = signatureSecretKeys[signerPosition]?.[2];
            if (finalitySecretKey === undefined) {
                throw new Error('test no-result finality key is absent');
            }
            noResultFinalitySignatures.push({
                signerPosition,
                signature: finalityRuntime.encodeSignature(
                    signerPosition,
                    noResultTarget.targetIdentity,
                    signatureRuntime.signBodyIdentity(
                        finalitySecretKey,
                        noResultTarget.targetIdentity,
                    ),
                ),
            });
        }
        const noResultCertificate = {
            targetBody: noResultTarget.targetBody,
            actionKeySetBodies,
            signatures: noResultFinalitySignatures.slice(
                0,
                completionProfileFinalityQuorum,
            ),
        };
        expect(
            finalityRuntime.verifyCertificate(
                noResultCertificate.targetBody,
                noResultCertificate.actionKeySetBodies,
                noResultCertificate.signatures,
            ).targetKind,
        ).toBe('no-result');
        expect(() =>
            jointContinuationRuntime.generateParticipantBody(
                noResultCertificate,
                jointContinuationPlan,
                baselineParticipantInput,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation requires a finalized computation target$/,
        );
        expect(() =>
            jointContinuationRuntime.evaluateBatch(
                noResultCertificate,
                jointContinuationPlan,
                jointContinuationBodies,
                activationSignatures,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: joint continuation requires a finalized computation target$/,
        );

        const secondSubmissionCorrection = sourceRuntime.deriveHonestCorrection(
            abstainingPosition,
            Uint8Array.of(10, 9, 8, 7, 6, 5, 4, 3, 2, 1),
            abstainingPreparation.heldSubsetKeys,
        );
        const secondSubmission = sourceRuntime.encodeBody(
            abstainingContext,
            'submit',
            secondSubmissionCorrection,
        );
        const twoSubmissionSources = sources.map((source) => ({ ...source }));
        twoSubmissionSources[1] = {
            declaration: 'submit',
            body: secondSubmission.body,
            signature: sourceRuntime.encodeSignature(
                1,
                secondSubmission.identity,
                signatureRuntime.signBodyIdentity(
                    abstainingSourceSecretKey,
                    secondSubmission.identity,
                ),
            ),
        };
        expect(
            finalityRuntime.deriveTarget(
                finalityContext,
                actionKeySetBodies,
                twoSubmissionSources,
            ).sourceSubmissionBitmap,
        ).toBe(0b11);

        const corruptCorrection = Uint8Array.of(1, 0, 0, 0, 0);
        const corruptVariant = sourceRuntime.encodeBody(
            submittedContext,
            'submit',
            corruptCorrection,
        );
        const corruptSignature = sourceRuntime.encodeSignature(
            0,
            corruptVariant.identity,
            signatureRuntime.signBodyIdentity(
                sourceSecretKey,
                corruptVariant.identity,
            ),
        );
        expect(
            sourceRuntime.verify(
                submittedContext,
                'submit',
                actionKeySetBodies,
                corruptVariant.body,
                corruptSignature,
            ).correction,
        ).toEqual(corruptCorrection);

        const mutatedBody = Uint8Array.from(submitted.body);
        mutatedBody[mutatedBody.byteLength - 1] ^= 1;
        expect(() =>
            sourceRuntime.verify(
                submittedContext,
                'submit',
                actionKeySetBodies,
                mutatedBody,
                submittedSignature,
            ),
        ).toThrow(ConstructionKernelCommandError);
        const wrongRoot = {
            ...submittedContext,
            verifiedPreparationRoot: deterministicBytes(64, 0xffffn),
        };
        expect(() =>
            sourceRuntime.verify(
                wrongRoot,
                'submit',
                actionKeySetBodies,
                submitted.body,
                submittedSignature,
            ),
        ).toThrow(ConstructionKernelCommandError);
        expect(() =>
            sourceRuntime.encodeBody(
                submittedContext,
                'submit',
                new Uint8Array(4),
            ),
        ).toThrow(TypeError);
    });
});
