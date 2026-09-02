import { createHash } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
    actionSignatureKeyGenerationRandomnessByteLength,
    actionSignatureSigningRandomnessByteLength,
    openActionSignatureRuntime,
    type ActionSignaturePurpose,
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
    openPaddedContinuationRuntime,
    paddedContinuationChunkByteLength,
    paddedContinuationLabelEntropyByteLength,
} from '../../src/padded-continuation-runtime.js';
import {
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
} from '../../src/pair-encryption-runtime.js';
import {
    openPreparationMaterialRuntime,
    preparationContributionOpeningVectorByteLength,
    preparationPairwiseMasterVectorByteLength,
    type GeneratedPreparationMaterial,
} from '../../src/preparation-material-runtime.js';
import { openPreparationParentRuntime } from '../../src/preparation-parent-runtime.js';
import { openRosterRuntime } from '../../src/roster-runtime.js';
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

const deterministicPaddedLabelEntropy = (
    length: number,
    seed: bigint,
): Uint8Array => {
    const entropy = deterministicBytes(length, seed);
    for (let offset = 0; offset < entropy.byteLength; offset += 81) {
        entropy[offset + 80] = (entropy[offset + 80] ?? 0) & 1;
        let labelsEqual = true;
        for (let byte = 0; byte < 40; byte += 1) {
            if (entropy[offset + byte] !== entropy[offset + 40 + byte]) {
                labelsEqual = false;
                break;
            }
        }
        if (labelsEqual) {
            entropy[offset + 40] = (entropy[offset + 40] ?? 0) ^ 1;
        }
    }
    return entropy;
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

const hashFoundationVariableBytes = (
    domainText: string,
    bytes: Uint8Array,
): Uint8Array => {
    const domain = new TextEncoder().encode(domainText);
    const frame = new Uint8Array(
        2 +
            2 +
            4 +
            2 +
            4 +
            4 +
            domain.byteLength +
            2 +
            4 +
            4 +
            bytes.byteLength,
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
    view.setUint32(offset, bytes.byteLength + 4, true);
    offset += 4;
    view.setUint32(offset, bytes.byteLength, true);
    offset += 4;
    frame.set(bytes, offset);
    return Uint8Array.from(
        createHash('shake256', { outputLength: 64 }).update(frame).digest(),
    );
};

const hashJointContinuationBody = (body: Uint8Array): Uint8Array =>
    hashFoundationVariableBytes(
        'sealed-lattice/joint-continuation/body/v1',
        body,
    );

describe('source fixation scalar WASM runtime', () => {
    it('derives the exact retained preparation, source correction, and signed variants', async () => {
        const kernel = await instantiateConstructionKernelCommandRuntime(
            kernelUrl,
            { allowUnpinnedKernel: true },
        );
        const rawSignatureRuntime = openActionSignatureRuntime(kernel);
        const signatureContexts = new WeakMap<
            Uint8Array,
            { participantPosition: number; purpose: ActionSignaturePurpose }
        >();
        let signingOrdinal = 0n;
        const signatureRuntime = {
            generateKeyPair: rawSignatureRuntime.generateKeyPair,
            signBodyIdentity: (
                secretKey: Uint8Array,
                bodyIdentity: Uint8Array,
            ): Uint8Array => {
                const context = signatureContexts.get(secretKey);
                if (context === undefined) {
                    throw new Error('test signature context is absent');
                }
                signingOrdinal += 1n;
                return rawSignatureRuntime.signBodyIdentity(
                    secretKey,
                    context.participantPosition,
                    context.purpose,
                    bodyIdentity,
                    deterministicBytes(
                        actionSignatureSigningRandomnessByteLength,
                        0x7_0000n + signingOrdinal,
                    ),
                );
            },
        };
        const pairRuntime = openPairEncryptionRuntime(kernel);
        const rosterRuntime = openRosterRuntime(kernel);
        const materialRuntime = openPreparationMaterialRuntime(kernel);
        const parentRuntime = openPreparationParentRuntime(kernel);
        const sourceRuntime = openSourceRuntime(kernel);
        const finalityRuntime = openFinalityRuntime(kernel);
        const actionProposalIdentity = deterministicBytes(64, 0x1001n);
        const predecessorIdentity = deterministicBytes(64, 0x1002n);
        const rosterPublicKeys: Array<{
            signingVerificationKey: Uint8Array;
            mailboxEncapsulationKey: Uint8Array;
        }> = [];
        const signatureSecretKeys: Uint8Array[][] = [];
        const signaturePurposes = [
            'preparation',
            'source',
            'finality',
            'activation',
        ] as const satisfies readonly ActionSignaturePurpose[];

        for (
            let participantPosition = 0;
            participantPosition < participantCount;
            participantPosition += 1
        ) {
            const participantSignatureKeyPair =
                signatureRuntime.generateKeyPair(
                    deterministicBytes(
                        actionSignatureKeyGenerationRandomnessByteLength,
                        0x2000n + BigInt(participantPosition),
                    ),
                );
            const participantSignatureKeys = signaturePurposes.map(
                (purpose) => {
                    const secretKey = Uint8Array.from(
                        participantSignatureKeyPair.secretKey,
                    );
                    signatureContexts.set(secretKey, {
                        participantPosition,
                        purpose,
                    });
                    return secretKey;
                },
            );
            signatureSecretKeys.push(participantSignatureKeys);
            const mailboxKeyPair = pairRuntime.generateKeyPair(
                deterministicBytes(
                    pairEncryptionKeyGenerationRandomnessByteLength,
                    0x4000n + BigInt(participantPosition),
                ),
            );
            rosterPublicKeys.push({
                signingVerificationKey:
                    participantSignatureKeyPair.verificationKey,
                mailboxEncapsulationKey: mailboxKeyPair.encryptionKey,
            });
        }

        const roster = rosterRuntime.encode(rosterPublicKeys);
        const canonicalRosterBytes = roster.canonicalBytes;
        const rosterIdentity = roster.rosterIdentity;
        const sourcePreparationContext: SourcePreparationContext = {
            participantCount,
            actionProposalIdentity,
            rosterIdentity,
            preparationAttempt: 7,
            predecessorIdentity,
        };
        const contributionOpenings: Uint8Array[] = [];
        const pairwiseMasters: Uint8Array[] = [];
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
            const senderPairwiseMasters = deterministicBytes(
                preparationPairwiseMasterVectorByteLength,
                0x9000n + BigInt(senderPosition),
            );
            pairwiseMasters.push(senderPairwiseMasters);
            const material = materialRuntime.generate(
                { ...sourcePreparationContext, senderPosition },
                openings,
                senderPairwiseMasters,
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
            canonicalRosterBytes,
            parents,
            contributionOpenings[0] ?? new Uint8Array(),
            pairwiseMasters[0] ?? new Uint8Array(),
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
        const submittedContext = {
            ...sourcePreparationContext,
            verifiedPreparationRoot: sourcePreparation.root,
            senderPosition: 0,
        } as const;
        const zeroScores = new Uint8Array(10);
        const submittedScores = Uint8Array.of(1, 10, 3, 9, 5, 8, 7, 6, 4, 2);
        const correctionZero = sourceRuntime.deriveHonestCorrection(
            submittedContext,
            zeroScores,
            sourcePreparation.heldSubsetKeys,
        );
        const submittedCorrection = sourceRuntime.deriveHonestCorrection(
            submittedContext,
            submittedScores,
            sourcePreparation.heldSubsetKeys,
        );
        expect(
            Uint8Array.from(
                correctionZero,
                (value, index) => value ^ (submittedCorrection[index] ?? 0),
            ),
        ).toEqual(Uint8Array.of(0xa1, 0x93, 0x85, 0x67, 0x24));

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
                canonicalRosterBytes,
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
            canonicalRosterBytes,
            parents,
            contributionOpenings[abstainingPosition] ?? new Uint8Array(),
            pairwiseMasters[abstainingPosition] ?? new Uint8Array(),
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
                canonicalRosterBytes,
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
                canonicalRosterBytes,
                parents,
                contributionOpenings[position] ?? new Uint8Array(),
                pairwiseMasters[position] ?? new Uint8Array(),
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
            rosterIdentity,
            preparationAttempt: sourcePreparationContext.preparationAttempt,
            predecessorIdentity,
            verifiedPreparationRoot: sourcePreparation.root,
            topCount: 1,
        } as const;
        const target = finalityRuntime.deriveTarget(
            finalityContext,
            canonicalRosterBytes,
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
                canonicalRosterBytes,
                sources,
            ),
        ).toEqual(target);
        const admittedTargets = Array.from(
            { length: participantCount },
            (_, index) =>
                finalityRuntime.deriveTarget(
                    { ...finalityContext, topCount: index + 1 },
                    canonicalRosterBytes,
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
                canonicalRosterBytes,
                sources,
            ),
        ).toThrow(RangeError);
        expect(() =>
            finalityRuntime.deriveTarget(
                { ...finalityContext, topCount: participantCount + 1 },
                canonicalRosterBytes,
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
            canonicalRosterBytes,
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
            canonicalRosterBytes,
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
            canonicalRosterBytes,
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
        expect(
            Buffer.from(
                jointContinuationBodyIdentities[0] ?? new Uint8Array(),
            ).toString('hex'),
        ).toBe(
            '760d6d9f072242110c2d1077674daa16775cc1d7e407b7dbc839ec6ec9a2228eb6d0dea3c138bc7b2538c9e826a5b9f368f2dfc6112e07082a5905d5ed036b4b',
        );
        expect(
            Buffer.from(evaluatedJointContinuation.batchIdentity).toString(
                'hex',
            ),
        ).toBe(
            '678a81683e2dedbac4f34e22e70102cf107e7cc324cd749a7a2769514b8420149c169eb5c7e8505cfbbfd145161f410c0fefa3d5a9b56fc64b60c19b0a175aa2',
        );
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
            4 +
            canonicalRosterBytes.byteLength +
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
        expect(expectedEvaluationRequestByteLength).toBe(1_192_861);
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
        expect(observedEvaluationRequestByteLengths[1]).toBe(1_196_276);
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
        expect(observedEvaluationRequestByteLengths[2]).toBe(1_199_691);
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
            request.writeBytes(certificate.canonicalRosterBytes);
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

        const paddedContinuationRuntime = openPaddedContinuationRuntime(kernel);
        expect(
            paddedContinuationLabelEntropyByteLength(jointContinuationPlan),
        ).toBe(27_621);
        expect(paddedContinuationChunkByteLength(jointContinuationPlan)).toBe(
            69_099,
        );

        const paddedInputs = Array.from(
            { length: participantCount },
            (_unused, participantPosition) => ({
                participantPosition,
                initialWireValues:
                    initialWireValues[participantPosition] ?? new Uint8Array(),
                gateMaskShares: Uint8Array.from(
                    gateMaskShares[participantPosition] ?? [],
                ),
                terminalMaskShares: Uint8Array.from(
                    terminalMaskShares[participantPosition] ?? [],
                ),
                allocationNonce: deterministicBytes(
                    32,
                    0x710_000n + BigInt(participantPosition),
                ),
                labelEntropy: deterministicPaddedLabelEntropy(
                    paddedContinuationLabelEntropyByteLength(
                        jointContinuationPlan,
                    ),
                    0x720_000n + BigInt(participantPosition),
                ),
                preparationParents: parents,
                ownContributionOpenings:
                    contributionOpenings[participantPosition] ??
                    new Uint8Array(),
                ownPairwiseMasters:
                    pairwiseMasters[participantPosition] ?? new Uint8Array(),
                remotePlaintexts: remotePlaintextsFor(participantPosition),
            }),
        );
        const paddedChunks: Uint8Array[] = [];
        const paddedChunkIdentities: Uint8Array[] = [];
        const paddedManifests: Uint8Array[] = [];
        const paddedManifestIdentities: Uint8Array[] = [];
        const paddedActivationSignatures: Uint8Array[] = [];
        for (
            let participantPosition = 0;
            participantPosition < participantCount;
            participantPosition += 1
        ) {
            const input = paddedInputs[participantPosition];
            if (input === undefined) {
                throw new Error('test padded input is absent');
            }
            const generated = paddedContinuationRuntime.generateParticipant(
                jointContinuationCertificate,
                jointContinuationPlan,
                input,
            );
            expect(generated.chunk).toHaveLength(69_099);
            expect(generated.manifest).toHaveLength(254);
            expect(generated.chunk.subarray(0, 4)).toEqual(
                new TextEncoder().encode('SLPC'),
            );
            expect(generated.manifest.subarray(0, 4)).toEqual(
                new TextEncoder().encode('SLPM'),
            );
            expect(generated.chunkIdentity).toEqual(
                hashFoundationVariableBytes(
                    'sealed-lattice/padded-continuation/chunk/v1',
                    generated.chunk,
                ),
            );
            expect(generated.manifestIdentity).toEqual(
                hashFoundationVariableBytes(
                    'sealed-lattice/padded-continuation/manifest/v1',
                    generated.manifest,
                ),
            );
            const activationSecretKey =
                signatureSecretKeys[participantPosition]?.[3];
            if (activationSecretKey === undefined) {
                throw new Error('test padded activation key is absent');
            }
            paddedChunks.push(generated.chunk);
            paddedChunkIdentities.push(generated.chunkIdentity);
            paddedManifests.push(generated.manifest);
            paddedManifestIdentities.push(generated.manifestIdentity);
            paddedActivationSignatures.push(
                paddedContinuationRuntime.encodeActivationSignature(
                    participantPosition,
                    generated.manifestIdentity,
                    signatureRuntime.signBodyIdentity(
                        activationSecretKey,
                        generated.manifestIdentity,
                    ),
                ),
            );
        }

        const observedPaddedEvaluationRequestByteLengths: number[] = [];
        const recordingPaddedContinuationRuntime =
            openPaddedContinuationRuntime({
                executeCommand: (request) => {
                    if (request[0] === 40) {
                        observedPaddedEvaluationRequestByteLengths.push(
                            request.byteLength,
                        );
                    }
                    return kernel.executeCommand(request);
                },
                measureResources: () => kernel.measureResources(),
            });
        const evaluatedPadded =
            recordingPaddedContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                paddedManifests,
                paddedActivationSignatures,
                paddedChunks,
            );
        expect(
            Buffer.from(paddedChunkIdentities[0] ?? new Uint8Array()).toString(
                'hex',
            ),
        ).toBe(
            '190b05ce0757ac589ebaed6d0a6d2100d2cbf34c78e5f95fb9394f38fc0c8ae6f5d4ec27a71fc34b06352844a9c3cc99a6f803122bd1112b78fa6751db143048',
        );
        expect(
            Buffer.from(paddedManifests[0] ?? new Uint8Array()).toString('hex'),
        ).toBe(
            '534c504d0100071b5ef9d8e86841ef2a19086325741266c030cca1f3c55a5c93f8d2daf77ee88b77d6cc6cdd9ad60778db0d2194bf0e7447b08a18de9dd94fcfadec3c5ca11b6fb96c7ddb8fd1d847b8608460675c03ac902440d103fc97a23c5df76d08418514029b16ed4443549d75ff335aaeba2d4e0c28efd2b0fe28a2b4f1b870b7e1410a000000010000c4c722b87319a38e0bf5a0c7908b52a0572f230fd576ec7d71e96c624008f60100000000000000070000000101eb0d0100190b05ce0757ac589ebaed6d0a6d2100d2cbf34c78e5f95fb9394f38fc0c8ae6f5d4ec27a71fc34b06352844a9c3cc99a6f803122bd1112b78fa6751db143048',
        );
        const firstPaddedChunk = paddedChunks[0];
        const firstPaddedManifest = paddedManifests[0];
        if (
            firstPaddedChunk === undefined ||
            firstPaddedManifest === undefined
        ) {
            throw new Error('test padded carrier is absent');
        }
        const firstChunkView = new DataView(
            firstPaddedChunk.buffer,
            firstPaddedChunk.byteOffset,
            firstPaddedChunk.byteLength,
        );
        const firstManifestView = new DataView(
            firstPaddedManifest.buffer,
            firstPaddedManifest.byteOffset,
            firstPaddedManifest.byteLength,
        );
        expect(firstPaddedChunk.subarray(0, 4)).toEqual(
            new TextEncoder().encode('SLPC'),
        );
        expect(firstChunkView.getUint16(4, true)).toBe(1);
        expect(firstPaddedChunk.subarray(6, 70)).toEqual(target.targetIdentity);
        expect(firstPaddedChunk.subarray(70, 134)).toEqual(
            Uint8Array.from(
                Buffer.from(
                    '6fb96c7ddb8fd1d847b8608460675c03ac902440d103fc97a23c5df76d08418514029b16ed4443549d75ff335aaeba2d4e0c28efd2b0fe28a2b4f1b870b7e141',
                    'hex',
                ),
            ),
        );
        expect(firstChunkView.getUint16(134, true)).toBe(10);
        expect(firstChunkView.getUint16(136, true)).toBe(0);
        expect(firstChunkView.getUint16(138, true)).toBe(1);
        expect(firstPaddedChunk.subarray(140, 172)).toEqual(
            paddedInputs[0]?.allocationNonce,
        );
        expect(firstChunkView.getUint32(172, true)).toBe(0);
        expect(firstChunkView.getUint32(176, true)).toBe(0);
        expect(firstChunkView.getUint32(180, true)).toBe(7);
        expect(firstPaddedChunk.subarray(184, 186)).toEqual(
            Uint8Array.of(1, 1),
        );
        expect(firstPaddedChunk.subarray(186, 250)).toEqual(new Uint8Array(64));
        expect(firstPaddedManifest.subarray(0, 4)).toEqual(
            new TextEncoder().encode('SLPM'),
        );
        expect(firstManifestView.getUint16(4, true)).toBe(1);
        expect(firstPaddedManifest.subarray(6, 172)).toEqual(
            firstPaddedChunk.subarray(6, 172),
        );
        expect(firstManifestView.getUint32(172, true)).toBe(1);
        expect(firstManifestView.getUint32(176, true)).toBe(0);
        expect(firstManifestView.getUint32(180, true)).toBe(7);
        expect(firstPaddedManifest.subarray(184, 186)).toEqual(
            Uint8Array.of(1, 1),
        );
        expect(firstManifestView.getUint32(186, true)).toBe(69_099);
        expect(firstPaddedManifest.subarray(190, 254)).toEqual(
            paddedChunkIdentities[0],
        );
        expect(
            Buffer.from(
                paddedManifestIdentities[0] ?? new Uint8Array(),
            ).toString('hex'),
        ).toBe(
            'e036fe76fdf83f4e7812f4995f87170913e556ea4da015ad753c09438f96ac0963685c61e1355bfb6fa80553aa871bb819e55c2d6bc10a7cf325bec97054642b',
        );
        expect(Buffer.from(evaluatedPadded.batchIdentity).toString('hex')).toBe(
            '09bf02f9ee4886dad43bf377c7e03e99be606bb848462f5f675cd5de1b4ecbca4a3fa7feed29ccca41ec10810b8687e22939ab610c050c96c15248a72298727c',
        );
        expect(evaluatedPadded.terminalBits).toEqual(
            evaluatedJointContinuation.terminalBits,
        );
        expect(evaluatedPadded.batchIdentity).toHaveLength(64);
        expect(observedPaddedEvaluationRequestByteLengths).toEqual([787_841]);
        expect(
            observedPaddedEvaluationRequestByteLengths[0],
        ).toBeLessThanOrEqual(1_572_864);
        const nineSignatureEvaluation =
            recordingPaddedContinuationRuntime.evaluateBatch(
                {
                    ...jointContinuationCertificate,
                    signatures: finalitySignatures.slice(0, 9),
                },
                jointContinuationPlan,
                paddedManifests,
                paddedActivationSignatures,
                paddedChunks,
            );
        const tenSignatureEvaluation =
            recordingPaddedContinuationRuntime.evaluateBatch(
                {
                    ...jointContinuationCertificate,
                    signatures: finalitySignatures,
                },
                jointContinuationPlan,
                paddedManifests,
                paddedActivationSignatures,
                paddedChunks,
            );
        expect(nineSignatureEvaluation).toEqual(evaluatedPadded);
        expect(tenSignatureEvaluation).toEqual(evaluatedPadded);
        expect(observedPaddedEvaluationRequestByteLengths).toEqual([
            787_841, 791_256, 794_671,
        ]);
        expect(
            Math.max(...observedPaddedEvaluationRequestByteLengths),
        ).toBeLessThanOrEqual(1_572_864);
        expect(
            paddedContinuationRuntime.evaluateBatch(
                {
                    ...jointContinuationCertificate,
                    signatures: [
                        ...jointContinuationCertificate.signatures,
                    ].reverse(),
                },
                jointContinuationPlan,
                paddedManifests,
                paddedActivationSignatures,
                paddedChunks,
            ),
        ).toEqual(evaluatedPadded);

        const invalidPaddedGenerationOrderingRequest =
            new ConstructionCommandWriter();
        invalidPaddedGenerationOrderingRequest.writeU8(38);
        writeRawCertificate(
            invalidPaddedGenerationOrderingRequest,
            invalidCertificate,
        );
        invalidPaddedGenerationOrderingRequest.writeBytes(nonReviewedPlanBytes);
        expect(() =>
            executeConstructionCommand(
                kernel,
                invalidPaddedGenerationOrderingRequest,
                () => undefined,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: finality signature is invalid$/,
        );

        const paddedParticipantZero = paddedInputs[0];
        if (paddedParticipantZero === undefined) {
            throw new Error('test padded input is absent');
        }
        for (const field of [
            'initialWireValues',
            'gateMaskShares',
            'terminalMaskShares',
        ] as const) {
            const noncanonical = Uint8Array.from(paddedParticipantZero[field]);
            noncanonical[0] = 0x10;
            expect(() =>
                paddedContinuationRuntime.generateParticipant(
                    jointContinuationCertificate,
                    jointContinuationPlan,
                    { ...paddedParticipantZero, [field]: noncanonical },
                ),
            ).toThrowError(
                /^InvalidProtocolObject: padded continuation body is invalid$/,
            );
        }
        const validPaddedGenerationOrderingRequest =
            new ConstructionCommandWriter();
        validPaddedGenerationOrderingRequest.writeU8(38);
        writeRawCertificate(
            validPaddedGenerationOrderingRequest,
            jointContinuationCertificate,
        );
        validPaddedGenerationOrderingRequest.writeBytes(nonReviewedPlanBytes);
        validPaddedGenerationOrderingRequest.writeU16(
            paddedParticipantZero.participantPosition,
        );
        validPaddedGenerationOrderingRequest.writeBytes(
            paddedParticipantZero.initialWireValues,
        );
        validPaddedGenerationOrderingRequest.writeBytes(
            paddedParticipantZero.gateMaskShares,
        );
        validPaddedGenerationOrderingRequest.writeBytes(
            paddedParticipantZero.terminalMaskShares,
        );
        validPaddedGenerationOrderingRequest.writeBytes(
            paddedParticipantZero.allocationNonce,
        );
        validPaddedGenerationOrderingRequest.writeBytes(
            paddedParticipantZero.labelEntropy,
        );
        for (const parent of paddedParticipantZero.preparationParents) {
            validPaddedGenerationOrderingRequest.writeBytes(parent.body);
            validPaddedGenerationOrderingRequest.writeBytes(parent.signature);
        }
        validPaddedGenerationOrderingRequest.writeBytes(
            paddedParticipantZero.ownContributionOpenings,
        );
        validPaddedGenerationOrderingRequest.writeBytes(
            paddedParticipantZero.ownPairwiseMasters,
        );
        for (const plaintext of paddedParticipantZero.remotePlaintexts) {
            validPaddedGenerationOrderingRequest.writeBytes(plaintext);
        }
        expect(() =>
            executeConstructionCommand(
                kernel,
                validPaddedGenerationOrderingRequest,
                () => undefined,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation plan is invalid$/,
        );

        const invalidPaddedEvaluationOrderingRequest =
            new ConstructionCommandWriter();
        invalidPaddedEvaluationOrderingRequest.writeU8(40);
        writeRawCertificate(
            invalidPaddedEvaluationOrderingRequest,
            invalidCertificate,
        );
        invalidPaddedEvaluationOrderingRequest.writeBytes(nonReviewedPlanBytes);
        expect(() =>
            executeConstructionCommand(
                kernel,
                invalidPaddedEvaluationOrderingRequest,
                () => undefined,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: finality signature is invalid$/,
        );

        const validPaddedEvaluationOrderingRequest =
            new ConstructionCommandWriter();
        validPaddedEvaluationOrderingRequest.writeU8(40);
        writeRawCertificate(
            validPaddedEvaluationOrderingRequest,
            jointContinuationCertificate,
        );
        validPaddedEvaluationOrderingRequest.writeBytes(nonReviewedPlanBytes);
        expect(() =>
            executeConstructionCommand(
                kernel,
                validPaddedEvaluationOrderingRequest,
                () => undefined,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation plan is invalid$/,
        );

        const stalePaddedSignatures = paddedActivationSignatures.map(
            (signature) => Uint8Array.from(signature),
        );
        const staleLastSignature =
            stalePaddedSignatures[stalePaddedSignatures.length - 1];
        if (staleLastSignature === undefined) {
            throw new Error('test padded signature is absent');
        }
        staleLastSignature[staleLastSignature.byteLength - 1] =
            (staleLastSignature[staleLastSignature.byteLength - 1] ?? 0) ^ 1;
        expect(() =>
            paddedContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                paddedManifests,
                stalePaddedSignatures,
                paddedChunks,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation signature is invalid$/,
        );

        const malformedEarlyChunks = paddedChunks.map((chunk) =>
            Uint8Array.from(chunk),
        );
        const malformedEarlyChunk = malformedEarlyChunks[0];
        if (malformedEarlyChunk === undefined) {
            throw new Error('test padded chunk is absent');
        }
        malformedEarlyChunk[0] = (malformedEarlyChunk[0] ?? 0) ^ 1;
        expect(() =>
            paddedContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                paddedManifests,
                stalePaddedSignatures,
                malformedEarlyChunks,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation signature is invalid$/,
        );

        const evaluateSignedPaddedInventory = (
            chunks: readonly Uint8Array[],
            manifests: readonly Uint8Array[],
        ): void => {
            const signatures = manifests.map(
                (manifest, participantPosition) => {
                    const manifestIdentity = hashFoundationVariableBytes(
                        'sealed-lattice/padded-continuation/manifest/v1',
                        manifest,
                    );
                    return paddedContinuationRuntime.encodeActivationSignature(
                        participantPosition,
                        manifestIdentity,
                        signatureRuntime.signBodyIdentity(
                            signatureSecretKeys[participantPosition]?.[3] ??
                                new Uint8Array(),
                            manifestIdentity,
                        ),
                    );
                },
            );
            paddedContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                manifests,
                signatures,
                chunks,
            );
        };
        const evaluateSignedPaddedVariant = (
            chunk: Uint8Array,
            manifest: Uint8Array,
        ): void =>
            evaluateSignedPaddedInventory(
                [chunk, ...paddedChunks.slice(1)],
                [manifest, ...paddedManifests.slice(1)],
            );
        const manifestForChunk = (chunk: Uint8Array): Uint8Array => {
            const manifest = Uint8Array.from(firstPaddedManifest);
            manifest.set(
                hashFoundationVariableBytes(
                    'sealed-lattice/padded-continuation/chunk/v1',
                    chunk,
                ),
                190,
            );
            return manifest;
        };
        const firstMaskedMapOffset = 250 + 4 * 4 * 41 + 35 * 4 * 41 + 4 * 41;
        const noncanonicalMaskedMapChunk = Uint8Array.from(firstPaddedChunk);
        noncanonicalMaskedMapChunk[firstMaskedMapOffset] =
            (noncanonicalMaskedMapChunk[firstMaskedMapOffset] ?? 0) | 0x10;
        expect(() =>
            evaluateSignedPaddedVariant(
                noncanonicalMaskedMapChunk,
                manifestForChunk(noncanonicalMaskedMapChunk),
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation body is invalid$/,
        );

        const nonbinaryMaskedChunks = paddedChunks.map((chunk) => {
            const changed = Uint8Array.from(chunk);
            changed[firstMaskedMapOffset] =
                (changed[firstMaskedMapOffset] ?? 0) ^ 2;
            return changed;
        });
        const nonbinaryMaskedManifests = nonbinaryMaskedChunks.map(
            (chunk, participantPosition) => {
                const manifest = Uint8Array.from(
                    paddedManifests[participantPosition] ?? new Uint8Array(),
                );
                manifest.set(
                    hashFoundationVariableBytes(
                        'sealed-lattice/padded-continuation/chunk/v1',
                        chunk,
                    ),
                    190,
                );
                return manifest;
            },
        );
        expect(() =>
            evaluateSignedPaddedInventory(
                nonbinaryMaskedChunks,
                nonbinaryMaskedManifests,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation codeword is invalid$/,
        );

        const firstJointRowsOffset = firstMaskedMapOffset + 1;
        const firstContinuationRowsOffset =
            firstJointRowsOffset + 10 * 4 * 2 * 40;
        const paddedGatePayloadByteLength =
            35 * 4 * 41 + 4 * 41 + 1 + 10 * 4 * 2 * 40 + 2 * 81 + 3 * 41;
        for (const { gateIndex, selectedRow } of [
            { gateIndex: 0, selectedRow: 0 },
            { gateIndex: 1, selectedRow: 1 },
        ] as const) {
            const selectedRowOffset =
                firstContinuationRowsOffset +
                gateIndex * paddedGatePayloadByteLength +
                selectedRow * 81;
            for (
                let authenticatorByte = 0;
                authenticatorByte < 40;
                authenticatorByte += 1
            ) {
                const chunk = Uint8Array.from(firstPaddedChunk);
                const offset = selectedRowOffset + 41 + authenticatorByte;
                chunk[offset] = (chunk[offset] ?? 0) ^ 1;
                expect(() =>
                    evaluateSignedPaddedVariant(chunk, manifestForChunk(chunk)),
                ).toThrowError(
                    /^InvalidProtocolObject: padded continuation authentication failed$/,
                );
            }

            const malformedTokenChunk = Uint8Array.from(firstPaddedChunk);
            malformedTokenChunk[selectedRowOffset + 40] =
                (malformedTokenChunk[selectedRowOffset + 40] ?? 0) ^ 2;
            expect(() =>
                evaluateSignedPaddedVariant(
                    malformedTokenChunk,
                    manifestForChunk(malformedTokenChunk),
                ),
            ).toThrowError(
                /^InvalidProtocolObject: padded continuation body is invalid$/,
            );
        }
        const chunkMutationCases: readonly Readonly<{
            offset: number;
            expected: RegExp;
            replacement?: number;
        }>[] = [
            {
                offset: 0,
                expected:
                    /^InvalidProtocolObject: padded continuation context is invalid$/,
            },
            {
                offset: 6,
                expected:
                    /^InvalidProtocolObject: padded continuation context is invalid$/,
            },
            {
                offset: 136,
                replacement: 10,
                expected:
                    /^InvalidProtocolObject: padded continuation participant position is invalid$/,
            },
            {
                offset: 172,
                expected:
                    /^InvalidProtocolObject: padded continuation chunk is invalid$/,
            },
            {
                offset: 184,
                expected:
                    /^InvalidProtocolObject: padded continuation chunk is invalid$/,
            },
            {
                offset: 186,
                expected:
                    /^InvalidProtocolObject: padded continuation chunk is invalid$/,
            },
        ];
        for (const { offset, replacement, expected } of chunkMutationCases) {
            const chunk = Uint8Array.from(firstPaddedChunk);
            if (replacement === undefined) {
                chunk[offset] = (chunk[offset] ?? 0) ^ 1;
            } else {
                new DataView(
                    chunk.buffer,
                    chunk.byteOffset,
                    chunk.byteLength,
                ).setUint16(offset, replacement, true);
            }
            const manifest = manifestForChunk(chunk);
            expect(() =>
                evaluateSignedPaddedVariant(chunk, manifest),
            ).toThrowError(expected);
        }

        const manifestMutationCases: readonly Readonly<{
            offset: number;
            expected: RegExp;
        }>[] = [
            {
                offset: 0,
                expected:
                    /^InvalidProtocolObject: padded continuation context is invalid$/,
            },
            {
                offset: 140,
                expected:
                    /^InvalidProtocolObject: padded continuation context is invalid$/,
            },
            {
                offset: 172,
                expected:
                    /^InvalidProtocolObject: padded continuation manifest is invalid$/,
            },
            {
                offset: 180,
                expected:
                    /^InvalidProtocolObject: padded continuation manifest is invalid$/,
            },
            {
                offset: 184,
                expected:
                    /^InvalidProtocolObject: padded continuation manifest is invalid$/,
            },
            {
                offset: 186,
                expected:
                    /^InvalidProtocolObject: padded continuation manifest is invalid$/,
            },
            {
                offset: 190,
                expected:
                    /^InvalidProtocolObject: padded continuation chunk is invalid$/,
            },
        ];
        for (const { offset, expected } of manifestMutationCases) {
            const manifest = Uint8Array.from(firstPaddedManifest);
            manifest[offset] = (manifest[offset] ?? 0) ^ 1;
            expect(() =>
                evaluateSignedPaddedVariant(firstPaddedChunk, manifest),
            ).toThrowError(expected);
        }

        const losingForkBatchIdentities: Uint8Array[] = [];
        const losingForkParticipants: {
            chunk: Uint8Array;
            manifest: Uint8Array;
        }[] = [];
        for (let variant = 0; variant < 2; variant += 1) {
            const baseInput = paddedInputs[0];
            if (baseInput === undefined) {
                throw new Error('test padded fork input is absent');
            }
            const fork = paddedContinuationRuntime.generateParticipant(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...baseInput,
                    allocationNonce: deterministicBytes(
                        32,
                        0x730_000n + BigInt(variant),
                    ),
                    labelEntropy: deterministicPaddedLabelEntropy(
                        paddedContinuationLabelEntropyByteLength(
                            jointContinuationPlan,
                        ),
                        0x740_000n + BigInt(variant),
                    ),
                },
            );
            const forkSignature =
                paddedContinuationRuntime.encodeActivationSignature(
                    0,
                    fork.manifestIdentity,
                    signatureRuntime.signBodyIdentity(
                        signatureSecretKeys[0]?.[3] ?? new Uint8Array(),
                        fork.manifestIdentity,
                    ),
                );
            const forkEvaluation = paddedContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                [fork.manifest, ...paddedManifests.slice(1)],
                [forkSignature, ...paddedActivationSignatures.slice(1)],
                [fork.chunk, ...paddedChunks.slice(1)],
            );
            expect(forkEvaluation.terminalBits).toEqual(
                evaluatedPadded.terminalBits,
            );
            expect(forkEvaluation.batchIdentity).not.toEqual(
                evaluatedPadded.batchIdentity,
            );
            losingForkBatchIdentities.push(forkEvaluation.batchIdentity);
            losingForkParticipants.push(fork);
        }
        expect(losingForkBatchIdentities[0]).not.toEqual(
            losingForkBatchIdentities[1],
        );
        for (const [recipientIndex, donorIndex] of [
            [0, 1],
            [1, 0],
        ] as const) {
            const recipient = losingForkParticipants[recipientIndex];
            const donor = losingForkParticipants[donorIndex];
            if (recipient === undefined || donor === undefined) {
                throw new Error('test padded fork participant is absent');
            }
            const transplantedChunk = Uint8Array.from(recipient.chunk);
            transplantedChunk.set(
                donor.chunk.subarray(
                    firstContinuationRowsOffset,
                    firstContinuationRowsOffset + 2 * 81,
                ),
                firstContinuationRowsOffset,
            );
            const transplantedManifest = Uint8Array.from(recipient.manifest);
            transplantedManifest.set(
                hashFoundationVariableBytes(
                    'sealed-lattice/padded-continuation/chunk/v1',
                    transplantedChunk,
                ),
                190,
            );
            expect(() =>
                evaluateSignedPaddedVariant(
                    transplantedChunk,
                    transplantedManifest,
                ),
            ).toThrowError(
                /^InvalidProtocolObject: padded continuation authentication failed$/,
            );
        }

        const invalidOwnOpening = Uint8Array.from(
            paddedInputs[0]?.ownContributionOpenings ?? new Uint8Array(),
        );
        invalidOwnOpening[0] = (invalidOwnOpening[0] ?? 0) ^ 1;
        expect(() =>
            paddedContinuationRuntime.generateParticipant(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...(paddedInputs[0] ??
                        (() => {
                            throw new Error('test padded input is absent');
                        })()),
                    ownContributionOpenings: invalidOwnOpening,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: source or preparation has the wrong context$/,
        );

        const equalPairEntropy = Uint8Array.from(
            paddedInputs[0]?.labelEntropy ?? new Uint8Array(),
        );
        equalPairEntropy.copyWithin(40, 0, 40);
        expect(() =>
            paddedContinuationRuntime.generateParticipant(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...(paddedInputs[0] ??
                        (() => {
                            throw new Error('test padded input is absent');
                        })()),
                    labelEntropy: equalPairEntropy,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation label entropy is invalid$/,
        );

        const invalidRemotePlaintexts = (
            paddedInputs[0]?.remotePlaintexts ?? []
        ).map((plaintext) => Uint8Array.from(plaintext));
        const invalidRemotePlaintext = invalidRemotePlaintexts[0];
        if (invalidRemotePlaintext === undefined) {
            throw new Error('test remote preparation plaintext is absent');
        }
        invalidRemotePlaintext[20] = (invalidRemotePlaintext[20] ?? 0) ^ 1;
        expect(() =>
            paddedContinuationRuntime.generateParticipant(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...(paddedInputs[0] ??
                        (() => {
                            throw new Error('test padded input is absent');
                        })()),
                    remotePlaintexts: invalidRemotePlaintexts,
                },
            ),
        ).toThrowError(
            /^InvalidProtocolObject: source or preparation has the wrong context$/,
        );

        const inconsistentPairwiseMasters = Uint8Array.from(
            paddedParticipantZero.ownPairwiseMasters,
        );
        inconsistentPairwiseMasters[32] =
            (inconsistentPairwiseMasters[32] ?? 0) ^ 1;
        const inconsistentPairwiseParticipant =
            paddedContinuationRuntime.generateParticipant(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...paddedParticipantZero,
                    ownPairwiseMasters: inconsistentPairwiseMasters,
                    allocationNonce: deterministicBytes(32, 0x750_000n),
                    labelEntropy: deterministicPaddedLabelEntropy(
                        paddedContinuationLabelEntropyByteLength(
                            jointContinuationPlan,
                        ),
                        0x760_000n,
                    ),
                },
            );
        const inconsistentPairwiseSignature =
            paddedContinuationRuntime.encodeActivationSignature(
                0,
                inconsistentPairwiseParticipant.manifestIdentity,
                signatureRuntime.signBodyIdentity(
                    signatureSecretKeys[0]?.[3] ?? new Uint8Array(),
                    inconsistentPairwiseParticipant.manifestIdentity,
                ),
            );
        expect(() =>
            paddedContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                [
                    inconsistentPairwiseParticipant.manifest,
                    ...paddedManifests.slice(1),
                ],
                [
                    inconsistentPairwiseSignature,
                    ...paddedActivationSignatures.slice(1),
                ],
                [
                    inconsistentPairwiseParticipant.chunk,
                    ...paddedChunks.slice(1),
                ],
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation authentication failed$/,
        );

        const duplicatedNonceInput = paddedInputs[1];
        const firstPaddedInput = paddedInputs[0];
        if (
            duplicatedNonceInput === undefined ||
            firstPaddedInput === undefined
        ) {
            throw new Error('test padded duplicate-nonce input is absent');
        }
        const duplicatedNonceParticipant =
            paddedContinuationRuntime.generateParticipant(
                jointContinuationCertificate,
                jointContinuationPlan,
                {
                    ...duplicatedNonceInput,
                    allocationNonce: firstPaddedInput.allocationNonce,
                },
            );
        const duplicateNonceSignature =
            paddedContinuationRuntime.encodeActivationSignature(
                1,
                duplicatedNonceParticipant.manifestIdentity,
                signatureRuntime.signBodyIdentity(
                    signatureSecretKeys[1]?.[3] ?? new Uint8Array(),
                    duplicatedNonceParticipant.manifestIdentity,
                ),
            );
        expect(() =>
            paddedContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                [
                    paddedManifests[0] ?? new Uint8Array(),
                    duplicatedNonceParticipant.manifest,
                    ...paddedManifests.slice(2),
                ],
                [
                    paddedActivationSignatures[0] ?? new Uint8Array(),
                    duplicateNonceSignature,
                    ...paddedActivationSignatures.slice(2),
                ],
                [
                    paddedChunks[0] ?? new Uint8Array(),
                    duplicatedNonceParticipant.chunk,
                    ...paddedChunks.slice(2),
                ],
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation reuses a label-allocation nonce$/,
        );

        const corruptPaddedChunks = paddedChunks.map((chunk) =>
            Uint8Array.from(chunk),
        );
        const corruptFirstChunk = corruptPaddedChunks[0];
        if (corruptFirstChunk === undefined) {
            throw new Error('test padded chunk is absent');
        }
        const firstPaddedRowsOffset =
            250 + 4 * 4 * 41 + 35 * 4 * 41 + 4 * 41 + 1;
        corruptFirstChunk[firstPaddedRowsOffset] =
            (corruptFirstChunk[firstPaddedRowsOffset] ?? 0) ^ 1;
        corruptFirstChunk[firstPaddedRowsOffset + 40] =
            (corruptFirstChunk[firstPaddedRowsOffset + 40] ?? 0) ^ 1;
        const corruptChunkIdentity = hashFoundationVariableBytes(
            'sealed-lattice/padded-continuation/chunk/v1',
            corruptFirstChunk,
        );
        const corruptPaddedManifests = paddedManifests.map((manifest) =>
            Uint8Array.from(manifest),
        );
        const corruptFirstManifest = corruptPaddedManifests[0];
        if (corruptFirstManifest === undefined) {
            throw new Error('test padded manifest is absent');
        }
        corruptFirstManifest.set(
            corruptChunkIdentity,
            corruptFirstManifest.byteLength - 64,
        );
        const corruptManifestIdentity = hashFoundationVariableBytes(
            'sealed-lattice/padded-continuation/manifest/v1',
            corruptFirstManifest,
        );
        const corruptPaddedSignatures = [...paddedActivationSignatures];
        corruptPaddedSignatures[0] =
            paddedContinuationRuntime.encodeActivationSignature(
                0,
                corruptManifestIdentity,
                signatureRuntime.signBodyIdentity(
                    signatureSecretKeys[0]?.[3] ?? new Uint8Array(),
                    corruptManifestIdentity,
                ),
            );
        expect(() =>
            paddedContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                jointContinuationPlan,
                corruptPaddedManifests,
                corruptPaddedSignatures,
                corruptPaddedChunks,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation authentication failed$/,
        );

        expect(() =>
            paddedContinuationRuntime.evaluateBatch(
                jointContinuationCertificate,
                {
                    ...jointContinuationPlan,
                    outputWires: [4, 7],
                },
                paddedManifests,
                paddedActivationSignatures,
                paddedChunks,
            ),
        ).toThrow(RangeError);

        expect(
            finalityRuntime.verifyCertificate(
                target.targetBody,
                canonicalRosterBytes,
                finalitySignatures
                    .slice(0, completionProfileFinalityQuorum)
                    .reverse(),
            ),
        ).toEqual(firstCertificate);
        expect(
            finalityRuntime.verifyCertificate(
                target.targetBody,
                canonicalRosterBytes,
                finalitySignatures.slice(
                    participantCount - completionProfileFinalityQuorum,
                ),
            ),
        ).toEqual(firstCertificate);
        expect(
            finalityRuntime.verifyCertificate(
                target.targetBody,
                canonicalRosterBytes,
                finalitySignatures.slice(0, completionProfileFinalityQuorum),
            ),
        ).toEqual(firstCertificate);

        expect(() =>
            finalityRuntime.verifySignature(
                1,
                target.targetBody,
                canonicalRosterBytes,
                finalitySignatures[0]?.signature ?? new Uint8Array(),
            ),
        ).toThrow(ConstructionKernelCommandError);
        expect(() =>
            finalityRuntime.verifyCertificate(
                target.targetBody,
                canonicalRosterBytes,
                finalitySignatures.slice(0, 7),
            ),
        ).toThrow(RangeError);
        expect(() =>
            finalityRuntime.verifyCertificate(
                target.targetBody,
                canonicalRosterBytes,
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
                canonicalRosterBytes,
                finalitySignatures,
            ),
        ).toThrow(ConstructionKernelCommandError);

        const conflictingTarget = finalityRuntime.deriveTarget(
            { ...finalityContext, topCount: 2 },
            canonicalRosterBytes,
            sources,
        );
        expect(() =>
            finalityRuntime.verifyCertificate(
                conflictingTarget.targetBody,
                canonicalRosterBytes,
                finalitySignatures.slice(0, completionProfileFinalityQuorum),
            ),
        ).toThrow(ConstructionKernelCommandError);

        const unrelatedSignatureKeyPair = rawSignatureRuntime.generateKeyPair(
            deterministicBytes(
                actionSignatureKeyGenerationRandomnessByteLength,
                0xc000n,
            ),
        );
        const unrelatedMailboxKeyPair = pairRuntime.generateKeyPair(
            deterministicBytes(
                pairEncryptionKeyGenerationRandomnessByteLength,
                0xc001n,
            ),
        );
        const unrelatedRosterBytes = rosterRuntime.encode(
            rosterPublicKeys.map((keys, participantPosition) =>
                participantPosition === 0
                    ? {
                          signingVerificationKey:
                              unrelatedSignatureKeyPair.verificationKey,
                          mailboxEncapsulationKey:
                              unrelatedMailboxKeyPair.encryptionKey,
                      }
                    : keys,
            ),
        ).canonicalBytes;
        expect(() =>
            finalityRuntime.verifyCertificate(
                target.targetBody,
                unrelatedRosterBytes,
                finalitySignatures.slice(0, completionProfileFinalityQuorum),
            ),
        ).toThrow(ConstructionKernelCommandError);

        const malformedCircuitTarget = Uint8Array.from(target.targetBody);
        malformedCircuitTarget[620] ^= 1;
        expect(() =>
            finalityRuntime.verifyCertificate(
                malformedCircuitTarget,
                canonicalRosterBytes,
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
            canonicalRosterBytes,
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
            canonicalRosterBytes,
            signatures: noResultFinalitySignatures.slice(
                0,
                completionProfileFinalityQuorum,
            ),
        };
        expect(
            finalityRuntime.verifyCertificate(
                noResultCertificate.targetBody,
                noResultCertificate.canonicalRosterBytes,
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
        expect(() =>
            paddedContinuationRuntime.generateParticipant(
                noResultCertificate,
                jointContinuationPlan,
                paddedParticipantZero,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation requires a finalized computation target$/,
        );
        expect(() =>
            paddedContinuationRuntime.evaluateBatch(
                noResultCertificate,
                jointContinuationPlan,
                paddedManifests,
                paddedActivationSignatures,
                paddedChunks,
            ),
        ).toThrowError(
            /^InvalidProtocolObject: padded continuation requires a finalized computation target$/,
        );

        const secondSubmissionCorrection = sourceRuntime.deriveHonestCorrection(
            abstainingContext,
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
                canonicalRosterBytes,
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
                canonicalRosterBytes,
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
                canonicalRosterBytes,
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
                canonicalRosterBytes,
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
