import { describe, expect, it } from 'vitest';

import { openActionKeySetRuntime } from '../../src/action-key-set-runtime.js';
import {
    actionSignatureKeyByteLength,
    openActionSignatureRuntime,
} from '../../src/action-signature-runtime.js';
import { ConstructionKernelCommandError } from '../../src/construction-kernel-command-runtime.js';
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
    openPairEncryptionRuntime,
    pairEncryptionKeyGenerationRandomnessByteLength,
} from '../../src/pair-encryption-runtime.js';
import {
    openPreparationMaterialRuntime,
    preparationAffineCoefficientByteLength,
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
import {
    openTallyActivationRuntime,
    type ActivationChunkDescriptor,
    type SignedActivationManifest,
} from '../../src/tally-activation-runtime.js';

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
        const tallyActivationRuntime = openTallyActivationRuntime(kernel);
        const actionProposalIdentity = deterministicBytes(64, 0x1001n);
        const predecessorIdentity = deterministicBytes(64, 0x1002n);
        const actionKeySetBodies: Uint8Array[] = [];
        const signatureSecretKeys: Uint8Array[][] = [];

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
        const affineCoefficients: Uint8Array[] = [];
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
            const affine = deterministicBytes(
                preparationAffineCoefficientByteLength,
                0x9000n + BigInt(senderPosition),
            );
            contributionOpenings.push(openings);
            affineCoefficients.push(affine);
            const material = materialRuntime.generate(
                { ...sourcePreparationContext, senderPosition },
                openings,
                affine,
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
            affineCoefficients[0] ?? new Uint8Array(),
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
        const verifiedPreparations = [sourcePreparation];
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
            affineCoefficients[abstainingPosition] ?? new Uint8Array(),
            remotePlaintextsFor(abstainingPosition),
        );
        expect(abstainingPreparation.root).toEqual(sourcePreparation.root);
        verifiedPreparations.push(abstainingPreparation);
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
                affineCoefficients[position] ?? new Uint8Array(),
                remotePlaintextsFor(position),
            );
            expect(preparation.root).toEqual(sourcePreparation.root);
            verifiedPreparations.push(preparation);
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
            actionKeySetRosterIdentity,
            preparationAttempt: sourcePreparationContext.preparationAttempt,
            predecessorIdentity,
            verifiedPreparationRoot: sourcePreparation.root,
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
        expect(target.targetKind).toBe('computation');
        expect(target.quorum).toBe(completionProfileFinalityQuorum);
        expect(
            finalityRuntime.deriveTarget(
                finalityContext,
                actionKeySetBodies,
                sources,
            ),
        ).toEqual(target);

        const finalitySignatures: FinalitySignatureCarrier[] = [];
        for (
            let signerPosition = 0;
            signerPosition < completionProfileFinalityQuorum;
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
        expect(
            finalityRuntime.verifyCertificate(
                target.targetBody,
                actionKeySetBodies,
                finalitySignatures,
            ),
        ).toEqual({
            signerBitmap: 0xff,
            quorum: completionProfileFinalityQuorum,
            targetKind: 'computation',
            sourceSubmissionBitmap: 1,
            targetIdentity: target.targetIdentity,
        });
        finalityRuntime.verifySignature(
            0,
            target.targetIdentity,
            actionKeySetBodies,
            finalitySignatures[0]?.signature ?? new Uint8Array(),
        );

        const activationContext = {
            targetIdentity: target.targetIdentity,
            topCount: 1,
            sourceSubmissionBitmap: 1,
            sourceCorrections: [
                submittedCorrection,
                ...Array.from(
                    { length: participantCount - 1 },
                    () => undefined,
                ),
            ],
        } as const;
        const activationPlan = tallyActivationRuntime.plan(1);
        expect(activationPlan.conjunctionCount).toBe(2_098);
        expect(activationPlan.outputBitCount).toBe(15);
        const activationChunksByRange: Uint8Array[][] = [];
        const activationDescriptors = Array.from(
            { length: participantCount },
            () => [] as ActivationChunkDescriptor[],
        );
        for (const range of activationPlan.ranges) {
            const chunks = verifiedPreparations.map(
                (preparation, participantPosition) => {
                    const chunk = tallyActivationRuntime.generateChunk(
                        activationContext,
                        {
                            participantPosition,
                            activationSeed: deterministicBytes(
                                32,
                                0xc000n + BigInt(participantPosition),
                            ),
                            heldSubsetKeys: preparation.heldSubsetKeys,
                            heldAffineEvaluations:
                                preparation.heldAffineEvaluations,
                            localAffineConstants:
                                preparation.localAffineConstants,
                        },
                        range,
                    );
                    activationDescriptors[participantPosition]?.push({
                        ...range,
                        byteLength: chunk.byteLength,
                        identity: tallyActivationRuntime.identifyChunk(chunk),
                    });
                    return chunk;
                },
            );
            activationChunksByRange.push(chunks);
        }
        const signedActivationManifests: SignedActivationManifest[] =
            activationDescriptors.map((descriptors, participantPosition) => {
                const encoded = tallyActivationRuntime.encodeManifest(
                    activationContext,
                    participantPosition,
                    descriptors,
                );
                const activationSecretKey =
                    signatureSecretKeys[participantPosition]?.[3];
                if (activationSecretKey === undefined) {
                    throw new Error('test activation key is absent');
                }
                const signature = tallyActivationRuntime.encodeSignature(
                    participantPosition,
                    encoded.identity,
                    signatureRuntime.signBodyIdentity(
                        activationSecretKey,
                        encoded.identity,
                    ),
                );
                expect(
                    tallyActivationRuntime.verifyManifest(
                        actionKeySetBodies,
                        encoded.body,
                        signature,
                    ),
                ).toMatchObject({
                    targetIdentity: target.targetIdentity,
                    topCount: 1,
                    sourceSubmissionBitmap: 1,
                    participantPosition,
                    chunks: descriptors,
                });
                return { body: encoded.body, signature };
            });
        const firstChunks = activationChunksByRange[0];
        const firstRange = activationPlan.ranges[0];
        if (firstChunks === undefined || firstRange === undefined) {
            throw new Error('test activation plan is empty');
        }
        const corruptedFirstChunks = firstChunks.map((chunk) =>
            Uint8Array.from(chunk),
        );
        const corruptedFirstChunk = corruptedFirstChunks[0];
        if (corruptedFirstChunk === undefined) {
            throw new Error('test activation chunk is absent');
        }
        corruptedFirstChunk[corruptedFirstChunk.byteLength - 1] ^= 1;
        expect(() =>
            tallyActivationRuntime.advance(
                activationContext,
                undefined,
                firstRange,
                actionKeySetBodies,
                signedActivationManifests,
                corruptedFirstChunks,
            ),
        ).toThrow(ConstructionKernelCommandError);

        let activationCheckpoint: Uint8Array | undefined;
        let activationTerminal:
            | ReturnType<typeof tallyActivationRuntime.advance>
            | undefined;
        let checkpointBeforeTerminal: Uint8Array | undefined;
        let maximumCheckpointByteLength = 0;
        for (const [rangeIndex, range] of activationPlan.ranges.entries()) {
            const chunks = activationChunksByRange[rangeIndex];
            if (chunks === undefined) {
                throw new Error('test activation chunk range is absent');
            }
            checkpointBeforeTerminal = activationCheckpoint;
            const advance = tallyActivationRuntime.advance(
                activationContext,
                activationCheckpoint,
                range,
                actionKeySetBodies,
                signedActivationManifests,
                chunks,
            );
            if (advance.kind === 'pending') {
                maximumCheckpointByteLength = Math.max(
                    maximumCheckpointByteLength,
                    advance.checkpoint.byteLength,
                );
                activationCheckpoint = Uint8Array.from(advance.checkpoint);
            } else {
                activationTerminal = advance;
            }
        }
        expect(maximumCheckpointByteLength).toBeGreaterThan(0);
        expect(maximumCheckpointByteLength).toBeLessThan(3_000_000);
        expect(activationTerminal).toEqual({
            kind: 'result',
            acceptedBallotAuthorshipBitmap: 1,
            orderedOptionPositions: [1],
        });
        const lastRange =
            activationPlan.ranges[activationPlan.ranges.length - 1];
        const lastChunks =
            activationChunksByRange[activationChunksByRange.length - 1];
        if (
            lastRange === undefined ||
            lastChunks === undefined ||
            checkpointBeforeTerminal === undefined
        ) {
            throw new Error('test terminal activation range is absent');
        }
        expect(
            tallyActivationRuntime.advance(
                activationContext,
                checkpointBeforeTerminal,
                lastRange,
                actionKeySetBodies,
                signedActivationManifests,
                lastChunks,
            ),
        ).toEqual(activationTerminal);
        const secondRange = activationPlan.ranges[1];
        const secondChunks = activationChunksByRange[1];
        if (secondRange === undefined || secondChunks === undefined) {
            throw new Error('test second activation range is absent');
        }
        expect(() =>
            tallyActivationRuntime.advance(
                activationContext,
                undefined,
                secondRange,
                actionKeySetBodies,
                signedActivationManifests,
                secondChunks,
            ),
        ).toThrow(ConstructionKernelCommandError);

        expect(() =>
            finalityRuntime.verifySignature(
                1,
                target.targetIdentity,
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
