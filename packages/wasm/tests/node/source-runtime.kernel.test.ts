import { describe, expect, it } from 'vitest';

import { openActionKeySetRuntime } from '../../src/action-key-set-runtime.js';
import {
    actionSignatureKeyByteLength,
    openActionSignatureRuntime,
} from '../../src/action-signature-runtime.js';
import { ConstructionKernelCommandError } from '../../src/construction-kernel-command-runtime.js';
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
        const correctionZero = sourceRuntime.deriveHonestCorrection(
            0,
            0,
            sourcePreparation.heldSubsetKeys,
        );
        const correctionOne = sourceRuntime.deriveHonestCorrection(
            0,
            1,
            sourcePreparation.heldSubsetKeys,
        );
        expect(correctionZero ^ correctionOne).toBe(0b11);

        const submittedContext = {
            ...sourcePreparationContext,
            verifiedPreparationRoot: sourcePreparation.root,
            senderPosition: 0,
        } as const;
        const submitted = sourceRuntime.encodeBody(
            submittedContext,
            'submit',
            correctionOne,
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
            correction: correctionOne,
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

        const corruptVariant = sourceRuntime.encodeBody(
            submittedContext,
            'submit',
            0b01,
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
        ).toBe(0b01);

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
            sourceRuntime.encodeBody(submittedContext, 'submit', 4),
        ).toThrow(RangeError);
    });
});
