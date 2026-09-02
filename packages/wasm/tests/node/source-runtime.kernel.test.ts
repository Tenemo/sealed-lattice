import { describe, expect, it } from 'vitest';

import {
    actionSignatureKeyGenerationRandomnessByteLength,
    actionSignatureSigningRandomnessByteLength,
    openActionSignatureRuntime,
    type ActionSignaturePurpose,
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
