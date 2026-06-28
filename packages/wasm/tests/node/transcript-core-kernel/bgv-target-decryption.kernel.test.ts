import { describe, expect, it } from 'vitest';

import {
    deriveTargetDecryptionSmudgingSeedHex,
    prepareLocalTargetDecryptionShareWitness,
} from '#packages/protocol/src/target-decryption/local-target-share-witness';
import {
    encodeBgvTargetDecryptionShareProofMaterialBinary,
    type BgvTargetDecryptionShareProofMaterial,
} from '#packages/protocol/src/target-decryption/proof-material-transport';
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
    type BgvTargetDecryptionShareProofStatement,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

type CompactAggregateOpeningBinding = {
    readonly publicMatrixSeedHash: string;
    readonly shareLinkageStatementRoot: string;
    readonly aggregateThresholdCommitmentRoot: string;
    readonly activeCredentialBindingRoot: string;
    readonly activeCredentialBindings: readonly unknown[];
};

type CompactAggregateCredentialBinding = {
    readonly aggregateCommitment: unknown;
};

type CompactAggregateOpeningWitnessCredentials = {
    compactAggregateOpening: {
        compactAggregateOpeningCredentials: unknown[];
    };
};

type CompactAggregateOpeningWitnessSeed = {
    compactAggregateOpening: {
        publicMatrixSeedHash: string;
    };
};

type CompactAggregateOpeningWitnessForMutation =
    CompactAggregateOpeningWitnessCredentials &
        CompactAggregateOpeningWitnessSeed;

type CompactAggregateOpeningWitnessContainer = {
    compactAggregateOpening?: unknown;
};

type SetupPackageWithCommonRandomness = {
    commonRandomness: {
        publicMatrixSeedHash: string;
    };
};

type SetupPackageWithCompactAggregateSet = {
    compactVssShareLinkageStatement: {
        statementRoot: string;
    };
    compactVssAggregateThresholdCommitmentSet: {
        aggregateThresholdCommitmentRoot: string;
        rnsLimbCount: number;
        recipientRecords: readonly {
            readonly commitment: unknown;
        }[];
    };
};

const rebindProofStatementRoot = (
    kernel: TranscriptCoreKernel,
    proofStatement: BgvTargetDecryptionShareProofStatement,
): BgvTargetDecryptionShareProofStatement => {
    const statementWithoutRoot = {
        ...proofStatement,
    } as Record<string, unknown>;
    delete statementWithoutRoot.proofStatementRoot;

    return {
        ...proofStatement,
        proofStatementRoot: kernel.deriveProtocolHash({
            namespace: 'BgvTargetDecryptionShareProofStatementRoot',
            value: statementWithoutRoot,
        }),
    };
};

describe('BGV target-decryption kernel commands', () => {
    it('generates target share proof statements and checks their bindings from restored compact local state through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const fixture = kernel.generateBgvTargetDecryptionDevelopmentFixture();
        const setupPublicMatrixSeedHash = (
            fixture.setupPackage as unknown as SetupPackageWithCommonRandomness
        ).commonRandomness.publicMatrixSeedHash;
        const targetDecryptionCiphertextHash = (
            fixture.targetAcceptedRecord as {
                readonly targetCiphertextHash: string;
            }
        ).targetCiphertextHash;
        const restoredCompactLocalWitness = structuredClone(
            fixture.localTargetShareWitness,
        );
        const kernelGeneratedSmudgingWitness =
            restoredCompactLocalWitness.targetDecryptionSmudging as
                | { readonly smudgingSeedHex?: unknown }
                | undefined;
        delete restoredCompactLocalWitness.targetDecryptionSmudging;
        const derivedSmudgingSeedHex = deriveTargetDecryptionSmudgingSeedHex({
            localSmudgingSeedMaterial: fixture.setupPrivateWitness.setupSeed,
            setupPackage: fixture.setupPackage,
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetDecryptionCiphertextHash,
            targetShareProfile: fixture.targetShareProfile,
        });
        expect(
            deriveTargetDecryptionSmudgingSeedHex({
                localSmudgingSeedMaterial:
                    fixture.setupPrivateWitness.setupSeed,
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetDecryptionCiphertextHash: 'a'.repeat(128),
                targetShareProfile: fixture.targetShareProfile,
            }),
        ).not.toBe(derivedSmudgingSeedHex);
        const preparedLocalTargetShareWitness =
            prepareLocalTargetDecryptionShareWitness({
                restoredLocalTargetShareWitness: restoredCompactLocalWitness,
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetDecryptionCiphertextHash,
                targetShareProfile: fixture.targetShareProfile,
                trusteeIdentity: fixture.trusteeIdentity,
                localSmudgingSeedMaterial:
                    fixture.setupPrivateWitness.setupSeed,
            });

        const localShare =
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: fixture.setupPackage,
                localTargetShareWitness: preparedLocalTargetShareWitness,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                trusteeIdentity: fixture.trusteeIdentity,
            });

        expect(kernelGeneratedSmudgingWitness?.smudgingSeedHex).toBe(
            derivedSmudgingSeedHex,
        );
        expect(
            preparedLocalTargetShareWitness.targetDecryptionSmudging,
        ).toEqual(kernelGeneratedSmudgingWitness);
        expect(
            preparedLocalTargetShareWitness.targetDecryptionSmudging
                .targetDecryptionCiphertextHash,
        ).toBe(targetDecryptionCiphertextHash);
        expect(() =>
            prepareLocalTargetDecryptionShareWitness({
                restoredLocalTargetShareWitness:
                    fixture.localTargetShareWitness,
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetDecryptionCiphertextHash,
                targetShareProfile: fixture.targetShareProfile,
                trusteeIdentity: fixture.trusteeIdentity,
                localSmudgingSeedMaterial:
                    fixture.setupPrivateWitness.setupSeed,
            }),
        ).toThrow(/already contains target-decryption smudging material/u);
        expect(localShare.sharePayload.smudgingInputReport).toMatchObject({
            objectType: 'TargetDecryptionSmudgingInputReport',
            smudgingProfileId:
                'sealed-lattice-target-decryption-zero-share-smudging-development-v1',
        });
        expect(
            localShare.sharePayload.smudgingInputReport.roleReports,
        ).toHaveLength(2);
        expect(localShare.sharePayload.smudgingInputReportHash).toBe(
            kernel.deriveProtocolHash({
                namespace: 'TargetDecryptionSmudgingInputReportHash',
                value: localShare.sharePayload.smudgingInputReport,
            }),
        );

        const localWitnessWithoutCompactOpening = structuredClone(
            preparedLocalTargetShareWitness,
        ) as CompactAggregateOpeningWitnessContainer;
        delete localWitnessWithoutCompactOpening.compactAggregateOpening;
        let missingCompactOpeningError: unknown;
        try {
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: fixture.setupPackage,
                localTargetShareWitness: localWitnessWithoutCompactOpening,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                trusteeIdentity: fixture.trusteeIdentity,
            });
        } catch (error: unknown) {
            missingCompactOpeningError = error;
        }
        expect(missingCompactOpeningError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (missingCompactOpeningError as TranscriptCoreKernelCommandError)
                .code,
        ).toBe('InvalidFixture');
        expect(
            (missingCompactOpeningError as TranscriptCoreKernelCommandError)
                .message,
        ).toContain('compactAggregateOpening');

        const localWitnessWithoutOneOpeningCredential = structuredClone(
            preparedLocalTargetShareWitness,
        ) as typeof preparedLocalTargetShareWitness &
            CompactAggregateOpeningWitnessForMutation;
        localWitnessWithoutOneOpeningCredential.compactAggregateOpening.compactAggregateOpeningCredentials =
            localWitnessWithoutOneOpeningCredential.compactAggregateOpening.compactAggregateOpeningCredentials.slice(
                1,
            );
        let missingOpeningCredentialError: unknown;
        try {
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: fixture.setupPackage,
                localTargetShareWitness:
                    localWitnessWithoutOneOpeningCredential,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                trusteeIdentity: fixture.trusteeIdentity,
            });
        } catch (error: unknown) {
            missingOpeningCredentialError = error;
        }
        expect(missingOpeningCredentialError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (missingOpeningCredentialError as TranscriptCoreKernelCommandError)
                .code,
        ).toBe('MalformedLength');
        expect(
            (missingOpeningCredentialError as TranscriptCoreKernelCommandError)
                .message,
        ).toContain('missing active limb');

        const localWitnessWithWrongPublicMatrixSeed = structuredClone(
            preparedLocalTargetShareWitness,
        ) as typeof preparedLocalTargetShareWitness &
            CompactAggregateOpeningWitnessForMutation;
        localWitnessWithWrongPublicMatrixSeed.compactAggregateOpening.publicMatrixSeedHash =
            '0'.repeat(128);
        let wrongPublicMatrixSeedError: unknown;
        try {
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: fixture.setupPackage,
                localTargetShareWitness: localWitnessWithWrongPublicMatrixSeed,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                trusteeIdentity: fixture.trusteeIdentity,
            });
        } catch (error: unknown) {
            wrongPublicMatrixSeedError = error;
        }
        expect(wrongPublicMatrixSeedError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (wrongPublicMatrixSeedError as TranscriptCoreKernelCommandError)
                .code,
        ).toBe('ProfileComponentMismatch');
        expect(
            (wrongPublicMatrixSeedError as TranscriptCoreKernelCommandError)
                .message,
        ).toContain('public matrix seed');

        const proofStatement =
            kernel.deriveBgvTargetDecryptionShareProofStatement({
                setupPackage: fixture.setupPackage,
                localTargetShareWitness: preparedLocalTargetShareWitness,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                trusteeIdentity: fixture.trusteeIdentity,
                targetDecryptionShare: localShare,
            });
        const compactBinding =
            proofStatement.compactAggregateOpeningBinding as CompactAggregateOpeningBinding;
        const acceptedAggregateThresholdCommitmentRoot = (
            fixture.setupPackage as unknown as SetupPackageWithCompactAggregateSet
        ).compactVssAggregateThresholdCommitmentSet
            .aggregateThresholdCommitmentRoot;
        const acceptedShareLinkageStatementRoot = (
            fixture.setupPackage as unknown as SetupPackageWithCompactAggregateSet
        ).compactVssShareLinkageStatement.statementRoot;

        expect(proofStatement).toMatchObject({
            objectType: 'BgvTargetDecryptionShareProofStatement',
            targetDecryptionShareHash: localShare.targetDecryptionShareHash,
            shareRoot: localShare.shareRoot,
            smudgingInputReportHash:
                localShare.sharePayload.smudgingInputReportHash,
        });
        expect(compactBinding).toMatchObject({
            publicMatrixSeedHash: setupPublicMatrixSeedHash,
            shareLinkageStatementRoot: acceptedShareLinkageStatementRoot,
            aggregateThresholdCommitmentRoot:
                acceptedAggregateThresholdCommitmentRoot,
            activeCredentialBindingRoot: kernel.deriveProtocolHash({
                namespace:
                    'TargetDecryptionCompactAggregateOpeningCredentialBindingRoot',
                value: {
                    objectType:
                        'TargetDecryptionCompactAggregateOpeningCredentialBindingSet',
                    objectVersion: 1,
                    activeCredentialBindings:
                        compactBinding.activeCredentialBindings,
                },
            }),
        });
        expect(compactBinding.activeCredentialBindings).toHaveLength(7);
        const activeCredentialBindings =
            compactBinding.activeCredentialBindings as readonly CompactAggregateCredentialBinding[];
        const acceptedAggregateSet = (
            fixture.setupPackage as unknown as SetupPackageWithCompactAggregateSet
        ).compactVssAggregateThresholdCommitmentSet;
        activeCredentialBindings.forEach(
            (activeCredentialBinding, limbIndex) => {
                const acceptedRecordIndex =
                    proofStatement.rosterPosition *
                        acceptedAggregateSet.rnsLimbCount +
                    limbIndex;
                expect(activeCredentialBinding.aggregateCommitment).toEqual(
                    acceptedAggregateSet.recipientRecords[acceptedRecordIndex]
                        ?.commitment,
                );
            },
        );

        const verification =
            kernel.verifyBgvTargetDecryptionShareProofStatementBinding({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: localShare,
                proofStatement,
            });

        expect(verification).toMatchObject({
            ok: false,
            operation: 'verifyBgvTargetDecryptionShareProofStatementBinding',
            refusalReason: 'TargetDecryptionProofUnavailable',
        });

        let invalidProofMaterialGenerationError: unknown;
        try {
            kernel.generateBgvTargetDecryptionShareProofMaterialFromLocalWitness(
                {
                    setupPackage: fixture.setupPackage,
                    localTargetShareWitness: preparedLocalTargetShareWitness,
                    targetAcceptedRecord: fixture.targetAcceptedRecord,
                    targetCiphertextBinding: fixture.targetCiphertextBinding,
                    targetCiphertexts: fixture.targetCiphertexts,
                    targetShareProfile: fixture.targetShareProfile,
                    trusteeIdentity: fixture.trusteeIdentity,
                    targetDecryptionShare: localShare,
                    proofStatement,
                    proofRandomnessSeedHex: '11'.repeat(63),
                    proofRandomnessNonceHex: '22'.repeat(64),
                },
            );
        } catch (error: unknown) {
            invalidProofMaterialGenerationError = error;
        }
        expect(invalidProofMaterialGenerationError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (
                invalidProofMaterialGenerationError as TranscriptCoreKernelCommandError
            ).code,
        ).toBe('InvalidProtocolObject');
        expect(
            (
                invalidProofMaterialGenerationError as TranscriptCoreKernelCommandError
            ).message,
        ).toContain('proofRandomnessSeedHex');

        let missingProofMaterialRootError: unknown;
        const malformedProofMaterial = {
            objectType: 'BgvTargetDecryptionShareProofMaterial',
            objectVersion: 8,
        } as unknown as Parameters<
            TranscriptCoreKernel['verifyBgvTargetDecryptionShareProofMaterial']
        >[0]['proofMaterial'];
        try {
            kernel.verifyBgvTargetDecryptionShareProofMaterial({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: localShare,
                proofStatement,
                proofMaterial: malformedProofMaterial,
            });
        } catch (error: unknown) {
            missingProofMaterialRootError = error;
        }
        expect(missingProofMaterialRootError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (missingProofMaterialRootError as TranscriptCoreKernelCommandError)
                .code,
        ).toBe('InvalidFixture');
        expect(
            (missingProofMaterialRootError as TranscriptCoreKernelCommandError)
                .message,
        ).toContain('proofMaterialRoot');

        const fakeProofMaterialWithoutRoot = {
            objectType: 'BgvTargetDecryptionShareProofMaterial',
            objectVersion: 8,
            proofRecords: [
                {
                    objectType: 'BgvTargetDecryptionShareProofRecord',
                    objectVersion: 7,
                    proofBytesBase64: 'AQIDBAU=',
                },
            ],
        } as const;
        const fakeProofMaterial = {
            ...fakeProofMaterialWithoutRoot,
            proofMaterialRoot: kernel.deriveProtocolHash({
                namespace: 'TargetDecryptionShareProofMaterialRoot',
                value: fakeProofMaterialWithoutRoot,
            }),
        } satisfies BgvTargetDecryptionShareProofMaterial;
        const transportedFakeProofMaterial =
            encodeBgvTargetDecryptionShareProofMaterialBinary(
                fakeProofMaterial,
            );
        const tamperedChunk = Uint8Array.from(
            transportedFakeProofMaterial.chunks[0] ?? new Uint8Array(),
        );
        tamperedChunk[tamperedChunk.length - 1] ^= 1;
        let tamperedBinaryProofMaterialError: unknown;
        try {
            kernel.verifyBgvTargetDecryptionShareBinaryProofMaterial({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: localShare,
                proofStatement,
                transportedProofMaterial: {
                    ...transportedFakeProofMaterial,
                    chunks: [tamperedChunk],
                },
            });
        } catch (error: unknown) {
            tamperedBinaryProofMaterialError = error;
        }
        expect(tamperedBinaryProofMaterialError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (
                tamperedBinaryProofMaterialError as TranscriptCoreKernelCommandError
            ).code,
        ).toBe('ProfileComponentMismatch');
        expect(
            (
                tamperedBinaryProofMaterialError as TranscriptCoreKernelCommandError
            ).message,
        ).toContain('fullObjectHash');

        let wrongChunkCountBinaryProofMaterialError: unknown;
        try {
            kernel.verifyBgvTargetDecryptionShareBinaryProofMaterial({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: localShare,
                proofStatement,
                transportedProofMaterial: {
                    ...transportedFakeProofMaterial,
                    chunkCount: transportedFakeProofMaterial.chunkCount + 1,
                },
            });
        } catch (error: unknown) {
            wrongChunkCountBinaryProofMaterialError = error;
        }
        expect(wrongChunkCountBinaryProofMaterialError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (
                wrongChunkCountBinaryProofMaterialError as TranscriptCoreKernelCommandError
            ).code,
        ).toBe('MalformedLength');
        expect(
            (
                wrongChunkCountBinaryProofMaterialError as TranscriptCoreKernelCommandError
            ).message,
        ).toContain('chunkCount');

        expect(kernel.verifyTargetDecryptionResult()).toEqual({
            ok: false,
            operation: 'verifyTargetDecryptionResult',
            refusalReason: 'CompactVssPublicMaterialNotBinding',
        });

        const reboundWrongShareRoot = rebindProofStatementRoot(kernel, {
            ...proofStatement,
            shareRoot: '0'.repeat(128),
        });
        let thrownError: unknown;
        try {
            kernel.verifyBgvTargetDecryptionShareProofStatementBinding({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: localShare,
                proofStatement: reboundWrongShareRoot,
            });
        } catch (error: unknown) {
            thrownError = error;
        }

        expect(thrownError).toBeInstanceOf(TranscriptCoreKernelCommandError);
        expect((thrownError as TranscriptCoreKernelCommandError).code).toBe(
            'ProfileComponentMismatch',
        );
    }, 120_000);
});
