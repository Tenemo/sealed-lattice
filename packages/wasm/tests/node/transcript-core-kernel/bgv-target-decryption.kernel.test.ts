import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
    type BgvTargetDecryptionShareProofStatement,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';

type CompactAggregateOpeningBinding = {
    readonly witnessOwnership: string;
    readonly publicMatrixSeedHash: string;
    readonly shareLinkageStatementRoot: string;
    readonly aggregateThresholdCommitmentRoot: string;
    readonly activeCredentialBindings: readonly unknown[];
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
    it('generates and verifies target share proof statements from restored compact local state through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const fixture = kernel.generateBgvTargetDecryptionFixture();

        const seedShare = kernel.generateBgvTargetDecryptionShare({
            setupPackage: fixture.setupPackage,
            setupPrivateWitness: fixture.setupPrivateWitness,
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetCiphertextBinding: fixture.targetCiphertextBinding,
            targetCiphertexts: fixture.targetCiphertexts,
            targetShareProfile: fixture.targetShareProfile,
            trusteeIdentity: fixture.trusteeIdentity,
        });
        const localShare =
            kernel.generateBgvTargetDecryptionShareFromLocalShare({
                setupPackage: fixture.setupPackage,
                localTargetShareWitness: fixture.localTargetShareWitness,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                trusteeIdentity: fixture.trusteeIdentity,
            });

        expect(localShare).toEqual(seedShare);
        expect(localShare.sharePayload.smudgingInputReport).toMatchObject({
            objectType: 'TargetDecryptionSmudgingInputReport',
            smudgingProfileId:
                'sealed-lattice-target-decryption-zero-share-smudging-development-v1',
            zeroSharingRule:
                'smudging masks are Shamir shares of zero over each active RNS prime and cancel under target-decryption Lagrange recombination',
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

        const proofStatement =
            kernel.deriveBgvTargetDecryptionShareProofStatement({
                setupPackage: fixture.setupPackage,
                localTargetShareWitness: fixture.localTargetShareWitness,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                trusteeIdentity: fixture.trusteeIdentity,
                targetDecryptionShare: localShare,
            });
        const compactBinding =
            proofStatement.compactAggregateOpeningBinding as CompactAggregateOpeningBinding;

        expect(proofStatement).toMatchObject({
            objectType: 'BgvTargetDecryptionShareProofStatement',
            targetDecryptionShareHash: localShare.targetDecryptionShareHash,
            shareRoot: localShare.shareRoot,
            smudgingInputReportHash:
                localShare.sharePayload.smudgingInputReportHash,
            oneShotTargetContextRule:
                'one accepted target context and target ciphertext pair require one target-decryption share proof statement',
            restoredWitnessOwnershipRule:
                'the prover uses recipient-owned restored compact aggregate opening material; source credentials alone are not a target-decryption share proof witness',
            targetBasisRule:
                'the share payload, target ciphertexts, compact aggregate openings, and accepted target record use the declared canonical target basis and active target limbs',
            smudgingRequirement:
                'released smudged decryption shares require zero-knowledge proof coverage before production target-decryption activation',
            recombinationRequirement:
                'target result acceptance requires denominator-cleared Lagrange recombination and decoding-margin verification before production activation',
            proofBoundary:
                'statement binding only; production activation still requires a zero-knowledge target-decryption proof backend for restored compact openings and released smudged shares',
        });
        expect(compactBinding).toMatchObject({
            witnessOwnership: 'recipient-owned-restorable-local-state',
            publicMatrixSeedHash: '3'.repeat(128),
            shareLinkageStatementRoot: '4'.repeat(128),
            aggregateThresholdCommitmentRoot: '5'.repeat(128),
        });
        expect(compactBinding.activeCredentialBindings).toHaveLength(7);

        const verification =
            kernel.verifyBgvTargetDecryptionShareProofStatement({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: localShare,
                proofStatement,
            });

        expect(verification).toMatchObject({
            ok: true,
            operation: 'verifyBgvTargetDecryptionShareProofStatement',
            proofStatementRoot: proofStatement.proofStatementRoot,
            targetDecryptionShareHash: localShare.targetDecryptionShareHash,
            shareRoot: localShare.shareRoot,
            smudgingInputReportHash:
                localShare.sharePayload.smudgingInputReportHash,
            smudgingRequirement:
                'released smudged decryption shares require zero-knowledge proof coverage before production target-decryption activation',
            recombinationRequirement:
                'target result acceptance requires denominator-cleared Lagrange recombination and decoding-margin verification before production activation',
            proofBoundary:
                'statement binding only; production activation still requires a zero-knowledge target-decryption proof backend for restored compact openings and released smudged shares',
        });

        const reboundWrongShareRoot = rebindProofStatementRoot(kernel, {
            ...proofStatement,
            shareRoot: '0'.repeat(128),
        });
        let thrownError: unknown;
        try {
            kernel.verifyBgvTargetDecryptionShareProofStatement({
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

        const reboundWeakenedSmudgingRequirement = rebindProofStatementRoot(
            kernel,
            {
                ...proofStatement,
                smudgingRequirement:
                    'released decryption shares require no smudging',
            },
        );
        let obligationError: unknown;
        try {
            kernel.verifyBgvTargetDecryptionShareProofStatement({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: localShare,
                proofStatement: reboundWeakenedSmudgingRequirement,
            });
        } catch (error: unknown) {
            obligationError = error;
        }

        expect(obligationError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect((obligationError as TranscriptCoreKernelCommandError).code).toBe(
            'ProfileComponentMismatch',
        );

        const reboundWeakenedProofBoundary = rebindProofStatementRoot(kernel, {
            ...proofStatement,
            proofBoundary: 'statement binding only',
        });
        let proofBoundaryError: unknown;
        try {
            kernel.verifyBgvTargetDecryptionShareProofStatement({
                setupPackage: fixture.setupPackage,
                targetAcceptedRecord: fixture.targetAcceptedRecord,
                targetCiphertextBinding: fixture.targetCiphertextBinding,
                targetCiphertexts: fixture.targetCiphertexts,
                targetShareProfile: fixture.targetShareProfile,
                targetDecryptionShare: localShare,
                proofStatement: reboundWeakenedProofBoundary,
            });
        } catch (error: unknown) {
            proofBoundaryError = error;
        }

        expect(proofBoundaryError).toBeInstanceOf(
            TranscriptCoreKernelCommandError,
        );
        expect(
            (proofBoundaryError as TranscriptCoreKernelCommandError).code,
        ).toBe('ProfileComponentMismatch');
    }, 120_000);

    it('reports denominator-cleared recombination inputs through WASM', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const fixture = kernel.generateBgvTargetDecryptionFixture();
        const firstShare = kernel.generateBgvTargetDecryptionShare({
            setupPackage: fixture.setupPackage,
            setupPrivateWitness: fixture.setupPrivateWitness,
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetCiphertextBinding: fixture.targetCiphertextBinding,
            targetCiphertexts: fixture.targetCiphertexts,
            targetShareProfile: fixture.targetShareProfile,
            trusteeIdentity: 'trustee-1',
        });
        const thirdShare = kernel.generateBgvTargetDecryptionShare({
            setupPackage: fixture.setupPackage,
            setupPrivateWitness: fixture.setupPrivateWitness,
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetCiphertextBinding: fixture.targetCiphertextBinding,
            targetCiphertexts: fixture.targetCiphertexts,
            targetShareProfile: fixture.targetShareProfile,
            trusteeIdentity: 'trustee-3',
        });

        const recombined = kernel.recombineBgvTargetDecryptionShares({
            setupPackage: fixture.setupPackage,
            targetAcceptedRecord: fixture.targetAcceptedRecord,
            targetCiphertextBinding: fixture.targetCiphertextBinding,
            targetCiphertexts: fixture.targetCiphertexts,
            targetShareProfile: fixture.targetShareProfile,
            decryptionShares: [thirdShare, firstShare],
        });
        const report = recombined.recombinationInputReport;

        expect(recombined).toMatchObject({
            ok: true,
            operation: 'recombineBgvTargetDecryptionShares',
            selectedBoardPositions: [2, 3],
            selectedRosterPositions: [2, 0],
            decryptScaling: 1,
        });
        expect(report).toMatchObject({
            objectType: 'TargetDecryptionRecombinationInputReport',
            selectedShareCount: 2,
            activeRnsLimbCount: 7,
            smudgingProfileId:
                'sealed-lattice-target-decryption-zero-share-smudging-development-v1',
            smudgingCombinationRule:
                'smudging masks are Shamir shares of zero over each active RNS prime and cancel under target-decryption Lagrange recombination',
            recombinationCoefficientEquation:
                'denominatorProductModuloPrime * lagrangeCoefficientModuloPrime = numeratorProductModuloPrime mod rnsPrime',
        });
        expect(recombined.recombinationInputReportHash).toBe(
            kernel.deriveProtocolHash({
                namespace: 'TargetDecryptionRecombinationInputReportHash',
                value: report,
            }),
        );
        expect(report.activeRnsLimbReports).toHaveLength(
            report.activeRnsLimbCount,
        );
        expect(report.selectedShares[0]).toMatchObject({
            trusteeIdentity: 'trustee-3',
            boardPosition: 2,
            rosterPosition: 2,
            interpolationPoint: 3,
            shareRoot: thirdShare.shareRoot,
            targetDecryptionShareHash: thirdShare.targetDecryptionShareHash,
            smudgingInputReportHash:
                thirdShare.sharePayload.smudgingInputReportHash,
        });
        expect(report.selectedShares[1]).toMatchObject({
            trusteeIdentity: 'trustee-1',
            smudgingInputReportHash:
                firstShare.sharePayload.smudgingInputReportHash,
        });

        const firstLimbReport = report.activeRnsLimbReports[0];
        if (firstLimbReport === undefined) {
            throw new Error('expected an active recombination limb report');
        }
        expect(firstLimbReport.lagrangeTerms).toHaveLength(2);
        for (const lagrangeTerm of firstLimbReport.lagrangeTerms) {
            const checkedNumerator = Number(
                (BigInt(lagrangeTerm.denominatorProductModuloPrime) *
                    BigInt(lagrangeTerm.lagrangeCoefficientModuloPrime)) %
                    BigInt(firstLimbReport.rnsPrime),
            );
            expect(checkedNumerator).toBe(
                lagrangeTerm.numeratorProductModuloPrime,
            );
        }
        expect(report.decodingMargin.centeredPositiveMargin).toBeGreaterThan(0);
    }, 120_000);
});
