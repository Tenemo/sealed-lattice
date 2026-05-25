import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
    type TranscriptCoreKernel,
} from '../../../src/index';
import type { BgvPassiveSetupPackage } from '../../../src/transcript-core-bridge/kernel-contracts';

import { deriveProtocolDigest } from '#packages/crypto/src/index';

const setupRequest = {
    ceremonyId: 'ceremony-main',
    manifestDigest: deriveProtocolDigest('ElectionManifestDigest', {
        manifest: 'm8-passive-setup-test',
    }),
    rosterDigest: deriveProtocolDigest('RosterDigest', {
        roster: 'm8-passive-setup-test',
    }),
    thresholdProfileDigest: deriveProtocolDigest('ThresholdProfileDigest', {
        threshold: 'm8-passive-setup-test',
    }),
    participants: [
        {
            trusteeIdentity: 'trustee-1',
            rosterPosition: 0,
            boardPosition: 3,
        },
        {
            trusteeIdentity: 'trustee-2',
            rosterPosition: 1,
            boardPosition: 4,
        },
        {
            trusteeIdentity: 'trustee-3',
            rosterPosition: 2,
            boardPosition: 5,
        },
    ],
    setupSeed: 'm8-passive-setup-test-seed',
} as const;

const rebindSetupPackageDigest = (
    kernel: TranscriptCoreKernel,
    setupPackage: BgvPassiveSetupPackage,
): BgvPassiveSetupPackage => {
    const digestInput = structuredClone(setupPackage) as Record<
        string,
        unknown
    >;
    delete digestInput.setupPackageDigest;

    return {
        ...setupPackage,
        setupPackageDigest: kernel.deriveProtocolDigest({
            namespace: 'BGVPassiveSetupPackageDigest',
            value: digestInput,
        }),
    };
};

describe('BGV passive M8 setup kernel commands', () => {
    it('describes the frozen passive setup object model', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const objectModel = kernel.describeBgvPassiveSetupObjectModel() as {
            readonly setupProfileId: string;
            readonly reservedRootsAndDigests: readonly string[];
            readonly trustedDealerBoundary: {
                readonly transcriptValidCentralizedSecretReconstruction: boolean;
            };
            readonly statusLabels: readonly string[];
        };

        expect(objectModel.setupProfileId).toBe(
            'sealed-lattice-bgv-rns-passive-full-roster-setup-v1',
        );
        expect(objectModel.reservedRootsAndDigests).toEqual(
            expect.arrayContaining([
                'BGVPassiveSetupPackageDigest',
                'CollectiveSecretDistributionCertificateDigest',
                'EvaluationKeySizeProfileDigest',
                'ThresholdShareVerificationKeyRoot',
            ]),
        );
        expect(
            objectModel.trustedDealerBoundary
                .transcriptValidCentralizedSecretReconstruction,
        ).toBe(false);
        expect(objectModel.statusLabels).toContain(
            'M8CanonicalObjectModelFrozen',
        );
    });

    it('generates deterministic full-roster passive setup material and verifies it', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const repeated = kernel.generateBgvPassiveSetup(setupRequest);
        const certificates = setup.certificates as {
            readonly setupParameterCertificate: {
                readonly finalSecurityStatus: string;
                readonly largestExposedModulusBitsWithoutQTarget: number;
            };
            readonly publicRlweSamplesByBasis: {
                readonly QData: {
                    readonly publicKeyShares: number;
                };
                readonly QPPublic: {
                    readonly rotationKeys: number;
                };
                readonly QTarget: {
                    readonly sampleCountStatus: string;
                };
            };
        };

        expect(setup.setupPackageDigest).toMatch(/^[a-f0-9]{128}$/u);
        expect(repeated.setupPackageDigest).toBe(setup.setupPackageDigest);
        expect(setup.statusLabels).toEqual(
            expect.arrayContaining([
                'M8PassiveSetupGenerated',
                'CollectivePublicKeyRootBound',
                'EvaluationKeyRootBound',
                'AppendixBSetupInputReady',
                'FinalAppendixBPendingQTarget',
            ]),
        );
        expect(setup.nonClaims).toContain('KLLPSPartDecNotImplemented');
        expect(setup.kllpsCompatibility).toMatchObject({
            thresholdDecryptionProfileId:
                'BGV-RNS-KLLPS26-AsyncLagrangeTarget-v1',
            setupMaterialCompatibleWithKLLPS: true,
            KLLPSPartDecImplemented: false,
            KLLPSC1C4Certified: false,
        });
        expect(certificates.setupParameterCertificate).toMatchObject({
            finalSecurityStatus: 'pendingQTarget',
            largestExposedModulusBitsWithoutQTarget: 799,
        });
        expect(certificates.publicRlweSamplesByBasis.QData).toMatchObject({
            publicKeyShares: 3,
        });
        expect(
            certificates.publicRlweSamplesByBasis.QPPublic.rotationKeys,
        ).toBeGreaterThan(0);
        expect(
            certificates.publicRlweSamplesByBasis.QTarget.sampleCountStatus,
        ).toBe('pendingUntilAppendixC');

        const verification = kernel.verifyBgvPassiveSetup({
            setupPackage: setup,
            expectedSetupPackageDigest: setup.setupPackageDigest,
            expectedRosterDigest: setupRequest.rosterDigest,
            expectedCollectivePublicKeyRoot:
                setup.collectivePublicKey.collectivePublicKeyRoot,
            expectedRotSetDigest: setup.evaluationKeys.rotSetDigest,
            expectedEvaluationKeyRoot: setup.evaluationKeys.evaluationKeyRoot,
        });

        expect(verification).toMatchObject({
            ok: true,
            operation: 'verifyBgvPassiveSetupPackage',
        });
        expect(verification.statusLabels).toContain(
            'M8PassiveSetupPackageVerified',
        );
    });

    it('refuses trusted-dealer setup fields and wrong expected roots', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);

        expect(() =>
            kernel.generateBgvPassiveSetup({
                ...setupRequest,
                participants: [
                    {
                        ...setupRequest.participants[0],
                        globalSecretPolynomial: 'forbidden',
                    },
                    setupRequest.participants[1],
                    setupRequest.participants[2],
                ],
            } as unknown as Parameters<
                typeof kernel.generateBgvPassiveSetup
            >[0]),
        ).toThrow(TranscriptCoreKernelCommandError);
        expect(() =>
            kernel.verifyBgvPassiveSetup({
                setupPackage: setup,
                expectedCollectivePublicKeyRoot: '0'.repeat(128),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        const mutatedSetup = {
            ...setup,
            collectivePublicKey: {
                ...setup.collectivePublicKey,
                collectivePublicKeyRoot: '0'.repeat(128),
            },
        } as BgvPassiveSetupPackage;

        expect(() =>
            kernel.verifyBgvPassiveSetup({
                setupPackage: mutatedSetup,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('refuses non-canonical participants and setup digests', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() =>
            kernel.generateBgvPassiveSetup({
                ...setupRequest,
                participants: [
                    setupRequest.participants[0],
                    {
                        ...setupRequest.participants[1],
                        rosterPosition: 0,
                    },
                    setupRequest.participants[2],
                ],
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        expect(() =>
            kernel.generateBgvPassiveSetup({
                ...setupRequest,
                participants: [
                    setupRequest.participants[0],
                    setupRequest.participants[1],
                    {
                        ...setupRequest.participants[2],
                        rosterPosition: 3,
                    },
                ],
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        expect(() =>
            kernel.generateBgvPassiveSetup({
                ...setupRequest,
                manifestDigest: setupRequest.manifestDigest.toUpperCase(),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('refuses internally inconsistent setup packages even when the top digest is rebound', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const inconsistentCollectiveKey = structuredClone(setup);

        (
            inconsistentCollectiveKey.collectivePublicKey.record as {
                publicKeyShareRoots: string[];
            }
        ).publicKeyShareRoots[0] = 'f'.repeat(128);

        expect(() =>
            kernel.verifyBgvPassiveSetup({
                setupPackage: rebindSetupPackageDigest(
                    kernel,
                    inconsistentCollectiveKey,
                ),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        const nestedSecretPackage = structuredClone(
            setup,
        ) as BgvPassiveSetupPackage & {
            participants: Record<string, unknown>[];
        };
        nestedSecretPackage.participants[0].globalSecretPolynomial =
            'forbidden';

        expect(() =>
            kernel.verifyBgvPassiveSetup({
                setupPackage: rebindSetupPackageDigest(
                    kernel,
                    nestedSecretPackage,
                ),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });
});
