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

type MutableJsonRecord = Record<string, unknown>;
type JsonPathSegment = string | number;

const validDigest = (fill: string): string => fill.repeat(128);

const setPathValue = (
    target: unknown,
    path: readonly JsonPathSegment[],
    value: unknown,
): void => {
    let currentValue = target;
    for (const pathSegment of path.slice(0, -1)) {
        currentValue =
            typeof pathSegment === 'number'
                ? (currentValue as unknown[])[pathSegment]
                : (currentValue as MutableJsonRecord)[pathSegment];
    }
    const finalSegment = path[path.length - 1];
    if (finalSegment === undefined) {
        throw new Error('Cannot set an empty JSON path.');
    }
    if (typeof finalSegment === 'number') {
        (currentValue as unknown[])[finalSegment] = value;
    } else {
        (currentValue as MutableJsonRecord)[finalSegment] = value;
    }
};

const arrayAtPath = (
    target: unknown,
    path: readonly JsonPathSegment[],
): unknown[] => {
    let currentValue = target;
    for (const pathSegment of path) {
        currentValue =
            typeof pathSegment === 'number'
                ? (currentValue as unknown[])[pathSegment]
                : (currentValue as MutableJsonRecord)[pathSegment];
    }

    return currentValue as unknown[];
};

const expectReboundSetupPackageToBeRejected = (
    kernel: TranscriptCoreKernel,
    setupPackage: BgvPassiveSetupPackage,
): void => {
    expect(() =>
        kernel.verifyBgvPassiveSetup({
            setupPackage: rebindSetupPackageDigest(kernel, setupPackage),
        }),
    ).toThrow(TranscriptCoreKernelCommandError);
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
                'BGVPublicCommonRandomPolynomialRoot',
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

    it('refuses rebound internal binding mutations', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const mutations: readonly (readonly [
            string,
            (setupPackage: BgvPassiveSetupPackage) => void,
        ])[] = [
            [
                'BGV public key root',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        ['collectivePublicKey', 'bgvPublicKeyRoot'],
                        validDigest('0'),
                    ),
            ],
            [
                'threshold share verification key root',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        [
                            'thresholdVerificationMaterial',
                            'thresholdShareVerificationKeyRoot',
                        ],
                        validDigest('1'),
                    ),
            ],
            [
                'trustee threshold verification key digest',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        [
                            'thresholdVerificationMaterial',
                            'trusteeThresholdVerificationKeyDigests',
                            0,
                        ],
                        validDigest('2'),
                    ),
            ],
            [
                'relinearization key root',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        ['evaluationKeys', 'relinearizationKeyRoot'],
                        validDigest('3'),
                    ),
            ],
            [
                'key-switch key root',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        ['evaluationKeys', 'keySwitchKeyRoot'],
                        validDigest('4'),
                    ),
            ],
            [
                'rotation key root',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        [
                            'evaluationKeys',
                            'rotationKeyRoots',
                            0,
                            'rotationKeyRoot',
                        ],
                        validDigest('5'),
                    ),
            ],
            [
                'certificate digest',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        ['certificates', 'setupParameterCertificateDigest'],
                        validDigest('6'),
                    ),
            ],
            [
                'KLLPS claim',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        ['kllpsCompatibility', 'KLLPSPartDecImplemented'],
                        true,
                    ),
            ],
            [
                'final security status',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        [
                            'certificates',
                            'setupParameterCertificate',
                            'finalSecurityStatus',
                        ],
                        'accepted',
                    ),
            ],
            [
                'development encryption claim',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        [
                            'developmentEncryptionFixture',
                            'fixture',
                            'm9BridgeEncryptionClaim',
                        ],
                        true,
                    ),
            ],
            [
                'arithmetic fixture',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        [
                            'evaluationKeys',
                            'relinearizationArithmeticFixture',
                            'fixture',
                            'sampledCoefficientChecks',
                            0,
                            'recompositionMatches',
                        ],
                        false,
                    ),
            ],
            [
                'streaming chunk root',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        [
                            'certificates',
                            'evaluationKeyStreamingFixture',
                            'fixture',
                            'chunkRoot',
                        ],
                        validDigest('7'),
                    ),
            ],
        ];

        for (const [, mutateSetupPackage] of mutations) {
            const mutatedSetup = structuredClone(setup);
            mutateSetupPackage(mutatedSetup);
            expectReboundSetupPackageToBeRejected(kernel, mutatedSetup);
        }
    });

    it('refuses evaluator-context binding drift', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);

        for (const fieldName of [
            'encryptedAggregateBridgeDigest',
            'encryptedAggregateTargetBasisDataRoot',
            'encryptedAggregateReconstructionDigest',
            'scoreBitDerivationCircuitDigest',
            'comparisonInputDerivationCircuitDigest',
            'encryptedScoreBitInputDigest',
            'encryptedComparisonInputDigest',
            'bitSlicedComparatorDigest',
            'encryptedSparseTargetProjectionDigest',
            'm8EvaluatorContextBindingDigest',
        ]) {
            const mutatedSetup = structuredClone(setup);
            setPathValue(
                mutatedSetup,
                ['profileBindings', fieldName],
                validDigest('8'),
            );
            expectReboundSetupPackageToBeRejected(kernel, mutatedSetup);
        }
    });

    it('refuses wrong request shapes and recovery-state drift', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(() =>
            kernel.generateBgvPassiveSetup({
                ...setupRequest,
                participants: [
                    {
                        ...setupRequest.participants[0],
                        trusteeIdentity: '',
                    },
                    setupRequest.participants[1],
                    setupRequest.participants[2],
                ],
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        expect(() =>
            kernel.generateBgvPassiveSetup({
                ...setupRequest,
                participants: [
                    setupRequest.participants[0],
                    {
                        ...setupRequest.participants[1],
                        trusteeIdentity:
                            setupRequest.participants[0].trusteeIdentity,
                    },
                    setupRequest.participants[2],
                ],
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        expect(() =>
            kernel.generateBgvPassiveSetup({
                ...setupRequest,
                participants: setupRequest.participants.slice(0, 2),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
        expect(() =>
            kernel.generateBgvPassiveSetup({
                ...setupRequest,
                participants: Array.from(
                    { length: 51 },
                    (_, participantIndex) => ({
                        trusteeIdentity: `trustee-${participantIndex}`,
                        rosterPosition: participantIndex,
                    }),
                ),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);

        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        for (const mutateSetupPackage of [
            (setupPackage: BgvPassiveSetupPackage): void =>
                setPathValue(
                    setupPackage,
                    ['setupInputs', 'ceremonyId'],
                    'ceremony-stale',
                ),
            (setupPackage: BgvPassiveSetupPackage): void =>
                setPathValue(
                    setupPackage,
                    ['setupInputs', 'participantCount'],
                    4,
                ),
            (setupPackage: BgvPassiveSetupPackage): void =>
                setPathValue(
                    setupPackage,
                    ['setupInputs', 'participantIdentities', 0],
                    'trustee-clone',
                ),
            (setupPackage: BgvPassiveSetupPackage): void =>
                setPathValue(
                    setupPackage,
                    ['participants', 0, 'recoveryEpoch'],
                    99,
                ),
            (setupPackage: BgvPassiveSetupPackage): void =>
                setPathValue(
                    setupPackage,
                    ['participants', 0, 'deviceEpoch'],
                    99,
                ),
        ]) {
            const mutatedSetup = structuredClone(setup);
            mutateSetupPackage(mutatedSetup);
            expectReboundSetupPackageToBeRejected(kernel, mutatedSetup);
        }
    });

    it('refuses missing rotation keys for each provisional purpose', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);

        for (const rotation of [1, 32, 256, 4096]) {
            const mutatedSetup = structuredClone(setup);
            const rotationRoots = arrayAtPath(mutatedSetup, [
                'evaluationKeys',
                'rotationKeyRoots',
            ]);
            const rotationIndex = rotationRoots.findIndex(
                (rotationRoot) =>
                    (rotationRoot as { readonly rotation: number }).rotation ===
                    rotation,
            );
            expect(rotationIndex).toBeGreaterThanOrEqual(0);
            rotationRoots.splice(rotationIndex, 1);
            expectReboundSetupPackageToBeRejected(kernel, mutatedSetup);
        }

        const wrongRotationGroup = structuredClone(setup);
        setPathValue(
            wrongRotationGroup,
            [
                'evaluationKeys',
                'rotSet',
                'requiredRotationGroups',
                0,
                'rotations',
                0,
            ],
            3,
        );
        expectReboundSetupPackageToBeRejected(kernel, wrongRotationGroup);
    });
});
