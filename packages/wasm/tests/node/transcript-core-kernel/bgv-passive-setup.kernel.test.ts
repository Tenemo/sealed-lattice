import { describe, expect, it } from 'vitest';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
    type TranscriptCoreKernel,
} from '../../../src/index';
import type { BgvPassiveSetupPackage } from '../../../src/transcript-core-bridge/kernel-contracts';

import { deriveProtocolHash } from '#packages/crypto/src/index';

const setupRequest = {
    ceremonyId: 'ceremony-main',
    manifestHash: deriveProtocolHash('ElectionManifestHash', {
        manifest: 'm8-passive-setup-test',
    }),
    rosterHash: deriveProtocolHash('RosterHash', {
        roster: 'm8-passive-setup-test',
    }),
    thresholdProfileHash: deriveProtocolHash('ThresholdProfileHash', {
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

const rebindSetupPackageHash = (
    kernel: TranscriptCoreKernel,
    setupPackage: BgvPassiveSetupPackage,
): BgvPassiveSetupPackage => {
    const hashInput = structuredClone(setupPackage) as Record<string, unknown>;
    delete hashInput.setupPackageHash;

    return {
        ...setupPackage,
        setupPackageHash: kernel.deriveProtocolHash({
            namespace: 'BGVPassiveSetupPackageHash',
            value: hashInput,
        }),
    };
};

type MutableJsonRecord = Record<string, unknown>;
type JsonPathSegment = string | number;

const validHash = (fill: string): string => fill.repeat(128);

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
            setupPackage: rebindSetupPackageHash(kernel, setupPackage),
        }),
    ).toThrow(TranscriptCoreKernelCommandError);
};

describe('BGV passive M8 setup kernel commands', () => {
    it('describes the frozen passive setup object model', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const objectModel = kernel.describeBgvPassiveSetupObjectModel() as {
            readonly setupProfileId: string;
            readonly reservedRootsAndHashes: readonly string[];
            readonly trustedDealerBoundary: {
                readonly transcriptValidCentralizedSecretReconstruction: boolean;
            };
            readonly statusLabels: readonly string[];
        };

        expect(objectModel.setupProfileId).toBe(
            'sealed-lattice-bgv-rns-passive-full-roster-setup-v1',
        );
        expect(objectModel.reservedRootsAndHashes).toEqual(
            expect.arrayContaining([
                'BGVPassiveSetupPackageHash',
                'CollectiveSecretDistributionCertificateHash',
                'BGVPublicCommonRandomPolynomialRoot',
                'EvaluationKeySizeProfileHash',
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

        expect(setup.setupPackageHash).toMatch(/^[a-f0-9]{128}$/u);
        expect(repeated.setupPackageHash).toBe(setup.setupPackageHash);
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
        expect(setup.kllpsStatus).toMatchObject({
            thresholdDecryptionProfileId:
                'BGV-RNS-KLLPS26-AsyncLagrangeTarget-v1',
            setupMaterialMatchesKLLPS: true,
            KLLPSPartDecStatusImplemented: false,
            KLLPSC1C4StatusAccepted: false,
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
            expectedSetupPackageHash: setup.setupPackageHash,
            expectedRosterHash: setupRequest.rosterHash,
            expectedCollectivePublicKeyRoot:
                setup.collectivePublicKey.collectivePublicKeyRoot,
            expectedRotSetHash: setup.evaluationKeys.rotSetHash,
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

    it('refuses non-canonical participants and setup Hashes', async () => {
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
                manifestHash: setupRequest.manifestHash.toUpperCase(),
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('refuses internally inconsistent setup packages even when the top hash is rebound', async () => {
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
                setupPackage: rebindSetupPackageHash(
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
                setupPackage: rebindSetupPackageHash(
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
                        validHash('0'),
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
                        validHash('1'),
                    ),
            ],
            [
                'trustee threshold verification key hash',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        [
                            'thresholdVerificationMaterial',
                            'trusteeThresholdVerificationKeyHashes',
                            0,
                        ],
                        validHash('2'),
                    ),
            ],
            [
                'relinearization key root',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        ['evaluationKeys', 'relinearizationKeyRoot'],
                        validHash('3'),
                    ),
            ],
            [
                'key-switch key root',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        ['evaluationKeys', 'keySwitchKeyRoot'],
                        validHash('4'),
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
                        validHash('5'),
                    ),
            ],
            [
                'certificate hash',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        ['certificates', 'setupParameterCertificateHash'],
                        validHash('6'),
                    ),
            ],
            [
                'KLLPS claim',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        ['kllpsStatus', 'KLLPSPartDecStatusImplemented'],
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
                        validHash('7'),
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
            'encryptedAggregateBridgeHash',
            'encryptedAggregateTargetBasisRoot',
            'encryptedAggregateReconstructionHash',
            'scoreBitDerivationCircuitHash',
            'comparisonInputDerivationCircuitHash',
            'encryptedScoreBitInputHash',
            'encryptedComparisonInputHash',
            'bitSlicedComparatorHash',
            'encryptedSparseTargetProjectionHash',
            'm8EvaluatorContextBindingHash',
        ]) {
            const mutatedSetup = structuredClone(setup);
            setPathValue(
                mutatedSetup,
                ['profileBindings', fieldName],
                validHash('8'),
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
