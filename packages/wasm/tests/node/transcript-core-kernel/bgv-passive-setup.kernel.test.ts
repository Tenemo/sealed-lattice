import { describe, expect, it } from 'vitest';

import {
    arrayAtPath,
    expectReboundSetupPackageToBeRejected,
    rebindSetupPackageHash,
    setupRequest,
    setPathValue,
    validHash,
} from './bgv-passive-setup-fixtures.js';

import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
} from '#packages/wasm/src/index';
import type { BgvPassiveSetupPackage } from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';

describe('BGV passive setup kernel commands', () => {
    it('generates deterministic full-roster passive setup material and verifies it', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const repeated = kernel.generateBgvPassiveSetup(setupRequest);
        const certificates = setup.certificates as {
            readonly publicRlweSamplesByBasis: {
                readonly QData: {
                    readonly publicKeyShares: number;
                    readonly rotationKeys: number;
                };
                readonly QPPublic: {
                    readonly rotationKeys: number;
                };
            };
        };

        expect(setup.setupPackageHash).toMatch(/^[a-f0-9]{128}$/u);
        expect(repeated.setupPackageHash).toBe(setup.setupPackageHash);
        expect(
            setup.targetDecryptionParameters.targetDecryptionParametersHash,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(
            setup.targetDecryptionParameters
                .targetDecryptionParametersBindingHash,
        ).toMatch(/^[a-f0-9]{128}$/u);
        expect(certificates.publicRlweSamplesByBasis.QData).toMatchObject({
            publicKeyShares: 3,
        });
        expect(
            certificates.publicRlweSamplesByBasis.QData.rotationKeys,
        ).toBeGreaterThan(0);
        expect(certificates.publicRlweSamplesByBasis.QPPublic).toMatchObject({
            rotationKeys: 0,
        });
        expect(
            setup.collectivePublicKey.collectivePublicKeyCoefficientRoot,
        ).toHaveLength(128);
        expect(setup.collectivePublicKey.coefficientMaterial).toMatchObject({
            objectType: 'BgvCollectivePublicKeyCoefficientMaterial',
            objectVersion: 1,
        });

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
            operation: 'verifyBgvPassiveSetupPackage',
        });
    });

    it('refuses wrong expected roots and mutated canonical bindings', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);

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

        const mutatedCoefficientSetup = {
            ...setup,
            collectivePublicKey: {
                ...setup.collectivePublicKey,
                collectivePublicKeyCoefficientRoot: '0'.repeat(128),
            },
        } as BgvPassiveSetupPackage;

        expect(() =>
            kernel.verifyBgvPassiveSetup({
                setupPackage: mutatedCoefficientSetup,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('generates public evaluation-key material and rejects the wrong setup witness', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const material = kernel.generateBgvEvaluationKeyMaterial({
            setupPackage: setup,
            setupPrivateWitness: {
                setupSeed: setupRequest.setupSeed,
            },
            workingLevel: 1,
        });

        expect(material).toMatchObject({
            objectType: 'BgvPublicEvaluationKeyMaterial',
            setupPackageHash: setup.setupPackageHash,
            evaluationKeyRoot: setup.evaluationKeys.evaluationKeyRoot,
        });
        expect((material.rotationKeys as readonly unknown[]).length).toBe(0);
        expect(() =>
            kernel.generateBgvEvaluationKeyMaterial({
                setupPackage: setup,
                setupPrivateWitness: {
                    setupSeed: 'wrong-private-setup-seed',
                },
                workingLevel: 1,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('rejects duplicate public evaluation-key rotation requests', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const selectedRotationKeyRoot = arrayAtPath(setup, [
            'evaluationKeys',
            'rotationKeyRoots',
        ])[0] as
            | { readonly rotation: number; readonly level: number }
            | undefined;

        expect(selectedRotationKeyRoot).toBeDefined();
        expect(() =>
            kernel.generateBgvEvaluationKeyMaterial({
                setupPackage: setup,
                setupPrivateWitness: {
                    setupSeed: setupRequest.setupSeed,
                },
                workingLevel: 1,
                rotationKeys: [
                    selectedRotationKeyRoot!,
                    selectedRotationKeyRoot!,
                ],
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
                'evaluation key material commitment',
                (setupPackage) =>
                    setPathValue(
                        setupPackage,
                        [
                            'evaluationKeys',
                            'evaluationKeyMaterialCommitment',
                            'record',
                            'sampledRelationChecks',
                            0,
                            'samples',
                            0,
                            'relationMatches',
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
                            'evaluationKeyStreamingCommitment',
                            'commitment',
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
            'comparisonInputDerivationCircuitHash',
            'encryptedComparisonInputHash',
            'encryptedSparseTargetProjectionHash',
            'targetLayoutHash',
            'passiveSetupEvaluatorContextBindingHash',
        ]) {
            const mutatedSetup = structuredClone(setup);
            setPathValue(
                mutatedSetup,
                ['parameterBindings', fieldName],
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

    it('refuses missing rotation keys for each selected purpose', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const selectedRotations = arrayAtPath(setup, [
            'evaluationKeys',
            'rotationKeyRoots',
        ])
            .slice(0, 4)
            .map(
                (rotationRoot) =>
                    (rotationRoot as { readonly rotation: number }).rotation,
            );

        for (const rotation of selectedRotations) {
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
            1,
        );
        expectReboundSetupPackageToBeRejected(kernel, wrongRotationGroup);
    });
});
