import { describe, expect, it } from 'vitest';

import { deriveProtocolHash } from '#packages/crypto/src/index';
import {
    loadTranscriptCoreKernel,
    TranscriptCoreKernelCommandError,
    type TranscriptCoreKernel,
} from '#packages/wasm/src/index';
import type {
    BgvPassiveSetupPackage,
    TopKEvaluatorEncryptedAggregateEvaluationInput,
    TopKEvaluatorEncryptedAggregateEvaluationSweepInput,
    TopKEvaluatorEncryptedAggregateInput,
} from '#packages/wasm/src/transcript-core-bridge/kernel-contracts';

const setupRequest = {
    ceremonyId: 'ceremony-main',
    manifestHash: deriveProtocolHash('ElectionManifestHash', {
        manifest: 'passive-bgv-setup-test',
    }),
    rosterHash: deriveProtocolHash('RosterHash', {
        roster: 'passive-bgv-setup-test',
    }),
    thresholdProfileHash: deriveProtocolHash('ThresholdProfileHash', {
        threshold: 'passive-bgv-setup-test',
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
    setupSeed: 'passive-bgv-setup-test-seed',
} as const;

const expectKernelCommandError = (
    action: () => unknown,
): TranscriptCoreKernelCommandError => {
    try {
        action();
    } catch (error) {
        expect(error).toBeInstanceOf(TranscriptCoreKernelCommandError);

        return error as TranscriptCoreKernelCommandError;
    }

    throw new Error('Expected transcript-core kernel command to reject.');
};

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
type AlgebraicShareVerificationMaterial = {
    readonly verificationKeySet: {
        readonly algebraicShareVerificationKeySet: Record<string, unknown>;
    };
};

const validHash = (fill: string): string => fill.repeat(128);

const acceptedEvaluatorBindingFields = {
    canonicalBallotSetHash: validHash('1'),
    preTargetBoardHead: validHash('2'),
    evaluatorSignature: validHash('3'),
} as const;

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

describe('BGV passive passive BGV setup kernel commands', () => {
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
                'AlgebraicThresholdShareVerificationKeyRoot',
                'AlgebraicThresholdShareVerificationKeyHash',
            ]),
        );
        expect(
            objectModel.trustedDealerBoundary
                .transcriptValidCentralizedSecretReconstruction,
        ).toBe(false);
        expect(objectModel.statusLabels).toContain(
            'PassiveBgvSetupCanonicalObjectModelFrozen',
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
                    readonly rotationKeys: number;
                };
                readonly QPPublic: {
                    readonly exposedOnAcceptedSetupBridgeEvaluatorPath: boolean;
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
                'PassiveBgvSetupGenerated',
                'CollectivePublicKeyRootBound',
                'EvaluationKeyRootBound',
                'PassiveSetupInputReady',
                'SetupBridgeEvaluatorHeSecurityAccepted',
                'FinalTargetSecurityPendingTargetModulus',
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
        const thresholdVerificationMaterial =
            setup.thresholdVerificationMaterial as AlgebraicShareVerificationMaterial;
        expect(
            thresholdVerificationMaterial.verificationKeySet
                .algebraicShareVerificationKeySet,
        ).toMatchObject({
            objectType: 'BgvThresholdLsssShareVerificationKeySet',
            profileId:
                'sealed-lattice-bgv-threshold-lsss-share-verification-v1',
            algebraicPartDecProofStatus:
                'ZeroKnowledgeShareEquationProofPending',
            lsssSecretSharesExported: false,
        });
        expect(certificates.setupParameterCertificate).toMatchObject({
            finalSecurityStatus: 'acceptedForSetupBridgeEvaluatorTargetPending',
            largestExposedModulusBitsWithoutQTarget: 799,
        });
        expect(certificates.publicRlweSamplesByBasis.QData).toMatchObject({
            publicKeyShares: 3,
        });
        expect(
            certificates.publicRlweSamplesByBasis.QData.rotationKeys,
        ).toBeGreaterThan(0);
        expect(certificates.publicRlweSamplesByBasis.QPPublic).toMatchObject({
            exposedOnAcceptedSetupBridgeEvaluatorPath: false,
            rotationKeys: 0,
        });
        expect(
            certificates.publicRlweSamplesByBasis.QTarget.sampleCountStatus,
        ).toBe('pendingUntilFinalNoiseAnalysis');
        expect(
            setup.collectivePublicKey.collectivePublicKeyCoefficientRoot,
        ).toHaveLength(128);
        expect(
            Object.prototype.hasOwnProperty.call(
                setup.setupInputs,
                'privateSetupSeedHash',
            ),
        ).toBe(false);
        expect(
            Object.prototype.hasOwnProperty.call(setup, 'privateSetupSeedHash'),
        ).toBe(false);
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
            ok: true,
            operation: 'verifyBgvPassiveSetupPackage',
        });
        expect(verification.statusLabels).toContain(
            'PassiveBgvSetupPackageVerified',
        );
    });

    it('refuses trusted-dealer setup fields and wrong expected roots', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);

        for (const fieldName of [
            'globalSecretPolynomial',
            'trustedDealerSecret',
            'trustedDealerKeyMaterial',
            'fullSecretKey',
            'collectiveSecretKey',
            'fullSecretReconstruction',
            'thresholdSecretShares',
        ]) {
            expect(() =>
                kernel.generateBgvPassiveSetup({
                    ...setupRequest,
                    participants: [
                        {
                            ...setupRequest.participants[0],
                            [fieldName]: 'forbidden',
                        },
                        setupRequest.participants[1],
                        setupRequest.participants[2],
                    ],
                }),
            ).toThrow(TranscriptCoreKernelCommandError);
        }
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

    it('generates public evaluation-key material without exporting the private setup witness', async () => {
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
            rawSecretMaterialExported: false,
        });
        expect((material.rotationKeys as readonly unknown[]).length).toBe(0);
        expect(material.statusLabels).toEqual(
            expect.arrayContaining([
                'PublicEvaluationKeyMaterialGenerated',
                'SetupPrivateWitnessNotExported',
            ]),
        );
        const preparedMaterial = kernel.prepareBgvEvaluationKeyMaterial({
            setupPackage: setup,
            setupPrivateWitness: {
                setupSeed: setupRequest.setupSeed,
            },
            workingLevel: 1,
            rotationKeys: [],
        });
        expect(preparedMaterial).toMatchObject({
            objectType: 'PreparedBgvPublicEvaluationKeyMaterial',
            setupPackageHash: setup.setupPackageHash,
            evaluationKeyRoot: setup.evaluationKeys.evaluationKeyRoot,
            rawSecretMaterialExported: false,
            relinearizationKeyCount: 1,
            rotationKeyCount: 0,
            workingLevel: 1,
        });
        expect(
            typeof preparedMaterial.preparedEvaluationKeyMaterialHandle,
        ).toBe('string');
        expect(preparedMaterial.statusLabels).toEqual(
            expect.arrayContaining([
                'PreparedPublicEvaluationKeyMaterialGenerated',
                'PreparedEvaluationKeyMaterialHandleRegistered',
                'SetupPrivateWitnessNotExported',
            ]),
        );
        expect(
            Object.prototype.hasOwnProperty.call(
                material,
                'setupPrivateWitness',
            ),
        ).toBe(false);
        expect(
            Object.prototype.hasOwnProperty.call(
                preparedMaterial,
                'setupPrivateWitness',
            ),
        ).toBe(false);
        expect(
            Object.prototype.hasOwnProperty.call(
                material,
                'privateSetupSeedHash',
            ),
        ).toBe(false);
        expect(
            Object.prototype.hasOwnProperty.call(
                preparedMaterial,
                'privateSetupSeedHash',
            ),
        ).toBe(false);
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
        const selectedRotationRequest = arrayAtPath(setup, [
            'evaluationKeys',
            'rotationKeyRoots',
        ])[0] as
            | { readonly rotation: number; readonly level: number }
            | undefined;

        expect(selectedRotationRequest).toBeDefined();
        expect(() =>
            kernel.generateBgvEvaluationKeyMaterial({
                setupPackage: setup,
                setupPrivateWitness: {
                    setupSeed: setupRequest.setupSeed,
                },
                workingLevel: 1,
                rotationKeys: [
                    selectedRotationRequest!,
                    selectedRotationRequest!,
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
                        'pendingQTarget',
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
                            'bridgeEncryptionClaim',
                        ],
                        true,
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
            'encryptedAggregateBridgeHash',
            'encryptedAggregateTargetBasisRoot',
            'encryptedAggregateReconstructionHash',
            'scoreBitDerivationCircuitHash',
            'comparisonInputDerivationCircuitHash',
            'encryptedScoreBitInputHash',
            'encryptedComparisonInputHash',
            'bitSlicedComparatorHash',
            'encryptedSparseTargetProjectionHash',
            'targetLayoutHash',
            'passiveSetupEvaluatorContextBindingHash',
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

    it('refuses encrypted aggregate evaluation when bridge ciphertexts use the wrong setup key', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const profileBindings = setup.profileBindings as Record<string, string>;
        const wrongKeyBridgeInput: TopKEvaluatorEncryptedAggregateInput = {
            aggregateDerivationComponentHash: validHash('1'),
            aggregateDerivationStatementHash: validHash('2'),
            postVotingClosedContextHash: validHash('3'),
            bridgeEncryption: {
                profileHash: profileBindings.profileHash,
                rustBgvBackendProfileHash: profileBindings.backendProfileHash,
                canonicalCiphertextConventionHash:
                    profileBindings.canonicalCiphertextConventionHash,
                plaintextRoot: validHash('4'),
                ciphertextRoot: validHash('5'),
                collectivePublicKeyRoot: validHash('6'),
            },
        };

        expect(() =>
            kernel.runEncryptedAggregateTopKEvaluation({
                setupPackage: setup,
                evaluationKeyMaterial: {},
                aggregateReadyRecord: {},
                encryptedAggregateInputs: [
                    wrongKeyBridgeInput,
                    wrongKeyBridgeInput,
                ],
                topCount: 1,
                scoreDomainMax: 200,
                ...acceptedEvaluatorBindingFields,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('refuses encrypted aggregate evaluation outside the selected score domain', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);

        expect(() =>
            kernel.runEncryptedAggregateTopKEvaluation({
                setupPackage: setup,
                evaluationKeyMaterial: {},
                aggregateReadyRecord: {},
                encryptedAggregateInputs: [],
                topCount: 1,
                scoreDomainMax: 10,
                ...acceptedEvaluatorBindingFields,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('requires finality-bound hashes on accepted evaluator requests', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const baseRequest = {
            setupPackage: setup,
            evaluationKeyMaterial: {},
            aggregateReadyRecord: {},
            encryptedAggregateInputs: [],
            topCount: 1,
            scoreDomainMax: 200,
            ...acceptedEvaluatorBindingFields,
        } satisfies TopKEvaluatorEncryptedAggregateEvaluationInput;

        for (const fieldName of [
            'canonicalBallotSetHash',
            'preTargetBoardHead',
            'evaluatorSignature',
        ] as const) {
            const missingRequest = {
                ...baseRequest,
            } as Partial<TopKEvaluatorEncryptedAggregateEvaluationInput>;
            delete missingRequest[fieldName];
            const missingError = expectKernelCommandError(() =>
                kernel.runEncryptedAggregateTopKEvaluation(
                    missingRequest as TopKEvaluatorEncryptedAggregateEvaluationInput,
                ),
            );
            expect(missingError.message).toContain(fieldName);

            const malformedError = expectKernelCommandError(() =>
                kernel.runEncryptedAggregateTopKEvaluation({
                    ...baseRequest,
                    [fieldName]: 'ABC',
                }),
            );
            expect(malformedError.message).toContain(fieldName);
        }
    });

    it('refuses accepted evaluator requests that carry plaintext or private witnesses', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);

        for (const [fieldName, fieldValue] of [
            ['decodedTargetIdSlots', [1, 0]],
            ['plaintextRanks', [0, 1]],
            ['developmentKeySet', { keySeed: 'not-on-this-path' }],
            ['rawSecretShares', ['share-1', 'share-2']],
            [
                'trustedDealerSecret',
                { secret: 'not-on-accepted-evaluation-path' },
            ],
            ['fullSecretReconstruction', { shares: ['not', 'accepted'] }],
            ['setupPrivateWitness', { setupSeed: 'not-on-this-path' }],
            ['targetDecryptionShare', { share: 'not-yet-owned' }],
            ['evaluationProofVerified', true],
        ] as const) {
            const request = {
                setupPackage: setup,
                evaluationKeyMaterial: {},
                aggregateReadyRecord: {},
                encryptedAggregateInputs: [],
                topCount: 1,
                scoreDomainMax: 200,
                ...acceptedEvaluatorBindingFields,
                [fieldName]: fieldValue,
            } as unknown as TopKEvaluatorEncryptedAggregateEvaluationInput;

            const error = expectKernelCommandError(() =>
                kernel.runEncryptedAggregateTopKEvaluation(request),
            );
            expect(error.code).toBe('InvalidFixture');
            expect(error.message).toContain(fieldName);

            const sweepError = expectKernelCommandError(() =>
                kernel.runEncryptedAggregateTopKEvaluationSweep({
                    topCounts: [1],
                    [fieldName]: fieldValue,
                } as unknown as TopKEvaluatorEncryptedAggregateEvaluationSweepInput),
            );
            expect(sweepError.code).toBe('InvalidFixture');
            expect(sweepError.message).toContain(fieldName);
        }

        const nestedError = expectKernelCommandError(() =>
            kernel.runEncryptedAggregateTopKEvaluation({
                setupPackage: setup,
                evaluationKeyMaterial: {},
                aggregateReadyRecord: {},
                encryptedAggregateInputs: [
                    {
                        aggregateDerivationComponentHash: validHash('1'),
                        aggregateDerivationStatementHash: validHash('2'),
                        postVotingClosedContextHash: validHash('3'),
                        bridgeEncryption: {},
                        aggregateContribution: {
                            proofWitness: {
                                aggregateScore: [3, 2, 1],
                            },
                        },
                    },
                ],
                topCount: 1,
                scoreDomainMax: 200,
                ...acceptedEvaluatorBindingFields,
            }),
        );
        expect(nestedError.code).toBe('InvalidFixture');
        expect(nestedError.message).toContain(
            'encryptedAggregateInputs.0.aggregateContribution.proofWitness',
        );
    });

    it('exposes a fail-closed masked rank refresh profile and refuses evaluator refresh transcripts', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const profile = kernel.describeMaskedRankRefreshProfile();
        expect(profile.profile).toMatchObject({
            profileId: 'sealed-lattice-masked-rank-refresh-v1',
            partDecRequired: true,
            finDecRequired: true,
            semanticRankDecryptionAllowed: false,
        });

        const error = expectKernelCommandError(() =>
            kernel.runEncryptedAggregateTopKEvaluation({
                rankRefreshTranscript: {
                    objectType: 'MaskedRankRefreshTranscript',
                },
            } as unknown as TopKEvaluatorEncryptedAggregateEvaluationInput),
        );
        expect(error.code).toBe('ProfileComponentMismatch');
        expect(error.message).toContain(
            'rank refresh PartDec/FinDec share verification',
        );

        const sweepError = expectKernelCommandError(() =>
            kernel.runEncryptedAggregateTopKEvaluationSweep({
                rankRefreshTranscript: {
                    objectType: 'MaskedRankRefreshTranscript',
                },
            } as unknown as TopKEvaluatorEncryptedAggregateEvaluationSweepInput),
        );
        expect(sweepError.code).toBe('ProfileComponentMismatch');
        expect(sweepError.message).toContain(
            'rank refresh PartDec/FinDec share verification',
        );
    });

    it('refuses accepted evaluator requests with unbound top-level fields', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);

        const error = expectKernelCommandError(() =>
            kernel.runEncryptedAggregateTopKEvaluation({
                setupPackage: setup,
                evaluationKeyMaterial: {},
                aggregateReadyRecord: {},
                encryptedAggregateInputs: [],
                topCount: 1,
                scoreDomainMax: 200,
                ...acceptedEvaluatorBindingFields,
                unboundDebugArtifact: 'not-on-accepted-path',
            } as unknown as TopKEvaluatorEncryptedAggregateEvaluationInput),
        );
        expect(error.code).toBe('InvalidFixture');
        expect(error.message).toContain('unboundDebugArtifact');
    });

    it('exposes the encrypted aggregate evaluation sweep and rejects malformed top-count sets before evaluation work', async () => {
        const kernel = await loadTranscriptCoreKernel();

        expect(typeof kernel.runEncryptedAggregateTopKEvaluationSweep).toBe(
            'function',
        );

        const error = expectKernelCommandError(() =>
            kernel.runEncryptedAggregateTopKEvaluationSweep({
                topCounts: [1, 1],
            } as unknown as TopKEvaluatorEncryptedAggregateEvaluationSweepInput),
        );
        expect(error.code).toBe('InvalidFixture');
        expect(error.message).toBe(
            'InvalidFixture: topCounts must not contain duplicate values',
        );
    });

    it('refuses accepted bridge inputs with development randomness evidence', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const compactBridgeStatus = {
            bgvEncryptionKeyMaterialKind:
                'passive-transcript-derived-collective-public-key',
            developmentKeyOnly: false,
            bridgeClaimClosureVerified: true,
            bridgeClaimVerificationStatus: 'BridgeProofClaimClosureVerified',
            thresholdDecryptable: true,
            claimBearingBridgeEncryption: true,
        };
        const developmentRandomnessEvidence = {
            proverRandomnessSource: 'development-deterministic-fixture',
            encryptionRandomnessSeedSource: 'fresh-csprng',
            randomnessSourceEvidence: {
                objectType: 'AggregateBridgeRandomnessSourceEvidence',
                objectVersion: 1,
                proverRandomnessSource: 'development-deterministic-fixture',
                encryptionRandomnessSeedSource: 'fresh-csprng',
                callerSuppliedDevelopmentRandomness: true,
                claimBearingEntropyEvidence: false,
            },
        };
        const rejectedBridgeInput: TopKEvaluatorEncryptedAggregateInput = {
            aggregateDerivationComponentHash: validHash('1'),
            aggregateDerivationStatementHash: validHash('2'),
            postVotingClosedContextHash: validHash('3'),
            bridgeEncryption: {
                ...compactBridgeStatus,
                ...developmentRandomnessEvidence,
            },
            bridgeEvidenceVerification: {
                ...compactBridgeStatus,
                ...developmentRandomnessEvidence,
                bridgeProofVerificationStatus: 'BridgeProofRelationChecked',
                bridgeEvidenceVerificationStatus: 'BridgeProofEvidenceChecked',
            },
            aggregateContribution: {
                contributorRosterPosition: 1,
                aggregateContributionHash: validHash('4'),
                bridgeProofRecord: {
                    ...compactBridgeStatus,
                    ...developmentRandomnessEvidence,
                    bridgeProofVerificationStatus: 'BridgeProofRelationChecked',
                },
            },
        };

        expect(() =>
            kernel.runEncryptedAggregateTopKEvaluation({
                setupPackage: setup,
                evaluationKeyMaterial: {},
                aggregateReadyRecord: {},
                encryptedAggregateInputs: [
                    rejectedBridgeInput,
                    rejectedBridgeInput,
                ],
                topCount: 1,
                scoreDomainMax: 200,
                ...acceptedEvaluatorBindingFields,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
    });

    it('refuses accepted bridge inputs with drifted bridge proof context', async () => {
        const kernel = await loadTranscriptCoreKernel();
        const setup = kernel.generateBgvPassiveSetup(setupRequest);
        const compactBridgeStatus = {
            bgvEncryptionKeyMaterialKind:
                'passive-transcript-derived-collective-public-key',
            developmentKeyOnly: false,
            bridgeClaimClosureVerified: true,
            bridgeClaimVerificationStatus: 'BridgeProofClaimClosureVerified',
            thresholdDecryptable: true,
            claimBearingBridgeEncryption: true,
        };
        const freshRandomnessEvidence = {
            proverRandomnessSource: 'fresh-csprng',
            encryptionRandomnessSeedSource: 'fresh-csprng',
            randomnessSourceEvidence: {
                objectType: 'AggregateBridgeRandomnessSourceEvidence',
                objectVersion: 1,
                proverRandomnessSource: 'fresh-csprng',
                encryptionRandomnessSeedSource: 'fresh-csprng',
                callerSuppliedDevelopmentRandomness: false,
                claimBearingEntropyEvidence: true,
            },
        };
        const bridgeProofFields = {
            bridgeProofProfileHash: validHash('1'),
            bridgeProofStatementHash: validHash('2'),
            bridgeProofChallengeContextHash: validHash('3'),
            bridgeProofTargetContractHash: validHash('4'),
            bridgeProofBytesHash: validHash('5'),
            bridgeProofRoot: validHash('6'),
            encryptedAggregateInputRoot: validHash('7'),
            encryptedAggregateShareCiphertextRoot: validHash('8'),
            plaintextCoefficientBindingCommitmentHash: validHash('9'),
            proofFriendlyPlaintextLiftBindingHash: validHash('a'),
            collectivePublicKeyCoefficientRoot:
                setup.collectivePublicKey.collectivePublicKeyCoefficientRoot,
        };
        const rejectedBridgeInput: TopKEvaluatorEncryptedAggregateInput = {
            aggregateDerivationComponentHash: validHash('b'),
            aggregateDerivationStatementHash: validHash('c'),
            postVotingClosedContextHash: validHash('d'),
            bridgeEncryption: {
                ...compactBridgeStatus,
                ...freshRandomnessEvidence,
                ...bridgeProofFields,
                collectivePublicKeyRoot:
                    setup.collectivePublicKey.collectivePublicKeyRoot,
                bgvPublicKeyRoot: setup.collectivePublicKey.bgvPublicKeyRoot,
            },
            bridgeEvidenceVerification: {
                ...compactBridgeStatus,
                ...freshRandomnessEvidence,
                ...bridgeProofFields,
                bridgeProofVerificationStatus: 'BridgeProofRelationChecked',
                bridgeEvidenceVerificationStatus: 'BridgeProofEvidenceChecked',
            },
            aggregateContribution: {
                contributorRosterPosition: 1,
                aggregateContributionHash: validHash('e'),
                bridgeProofRecord: {
                    ...compactBridgeStatus,
                    ...freshRandomnessEvidence,
                    setupPackageHash: setup.setupPackageHash,
                    bridgeProofProfileHash:
                        bridgeProofFields.bridgeProofProfileHash,
                    proofStatementHash:
                        bridgeProofFields.bridgeProofStatementHash,
                    bridgeProofChallengeContextHash: validHash('f'),
                    bridgeProofTargetContractHash:
                        bridgeProofFields.bridgeProofTargetContractHash,
                    proofBytesHash: bridgeProofFields.bridgeProofBytesHash,
                    proofRoot: bridgeProofFields.bridgeProofRoot,
                    encryptedAggregateInputRoot:
                        bridgeProofFields.encryptedAggregateInputRoot,
                    encryptedAggregateShareCiphertextRoot:
                        bridgeProofFields.encryptedAggregateShareCiphertextRoot,
                    plaintextCoefficientBindingCommitmentHash:
                        bridgeProofFields.plaintextCoefficientBindingCommitmentHash,
                    proofFriendlyPlaintextLiftBindingHash:
                        bridgeProofFields.proofFriendlyPlaintextLiftBindingHash,
                    collectivePublicKeyRoot:
                        setup.collectivePublicKey.collectivePublicKeyRoot,
                    collectivePublicKeyCoefficientRoot:
                        setup.collectivePublicKey
                            .collectivePublicKeyCoefficientRoot,
                    bgvPublicKeyRoot:
                        setup.collectivePublicKey.bgvPublicKeyRoot,
                    bridgeProofVerificationStatus: 'BridgeProofRelationChecked',
                },
            },
        };

        expect(() =>
            kernel.runEncryptedAggregateTopKEvaluation({
                setupPackage: setup,
                evaluationKeyMaterial: {},
                aggregateReadyRecord: {},
                encryptedAggregateInputs: [
                    rejectedBridgeInput,
                    rejectedBridgeInput,
                ],
                topCount: 1,
                scoreDomainMax: 200,
                ...acceptedEvaluatorBindingFields,
            }),
        ).toThrow(TranscriptCoreKernelCommandError);
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
