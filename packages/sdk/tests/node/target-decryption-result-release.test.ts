import { beforeEach, describe, expect, it, vi } from 'vitest';

import type {
    generateTargetDecryptionShareProofMaterial,
    TargetDecryptionShareProofMaterialGenerationInput,
    TargetDecryptionResultReleaseInput,
    verifyTargetDecryptionResult,
} from '#packages/sdk/src/index.js';
import { canonicalStreamDescriptorFixture } from '#tests/support/canonical-stream-descriptor-fixture';

type JsonRecord = Record<string, unknown>;
type ProofMaterialChunkPull =
    TargetDecryptionResultReleaseInput['shareProofs'][number]['pullProofMaterialChunk'];
type CanonicalReadInput = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly descriptorBytes: Uint8Array;
    readonly family: number;
    readonly materialRoot: string;
    readonly pullChunk: ProofMaterialChunkPull;
}>;

const readCanonicalMaterial = vi.hoisted(() => vi.fn());
const openCanonicalRuntime = vi.hoisted(() => vi.fn());
const stageAggregateOpeningMaterials = vi.hoisted(() => vi.fn());

vi.mock('@sealed-lattice/wasm/published-sdk', async (importOriginal) => ({
    ...(await importOriginal<Record<string, unknown>>()),
    openBgvCanonicalStreamRuntime: openCanonicalRuntime,
    stageBgvTargetDecryptionAggregateOpeningMaterials:
        stageAggregateOpeningMaterials,
}));

let absorbedShareCount: number;
let cleanupFailure: Error | undefined;
let freshKernelLoadCount: number;
let freshKernelLoadMutation: (() => void) | undefined;
let sharedKernelLoadCount: number;
let sharedKernelLoadMutation: (() => void) | undefined;
let mockKernel: {
    readonly absorbBgvTargetDecryptionResultReleaseShare: ReturnType<
        typeof vi.fn
    >;
    readonly beginBgvTargetDecryptionResultRelease: ReturnType<typeof vi.fn>;
    readonly finishBgvTargetDecryptionResultRelease: ReturnType<typeof vi.fn>;
    readonly generateBgvTargetDecryptionShareProofMaterialFromLocalWitness: ReturnType<
        typeof vi.fn
    >;
};

vi.mock('../../src/kernel.js', () => ({
    loadFreshTranscriptCoreKernel: async () => {
        freshKernelLoadCount += 1;
        await Promise.resolve();
        freshKernelLoadMutation?.();
        return mockKernel;
    },
    loadTranscriptCoreKernel: async () => {
        sharedKernelLoadCount += 1;
        await Promise.resolve();
        sharedKernelLoadMutation?.();
        return mockKernel;
    },
}));

const publicPackage = (await import('../../src/index.js')) as Readonly<{
    readonly generateTargetDecryptionShareProofMaterial: typeof generateTargetDecryptionShareProofMaterial;
    readonly verifyTargetDecryptionResult: typeof verifyTargetDecryptionResult;
}>;

const protocolHash = (digit: string): string => digit.repeat(128);

const shareProof = (
    proofIndex: number,
    pullProofMaterialChunk: ProofMaterialChunkPull,
): TargetDecryptionResultReleaseInput['shareProofs'][number] => {
    const proofMaterial = {
        objectType: 'BgvTargetDecryptionShareProofMaterial',
        proofBytesHash: protocolHash(String(proofIndex + 1)),
    } as const;

    return {
        proofMaterial,
        proofMaterialTransport: {
            objectType:
                'BgvTargetDecryptionShareCanonicalProofMaterialTransport',
            proofBytesHash: proofMaterial.proofBytesHash,
            descriptorBytes: canonicalStreamDescriptorFixture(
                1,
                0x41 + proofIndex,
                0x51 + proofIndex,
            ),
        },
        proofStatement: { proofIndex },
        pullProofMaterialChunk,
        targetDecryptionShare: { proofIndex },
    };
};

const releaseInput = (
    pulls: readonly ProofMaterialChunkPull[],
    abortSignal?: AbortSignal,
): TargetDecryptionResultReleaseInput => ({
    ...(abortSignal === undefined ? {} : { abortSignal }),
    acceptedSetupHandle: 7,
    releaseVerificationId: 'release-verification-1',
    shareProofs: pulls.map((pull, proofIndex) => shareProof(proofIndex, pull)),
    targetAcceptedRecord: {},
    targetCiphertextBinding: {},
    targetCiphertexts: {},
    targetShareProfile: {},
});

const successfulPull = (): Promise<ArrayBuffer | undefined> =>
    Promise.resolve(Uint8Array.of(1).buffer);

const aggregateOpeningRoot = protocolHash('a');
const aggregateOpeningPullChunk = (): Promise<ArrayBuffer | undefined> =>
    Promise.resolve(new ArrayBuffer(32_768 * 8));

const proofMaterialGenerationInput =
    (): TargetDecryptionShareProofMaterialGenerationInput => ({
        aggregateOpeningMaterialSources: [
            {
                aggregateOpeningRoot,
                pullChunk: aggregateOpeningPullChunk,
                totalByteLength: 32_768 * 8,
            },
        ],
        emitProofMaterialChunk: () => Promise.resolve(),
        localTargetShareWitness: {
            aggregateOpening: {
                aggregateOpeningCredentials: [{ aggregateOpeningRoot }],
            },
        },
        proofRandomnessNonceHex: '22'.repeat(32),
        proofRandomnessSeedHex: '11'.repeat(32),
        proofStatement: {},
        setupPackage: {},
        targetAcceptedRecord: {},
        targetCiphertextBinding: {},
        targetCiphertexts: {},
        targetDecryptionShare: {},
        targetShareProfile: {},
        trusteeIdentity: 'trustee-1',
    });

describe('target-decryption result release session cleanup', () => {
    beforeEach(() => {
        absorbedShareCount = 0;
        cleanupFailure = undefined;
        freshKernelLoadCount = 0;
        freshKernelLoadMutation = undefined;
        sharedKernelLoadCount = 0;
        sharedKernelLoadMutation = undefined;
        readCanonicalMaterial.mockReset();
        stageAggregateOpeningMaterials.mockReset();
        stageAggregateOpeningMaterials.mockResolvedValue(undefined);
        openCanonicalRuntime.mockReset();
        openCanonicalRuntime.mockReturnValue({
            readMaterial: readCanonicalMaterial,
        });
        readCanonicalMaterial.mockImplementation(
            async (input: CanonicalReadInput): Promise<void> => {
                if (input.abortSignal?.aborted === true) {
                    throw new Error('canonical stream cancelled');
                }
                await input.pullChunk({
                    chunkIndex: 0,
                    expectedByteLength: 1,
                });
            },
        );
        mockKernel = {
            beginBgvTargetDecryptionResultRelease: vi.fn(() => {
                absorbedShareCount = 0;
                return {
                    requiredShareCount: 2,
                };
            }),
            absorbBgvTargetDecryptionResultReleaseShare: vi.fn(() => {
                absorbedShareCount += 1;
            }),
            finishBgvTargetDecryptionResultRelease: vi.fn(() => {
                if (absorbedShareCount < 2 && cleanupFailure !== undefined) {
                    throw cleanupFailure;
                }
                return {
                    shareEvidence: [],
                    targetIdByOption: [7],
                    targetOrderByOption: [0],
                    targetResultHash: protocolHash('7'),
                    topCount: 1,
                };
            }),
            generateBgvTargetDecryptionShareProofMaterialFromLocalWitness:
                vi.fn(),
        };
    });

    it('constructs the canonical runtime before retaining generated proof material', async () => {
        openCanonicalRuntime.mockImplementationOnce(() => {
            throw new Error('canonical runtime unavailable');
        });

        await expect(
            publicPackage.generateTargetDecryptionShareProofMaterial(
                proofMaterialGenerationInput(),
            ),
        ).rejects.toThrow('canonical runtime unavailable');
        expect(
            mockKernel.generateBgvTargetDecryptionShareProofMaterialFromLocalWitness,
        ).not.toHaveBeenCalled();
        expect(freshKernelLoadCount).toBe(1);
        expect(sharedKernelLoadCount).toBe(0);
    });

    it('snapshots proof generation input before loading the fresh kernel', async () => {
        const originalEmitProofMaterialChunk = vi.fn(() => Promise.resolve());
        const generationInput: TargetDecryptionShareProofMaterialGenerationInput =
            {
                ...proofMaterialGenerationInput(),
                emitProofMaterialChunk: originalEmitProofMaterialChunk,
                localTargetShareWitness: {
                    aggregateOpening: {
                        aggregateOpeningCredentials: [{ aggregateOpeningRoot }],
                    },
                    witness: { generation: 1 },
                },
                proofStatement: { statement: { generation: 1 } },
                setupPackage: { setup: { generation: 1 } },
                targetAcceptedRecord: { accepted: { generation: 1 } },
                targetCiphertextBinding: { binding: { generation: 1 } },
                targetCiphertexts: { ciphertexts: [{ generation: 1 }] },
                targetDecryptionShare: { share: { generation: 1 } },
                targetShareProfile: { profile: { generation: 1 } },
            };
        const mutableGenerationInput = generationInput as unknown as JsonRecord;
        freshKernelLoadMutation = () => {
            mutableGenerationInput.aggregateOpeningMaterialSources = [
                {
                    aggregateOpeningRoot: '99'.repeat(64),
                    pullChunk: vi.fn(),
                    totalByteLength: 1,
                },
            ];
            mutableGenerationInput.emitProofMaterialChunk = vi.fn();
            mutableGenerationInput.localTargetShareWitness = {
                witness: { generation: 99 },
            };
            mutableGenerationInput.proofRandomnessNonceHex = '99'.repeat(32);
            mutableGenerationInput.proofRandomnessSeedHex = '88'.repeat(32);
            mutableGenerationInput.proofStatement = {
                statement: { generation: 99 },
            };
            mutableGenerationInput.setupPackage = {
                setup: { generation: 99 },
            };
            mutableGenerationInput.targetAcceptedRecord = {
                accepted: { generation: 99 },
            };
            mutableGenerationInput.targetCiphertextBinding = {
                binding: { generation: 99 },
            };
            mutableGenerationInput.targetCiphertexts = {
                ciphertexts: [{ generation: 99 }],
            };
            mutableGenerationInput.targetDecryptionShare = {
                share: { generation: 99 },
            };
            mutableGenerationInput.targetShareProfile = {
                profile: { generation: 99 },
            };
            mutableGenerationInput.trusteeIdentity = 'trustee-99';
        };
        const generatedProofMaterial = shareProof(
            0,
            successfulPull,
        ).proofMaterial;
        mockKernel.generateBgvTargetDecryptionShareProofMaterialFromLocalWitness.mockReturnValue(
            generatedProofMaterial,
        );
        const writeMaterial = vi.fn(() =>
            Promise.resolve(canonicalStreamDescriptorFixture(1)),
        );
        openCanonicalRuntime.mockReturnValueOnce({ writeMaterial });

        await publicPackage.generateTargetDecryptionShareProofMaterial(
            generationInput,
        );

        expect(
            mockKernel.generateBgvTargetDecryptionShareProofMaterialFromLocalWitness,
        ).toHaveBeenCalledWith({
            localTargetShareWitness: {
                aggregateOpening: {
                    aggregateOpeningCredentials: [{ aggregateOpeningRoot }],
                },
                witness: { generation: 1 },
            },
            proofRandomnessNonceHex: '22'.repeat(32),
            proofRandomnessSeedHex: '11'.repeat(32),
            proofStatement: { statement: { generation: 1 } },
            setupPackage: { setup: { generation: 1 } },
            targetAcceptedRecord: { accepted: { generation: 1 } },
            targetCiphertextBinding: { binding: { generation: 1 } },
            targetCiphertexts: { ciphertexts: [{ generation: 1 }] },
            targetDecryptionShare: { share: { generation: 1 } },
            targetShareProfile: { profile: { generation: 1 } },
            trusteeIdentity: 'trustee-1',
        });
        expect(stageAggregateOpeningMaterials).toHaveBeenCalledWith({
            kernel: mockKernel,
            sources: [
                {
                    aggregateOpeningRoot,
                    pullChunk: aggregateOpeningPullChunk,
                    totalByteLength: 32_768 * 8,
                },
            ],
        });
        expect(writeMaterial).toHaveBeenCalledWith(
            expect.objectContaining({
                emitChunk: originalEmitProofMaterialChunk,
                materialRoot: generatedProofMaterial.proofBytesHash,
            }),
        );
    });

    it('rejects aggregate-opening source and witness root mismatches before staging', async () => {
        const generationInput = proofMaterialGenerationInput();
        const mismatchedInput = {
            ...generationInput,
            localTargetShareWitness: {
                aggregateOpening: {
                    aggregateOpeningCredentials: [
                        { aggregateOpeningRoot: protocolHash('b') },
                    ],
                },
            },
        } satisfies TargetDecryptionShareProofMaterialGenerationInput;

        await expect(
            publicPackage.generateTargetDecryptionShareProofMaterial(
                mismatchedInput,
            ),
        ).rejects.toThrow(/canonical credential order/u);
        expect(freshKernelLoadCount).toBe(0);
        expect(stageAggregateOpeningMaterials).not.toHaveBeenCalled();
    });

    it('uses one deep target release snapshot across kernel loading and chunk callbacks', async () => {
        const verificationInputReference: {
            current?: TargetDecryptionResultReleaseInput;
        } = {};
        const mutatingPull: ProofMaterialChunkPull = () => {
            const callerShareProof =
                verificationInputReference.current?.shareProofs[0];
            if (callerShareProof === undefined) {
                throw new Error('Missing target share proof fixture.');
            }
            const mutableShareProof = callerShareProof as unknown as JsonRecord;
            const callerProofMaterial =
                callerShareProof.proofMaterial as unknown as JsonRecord;
            const callerTransport =
                callerShareProof.proofMaterialTransport as unknown as JsonRecord;
            const callerDescriptor =
                callerTransport.descriptorBytes as Uint8Array;
            mutableShareProof.proofStatement = { proofIndex: 99 };
            mutableShareProof.targetDecryptionShare = { proofIndex: 99 };
            callerProofMaterial.objectType = 'MutatedTargetProofMaterial';
            callerProofMaterial.proofBytesHash = protocolHash('9');
            callerTransport.objectType = 'MutatedTargetProofTransport';
            callerTransport.proofBytesHash = protocolHash('8');
            callerDescriptor.fill(0xff);

            return successfulPull();
        };
        const verificationInput = releaseInput([mutatingPull, successfulPull]);
        verificationInputReference.current = verificationInput;
        const mutableVerificationInput =
            verificationInput as unknown as JsonRecord;
        mutableVerificationInput.acceptedSetupHandle = 41;
        mutableVerificationInput.targetAcceptedRecord = {
            acceptedTarget: { targetIndex: 2 },
        };
        mutableVerificationInput.targetCiphertexts = {
            ciphertextSet: { ciphertextCount: 3 },
        };
        mutableVerificationInput.targetCiphertextBinding = {
            ciphertextBinding: { bindingIndex: 4 },
        };
        mutableVerificationInput.targetShareProfile = {
            shareProfile: { threshold: 5 },
        };
        const callerShareProof = verificationInput.shareProofs[0];
        if (callerShareProof === undefined) {
            throw new Error('Missing target share proof fixture.');
        }
        const expectedProofBytesHash =
            callerShareProof.proofMaterial.proofBytesHash;
        const callerDescriptor =
            callerShareProof.proofMaterialTransport.descriptorBytes;
        const authenticatedDescriptor = callerDescriptor.slice();
        sharedKernelLoadMutation = () => {
            const targetAcceptedRecord =
                verificationInput.targetAcceptedRecord as JsonRecord;
            const targetCiphertexts =
                verificationInput.targetCiphertexts as JsonRecord;
            const targetCiphertextBinding =
                verificationInput.targetCiphertextBinding as JsonRecord;
            const targetShareProfile =
                verificationInput.targetShareProfile as JsonRecord;
            mutableVerificationInput.acceptedSetupHandle = 91;
            (targetAcceptedRecord.acceptedTarget as JsonRecord).targetIndex =
                92;
            (targetCiphertexts.ciphertextSet as JsonRecord).ciphertextCount =
                93;
            (
                targetCiphertextBinding.ciphertextBinding as JsonRecord
            ).bindingIndex = 94;
            (targetShareProfile.shareProfile as JsonRecord).threshold = 95;
            mutableVerificationInput.releaseVerificationId =
                'release-verification-mutated';
            (callerShareProof.targetDecryptionShare as JsonRecord).proofIndex =
                96;
            (callerShareProof.proofStatement as JsonRecord).proofIndex = 97;
            (
                callerShareProof.proofMaterial as unknown as JsonRecord
            ).proofBytesHash = protocolHash('6');
        };

        const result =
            await publicPackage.verifyTargetDecryptionResult(verificationInput);

        expect(result.targetResultHash).toBe(protocolHash('7'));
        expect(
            mockKernel.beginBgvTargetDecryptionResultRelease,
        ).toHaveBeenCalledWith({
            releaseVerificationId: 'release-verification-1',
            acceptedSetupHandle: 41,
            targetAcceptedRecord: {
                acceptedTarget: { targetIndex: 2 },
            },
            targetCiphertexts: {
                ciphertextSet: { ciphertextCount: 3 },
            },
            targetCiphertextBinding: {
                ciphertextBinding: { bindingIndex: 4 },
            },
            targetShareProfile: {
                shareProfile: { threshold: 5 },
            },
        });
        const firstStreamInput = readCanonicalMaterial.mock.calls[0]?.[0] as
            | CanonicalReadInput
            | undefined;
        expect(firstStreamInput).toMatchObject({
            descriptorBytes: authenticatedDescriptor,
            family: 8,
            materialRoot: expectedProofBytesHash,
        });
        expect(firstStreamInput?.descriptorBytes).not.toBe(callerDescriptor);
        const firstAbsorptionInput = mockKernel
            .absorbBgvTargetDecryptionResultReleaseShare.mock.calls[0]?.[0] as
            | JsonRecord
            | undefined;
        const absorbedShareProof = firstAbsorptionInput?.targetShareProof as
            | JsonRecord
            | undefined;
        const absorbedProofMaterial = absorbedShareProof?.proofMaterial as
            | JsonRecord
            | undefined;
        expect(absorbedShareProof).toMatchObject({
            proofStatement: { proofIndex: 0 },
            targetDecryptionShare: { proofIndex: 0 },
        });
        expect(absorbedProofMaterial).toMatchObject({
            objectType: 'BgvTargetDecryptionShareProofMaterial',
            proofBytesHash: expectedProofBytesHash,
        });
        expect(firstAbsorptionInput?.releaseVerificationId).toBe(
            'release-verification-1',
        );
        expect(callerDescriptor).toEqual(
            new Uint8Array(callerDescriptor.byteLength).fill(0xff),
        );
    });

    it('cleans an aborted pre-quorum session and permits a retry', async () => {
        const abortController = new AbortController();
        abortController.abort();

        await expect(
            publicPackage.verifyTargetDecryptionResult(
                releaseInput(
                    [successfulPull, successfulPull],
                    abortController.signal,
                ),
            ),
        ).rejects.toThrow('canonical stream cancelled');
        expect(
            mockKernel.finishBgvTargetDecryptionResultRelease,
        ).toHaveBeenCalledOnce();

        const result = await publicPackage.verifyTargetDecryptionResult(
            releaseInput([successfulPull, successfulPull]),
        );
        expect(result.targetResultHash).toBe(protocolHash('7'));
        expect(
            mockKernel.finishBgvTargetDecryptionResultRelease,
        ).toHaveBeenCalledTimes(2);
        expect(freshKernelLoadCount).toBe(0);
        expect(sharedKernelLoadCount).toBe(2);
    });

    it('preserves a pull failure and cleanup failure and permits a retry', async () => {
        const pullFailure = new Error('proof material pull failed');
        cleanupFailure = new Error('incomplete release cleanup refused');
        const failingPull = (): Promise<ArrayBuffer | undefined> =>
            Promise.reject(pullFailure);

        let observedFailure: unknown;
        try {
            await publicPackage.verifyTargetDecryptionResult(
                releaseInput([failingPull, successfulPull]),
            );
        } catch (error) {
            observedFailure = error;
        }
        expect(observedFailure).toMatchObject({
            name: 'TargetDecryptionResultReleaseCleanupError',
            cleanupFailure,
            operationFailure: pullFailure,
        });

        cleanupFailure = undefined;
        const result = await publicPackage.verifyTargetDecryptionResult(
            releaseInput([successfulPull, successfulPull]),
        );
        expect(result.targetResultHash).toBe(protocolHash('7'));
        expect(
            mockKernel.beginBgvTargetDecryptionResultRelease,
        ).toHaveBeenCalledTimes(2);
    });
});
