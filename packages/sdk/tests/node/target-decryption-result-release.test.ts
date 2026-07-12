import { beforeEach, describe, expect, it, vi } from 'vitest';

import { deriveCanonicalObjectHash } from '#packages/crypto/src/index';
import type {
    generateTargetDecryptionShareProofMaterial,
    TargetDecryptionShareProofMaterialGenerationInput,
    TargetDecryptionResultReleaseInput,
    verifyTargetDecryptionResult,
} from '#packages/sdk/src/index.js';

type ProofMaterialChunkPull =
    TargetDecryptionResultReleaseInput['shareProofs'][number]['pullProofMaterialChunk'];
type CanonicalReadInput = Readonly<{
    readonly abortSignal?: AbortSignal;
    readonly pullChunk: ProofMaterialChunkPull;
}>;

const readCanonicalMaterial = vi.hoisted(() => vi.fn());
const openCanonicalRuntime = vi.hoisted(() => vi.fn());

vi.mock(
    '../../dist/internal/transcript-core-bridge.js',
    async (importOriginal) => ({
        ...(await importOriginal<Record<string, unknown>>()),
        openBgvCanonicalStreamRuntime: openCanonicalRuntime,
    }),
);

let absorbedShareCount: number;
let cleanupFailure: Error | undefined;
let freshKernelLoadCount: number;
let sharedKernelLoadCount: number;
let mockKernel: {
    readonly absorbBgvTargetDecryptionResultReleaseShare: ReturnType<
        typeof vi.fn
    >;
    readonly beginBgvTargetDecryptionResultRelease: ReturnType<typeof vi.fn>;
    readonly deriveBgvTargetDecryptionResultReleaseSetupContext: ReturnType<
        typeof vi.fn
    >;
    readonly finishBgvTargetDecryptionResultRelease: ReturnType<typeof vi.fn>;
    readonly generateBgvTargetDecryptionShareProofMaterialFromLocalWitness: ReturnType<
        typeof vi.fn
    >;
};

vi.mock('../../dist/kernel.js', () => ({
    loadFreshTranscriptCoreKernel: () => {
        freshKernelLoadCount += 1;
        return Promise.resolve(mockKernel);
    },
    loadTranscriptCoreKernel: () => {
        sharedKernelLoadCount += 1;
        return Promise.resolve(mockKernel);
    },
}));

const publicPackage = (await import('../../dist/index.js')) as Readonly<{
    readonly generateTargetDecryptionShareProofMaterial: typeof generateTargetDecryptionShareProofMaterial;
    readonly verifyTargetDecryptionResult: typeof verifyTargetDecryptionResult;
}>;

const protocolHash = (digit: string): string => digit.repeat(128);

const shareProof = (
    proofIndex: number,
    pullProofMaterialChunk: ProofMaterialChunkPull,
): TargetDecryptionResultReleaseInput['shareProofs'][number] => {
    const proofRecord = {
        objectType: 'BgvTargetDecryptionShareProofRecord',
        proofBytesEncoding: 'binary-chunked-proof-bytes',
        proofBytesHash: protocolHash(String(proofIndex + 1)),
    };
    const proofMaterialWithoutRoot = {
        objectType: 'BgvTargetDecryptionShareProofMaterial',
        proofRecords: [proofRecord],
    } as const;
    const proofMaterial = {
        ...proofMaterialWithoutRoot,
        proofMaterialRoot: deriveCanonicalObjectHash(proofMaterialWithoutRoot),
    } as const;

    return {
        proofMaterial,
        proofMaterialTransport: {
            objectType:
                'BgvTargetDecryptionShareCanonicalProofMaterialTransport',
            proofFamily: 'target-decryption-share',
            proofMaterialRoot: proofMaterial.proofMaterialRoot,
            descriptorBytes: Uint8Array.of(proofIndex + 1),
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
    releaseVerificationId: 'release-verification-1',
    setupPackage: {},
    shareProofs: pulls.map((pull, proofIndex) => shareProof(proofIndex, pull)),
    targetAcceptedRecord: {},
    targetCiphertextBinding: {},
    targetCiphertexts: {},
    targetShareProfile: {},
});

const successfulPull = (): Promise<ArrayBuffer | undefined> =>
    Promise.resolve(Uint8Array.of(1).buffer);

const proofMaterialGenerationInput =
    (): TargetDecryptionShareProofMaterialGenerationInput => ({
        emitProofMaterialChunk: () => Promise.resolve(),
        localTargetShareWitness: {},
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
        sharedKernelLoadCount = 0;
        readCanonicalMaterial.mockReset();
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
            deriveBgvTargetDecryptionResultReleaseSetupContext: vi.fn(() => ({
                operation: 'deriveBgvTargetDecryptionResultReleaseSetupContext',
            })),
            beginBgvTargetDecryptionResultRelease: vi.fn(() => {
                absorbedShareCount = 0;
                return {
                    operation: 'beginBgvTargetDecryptionResultRelease',
                    requiredShareCount: 2,
                };
            }),
            absorbBgvTargetDecryptionResultReleaseShare: vi.fn(() => {
                absorbedShareCount += 1;
                return {
                    absorbedShareCount,
                    operation: 'absorbBgvTargetDecryptionResultReleaseShare',
                    requiredShareCount: 2,
                };
            }),
            finishBgvTargetDecryptionResultRelease: vi.fn(() => {
                if (absorbedShareCount < 2 && cleanupFailure !== undefined) {
                    throw cleanupFailure;
                }
                return {
                    operation: 'finishBgvTargetDecryptionResultRelease',
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

    it('cleans a session when canonical runtime construction fails after begin', async () => {
        openCanonicalRuntime.mockImplementationOnce(() => {
            throw new Error('canonical runtime unavailable');
        });

        await expect(
            publicPackage.verifyTargetDecryptionResult(
                releaseInput([successfulPull, successfulPull]),
            ),
        ).rejects.toThrow('canonical runtime unavailable');
        expect(
            mockKernel.finishBgvTargetDecryptionResultRelease,
        ).toHaveBeenCalledOnce();

        const result = await publicPackage.verifyTargetDecryptionResult(
            releaseInput([successfulPull, successfulPull]),
        );
        expect(result.targetResultHash).toBe(protocolHash('7'));
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
