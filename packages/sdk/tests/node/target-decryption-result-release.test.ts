import type { PublishedSdkKernel } from '@sealed-lattice/wasm/published-sdk';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import type {
    TargetDecryptionResultReleaseInput,
    verifyTargetDecryptionResult,
} from '#packages/sdk/src/index.js';
import { issueVerifiedSetup } from '#packages/sdk/src/verified-setup-capability.js';
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

vi.mock('@sealed-lattice/wasm/published-sdk', async (importOriginal) => ({
    ...(await importOriginal<Record<string, unknown>>()),
    openBgvCanonicalStreamRuntime: openCanonicalRuntime,
}));

let absorbedShareCount: number;
let cleanupFailure: Error | undefined;
let freshKernelLoadCount: number;
let mockKernel: {
    readonly absorbBgvTargetDecryptionResultReleaseShare: ReturnType<
        typeof vi.fn
    >;
    readonly beginBgvTargetDecryptionResultRelease: ReturnType<typeof vi.fn>;
    readonly finishBgvTargetDecryptionResultRelease: ReturnType<typeof vi.fn>;
};

vi.mock('../../src/kernel.js', () => ({
    loadFreshTranscriptCoreKernel: async () => {
        freshKernelLoadCount += 1;
        await Promise.resolve();
        return mockKernel;
    },
}));

const publicPackage = (await import('../../src/index.js')) as Readonly<{
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
    verifiedSetup: issueVerifiedSetup({
        acceptedSetupHandle: 7,
        kernel: mockKernel as unknown as PublishedSdkKernel,
        setupPackageHash: protocolHash('f'),
    }),
    shareProofs: pulls.map((pull, proofIndex) => shareProof(proofIndex, pull)),
    targetAcceptedRecord: {},
    targetCiphertextBinding: {},
    targetCiphertexts: {},
    targetShareProfile: {},
});

const successfulPull = (): Promise<ArrayBuffer | undefined> =>
    Promise.resolve(Uint8Array.of(1).buffer);

describe('target-decryption result release session cleanup', () => {
    beforeEach(() => {
        absorbedShareCount = 0;
        cleanupFailure = undefined;
        freshKernelLoadCount = 0;
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
        };
    });

    it('uses one deep target release snapshot across capability resolution and chunk callbacks', async () => {
        const verificationInputReference: {
            current?: TargetDecryptionResultReleaseInput;
        } = {};
        const mutatingPull: ProofMaterialChunkPull = () => {
            const callerInput = verificationInputReference.current;
            const callerShareProof = callerInput?.shareProofs[0];
            if (callerInput === undefined || callerShareProof === undefined) {
                throw new Error('Missing target release fixture.');
            }
            const targetAcceptedRecord =
                callerInput.targetAcceptedRecord as JsonRecord;
            const targetCiphertexts =
                callerInput.targetCiphertexts as JsonRecord;
            const targetCiphertextBinding =
                callerInput.targetCiphertextBinding as JsonRecord;
            const targetShareProfile =
                callerInput.targetShareProfile as JsonRecord;
            const mutableShareProof = callerShareProof as unknown as JsonRecord;
            const callerProofMaterial =
                callerShareProof.proofMaterial as unknown as JsonRecord;
            const callerTransport =
                callerShareProof.proofMaterialTransport as unknown as JsonRecord;
            const callerDescriptor =
                callerTransport.descriptorBytes as Uint8Array;
            (targetAcceptedRecord.acceptedTarget as JsonRecord).targetIndex =
                92;
            (targetCiphertexts.ciphertextSet as JsonRecord).ciphertextCount =
                93;
            (
                targetCiphertextBinding.ciphertextBinding as JsonRecord
            ).bindingIndex = 94;
            (targetShareProfile.shareProfile as JsonRecord).threshold = 95;
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

        const result =
            await publicPackage.verifyTargetDecryptionResult(verificationInput);

        expect(result.targetResultHash).toBe(protocolHash('7'));
        const releaseBeginInput = mockKernel
            .beginBgvTargetDecryptionResultRelease.mock.calls[0]?.[0] as
            | JsonRecord
            | undefined;
        const issuedReleaseVerificationId =
            releaseBeginInput?.releaseVerificationId;
        expect(issuedReleaseVerificationId).toMatch(/^[0-9a-f]{64}$/u);
        expect(releaseBeginInput).toEqual({
            releaseVerificationId: issuedReleaseVerificationId,
            acceptedSetupHandle: 7,
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
            issuedReleaseVerificationId,
        );
        expect(callerDescriptor).toEqual(
            new Uint8Array(callerDescriptor.byteLength).fill(0xff),
        );
    });

    it('uses the exact kernel instance that issued the verified setup capability', async () => {
        const issuingKernel = mockKernel;
        const verificationInput = releaseInput([
            successfulPull,
            successfulPull,
        ]);
        const unrelatedKernel = {
            ...mockKernel,
            beginBgvTargetDecryptionResultRelease: vi.fn(() => ({
                requiredShareCount: 2,
            })),
        };
        mockKernel = unrelatedKernel;

        const result =
            await publicPackage.verifyTargetDecryptionResult(verificationInput);

        expect(result.targetResultHash).toBe(protocolHash('7'));
        expect(
            issuingKernel.beginBgvTargetDecryptionResultRelease,
        ).toHaveBeenCalledOnce();
        expect(
            unrelatedKernel.beginBgvTargetDecryptionResultRelease,
        ).not.toHaveBeenCalled();
        expect(freshKernelLoadCount).toBe(0);
    });

    it('rejects copied and serialized setup capability lookalikes before opening a release', async () => {
        const verificationInput = releaseInput([
            successfulPull,
            successfulPull,
        ]);
        const copiedCapability = Object.freeze({
            ...verificationInput.verifiedSetup,
        }) as TargetDecryptionResultReleaseInput['verifiedSetup'];
        const serializedCapability = structuredClone(
            verificationInput.verifiedSetup,
        );

        for (const unownedCapability of [
            copiedCapability,
            serializedCapability,
        ]) {
            await expect(
                publicPackage.verifyTargetDecryptionResult({
                    ...verificationInput,
                    verifiedSetup: unownedCapability,
                }),
            ).rejects.toThrow(/active capability/u);
        }
        expect(
            mockKernel.beginBgvTargetDecryptionResultRelease,
        ).not.toHaveBeenCalled();
    });

    it('rejects a capability issued by a foreign SDK module instance', async () => {
        vi.resetModules();
        const foreignCapabilityModule =
            await import('../../src/verified-setup-capability.js');
        const foreignCapability = foreignCapabilityModule.issueVerifiedSetup({
            acceptedSetupHandle: 7,
            kernel: mockKernel as unknown as PublishedSdkKernel,
            setupPackageHash: protocolHash('f'),
        });

        await expect(
            publicPackage.verifyTargetDecryptionResult({
                ...releaseInput([successfulPull, successfulPull]),
                verifiedSetup: foreignCapability,
            }),
        ).rejects.toThrow(/active capability/u);
        expect(
            mockKernel.beginBgvTargetDecryptionResultRelease,
        ).not.toHaveBeenCalled();
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
