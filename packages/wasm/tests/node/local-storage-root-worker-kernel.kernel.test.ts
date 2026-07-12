import { BrowserActionStorageCustodyError } from '@sealed-lattice/protocol/browser-action-storage-custody';
import { describe, expect, it } from 'vitest';

import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
} from '#packages/wasm/src/index';

const createBytes = (byteLength: number, seed: number): Uint8Array =>
    Uint8Array.from(
        { length: byteLength },
        (_, byteIndex) => (seed + byteIndex * 97) & 0xff,
    );

const binding = Object.freeze({
    actionContextHash: createBytes(64, 31),
    ceremonyContextHash: createBytes(64, 19),
    participantId: createBytes(64, 43),
    suiteId: createBytes(64, 7),
});

const mutationIdentifier = createBytes(32, 113);

const expectCustodyErrorCode = async (
    operation: Promise<unknown>,
    code: BrowserActionStorageCustodyError['code'],
): Promise<void> => {
    await expect(operation).rejects.toMatchObject({
        code,
        name: 'BrowserActionStorageCustodyError',
    });
};

describe('Local storage-root real-WASM worker kernel', () => {
    it('wraps, activates, exports, confirms, destroys, and reopens after a worker crash', async () => {
        const initialWorkerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: loadFreshTranscriptCoreKernel(),
        });
        const prepared =
            await initialWorkerKernel.createAndStageDeviceWrappingState({
                binding,
            });

        expect(prepared.storageRootCommitment).toHaveLength(64);
        expect(prepared.wrappedStorageRoot.length).toBeGreaterThan(0);
        expect(prepared.wrappedStorageRoot.length).toBeLessThanOrEqual(492);
        expect(prepared.deviceKey.extractable).toBe(false);
        await expect(
            crypto.subtle.exportKey('raw', prepared.deviceKey),
        ).rejects.toBeDefined();

        await expectCustodyErrorCode(
            initialWorkerKernel.createAndStageDeviceWrappingState({ binding }),
            'InvalidState',
        );
        const conflictingCommitment = prepared.storageRootCommitment.slice();
        conflictingCommitment[0] ^= 1;
        await expectCustodyErrorCode(
            initialWorkerKernel.stageDeviceWrappingStateOpen({
                binding,
                externallyVerifiedCommitment: {
                    storageRootCommitment: conflictingCommitment,
                },
                state: {
                    ...prepared,
                    storageRootCommitment: conflictingCommitment,
                },
            }),
            'InvalidState',
        );
        await initialWorkerKernel.stageDeviceWrappingStateOpen({
            binding,
            externallyVerifiedCommitment: {
                storageRootCommitment: prepared.storageRootCommitment,
            },
            state: prepared,
        });
        await initialWorkerKernel.commitStagedActionStorageRoot({
            mutationIdentifier,
        });
        const recovery = await initialWorkerKernel.prepareRecoveryExport({
            activeMutationIdentifier: mutationIdentifier,
        });
        expect(recovery.canonicalRecoveryText).toMatch(/^[A-Z2-7]{708}$/u);
        expect(recovery.recoveryChecksum).toHaveLength(16);
        await expectCustodyErrorCode(
            initialWorkerKernel.prepareRecoveryExport({
                activeMutationIdentifier: createBytes(32, 114),
            }),
            'InvalidState',
        );
        const wrongChecksum = recovery.recoveryChecksum.slice();
        wrongChecksum[0] ^= 1;
        await expectCustodyErrorCode(
            initialWorkerKernel.confirmRecoveryChecksum({
                canonicalRecoveryText: recovery.canonicalRecoveryText,
                confirmedChecksum: wrongChecksum,
            }),
            'RecoveryConfirmationFailed',
        );
        await initialWorkerKernel.confirmRecoveryChecksum({
            canonicalRecoveryText: recovery.canonicalRecoveryText,
            confirmedChecksum: recovery.recoveryChecksum,
        });
        await initialWorkerKernel.destroyActiveActionStorageRoot();
        await initialWorkerKernel.destroyActiveActionStorageRoot();
        await expectCustodyErrorCode(
            initialWorkerKernel.prepareRecoveryExport({
                activeMutationIdentifier: mutationIdentifier,
            }),
            'InvalidState',
        );

        const replacementKernel = await loadFreshTranscriptCoreKernel();
        const replacementWorkerKernel =
            createWasmBrowserActionStorageWorkerKernel({
                kernel: replacementKernel,
            });
        await replacementWorkerKernel.stageDeviceWrappingStateOpen({
            binding,
            externallyVerifiedCommitment: {
                storageRootCommitment: prepared.storageRootCommitment,
            },
            state: prepared,
        });
        await replacementWorkerKernel.commitStagedActionStorageRoot({
            mutationIdentifier,
        });
        const reopenedRecovery =
            await replacementWorkerKernel.prepareRecoveryExport({
                activeMutationIdentifier: mutationIdentifier,
            });
        expect(reopenedRecovery.canonicalRecoveryText).toBe(
            recovery.canonicalRecoveryText,
        );
        expect(reopenedRecovery.recoveryChecksum).toEqual(
            recovery.recoveryChecksum,
        );
        await replacementWorkerKernel.destroyActiveActionStorageRoot();
    });

    it('refuses wrong bindings, commitments, envelopes, and stale staged state', async () => {
        const sourceKernel = await loadFreshTranscriptCoreKernel();
        const sourceWorkerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: sourceKernel,
        });
        const prepared =
            await sourceWorkerKernel.createAndStageDeviceWrappingState({
                binding,
            });
        await sourceWorkerKernel.discardStagedActionStorageRoot();
        await sourceWorkerKernel.discardStagedActionStorageRoot();

        const openingKernel = await loadFreshTranscriptCoreKernel();
        const openingWorkerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: openingKernel,
        });
        const wrongBinding = {
            ...binding,
            actionContextHash: createBytes(64, 32),
        };
        await expectCustodyErrorCode(
            openingWorkerKernel.stageDeviceWrappingStateOpen({
                binding: wrongBinding,
                externallyVerifiedCommitment: {
                    storageRootCommitment: prepared.storageRootCommitment,
                },
                state: prepared,
            }),
            'CommitmentMismatch',
        );

        const wrongCommitment = prepared.storageRootCommitment.slice();
        wrongCommitment[17] ^= 1;
        await expectCustodyErrorCode(
            openingWorkerKernel.stageDeviceWrappingStateOpen({
                binding,
                externallyVerifiedCommitment: {
                    storageRootCommitment: wrongCommitment,
                },
                state: prepared,
            }),
            'CommitmentMismatch',
        );

        const tamperedState = {
            ...prepared,
            wrappedStorageRoot: prepared.wrappedStorageRoot.slice(),
        };
        tamperedState.wrappedStorageRoot[
            tamperedState.wrappedStorageRoot.length - 1
        ] ^= 1;
        await expectCustodyErrorCode(
            openingWorkerKernel.stageDeviceWrappingStateOpen({
                binding,
                externallyVerifiedCommitment: {
                    storageRootCommitment: prepared.storageRootCommitment,
                },
                state: tamperedState,
            }),
            'InvalidCanonicalMaterial',
        );

        await openingWorkerKernel.stageDeviceWrappingStateOpen({
            binding,
            externallyVerifiedCommitment: {
                storageRootCommitment: prepared.storageRootCommitment,
            },
            state: prepared,
        });
        await openingWorkerKernel.discardStagedActionStorageRoot();
        await expectCustodyErrorCode(
            openingWorkerKernel.commitStagedActionStorageRoot({
                mutationIdentifier,
            }),
            'InvalidState',
        );
    });

    it('imports recovery material under the exact binding and reclaims repeated staged roots', async () => {
        const sourceKernel = await loadFreshTranscriptCoreKernel();
        const sourceWorkerKernel = createWasmBrowserActionStorageWorkerKernel({
            kernel: sourceKernel,
        });
        const prepared =
            await sourceWorkerKernel.createAndStageDeviceWrappingState({
                binding,
            });
        await sourceWorkerKernel.commitStagedActionStorageRoot({
            mutationIdentifier,
        });
        const recovery = await sourceWorkerKernel.prepareRecoveryExport({
            activeMutationIdentifier: mutationIdentifier,
        });

        const recoveryKernel = await loadFreshTranscriptCoreKernel();
        const recoveryWorkerKernel = createWasmBrowserActionStorageWorkerKernel(
            { kernel: recoveryKernel },
        );
        const wrongBinding = {
            ...binding,
            participantId: createBytes(64, 44),
        };
        await expectCustodyErrorCode(
            recoveryWorkerKernel.stageRecoveryValueImportAndDeviceWrapping({
                binding: wrongBinding,
                caseInsensitiveRecoveryText:
                    recovery.canonicalRecoveryText.toLowerCase(),
                externallyVerifiedCommitment: {
                    storageRootCommitment: prepared.storageRootCommitment,
                },
            }),
            'CommitmentMismatch',
        );
        const wrongCommitment = prepared.storageRootCommitment.slice();
        wrongCommitment[63] ^= 1;
        await expectCustodyErrorCode(
            recoveryWorkerKernel.stageRecoveryValueImportAndDeviceWrapping({
                binding,
                caseInsensitiveRecoveryText: recovery.canonicalRecoveryText,
                externallyVerifiedCommitment: {
                    storageRootCommitment: wrongCommitment,
                },
            }),
            'CommitmentMismatch',
        );

        const recovered =
            await recoveryWorkerKernel.stageRecoveryValueImportAndDeviceWrapping(
                {
                    binding,
                    caseInsensitiveRecoveryText:
                        recovery.canonicalRecoveryText.toLowerCase(),
                    externallyVerifiedCommitment: {
                        storageRootCommitment: prepared.storageRootCommitment,
                    },
                },
            );
        expect(recovered.canonicalRecoveryText).toBe(
            recovery.canonicalRecoveryText,
        );
        expect(recovered.storageRootCommitment).toEqual(
            prepared.storageRootCommitment,
        );
        await recoveryWorkerKernel.discardStagedActionStorageRoot();

        for (let iteration = 0; iteration < 64; iteration += 1) {
            await recoveryWorkerKernel.createAndStageDeviceWrappingState({
                binding,
            });
            await recoveryWorkerKernel.discardStagedActionStorageRoot();
        }
    });
});
