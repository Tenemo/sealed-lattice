import { foundationProfile } from '@sealed-lattice/types';

import type { BrowserActionStorageRootBinding } from '#packages/protocol/src/runtime/browser-action-storage-custody';
import {
    commonProofStorageCapacityProfile,
    openWebLockOwnedBrowserActionStorageCustody,
} from '#packages/protocol/src/runtime/web-lock-owned-untrusted-storage-transaction-store';
import {
    createWasmBrowserActionStorageWorkerKernel,
    loadFreshTranscriptCoreKernel,
} from '#packages/wasm/src/index';

type CrashWorkerRequest = Readonly<{
    binding: BrowserActionStorageRootBinding;
    databaseName: string;
    runtimeBuildManifestHash: Uint8Array;
    storageNamespace: string;
}>;

type CrashWorkerScope = Readonly<{
    addEventListener(
        type: 'message',
        listener: (event: MessageEvent<unknown>) => void,
    ): void;
    postMessage(message: unknown): void;
}>;

const workerScope = globalThis as unknown as CrashWorkerScope;
const transactionLimits = Object.freeze({
    maximumActiveTransactionCount: 2,
    maximumLeaseByteLength:
        commonProofStorageCapacityProfile.maximumLeaseByteLength,
    maximumLeaseCountPerTransaction:
        commonProofStorageCapacityProfile.maximumLeaseCountPerTransaction,
    maximumOwnedRecordCount:
        commonProofStorageCapacityProfile.maximumAdditionalOwnedRecordCount +
        256,
    maximumStoredValueByteLength:
        commonProofStorageCapacityProfile.maximumAdditionalStoredValueByteLength +
        commonProofStorageCapacityProfile.maximumAdditionalAuthenticatedRepairHeadPlaintextByteLength +
        1_048_576,
    maximumTransactionByteLength:
        commonProofStorageCapacityProfile.maximumTransactionByteLength,
    maximumTransactionLifetimeMilliseconds: 10_000,
});

const copyRequest = (value: unknown): CrashWorkerRequest => {
    if (
        typeof value !== 'object' ||
        value === null ||
        !('binding' in value) ||
        !('databaseName' in value) ||
        typeof value.databaseName !== 'string' ||
        !('runtimeBuildManifestHash' in value) ||
        !(value.runtimeBuildManifestHash instanceof Uint8Array) ||
        !('storageNamespace' in value) ||
        typeof value.storageNamespace !== 'string'
    ) {
        throw new Error('The common-proof handoff crash request is malformed.');
    }
    const binding = value.binding;
    if (
        typeof binding !== 'object' ||
        binding === null ||
        !('actionContextHash' in binding) ||
        !(binding.actionContextHash instanceof Uint8Array) ||
        !('ceremonyContextHash' in binding) ||
        !(binding.ceremonyContextHash instanceof Uint8Array) ||
        !('participantId' in binding) ||
        !(binding.participantId instanceof Uint8Array) ||
        !('suiteId' in binding) ||
        !(binding.suiteId instanceof Uint8Array)
    ) {
        throw new Error('The common-proof handoff crash binding is malformed.');
    }
    return Object.freeze({
        binding: Object.freeze({
            actionContextHash: Uint8Array.from(binding.actionContextHash),
            ceremonyContextHash: Uint8Array.from(binding.ceremonyContextHash),
            participantId: Uint8Array.from(binding.participantId),
            suiteId: Uint8Array.from(binding.suiteId),
        }),
        databaseName: value.databaseName,
        runtimeBuildManifestHash: Uint8Array.from(
            value.runtimeBuildManifestHash,
        ),
        storageNamespace: value.storageNamespace,
    });
};

workerScope.addEventListener('message', (event) => {
    void (async () => {
        try {
            const request = copyRequest(event.data);
            const workerKernel = createWasmBrowserActionStorageWorkerKernel({
                kernel: loadFreshTranscriptCoreKernel(),
            });
            const owner = await openWebLockOwnedBrowserActionStorageCustody({
                binding: request.binding,
                databaseName: request.databaseName,
                limits: transactionLimits,
                namespace: request.storageNamespace,
                runtimeBuildManifestHash: request.runtimeBuildManifestHash,
                workerKernel,
            });
            const deviceWrappingSnapshot = await owner.custody.initialize();
            await owner.openRootAndAuthenticatedStore({
                expectedSnapshot: deviceWrappingSnapshot,
                untrustedExpectedCommitment: {
                    storageRootCommitment:
                        deviceWrappingSnapshot.storageRootCommitment.slice(),
                },
            });
            await owner.commitFreshFoundationInitialization({
                actionRandomnessRecordContext: { recordVersion: 0n },
                orderedWitnessBindings: Object.freeze(
                    Array.from(
                        {
                            length: foundationProfile.participantCount - 1,
                        },
                        (_unused, witnessIndex) =>
                            Object.freeze({
                                subjectParticipantIdentity: new Uint8Array(
                                    64,
                                ).fill(0x80 + witnessIndex),
                                witnessParticipantIdentity:
                                    request.binding.participantId.slice(),
                            }),
                    ),
                ),
                runtimeBuildManifestHash:
                    request.runtimeBuildManifestHash.slice(),
            });
            if (owner.openCommonProofCustody === undefined) {
                throw new Error(
                    'The browser owner does not provide common-proof custody.',
                );
            }
            const commonProofCustody = await owner.openCommonProofCustody({
                actionRandomnessCommitment: new Uint8Array(64).fill(0x31),
                commonProofEnvironmentIdentifier: new Uint8Array(32).fill(0x41),
                commonProofRuntimeBindingHash: new Uint8Array(64).fill(0x51),
                proofAttemptLineageIdentifier: new Uint8Array(32).fill(0x61),
            });
            await commonProofCustody.outputStore.commitChunk(
                0,
                Uint8Array.of(0x71),
            );
            commonProofCustody.sealCanonicalOutput();
            await commonProofCustody.releaseExternalMemory();
            const handoff = await commonProofCustody.armApplicationHandoff();
            try {
                await commonProofCustody.completeVerifiedOutput();
            } finally {
                handoff.canonicalMarkerRecordBytes.fill(0);
            }
            workerScope.postMessage({
                deviceWrappingSnapshot: {
                    mutationIdentifier:
                        deviceWrappingSnapshot.mutationIdentifier.slice(),
                    storageRootCommitment:
                        deviceWrappingSnapshot.storageRootCommitment.slice(),
                },
                messageKind: 'common-proof-handoff-armed',
            });
        } catch (error) {
            workerScope.postMessage({
                errorCode:
                    typeof error === 'object' &&
                    error !== null &&
                    'code' in error
                        ? String(error.code)
                        : 'UnclassifiedFailure',
                errorMessage:
                    error instanceof Error
                        ? error.message
                        : 'The common-proof handoff crash worker failed with a non-error value.',
                messageKind: 'common-proof-handoff-failed',
            });
        }
    })();
});
