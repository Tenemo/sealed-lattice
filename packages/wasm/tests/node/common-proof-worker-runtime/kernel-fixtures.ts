import { expect } from 'vitest';

import {
    runPreparedCommonProofVerificationWorker,
    type CommonProofApplicationFreshnessCoordinate,
    type CommonProofApplicationStorageRootAccess,
    type VerifiedCommonProofCapability,
} from '../../../src/common-proof-worker-runtime.js';
import type { TranscriptCoreKernelCommandRuntime } from '../../../src/transcript-core-bridge/kernel-runtime.js';
import type { TranscriptCoreKernelExports } from '../../../src/transcript-core-bridge/kernel-types.js';

import {
    hashByteLength,
    installedCommonProofVerificationBindingHash,
    installedProofAttemptLineageIdentifier,
} from './wire-fixtures.js';

export const noSecondPollValue = 0xffff_ffff;

export const writeUnsigned32 = (
    memory: WebAssembly.Memory,
    pointer: number,
    value: number,
): void => {
    new DataView(memory.buffer).setUint32(pointer, value, true);
};

export const memoryBytes = (
    memory: WebAssembly.Memory,
    pointer: number,
    byteLength: number,
): Uint8Array => new Uint8Array(memory.buffer, pointer, byteLength);

export const createMockKernelRuntime = (
    createCommonProofExports: (
        memory: WebAssembly.Memory,
    ) => Partial<TranscriptCoreKernelExports>,
    initialMemoryPageCount = 64,
): TranscriptCoreKernelCommandRuntime => {
    const memory = new WebAssembly.Memory({
        initial: initialMemoryPageCount,
    });
    let nextPointer = 8;
    const allocate = (byteLength: number): number => {
        const pointer = nextPointer;
        nextPointer += Math.ceil(byteLength / 8) * 8;
        expect(nextPointer).toBeLessThan(memory.buffer.byteLength);
        return pointer;
    };
    const deallocate = (pointer: number, byteLength: number): void => {
        expect(pointer).toBeGreaterThan(0);
        expect(byteLength).toBeGreaterThan(0);
    };
    const wasmExports: TranscriptCoreKernelExports = {
        memory,
        sealed_lattice_allocate: allocate,
        sealed_lattice_deallocate: deallocate,
        ...createCommonProofExports(memory),
    };
    let operationInProgress = false;
    return {
        allocate,
        deallocate,
        executeCommand: <Result>(): Result => {
            throw new Error(
                'The mock common-proof runtime has no JSON command.',
            );
        },
        memory,
        runExclusive: <Result>(
            _operationName: string,
            operation: () => Result,
        ): Result => {
            expect(operationInProgress).toBe(false);
            operationInProgress = true;
            try {
                return operation();
            } finally {
                operationInProgress = false;
            }
        },
        wasmExports,
    };
};

export const writeGenerationPoll = (
    memory: WebAssembly.Memory,
    pollKindPointer: number,
    primaryValuePointer: number,
    secondaryValuePointer: number,
    pollKind: number,
    primaryValue: number,
    secondaryValue: number,
): number => {
    writeUnsigned32(memory, pollKindPointer, pollKind);
    writeUnsigned32(memory, primaryValuePointer, primaryValue);
    writeUnsigned32(memory, secondaryValuePointer, secondaryValue);
    return 0;
};

export const createResetSafeCommonProofCursorManifest = (
    streamAttemptIdentifier: Uint8Array = installedProofAttemptLineageIdentifier,
): Uint8Array<ArrayBuffer> => {
    if (streamAttemptIdentifier.byteLength !== 32) {
        throw new TypeError(
            'The cursor-manifest stream-attempt identifier must contain exactly 32 bytes.',
        );
    }
    const prefixByteLength = 19;
    const identityByteLength = 98;
    const manifest = new Uint8Array(prefixByteLength + identityByteLength);
    manifest.set(Uint8Array.of(0x53, 0x4c, 0x43, 0x50, 0x43, 0x4d, 0x30, 0x33));
    const view = new DataView(manifest.buffer);
    view.setUint16(8, 3, true);
    manifest[10] = 1;
    view.setUint32(11, 0, true);
    view.setUint32(15, 0, true);
    view.setUint16(19, 0x1217, true);
    manifest.set(installedCommonProofVerificationBindingHash, 21);
    manifest.set(streamAttemptIdentifier, 85);
    return manifest;
};

export const createCheckpointGenerationKernelFixture = (
    checkpointCursorManifestBytes: Uint8Array = createResetSafeCommonProofCursorManifest(),
): Readonly<{
    canonicalStateBytes: Uint8Array<ArrayBuffer>;
    cursorManifestBytes: Uint8Array<ArrayBuffer>;
    observations: {
        acknowledgedCheckpointCount: number;
        discardedCheckpointCount: number;
        retiredOperationCount: number;
    };
    runtime: TranscriptCoreKernelCommandRuntime;
    stableAttemptBindingHash: Uint8Array<ArrayBuffer>;
}> => {
    const canonicalStateBytes = new Uint8Array(37).fill(0x91);
    const cursorManifestBytes = Uint8Array.from(checkpointCursorManifestBytes);
    const stableAttemptBindingHash = new Uint8Array(hashByteLength).fill(0x62);
    const observations = {
        acknowledgedCheckpointCount: 0,
        discardedCheckpointCount: 0,
        retiredOperationCount: 0,
    };
    let phase: 'checkpoint' | 'complete' | 'finished' | 'retired' =
        'checkpoint';
    const runtime = createMockKernelRuntime((memory) => ({
        sealed_lattice_common_proof_begin_generation: (
            preparedGenerationHandle,
            statusPointer,
        ) => {
            expect(preparedGenerationHandle).toBe(81);
            writeUnsigned32(memory, statusPointer, 0);
            return 91;
        },
        sealed_lattice_common_proof_generation_poll: (
            operationHandle,
            pollKindPointer,
            primaryValuePointer,
            secondaryValuePointer,
        ) => {
            expect(operationHandle).toBe(91);
            return writeGenerationPoll(
                memory,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
                phase === 'checkpoint' ? 1 : 5,
                phase === 'checkpoint' ? 4 : 0,
                phase === 'checkpoint' ? 1 : noSecondPollValue,
            );
        },
        sealed_lattice_common_proof_generation_checkpoint_state_byte_length:
            () => canonicalStateBytes.byteLength,
        sealed_lattice_common_proof_generation_describe_checkpoint: (
            operationHandle,
            safeBoundaryOrdinalPointer,
            stateByteLengthPointer,
            cursorManifestByteLengthPointer,
        ) => {
            expect(operationHandle).toBe(91);
            expect(phase).toBe('checkpoint');
            writeUnsigned32(memory, safeBoundaryOrdinalPointer, 4);
            writeUnsigned32(
                memory,
                stateByteLengthPointer,
                canonicalStateBytes.byteLength,
            );
            writeUnsigned32(
                memory,
                cursorManifestByteLengthPointer,
                cursorManifestBytes.byteLength,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_copy_checkpoint_state: (
            operationHandle,
            outputPointer,
            outputByteLength,
        ) => {
            expect(operationHandle).toBe(91);
            expect(outputByteLength).toBe(canonicalStateBytes.byteLength);
            memoryBytes(memory, outputPointer, outputByteLength).set(
                canonicalStateBytes,
            );
            return 0;
        },
        sealed_lattice_common_proof_generation_copy_checkpoint_cursor_manifest:
            (operationHandle, outputPointer, outputByteLength) => {
                expect(operationHandle).toBe(91);
                expect(outputByteLength).toBe(cursorManifestBytes.byteLength);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    cursorManifestBytes,
                );
                return 0;
            },
        sealed_lattice_common_proof_generation_copy_checkpoint_stable_attempt_binding_hash:
            (operationHandle, outputPointer, outputByteLength) => {
                expect(operationHandle).toBe(91);
                expect(outputByteLength).toBe(hashByteLength);
                memoryBytes(memory, outputPointer, outputByteLength).set(
                    stableAttemptBindingHash,
                );
                return 0;
            },
        sealed_lattice_common_proof_generation_acknowledge_checkpoint: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(91);
            expect(phase).toBe('checkpoint');
            observations.acknowledgedCheckpointCount += 1;
            phase = 'complete';
            return 0;
        },
        sealed_lattice_common_proof_generation_discard_checkpoint: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(91);
            expect(phase).toBe('checkpoint');
            observations.discardedCheckpointCount += 1;
            phase = 'complete';
            return 0;
        },
        sealed_lattice_common_proof_generation_finish: (
            operationHandle,
            statusPointer,
        ) => {
            expect(operationHandle).toBe(91);
            expect(phase).toBe('complete');
            writeUnsigned32(memory, statusPointer, 0);
            phase = 'finished';
            return 101;
        },
        sealed_lattice_common_proof_release_generated_proof: (
            capabilityHandle,
        ) => {
            expect(capabilityHandle).toBe(101);
            expect(phase).toBe('finished');
            return 0;
        },
        sealed_lattice_common_proof_generation_retire_failed: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(91);
            expect(phase).toBe('checkpoint');
            observations.retiredOperationCount += 1;
            phase = 'retired';
            return 0;
        },
    }));
    return {
        canonicalStateBytes,
        cursorManifestBytes,
        observations,
        runtime,
        stableAttemptBindingHash,
    };
};

export const createVerifiedApplicationFixture = async (input?: {
    failVerifiedCapabilityReleaseAttempt?: number;
    predecessorFreshnessSequence?: bigint;
    proofBytes?: Uint8Array;
}): Promise<
    Readonly<{
        authorizationFrame: Uint8Array<ArrayBuffer>;
        capability: VerifiedCommonProofCapability;
        observations: {
            abortedApplicationCount: number;
            confirmedApplicationCount: number;
            preparedApplicationCount: number;
            releasedCapabilityCount: number;
        };
        predecessor: CommonProofApplicationFreshnessCoordinate;
        proofApplicationSlotHash: Uint8Array<ArrayBuffer>;
        runtime: TranscriptCoreKernelCommandRuntime;
        storageRootAccess: CommonProofApplicationStorageRootAccess;
        successor: CommonProofApplicationFreshnessCoordinate;
    }>
> => {
    const authorizationFrame = Uint8Array.from(
        { length: 746 },
        (_unused, byteIndex) => (byteIndex * 29 + 17) & 0xff,
    );
    const proofApplicationSlotHash = new Uint8Array(hashByteLength).fill(0x71);
    const proofBytes = Uint8Array.from(
        input?.proofBytes ?? Uint8Array.of(0xa1),
    );
    const storageRootCapability = new Uint8Array(32).fill(0x41);
    const predecessorFreshnessSequence =
        input?.predecessorFreshnessSequence ?? 7n;
    const predecessor: CommonProofApplicationFreshnessCoordinate =
        Object.freeze({
            authenticatedHeadDigest: new Uint8Array(hashByteLength).fill(0x51),
            freshnessSequence: predecessorFreshnessSequence,
            storageInstanceIdentity: new Uint8Array(hashByteLength).fill(0x61),
        });
    const successor: CommonProofApplicationFreshnessCoordinate = Object.freeze({
        authenticatedHeadDigest: new Uint8Array(hashByteLength).fill(0x52),
        freshnessSequence: predecessorFreshnessSequence + 1n,
        storageInstanceIdentity: predecessor.storageInstanceIdentity.slice(),
    });
    const observations = {
        abortedApplicationCount: 0,
        confirmedApplicationCount: 0,
        preparedApplicationCount: 0,
        releasedCapabilityCount: 0,
    };
    let capabilityAvailable = false;
    let pendingApplication = false;
    let pendingPredecessorAuthenticatedHeadDigest:
        | Uint8Array<ArrayBuffer>
        | undefined;
    let pendingPredecessorFreshnessSequence: bigint | undefined;
    let pendingStorageRootCapability: Uint8Array<ArrayBuffer> | undefined;
    let pendingStorageRootHandle: number | undefined;
    const runtime = createMockKernelRuntime((memory) => ({
        sealed_lattice_common_proof_describe_verification_family_adapter: (
            adapterHandle,
            verificationBindingHashOutputPointer,
            statusPointer,
        ) => {
            expect(adapterHandle).toBe(51);
            memoryBytes(
                memory,
                verificationBindingHashOutputPointer,
                hashByteLength,
            ).set(installedCommonProofVerificationBindingHash);
            writeUnsigned32(memory, statusPointer, 0);
            return 0;
        },
        sealed_lattice_common_proof_prepare_verification_family_adapter: (
            adapterHandle,
            statusPointer,
        ) => {
            expect(adapterHandle).toBe(51);
            writeUnsigned32(memory, statusPointer, 0);
            return 62;
        },
        sealed_lattice_common_proof_discard_verification_family_adapter: (
            adapterHandle,
        ) => {
            expect(adapterHandle).toBe(51);
            return 0;
        },
        sealed_lattice_common_proof_begin_verification: (
            preparedVerificationHandle,
            statusPointer,
        ) => {
            expect(preparedVerificationHandle).toBe(62);
            writeUnsigned32(memory, statusPointer, 0);
            return 72;
        },
        sealed_lattice_common_proof_verification_absorb_input_chunk: (
            operationHandle,
            chunkIndex,
            chunkPointer,
            chunkLength,
        ) => {
            expect(operationHandle).toBe(72);
            expect(chunkIndex).toBe(0);
            expect([...memoryBytes(memory, chunkPointer, chunkLength)]).toEqual(
                [...proofBytes],
            );
            return 0;
        },
        sealed_lattice_common_proof_verification_finish_input: (
            operationHandle,
        ) => {
            expect(operationHandle).toBe(72);
            return 0;
        },
        sealed_lattice_common_proof_verification_poll: (
            operationHandle,
            pollKindPointer,
            primaryValuePointer,
            secondaryValuePointer,
        ) => {
            expect(operationHandle).toBe(72);
            return writeGenerationPoll(
                memory,
                pollKindPointer,
                primaryValuePointer,
                secondaryValuePointer,
                5,
                0,
                noSecondPollValue,
            );
        },
        sealed_lattice_common_proof_verification_finish: (
            operationHandle,
            statusPointer,
        ) => {
            expect(operationHandle).toBe(72);
            writeUnsigned32(memory, statusPointer, 0);
            capabilityAvailable = true;
            return 82;
        },
        sealed_lattice_common_proof_application_frame_byte_length: () =>
            authorizationFrame.byteLength,
        sealed_lattice_common_proof_prepare_application: (
            terminalCapabilityHandle,
            storageRootHandle,
            storageRootCapabilityPointer,
            predecessorNamespaceSequence,
            predecessorAuthenticatedHeadDigestPointer,
            storageInstanceIdentityPointer,
            durableFrameOutputPointer,
            durableFrameOutputByteLength,
            proofApplicationSlotHashOutputPointer,
            proofApplicationSlotHashOutputByteLength,
            statusPointer,
        ) => {
            const suppliedStorageRootCapability = Uint8Array.from(
                memoryBytes(
                    memory,
                    storageRootCapabilityPointer,
                    storageRootCapability.byteLength,
                ),
            );
            const inputMatches =
                terminalCapabilityHandle === 82 &&
                Number.isSafeInteger(storageRootHandle) &&
                storageRootHandle > 0 &&
                predecessorNamespaceSequence >= 0n &&
                suppliedStorageRootCapability.some((byte) => byte !== 0) &&
                predecessor.storageInstanceIdentity.every(
                    (byte, byteIndex) =>
                        byte ===
                        memoryBytes(
                            memory,
                            storageInstanceIdentityPointer,
                            hashByteLength,
                        )[byteIndex],
                ) &&
                durableFrameOutputByteLength ===
                    authorizationFrame.byteLength &&
                proofApplicationSlotHashOutputByteLength === hashByteLength;
            if (!capabilityAvailable || pendingApplication || !inputMatches) {
                writeUnsigned32(memory, statusPointer, 6);
                return 0;
            }
            capabilityAvailable = false;
            pendingApplication = true;
            pendingPredecessorAuthenticatedHeadDigest = Uint8Array.from(
                memoryBytes(
                    memory,
                    predecessorAuthenticatedHeadDigestPointer,
                    hashByteLength,
                ),
            );
            pendingPredecessorFreshnessSequence = predecessorNamespaceSequence;
            pendingStorageRootCapability = suppliedStorageRootCapability;
            pendingStorageRootHandle = storageRootHandle;
            observations.preparedApplicationCount += 1;
            memoryBytes(
                memory,
                durableFrameOutputPointer,
                durableFrameOutputByteLength,
            ).set(authorizationFrame);
            memoryBytes(
                memory,
                proofApplicationSlotHashOutputPointer,
                proofApplicationSlotHashOutputByteLength,
            ).set(proofApplicationSlotHash);
            writeUnsigned32(memory, statusPointer, 0);
            return 92;
        },
        sealed_lattice_common_proof_confirm_application: (
            pendingHandle,
            storageRootHandle,
            storageRootCapabilityPointer,
            predecessorNamespaceSequence,
            predecessorAuthenticatedHeadDigestPointer,
            successorNamespaceSequence,
            successorAuthenticatedHeadDigestPointer,
            storageInstanceIdentityPointer,
            authenticatedDurableFramePointer,
            authenticatedDurableFrameByteLength,
        ) => {
            const bytesMatch = (
                expected: Uint8Array,
                pointer: number,
            ): boolean =>
                expected.every(
                    (byte, byteIndex) =>
                        byte ===
                        memoryBytes(memory, pointer, expected.byteLength)[
                            byteIndex
                        ],
                );
            if (
                !pendingApplication ||
                pendingPredecessorAuthenticatedHeadDigest === undefined ||
                pendingPredecessorFreshnessSequence === undefined ||
                pendingStorageRootCapability === undefined ||
                pendingStorageRootHandle === undefined
            ) {
                return 6;
            }
            const transitionMatches =
                pendingHandle === 92 &&
                storageRootHandle === pendingStorageRootHandle &&
                predecessorNamespaceSequence ===
                    pendingPredecessorFreshnessSequence &&
                successorNamespaceSequence ===
                    pendingPredecessorFreshnessSequence + 1n &&
                bytesMatch(
                    pendingStorageRootCapability,
                    storageRootCapabilityPointer,
                ) &&
                bytesMatch(
                    pendingPredecessorAuthenticatedHeadDigest,
                    predecessorAuthenticatedHeadDigestPointer,
                ) &&
                !bytesMatch(
                    pendingPredecessorAuthenticatedHeadDigest,
                    successorAuthenticatedHeadDigestPointer,
                ) &&
                bytesMatch(
                    successor.storageInstanceIdentity,
                    storageInstanceIdentityPointer,
                ) &&
                authenticatedDurableFrameByteLength ===
                    authorizationFrame.byteLength &&
                bytesMatch(
                    authorizationFrame,
                    authenticatedDurableFramePointer,
                );
            if (!transitionMatches) {
                return 6;
            }
            pendingApplication = false;
            pendingPredecessorAuthenticatedHeadDigest.fill(0);
            pendingPredecessorAuthenticatedHeadDigest = undefined;
            pendingPredecessorFreshnessSequence = undefined;
            pendingStorageRootCapability?.fill(0);
            pendingStorageRootCapability = undefined;
            pendingStorageRootHandle = undefined;
            observations.confirmedApplicationCount += 1;
            return 0;
        },
        sealed_lattice_common_proof_abort_application: (
            pendingHandle,
            statusPointer,
        ) => {
            if (!pendingApplication || pendingHandle !== 92) {
                writeUnsigned32(memory, statusPointer, 0x0001_0001);
                return 0;
            }
            pendingApplication = false;
            capabilityAvailable = true;
            pendingPredecessorAuthenticatedHeadDigest?.fill(0);
            pendingPredecessorAuthenticatedHeadDigest = undefined;
            pendingPredecessorFreshnessSequence = undefined;
            pendingStorageRootCapability?.fill(0);
            pendingStorageRootCapability = undefined;
            pendingStorageRootHandle = undefined;
            observations.abortedApplicationCount += 1;
            writeUnsigned32(memory, statusPointer, 0);
            return 82;
        },
        sealed_lattice_common_proof_discard_verified_proof: (
            capabilityHandle,
        ) => {
            if (!capabilityAvailable || capabilityHandle !== 82) {
                return 0x0001_0001;
            }
            observations.releasedCapabilityCount += 1;
            if (
                observations.releasedCapabilityCount ===
                input?.failVerifiedCapabilityReleaseAttempt
            ) {
                return 0x0001_0001;
            }
            capabilityAvailable = false;
            return 0;
        },
    }));
    const capability = await runPreparedCommonProofVerificationWorker(
        runtime,
        62,
        {
            declaredByteLength: proofBytes.byteLength,
            readCommittedChunk: () => Promise.resolve(proofBytes.slice()),
        },
        { yieldControl: () => Promise.resolve() },
    );
    return Object.freeze({
        authorizationFrame,
        capability,
        observations,
        predecessor,
        proofApplicationSlotHash,
        runtime,
        storageRootAccess: Object.freeze({
            context: runtime,
            storageRootCapability,
            storageRootHandle: 33,
        }),
        successor,
    });
};
